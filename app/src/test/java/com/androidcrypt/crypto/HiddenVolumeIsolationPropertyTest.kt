package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile

/**
 * **T12 — Hidden-volume isolation under outer-volume writes (with protection).**
 *
 * VeraCrypt's plausible-deniability guarantee: when the outer volume is
 * mounted with `hiddenVolumeProtectionPassword`, writes through the outer
 * filesystem MUST NOT touch any byte that belongs to the hidden volume
 * (data area, header, or backup header).
 *
 * The property:
 *
 *   1. Create outer (50 MB) + hidden (10 MB).
 *   2. Write known random content into the hidden volume; snapshot the
 *      raw byte ranges that comprise the hidden volume on disk.
 *   3. Mount the outer volume *with hidden-volume protection enabled*.
 *   4. Apply a random sequence of FS writes to the outer volume.
 *   5. Unmount.
 *   6. Read the raw byte ranges from step 2 again.
 *   7. Assert the hidden-region bytes are bit-identical to step 2's snapshot.
 *   8. Mount the hidden volume again and verify the originally-written
 *      content is intact.
 *
 * Failure modes this catches:
 *   - protection guard not consulted on a particular write path;
 *   - off-by-one in the protected-region bounds calculation;
 *   - write-batching path that bypasses the per-sector protection check;
 *   - cache flush that writes back stale outer-FS data into hidden sectors.
 */
class HiddenVolumeIsolationPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_hidden_pbt")
    private val outerPw = "OuterPBT-2026!".toCharArray()
    private val hiddenPw = "HiddenPBT-2026!".toCharArray()
    private val outerSizeMb = 50L
    private val hiddenSizeMb = 10L

    /** Read a contiguous byte range directly from the underlying file
     *  (bypassing the encryption layer — we want to compare ciphertext
     *  bytes, which is what isolation actually means on disk). */
    private fun readRaw(container: File, offset: Long, length: Int): ByteArray =
        RandomAccessFile(container, "r").use { raf ->
            raf.seek(offset)
            ByteArray(length).also { raf.readFully(it) }
        }

    /** Hidden-volume on-disk regions for a 50 MB outer / 10 MB hidden setup:
     *
     *   - hidden header        : [VOLUME_HEADER_SIZE, 2*VOLUME_HEADER_SIZE)
     *   - hidden data area     : [outerSize - 128KB - hiddenBytes, outerSize - 128KB)
     *   - hidden backup header : [outerSize - VOLUME_HEADER_SIZE, outerSize)
     *
     * All offsets in bytes. */
    private data class Region(val name: String, val offset: Long, val length: Int)

    private fun hiddenRegions(container: File): List<Region> {
        val total = container.length()
        val vh = VolumeConstants.VOLUME_HEADER_SIZE
        val vhg = VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        val hiddenBytes = hiddenSizeMb * 1024 * 1024
        return listOf(
            Region("hidden_header", vh, vh.toInt()),
            Region("hidden_data", total - vhg - hiddenBytes, hiddenBytes.toInt()),
            Region("hidden_backup", total - vh, vh.toInt()),
        )
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `outer-volume writes with hidden protection do not touch hidden bytes`(): Unit = runBlocking {
        testDir.mkdirs()
        try {
            checkAll(
                PropTestConfig(iterations = 3, seed = 0xABCD0001L),
                Arb.list(Arb.byteArray(Arb.int(0, 4096), Arb.byte()), 2..6)
            ) { outerPayloads ->
                val container = File(testDir, "iso_${System.nanoTime()}.hc")

                // ── Step 1: outer + hidden ──
                VolumeCreator.createContainer(container.absolutePath, outerPw.copyOf(), outerSizeMb).getOrThrow()
                VolumeCreator.createHiddenVolume(
                    container.absolutePath, outerPw.copyOf(),
                    hiddenPw.copyOf(), hiddenSizeMb
                ).getOrThrow()

                // ── Step 2: write known content to hidden, snapshot hidden bytes ──
                val hiddenContent = "hidden-payload-${System.nanoTime()}".toByteArray(Charsets.UTF_8)
                run {
                    val r = VolumeReader(container.absolutePath)
                    r.mount(hiddenPw.copyOf(), useHiddenVolume = true).getOrThrow()
                    val fs = FAT32Reader(r); fs.initialize().getOrThrow()
                    fs.createFile("/", "h.bin").getOrThrow()
                    fs.writeFile("/h.bin", hiddenContent).getOrThrow()
                    r.sync()
                    r.unmount()
                }
                val regions = hiddenRegions(container)
                val snapshots = regions.map { r -> r to readRaw(container, r.offset, r.length) }

                // ── Step 3+4: mount outer WITH protection, apply outer writes ──
                val r2 = VolumeReader(container.absolutePath)
                r2.mount(outerPw.copyOf(), hiddenVolumeProtectionPassword = hiddenPw.copyOf()).getOrThrow()
                val fs2 = FAT32Reader(r2); fs2.initialize().getOrThrow()
                outerPayloads.forEachIndexed { i, p ->
                    try {
                        fs2.createFile("/", "o$i.bin").getOrThrow()
                        fs2.writeFile("/o$i.bin", p).getOrThrow()
                    } catch (_: Exception) {
                        // Protection-triggered failures are fine — the contract
                        // is "hidden region untouched", not "every write succeeds".
                    }
                }
                r2.sync()
                r2.unmount()

                // ── Step 5+6+7: hidden bytes must be unchanged ──
                for ((region, snap) in snapshots) {
                    val now = readRaw(container, region.offset, region.length)
                    assertArrayEquals(
                        "hidden region '${region.name}' (offset=${region.offset} len=${region.length}) " +
                                "was modified by outer-volume writes — hidden-volume protection failed",
                        snap, now
                    )
                }

                // ── Step 8: hidden volume still mounts with original content ──
                val r3 = VolumeReader(container.absolutePath)
                r3.mount(hiddenPw.copyOf(), useHiddenVolume = true).getOrThrow()
                val fs3 = FAT32Reader(r3); fs3.initialize().getOrThrow()
                assertTrue("hidden file disappeared after outer writes", fs3.exists("/h.bin"))
                assertArrayEquals(
                    "hidden file content corrupted after outer writes",
                    hiddenContent, fs3.readFile("/h.bin").getOrThrow()
                )
                r3.unmount()

                container.delete()
            }
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }
}
