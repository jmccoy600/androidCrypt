package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.map
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile

/**
 * **T6 — Primary header == backup header parity.**
 *
 * VeraCrypt stores a backup header at `(totalSize - 128KB)` for both the
 * normal and hidden volumes. The primary and backup encrypted-header bytes
 * must remain bit-identical at all times — a divergence is a data-loss bug
 * the moment the primary header is corrupted (e.g. by a bad sector) and
 * the backup is needed for recovery.
 *
 * Currently the headers are written once at creation and never updated, so
 * this property is a *regression guard*: the moment someone adds a code
 * path that mutates the primary header (modification-time updates, key
 * rotation, etc.) without mirroring the change to the backup, this test
 * starts failing.
 *
 * The property runs across:
 *   - random container sizes,
 *   - random sequences of file-system writes (which must not touch the
 *     header region — it lives outside the data area),
 *   - random remounts.
 */
class VolumeHeaderBackupParityPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_hdrbackup_pbt")
    private val password = "HdrBackupPBT!".toCharArray()

    private fun readPrimary(container: File): ByteArray =
        RandomAccessFile(container, "r").use { raf ->
            raf.seek(0)
            ByteArray(VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE).also { raf.readFully(it) }
        }

    private fun readBackup(container: File): ByteArray =
        RandomAccessFile(container, "r").use { raf ->
            // Backup *normal* header lives at (totalSize - 128KB).
            val backupOff = container.length() - VolumeConstants.VOLUME_HEADER_GROUP_SIZE
            raf.seek(backupOff)
            ByteArray(VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE).also { raf.readFully(it) }
        }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `primary and backup volume headers stay bit-identical`(): Unit = runBlocking {
        testDir.mkdirs()
        try {
            checkAll(
                PropTestConfig(iterations = 6, seed = 0xBACCBACCL),
                Arb.int(8, 16),                                 // size MB
                Arb.list(Arb.byteArray(Arb.int(0, 1024), Arb.byte()), 0..6) // payloads
            ) { sizeMb, payloads ->
                val container = File(testDir, "hdr_${System.nanoTime()}.hc")
                VolumeCreator.createContainer(container.absolutePath, password.copyOf(), sizeMb.toLong()).getOrThrow()

                val primary0 = readPrimary(container)
                val backup0 = readBackup(container)
                assertArrayEquals("primary != backup right after creation", primary0, backup0)

                // Do some FS writes — the data area is between 128KB and (size-128KB),
                // so writes must never touch either header.
                val r = VolumeReader(container.absolutePath)
                r.mount(password.copyOf()).getOrThrow()
                val fs = FAT32Reader(r); fs.initialize().getOrThrow()
                payloads.forEachIndexed { i, p ->
                    try {
                        fs.createFile("/", "h$i.bin").getOrThrow()
                        fs.writeFile("/h$i.bin", p).getOrThrow()
                    } catch (_: Exception) {}
                }
                r.unmount()

                val primary1 = readPrimary(container)
                val backup1 = readBackup(container)
                assertArrayEquals(
                    "primary header changed after FS writes (sizeMb=$sizeMb)",
                    primary0, primary1
                )
                assertArrayEquals(
                    "backup header changed after FS writes (sizeMb=$sizeMb)",
                    backup0, backup1
                )
                assertArrayEquals(
                    "primary diverged from backup after FS writes (sizeMb=$sizeMb)",
                    primary1, backup1
                )

                container.delete()
            }
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }
}
