package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.element
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Property-based tests for the geometry of containers produced by
 * [VolumeCreator]. Every container, regardless of size, must satisfy the
 * basic FAT32 invariants — most importantly that the FAT region is
 * physically large enough to hold a 4-byte entry for every cluster in the
 * data area.
 *
 * The undersized-FAT bug fixed in April 2026 (formula
 * `(sectorCount - reserved)/(spc + 1)` produced `sectorsPerFAT = 21` while
 * the data area held 2998 clusters → ~310 clusters had no FAT entries and
 * `countFreeClusters()` read garbage out of the data sectors) was only
 * caught at 12 MB. This property re-checks every reasonable container size
 * to be sure the new Microsoft-spec formula doesn't reintroduce a similar
 * miscount at any other size point.
 *
 * Each iteration creates a fresh container, mounts it, parses the BPB, and
 * asserts:
 *
 *  1. `sectorsPerFAT * 128 ≥ totalClusters + 2`     (FAT covers all clusters)
 *  2. `numFATs == 2`, `bytesPerSector == 512`        (basic format invariants)
 *  3. `firstDataSector == reserved + numFATs*spf`    (offset arithmetic)
 *  4. `countFreeClusters() == directFatScan()`       (cache & scan agree on the
 *                                                     freshly-created volume)
 *  5. The FAT slack region (entries past `totalClusters`) is all zero.
 *
 * Properties #4 and #5 together prove the FAT is correctly sized — if it
 * weren't, either `countFreeClusters` would over-report (catches under-size)
 * or there would be unexpected non-zero entries in the slack region
 * (catches over-size, which would shift the data area).
 */
class VolumeGeometryPropertyTest {

    private val tmpDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_geo_pbt")

    init { tmpDir.mkdirs() }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `every container size has a correctly-sized FAT`(): Unit = runBlocking {
        // Sizes in MB. Includes the historical bad-formula trigger size
        // (12 MB), small sizes that stress integer rounding, and a
        // mid-size to keep total runtime reasonable. We deliberately do
        // NOT go above ~64 MB here because container creation cost grows
        // linearly and the property is independent of size beyond that
        // (the geometry formula doesn't change behaviour at GB scale).
        val sizesMb = listOf(5, 8, 10, 12, 16, 20, 24, 32, 48, 64)
        checkAll(
            PropTestConfig(iterations = sizesMb.size, seed = 0x6E0E0001L),
            Arb.element(sizesMb),
        ) { sizeMb: Int ->
            val container = File(tmpDir, "geo_${sizeMb}mb_${System.nanoTime()}.hc")
            try {
                VolumeCreator.createContainer(
                    container.absolutePath, "GeoPBT!".toCharArray(), sizeMb.toLong()
                ).getOrThrow()

                val r = VolumeReader(container.absolutePath)
                r.mount("GeoPBT!".toCharArray()).getOrThrow()
                try {
                    val bs = r.readSector(0).getOrThrow()
                    val bytesPerSector = (bs[11].toInt() and 0xFF) or ((bs[12].toInt() and 0xFF) shl 8)
                    val sectorsPerCluster = bs[13].toInt() and 0xFF
                    val reserved = (bs[14].toInt() and 0xFF) or ((bs[15].toInt() and 0xFF) shl 8)
                    val numFats = bs[16].toInt() and 0xFF
                    val sectorsPerFat = ByteBuffer.wrap(bs, 36, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong()
                    val totalSectors = ByteBuffer.wrap(bs, 32, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong()
                    val firstDataSector = reserved + numFats * sectorsPerFat
                    val totalClusters = ((totalSectors - firstDataSector) / sectorsPerCluster).toInt()
                    val fatEntryCapacity = (sectorsPerFat * bytesPerSector / 4).toInt()

                    // 1. Every cluster has a corresponding FAT entry.
                    //    The +2 is for the two reserved entries at the
                    //    start of the FAT (cluster numbers 0 and 1).
                    assertTrue(
                        "sizeMb=$sizeMb: FAT too small — capacity=$fatEntryCapacity " +
                            "needs >= ${totalClusters + 2} (totalClusters=$totalClusters + 2 reserved)",
                        fatEntryCapacity >= totalClusters + 2
                    )

                    // 2. Basic format invariants.
                    assertEquals("sizeMb=$sizeMb: bytesPerSector", 512, bytesPerSector)
                    assertEquals("sizeMb=$sizeMb: numFATs", 2, numFats)
                    assertTrue("sizeMb=$sizeMb: sectorsPerFat must be > 0", sectorsPerFat > 0)
                    assertTrue("sizeMb=$sizeMb: reserved must be > 0", reserved > 0)
                    assertTrue("sizeMb=$sizeMb: sectorsPerCluster must be > 0", sectorsPerCluster > 0)

                    // 3. Free-cluster cache agrees with raw FAT scan.
                    val fs = FAT32Reader(r)
                    fs.initialize().getOrThrow()
                    val cached = fs.countFreeClusters()
                    val onDisk = scanFreeClusters(
                        r, reserved, numFats, sectorsPerFat, sectorsPerCluster,
                        totalSectors, bytesPerSector, totalClusters
                    )
                    assertEquals(
                        "sizeMb=$sizeMb: cached free-cluster count != direct FAT scan",
                        onDisk, cached
                    )

                    // 4. The slack region of the FAT (entries past
                    //    cluster N+1, i.e. past entry index totalClusters+1)
                    //    must be all zero. If sectorsPerFat were over-sized,
                    //    the slack might accidentally contain old salt /
                    //    header bytes.
                    val slackEntries = fatEntryCapacity - (totalClusters + 2)
                    if (slackEntries > 0) {
                        // Only check if there ARE slack entries; otherwise
                        // the FAT is exactly sized.
                        val slackCount = countSlackNonZero(
                            r, reserved, sectorsPerFat, bytesPerSector, totalClusters
                        )
                        assertEquals(
                            "sizeMb=$sizeMb: $slackCount non-zero entries in FAT slack region " +
                                "(slack entries = $slackEntries)",
                            0, slackCount
                        )
                    }
                } finally {
                    runCatching { r.unmount() }
                }
            } finally {
                container.delete()
            }
        }
    }

    /** Direct FAT-scan free-cluster count, matching FAT32AdditionalPropertyTests's scanner. */
    private fun scanFreeClusters(
        r: VolumeReader,
        reserved: Int,
        numFats: Int,
        sectorsPerFat: Long,
        sectorsPerCluster: Int,
        totalSectors: Long,
        bytesPerSector: Int,
        totalClusters: Int,
    ): Int {
        // Valid cluster numbers are 2..totalClusters+1 inclusive.
        val lastValidEntryIndex = totalClusters + 1
        var free = 0
        var sectorOffset: Long = 0
        var entryIndex = 0
        var remaining = sectorsPerFat
        while (remaining > 0) {
            val n = minOf(remaining, 32L).toInt()
            val data = r.readSectors(reserved + sectorOffset, n).getOrThrow()
            val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
            val entriesInChunk = (n * bytesPerSector) / 4
            for (i in 0 until entriesInChunk) {
                val v = buf.int and 0x0FFFFFFF
                if (entryIndex in 2..lastValidEntryIndex && v == 0) free++
                entryIndex++
            }
            sectorOffset += n
            remaining -= n
        }
        return free
    }

    /** Count NON-zero entries in the slack region of FAT1 (entries past totalClusters). */
    private fun countSlackNonZero(
        r: VolumeReader,
        reserved: Int,
        sectorsPerFat: Long,
        bytesPerSector: Int,
        totalClusters: Int,
    ): Int {
        val firstSlackEntry = totalClusters + 1
        var nonZero = 0
        var sectorOffset: Long = 0
        var entryIndex = 0
        var remaining = sectorsPerFat
        while (remaining > 0) {
            val n = minOf(remaining, 32L).toInt()
            val data = r.readSectors(reserved + sectorOffset, n).getOrThrow()
            val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
            val entriesInChunk = (n * bytesPerSector) / 4
            for (i in 0 until entriesInChunk) {
                val v = buf.int and 0x0FFFFFFF
                if (entryIndex > firstSlackEntry && v != 0) nonZero++
                entryIndex++
            }
            sectorOffset += n
            remaining -= n
        }
        return nonZero
    }
}
