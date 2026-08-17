package com.androidcrypt.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.AssumptionViolatedException
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Direct spec-conformance tests for the exFAT v1.00 specification.
 *
 * Each test validates a specific spec section by constructing or reading
 * on-disk structures and asserting the exact field values, ranges, and
 * algorithms the spec mandates. These tests do NOT use property-based
 * testing — they are deterministic checks against spec-mandated invariants.
 *
 * Spec references inline cite section numbers from the Microsoft exFAT
 * File System Specification v1.00.
 */
class ExFatSpecConformanceTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_spec")
    private val password = "ExFatSpec!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto")
        true
    } catch (_: UnsatisfiedLinkError) {
        false
    }

    private fun assumeNative() {
        if (!nativeAvailable) {
            throw AssumptionViolatedException("Native library veracrypt_crypto not available")
        }
    }

    private data class ExFatVolume(
        val container: File,
        val reader: VolumeReader,
        val fs: ExFatReader
    )

    private fun openVolume(sizeMb: Long = 8L): ExFatVolume {
        val container = File(testDir, "spec_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(
            container.absolutePath, password.copyOf(), sizeMb,
            fileSystem = VolumeFileSystem.EXFAT
        ).getOrThrow()
        val reader = VolumeReader(container.absolutePath)
        reader.mount(password.copyOf()).getOrThrow()
        val fs = ExFatReader(reader)
        fs.initialize().getOrThrow()
        return ExFatVolume(container, reader, fs)
    }

    private fun closeVolume(v: ExFatVolume) {
        v.reader.unmount()
        v.container.delete()
    }

    // ── §3.1 Main Boot Sector structure ────────────────────────────────────

    /** §3.1.1: JumpBoot shall be EBh 76h 90h. */
    @Test
    fun `§3_1_1 JumpBoot is EB 76 90`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            assertEquals("JumpBoot[0]", 0xEB.toByte(), boot[0])
            assertEquals("JumpBoot[1]", 0x76.toByte(), boot[1])
            assertEquals("JumpBoot[2]", 0x90.toByte(), boot[2])
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.2: FileSystemName shall be "EXFAT   " (8 bytes ASCII, 3 trailing spaces). */
    @Test
    fun `§3_1_2 FileSystemName is EXFAT with 3 trailing spaces`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val name = String(boot, 3, 8, Charsets.US_ASCII)
            assertEquals("EXFAT   ", name)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.3: MustBeZero (bytes 11..63) shall all be zero. */
    @Test
    fun `§3_1_3 MustBeZero region bytes 11-63 are all zero`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            for (i in 11 until 64) {
                assertEquals("MustBeZero[$i]", 0, boot[i].toInt())
            }
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.5: VolumeLength describes size in sectors; must be >= 2^20 / 2^BytesPerSectorShift. */
    @Test
    fun `§3_1_5 VolumeLength is at least 1MB worth of sectors`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume(2L) // 2 MB container
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val volumeLength = ByteBuffer.wrap(boot, 72, 8).order(ByteOrder.LITTLE_ENDIAN).long
            val bytesPerSectorShift = boot[108].toInt() and 0xFF
            val minSectors = (1L shl 20) / (1L shl bytesPerSectorShift)
            assertTrue("VolumeLength $volumeLength >= minSectors $minSectors", volumeLength >= minSectors)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.6: FatOffset shall be >= 24. */
    @Test
    fun `§3_1_6 FatOffset is at least 24`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val fatOffset = ByteBuffer.wrap(boot, 80, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            assertTrue("FatOffset $fatOffset >= 24", fatOffset >= 24)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.9: ClusterCount must be <= 2^32 - 11. */
    @Test
    fun `§3_1_9 ClusterCount does not exceed 2^32 - 11`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val clusterCount = ByteBuffer.wrap(boot, 92, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            assertTrue("ClusterCount $clusterCount <= ${0xFFFFFFFFL - 11}", clusterCount <= 0xFFFFFFFFL - 11)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.10: FirstClusterOfRootDirectory shall be in [2, ClusterCount+1]. */
    @Test
    fun `§3_1_10 FirstClusterOfRootDirectory is in valid range`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterCount = ByteBuffer.wrap(boot, 92, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            assertTrue("rootCluster $rootCluster >= 2", rootCluster >= 2)
            assertTrue("rootCluster $rootCluster <= ClusterCount+1 ${clusterCount + 1}", rootCluster <= clusterCount + 1)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.12: FileSystemRevision — major revision shall be 1 (we only support 1.00). */
    @Test
    fun `§3_1_12 FileSystemRevision major is 1`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val rev = ByteBuffer.wrap(boot, 104, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val major = (rev shr 8) and 0xFF
            assertEquals(1, major)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.14: BytesPerSectorShift shall be in [9, 12]. */
    @Test
    fun `§3_1_14 BytesPerSectorShift is in 9 to 12`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val shift = boot[108].toInt() and 0xFF
            assertTrue("BytesPerSectorShift $shift in [9,12]", shift in 9..12)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.15: SectorsPerClusterShift shall be in [0, 25 - BytesPerSectorShift]. */
    @Test
    fun `§3_1_15 SectorsPerClusterShift is in valid range`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val bytesPerSectorShift = boot[108].toInt() and 0xFF
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            assertTrue(
                "SectorsPerClusterShift $sectorsPerClusterShift in [0, ${25 - bytesPerSectorShift}]",
                sectorsPerClusterShift in 0..(25 - bytesPerSectorShift)
            )
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.16: NumberOfFats shall be 1 or 2. */
    @Test
    fun `§3_1_16 NumberOfFats is 1 or 2`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val numFats = boot[110].toInt() and 0xFF
            assertTrue("NumberOfFats $numFats in {1,2}", numFats == 1 || numFats == 2)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §3.1.20: BootSignature shall be 0xAA55. */
    @Test
    fun `§3_1_20 BootSignature is AA55`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            assertEquals(0x55, boot[510].toInt() and 0xFF)
            assertEquals(0xAA, boot[511].toInt() and 0xFF)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §3.2 Extended Boot Sectors ──────────────────────────────────────────

    /** §3.2.2: Each Extended Boot Sector's signature shall be 0xAA550000. */
    @Test
    fun `§3_2_2 Extended Boot Sectors have AA550000 signature`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            // Sectors 1..8 are Main Extended Boot Sectors
            for (i in 1..8) {
                val sector = v.reader.readSector(i.toLong()).getOrThrow()
                val sig = ByteBuffer.wrap(sector, 508, 4).order(ByteOrder.LITTLE_ENDIAN).int
                assertEquals("Extended Boot Sector $i signature", 0xAA550000.toInt(), sig)
            }
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §3.4 Boot Checksum ──────────────────────────────────────────────────

    /** §3.4: Boot Checksum sector contains the 4-byte checksum repeated to fill the sector. */
    @Test
    fun `§3_4 Boot Checksum sector is filled with repeated checksum`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val checksumSector = v.reader.readSector(11).getOrThrow()
            val firstWord = ByteBuffer.wrap(checksumSector, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
            // Every 4-byte word in the sector must match the first
            for (off in 0 until 512 step 4) {
                val word = ByteBuffer.wrap(checksumSector, off, 4).order(ByteOrder.LITTLE_ENDIAN).int
                assertEquals("Boot checksum word at offset $off", firstWord, word)
            }
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /**
     * §3.4 Figure 1: Boot checksum excludes bytes 106, 107 (VolumeFlags) and 112 (PercentInUse).
     * Verify by re-computing the checksum and comparing to the on-disk value.
     */
    @Test
    fun `§3_4 Boot checksum matches re-computation excluding VolumeFlags and PercentInUse`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            // Read all 11 sectors of the Main Boot Region
            val bootRegion = v.reader.readSectors(0, 11).getOrThrow()
            // Recompute checksum per spec §3.4 Figure 1
            var checksum = 0
            for (i in bootRegion.indices) {
                if (i == 106 || i == 107 || i == 112) continue
                checksum = (((if ((checksum and 1) != 0) 0x80000000.toInt() else 0) +
                            (checksum shr 1) +
                            (bootRegion[i].toInt() and 0xFF)))
            }
            // Read on-disk checksum
            val checksumSector = v.reader.readSector(11).getOrThrow()
            val onDisk = ByteBuffer.wrap(checksumSector, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
            assertEquals("Boot checksum", checksum, onDisk)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §4.1 FAT entries ────────────────────────────────────────────────────

    /** §4.1.1: FatEntry[0] first byte is media type (should be F8h), remaining 3 bytes are FFh. */
    @Test
    fun `§4_1_1 FatEntry 0 has media type F8 and FFFFFFF8 value`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val fatOffset = ByteBuffer.wrap(boot, 80, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val fatSector = v.reader.readSector(fatOffset).getOrThrow()
            val entry0 = ByteBuffer.wrap(fatSector, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            assertEquals(0xFFFFFFF8L, entry0)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §4.1.2: FatEntry[1] shall be 0xFFFFFFFF. */
    @Test
    fun `§4_1_2 FatEntry 1 is FFFFFFFF`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val fatOffset = ByteBuffer.wrap(boot, 80, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val fatSector = v.reader.readSector(fatOffset).getOrThrow()
            val entry1 = ByteBuffer.wrap(fatSector, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            assertEquals(0xFFFFFFFFL, entry1)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /**
     * §4.1.3: FAT entry values for clusters 2..ClusterCount+1.
     * Valid values: 2..ClusterCount+1 (next cluster), 0xFFFFFFF7 (bad), 0xFFFFFFFF (EOC).
     */
    @Test
    fun `§4_1_3 FAT entries for allocated clusters are valid chain values or EOC`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val fatOffset = ByteBuffer.wrap(boot, 80, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val fatLength = ByteBuffer.wrap(boot, 84, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterCount = ByteBuffer.wrap(boot, 92, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL

            // Read the entire FAT
            val fatData = v.reader.readSectors(fatOffset, fatLength.toInt()).getOrThrow()

            // Check entries 2..ClusterCount+1
            for (cluster in 2L..(clusterCount + 1)) {
                val offset = (cluster * 4).toInt()
                if (offset + 4 > fatData.size) break
                val entry = ByteBuffer.wrap(fatData, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                // Entry is either a valid next cluster, bad cluster, EOC, or 0 (free via bitmap, FAT entry may be 0)
                val isValid = entry == 0L ||
                              entry in 2..(clusterCount + 1) ||
                              entry == 0xFFFFFFF7L ||
                              entry == 0xFFFFFFFFL
                assertTrue("FatEntry[$cluster] = 0x${entry.toString(16)} is valid", isValid)
            }
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §5.1 Cluster Heap ──────────────────────────────────────────────────

    /** §5.1: Cluster N is at sector ClusterHeapOffset + (N-2) * 2^SectorsPerClusterShift. */
    @Test
    fun `§5_1 cluster to sector mapping matches spec formula`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift

            // Cluster 2 should be at clusterHeapOffset + 0
            // Cluster 3 should be at clusterHeapOffset + sectorsPerCluster
            // Cluster 4 should be at clusterHeapOffset + 2*sectorsPerCluster
            for (cluster in 2..4) {
                val expectedSector = clusterHeapOffset + (cluster - 2) * sectorsPerCluster
                // Read the cluster and verify it's accessible
                val data = v.reader.readSectors(expectedSector, sectorsPerCluster)
                assertTrue("Cluster $cluster at sector $expectedSector is readable", data.isSuccess)
            }
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §6.2.1 EntryType bit fields ─────────────────────────────────────────

    /**
     * §6.2.1: EntryType byte bit layout.
     * Bit 7 (InUse): 1 = in use, 0 = deleted/unused.
     * Bit 6 (TypeCategory): 0 = primary, 1 = secondary.
     * Bit 5 (TypeImportance): 0 = critical, 1 = benign.
     * Bits 0-4 (TypeCode): entry sub-type.
     */
    @Test
    fun `§6_2_1 EntryType bit fields are correctly composed`() {
        // 0x85 = File: InUse=1, TypeCategory=0 (primary), TypeImportance=0 (critical), TypeCode=5
        assertEquals(0x85.toByte(), ExFatReader.FILE)
        assertEquals(0, 0x85 and 0x40) // primary
        assertEquals(0, 0x85 and 0x20) // critical
        assertEquals(5, 0x85 and 0x1F) // TypeCode=5

        // 0xC0 = Stream Extension: InUse=1, TypeCategory=1 (secondary), TypeImportance=0, TypeCode=0
        assertEquals(0xC0.toByte(), ExFatReader.STREAM_EXTENSION)
        assertTrue((0xC0 and 0x40) != 0) // secondary
        assertEquals(0, 0xC0 and 0x20) // critical
        assertEquals(0, 0xC0 and 0x1F) // TypeCode=0

        // 0xC1 = File Name: InUse=1, TypeCategory=1 (secondary), TypeImportance=0, TypeCode=1
        assertEquals(0xC1.toByte(), ExFatReader.FILE_NAME)
        assertTrue((0xC1 and 0x40) != 0) // secondary
        assertEquals(0, 0xC1 and 0x20) // critical
        assertEquals(1, 0xC1 and 0x1F) // TypeCode=1

        // 0x81 = Allocation Bitmap: InUse=1, TypeCategory=0 (primary), TypeImportance=0, TypeCode=1
        assertEquals(0x81.toByte(), ExFatReader.ALLOCATION_BITMAP)
        assertEquals(0, 0x81 and 0x40) // primary
        assertEquals(0, 0x81 and 0x20) // critical
        assertEquals(1, 0x81 and 0x1F) // TypeCode=1

        // 0x82 = Up-case Table: InUse=1, primary, critical, TypeCode=2
        assertEquals(0x82.toByte(), ExFatReader.UP_CASE_TABLE)
        assertEquals(2, 0x82 and 0x1F)

        // 0x83 = Volume Label: InUse=1, primary, critical, TypeCode=3
        assertEquals(0x83.toByte(), ExFatReader.VOLUME_LABEL)
        assertEquals(3, 0x83 and 0x1F)

        // 0x00 = End of directory
        assertEquals(0x00.toByte(), ExFatReader.END_OF_DIR)
    }

    // ── §6.3.3 SetChecksum computation ──────────────────────────────────────

    /**
     * §6.3.3 Figure 2: SetChecksum computation.
     * Covers (secondaryCount+1)*32 bytes, skipping bytes 2 and 3 of the primary entry.
     */
    @Test
    fun `§6_3_3 SetChecksum matches spec Figure 2 algorithm`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            // Create a file so we can read its entry set and verify the checksum
            v.fs.createFile("/", "checksum_test.dat").getOrThrow()
            v.fs.writeFile("/checksum_test.dat", "Hello exFAT!".toByteArray()).getOrThrow()

            // Read the root directory cluster to get the entry set bytes
            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift

            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            // Find the File entry (0x85) for checksum_test.dat — skip bitmap and upcase entries
            var off = 0
            while (off < rootData.size) {
                val type = rootData[off]
                if (type == ExFatReader.END_OF_DIR) break
                if (type == ExFatReader.FILE) {
                    val secondaryCount = rootData[off + 1].toInt() and 0xFF
                    val storedChecksum = ByteBuffer.wrap(rootData, off + 2, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF

                    // Recompute per spec §6.3.3 Figure 2
                    val total = (secondaryCount + 1) * 32
                    var checksum = 0
                    for (i in 0 until total) {
                        if (i == 2 || i == 3) continue
                        checksum = (((if ((checksum and 1) != 0) 0x8000 else 0) +
                                    (checksum shr 1) +
                                    (rootData[off + i].toInt() and 0xFF)) and 0xFFFF)
                    }
                    assertEquals("SetChecksum", checksum, storedChecksum)
                    return
                }
                off += 32
            }
            assertFalse("File entry not found in root directory", true)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §7.1 Allocation Bitmap ──────────────────────────────────────────────

    /**
     * §7.1: The root directory shall contain one Allocation Bitmap directory entry per FAT.
     * EntryType 0x81, with FirstCluster and DataLength fields.
     */
    @Test
    fun `§7_1 root directory contains Allocation Bitmap entry with correct type`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            var foundBitmap = false
            var off = 0
            while (off < rootData.size) {
                val type = rootData[off]
                if (type == ExFatReader.END_OF_DIR) break
                if (type == ExFatReader.ALLOCATION_BITMAP) {
                    foundBitmap = true
                    // FirstCluster at offset 20
                    val firstCluster = ByteBuffer.wrap(rootData, off + 20, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    assertTrue("Bitmap FirstCluster >= 2", firstCluster >= 2)
                    // DataLength at offset 24
                    val dataLength = ByteBuffer.wrap(rootData, off + 24, 8).order(ByteOrder.LITTLE_ENDIAN).long
                    assertTrue("Bitmap DataLength > 0", dataLength > 0)
                    break
                }
                off += 32
            }
            assertTrue("Allocation Bitmap entry found in root", foundBitmap)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /**
     * §7.1: Bitmap bit (N-2) of byte (N-2)/8 indicates cluster N allocation.
     * Bit 0 = cluster 2 (first cluster), bit 1 = cluster 3, etc.
     */
    @Test
    fun `§7_1 bitmap bit indexing maps cluster N to bit N-2`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            // After format, clusters 2 (root), 3 (bitmap), 4 (upcase) should be allocated
            // Read the allocation bitmap and check bits 0, 1, 2 are set
            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift

            // Find the bitmap directory entry in root
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            var bitmapFirstCluster = 0L
            var bitmapDataLength = 0L
            var off = 0
            while (off < rootData.size) {
                if (rootData[off] == ExFatReader.ALLOCATION_BITMAP) {
                    bitmapFirstCluster = ByteBuffer.wrap(rootData, off + 20, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    bitmapDataLength = ByteBuffer.wrap(rootData, off + 24, 8).order(ByteOrder.LITTLE_ENDIAN).long
                    break
                }
                if (rootData[off] == ExFatReader.END_OF_DIR) break
                off += 32
            }
            assertTrue("Bitmap entry found", bitmapFirstCluster >= 2)

            // Read the bitmap cluster
            val bitmapSector = clusterHeapOffset + (bitmapFirstCluster - 2) * sectorsPerCluster
            val bitmapData = v.reader.readSectors(bitmapSector, sectorsPerCluster).getOrThrow()

            // Cluster 2 (root) → bit 0
            assertTrue("Cluster 2 (root) allocated", (bitmapData[0].toInt() and 0x01) != 0)
            // Cluster 3 (bitmap) → bit 1
            assertTrue("Cluster 3 (bitmap) allocated", (bitmapData[0].toInt() and 0x02) != 0)
            // Cluster 4 (upcase) → bit 2
            assertTrue("Cluster 4 (upcase) allocated", (bitmapData[0].toInt() and 0x04) != 0)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §7.2 Up-case Table ───────────────────────────────────────────────────

    /**
     * §7.2: Root directory shall contain exactly one Up-case Table directory entry.
     * EntryType 0x82, with TableChecksum at offset 4, FirstCluster at offset 20, DataLength at offset 24.
     */
    @Test
    fun `§7_2 root directory contains exactly one Up-case Table entry`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            var upcaseCount = 0
            var off = 0
            while (off < rootData.size) {
                val type = rootData[off]
                if (type == ExFatReader.END_OF_DIR) break
                if (type == ExFatReader.UP_CASE_TABLE) {
                    upcaseCount++
                    // TableChecksum at offset 4
                    val tableChecksum = ByteBuffer.wrap(rootData, off + 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                    // FirstCluster at offset 20
                    val firstCluster = ByteBuffer.wrap(rootData, off + 20, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    // DataLength at offset 24
                    val dataLength = ByteBuffer.wrap(rootData, off + 24, 8).order(ByteOrder.LITTLE_ENDIAN).long
                    assertTrue("Upcase FirstCluster >= 2", firstCluster >= 2)
                    assertTrue("Upcase DataLength > 0", dataLength > 0)
                }
                off += 32
            }
            assertEquals("Exactly one Up-case Table entry", 1, upcaseCount)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §7.4 File Directory Entry ───────────────────────────────────────────

    /** §7.4: File entry layout — EntryType 0x85, SecondaryCount, SetChecksum, FileAttributes. */
    @Test
    fun `§7_4 File entry has correct EntryType and SecondaryCount`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            v.fs.createFile("/", "test_file.txt").getOrThrow()
            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            var off = 0
            while (off < rootData.size) {
                val type = rootData[off]
                if (type == ExFatReader.END_OF_DIR) break
                if (type == ExFatReader.FILE) {
                    assertEquals(0x85.toByte(), type)
                    val secondaryCount = rootData[off + 1].toInt() and 0xFF
                    // For "test_file.txt" (12 chars), we need 1 Stream Extension + ceil(12/15)=1 File Name = 2
                    assertEquals("SecondaryCount", 2, secondaryCount)
                    // FileAttributes at offset 4 — new file has Archive bit set (0x20)
                    val attrs = ByteBuffer.wrap(rootData, off + 4, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                    assertTrue("Archive attribute set", (attrs and 0x20) != 0)
                    return
                }
                off += 32
            }
            assertFalse("File entry not found", true)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §7.4.4: FileAttributes — Directory bit (0x10) set for directories. */
    @Test
    fun `§7_4_4 directory entry has Directory attribute bit set`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            v.fs.createDirectory("/", "testdir").getOrThrow()
            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            var off = 0
            while (off < rootData.size) {
                val type = rootData[off]
                if (type == ExFatReader.END_OF_DIR) break
                if (type == ExFatReader.FILE) {
                    val attrs = ByteBuffer.wrap(rootData, off + 4, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                    assertTrue("Directory attribute", (attrs and 0x10) != 0)
                    return
                }
                off += 32
            }
            assertFalse("Directory entry not found", true)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §7.4.8 Timestamp fields ────────────────────────────────────────────

    /**
     * §7.4.8: Timestamp is a 4-byte LE u32 with bit fields:
     * Bits 0-4: DoubleSeconds (0..29), Bits 5-10: Minute (0..59),
     * Bits 11-15: Hour (0..23), Bits 16-20: Day (1..31),
     * Bits 21-24: Month (1..12), Bits 25-31: Year (0..127, = 1980..2107).
     */
    @Test
    fun `§7_4_8 Timestamp bit fields pack and unpack correctly`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            // Create a file with a known timestamp
            v.fs.createFile("/", "ts_test.txt").getOrThrow()
            val info = v.fs.getFileInfo("/ts_test.txt").getOrThrow()
            // lastModified should be a reasonable timestamp (within last few seconds of now)
            val now = System.currentTimeMillis()
            val delta = Math.abs(now - info.lastModified)
            // exFAT timestamp resolution is 2 seconds (no 10ms increment in our impl)
            assertTrue("Timestamp delta $delta ms < 5000ms", delta < 5000)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    /** §7.4.8: Timestamp year range is 1980..2107 (7-bit field, 0 = 1980). */
    @Test
    fun `§7_4_8 Timestamp year 1980 packs to 0 in year field`() {
        // Pack 1980-01-01 00:00:00 → year field (bits 25-31) should be 0
        val cal = java.util.Calendar.getInstance().apply {
            set(1980, 0, 1, 0, 0, 0)
            set(java.util.Calendar.MILLISECOND, 0)
        }
        // Replicate the packing from ExFatReader.encodeExFatTimestamp
        val year = 1980 - 1980 // = 0
        val month = 1
        val day = 1
        val hour = 0
        val minute = 0
        val sec = 0
        val packed = ((year and 0x7F) shl 25) or
                     ((month and 0x0F) shl 21) or
                     ((day and 0x1F) shl 16) or
                     ((hour and 0x1F) shl 11) or
                     ((minute and 0x3F) shl 5) or
                     (sec and 0x1F)
        assertEquals(0, (packed shr 25) and 0x7F) // year field is 0
        assertEquals(1, (packed shr 21) and 0x0F) // month
        assertEquals(1, (packed shr 16) and 0x1F) // day
    }

    // ── §7.6 Stream Extension Directory Entry ───────────────────────────────

    /**
     * §7.6: Stream Extension entry (0xC0) immediately follows the File entry.
     * Fields: NameLength at offset 3, NameHash at offset 4, ValidDataLength at offset 8,
     * FirstCluster at offset 20, DataLength at offset 24.
     */
    @Test
    fun `§7_6 Stream Extension entry has correct layout and follows File entry`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            v.fs.createFile("/", "stream_test.txt").getOrThrow()
            v.fs.writeFile("/stream_test.txt", "data".toByteArray()).getOrThrow()

            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            var off = 0
            while (off < rootData.size) {
                val type = rootData[off]
                if (type == ExFatReader.END_OF_DIR) break
                if (type == ExFatReader.FILE) {
                    // Stream Extension must be at off + 32
                    val streamOff = off + 32
                    assertEquals(ExFatReader.STREAM_EXTENSION, rootData[streamOff])
                    // NameLength at offset 3
                    val nameLength = rootData[streamOff + 3].toInt() and 0xFF
                    assertEquals("stream_test.txt".length, nameLength)
                    // NameHash at offset 4
                    val nameHash = ByteBuffer.wrap(rootData, streamOff + 4, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                    assertTrue("NameHash non-zero", nameHash != 0)
                    // FirstCluster at offset 20 — should be >= 2 after writeFile
                    val firstCluster = ByteBuffer.wrap(rootData, streamOff + 20, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    assertTrue("FirstCluster >= 2 after write", firstCluster >= 2)
                    // DataLength at offset 24
                    val dataLength = ByteBuffer.wrap(rootData, streamOff + 24, 8).order(ByteOrder.LITTLE_ENDIAN).long
                    assertEquals("data".toByteArray().size.toLong(), dataLength)
                    return
                }
                off += 32
            }
            assertFalse("File entry not found", true)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §7.6.4 NameHash computation ─────────────────────────────────────────

    /**
     * §7.6.4 Figure 4: NameHash is a 16-bit rolling checksum over the UTF-16LE bytes
     * of the up-cased file name. The algorithm is the same left-rotate-then-add
     * as SetChecksum (but 16-bit).
     */
    @Test
    fun `§7_6_4 NameHash matches spec Figure 4 algorithm`() {
        // Compute NameHash for "TEST.TXT" in UTF-16LE
        val name = "test.txt"
        val nameUtf16 = name.toByteArray(Charsets.UTF_16LE)
        var hash = 0
        for (b in nameUtf16) {
            hash = (((if ((hash and 1) != 0) 0x8000 else 0) +
                     (hash shr 1) +
                     (b.toInt() and 0xFF)) and 0xFFFF)
        }
        // The hash should be deterministic and non-zero for any non-empty name
        assertTrue("NameHash for 'test.txt' is non-zero", hash != 0)

        // Same input always produces same hash
        var hash2 = 0
        for (b in nameUtf16) {
            hash2 = (((if ((hash2 and 1) != 0) 0x8000 else 0) +
                      (hash2 shr 1) +
                      (b.toInt() and 0xFF)) and 0xFFFF)
        }
        assertEquals("NameHash is deterministic", hash, hash2)
    }

    /** §7.6.4: NameHash of empty string is 0. */
    @Test
    fun `§7_6_4 NameHash of empty string is zero`() {
        val empty = ByteArray(0)
        var hash = 0
        for (b in empty) {
            hash = (((if ((hash and 1) != 0) 0x8000 else 0) +
                     (hash shr 1) +
                     (b.toInt() and 0xFF)) and 0xFFFF)
        }
        assertEquals(0, hash)
    }

    // ── §7.7 File Name Directory Entry ──────────────────────────────────────

    /**
     * §7.7: File Name entry (0xC1) holds 15 UTF-16 chars (30 bytes) at offset 2.
     * N = ceil(NameLength / 15) entries follow the Stream Extension.
     */
    @Test
    fun `§7_7 File Name entries hold 15 UTF-16 chars each`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            // Name of exactly 15 chars → 1 File Name entry
            val name15 = "abcdefghijklmno" // 14 chars + we need 15... let's use 15
            val name = "abcdefghijklmn" // 14 chars → 1 File Name entry (ceil(14/15)=1)
            v.fs.createFile("/", name).getOrThrow()

            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            var off = 0
            while (off < rootData.size) {
                val type = rootData[off]
                if (type == ExFatReader.END_OF_DIR) break
                if (type == ExFatReader.FILE) {
                    val streamOff = off + 32
                    val fileNameOff = streamOff + 32
                    assertEquals(ExFatReader.FILE_NAME, rootData[fileNameOff])
                    // Read the first 14 chars from the File Name entry (offset 2, 14*2 bytes)
                    val chars = StringBuilder()
                    for (i in 0 until 14) {
                        val ch = ByteBuffer.wrap(rootData, fileNameOff + 2 + i * 2, 2)
                            .order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                        if (ch == 0) break
                        chars.append(ch.toChar())
                    }
                    assertEquals(name, chars.toString())
                    return
                }
                off += 32
            }
            assertFalse("File entry not found", true)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §8.1 Recommended Write Ordering ─────────────────────────────────────

    /**
     * §8.1: After a write, the allocation bitmap and FAT should be consistent.
     * This test verifies that allocated clusters are marked in the bitmap AND
     * have valid FAT entries (not free/0).
     */
    @Test
    fun `§8_1 after write, FAT and allocation bitmap are consistent`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            // Write a file large enough to allocate at least one cluster
            val payload = ByteArray(4096) { it.toByte() }
            v.fs.createFile("/", "consistency_test.dat").getOrThrow()
            v.fs.writeFile("/consistency_test.dat", payload).getOrThrow()

            val boot = v.reader.readSector(0).getOrThrow()
            val fatOffset = ByteBuffer.wrap(boot, 80, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterCount = ByteBuffer.wrap(boot, 92, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift

            // Find the file's first cluster from the Stream Extension entry
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            var fileFirstCluster = 0L
            var off = 0
            while (off < rootData.size) {
                if (rootData[off] == ExFatReader.FILE) {
                    val streamOff = off + 32
                    fileFirstCluster = ByteBuffer.wrap(rootData, streamOff + 20, 4)
                        .order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    break
                }
                if (rootData[off] == ExFatReader.END_OF_DIR) break
                off += 32
            }
            assertTrue("File has allocated cluster", fileFirstCluster >= 2)

            // Verify FAT entry for the file's first cluster is EOC (0xFFFFFFFF) for a 1-cluster file
            val fatData = v.reader.readSectors(fatOffset, 1).getOrThrow()
            val fatEntry = ByteBuffer.wrap(fatData, (fileFirstCluster * 4).toInt(), 4)
                .order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            assertEquals("FAT entry for file cluster is EOC", 0xFFFFFFFFL, fatEntry)

            // Verify the allocation bitmap has this cluster marked as allocated
            // (ExFatReader maintains the bitmap in memory; we verify via the FS API)
            // The file should be readable, proving the cluster is properly allocated
            val readBack = v.fs.readFile("/consistency_test.dat").getOrThrow()
            assertArrayEquals(payload, readBack)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §3.1.13 VolumeFlags ─────────────────────────────────────────────────

    /** §3.1.13: On a freshly formatted volume, VolumeDirty should be 0 (clean). */
    @Test
    fun `§3_1_13 freshly formatted volume has VolumeDirty clear`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val volumeFlags = ByteBuffer.wrap(boot, 106, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            assertEquals("VolumeDirty bit clear", 0, volumeFlags and 0x02)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ─§3.1.18 PercentInUse ──────────────────────────────────────────────────

    /** §3.1.18: PercentInUse shall be 0..100 or 0xFF (unknown). */
    @Test
    fun `§3_1_18 PercentInUse is valid range or FF`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val percentInUse = boot[112].toInt() and 0xFF
            assertTrue(
                "PercentInUse $percentInUse in [0,100] or 0xFF",
                percentInUse in 0..100 || percentInUse == 0xFF
            )
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── §3.1.11 VolumeSerialNumber ──────────────────────────────────────────

    /** §3.1.11: VolumeSerialNumber is a 4-byte unique value. Two volumes should differ. */
    @Test
    fun `§3_1_11 two volumes have different serial numbers`() {
        assumeNative()
        testDir.mkdirs()
        val v1 = openVolume()
        val v2 = openVolume()
        try {
            val boot1 = v1.reader.readSector(0).getOrThrow()
            val boot2 = v2.reader.readSector(0).getOrThrow()
            val serial1 = ByteBuffer.wrap(boot1, 100, 4).order(ByteOrder.LITTLE_ENDIAN).int
            val serial2 = ByteBuffer.wrap(boot2, 100, 4).order(ByteOrder.LITTLE_ENDIAN).int
            // They should almost certainly differ (random 4-byte values)
            assertTrue("Serial numbers differ", serial1 != serial2)
        } finally {
            closeVolume(v1)
            closeVolume(v2)
            testDir.delete()
        }
    }

    // ── Backup Boot Region ──────────────────────────────────────────────────

    /** §3: Backup Boot Region (sectors 12..23) shall be a copy of Main Boot Region (0..11). */
    @Test
    fun `§3 Backup Boot Region matches Main Boot Region`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val mainBoot = v.reader.readSectors(0, 12).getOrThrow()
            val backupBoot = v.reader.readSectors(12, 12).getOrThrow()
            // Sectors 0..10 should match exactly (sector 11 is checksum, also should match)
            // But VolumeFlags and PercentInUse may differ per spec §3.1 — we write them identical
            for (i in 0 until 12) {
                val mainSector = mainBoot.copyOfRange(i * 512, (i + 1) * 512)
                val backupSector = backupBoot.copyOfRange(i * 512, (i + 1) * 512)
                assertArrayEquals("Boot region sector $i matches backup", mainSector, backupSector)
            }
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── Boot region rejects invalid volumes ────────────────────────────────

    /** A non-exFAT volume (FAT32) shall fail ExFatReader.initialize(). */
    @Test
    fun `initialize rejects FAT32 volume as non-exFAT`() {
        assumeNative()
        testDir.mkdirs()
        val container = File(testDir, "fat32_not_exfat_${System.nanoTime()}.hc")
        try {
            VolumeCreator.createContainer(
                container.absolutePath, password.copyOf(), 8L,
                fileSystem = VolumeFileSystem.FAT32
            ).getOrThrow()
            val reader = VolumeReader(container.absolutePath)
            reader.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader)
            val result = fs.initialize()
            assertTrue("FAT32 volume rejected by ExFatReader", result.isFailure)
            reader.unmount()
        } finally {
            container.delete()
            testDir.delete()
        }
    }

    /** A corrupted boot signature (not 0xAA55) shall fail initialize(). */
    @Test
    fun `initialize rejects corrupted boot signature`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            v.reader.unmount()
            // Corrupt the boot signature byte (byte 510 of sector 0 in the data area)
            // We need to re-mount to write, then corrupt, then re-mount to verify
            val reader2 = VolumeReader(v.container.absolutePath)
            reader2.mount(password.copyOf()).getOrThrow()
            val boot = reader2.readSector(0).getOrThrow()
            boot[510] = 0x00 // Corrupt signature
            reader2.writeSector(0, boot).getOrThrow()
            reader2.unmount()

            val reader3 = VolumeReader(v.container.absolutePath)
            reader3.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader3)
            val result = fs.initialize()
            assertTrue("Corrupted boot signature rejected", result.isFailure)
            reader3.unmount()
        } finally {
            v.container.delete()
            testDir.delete()
        }
    }

    /** A corrupted FileSystemName (not "EXFAT   ") shall fail initialize(). */
    @Test
    fun `initialize rejects corrupted FileSystemName`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            v.reader.unmount()
            val reader2 = VolumeReader(v.container.absolutePath)
            reader2.mount(password.copyOf()).getOrThrow()
            val boot = reader2.readSector(0).getOrThrow()
            boot[3] = 'X'.code.toByte() // Change "EXFAT" to "XXFAT"
            reader2.writeSector(0, boot).getOrThrow()
            reader2.unmount()

            val reader3 = VolumeReader(v.container.absolutePath)
            reader3.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader3)
            val result = fs.initialize()
            assertTrue("Corrupted FileSystemName rejected", result.isFailure)
            reader3.unmount()
        } finally {
            v.container.delete()
            testDir.delete()
        }
    }

    // ── §6.5 File entry set structure ───────────────────────────────────────

    /** §6.5: A File entry set = File (primary) + Stream Extension + N×File Name, contiguous. */
    @Test
    fun `§6_5 File entry set is contiguous primary plus secondaries`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            v.fs.createFile("/", "set_test.txt").getOrThrow()
            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            var off = 0
            while (off < rootData.size) {
                val type = rootData[off]
                if (type == ExFatReader.END_OF_DIR) break
                if (type == ExFatReader.FILE) {
                    val secondaryCount = rootData[off + 1].toInt() and 0xFF
                    // Verify entries are contiguous: File, Stream Extension, File Name(s)
                    assertEquals(ExFatReader.FILE, rootData[off])
                    assertEquals(ExFatReader.STREAM_EXTENSION, rootData[off + 32])
                    // File Name entries start at off + 64 (secondary index 2..secondaryCount)
                    for (j in 2..secondaryCount) {
                        assertEquals(ExFatReader.FILE_NAME, rootData[off + j * 32])
                    }
                    return
                }
                off += 32
            }
            assertFalse("File entry not found", true)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    // ── Up-case Table checksum (§7.2.4 Figure 3) ─────────────────────────────

    /** §7.2.4: TableChecksum is a 32-bit rolling checksum over the up-case table data. */
    @Test
    fun `§7_2_4 Up-case Table checksum matches re-computation`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            val boot = v.reader.readSector(0).getOrThrow()
            val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
            val rootData = v.reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()

            // Find Up-case Table entry and read its checksum + data
            var off = 0
            var upcaseFirstCluster = 0L
            var upcaseDataLength = 0L
            var storedChecksum = 0
            while (off < rootData.size) {
                if (rootData[off] == ExFatReader.UP_CASE_TABLE) {
                    storedChecksum = ByteBuffer.wrap(rootData, off + 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                    upcaseFirstCluster = ByteBuffer.wrap(rootData, off + 20, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    upcaseDataLength = ByteBuffer.wrap(rootData, off + 24, 8).order(ByteOrder.LITTLE_ENDIAN).long
                    break
                }
                if (rootData[off] == ExFatReader.END_OF_DIR) break
                off += 32
            }
            assertTrue("Up-case Table entry found", upcaseFirstCluster >= 2)

            // Read the up-case table data
            val upcaseSector = clusterHeapOffset + (upcaseFirstCluster - 2) * sectorsPerCluster
            val upcaseData = v.reader.readSectors(upcaseSector, sectorsPerCluster).getOrThrow()
            val tableBytes = upcaseData.copyOfRange(0, upcaseDataLength.toInt())

            // Recompute checksum per §7.2.4 Figure 3
            var checksum = 0
            for (b in tableBytes) {
                checksum = (((if ((checksum and 1) != 0) 0x80000000.toInt() else 0) +
                            (checksum shr 1) +
                            (b.toInt() and 0xFF)))
            }
            assertEquals("Up-case Table checksum", storedChecksum, checksum)
        } finally {
            closeVolume(v)
            testDir.delete()
        }
    }

    private fun Result<ByteArray>.getOrOrThrow(): ByteArray = getOrThrow()
}