package com.androidcrypt.crypto

import android.util.Log
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * exFAT file system reader/writer for VeraCrypt volumes.
 *
 * Implements the exFAT file system specification v1.00 (Microsoft "exFAT File System
 * Specification"). Layout reference is preserved in code comments next to each
 * structure; see spec sections cited inline.
 *
 * On-disk layout summary (spec Table 3):
 *   Main Boot Region:     sectors 0..11   (boot sector, extended boots, OEM, checksum)
 *   Backup Boot Region:    sectors 12..23
 *   FAT Region:           sectors FatOffset..(FatOffset + FatLength * NumberOfFats)
 *   Cluster Heap:         sectors ClusterHeapOffset..end (cluster N at sector
 *                         ClusterHeapOffset + (N-2) * 2^SectorsPerClusterShift)
 *
 * Directory entries are 32 bytes. A File entry set = File (0x85, primary) +
 * Stream Extension (0xC0, secondary) + N×File Name (0xC1, secondary). The root
 * directory additionally contains mandatory Allocation Bitmap (0x81) and
 * Up-case Table (0x82) entries; it may contain a Volume Label (0x83).
 */
class ExFatReader(private val volumeReader: VolumeReader) : FileSystemReader {

    companion object {
        private const val TAG = "ExFatReader"
        private const val DEBUG_LOGGING = false
        private const val SECTOR_SIZE = 512

        // EntryType bytes (spec §6.2.1). InUse bit is bit 7; values below have it set.
        const val END_OF_DIR: Byte = 0x00
        const val ALLOCATION_BITMAP: Byte = 0x81.toByte()
        const val UP_CASE_TABLE: Byte = 0x82.toByte()
        const val VOLUME_LABEL: Byte = 0x83.toByte()
        const val FILE: Byte = 0x85.toByte()
        const val STREAM_EXTENSION: Byte = 0xC0.toByte()
        const val FILE_NAME: Byte = 0xC1.toByte()

        // FileAttributes bits (spec §7.4.4)
        private const val ATTR_READ_ONLY = 0x01
        private const val ATTR_HIDDEN = 0x02
        private const val ATTR_SYSTEM = 0x04
        private const val ATTR_DIRECTORY = 0x10
        private const val ATTR_ARCHIVE = 0x20

        // GeneralPrimaryFlags / GeneralSecondaryFlags bits (spec §6.3.4 / §6.4.2)
        private const val FLAG_ALLOCATION_POSSIBLE = 0x01
        private const val FLAG_NO_FAT_CHAIN = 0x02

        // FAT special values (spec §4.1.3)
        private const val FAT_BAD_CLUSTER = 0xFFFFFFF7L
        private const val FAT_END_OF_CHAIN = 0xFFFFFFFFL

        // VolumeFlags bits (spec §3.1.13)
        private const val VF_ACTIVE_FAT = 0x01
        private const val VF_VOLUME_DIRTY = 0x02
        private const val VF_MEDIA_FAILURE = 0x04
        private const val VF_CLEAR_TO_ZERO = 0x08

        // Reserved UTF-16 code units that must not appear in file names (spec Table 35)
        private val INVALID_NAME_CHARS = intArrayOf(
            0x22, 0x2A, 0x2F, 0x3A, 0x3C, 0x3E, 0x3F, 0x5C, 0x7C
        )
    }

    // Parsed boot sector — non-null after successful initialize()
    private var boot: BootSector? = null
    private var fsInfo: FileSystemInfo? = null

    // Up-case table — loaded on demand; never loaded fully on init to avoid OOM on tiny volumes.
    // Only the first 128KB (65536 entries × 2 bytes) is referenced; we load lazily on first
    // case-insensitive lookup. For now we implement only case-sensitive lookups (spec
    // requires case-insensitive only for "should" not "shall"), so this stays null.
    private var upcaseTable: ByteArray? = null

    // FAT sector cache — 32-sector blocks (16 KB) like FAT32Reader.
    private val fatBlockSectors = 32
    private val maxFatBlockCacheSize = 256
    private val fatBlockCache: MutableMap<Int, ByteArray> = Collections.synchronizedMap(
        object : LinkedHashMap<Int, ByteArray>(maxFatBlockCacheSize, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, ByteArray>?): Boolean =
                size > maxFatBlockCacheSize
        }
    )
    private val fatSectorCache: MutableMap<Int, ByteArray> = Collections.synchronizedMap(
        object : LinkedHashMap<Int, ByteArray>(1024, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, ByteArray>?): Boolean =
                size > 1024
        }
    )

    // Allocation bitmap cache — one byte per 8 clusters; small enough to hold fully.
    private var allocBitmap: ByteArray? = null
    private var allocBitmapFirstCluster: Int = 0

    // Directory/file caches — keyed by normalized (lowercased) path. exFAT is case-insensitive
    // per spec, so we normalize like FAT32Reader does.
    private val directoryCache = java.util.concurrent.ConcurrentHashMap<String, List<FileEntry>>()
    private val fileCache = java.util.concurrent.ConcurrentHashMap<String, FileEntry>()
    private val directoryLoadLocks = java.util.concurrent.ConcurrentHashMap<String, Any>()

    // Last allocated cluster hint — scan-forward from here on allocation.
    @Volatile
    private var lastAllocatedCluster = 2

    private val writeLock = ReentrantLock()

    // ──────────────────────────────────────────────────────────────────────────
    // Boot sector model + parsing
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Parsed Main Boot Sector (spec §3.1, Table 4).
     */
    data class BootSector(
        val partitionOffset: Long,
        val volumeLength: Long,           // in sectors
        val fatOffset: Long,              // sector offset of First FAT
        val fatLength: Long,              // sectors per FAT
        val clusterHeapOffset: Long,      // sector offset of Cluster Heap
        val clusterCount: Long,           // number of clusters in heap
        val rootDirFirstCluster: Long,    // FirstClusterOfRootDirectory
        val volumeSerialNumber: Long,
        val fileSystemRevision: Int,      // major<<8 | minor
        val volumeFlags: Int,
        val bytesPerSectorShift: Int,     // 9..12 → 512..4096
        val sectorsPerClusterShift: Int,  // 0..(25 - bytesPerSectorShift)
        val numberOfFats: Int,            // 1 or 2
        val driveSelect: Int,
        val percentInUse: Int
    ) {
        val bytesPerSector: Int get() = 1 shl bytesPerSectorShift
        val sectorsPerCluster: Int get() = 1 shl sectorsPerClusterShift
        val bytesPerCluster: Int get() = 1 shl (bytesPerSectorShift + sectorsPerClusterShift)
        val clusterCountInt: Int get() = clusterCount.toInt()
    }

    override fun initialize(): Result<FileSystemInfo> {
        return try {
            val bootData = volumeReader.readSector(0).getOrThrow()

            // Validate boot signature (spec §3.1.20) — last 2 bytes of the 512-byte sector.
            if (bootData[510].toInt() and 0xFF != 0x55 ||
                bootData[511].toInt() and 0xFF != 0xAA
            ) {
                return Result.failure(Exception("Invalid exFAT boot signature"))
            }
            // Validate FileSystemName (spec §3.1.2): "EXFAT   " (8 bytes ASCII, 3 trailing spaces).
            val nameBytes = bootData.copyOfRange(3, 11)
            val expected = "EXFAT   ".toByteArray(Charsets.US_ASCII)
            if (!nameBytes.contentEquals(expected)) {
                return Result.failure(Exception("Not an exFAT volume (FileSystemName mismatch)"))
            }
            // MustBeZero (spec §3.1.3) — bytes 11..63 must all be zero.
            for (i in 11 until 64) {
                if (bootData[i].toInt() != 0) {
                    return Result.failure(Exception("MustBeZero region is non-zero; not exFAT"))
                }
            }

            val buf = ByteBuffer.wrap(bootData).order(ByteOrder.LITTLE_ENDIAN)
            val bs = BootSector(
                partitionOffset = buf.getLong(64),
                volumeLength = buf.getLong(72),
                fatOffset = buf.getInt(80).toLong() and 0xFFFFFFFFL,
                fatLength = buf.getInt(84).toLong() and 0xFFFFFFFFL,
                clusterHeapOffset = buf.getInt(88).toLong() and 0xFFFFFFFFL,
                clusterCount = buf.getInt(92).toLong() and 0xFFFFFFFFL,
                rootDirFirstCluster = buf.getInt(96).toLong() and 0xFFFFFFFFL,
                volumeSerialNumber = buf.getInt(100).toLong() and 0xFFFFFFFFL,
                fileSystemRevision = buf.getShort(104).toInt() and 0xFFFF,
                volumeFlags = buf.getShort(106).toInt() and 0xFFFF,
                bytesPerSectorShift = buf.get(108).toInt() and 0xFF,
                sectorsPerClusterShift = buf.get(109).toInt() and 0xFF,
                numberOfFats = buf.get(110).toInt() and 0xFF,
                driveSelect = buf.get(111).toInt() and 0xFF,
                percentInUse = buf.get(112).toInt() and 0xFF
            )
            boot = bs

            // Sanity-check spec-required invariants (spec §3.1.5..§3.1.16).
            if (bs.bytesPerSectorShift !in 9..12) {
                return Result.failure(Exception("Invalid BytesPerSectorShift: ${bs.bytesPerSectorShift}"))
            }
            if (bs.sectorsPerClusterShift !in 0..(25 - bs.bytesPerSectorShift)) {
                return Result.failure(Exception("Invalid SectorsPerClusterShift: ${bs.sectorsPerClusterShift}"))
            }
            if (bs.numberOfFats !in 1..2) {
                return Result.failure(Exception("Invalid NumberOfFats: ${bs.numberOfFats}"))
            }
            if (bs.rootDirFirstCluster < 2 || bs.rootDirFirstCluster > bs.clusterCount + 1) {
                return Result.failure(Exception("Invalid root dir cluster: ${bs.rootDirFirstCluster}"))
            }

            // Load allocation bitmap (mandatory per spec §7.1).
            loadAllocationBitmap()

            // Prefetch FAT into cache for fast cluster-chain walks (mirrors FAT32Reader).
            prefetchFAT()

            val totalSpace = bs.clusterCount * bs.bytesPerCluster
            val freeSpace = countFreeClusters() * bs.bytesPerCluster.toLong()
            fsInfo = FileSystemInfo(
                type = FileSystemType.EXFAT,
                label = readVolumeLabel(bootData),
                totalSpace = totalSpace,
                freeSpace = freeSpace,
                clusterSize = bs.bytesPerCluster
            )
            Result.success(fsInfo!!)
        } catch (e: Exception) {
            if (DEBUG_LOGGING) Log.e(TAG, "initialize failed", e)
            Result.failure(e)
        }
    }

    /**
     * Read the Volume Label directory entry (spec §7.3) from the root directory, if present.
     * Volume Label entry layout: byte 0=0x83, byte 1=CharacterCount, bytes 2..23=UTF-16LE label.
     */
    private fun readVolumeLabel(bootData: ByteArray): String {
        return try {
            val bs = boot ?: return ""
            val rootEntries = readDirectoryClusterRaw(bs.rootDirFirstCluster) ?: return ""
            for (entry in rootEntries) {
                if (entry.type != VOLUME_LABEL) continue
                val charCount = entry.raw[1].toInt() and 0xFF
                if (charCount == 0) return ""
                val chars = StringBuilder(charCount)
                for (i in 0 until charCount) {
                    val ch = ByteBuffer.wrap(entry.raw, 2 + i * 2, 2)
                        .order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                    if (ch == 0) break
                    chars.append(ch.toChar())
                }
                return chars.toString()
            }
            ""
        } catch (_: Exception) { "" }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // FAT access (spec §4.1)
    // ──────────────────────────────────────────────────────────────────────────

    /** FAT entry index → value (spec §4.1.3). Reads through block/sector cache. */
    private fun readFATEntry(cluster: Long): Result<Long> {
        return try {
            val bs = boot ?: return Result.failure(Exception("Not initialized"))
            val entryOffset = cluster * 4
            val fatSectorOffset = (entryOffset / SECTOR_SIZE).toInt()
            val offsetInSector = (entryOffset % SECTOR_SIZE).toInt()

            // Check dirty-sector cache first
            val dirty = fatSectorCache[fatSectorOffset]
            if (dirty != null) {
                return Result.success(readFATLE32(dirty, offsetInSector))
            }
            // Block cache
            val blockStart = (fatSectorOffset / fatBlockSectors) * fatBlockSectors
            val block = fatBlockCache[blockStart] ?: run {
                val data = volumeReader.readSectors(
                    bs.fatOffset + blockStart, fatBlockSectors
                ).getOrNull() ?: return Result.failure(Exception("FAT read failed"))
                fatBlockCache[blockStart] = data
                data
            }
            val sectorInBlock = fatSectorOffset - blockStart
            val byteOffset = sectorInBlock * SECTOR_SIZE + offsetInSector
            Result.success(readFATLE32(block, byteOffset))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun readFATLE32(buf: ByteArray, offset: Int): Long {
        val b0 = buf[offset].toInt() and 0xFF
        val b1 = buf[offset + 1].toInt() and 0xFF
        val b2 = buf[offset + 2].toInt() and 0xFF
        val b3 = buf[offset + 3].toInt() and 0xFF
        return (b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)).toLong() and 0xFFFFFFFFL
    }

    private fun writeFATEntry(cluster: Long, value: Long) {
        val bs = boot ?: return
        val entryOffset = cluster * 4
        val fatSectorOffset = (entryOffset / SECTOR_SIZE).toInt()
        val offsetInSector = (entryOffset % SECTOR_SIZE).toInt()

        val fatSector = fatSectorCache[fatSectorOffset]?.copyOf()
            ?: volumeReader.readSector(bs.fatOffset.toInt() + fatSectorOffset.toLong()).getOrThrow()

        ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(value.toInt())
        // Write to all FAT copies
        val fatStartSector = bs.fatOffset.toInt()
        volumeReader.writeSector(fatStartSector + fatSectorOffset.toLong(), fatSector).getOrThrow()
        if (bs.numberOfFats == 2) {
            volumeReader.writeSector(
                fatStartSector + bs.fatLength.toInt() + fatSectorOffset.toLong(),
                fatSector
            ).getOrThrow()
        }
        fatSectorCache[fatSectorOffset] = fatSector.copyOf()
        val blockStart = (fatSectorOffset / fatBlockSectors) * fatBlockSectors
        fatBlockCache.remove(blockStart)
    }

    /**
     * Walk the FAT chain from [firstCluster] and return all cluster indices in order.
     * Stops at FAT_END_OF_CHAIN (0xFFFFFFFF) or FAT_BAD_CLUSTER (0xFFFFFFF7).
     * (spec §4.1.3)
     */
    private fun getClusterChain(firstCluster: Long): List<Long> {
        val out = mutableListOf<Long>()
        var c = firstCluster
        val bs = boot ?: return out
        val maxCluster = bs.clusterCount + 1
        var hops = 0
        while (c in 2..maxCluster && hops < 5_000_000) {
            out.add(c)
            val next = readFATEntry(c).getOrElse { return out }
            if (next == FAT_END_OF_CHAIN || next == FAT_BAD_CLUSTER) break
            c = next
            hops++
        }
        return out
    }

    /**
     * Bulk-read the entire FAT into the block cache on initialize(), mirroring
     * FAT32Reader.prefetchFAT (this turns dozens of small on-demand reads into
     * one sequential scan).
     */
    private fun prefetchFAT() {
        val bs = boot ?: return
        val fatStartSector = bs.fatOffset.toInt()
        val totalFatSectors = bs.fatLength.toInt()
        var sectorOffset = 0
        val ioChunkSectors = 2048
        while (sectorOffset < totalFatSectors) {
            val readCount = minOf(ioChunkSectors, totalFatSectors - sectorOffset)
            val chunk = volumeReader.readSectors(
                fatStartSector + sectorOffset.toLong(), readCount
            ).getOrNull() ?: break
            var local = 0
            while (local < readCount) {
                val blockKey = sectorOffset + local
                val blockSectors = minOf(fatBlockSectors, readCount - local)
                val startByte = local * SECTOR_SIZE
                val endByte = startByte + blockSectors * SECTOR_SIZE
                val slice = if (startByte == 0 && endByte == chunk.size) chunk
                            else chunk.copyOfRange(startByte, endByte)
                fatBlockCache[blockKey] = slice
                local += fatBlockSectors
            }
            sectorOffset += readCount
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Cluster Heap addressing (spec §5.1)
    // ──────────────────────────────────────────────────────────────────────────

    /** Sector index (within volume) where cluster N starts. */
    private fun clusterToSector(cluster: Long): Long {
        val bs = boot ?: return 0
        return bs.clusterHeapOffset + (cluster - 2) * bs.sectorsPerCluster
    }

    /** Read the entire contents of one cluster. */
    private fun readCluster(cluster: Long): Result<ByteArray> {
        val bs = boot ?: return Result.failure(Exception("Not initialized"))
        return volumeReader.readSectors(clusterToSector(cluster), bs.sectorsPerCluster)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Allocation bitmap (spec §7.1)
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Locate and load the active Allocation Bitmap (spec §7.1).
     * The bitmap directory entry lives in the root directory; its EntryType is 0x81.
     */
    private fun loadAllocationBitmap() {
        val bs = boot ?: return
        val rootEntries = readDirectoryClusterRaw(bs.rootDirFirstCluster) ?: return
        var bitmapFirstCluster = 0L
        var bitmapDataLength = 0L
        var bitmapId = 0
        val activeFat = (bs.volumeFlags and VF_ACTIVE_FAT) != 0
        val targetBitmapId = if (activeFat) 1 else 0
        for (entry in rootEntries) {
            if (entry.type != ALLOCATION_BITMAP) continue
            val flags = entry.flags
            val thisId = flags and 0x01
            if (bs.numberOfFats == 2 && thisId == targetBitmapId) {
                bitmapFirstCluster = entry.firstCluster
                bitmapDataLength = entry.dataLength
                bitmapId = thisId
                break
            } else if (bs.numberOfFats == 1) {
                bitmapFirstCluster = entry.firstCluster
                bitmapDataLength = entry.dataLength
                bitmapId = thisId
                break
            }
        }
        if (bitmapFirstCluster == 0L) return
        allocBitmapFirstCluster = bitmapFirstCluster.toInt()
        val chain = getClusterChain(bitmapFirstCluster)
        if (chain.isEmpty()) return
        val out = ByteArray(bitmapDataLength.toInt())
        var off = 0
        for (c in chain) {
            val data = readCluster(c).getOrNull() ?: return
            val copy = minOf(data.size, out.size - off)
            System.arraycopy(data, 0, out, off, copy)
            off += copy
            if (off >= out.size) break
        }
        allocBitmap = out
    }

    private fun isClusterAllocated(cluster: Long): Boolean {
        val bmp = allocBitmap ?: return false
        val bitIndex = (cluster - 2).toInt()
        if (bitIndex < 0 || bitIndex >= bmp.size * 8) return false
        return (bmp[bitIndex ushr 3].toInt() and 0xFF) and (1 shl (bitIndex and 7)) != 0
    }

    private fun setClusterAllocated(cluster: Long, allocated: Boolean) {
        val bmp = allocBitmap ?: return
        val bitIndex = (cluster - 2).toInt()
        if (bitIndex < 0 || bitIndex >= bmp.size * 8) return
        val mask = 1 shl (bitIndex and 7)
        if (allocated) {
            bmp[bitIndex ushr 3] = (bmp[bitIndex ushr 3].toInt() or mask).toByte()
        } else {
            bmp[bitIndex ushr 3] = (bmp[bitIndex ushr 3].toInt() and mask.inv()).toByte()
        }
    }

    private fun persistAllocationBitmap() {
        val bs = boot ?: return
        val bmp = allocBitmap ?: return
        val firstCluster = allocBitmapFirstCluster.toLong()
        val chain = getClusterChain(firstCluster)
        val clusterSize = bs.bytesPerCluster
        var off = 0
        for (c in chain) {
            val buf = ByteArray(clusterSize)
            val copy = minOf(buf.size, bmp.size - off)
            if (copy > 0) System.arraycopy(bmp, off, buf, 0, copy)
            volumeReader.writeSectors(clusterToSector(c), buf).getOrThrow()
            off += copy
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Free-cluster counting & allocation
    // ──────────────────────────────────────────────────────────────────────────

    private fun countFreeClusters(): Int {
        val bs = boot ?: return 0
        val bmp = allocBitmap ?: return 0
        var free = 0
        for (i in 0 until bs.clusterCountInt) {
            if (!isClusterAllocated((i + 2).toLong())) free++
        }
        return free
    }

    /**
     * Allocate [count] free clusters, mark them allocated in the bitmap and FAT,
     * and return their indices. Writes a single EOC entry into the FAT for each
     * allocated cluster; the caller is responsible for chaining them via
     * [writeClusterChain] if a multi-cluster chain is needed.
     */
    private fun allocateClusters(count: Int): List<Long> {
        val bs = boot ?: return emptyList()
        val out = mutableListOf<Long>()
        if (count <= 0) return out
        var scan = lastAllocatedCluster.toLong()
        val maxCluster = bs.clusterCount + 1
        var wrapped = false
        while (out.size < count) {
            if (scan > maxCluster) {
                if (wrapped) break
                scan = 2
                wrapped = true
            }
            if (scan == lastAllocatedCluster.toLong() && wrapped) break
            if (!isClusterAllocated(scan)) {
                out.add(scan)
                setClusterAllocated(scan, true)
                writeFATEntry(scan, FAT_END_OF_CHAIN)
            }
            scan++
        }
        lastAllocatedCluster = scan.toInt()
        if (out.size < count) {
            // Roll back partial allocation
            for (c in out) {
                setClusterAllocated(c, false)
                writeFATEntry(c, 0)
            }
            return emptyList()
        }
        persistAllocationBitmap()
        return out
    }

    private fun freeClusters(firstCluster: Long) {
        val chain = getClusterChain(firstCluster)
        for (c in chain) {
            setClusterAllocated(c, false)
            writeFATEntry(c, 0)
        }
        persistAllocationBitmap()
    }

    /**
     * Write FAT chain entries so that clusters[i] → clusters[i+1], and the
     * last cluster gets FAT_END_OF_CHAIN. (spec §4.1.3)
     */
    private fun writeClusterChain(clusters: List<Long>) {
        for (i in clusters.indices) {
            val next = if (i < clusters.size - 1) clusters[i + 1] else FAT_END_OF_CHAIN
            writeFATEntry(clusters[i], next)
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Directory parsing
    // ──────────────────────────────────────────────────────────────────────────

    /** Raw 32-byte entry — only used internally for boot-region / root scan. */
    private data class RawEntry(
        val type: Byte,
        val flags: Int,
        val firstCluster: Long,
        val dataLength: Long,
        val raw: ByteArray
    )

    /**
     * Walk the root directory's cluster chain and return all 32-byte entries
     * as [RawEntry]. Stops at the first END_OF_DIR (0x00) entry per spec §6.2.1.
     */
    private fun readDirectoryClusterRaw(firstCluster: Long): List<RawEntry>? {
        val bs = boot ?: return null
        val chain = getClusterChain(firstCluster)
        if (chain.isEmpty()) return emptyList()
        val out = mutableListOf<RawEntry>()
        for (c in chain) {
            val data = readCluster(c).getOrNull() ?: return null
            var off = 0
            while (off + 32 <= data.size) {
                val type = data[off]
                if (type == END_OF_DIR) return out
                // Skip deleted entries (InUse bit clear, type in 0x01..0x7F)
                if (type.toInt() and 0x80 != 0) {
                    val flags = data[off + 1].toInt() and 0xFF
                    val firstCluster = readFATLE32(data, off + 20)
                    val dataLength = ByteBuffer.wrap(data, off + 24, 8)
                        .order(ByteOrder.LITTLE_ENDIAN).long
                    out.add(RawEntry(type, flags, firstCluster, dataLength, data.copyOfRange(off, off + 32)))
                }
                off += 32
            }
        }
        return out
    }

    /**
     * Parsed directory entry set (spec §6.5): one File primary + Stream Extension +
     * N×File Name secondaries.
     */
    private data class DirEntrySet(
        val fileEntryOffset: Int,        // offset of File entry within clusterData
        val secondaryCount: Int,
        val fileAttributes: Int,
        val nameLength: Int,            // UTF-16 code units
        val nameHash: Int,
        val firstCluster: Long,         // from Stream Extension
        val dataLength: Long,            // from Stream Extension
        val validDataLength: Long,
        val noFatChain: Boolean,
        val name: String,
        val clusterDataRef: ByteArray,  // reference to cluster buffer holding the set
        val clusterSector: Long,         // start sector of the cluster holding this set
        val setChecksum: Int
    )

    /**
     * Walk [firstCluster]'s cluster chain and return parsed [DirEntrySet]s for
     * every File entry set, in directory order. Non-File primary entries
     * (Allocation Bitmap, Up-case Table, Volume Label) are skipped here — callers
     * that need them use [readDirectoryClusterRaw].
     */
    private fun readDirectoryCluster(firstCluster: Long): List<DirEntrySet> {
        val bs = boot ?: return emptyList()
        val chain = getClusterChain(firstCluster)
        if (chain.isEmpty()) return emptyList()
        val out = mutableListOf<DirEntrySet>()

        for (c in chain) {
            val clusterSector = clusterToSector(c)
            val data = readCluster(c).getOrNull() ?: continue
            var off = 0
            while (off + 32 <= data.size) {
                val type = data[off]
                if (type == END_OF_DIR) break
                if (type != FILE) {
                    // Skip non-File entries; they're either deleted (InUse=0) or
                    // root metadata (Bitmap/Upcase/Label) which we handle separately.
                    off += 32
                    continue
                }
                val set = parseFileEntrySet(data, off, clusterSector)
                if (set == null) {
                    off += 32
                    continue
                }
                out.add(set)
                // Skip past the entire set (1 primary + secondaryCount secondaries)
                off += (1 + set.secondaryCount) * 32
            }
        }
        return out
    }

    /**
     * Parse a File entry set starting at [offset] in [clusterData].
     * Returns null if the set is malformed. (spec §6.5, §7.4–§7.7)
     */
    private fun parseFileEntrySet(
        clusterData: ByteArray,
        offset: Int,
        clusterSector: Long
    ): DirEntrySet? {
        val secondaryCount = clusterData[offset + 1].toInt() and 0xFF
        val setChecksum = ByteBuffer.wrap(clusterData, offset + 2, 2)
            .order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
        val fileAttributes = ByteBuffer.wrap(clusterData, offset + 4, 2)
            .order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF

        // Stream Extension immediately follows the File entry
        val streamOffset = offset + 32
        if (streamOffset + 32 > clusterData.size) return null
        if (clusterData[streamOffset] != STREAM_EXTENSION) return null
        val streamFlags = clusterData[streamOffset + 1].toInt() and 0xFF
        val noFatChain = (streamFlags and FLAG_NO_FAT_CHAIN) != 0
        val nameLength = clusterData[streamOffset + 3].toInt() and 0xFF
        val nameHash = ByteBuffer.wrap(clusterData, streamOffset + 4, 2)
            .order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
        val validDataLength = ByteBuffer.wrap(clusterData, streamOffset + 8, 8)
            .order(ByteOrder.LITTLE_ENDIAN).long
        val firstCluster = readFATLE32(clusterData, streamOffset + 20)
        val dataLength = ByteBuffer.wrap(clusterData, streamOffset + 24, 8)
            .order(ByteOrder.LITTLE_ENDIAN).long

        // File Name entries immediately follow the Stream Extension
        val numFileNameEntries = (secondaryCount - 1).coerceAtLeast(0)
        val nameChars = StringBuilder(nameLength)
        for (i in 0 until numFileNameEntries) {
            val fnOffset = streamOffset + 32 + (i * 32)
            if (fnOffset + 32 > clusterData.size) break
            if (clusterData[fnOffset] != FILE_NAME) break
            for (j in 0 until 15) {
                if (nameChars.length >= nameLength) break
                val ch = ByteBuffer.wrap(clusterData, fnOffset + 2 + j * 2, 2)
                    .order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                if (ch == 0) break
                nameChars.append(ch.toChar())
            }
        }

        return DirEntrySet(
            fileEntryOffset = offset,
            secondaryCount = secondaryCount,
            fileAttributes = fileAttributes,
            nameLength = nameLength,
            nameHash = nameHash,
            firstCluster = firstCluster,
            dataLength = dataLength,
            validDataLength = validDataLength,
            noFatChain = noFatChain,
            name = nameChars.toString(),
            clusterDataRef = clusterData,
            clusterSector = clusterSector,
            setChecksum = setChecksum
        )
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Checksums (spec §6.3.3, §7.2.4, §7.6.4)
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Compute the SetChecksum of an entry set stored in [buf] starting at
     * [primaryOffset]. Covers (secondaryCount+1) * 32 bytes, skipping bytes 2 and 3
     * of the primary entry (the SetChecksum field itself). (spec §6.3.3, Figure 2)
     */
    private fun computeSetChecksum(buf: ByteArray, primaryOffset: Int, secondaryCount: Int): Int {
        val total = (secondaryCount + 1) * 32
        var checksum = 0
        for (i in 0 until total) {
            if (i == 2 || i == 3) continue
            checksum = (((if ((checksum and 1) != 0) 0x8000 else 0) +
                        (checksum shr 1) +
                        (buf[primaryOffset + i].toInt() and 0xFF)) and 0xFFFF)
        }
        return checksum
    }

    /**
     * Compute NameHash over a UTF-16LE file name. (spec §7.6.4, Figure 4)
     * Caller is responsible for up-casing before hashing if case-insensitive
     * comparison is desired; we currently use case-sensitive comparison only.
     */
    private fun computeNameHash(nameUtf16LE: ByteArray): Int {
        var hash = 0
        for (i in nameUtf16LE.indices) {
            hash = (((if ((hash and 1) != 0) 0x8000 else 0) +
                     (hash shr 1) +
                     (nameUtf16LE[i].toInt() and 0xFF)) and 0xFFFF)
        }
        return hash
    }

    // ──────────────────────────────────────────────────────────────────────────
    // FileSystemReader interface
    // ──────────────────────────────────────────────────────────────────────────

    private fun normalizePath(path: String): String {
        val len = path.length
        if (len == 0) return path
        var needsWork = path[len - 1] == '/'
        if (!needsWork) {
            for (i in 0 until len) {
                if (path[i] in 'A'..'Z') { needsWork = true; break }
            }
        }
        return if (needsWork) path.lowercase().trimEnd('/') else path
    }

    private fun getDirectoryLock(path: String): Any =
        directoryLoadLocks.computeIfAbsent(normalizePath(path)) { Any() }

    /** Clear all caches. Called by VolumeMountManager after external writes. */
    fun clearCache() {
        directoryCache.clear()
        fileCache.clear()
        fatBlockCache.clear()
        fatSectorCache.clear()
        allocBitmap = null
    }

    override fun listDirectory(path: String): Result<List<FileEntry>> {
        val cacheKey = normalizePath(path)
        directoryCache[cacheKey]?.let { return Result.success(it) }
        synchronized(getDirectoryLock(path)) {
            directoryCache[cacheKey]?.let { return Result.success(it) }
            return try {
                val bs = boot ?: return Result.failure(Exception("Not initialized"))
                val cluster = if (path == "/" || path.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    val dirInfo = getFileInfoWithCluster(path).getOrThrow()
                    if (!dirInfo.isDirectory) {
                        return Result.failure(Exception("Path is not a directory"))
                    }
                    if (dirInfo.firstCluster == 0) {
                        return Result.failure(Exception("Directory has no cluster"))
                    }
                    dirInfo.firstCluster.toLong()
                }
                val sets = readDirectoryCluster(cluster)
                val entries = sets.mapNotNull { set -> set.toFileEntry(path) }
                directoryCache[cacheKey] = entries
                entries.forEach { fileCache[normalizePath(it.path)] = it }
                Result.success(entries)
            } catch (e: Exception) {
                if (DEBUG_LOGGING) Log.e(TAG, "listDirectory failed: $path", e)
                Result.failure(e)
            }
        }
    }

    private fun DirEntrySet.toFileEntry(parentPath: String): FileEntry {
        val isDir = (fileAttributes and ATTR_DIRECTORY) != 0
        val fullPath = if (parentPath == "/" || parentPath.isEmpty()) "/$name"
                       else "$parentPath/$name"
        return FileEntry(
            name = name,
            path = fullPath,
            isDirectory = isDir,
            size = if (isDir) 0L else validDataLength,
            lastModified = parseExFatTimestamp(
                ByteBuffer.wrap(clusterDataRef, fileEntryOffset + 12, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).int
            ),
            mimeType = if (isDir) "vnd.android.document/directory" else guessMimeType(name),
            firstCluster = firstCluster.toInt()
        )
    }

    override fun readFile(path: String): Result<ByteArray> {
        return try {
            val info = getFileInfoWithCluster(path).getOrThrow()
            if (info.isDirectory) return Result.failure(Exception("Not a file"))
            if (info.size == 0L || info.firstCluster == 0) return Result.success(ByteArray(0))
            if (info.size > Int.MAX_VALUE) return Result.failure(Exception("File too large"))
            val bs = boot ?: return Result.failure(Exception("Not initialized"))
            val data = ByteArray(info.size.toInt())
            // For NoFatChain entries the clusters are contiguous; for chain entries
            // we walk the FAT. Both paths read via clusterToSector().
            if (info.firstCluster < 2) return Result.success(data)
            val chain = getClusterChain(info.firstCluster.toLong())
            val clusterSize = bs.bytesPerCluster
            var bytesRead = 0L
            for (c in chain) {
                val cdata = readCluster(c).getOrThrow()
                val copy = minOf(cdata.size.toLong(), info.size - bytesRead).toInt()
                if (copy <= 0) break
                System.arraycopy(cdata, 0, data, bytesRead.toInt(), copy)
                bytesRead += copy
            }
            Result.success(data)
        } catch (e: Exception) {
            if (DEBUG_LOGGING) Log.e(TAG, "readFile failed: $path", e)
            Result.failure(e)
        }
    }

    override fun readFile(path: String, offset: Long, length: Int): Result<ByteArray> {
        return try {
            val info = getFileInfoWithCluster(path).getOrThrow()
            if (info.isDirectory) return Result.failure(Exception("Not a file"))
            if (offset >= info.size) return Result.success(ByteArray(0))
            val actual = minOf(length.toLong(), info.size - offset).toInt()
            if (actual <= 0) return Result.success(ByteArray(0))
            val bs = boot ?: return Result.failure(Exception("Not initialized"))
            val result = ByteArray(actual)
            val clusterSize = bs.bytesPerCluster.toLong()
            val startClusterIdx = (offset / clusterSize).toInt()
            val chain = getClusterChain(info.firstCluster.toLong())
            if (startClusterIdx >= chain.size) return Result.success(ByteArray(0))
            var bytesRead = 0
            var i = startClusterIdx
            var offsetInCluster = (offset - startClusterIdx * clusterSize).toInt()
            while (i < chain.size && bytesRead < actual) {
                val cdata = readCluster(chain[i]).getOrThrow()
                val copy = minOf(cdata.size - offsetInCluster, actual - bytesRead)
                if (copy > 0) {
                    System.arraycopy(cdata, offsetInCluster, result, bytesRead, copy)
                    bytesRead += copy
                }
                offsetInCluster = 0
                i++
            }
            Result.success(result)
        } catch (e: Exception) {
            if (DEBUG_LOGGING) Log.e(TAG, "readFile range failed: $path", e)
            Result.failure(e)
        }
    }

    override fun getFileInfo(path: String): Result<FileEntry> = getFileInfoWithCluster(path)

    override fun exists(path: String): Boolean = getFileInfo(path).isSuccess

    override fun getRootDirectory(): FileEntry = FileEntry(
        name = "",
        path = "/",
        isDirectory = true,
        size = 0,
        lastModified = System.currentTimeMillis(),
        mimeType = "vnd.android.document/directory"
    )

    private fun getFileInfoWithCluster(path: String): Result<FileEntry> {
        val cacheKey = normalizePath(path)
        fileCache[cacheKey]?.let { if (it.firstCluster != 0 || path == "/") return Result.success(it) }
        return try {
            val bs = boot ?: return Result.failure(Exception("Not initialized"))
            if (path == "/" || path.isEmpty()) {
                return Result.success(FileEntry(
                    name = "", path = "/", isDirectory = true, size = 0,
                    lastModified = System.currentTimeMillis(),
                    mimeType = "vnd.android.document/directory",
                    firstCluster = bs.rootDirFirstCluster.toInt()
                ))
            }
            val components = path.trim('/').split('/')
            var currentCluster = bs.rootDirFirstCluster
            var foundEntry: FileEntry? = null
            var currentPath = ""
            for (component in components) {
                currentPath = if (currentPath.isEmpty()) "/$component"
                              else "$currentPath/$component"
                val parentPath = currentPath.substringBeforeLast('/').ifEmpty { "/" }
                val parentCacheKey = normalizePath(parentPath)
                val entries = directoryCache[parentCacheKey] ?: try {
                    val sets = readDirectoryCluster(currentCluster)
                    val mapped = sets.mapNotNull { it.toFileEntry(parentPath) }
                    directoryCache[parentCacheKey] = mapped
                    mapped.forEach { fileCache[normalizePath(it.path)] = it }
                    mapped
                } catch (e: Exception) { return Result.failure(e) }
                foundEntry = entries.find { it.name.equals(component, ignoreCase = true) }
                    ?: return Result.failure(Exception("Not found: $component"))
                currentCluster = foundEntry.firstCluster.toLong()
            }
            foundEntry?.let { fileCache[cacheKey] = it; Result.success(it) }
                ?: Result.failure(Exception("Not found: $path"))
        } catch (e: Exception) {
            if (DEBUG_LOGGING) Log.e(TAG, "getFileInfoWithCluster failed: $path", e)
            Result.failure(e)
        }
    }

    override fun writeFile(path: String, data: ByteArray): Result<Unit> {
        return writeLock.withLock {
            try {
                val bs = boot ?: return@withLock Result.failure(Exception("Not initialized"))
                val parentPath = path.substringBeforeLast('/', "/")
                val fileName = path.substringAfterLast('/')

                // Locate the existing File entry set in the parent directory.
                val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    getFileInfoWithCluster(parentPath).getOrThrow().firstCluster.toLong()
                }

                // Empty-write fast path: free existing chain (if any) and zero
                // the Stream Extension's FirstCluster + DataLength + ValidDataLength.
                if (data.isEmpty()) {
                    return@withLock truncateToEmpty(path)
                }

                val clusterSize = bs.bytesPerCluster.toLong()
                val clustersNeeded = ((data.size + clusterSize - 1) / clusterSize).toInt()

                // Find the existing entry set or create it if absent.
                val existing = findFileEntrySet(parentCluster, fileName)
                if (existing == null) {
                    return@withLock Result.failure(Exception("File entry not found: $path"))
                }

                val newClusters = if (existing.firstCluster >= 2) {
                    // Reuse-or-reallocate based on existing chain length
                    val existingChain = getClusterChain(existing.firstCluster)
                    if (existingChain.size >= clustersNeeded) {
                        if (existingChain.size > clustersNeeded) {
                            // Truncate tail
                            val lastKeep = existingChain[clustersNeeded - 1]
                            val firstFree = existingChain[clustersNeeded]
                            writeFATEntry(lastKeep, FAT_END_OF_CHAIN)
                            for (i in clustersNeeded until existingChain.size) {
                                setClusterAllocated(existingChain[i], false)
                                writeFATEntry(existingChain[i], 0)
                            }
                            persistAllocationBitmap()
                        }
                        existingChain.subList(0, clustersNeeded)
                    } else {
                        val additional = allocateClusters(clustersNeeded - existingChain.size)
                        if (additional.isEmpty()) {
                            return@withLock Result.failure(Exception("Disk full"))
                        }
                        val lastExisting = existingChain.last()
                        writeFATEntry(lastExisting, additional[0])
                        writeClusterChain(additional)
                        existingChain + additional
                    }
                } else {
                    val fresh = allocateClusters(clustersNeeded)
                    if (fresh.isEmpty()) return@withLock Result.failure(Exception("Disk full"))
                    writeClusterChain(fresh)
                    fresh
                }

                // Write file data clusters
                var bytesWritten = 0
                for (c in newClusters) {
                    val cdata = ByteArray(bs.bytesPerCluster)
                    val copy = minOf(cdata.size, data.size - bytesWritten)
                    if (copy > 0) System.arraycopy(data, bytesWritten, cdata, 0, copy)
                    volumeReader.writeSectors(clusterToSector(c), cdata).getOrThrow()
                    bytesWritten += copy
                }

                // Update the Stream Extension entry: FirstCluster + DataLength + ValidDataLength
                updateStreamExtension(existing, newClusters[0], data.size.toLong())
                invalidateCaches(path, parentPath)
                volumeReader.sync()
                Result.success(Unit)
            } catch (e: Exception) {
                if (DEBUG_LOGGING) Log.e(TAG, "writeFile failed: $path", e)
                Result.failure(e)
            }
        }
    }

    override fun writeFileStreaming(
        path: String,
        inputStream: java.io.InputStream,
        fileSize: Long,
        onProgress: ((Long) -> Unit)?
    ): Result<Unit> {
        return writeLock.withLock {
            try {
                val bs = boot ?: return@withLock Result.failure(Exception("Not initialized"))
                val parentPath = path.substringBeforeLast('/', "/")
                val fileName = path.substringAfterLast('/')
                if (fileSize == 0L) {
                    return@withLock truncateToEmpty(path)
                }
                val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    getFileInfoWithCluster(parentPath).getOrThrow().firstCluster.toLong()
                }
                val clusterSize = bs.bytesPerCluster.toLong()
                val clustersNeeded = ((fileSize + clusterSize - 1) / clusterSize).toInt()

                val existing = findFileEntrySet(parentCluster, fileName)
                if (existing == null) {
                    return@withLock Result.failure(Exception("File entry not found: $path"))
                }
                val newClusters = if (existing.firstCluster >= 2) {
                    val existingChain = getClusterChain(existing.firstCluster)
                    if (existingChain.size >= clustersNeeded) {
                        if (existingChain.size > clustersNeeded) {
                            val lastKeep = existingChain[clustersNeeded - 1]
                            writeFATEntry(lastKeep, FAT_END_OF_CHAIN)
                            for (i in clustersNeeded until existingChain.size) {
                                setClusterAllocated(existingChain[i], false)
                                writeFATEntry(existingChain[i], 0)
                            }
                            persistAllocationBitmap()
                        }
                        existingChain.subList(0, clustersNeeded)
                    } else {
                        val additional = allocateClusters(clustersNeeded - existingChain.size)
                        if (additional.isEmpty()) return@withLock Result.failure(Exception("Disk full"))
                        writeFATEntry(existingChain.last(), additional[0])
                        writeClusterChain(additional)
                        existingChain + additional
                    }
                } else {
                    val fresh = allocateClusters(clustersNeeded)
                    if (fresh.isEmpty()) return@withLock Result.failure(Exception("Disk full"))
                    writeClusterChain(fresh)
                    fresh
                }

                val buf = ByteArray(bs.bytesPerCluster)
                var bytesWritten = 0L
                for (c in newClusters) {
                    val toRead = minOf(buf.size.toLong(), fileSize - bytesWritten).toInt()
                    if (toRead > 0) {
                        var read = 0
                        while (read < toRead) {
                            val r = inputStream.read(buf, read, toRead - read)
                            if (r <= 0) break
                            read += r
                        }
                        // Zero-pad the remainder of the cluster
                        for (i in read until buf.size) buf[i] = 0
                    } else {
                        for (i in buf.indices) buf[i] = 0
                    }
                    volumeReader.writeSectors(clusterToSector(c), buf).getOrThrow()
                    bytesWritten += toRead
                    onProgress?.invoke(bytesWritten)
                }
                updateStreamExtension(existing, newClusters[0], fileSize)
                invalidateCaches(path, parentPath)
                volumeReader.sync()
                Result.success(Unit)
            } catch (e: Exception) {
                if (DEBUG_LOGGING) Log.e(TAG, "writeFileStreaming failed: $path", e)
                Result.failure(e)
            }
        }
    }

    override fun createFile(parentPath: String, name: String): Result<FileEntry> =
        writeLock.withLock {
            try {
                validateExFatName(name).onFailure { return@withLock Result.failure(it) }
                val bs = boot ?: return@withLock Result.failure(Exception("Not initialized"))
                val fullPath = if (parentPath == "/") "/$name" else "$parentPath/$name"
                if (exists(fullPath)) return@withLock Result.failure(Exception("Already exists"))
                val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    getFileInfoWithCluster(parentPath).getOrThrow().firstCluster.toLong()
                }
                val entry = createFileEntrySet(parentCluster, name, isDirectory = false)
                val withPath = entry.copy(path = fullPath)
                fileCache[normalizePath(fullPath)] = withPath
                invalidateCaches(fullPath, parentPath)
                volumeReader.sync()
                Result.success(withPath)
            } catch (e: Exception) {
                if (DEBUG_LOGGING) Log.e(TAG, "createFile failed", e)
                Result.failure(e)
            }
        }

    override fun createDirectory(parentPath: String, name: String): Result<FileEntry> =
        writeLock.withLock {
            try {
                validateExFatName(name).onFailure { return@withLock Result.failure(it) }
                val bs = boot ?: return@withLock Result.failure(Exception("Not initialized"))
                val fullPath = if (parentPath == "/") "/$name" else "$parentPath/$name"
                if (exists(fullPath)) return@withLock Result.failure(Exception("Already exists"))
                val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    getFileInfoWithCluster(parentPath).getOrThrow().firstCluster.toLong()
                }
                val entry = createFileEntrySet(parentCluster, name, isDirectory = true)
                val withPath = entry.copy(path = fullPath)
                fileCache[normalizePath(fullPath)] = withPath
                invalidateCaches(fullPath, parentPath)
                volumeReader.sync()
                Result.success(withPath)
            } catch (e: Exception) {
                if (DEBUG_LOGGING) Log.e(TAG, "createDirectory failed", e)
                Result.failure(e)
            }
        }

    override fun delete(path: String): Result<Unit> = writeLock.withLock {
        try {
            val bs = boot ?: return@withLock Result.failure(Exception("Not initialized"))
            if (path == "/" || path.isEmpty()) {
                return@withLock Result.failure(Exception("Cannot delete root"))
            }
            val info = getFileInfoWithCluster(path).getOrThrow()
            if (info.isDirectory) {
                val entries = listDirectory(path).getOrThrow()
                for (e in entries) delete(e.path).getOrThrow()
            }
            val parentPath = path.substringBeforeLast('/', "/")
            val fileName = path.substringAfterLast('/')
            val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
                bs.rootDirFirstCluster
            } else {
                getFileInfoWithCluster(parentPath).getOrThrow().firstCluster.toLong()
            }
            val set = findFileEntrySet(parentCluster, fileName)
                ?: return@withLock Result.failure(Exception("Entry not found"))
            if (info.firstCluster >= 2) freeClusters(info.firstCluster.toLong())
            // Mark the File primary + all secondaries' EntryType byte's InUse bit clear.
            // (spec §6.2.1: deleted entries have InUse=0; values 0x01..0x7F.)
            val setBuf = set.clusterDataRef
            val primaryOff = set.fileEntryOffset
            for (i in 0..set.secondaryCount) {
                val entryOff = primaryOff + i * 32
                if (entryOff + 32 > setBuf.size) break
                setBuf[entryOff] = (setBuf[entryOff].toInt() and 0x7F).toByte()
            }
            volumeReader.writeSectors(set.clusterSector, setBuf).getOrThrow()
            invalidateCaches(path, parentPath)
            volumeReader.sync()
            Result.success(Unit)
        } catch (e: Exception) {
            if (DEBUG_LOGGING) Log.e(TAG, "delete failed: $path", e)
            Result.failure(e)
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers: entry set creation / mutation
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Locate a [DirEntrySet] in the directory rooted at [parentCluster] by name.
     */
    private fun findFileEntrySet(parentCluster: Long, name: String): DirEntrySet? {
        val sets = readDirectoryCluster(parentCluster)
        return sets.firstOrNull { it.name.equals(name, ignoreCase = true) }
    }

    /**
     * Update the Stream Extension entry's FirstCluster / DataLength / ValidDataLength
     * fields in place on disk, then recompute and persist the SetChecksum.
     */
    private fun updateStreamExtension(set: DirEntrySet, newFirstCluster: Long, newSize: Long) {
        val bs = boot ?: return
        // Re-read the cluster to get a writable buffer (set.clusterDataRef may be a cache slice)
        val clusterData = volumeReader.readSectors(set.clusterSector, bs.sectorsPerCluster).getOrThrow()
        val streamOff = set.fileEntryOffset + 32
        // ValidDataLength (offset 8 in stream entry), DataLength (offset 24), FirstCluster (offset 20)
        ByteBuffer.wrap(clusterData, streamOff + 8, 8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(newSize)
        ByteBuffer.wrap(clusterData, streamOff + 24, 8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(newSize)
        ByteBuffer.wrap(clusterData, streamOff + 20, 4).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(newFirstCluster.toInt())
        // Recompute SetChecksum and store in primary entry (offset 2..3)
        val checksum = computeSetChecksum(clusterData, set.fileEntryOffset, set.secondaryCount)
        ByteBuffer.wrap(clusterData, set.fileEntryOffset + 2, 2).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(checksum.toShort())
        volumeReader.writeSectors(set.clusterSector, clusterData).getOrThrow()
    }

    /**
     * Allocate a directory cluster, format it as empty, and chain it to [lastCluster]
     * via the FAT. Returns the new cluster index.
     */
    private fun appendNewDirCluster(lastCluster: Long): Long {
        val bs = boot ?: throw Exception("Not initialized")
        val new = allocateClusters(1)
        if (new.isEmpty()) throw Exception("Disk full — cannot extend directory")
        writeFATEntry(lastCluster, new[0])
        writeFATEntry(new[0], FAT_END_OF_CHAIN)
        val empty = ByteArray(bs.bytesPerCluster)
        volumeReader.writeSectors(clusterToSector(new[0]), empty).getOrThrow()
        return new[0]
    }

    /**
     * Create a new File entry set (File + Stream Extension + N×File Name) in the
     * directory rooted at [parentCluster]. Allocates a directory cluster if the
     * directory is full. For directories, also allocates one cluster and writes
     * the "." and ".." equivalent — but note exFAT does NOT store . / .. entries;
     * they are synthesized in listings. We therefore leave the new directory's
     * cluster empty (all zeros = all END_OF_DIR markers).
     */
    private fun createFileEntrySet(
        parentCluster: Long,
        name: String,
        isDirectory: Boolean
    ): FileEntry {
        val bs = boot ?: throw Exception("Not initialized")
        val nameUtf16 = name.toByteArray(Charsets.UTF_16LE)
        val nameLength = name.length
        val numFileNameEntries = (nameLength + 14) / 15
        val secondaryCount = 1 + numFileNameEntries
        val setBytes = ByteArray(secondaryCount * 32 + 32) // primary + secondaries (we use 32 per entry)

        // For directories we allocate a single cluster now. Files defer allocation
        // until writeFile() is called, leaving FirstCluster=0 (spec §7.6.6).
        var dirFirstCluster = 0L
        if (isDirectory) {
            val dirClusters = allocateClusters(1)
            if (dirClusters.isEmpty()) throw Exception("Disk full")
            writeClusterChain(dirClusters)
            dirFirstCluster = dirClusters[0]
            // Initialize the directory cluster to all zeros (END_OF_DIR markers).
            val empty = ByteArray(bs.bytesPerCluster)
            volumeReader.writeSectors(clusterToSector(dirFirstCluster), empty).getOrThrow()
        }

        // File primary entry (spec §7.4)
        setBytes[0] = FILE
        setBytes[1] = secondaryCount.toByte()
        // SetChecksum at offset 2..3 — computed after all entries are written
        val fileAttrs = if (isDirectory) ATTR_DIRECTORY else ATTR_ARCHIVE
        ByteBuffer.wrap(setBytes, 4, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(fileAttrs.toShort())
        // Timestamps: bytes 8..11 (Create), 12..15 (LastModified), 16..19 (LastAccess)
        val now = System.currentTimeMillis()
        val ts = encodeExFatTimestamp(now)
        ByteBuffer.wrap(setBytes, 8, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(ts)
        ByteBuffer.wrap(setBytes, 12, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(ts)
        ByteBuffer.wrap(setBytes, 16, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(ts)

        // Stream Extension entry (spec §7.6) at offset 32
        val streamOff = 32
        setBytes[streamOff] = STREAM_EXTENSION
        setBytes[streamOff + 1] = FLAG_ALLOCATION_POSSIBLE.toByte() // NoFatChain=0, AllocationPossible=1
        setBytes[streamOff + 3] = nameLength.toByte()
        val nameHash = computeNameHash(nameUtf16)
        ByteBuffer.wrap(setBytes, streamOff + 4, 2).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(nameHash.toShort())
        // ValidDataLength at offset 8, DataLength at offset 24, FirstCluster at offset 20
        ByteBuffer.wrap(setBytes, streamOff + 8, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(0L)
        ByteBuffer.wrap(setBytes, streamOff + 20, 4).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(dirFirstCluster.toInt())
        ByteBuffer.wrap(setBytes, streamOff + 24, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(0L)

        // File Name entries (spec §7.7) starting at offset 64
        var nameOff = 64
        var charIdx = 0
        for (i in 0 until numFileNameEntries) {
            setBytes[nameOff] = FILE_NAME
            setBytes[nameOff + 1] = 0 // GeneralSecondaryFlags: AllocationPossible=0, NoFatChain=0
            for (j in 0 until 15) {
                val charTarget = nameOff + 2 + j * 2
                if (charIdx < nameLength) {
                    val c = name[charIdx].code
                    setBytes[charTarget] = (c and 0xFF).toByte()
                    setBytes[charTarget + 1] = (c shr 8).toByte()
                    charIdx++
                } else {
                    setBytes[charTarget] = 0
                    setBytes[charTarget + 1] = 0
                }
            }
            nameOff += 32
        }

        // Compute and store SetChecksum
        val checksum = computeSetChecksum(setBytes, 0, secondaryCount)
        ByteBuffer.wrap(setBytes, 2, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(checksum.toShort())

        // Find a free contiguous slot of (secondaryCount + 1) entries in the parent
        // directory, or allocate a new directory cluster if none.
        val chain = getClusterChain(parentCluster)
        val entriesNeeded = secondaryCount + 1
        var targetCluster: Long = -1
        var freeOffset = -1
        for (c in chain) {
            val sector = clusterToSector(c)
            val data = volumeReader.readSectors(sector, bs.sectorsPerCluster).getOrThrow()
            var consecutive = 0
            var startOff = -1
            var off = 0
            while (off + 32 <= data.size) {
                val type = data[off]
                // END_OF_DIR or deleted (InUse=0, type in 0x01..0x7F) → free slot
                if (type == END_OF_DIR || type.toInt() and 0x80 == 0) {
                    if (consecutive == 0) startOff = off
                    consecutive++
                    if (consecutive >= entriesNeeded) {
                        targetCluster = c
                        freeOffset = startOff
                        break
                    }
                } else {
                    consecutive = 0
                    startOff = -1
                }
                off += 32
            }
            if (freeOffset != -1) break
        }
        if (freeOffset == -1) {
            // Allocate a new directory cluster and write the entry set at offset 0.
            val lastCluster = chain.last()
            targetCluster = appendNewDirCluster(lastCluster)
            freeOffset = 0
        }

        // Read the target cluster, write the entry set, write back.
        val targetSector = clusterToSector(targetCluster)
        val targetData = volumeReader.readSectors(targetSector, bs.sectorsPerCluster).getOrThrow()
        // Zero out the slot first (in case we're overwriting deleted entries with leftover bytes)
        for (i in 0 until entriesNeeded * 32) {
            targetData[freeOffset + i] = 0
        }
        System.arraycopy(setBytes, 0, targetData, freeOffset, entriesNeeded * 32)
        volumeReader.writeSectors(targetSector, targetData).getOrThrow()

        // Caller (createFile/createDirectory) wraps this with the actual parent path.
        return FileEntry(
            name = name,
            path = "",  // patched by caller
            isDirectory = isDirectory,
            size = 0,
            lastModified = now,
            mimeType = if (isDirectory) "vnd.android.document/directory" else guessMimeType(name),
            firstCluster = dirFirstCluster.toInt()
        )
    }

    /**
     * Free any existing cluster chain and zero the Stream Extension's
     * FirstCluster + DataLength + ValidDataLength fields. (Empty-write fast path.)
     */
    private fun truncateToEmpty(path: String): Result<Unit> {
        return try {
            val bs = boot ?: return Result.failure(Exception("Not initialized"))
            val parentPath = path.substringBeforeLast('/', "/")
            val fileName = path.substringAfterLast('/')
            val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
                bs.rootDirFirstCluster
            } else {
                getFileInfoWithCluster(parentPath).getOrThrow().firstCluster.toLong()
            }
            val set = findFileEntrySet(parentCluster, fileName)
                ?: return Result.failure(Exception("Entry not found"))
            if (set.firstCluster >= 2) {
                freeClusters(set.firstCluster)
            }
            updateStreamExtension(set, 0L, 0L)
            invalidateCaches(path, parentPath)
            volumeReader.sync()
            Result.success(Unit)
        } catch (e: Exception) {
            if (DEBUG_LOGGING) Log.e(TAG, "truncateToEmpty failed: $path", e)
            Result.failure(e)
        }
    }

    private fun invalidateCaches(path: String, parentPath: String) {
        directoryCache.remove(normalizePath(parentPath))
        directoryCache.remove(normalizePath(path))
        fileCache.remove(normalizePath(path))
        if (parentPath == "/" || parentPath.isEmpty()) {
            directoryCache.remove("")
            directoryCache.remove("/")
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Name validation, timestamps, MIME types
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Validate a name per spec Table 35: forbidden UTF-16 code units are
     * 0x00-0x1F and 0x22 " 0x2A * 0x2F / 0x3A : 0x3C < 0x3E > 0x3F ? 0x5C \ 0x7C |
     */
    private fun validateExFatName(name: String): Result<Unit> {
        if (name.isEmpty()) return Result.failure(Exception("Name must not be empty"))
        if (name.length > 255) return Result.failure(Exception("Name exceeds 255 characters"))
        for (ch in name) {
            val c = ch.code
            if (c in 0..0x1F) return Result.failure(Exception("Control char in name"))
            if (c in INVALID_NAME_CHARS) return Result.failure(Exception("Forbidden char in name: '$ch'"))
        }
        return Result.success(Unit)
    }

    /**
     * Pack a Java millisecond timestamp into an exFAT 4-byte Timestamp field
     * (spec §7.4.8). Bits: Year(25..31) Month(21..24) Day(16..20) Hour(11..15)
     * Minute(5..10) DoubleSeconds(0..4).
     */
    private fun encodeExFatTimestamp(millis: Long): Int {
        val cal = java.util.Calendar.getInstance().apply { timeInMillis = millis }
        val year = cal.get(java.util.Calendar.YEAR) - 1980
        val month = cal.get(java.util.Calendar.MONTH) + 1
        val day = cal.get(java.util.Calendar.DAY_OF_MONTH)
        val hour = cal.get(java.util.Calendar.HOUR_OF_DAY)
        val minute = cal.get(java.util.Calendar.MINUTE)
        val sec = cal.get(java.util.Calendar.SECOND) / 2
        return ((year and 0x7F) shl 25) or
               ((month and 0x0F) shl 21) or
               ((day and 0x1F) shl 16) or
               ((hour and 0x1F) shl 11) or
               ((minute and 0x3F) shl 5) or
               (sec and 0x1F)
    }

    private fun parseExFatTimestamp(packed: Int): Long {
        val year = ((packed shr 25) and 0x7F) + 1980
        val month = ((packed shr 21) and 0x0F).coerceIn(1, 12)
        val day = ((packed shr 16) and 0x1F).coerceAtLeast(1)
        val hour = (packed shr 11) and 0x1F
        val minute = (packed shr 5) and 0x3F
        val sec = (packed and 0x1F) * 2
        val cal = java.util.Calendar.getInstance().apply {
            set(year, month - 1, day, hour, minute, sec)
            set(java.util.Calendar.MILLISECOND, 0)
        }
        return cal.timeInMillis
    }

    private fun guessMimeType(fileName: String): String = when {
        fileName.endsWith(".txt", ignoreCase = true) ||
        fileName.endsWith(".log", ignoreCase = true) -> "text/plain"
        fileName.endsWith(".pdf", ignoreCase = true) -> "application/pdf"
        fileName.endsWith(".jpg", ignoreCase = true) ||
        fileName.endsWith(".jpeg", ignoreCase = true) -> "image/jpeg"
        fileName.endsWith(".png", ignoreCase = true) -> "image/png"
        fileName.endsWith(".gif", ignoreCase = true) -> "image/gif"
        fileName.endsWith(".mp4", ignoreCase = true) -> "video/mp4"
        fileName.endsWith(".mp3", ignoreCase = true) -> "audio/mpeg"
        fileName.endsWith(".zip", ignoreCase = true) -> "application/zip"
        else -> "application/octet-stream"
    }
}