package com.androidcrypt.crypto

import android.util.Log
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.Charset
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.Executors
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * FAT32 file system reader for VeraCrypt volumes
 */
class FAT32Reader(private val volumeReader: VolumeReader) : FileSystemReader {
    
    companion object {
        private const val TAG = "FAT32Reader"
        private const val SECTOR_SIZE = 512
        // Set to false to disable debug logging for better performance
        private const val DEBUG_LOGGING = false
        // FAT32 directory entry attributes
        private const val ATTR_READ_ONLY = 0x01
        private const val ATTR_HIDDEN = 0x02
        private const val ATTR_SYSTEM = 0x04
        private const val ATTR_VOLUME_ID = 0x08
        private const val ATTR_DIRECTORY = 0x10
        private const val ATTR_ARCHIVE = 0x20
        private const val ATTR_LONG_NAME = 0x0F
    }
    
    private var bootSector: BootSector? = null
    private var fsInfo: FileSystemInfo? = null
    
    // Thread-safe caches using ConcurrentHashMap
    private val fileCache = java.util.concurrent.ConcurrentHashMap<String, FileEntry>()
    private val directoryCache = java.util.concurrent.ConcurrentHashMap<String, List<FileEntry>>()
    
    // Locks for directory reads to prevent multiple threads from reading same directory simultaneously
    private val directoryLoadLocks = java.util.concurrent.ConcurrentHashMap<String, Any>()
    
    // FAT sector cache - reduces disk I/O during cluster chain traversal
    // Using LRU LinkedHashMap for automatic eviction of least recently used entries.
    // Stores entire prefetch buffers (32 sectors = 16KB each), keyed by aligned start sector.
    // Reading a specific sector computes the containing block and offset within it.
    private val fatBlockSectors = 32 // Number of sectors per cached block
    private val maxFatBlockCacheSize = 256 // Cache up to 256 blocks (256×16KB = 4MB, covers full FAT for volumes up to ~4GB)
    private val fatBlockCache: MutableMap<Int, ByteArray> = Collections.synchronizedMap(
        object : LinkedHashMap<Int, ByteArray>(maxFatBlockCacheSize, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, ByteArray>?): Boolean {
                return size > maxFatBlockCacheSize
            }
        }
    )
    
    // Per-sector cache for write operations (individual FAT sectors that were modified)
    // Write-path methods modify individual sectors and cache them here.
    // Read path checks fatSectorCache first (for dirty sectors), then falls back to fatBlockCache.
    // Uses LRU LinkedHashMap with synchronized wrapper for proper eviction.
    private val maxFatCacheSize = 1024
    private val fatSectorCache: MutableMap<Int, ByteArray> = Collections.synchronizedMap(
        object : LinkedHashMap<Int, ByteArray>(maxFatCacheSize, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, ByteArray>?): Boolean {
                return size > maxFatCacheSize
            }
        }
    )
    
    // Track last allocated cluster to avoid re-scanning from beginning
    @Volatile
    private var lastAllocatedCluster = 2
    
    // Cached free cluster count to avoid rescanning FAT for each file
    @Volatile
    private var cachedFreeClusters: Int = -1
    
    // Cached free space to avoid slow FAT scanning on main thread
    @Volatile
    private var cachedFreeSpaceBytes: Long = -1L
    @Volatile 
    private var isFreeSpaceBeingCalculated = false
    
    // Background executor for non-urgent tasks (free space calculation, etc.)
    private val backgroundExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "FAT32-background").apply { isDaemon = true }
    }
    
    /**
     * Get the file system info (returns null if not initialized)
     */
    fun getFileSystemInfo(): FileSystemInfo? = fsInfo
    
    /**
     * Normalize path for cache keys - FAT32 is case-insensitive
     */
    private fun normalizePath(path: String): String {
        // Fast path: if already lowercase and no trailing slash, return as-is (no allocation)
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
    
    /**
     * Get or create a lock object for a specific directory path
     * This ensures only one thread reads a directory at a time
     */
    private fun getDirectoryLock(path: String): Any {
        return directoryLoadLocks.computeIfAbsent(normalizePath(path)) { Any() }
    }
    
    /**
     * Clear all caches. Call this when the file system may have been modified
     * by another FAT32Reader instance (e.g., after CopyService writes files).
     */
    fun clearCache() {
        directoryCache.clear()
        fileCache.clear()
        fatBlockCache.clear()
        fatSectorCache.clear()
        clusterChainCache.clear()
    }
    
    // Lock for write operations to prevent race conditions
    private val writeLock = ReentrantLock()
    
    data class BootSector(
        val bytesPerSector: Int,
        val sectorsPerCluster: Int,
        val reservedSectors: Int,
        val numberOfFATs: Int,
        val totalSectors: Long,
        val sectorsPerFAT: Int,
        val rootDirFirstCluster: Int,
        val volumeLabel: String,
        val fsType: String
    )
    
    override fun initialize(): Result<FileSystemInfo> {
        return try {
            if (DEBUG_LOGGING) Log.d(TAG, "Reading FAT32 boot sector...")
            
            // Read boot sector (sector 0)
            val bootSectorData = volumeReader.readSector(0).getOrThrow()
            
            // Parse boot sector
            val buffer = ByteBuffer.wrap(bootSectorData).order(ByteOrder.LITTLE_ENDIAN)
            
            // Check boot signature
            if (bootSectorData[510].toInt() and 0xFF != 0x55 || 
                bootSectorData[511].toInt() and 0xFF != 0xAA) {
                return Result.failure(Exception("Invalid boot sector signature"))
            }
            
            val bytesPerSector = buffer.getShort(11).toInt() and 0xFFFF
            val sectorsPerCluster = buffer.get(13).toInt() and 0xFF
            val reservedSectors = buffer.getShort(14).toInt() and 0xFFFF
            val numberOfFATs = buffer.get(16).toInt() and 0xFF
            val rootEntryCount = buffer.getShort(17).toInt() and 0xFFFF
            val totalSectors16 = buffer.getShort(19).toInt() and 0xFFFF
            val sectorsPerFAT16 = buffer.getShort(22).toInt() and 0xFFFF
            val totalSectors32 = buffer.getInt(32)
            val sectorsPerFAT32 = buffer.getInt(36)
            val rootDirFirstCluster = buffer.getInt(44)
            
            // Determine FAT type
            val totalSectors = if (totalSectors16 != 0) totalSectors16.toLong() else totalSectors32.toLong()
            val sectorsPerFAT = if (sectorsPerFAT16 != 0) sectorsPerFAT16 else sectorsPerFAT32
            
            // Read volume label and FS type
            val volumeLabel = if (sectorsPerFAT16 == 0) {
                // FAT32
                String(bootSectorData, 71, 11, Charset.forName("ASCII")).trim()
            } else {
                // FAT16
                String(bootSectorData, 43, 11, Charset.forName("ASCII")).trim()
            }
            
            val fsType = if (sectorsPerFAT16 == 0) {
                String(bootSectorData, 82, 8, Charset.forName("ASCII")).trim()
            } else {
                String(bootSectorData, 54, 8, Charset.forName("ASCII")).trim()
            }
            
            bootSector = BootSector(
                bytesPerSector = bytesPerSector,
                sectorsPerCluster = sectorsPerCluster,
                reservedSectors = reservedSectors,
                numberOfFATs = numberOfFATs,
                totalSectors = totalSectors,
                sectorsPerFAT = sectorsPerFAT,
                rootDirFirstCluster = rootDirFirstCluster,
                volumeLabel = volumeLabel,
                fsType = fsType
            )
            
            val clusterSize = bytesPerSector * sectorsPerCluster
            val totalSpace = totalSectors * bytesPerSector
            
            fsInfo = FileSystemInfo(
                type = when {
                    fsType.contains("FAT32") -> FileSystemType.FAT32
                    fsType.contains("FAT16") -> FileSystemType.FAT16
                    fsType.contains("FAT12") -> FileSystemType.FAT12
                    else -> FileSystemType.FAT32 // Default assumption
                },
                label = volumeLabel.ifEmpty { "VeraCrypt Volume" },
                totalSpace = totalSpace,
                freeSpace = 0, // Would need to scan FAT to calculate
                clusterSize = clusterSize
            )
            
            if (DEBUG_LOGGING) Log.d(TAG, "File system detected: ${fsInfo?.type}, Label: ${fsInfo?.label}, Cluster size: $clusterSize")
            
            // Compute total clusters for FSInfo validation and logging
            val totalClustersComputed = ((totalSectors - (reservedSectors + (numberOfFATs.toLong() * sectorsPerFAT))) / sectorsPerCluster).toInt()
            
            // Read FSInfo sector (sector 1 typically) to get the free cluster hint
            // This avoids scanning the entire FAT from cluster 2 on first allocation
            try {
                val fsInfoSectorNum = buffer.getShort(48).toInt() and 0xFFFF // FSInfo sector number
                if (fsInfoSectorNum in 1..reservedSectors) {
                    val fsInfoData = volumeReader.readSector(fsInfoSectorNum.toLong()).getOrNull()
                    if (fsInfoData != null) {
                        val fsInfoBuf = ByteBuffer.wrap(fsInfoData).order(ByteOrder.LITTLE_ENDIAN)
                        val leadSig = fsInfoBuf.getInt(0)
                        val structSig = fsInfoBuf.getInt(484)
                        if (leadSig == 0x41615252 && structSig == 0x61417272) {
                            val nxtFree = fsInfoBuf.getInt(492)
                            val freeCount = fsInfoBuf.getInt(488)
                            if (nxtFree in 2..totalClustersComputed && nxtFree != -1) {
                                lastAllocatedCluster = nxtFree
                                Log.d(TAG, "FSInfo: nxtFree=$nxtFree, freeCount=$freeCount")
                            }
                            if (freeCount >= 0 && freeCount != -1) {
                                cachedFreeClusters = freeCount
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to read FSInfo sector, will scan from cluster 2", e)
            }
            
            Log.d(TAG, "FAT32 initialized: totalClusters=$totalClustersComputed, lastAllocatedCluster=$lastAllocatedCluster")
            
            // Prefetch entire FAT table into cache — turns 60+ seconds of
            // on-demand 16KB reads into a single ~1-2s bulk read.
            prefetchFAT()
            
            Result.success(fsInfo!!)
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize FAT32 reader", e)
            Result.failure(e)
        }
    }
    
    /**
     * Prefetch the entire FAT table and count free clusters.
     *
     * On-demand reading (used by countFreeClusters / readFATEntry) issues
     * dozens of small 16 KB reads, each with its own I/O + decrypt round-trip.
     * For a 1 GB volume this alone took ~61 s on a typical phone.
     *
     * Instead, we stream the FAT in large 1 MB chunks (2048 sectors) which
     * dramatically reduces syscall + decrypt overhead (typically < 2 s for 1 GB,
     * ~4 s for 20 GB).
     *
     * The ENTIRE FAT is always read so free clusters are counted exactly,
     * regardless of volume size. Only 1 MB is resident at a time — old chunks
     * are GC'd as we advance. Blocks are stored in fatBlockCache (LRU eviction
     * keeps memory bounded to maxFatBlockCacheSize × 16 KB ≈ 4 MB).
     * For volumes whose FAT fits in cache, every subsequent readFATEntry() is
     * an in-memory hit. For larger volumes, the most-recently-used blocks stay
     * cached and the rest are re-read on demand (rare — allocation scans forward).
     */
    private fun prefetchFAT() {
        val bs = bootSector ?: return
        val fatStartSector = bs.reservedSectors
        val totalFatSectors = bs.sectorsPerFAT

        val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
        val totalClusters = ((bs.totalSectors - firstDataSector) / bs.sectorsPerCluster).toInt()

        val start = System.currentTimeMillis()
        var freeClusters = 0
        var sectorOffset = 0
        // 1 MB per I/O call — maximises sequential throughput & parallel decrypt
        val ioChunkSectors = 2048

        while (sectorOffset < totalFatSectors) {
            val readCount = minOf(ioChunkSectors, totalFatSectors - sectorOffset)
            val chunkData = volumeReader.readSectors(
                (fatStartSector + sectorOffset).toLong(), readCount
            ).getOrNull() ?: break

            // ---- store in fatBlockCache (fatBlockSectors-sized slices) ----
            // LRU eviction in the LinkedHashMap keeps memory bounded; for large
            // volumes the tail blocks are evicted as head blocks are inserted,
            // but the free-cluster count (computed below) is still exact.
            var blockLocalOffset = 0
            while (blockLocalOffset < readCount) {
                val blockKey = sectorOffset + blockLocalOffset
                val blockSectors = minOf(fatBlockSectors, readCount - blockLocalOffset)
                val startByte = blockLocalOffset * SECTOR_SIZE
                val endByte = startByte + blockSectors * SECTOR_SIZE
                val blockData = if (startByte == 0 && endByte == chunkData.size) {
                    chunkData          // single-block chunk → avoid copy
                } else {
                    chunkData.copyOfRange(startByte, endByte)
                }
                fatBlockCache[blockKey] = blockData
                blockLocalOffset += fatBlockSectors
            }

            // ---- count free clusters in this chunk ----
            val chunkStartByte = sectorOffset.toLong() * SECTOR_SIZE
            val firstCluster = maxOf((chunkStartByte / 4).toInt(), 2) // entries 0-1 reserved
            val lastCluster = minOf(
                ((chunkStartByte + readCount * SECTOR_SIZE) / 4).toInt(),
                totalClusters + 2
            )
            for (cluster in firstCluster until lastCluster) {
                val byteInChunk = (cluster * 4 - chunkStartByte).toInt()
                if (byteInChunk + 3 < chunkData.size) {
                    val b0 = chunkData[byteInChunk].toInt() and 0xFF
                    val b1 = chunkData[byteInChunk + 1].toInt() and 0xFF
                    val b2 = chunkData[byteInChunk + 2].toInt() and 0xFF
                    val b3 = chunkData[byteInChunk + 3].toInt() and 0xFF
                    val entry = (b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)) and 0x0FFFFFFF
                    if (entry == 0) freeClusters++
                }
            }

            sectorOffset += readCount
        }

        val elapsed = System.currentTimeMillis() - start
        // Always exact — we read the entire FAT
        cachedFreeClusters = freeClusters
        val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
        cachedFreeSpaceBytes = freeClusters.toLong() * clusterSize
        Log.d(TAG, "FAT prefetch complete in ${elapsed}ms: " +
                "$freeClusters free clusters (${cachedFreeSpaceBytes / 1024 / 1024}MB free), " +
                "${fatBlockCache.size} cache blocks, $totalFatSectors FAT sectors total")
    }

    override fun listDirectory(path: String): Result<List<FileEntry>> {
        // Check cache first (use normalized path for FAT32 case-insensitivity)
        val cacheKey = normalizePath(path)
        directoryCache[cacheKey]?.let { return Result.success(it) }
        
        // Use per-directory lock to prevent multiple threads from reading same directory
        // This ensures only one thread does the actual read, others wait and use cache
        val listStart = System.currentTimeMillis()
        synchronized(getDirectoryLock(path)) {
            // Double-check cache after acquiring lock (another thread may have populated it)
            directoryCache[cacheKey]?.let { 
                if (DEBUG_LOGGING) Log.d(TAG, "LISTDIR: cache hit after lock (${System.currentTimeMillis() - listStart}ms)")
                return Result.success(it) 
            }
            
            return try {
                val bs = bootSector ?: return Result.failure(Exception("File system not initialized"))
                
                val cluster = if (path == "/" || path.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    // Find directory entry to get its cluster
                    val dirEntry = getFileInfoWithCluster(path).getOrThrow()
                    if (!dirEntry.isDirectory) {
                        return Result.failure(Exception("Path is not a directory"))
                    }
                    if (dirEntry.firstCluster == 0) {
                        return Result.failure(Exception("Directory has no cluster allocated"))
                    }
                    dirEntry.firstCluster
                }
                
                val entries = readDirectoryCluster(cluster, path)
                directoryCache[cacheKey] = entries
                if (DEBUG_LOGGING) Log.d(TAG, "LISTDIR: loaded ${entries.size} entries in ${System.currentTimeMillis() - listStart}ms")
                Result.success(entries)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to list directory", e)
                Result.failure(e)
            }
        }
    }
    
    private fun readDirectoryCluster(startCluster: Int, parentPath: String = "/"): List<FileEntry> {
        val bs = bootSector ?: return emptyList()
        val entries = mutableListOf<FileEntry>()

        try {
            val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
            val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE

            // Phase 1: Walk the FAT chain to collect all cluster numbers.
            // This is cheap — FAT sectors are aggressively cached after the first prefetch,
            // so each readFATEntry() call is typically a HashMap lookup with no I/O.
            val clusterChain = mutableListOf<Int>()
            var c = startCluster
            while (c >= 2 && c < 0x0FFFFFF8) {
                clusterChain.add(c)
                c = readFATEntry(c).getOrElse { break }
            }

            if (clusterChain.isEmpty()) return entries

            // Phase 2: Read all directory data in large contiguous batches.
            // A freshly-formatted volume typically has the entire directory as one
            // contiguous run, so this usually becomes a single readSectors() call
            // instead of one call per cluster (potentially hundreds of calls).
            val lfnParts = mutableListOf<String>()
            var chainIndex = 0

            while (chainIndex < clusterChain.size) {
                // Find the length of the contiguous run starting at chainIndex
                var runLength = 1
                while (chainIndex + runLength < clusterChain.size &&
                       clusterChain[chainIndex + runLength] == clusterChain[chainIndex + runLength - 1] + 1) {
                    runLength++
                }

                val firstClusterInRun = clusterChain[chainIndex]
                val runSectorStart = (firstClusterInRun - 2).toLong() * bs.sectorsPerCluster + firstDataSector
                val sectorsToRead = runLength * bs.sectorsPerCluster

                val runData = volumeReader.readSectors(runSectorStart, sectorsToRead).getOrNull() ?: break

                // Parse entries cluster by cluster within the batch buffer.
                // Honour the 0x00 rule: stop at the first 0x00 in each cluster
                // (skip rest of that cluster) but continue to subsequent clusters.
                for (clusterInRun in 0 until runLength) {
                    val clusterBase = clusterInRun * clusterSize
                    var offset = clusterBase

                    while (offset < clusterBase + clusterSize) {
                        val firstByte = runData[offset].toInt() and 0xFF

                        // 0x00 = free entry. Skip rest of THIS cluster but keep going
                        // through the FAT chain — valid entries may follow in later clusters.
                        if (firstByte == 0x00) break

                        // Deleted entry
                        if (firstByte == 0xE5) { offset += 32; continue }

                        val attr = runData[offset + 11].toInt() and 0xFF

                        // Long file name entry — collect parts in order (reversed at assembly)
                        if (attr == ATTR_LONG_NAME) {
                            lfnParts.add(parseLongFileName(runData, offset))
                            offset += 32; continue
                        }

                        // Skip volume label
                        if ((attr and ATTR_VOLUME_ID) != 0) { offset += 32; continue }

                        val shortName = parseShortFileName(runData, offset)
                        // Assemble LFN from collected parts (stored newest-first, need reverse)
                        val name = if (lfnParts.isNotEmpty()) {
                            val sb = StringBuilder(lfnParts.size * 13)
                            for (p in lfnParts.indices.reversed()) sb.append(lfnParts[p])
                            sb.toString()
                        } else shortName
                        lfnParts.clear()

                        if (name == "." || name == "..") { offset += 32; continue }

                        val isDirectory = (attr and ATTR_DIRECTORY) != 0

                        val size = ((runData[offset + 28].toInt() and 0xFF) or
                                   ((runData[offset + 29].toInt() and 0xFF) shl 8) or
                                   ((runData[offset + 30].toInt() and 0xFF) shl 16) or
                                   ((runData[offset + 31].toInt() and 0xFF) shl 24)).toLong() and 0xFFFFFFFFL

                        val clusterLo = (runData[offset + 26].toInt() and 0xFF) or
                                        ((runData[offset + 27].toInt() and 0xFF) shl 8)
                        val clusterHi = (runData[offset + 20].toInt() and 0xFF) or
                                        ((runData[offset + 21].toInt() and 0xFF) shl 8)
                        val entryFirstCluster = (clusterHi shl 16) or clusterLo

                        val modDate = (runData[offset + 24].toInt() and 0xFF) or
                                      ((runData[offset + 25].toInt() and 0xFF) shl 8)
                        val modTime = (runData[offset + 22].toInt() and 0xFF) or
                                      ((runData[offset + 23].toInt() and 0xFF) shl 8)
                        val lastModified = parseFATDateTime(modDate, modTime)

                        val mimeType = if (isDirectory) "vnd.android.document/directory"
                                       else guessMimeType(name)

                        val fullPath = if (parentPath == "/") "/$name" else "$parentPath/$name"

                        val entry = FileEntry(
                            name = name,
                            path = fullPath,
                            isDirectory = isDirectory,
                            size = size,
                            lastModified = lastModified,
                            mimeType = mimeType,
                            firstCluster = entryFirstCluster
                        )
                        entries.add(entry)
                        // Pre-populate fileCache so getFileInfoWithCluster doesn't re-walk
                        fileCache[normalizePath(fullPath)] = entry

                        offset += 32
                    }
                }

                chainIndex += runLength
            }

            if (DEBUG_LOGGING) Log.d(TAG, "readDirectoryCluster: cluster=$startCluster clusters=${clusterChain.size} entries=${entries.size}")

        } catch (e: Exception) {
            Log.e(TAG, "Error reading directory cluster $startCluster", e)
        }

        return entries
    }
    
    // Pre-cached charset to avoid Charset.forName() lookup per call
    private val asciiCharset = Charsets.US_ASCII
    
    private fun parseShortFileName(data: ByteArray, offset: Int): String {
        val name = String(data, offset, 8, asciiCharset).trimEnd()
        val ext = String(data, offset + 8, 3, asciiCharset).trimEnd()
        
        return if (ext.isNotEmpty()) "$name.$ext" else name
    }
    
    // Pre-allocated LFN character offsets (avoids creating a List each call)
    private val lfnOffsets = intArrayOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
    
    private fun parseLongFileName(data: ByteArray, offset: Int): String {
        val sb = StringBuilder(13) // LFN entry holds max 13 chars
        
        for (o in lfnOffsets) {
            if (offset + o + 1 < data.size) {
                val c1 = data[offset + o].toInt() and 0xFF
                val c2 = data[offset + o + 1].toInt() and 0xFF
                val char = ((c2 shl 8) or c1).toChar()
                if (char == '\u0000' || char == '\uFFFF') break
                sb.append(char)
            }
        }
        
        return sb.toString()
    }
    
    // Days from Jan 1 to the start of each month (non-leap year)
    private val DAYS_BEFORE_MONTH = intArrayOf(0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334)

    // Precomputed cumulative days from Unix epoch (1970-01-01) to Jan 1 of each year.
    // FAT dates encode years 1980–2107 (7-bit field), so index 0 = 1970, index 137 = 2107.
    // This replaces the per-entry loop ("for (y in 1970 until year)") with a single table lookup.
    private val DAYS_TO_YEAR: IntArray = IntArray(138).also { table ->
        var acc = 0
        for (y in 1970..2107) {
            table[y - 1970] = acc
            acc += if (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) 366 else 365
        }
    }
    
    private fun parseFATDateTime(date: Int, time: Int): Long {
        // FAT date: bits 15-9: year (1980+), 8-5: month, 4-0: day
        // FAT time: bits 15-11: hour, 10-5: minute, 4-0: second/2
        val year = 1980 + ((date shr 9) and 0x7F)
        val month = ((date shr 5) and 0x0F).coerceIn(1, 12)
        val day = (date and 0x1F).coerceAtLeast(1)
        val hour = (time shr 11) and 0x1F
        val minute = (time shr 5) and 0x3F
        val second = (time and 0x1F) * 2
        
        // Convert to Unix epoch millis using precomputed table (single array lookup, no loop)
        var days = DAYS_TO_YEAR[year - 1970].toLong()
        days += DAYS_BEFORE_MONTH[month - 1]
        // Add leap day if applicable
        if (month > 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) days++
        days += day - 1
        
        return (days * 86400L + hour * 3600L + minute * 60L + second) * 1000L
    }
    
    private fun guessMimeType(fileName: String): String {
        // Use endsWith with ignoreCase instead of allocating a lowercase extension string
        return when {
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
            fileName.endsWith(".doc", ignoreCase = true) ||
            fileName.endsWith(".docx", ignoreCase = true) -> "application/msword"
            fileName.endsWith(".valv", ignoreCase = true) -> "application/octet-stream"
            else -> "application/octet-stream"
        }
    }
    
    override fun readFile(path: String): Result<ByteArray> {
        return try {
            if (DEBUG_LOGGING) Log.d(TAG, "readFile: Starting to read '$path'")
            
            // Use getFileInfoWithCluster to get the file info with firstCluster populated
            val fileInfo = getFileInfoWithCluster(path).getOrThrow()
            if (fileInfo.isDirectory) {
                return Result.failure(Exception("Path is a directory, not a file"))
            }
            
            if (DEBUG_LOGGING) Log.d(TAG, "readFile: File info - size=${fileInfo.size}, firstCluster=${fileInfo.firstCluster}")
            
            val bs = bootSector ?: return Result.failure(Exception("File system not initialized"))
            
            // Get the first cluster from the file info (already retrieved via directory traversal)
            val fileFirstCluster = fileInfo.firstCluster
            
            // If file has no clusters, it's truly empty
            if (fileFirstCluster == 0) {
                if (fileInfo.size == 0L) {
                    return Result.success(ByteArray(0))
                }
                Log.e(TAG, "readFile: File has size=${fileInfo.size} but no clusters allocated!")
                return Result.failure(Exception("File has no clusters allocated but size is ${fileInfo.size}"))
            }
            
            // Calculate first data sector
            val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
            val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
            
            // Determine actual file size
            val actualFileSize = if (fileInfo.size == 0L && fileFirstCluster != 0) {
                if (DEBUG_LOGGING) Log.w(TAG, "readFile: File '$path' has size=0 but firstCluster=$fileFirstCluster, calculating actual size from cluster chain")
                var clusterCount = 0
                var currentCluster = fileFirstCluster
                val maxClusters = 100000
                while (currentCluster >= 2 && currentCluster < 0x0FFFFFF8 && clusterCount < maxClusters) {
                    clusterCount++
                    currentCluster = readFATEntry(currentCluster).getOrElse { break }
                }
                val estimatedSize = clusterCount.toLong() * clusterSize
                if (DEBUG_LOGGING) Log.d(TAG, "readFile: Estimated size from $clusterCount clusters: $estimatedSize bytes")
                estimatedSize
            } else {
                fileInfo.size
            }
            
            // If file is empty after checking clusters, return empty array
            if (actualFileSize == 0L) {
                return Result.success(ByteArray(0))
            }
            
            // Validate file size fits in a ByteArray (max ~2GB)
            if (actualFileSize > Int.MAX_VALUE) {
                return Result.failure(Exception("File too large to read into memory (${actualFileSize / (1024*1024)} MB). Use streaming read instead."))
            }
            
            // Pre-build entire cluster chain for efficient batch reading
            val clusterChain = mutableListOf<Int>()
            var currentCluster = fileFirstCluster
            val maxClusters = ((actualFileSize + clusterSize - 1) / clusterSize).toInt() + 10
            
            while (currentCluster >= 2 && currentCluster < 0x0FFFFFF8 && clusterChain.size < maxClusters) {
                clusterChain.add(currentCluster)
                currentCluster = readFATEntry(currentCluster).getOrElse { break }
            }
            
            // Allocate result buffer
            val fileData = ByteArray(actualFileSize.toInt())
            var bytesRead = 0
            var chainIndex = 0
            
            // Read consecutive cluster runs in batches for better I/O performance
            while (chainIndex < clusterChain.size && bytesRead < actualFileSize) {
                // Find consecutive cluster run
                var runLength = 1
                while (chainIndex + runLength < clusterChain.size &&
                       clusterChain[chainIndex + runLength] == clusterChain[chainIndex + runLength - 1] + 1 &&
                       runLength < 256) { // Max 256 clusters per batch (1MB with 4KB clusters)
                    runLength++
                }
                
                // Read all consecutive clusters in one I/O operation
                val firstClusterInBatch = clusterChain[chainIndex]
                val batchSectorStart = firstDataSector.toLong() + (firstClusterInBatch - 2).toLong() * bs.sectorsPerCluster
                val sectorsToRead = runLength * bs.sectorsPerCluster
                
                val batchData = volumeReader.readSectors(batchSectorStart, sectorsToRead).getOrThrow()
                
                // Copy only actual file data (not padding)
                val bytesToCopy = minOf(batchData.size, actualFileSize.toInt() - bytesRead)
                System.arraycopy(batchData, 0, fileData, bytesRead, bytesToCopy)
                bytesRead += bytesToCopy
                
                chainIndex += runLength
            }
            
            if (DEBUG_LOGGING) Log.d(TAG, "readFile: Returning ${fileData.size} bytes")
            
            Result.success(fileData)
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read file", e)
            Result.failure(e)
        }
    }
    
    private fun readFATEntry(cluster: Int, bypassCache: Boolean = false): Result<Int> {
        return try {
            val bs = bootSector ?: return Result.failure(Exception("File system not initialized"))
            val fatStartSector = bs.reservedSectors
            
            // Calculate which FAT sector contains this cluster entry
            val entryOffset = cluster * 4
            val fatSectorOffset = entryOffset / SECTOR_SIZE
            
            // Align to block boundary for cache lookup
            val blockStart = (fatSectorOffset / fatBlockSectors) * fatBlockSectors
            val offsetInBlock = (fatSectorOffset - blockStart) * SECTOR_SIZE + (entryOffset % SECTOR_SIZE)
            
            // Check per-sector dirty cache FIRST — if a sector was modified by a write
            // operation, fatSectorCache has the authoritative copy. fatBlockCache may be stale.
            if (!bypassCache) {
                val dirtySector = fatSectorCache[fatSectorOffset]
                if (dirtySector != null) {
                    val offsetInSector = entryOffset % SECTOR_SIZE
                    val b0 = dirtySector[offsetInSector].toInt() and 0xFF
                    val b1 = dirtySector[offsetInSector + 1].toInt() and 0xFF
                    val b2 = dirtySector[offsetInSector + 2].toInt() and 0xFF
                    val b3 = dirtySector[offsetInSector + 3].toInt() and 0xFF
                    return Result.success((b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)) and 0x0FFFFFFF)
                }
            }
            
            val block: ByteArray
            if (bypassCache) {
                // Read fresh from disk, then update cache
                val freshData = volumeReader.readSectors((fatStartSector + blockStart).toLong(), fatBlockSectors).getOrThrow()
                fatBlockCache[blockStart] = freshData
                block = freshData
            } else {
                block = fatBlockCache[blockStart] ?: run {
                    // Read entire block (32 sectors = 16KB, covers 4096 clusters) in one I/O
                    // LRU eviction handled automatically by LinkedHashMap
                    val blockData = volumeReader.readSectors(
                        (fatStartSector + blockStart).toLong(),
                        fatBlockSectors
                    ).getOrNull()
                    
                    if (blockData != null) {
                        fatBlockCache[blockStart] = blockData
                        blockData
                    } else {
                        // Fallback to single sector read
                        val singleSector = volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
                        // Don't cache partial block
                        return@run singleSector.also {
                            // offsetInBlock needs to be relative to this single sector
                            val b0 = it[entryOffset % SECTOR_SIZE].toInt() and 0xFF
                            val b1 = it[(entryOffset % SECTOR_SIZE) + 1].toInt() and 0xFF
                            val b2 = it[(entryOffset % SECTOR_SIZE) + 2].toInt() and 0xFF
                            val b3 = it[(entryOffset % SECTOR_SIZE) + 3].toInt() and 0xFF
                            return Result.success((b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)) and 0x0FFFFFFF)
                        }
                    }
                }
            }
            
            // Read FAT entry (4 bytes for FAT32) - direct byte read from block buffer
            val b0 = block[offsetInBlock].toInt() and 0xFF
            val b1 = block[offsetInBlock + 1].toInt() and 0xFF
            val b2 = block[offsetInBlock + 2].toInt() and 0xFF
            val b3 = block[offsetInBlock + 3].toInt() and 0xFF
            val entry = (b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)) and 0x0FFFFFFF
            
            Result.success(entry)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    override fun readFile(path: String, offset: Long, length: Int): Result<ByteArray> {
        return readFileRange(path, offset, length)
    }
    
    /**
     * Read a range of bytes from a file at a specific offset.
     * Optimized for random access - only reads the clusters containing the requested range.
     */
    fun readFileRange(path: String, offset: Long, length: Int): Result<ByteArray> {
        return try {
            val fileInfo = getFileInfoWithCluster(path).getOrThrow()
            if (fileInfo.isDirectory) {
                return Result.failure(Exception("Path is a directory, not a file"))
            }
            readFileRangeByCluster(fileInfo.firstCluster, fileInfo.size, offset, length)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read file range at offset $offset, length $length", e)
            Result.failure(e)
        }
    }
    
    /**
     * Read a range of bytes from a file using a pre-resolved firstCluster.
     * Skips the directory-traversal metadata lookup on every call.
     * Use when the caller already knows the firstCluster (e.g. ProxyCallback).
     */
    fun readFileRangeByCluster(firstCluster: Int, fileSize: Long, offset: Long, length: Int): Result<ByteArray> {
        return try {
            if (firstCluster < 2) {
                return Result.failure(Exception("Invalid first cluster"))
            }
            
            val bs = bootSector ?: return Result.failure(Exception("File system not initialized"))
            val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
            val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
            
            // Clamp to file size
            val actualLength = minOf(length.toLong(), fileSize - offset).toInt()
            if (actualLength <= 0 || offset >= fileSize) {
                return Result.success(ByteArray(0))
            }
            
            // Calculate which clusters we need
            val startClusterIndex = (offset / clusterSize).toInt()
            val endClusterIndex = ((offset + actualLength - 1) / clusterSize).toInt()
            val clustersNeeded = endClusterIndex - startClusterIndex + 1
            
            // Build cluster chain (or use cached one if we already have it)
            val clusterChain = getClusterChain(firstCluster, endClusterIndex + 1)
            
            if (startClusterIndex >= clusterChain.size) {
                return Result.success(ByteArray(0))
            }
            
            // Read only the clusters we need
            val result = ByteArray(actualLength)
            var resultOffset = 0
            var bytesRemaining = actualLength
            var i = startClusterIndex
            
            while (i <= minOf(endClusterIndex, clusterChain.size - 1) && bytesRemaining > 0) {
                val cluster = clusterChain[i]
                
                // Calculate offset within this cluster (only non-zero for the very first)
                val offsetInCluster = if (i == startClusterIndex) {
                    (offset - i.toLong() * clusterSize).toInt()
                } else 0
                
                // Always try to batch consecutive clusters — even when the first
                // cluster has a non-zero offset.  We read the full batch and then
                // copy starting at offsetInCluster.  This turns 2 I/O calls
                // (partial first + batch of rest) into a single one.
                var consecutiveCount = 1
                while (i + consecutiveCount <= endClusterIndex &&
                       i + consecutiveCount < clusterChain.size &&
                       clusterChain[i + consecutiveCount] == cluster + consecutiveCount &&
                       consecutiveCount < 256) {
                    consecutiveCount++
                }
                
                // Use Long arithmetic to avoid int overflow on large volumes
                val batchSectorStart = firstDataSector.toLong() + (cluster - 2).toLong() * bs.sectorsPerCluster
                val sectorsToRead = consecutiveCount * bs.sectorsPerCluster
                val batchData = volumeReader.readSectors(batchSectorStart, sectorsToRead).getOrThrow()
                
                val bytesToCopy = minOf(batchData.size - offsetInCluster, bytesRemaining)
                System.arraycopy(batchData, offsetInCluster, result, resultOffset, bytesToCopy)
                resultOffset += bytesToCopy
                bytesRemaining -= bytesToCopy
                
                i += consecutiveCount
            }
            
            Result.success(result)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read file range at offset $offset, length $length", e)
            Result.failure(e)
        }
    }
    
    // Cache for cluster chains to avoid rebuilding for sequential reads (LRU eviction)
    private val maxClusterChainCacheSize = 200
    private val clusterChainCache: MutableMap<Int, List<Int>> = Collections.synchronizedMap(
        object : LinkedHashMap<Int, List<Int>>(maxClusterChainCacheSize, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, List<Int>>?): Boolean {
                return size > maxClusterChainCacheSize
            }
        }
    )
    
    private fun getClusterChain(firstCluster: Int, maxClusters: Int): List<Int> {
        // Return from cache if it already covers what we need
        clusterChainCache[firstCluster]?.let { cached ->
            if (cached.size >= maxClusters) return cached
        }
        
        // Build the COMPLETE chain to EOF — no maxClusters cap here.
        // FAT entries are all cached after the first directory read, so traversal
        // is pure in-memory HashMap lookups (~100ns each). Building 5000 entries
        // for a 20MB file takes ~0.5ms and means every subsequent call is a cache hit.
        val chain = mutableListOf<Int>()
        var cluster = firstCluster
        while (cluster >= 2 && cluster < 0x0FFFFFF8) {
            chain.add(cluster)
            cluster = readFATEntry(cluster).getOrElse { break }
        }
        
        clusterChainCache[firstCluster] = chain
        // LRU eviction handled automatically by LinkedHashMap
        
        return chain
    }
    
    /**
     * Stream file data directly to an OutputStream, reading cluster by cluster.
     * This avoids loading the entire file into memory, preventing OOM for large files.
     * 
     * @param path The file path
     * @param outputStream The stream to write data to
     * @return Result indicating success or failure
     */
    fun streamFileToOutput(path: String, outputStream: java.io.OutputStream): Result<Long> {
        return try {
            val totalStart = System.currentTimeMillis()
            if (DEBUG_LOGGING) Log.d(TAG, "streamFileToOutput: Starting to stream '$path'")
            
            val fileInfoStart = System.currentTimeMillis()
            val fileInfo = getFileInfoWithCluster(path).getOrThrow()
            val fileInfoTime = System.currentTimeMillis() - fileInfoStart
            
            if (fileInfo.isDirectory) {
                return Result.failure(Exception("Path is a directory, not a file"))
            }
            
            if (DEBUG_LOGGING) Log.d(TAG, "streamFileToOutput: File info - size=${fileInfo.size}, firstCluster=${fileInfo.firstCluster}")
            
            val bs = bootSector ?: return Result.failure(Exception("File system not initialized"))
            
            val fileFirstCluster = fileInfo.firstCluster
            
            // If file has no clusters, it's truly empty
            if (fileFirstCluster == 0) {
                if (fileInfo.size == 0L) {
                    return Result.success(0L)
                }
                return Result.failure(Exception("File has no clusters allocated but size is ${fileInfo.size}"))
            }
            
            val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
            val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
            
            // Determine actual file size
            val actualFileSize = if (fileInfo.size == 0L && fileFirstCluster != 0) {
                var clusterCount = 0
                var currentCluster = fileFirstCluster
                val maxClusters = 100000
                while (currentCluster >= 2 && currentCluster < 0x0FFFFFF8 && clusterCount < maxClusters) {
                    clusterCount++
                    currentCluster = readFATEntry(currentCluster).getOrElse { break }
                }
                clusterCount.toLong() * clusterSize
            } else {
                fileInfo.size
            }
            
            if (actualFileSize == 0L) {
                return Result.success(0L)
            }
            
            // Use buffered output for better write performance
            val bufferedOutput = java.io.BufferedOutputStream(outputStream, 512 * 1024) // 512KB buffer
            
            // Pre-build the entire cluster chain for maximum batching efficiency
            val fatChainStart = System.currentTimeMillis()
            val clusterChain = mutableListOf<Int>()
            var chainCluster = fileFirstCluster
            val maxClusters = (actualFileSize / clusterSize + 1).toInt()
            while (chainCluster != 0 && chainCluster < 0x0FFFFFF8 && clusterChain.size < maxClusters) {
                clusterChain.add(chainCluster)
                chainCluster = readFATEntry(chainCluster).getOrElse { break }
            }
            val fatChainTime = System.currentTimeMillis() - fatChainStart
            
            // Now process the chain in large consecutive batches
            val streamStart = System.currentTimeMillis()
            var bytesWritten = 0L
            var chainIndex = 0
            
            while (chainIndex < clusterChain.size && bytesWritten < actualFileSize) {
                // Find consecutive cluster run starting at chainIndex
                var runLength = 1
                while (chainIndex + runLength < clusterChain.size &&
                       clusterChain[chainIndex + runLength] == clusterChain[chainIndex + runLength - 1] + 1 &&
                       runLength < 256) { // Max 256 clusters per batch (1MB with 4KB clusters)
                    runLength++
                }
                
                // Read all consecutive clusters in one I/O operation
                val firstClusterInBatch = clusterChain[chainIndex]
                val batchSectorStart = firstDataSector.toLong() + (firstClusterInBatch - 2).toLong() * bs.sectorsPerCluster
                val sectorsToRead = runLength * bs.sectorsPerCluster
                
                val batchData = volumeReader.readSectors(batchSectorStart, sectorsToRead).getOrThrow()
                
                // Write only the actual file data (not padding at end)
                val bytesToWrite = minOf(batchData.size.toLong(), actualFileSize - bytesWritten).toInt()
                bufferedOutput.write(batchData, 0, bytesToWrite)
                bytesWritten += bytesToWrite
                
                chainIndex += runLength
            }
            
            bufferedOutput.flush()
            val streamTime = System.currentTimeMillis() - streamStart
            val totalTime = System.currentTimeMillis() - totalStart
            if (DEBUG_LOGGING) Log.d(TAG, "STREAM: ${bytesWritten/1024}KB total=${totalTime}ms (fileInfo=${fileInfoTime}ms, fatChain=${fatChainTime}ms, stream=${streamTime}ms, clusters=${clusterChain.size})")
            Result.success(bytesWritten)
            
        } catch (e: java.io.IOException) {
            // EPIPE (Broken pipe) is normal when reader closes stream early (e.g., video seeking)
            val isBrokenPipe = e.message?.contains("EPIPE") == true || e.cause?.message?.contains("EPIPE") == true
            if (isBrokenPipe) {
                if (DEBUG_LOGGING) Log.d(TAG, "Stream closed by reader for: $path (normal for seeking)")
            } else {
                Log.e(TAG, "Failed to stream file", e)
            }
            Result.failure(e)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stream file", e)
            Result.failure(e)
        }
    }
    
    override fun getFileInfo(path: String): Result<FileEntry> {
        // Use normalized path for FAT32 case-insensitivity
        val cacheKey = normalizePath(path)
        fileCache[cacheKey]?.let { return Result.success(it) }
        
        return try {
            if (path == "/" || path.isEmpty()) {
                val rootEntry = FileEntry(
                    name = "",
                    path = "/",
                    isDirectory = true,
                    size = 0,
                    lastModified = System.currentTimeMillis(),
                    mimeType = "vnd.android.document/directory"
                )
                fileCache[cacheKey] = rootEntry
                return Result.success(rootEntry)
            }
            
            // Search in parent directory
            val parentPath = path.substringBeforeLast('/', "/")
            val fileName = path.substringAfterLast('/')
            
            val parentEntries = listDirectory(parentPath).getOrThrow()
            val entry = parentEntries.find { it.name.equals(fileName, ignoreCase = true) }
                ?: return Result.failure(Exception("File not found: $path"))
            
            fileCache[cacheKey] = entry
            Result.success(entry)
            
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Get file info with firstCluster guaranteed to be populated.
     * Use this when you need the cluster number for subsequent I/O.
     */
    fun getFileInfoWithClusterPublic(path: String): Result<FileEntry> {
        return getFileInfoWithCluster(path)
    }
    
    /**
     * Get file info with cluster number by walking the directory tree.
     * This is used internally to avoid circular dependency with listDirectory.
     */
    private fun getFileInfoWithCluster(path: String): Result<FileEntry> {
        // Check cache first (use normalized path for FAT32 case-insensitivity)
        val cacheKey = normalizePath(path)
        fileCache[cacheKey]?.let { 
            if (it.firstCluster != 0 || path == "/") return Result.success(it) 
        }
        
        return try {
            val bs = bootSector ?: return Result.failure(Exception("File system not initialized"))
            
            if (path == "/" || path.isEmpty()) {
                val rootEntry = FileEntry(
                    name = "",
                    path = "/",
                    isDirectory = true,
                    size = 0,
                    lastModified = System.currentTimeMillis(),
                    mimeType = "vnd.android.document/directory",
                    firstCluster = bs.rootDirFirstCluster
                )
                return Result.success(rootEntry)
            }
            
            // Split path into components
            val pathComponents = path.trim('/').split('/')
            var currentCluster = bs.rootDirFirstCluster
            var currentPath = ""
            var foundEntry: FileEntry? = null
            
            for (component in pathComponents) {
                currentPath = if (currentPath.isEmpty()) "/$component" else "$currentPath/$component"
                val parentPath = currentPath.substringBeforeLast('/').ifEmpty { "/" }
                
                // Try to use cached directory listing first, fall back to readDirectoryCluster
                val parentCacheKey = normalizePath(parentPath)
                val entries = directoryCache[parentCacheKey] 
                    ?: readDirectoryCluster(currentCluster, parentPath)
                foundEntry = entries.find { it.name.equals(component, ignoreCase = true) }
                
                if (foundEntry == null) {
                    return Result.failure(Exception("Path component not found: $component in $path"))
                }
                
                // Update current cluster for next iteration
                currentCluster = foundEntry.firstCluster
            }
            
            if (foundEntry != null) {
                fileCache[cacheKey] = foundEntry
                Result.success(foundEntry)
            } else {
                Result.failure(Exception("File not found: $path"))
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get file info with cluster", e)
            Result.failure(e)
        }
    }
    
    override fun exists(path: String): Boolean {
        return getFileInfo(path).isSuccess
    }
    
    override fun getRootDirectory(): FileEntry {
        return FileEntry(
            name = "",
            path = "/",
            isDirectory = true,
            size = 0,
            lastModified = System.currentTimeMillis(),
            mimeType = "vnd.android.document/directory"
        )
    }
    
    /**
     * Holds the result of a metadata/allocation phase so the actual data writing
     * can proceed outside the writeLock. This prevents ANR when multiple binder
     * threads (e.g. DocumentsUI copy) contend on createFile while a write is in progress.
     */
    private data class WriteAllocation(
        val clusters: List<Int>,
        val firstDataSector: Int,
        val clusterSize: Int,
        val sectorsPerCluster: Int
    )
    
    override fun writeFile(path: String, data: ByteArray): Result<Unit> {
        // Phase 1: Metadata under writeLock (fast — allocates clusters, updates FAT & dir entry)
        val allocationResult: Result<WriteAllocation> = writeLock.withLock {
            try {
                val fileInfo = getFileInfo(path).getOrThrow()
                if (fileInfo.isDirectory) {
                    return@withLock Result.failure(Exception("Path is a directory, not a file"))
                }
                
                val bs = bootSector ?: return@withLock Result.failure(Exception("File system not initialized"))
                
                val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
                val clustersNeeded = ((data.size + clusterSize - 1) / clusterSize).coerceAtLeast(1)
            
            // Validate file size doesn't exceed available space
            val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
            val maxClusters = ((bs.totalSectors - firstDataSector) / bs.sectorsPerCluster).toInt() - 1 // -1 for root dir
            if (clustersNeeded > maxClusters) {
                return@withLock Result.failure(Exception("File too large: needs $clustersNeeded clusters, only $maxClusters available"))
            }
            
            // Find the directory entry
            val parentPath = path.substringBeforeLast('/', "/")
            val fileName = path.substringAfterLast('/')
            
            // Get parent directory cluster
            val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
                bs.rootDirFirstCluster
            } else {
                getFileInfoWithCluster(parentPath).getOrThrow().firstCluster
            }
            
            // Search for the file entry across all directory clusters
            var dirEntryOffset = -1
            var fileFirstCluster = 0
            var entriesFound = 0
            var foundInCluster = -1
            var foundClusterData: ByteArray? = null
            var foundFirstSectorOfCluster = 0L
            
            var currentDirCluster = parentCluster
            outerLoop@ while (currentDirCluster >= 2 && currentDirCluster < 0x0FFFFFF8) {
                val firstSectorOfCluster = ((currentDirCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
                
                // Read this directory cluster in one bulk read
                val clusterData = volumeReader.readSectors(firstSectorOfCluster, bs.sectorsPerCluster).getOrThrow()
                
                var offset = 0
                var lfnName = ""
                
                while (offset < clusterData.size) {
                    val firstByte = clusterData[offset].toInt() and 0xFF
                    if (firstByte == 0x00) break // No more entries in this cluster, check next cluster in chain
                    if (firstByte == 0xE5) {
                        offset += 32
                        continue
                    }
                    
                    val attr = clusterData[offset + 11].toInt() and 0xFF
                    if (attr == ATTR_LONG_NAME) {
                        lfnName = parseLongFileName(clusterData, offset) + lfnName
                        offset += 32
                        continue
                    }
                    
                    val shortName = parseShortFileName(clusterData, offset)
                    val entryName = if (lfnName.isNotEmpty()) lfnName else shortName
                    entriesFound++
                    lfnName = ""
                    
                    if (entryName.equals(fileName, ignoreCase = true)) {
                        dirEntryOffset = offset
                        foundInCluster = currentDirCluster
                        foundClusterData = clusterData
                        foundFirstSectorOfCluster = firstSectorOfCluster.toLong()
                        
                        // Get existing first cluster
                        val clusterLo = ByteBuffer.wrap(clusterData, offset + 26, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                        val clusterHi = ByteBuffer.wrap(clusterData, offset + 20, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                        fileFirstCluster = (clusterHi shl 16) or clusterLo
                        break@outerLoop
                    }
                    
                    offset += 32
                }
                
                // Get next cluster in the directory chain
                currentDirCluster = readFATEntry(currentDirCluster).getOrElse { break }
            }
            
            if (dirEntryOffset == -1 || foundClusterData == null) {
                Log.e(TAG, "writeFile: File entry not found after scanning $entriesFound entries, last cluster checked: $currentDirCluster")
                return@withLock Result.failure(Exception("File entry not found"))
            }
            
            val clusterData = foundClusterData
            val firstSectorOfCluster = foundFirstSectorOfCluster
            
            // Allocate clusters for the file
            val clusters = if (fileFirstCluster == 0) {
                // Need to allocate new clusters
                allocateClusters(clustersNeeded)
            } else {
                // File already has clusters — try to reuse existing chain
                reuseOrReallocateClusters(fileFirstCluster, clustersNeeded)
            }
            
            if (clusters.isEmpty()) {
                return@withLock Result.failure(Exception("Failed to allocate clusters"))
            }
            
            // Update directory entry with new cluster and size
            val newFirstCluster = clusters[0]
            ByteBuffer.wrap(clusterData, dirEntryOffset + 26, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((newFirstCluster and 0xFFFF).toShort())
            ByteBuffer.wrap(clusterData, dirEntryOffset + 20, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((newFirstCluster shr 16).toShort())
            ByteBuffer.wrap(clusterData, dirEntryOffset + 28, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(data.size)
            
            // Write back modified directory cluster
            volumeReader.writeSectors(firstSectorOfCluster, clusterData).getOrThrow()
            
            // Create cluster chain in FAT
            writeClusterChain(clusters)
            
            Result.success(WriteAllocation(clusters, firstDataSector, clusterSize, bs.sectorsPerCluster))
            } catch (e: Exception) {
                Log.e(TAG, "Failed to write file (metadata phase)", e)
                Result.failure(e)
            }
        }
        
        val allocation = allocationResult.getOrElse { return Result.failure(it) }
        
        // Phase 2: Write file data to allocated clusters (no lock needed —
        // clusters are reserved in FAT so no other operation will use them)
        return try {
            var dataOffset = 0
            var clusterIndex = 0
            // Reusable write buffer — sized once per contiguous run.
            // writeSectorsInPlace encrypts in-place, eliminating a separate
            // encrypted-data allocation (saves up to 8MB per run).
            var writeBuf: ByteArray? = null
            
            while (clusterIndex < allocation.clusters.size) {
                // Find contiguous runs of clusters for batch writing
                var contiguousCount = 1
                while (clusterIndex + contiguousCount < allocation.clusters.size &&
                       allocation.clusters[clusterIndex + contiguousCount] == allocation.clusters[clusterIndex + contiguousCount - 1] + 1) {
                    contiguousCount++
                }
                
                val batchBytes = contiguousCount * allocation.clusterSize
                val remaining = data.size - dataOffset
                val toWrite = minOf(remaining, batchBytes)
                
                // Reuse buffer only if it's exactly the right size
                if (writeBuf == null || writeBuf!!.size != batchBytes) {
                    writeBuf = ByteArray(batchBytes)
                } else if (toWrite < batchBytes) {
                    // Zero-fill padding area (buffer may contain stale data from prior run)
                    java.util.Arrays.fill(writeBuf!!, toWrite, batchBytes, 0.toByte())
                }
                System.arraycopy(data, dataOffset, writeBuf!!, 0, toWrite)
                
                val firstCluster = allocation.clusters[clusterIndex]
                val clusterSector = allocation.firstDataSector.toLong() + (firstCluster - 2).toLong() * allocation.sectorsPerCluster
                // Encrypt in-place and write — avoids allocating a separate encrypted copy
                volumeReader.writeSectorsInPlace(clusterSector, writeBuf!!, 0, batchBytes).getOrThrow()
                
                dataOffset += toWrite
                clusterIndex += contiguousCount
            }
            
            fileCache.remove(path)
            // Surgical cache invalidation — only remove the parent directory
            // instead of clearing all cached directories.
            val parentPath = path.substringBeforeLast('/', "/")
            directoryCache.remove(normalizePath(parentPath))
            if (parentPath == "/" || parentPath.isEmpty()) {
                directoryCache.remove(""); directoryCache.remove("/")
            }
            invalidateFreeSpaceCache()
            
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write file (data phase)", e)
            Result.failure(e)
        }
    }
    
    /**
     * Streaming write for large files - reads data in chunks to avoid OOM
     */
    override fun writeFileStreaming(
        path: String,
        inputStream: java.io.InputStream,
        fileSize: Long,
        onProgress: ((Long) -> Unit)?
    ): Result<Unit> {
        // Phase 1: Metadata under writeLock (fast — allocates clusters, updates FAT & dir entry)
        val allocationResult: Result<WriteAllocation> = writeLock.withLock {
            try {
                val fileInfo = getFileInfo(path).getOrThrow()
                if (fileInfo.isDirectory) {
                    return@withLock Result.failure(Exception("Path is a directory, not a file"))
                }
                
                val bs = bootSector ?: return@withLock Result.failure(Exception("File system not initialized"))
                
                val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
                val clustersNeeded = ((fileSize + clusterSize - 1) / clusterSize).toInt().coerceAtLeast(1)
                
                // Only check free space if we don't have a valid cache (expensive operation)
                // The actual allocation will fail if there isn't enough space
                if (cachedFreeClusters >= 0 && clustersNeeded > cachedFreeClusters) {
                    val freeBytes = cachedFreeClusters.toLong() * clusterSize
                    return@withLock Result.failure(Exception(
                        "Not enough space: need ${fileSize / 1024} KB, only ${freeBytes / 1024} KB free"
                    ))
                }
                
                // Validate file size doesn't exceed available space
                val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
                val maxClusters = ((bs.totalSectors - firstDataSector) / bs.sectorsPerCluster).toInt() - 1
                if (clustersNeeded > maxClusters) {
                    return@withLock Result.failure(Exception("File too large for this container"))
                }
                
                // Find the directory entry
                val parentPath = path.substringBeforeLast('/', "/")
                val fileName = path.substringAfterLast('/')
                
                // Get parent directory cluster
                val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    getFileInfoWithCluster(parentPath).getOrThrow().firstCluster
                }
                
                // Find the file entry - search across all directory clusters
                var dirEntryOffset = -1
                var fileFirstCluster = 0
                var foundClusterData: ByteArray? = null
                var foundFirstSectorOfCluster = 0L
                
                var currentDirCluster = parentCluster
                outerLoop@ while (currentDirCluster >= 2 && currentDirCluster < 0x0FFFFFF8) {
                    val firstSectorOfCluster = ((currentDirCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
                    
                    // Read this directory cluster in one bulk read
                    val clusterData = volumeReader.readSectors(firstSectorOfCluster, bs.sectorsPerCluster).getOrThrow()
                    
                    var offset = 0
                    var lfnName = ""
                    
                    while (offset < clusterData.size) {
                        val firstByte = clusterData[offset].toInt() and 0xFF
                        if (firstByte == 0x00) break // Check next cluster in chain
                        if (firstByte == 0xE5) {
                            offset += 32
                            continue
                        }
                        
                        val attr = clusterData[offset + 11].toInt() and 0xFF
                        if (attr == ATTR_LONG_NAME) {
                            lfnName = parseLongFileName(clusterData, offset) + lfnName
                            offset += 32
                            continue
                        }
                        
                        val shortName = parseShortFileName(clusterData, offset)
                        val entryName = if (lfnName.isNotEmpty()) lfnName else shortName
                        lfnName = ""
                        
                        if (entryName.equals(fileName, ignoreCase = true)) {
                            dirEntryOffset = offset
                            foundClusterData = clusterData
                            foundFirstSectorOfCluster = firstSectorOfCluster
                            val clusterLo = java.nio.ByteBuffer.wrap(clusterData, offset + 26, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                            val clusterHi = java.nio.ByteBuffer.wrap(clusterData, offset + 20, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                            fileFirstCluster = (clusterHi shl 16) or clusterLo
                            break@outerLoop
                        }
                        
                        offset += 32
                    }
                    
                    // Get next cluster in the directory chain
                    currentDirCluster = readFATEntry(currentDirCluster).getOrElse { break }
                }
                
                if (dirEntryOffset == -1 || foundClusterData == null) {
                    return@withLock Result.failure(Exception("File entry not found"))
                }
                
                val clusterData = foundClusterData
                val firstSectorOfCluster = foundFirstSectorOfCluster
                
                // Allocate clusters for the file
                val clusters = if (fileFirstCluster == 0) {
                    allocateClusters(clustersNeeded)
                } else {
                    // Reuse existing chain when possible
                    reuseOrReallocateClusters(fileFirstCluster, clustersNeeded)
                }
                
                if (clusters.isEmpty()) {
                    return@withLock Result.failure(Exception("Failed to allocate clusters"))
                }
                
                // Update directory entry with new cluster and size
                val newFirstCluster = clusters[0]
                java.nio.ByteBuffer.wrap(clusterData, dirEntryOffset + 26, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).putShort((newFirstCluster and 0xFFFF).toShort())
                java.nio.ByteBuffer.wrap(clusterData, dirEntryOffset + 20, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).putShort((newFirstCluster shr 16).toShort())
                java.nio.ByteBuffer.wrap(clusterData, dirEntryOffset + 28, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt((fileSize and 0xFFFFFFFFL).toInt())
                
                // Write back modified directory
                volumeReader.writeSectors(firstSectorOfCluster, clusterData).getOrThrow()
                
                // Create cluster chain in FAT
                writeClusterChain(clusters)
                
                Result.success(WriteAllocation(clusters, firstDataSector, clusterSize, bs.sectorsPerCluster))
            } catch (e: Exception) {
                Log.e(TAG, "Failed to write file streaming (metadata phase)", e)
                Result.failure(e)
            }
        }
        
        val allocation = allocationResult.getOrElse { return Result.failure(it) }
        
        // Phase 2: Stream data to allocated clusters (no lock needed —
        // clusters are reserved in FAT so no other operation will use them)
        return try {
            // Target 8MB batches regardless of cluster size for consistent throughput
            val targetBatchBytes = 8 * 1024 * 1024
            val clustersPerBatch = (targetBatchBytes / allocation.clusterSize).coerceAtLeast(1)
            val batchSize = allocation.clusterSize * clustersPerBatch
            val batchBuffer = ByteArray(batchSize)
            
            var bytesWritten = 0L
            var clusterIndex = 0
            
            while (clusterIndex < allocation.clusters.size) {
                val batchClusters = minOf(clustersPerBatch, allocation.clusters.size - clusterIndex)
                val batchBytes = batchClusters * allocation.clusterSize
                val remaining = fileSize - bytesWritten
                val toRead = minOf(remaining.toInt(), batchBytes)
                
                var totalRead = 0
                while (totalRead < toRead) {
                    val read = inputStream.read(batchBuffer, totalRead, toRead - totalRead)
                    if (read == -1) break
                    totalRead += read
                }
                
                if (totalRead < batchBytes) {
                    java.util.Arrays.fill(batchBuffer, totalRead, batchBytes, 0.toByte())
                }
                
                // Write contiguous runs directly from batchBuffer — encrypt in-place,
                // no scratch buffer, no allocation. Each run operates on a non-overlapping
                // slice of batchBuffer and is not needed after writing.
                var batchOffset = 0
                while (batchOffset < batchClusters) {
                    // Find length of contiguous run starting at batchOffset
                    var runLength = 1
                    while (batchOffset + runLength < batchClusters &&
                           allocation.clusters[clusterIndex + batchOffset + runLength] == 
                           allocation.clusters[clusterIndex + batchOffset + runLength - 1] + 1) {
                        runLength++
                    }
                    
                    val runCluster = allocation.clusters[clusterIndex + batchOffset]
                    val runSector = allocation.firstDataSector.toLong() + ((runCluster - 2).toLong() * allocation.sectorsPerCluster)
                    val runBytes = runLength * allocation.clusterSize
                    val srcOffset = batchOffset * allocation.clusterSize
                    
                    // Encrypt in-place and write directly from batchBuffer — zero allocation
                    volumeReader.writeSectorsInPlace(runSector, batchBuffer, srcOffset, runBytes).getOrThrow()
                    
                    batchOffset += runLength
                }
                
                bytesWritten += totalRead
                clusterIndex += batchClusters
                onProgress?.invoke(bytesWritten)
                
                // Periodic fdatasync every ~64MB to prevent data loss on crash
                if (bytesWritten % (64 * 1024 * 1024) < batchBytes) {
                    volumeReader.sync()
                }
            }
            
            fileCache.remove(path)
            // Surgical cache invalidation — only remove the parent directory
            val parentPath = path.substringBeforeLast('/', "/")
            directoryCache.remove(normalizePath(parentPath))
            if (parentPath == "/" || parentPath.isEmpty()) {
                directoryCache.remove(""); directoryCache.remove("/")
            }
            invalidateFreeSpaceCache()
            volumeReader.sync()
            
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write file streaming (data phase)", e)
            Result.failure(e)
        }
    }
    
    /**
     * Streaming write for files with unknown size (e.g., SAF pipe writes).
     * Allocates clusters on-demand in batches as data is read from the input stream.
     * Each batch of clusters is immediately marked in the FAT (as EOF) to prevent
     * concurrent allocations from grabbing them, then the final chain is written at the end.
     *
     * This enables true streaming without needing to buffer the entire file in memory
     * or know the file size upfront.
     */
    fun writeFileStreamingDynamic(
        path: String,
        inputStream: java.io.InputStream,
        onProgress: ((Long) -> Unit)? = null
    ): Result<Unit> {
        val bs = bootSector ?: return Result.failure(Exception("File system not initialized"))
        val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
        val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
        
        // Pre-allocate clusters in batches of ~8MB worth
        val preAllocClusters = (8 * 1024 * 1024 / clusterSize).coerceAtLeast(1)
        val batchBuffer = ByteArray(preAllocClusters * clusterSize)
        
        // Phase 1: Find directory entry and free existing clusters (under write lock)
        data class DirEntryInfo(
            val dirClusterData: ByteArray,
            val dirSector: Long,
            val entryOffset: Int,
            val existingFirstCluster: Int
        )
        
        val dirEntryResult: Result<DirEntryInfo> = writeLock.withLock {
            try {
                val fileInfo = getFileInfo(path).getOrThrow()
                if (fileInfo.isDirectory) {
                    return@withLock Result.failure(Exception("Path is a directory, not a file"))
                }
                
                val parentPath = path.substringBeforeLast('/', "/")
                val fileName = path.substringAfterLast('/')
                
                val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    getFileInfoWithCluster(parentPath).getOrThrow().firstCluster
                }
                
                // Find the file entry in the directory
                var dirEntryOffset = -1
                var fileFirstCluster = 0
                var foundClusterData: ByteArray? = null
                var foundFirstSectorOfCluster = 0L
                
                var currentDirCluster = parentCluster
                outerLoop@ while (currentDirCluster >= 2 && currentDirCluster < 0x0FFFFFF8) {
                    val sectorOfCluster = ((currentDirCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
                    val clusterData = volumeReader.readSectors(sectorOfCluster, bs.sectorsPerCluster).getOrThrow()
                    
                    var offset = 0
                    var lfnName = ""
                    while (offset < clusterData.size) {
                        val firstByte = clusterData[offset].toInt() and 0xFF
                        if (firstByte == 0x00) break
                        if (firstByte == 0xE5) { offset += 32; continue }
                        
                        val attr = clusterData[offset + 11].toInt() and 0xFF
                        if (attr == ATTR_LONG_NAME) {
                            lfnName = parseLongFileName(clusterData, offset) + lfnName
                            offset += 32; continue
                        }
                        
                        val shortName = parseShortFileName(clusterData, offset)
                        val entryName = if (lfnName.isNotEmpty()) lfnName else shortName
                        lfnName = ""
                        
                        if (entryName.equals(fileName, ignoreCase = true)) {
                            dirEntryOffset = offset
                            foundClusterData = clusterData
                            foundFirstSectorOfCluster = sectorOfCluster
                            val clusterLo = java.nio.ByteBuffer.wrap(clusterData, offset + 26, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                            val clusterHi = java.nio.ByteBuffer.wrap(clusterData, offset + 20, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                            fileFirstCluster = (clusterHi shl 16) or clusterLo
                            break@outerLoop
                        }
                        offset += 32
                    }
                    currentDirCluster = readFATEntry(currentDirCluster).getOrElse { break }
                }
                
                if (dirEntryOffset == -1 || foundClusterData == null) {
                    return@withLock Result.failure(Exception("File entry not found"))
                }
                
                // Free existing clusters if the file had data
                if (fileFirstCluster >= 2) {
                    freeClusters(fileFirstCluster)
                }
                
                Result.success(DirEntryInfo(foundClusterData, foundFirstSectorOfCluster, dirEntryOffset, fileFirstCluster))
            } catch (e: Exception) {
                Log.e(TAG, "writeFileStreamingDynamic: metadata phase failed", e)
                Result.failure(e)
            }
        }
        
        val dirEntry = dirEntryResult.getOrElse { return Result.failure(it) }
        
        // Phase 2: Stream data with on-demand cluster allocation
        val allClusters = mutableListOf<Int>()
        // Track the cumulative size at each batch boundary so Phase 3 can
        // link batches without rewriting the entire chain.
        val batchBoundaries = mutableListOf<Int>()  // indices into allClusters where each batch starts
        var totalBytesWritten = 0L
        
        return try {
            while (true) {
                // Read a batch of data from the input stream
                var bytesRead = 0
                while (bytesRead < batchBuffer.size) {
                    val read = inputStream.read(batchBuffer, bytesRead, batchBuffer.size - bytesRead)
                    if (read == -1) break
                    bytesRead += read
                }
                
                if (bytesRead == 0) break // EOF, no more data
                
                val clustersNeeded = (bytesRead + clusterSize - 1) / clusterSize
                
                // Allocate clusters and immediately mark them in FAT to prevent
                // concurrent operations from grabbing them
                val newClusters = writeLock.withLock {
                    val clusters = allocateClusters(clustersNeeded)
                    if (clusters.isEmpty()) {
                        throw Exception("No free space on volume")
                    }
                    // Write this batch as its own chain (internal links + EOF at end).
                    // Phase 3 will only fix the inter-batch links, avoiding a full rewrite.
                    writeClusterChain(clusters)
                    clusters
                }
                
                batchBoundaries.add(allClusters.size)
                allClusters.addAll(newClusters)
                
                // Zero-fill remainder of last cluster
                if (bytesRead < clustersNeeded * clusterSize) {
                    java.util.Arrays.fill(batchBuffer, bytesRead, clustersNeeded * clusterSize, 0.toByte())
                }
                
                // Write data to allocated clusters (find contiguous runs for batch I/O)
                var batchOffset = 0
                while (batchOffset < newClusters.size) {
                    var runLength = 1
                    while (batchOffset + runLength < newClusters.size &&
                           newClusters[batchOffset + runLength] == newClusters[batchOffset + runLength - 1] + 1) {
                        runLength++
                    }
                    
                    val runCluster = newClusters[batchOffset]
                    val runSector = firstDataSector.toLong() + ((runCluster - 2).toLong() * bs.sectorsPerCluster)
                    val runBytes = runLength * clusterSize
                    val srcOffset = batchOffset * clusterSize
                    
                    volumeReader.writeSectorsInPlace(runSector, batchBuffer, srcOffset, runBytes).getOrThrow()
                    batchOffset += runLength
                }
                
                totalBytesWritten += bytesRead
                onProgress?.invoke(totalBytesWritten)
                
                if (bytesRead < batchBuffer.size) break // EOF reached mid-batch
            }
            
            // Phase 3: Link batch boundaries and update directory entry (under write lock)
            // Each batch was already written as its own chain (c1→c2→...→cN→EOF).
            // We only need to fix the inter-batch links: change the last cluster of
            // each batch from EOF to point to the first cluster of the next batch.
            // This writes at most (numBatches-1) FAT entries instead of the entire chain.
            writeLock.withLock {
                if (batchBoundaries.size > 1) {
                    // Collect all inter-batch link updates into one batch write
                    val fatUpdates = mutableMapOf<Int, ByteArray>()
                    val fatStartSector = bs.reservedSectors
                    
                    for (i in 0 until batchBoundaries.size - 1) {
                        val nextBatchStart = batchBoundaries[i + 1]
                        val lastClusterOfThisBatch = allClusters[nextBatchStart - 1]
                        val firstClusterOfNextBatch = allClusters[nextBatchStart]
                        
                        // Update FAT entry for lastClusterOfThisBatch to point to firstClusterOfNextBatch
                        val entryOffset = lastClusterOfThisBatch * 4
                        val fatSectorOffset = entryOffset / SECTOR_SIZE
                        val offsetInSector = entryOffset % SECTOR_SIZE
                        
                        val fatSector = fatUpdates.getOrPut(fatSectorOffset) {
                            fatSectorCache[fatSectorOffset]?.copyOf()
                                ?: volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
                        }
                        ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(firstClusterOfNextBatch)
                    }
                    
                    batchWriteFATSectors(fatUpdates)
                }
                
                // Update directory entry with first cluster and actual file size
                val clusterData = dirEntry.dirClusterData
                val offset = dirEntry.entryOffset
                val newFirstCluster = if (allClusters.isNotEmpty()) allClusters[0] else 0
                
                java.nio.ByteBuffer.wrap(clusterData, offset + 26, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    .putShort((newFirstCluster and 0xFFFF).toShort())
                java.nio.ByteBuffer.wrap(clusterData, offset + 20, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    .putShort((newFirstCluster shr 16).toShort())
                java.nio.ByteBuffer.wrap(clusterData, offset + 28, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    .putInt((totalBytesWritten and 0xFFFFFFFFL).toInt())
                
                // Write back modified directory cluster
                volumeReader.writeSectors(dirEntry.dirSector, clusterData).getOrThrow()
            }
            
            fileCache.remove(path)
            // Surgical cache invalidation — only remove the parent directory
            val parentPath = path.substringBeforeLast('/', "/")
            directoryCache.remove(normalizePath(parentPath))
            if (parentPath == "/" || parentPath.isEmpty()) {
                directoryCache.remove(""); directoryCache.remove("/")
            }
            invalidateFreeSpaceCache()
            
            Log.d(TAG, "writeFileStreamingDynamic: wrote $totalBytesWritten bytes (${allClusters.size} clusters) to $path")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "writeFileStreamingDynamic failed", e)
            Result.failure(e)
        }
    }
    
    /**
     * Count the number of free clusters in the file system
     */
    fun countFreeClusters(): Int {
        val bs = bootSector ?: return 0
        
        // Use cached count if available (much faster)
        if (cachedFreeClusters >= 0) {
            return cachedFreeClusters
        }
        
        try {
            val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
            val fatStartSector = bs.reservedSectors
            val totalClusters = ((bs.totalSectors - firstDataSector) / bs.sectorsPerCluster).toInt()
            
            var freeClusters = 0
            val prefetchCount = 32
            var clusterIndex = 2
            
            while (clusterIndex <= totalClusters) {
                val fatSectorOffset = (clusterIndex * 4) / SECTOR_SIZE
                
                // Try per-sector cache (dirty sectors from writes), then block cache
                var fatSectorData = fatSectorCache[fatSectorOffset]
                // Offset into the data array (0 when using per-sector cache, computed for block cache)
                var fatDataBase = 0
                if (fatSectorData == null) {
                    // Try block cache — use offset into block directly, no copyOfRange
                    val blockStart = (fatSectorOffset / fatBlockSectors) * fatBlockSectors
                    val block = fatBlockCache[blockStart]
                    if (block != null) {
                        val sectorInBlock = fatSectorOffset - blockStart
                        if ((sectorInBlock + 1) * SECTOR_SIZE <= block.size) {
                            fatSectorData = block
                            fatDataBase = sectorInBlock * SECTOR_SIZE
                        }
                    }
                }
                if (fatSectorData == null) {
                    val batchData = volumeReader.readSectors(
                        (fatStartSector + fatSectorOffset).toLong(),
                        prefetchCount
                    ).getOrNull()
                    
                    if (batchData != null) {
                        // Store as block cache entry
                        val blockStart = (fatSectorOffset / fatBlockSectors) * fatBlockSectors
                        if (fatSectorOffset == blockStart) {
                            fatBlockCache.putIfAbsent(blockStart, batchData)
                        }
                        // Use batch data directly with offset 0
                        fatSectorData = batchData
                        fatDataBase = 0
                    }
                    
                    if (fatSectorData == null) {
                        fatSectorData = volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrNull()
                            ?: break
                        fatDataBase = 0
                    }
                }
                
                // Process all entries in this sector in a tight loop
                val data = fatSectorData
                var offsetInSector = (clusterIndex * 4) % SECTOR_SIZE
                while (offsetInSector <= SECTOR_SIZE - 4 && clusterIndex <= totalClusters) {
                    val absOff = fatDataBase + offsetInSector
                    val b0 = data[absOff].toInt() and 0xFF
                    val b1 = data[absOff + 1].toInt() and 0xFF
                    val b2 = data[absOff + 2].toInt() and 0xFF
                    val b3 = data[absOff + 3].toInt() and 0xFF
                    val entry = (b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)) and 0x0FFFFFFF
                    if (entry == 0) {
                        freeClusters++
                    }
                    clusterIndex++
                    offsetInSector += 4
                }
            }
            
            // Cache the result
            cachedFreeClusters = freeClusters
            return freeClusters
        } catch (e: Exception) {
            Log.e(TAG, "Failed to count free clusters", e)
            return 0
        }
    }
    
    /**
     * Get free space in bytes - returns cached value to avoid ANR
     * Will trigger background calculation if not yet calculated
     */
    fun getFreeSpaceBytes(): Long {
        val bs = bootSector ?: return 0L
        val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
        
        // If we have a cached value, return it
        if (cachedFreeSpaceBytes >= 0) {
            return cachedFreeSpaceBytes
        }
        
        // Return an estimate based on total size (assume 95% free for new volumes)
        // and trigger background calculation
        val totalBytes = getTotalSpaceBytes()
        val estimate = (totalBytes * 95) / 100
        
        // Start background calculation if not already running
        if (!isFreeSpaceBeingCalculated) {
            isFreeSpaceBeingCalculated = true
            backgroundExecutor.submit {
                try {
                    val freeClusters = countFreeClusters()
                    cachedFreeSpaceBytes = freeClusters.toLong() * clusterSize
                    Log.d(TAG, "Background free space calculation complete: $cachedFreeSpaceBytes bytes")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to calculate free space in background", e)
                } finally {
                    isFreeSpaceBeingCalculated = false
                }
            }
        }
        
        return estimate
    }
    
    /**
     * Get total space in bytes
     */
    fun getTotalSpaceBytes(): Long {
        val bs = bootSector ?: return 0L
        val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
        val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
        val totalClusters = ((bs.totalSectors - firstDataSector) / bs.sectorsPerCluster).toInt()
        return totalClusters.toLong() * clusterSize
    }
    
    /**
     * Get cluster size in bytes
     */
    fun getClusterSize(): Int {
        val bs = bootSector ?: return SECTOR_SIZE
        return bs.sectorsPerCluster * SECTOR_SIZE
    }
    
    /**
     * Invalidate cached free space (call after write operations)
     */
    fun invalidateFreeSpaceCache() {
        cachedFreeSpaceBytes = -1L
        cachedFreeClusters = -1
    }
    
    private fun allocateClusters(count: Int): List<Int> {
        val bs = bootSector ?: return emptyList()
        val clusters = mutableListOf<Int>()
        
        try {
            val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
            val fatStartSector = bs.reservedSectors
            val totalClusters = ((bs.totalSectors - firstDataSector) / bs.sectorsPerCluster).toInt()
            
            // Validate we have enough clusters
            if (count > totalClusters - 1) {
                Log.e(TAG, "Not enough clusters: need $count, have ${totalClusters - 1}")
                return emptyList()
            }
            
            // Start from last allocated cluster hint (avoids rescanning from beginning)
            var clusterIndex = lastAllocatedCluster
            var currentFatSector = -1
            var fatSectorData: ByteArray? = null
            var fatDataBase = 0  // Offset into fatSectorData for the current sector
            var wrapped = false
            val prefetchCount = 32 // Read 32 sectors at a time (covers 4096 clusters)
            val clustersPerSector = SECTOR_SIZE / 4 // 128 clusters per 512-byte sector
            
            while (clusters.size < count) {
                // Wrap around if we reached the end
                if (clusterIndex > totalClusters) {
                    if (wrapped) break
                    clusterIndex = 2
                    wrapped = true
                }
                
                // Stop if we've wrapped back to start point
                if (wrapped && clusterIndex >= lastAllocatedCluster) break
                
                // Calculate which FAT sector contains this cluster entry
                val fatSectorOffset = (clusterIndex * 4) / SECTOR_SIZE
                
                // Load FAT sector if needed
                if (fatSectorOffset != currentFatSector) {
                    currentFatSector = fatSectorOffset
                    fatDataBase = 0
                    // Check per-sector cache first (dirty writes), then block cache
                    fatSectorData = fatSectorCache[fatSectorOffset]
                    if (fatSectorData == null) {
                        val blockStart = (fatSectorOffset / fatBlockSectors) * fatBlockSectors
                        val block = fatBlockCache[blockStart]
                        if (block != null) {
                            val sectorInBlock = fatSectorOffset - blockStart
                            if ((sectorInBlock + 1) * SECTOR_SIZE <= block.size) {
                                // Read directly from block — no copy needed for read-only scan
                                fatSectorData = block
                                fatDataBase = sectorInBlock * SECTOR_SIZE
                            }
                        }
                    }
                    if (fatSectorData == null) {
                        val batchData = volumeReader.readSectors(
                            (fatStartSector + fatSectorOffset).toLong(),
                            prefetchCount
                        ).getOrNull()
                        
                        if (batchData != null) {
                            // Store in block cache
                            val blockStart = (fatSectorOffset / fatBlockSectors) * fatBlockSectors
                            if (fatSectorOffset == blockStart) {
                                fatBlockCache.putIfAbsent(blockStart, batchData)
                            }
                            // Use batch data directly
                            fatSectorData = batchData
                            fatDataBase = 0
                        }
                        
                        if (fatSectorData == null) {
                            fatSectorData = volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrNull()
                            if (fatSectorData == null) {
                                Log.e(TAG, "Failed to read FAT sector at offset $fatSectorOffset")
                                break
                            }
                            fatDataBase = 0
                        }
                        
                        if (fatSectorCache.size >= maxFatCacheSize) {
                            fatSectorCache.keys.take(maxFatCacheSize / 4).forEach { fatSectorCache.remove(it) }
                        }
                    }
                }
                
                // Process all remaining entries in this sector in one tight loop
                // (no ByteBuffer allocation per entry — direct byte reads)
                val data = fatSectorData!!
                var offsetInSector = (clusterIndex * 4) % SECTOR_SIZE
                
                while (offsetInSector <= SECTOR_SIZE - 4 && clusters.size < count) {
                    // Check wrap/bounds on clusterIndex
                    if (clusterIndex > totalClusters) break
                    if (wrapped && clusterIndex >= lastAllocatedCluster) break
                    
                    // Read 4-byte LE FAT entry directly from byte array
                    val absOff = fatDataBase + offsetInSector
                    val b0 = data[absOff].toInt() and 0xFF
                    val b1 = data[absOff + 1].toInt() and 0xFF
                    val b2 = data[absOff + 2].toInt() and 0xFF
                    val b3 = data[absOff + 3].toInt() and 0xFF
                    val entry = (b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)) and 0x0FFFFFFF
                    
                    if (entry == 0) {
                        clusters.add(clusterIndex)
                        lastAllocatedCluster = clusterIndex + 1
                    }
                    
                    clusterIndex++
                    offsetInSector += 4
                }
                // Loop back to top to load next sector
            }
            
            if (clusters.size < count) {
                Log.e(TAG, "Not enough free clusters: found ${clusters.size}, needed $count")
                return emptyList()
            }
            
            // Decrement cached free cluster count
            if (cachedFreeClusters >= 0) {
                cachedFreeClusters -= clusters.size
            }
            
            // Update FSInfo sector with new hint so next mount starts from the right place
            updateFSInfo()
            
            return clusters
        } catch (e: Exception) {
            Log.e(TAG, "Failed to allocate clusters", e)
            return emptyList()
        }
    }
    
    /**
     * Update the FSInfo sector with current free cluster count and next free cluster hint.
     * This persists the allocation hint so future mounts don't need to scan the entire FAT.
     */
    private fun updateFSInfo() {
        try {
            val bs = bootSector ?: return
            // Boot sector stores FSInfo sector number at offset 48
            val bootSectorData = volumeReader.readSector(0).getOrNull() ?: return
            val fsInfoSectorNum = ByteBuffer.wrap(bootSectorData).order(ByteOrder.LITTLE_ENDIAN).getShort(48).toInt() and 0xFFFF
            if (fsInfoSectorNum < 1 || fsInfoSectorNum >= bs.reservedSectors) return
            
            val fsInfoData = volumeReader.readSector(fsInfoSectorNum.toLong()).getOrNull() ?: return
            val buf = ByteBuffer.wrap(fsInfoData).order(ByteOrder.LITTLE_ENDIAN)
            
            // Verify signatures
            if (buf.getInt(0) != 0x41615252 || buf.getInt(484) != 0x61417272) return
            
            // Update nxtFree (offset 492) and free count (offset 488)
            buf.putInt(492, lastAllocatedCluster)
            if (cachedFreeClusters >= 0) {
                buf.putInt(488, cachedFreeClusters)
            }
            
            volumeReader.writeSector(fsInfoSectorNum.toLong(), fsInfoData).getOrThrow()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update FSInfo sector", e)
        }
    }
    
    /**
     * Batch-write modified FAT sectors to both FAT copies.
     * Groups consecutive sector offsets into single writeSectors calls to
     * reduce individual encrypt+lock+I/O cycles (e.g., 200 individual writes → ~4 batch writes).
     */
    private fun batchWriteFATSectors(fatUpdates: Map<Int, ByteArray>) {
        if (fatUpdates.isEmpty()) return
        val bs = bootSector ?: return
        val fatStartSector = bs.reservedSectors
        val secondFATStart = fatStartSector + bs.sectorsPerFAT
        val sortedKeys = fatUpdates.keys.sorted()
        var idx = 0
        
        while (idx < sortedKeys.size) {
            // Find consecutive run of FAT sectors
            var runLen = 1
            while (idx + runLen < sortedKeys.size &&
                   sortedKeys[idx + runLen] == sortedKeys[idx] + runLen) {
                runLen++
            }
            
            val firstKey = sortedKeys[idx]
            
            if (runLen == 1) {
                // Single sector — use existing writeSector
                val sectorData = fatUpdates[firstKey]!!
                volumeReader.writeSector((fatStartSector + firstKey).toLong(), sectorData).getOrThrow()
                volumeReader.writeSector((secondFATStart + firstKey).toLong(), sectorData).getOrThrow()
                fatSectorCache[firstKey] = sectorData.copyOf()
                // Invalidate stale block cache entry containing this sector
                val blockStart = (firstKey / fatBlockSectors) * fatBlockSectors
                fatBlockCache.remove(blockStart)
            } else {
                // Combine consecutive sectors into one batch write
                val combinedData = ByteArray(runLen * SECTOR_SIZE)
                for (r in 0 until runLen) {
                    System.arraycopy(fatUpdates[sortedKeys[idx + r]]!!, 0, combinedData, r * SECTOR_SIZE, SECTOR_SIZE)
                }
                // writeSectors allocates its own encrypted copy, so combinedData is preserved for FAT2
                volumeReader.writeSectors((fatStartSector + firstKey).toLong(), combinedData).getOrThrow()
                volumeReader.writeSectors((secondFATStart + firstKey).toLong(), combinedData).getOrThrow()
                
                // Invalidate stale block cache entries and update per-sector dirty cache
                val invalidatedBlocks = mutableSetOf<Int>()
                for (r in 0 until runLen) {
                    val sectorKey = sortedKeys[idx + r]
                    fatSectorCache[sectorKey] = fatUpdates[sectorKey]!!.copyOf()
                    val blockStart = (sectorKey / fatBlockSectors) * fatBlockSectors
                    invalidatedBlocks.add(blockStart)
                }
                for (blockStart in invalidatedBlocks) {
                    fatBlockCache.remove(blockStart)
                }
            }
            
            idx += runLen
        }
    }
    
    /**
     * Write a single FAT entry value for a given cluster.
     */
    private fun writeFATEntry(cluster: Int, value: Int) {
        val bs = bootSector ?: return
        val fatStartSector = bs.reservedSectors
        val entryOffset = cluster * 4
        val fatSectorOffset = entryOffset / SECTOR_SIZE
        val offsetInSector = entryOffset % SECTOR_SIZE
        
        val fatSector = fatSectorCache[fatSectorOffset]?.copyOf()
            ?: volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
        
        ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(value)
        batchWriteFATSectors(mapOf(fatSectorOffset to fatSector))
    }
    
    private fun writeClusterChain(clusters: List<Int>) {
        val bs = bootSector ?: return
        val fatStartSector = bs.reservedSectors
        
        try {
            // Create map of FAT sectors we need to modify
            val fatUpdates = mutableMapOf<Int, ByteArray>()
            
            for (i in clusters.indices) {
                val cluster = clusters[i]
                val nextCluster = if (i < clusters.size - 1) {
                    clusters[i + 1]
                } else {
                    0x0FFFFFFF // EOF marker
                }
                
                // Calculate which FAT sector contains this cluster entry
                val entryOffset = cluster * 4
                val fatSectorOffset = entryOffset / SECTOR_SIZE
                val offsetInSector = entryOffset % SECTOR_SIZE
                
                // Get or read FAT sector — check local map, then FAT cache, then disk
                val fatSector = fatUpdates.getOrPut(fatSectorOffset) {
                    fatSectorCache[fatSectorOffset]?.copyOf()
                        ?: volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
                }
                
                // Write next cluster value
                ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(nextCluster)
            }
            
            // Batch-write consecutive FAT sectors (reduces N×2 individual
            // encrypt+lock+write cycles to ~2-4 batch operations total)
            batchWriteFATSectors(fatUpdates)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write cluster chain", e)
        }
    }
    
    /**
     * Reuse existing cluster chain if it has enough clusters, otherwise extend or reallocate.
     * When the existing chain is longer than needed, truncate the excess clusters.
     * When it's shorter, extend the chain by allocating additional clusters.
     * This avoids expensive free+realloc cycles for same-size overwrites (the common case)
     * and avoids freeing+reallocating 900 clusters when only 100 more are needed.
     */
    private fun reuseOrReallocateClusters(firstCluster: Int, clustersNeeded: Int): List<Int> {
        // Walk existing chain to collect ALL clusters (need full chain to extend or truncate)
        val existingChain = mutableListOf<Int>()
        var c = firstCluster
        while (c >= 2 && c < 0x0FFFFFF8) {
            existingChain.add(c)
            if (existingChain.size > clustersNeeded) break // Only need +1 beyond needed for truncation check
            c = readFATEntry(c).getOrElse { break }
        }
        
        if (existingChain.size >= clustersNeeded) {
            // Chain is long enough — reuse first clustersNeeded clusters
            if (existingChain.size > clustersNeeded) {
                // Mark the last reused cluster as EOC and free the tail
                val lastKeep = existingChain[clustersNeeded - 1]
                val firstFree = existingChain[clustersNeeded]
                writeFATEntry(lastKeep, 0x0FFFFFFF) // EOC
                freeClusters(firstFree)
                // Invalidate cluster chain cache for the old chain
                clusterChainCache.remove(firstCluster)
            }
            return existingChain.subList(0, clustersNeeded)
        }
        
        // Chain too short — EXTEND by allocating only the additional clusters needed.
        // This avoids freeing 900 clusters and reallocating 1000 when only 100 more are needed.
        val additional = clustersNeeded - existingChain.size
        val newClusters = allocateClusters(additional)
        if (newClusters.isEmpty()) {
            // Allocation failed — fall back to freeing all and trying fresh allocation
            freeClusters(firstCluster)
            clusterChainCache.remove(firstCluster)
            return allocateClusters(clustersNeeded)
        }
        
        // Link the last existing cluster to the first new cluster, then write the new chain
        val lastExisting = existingChain.last()
        writeFATEntry(lastExisting, newClusters[0])
        writeClusterChain(newClusters)
        
        // Invalidate cluster chain cache (chain has changed)
        clusterChainCache.remove(firstCluster)
        
        return existingChain + newClusters
    }
    
    private fun freeClusters(firstCluster: Int) {
        val bs = bootSector ?: return
        val fatStartSector = bs.reservedSectors
        
        try {
            var cluster = firstCluster
            val fatUpdates = mutableMapOf<Int, ByteArray>()
            
            while (cluster != 0 && cluster < 0x0FFFFFF8) {
                // Calculate which FAT sector contains this cluster entry
                val entryOffset = cluster * 4
                val fatSectorOffset = entryOffset / SECTOR_SIZE
                val offsetInSector = entryOffset % SECTOR_SIZE
                
                // Get or read FAT sector — check local map, then FAT cache, then disk
                val fatSector = fatUpdates.getOrPut(fatSectorOffset) {
                    fatSectorCache[fatSectorOffset]?.copyOf()
                        ?: volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
                }
                
                // Read next cluster before we overwrite
                val nextCluster = ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).int
                
                // Mark cluster as free
                ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0)
                
                cluster = nextCluster
            }
            
            // Batch-write consecutive FAT sectors (same optimization as writeClusterChain)
            batchWriteFATSectors(fatUpdates)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to free clusters", e)
        }
    }
    
    /**
     * Get the next cluster in the chain from the FAT.
     * Uses readFATEntry which has 32-sector prefetch cache for performance.
     */
    private fun getNextCluster(cluster: Int): Int {
        return readFATEntry(cluster).getOrElse {
            Log.e(TAG, "Failed to get next cluster for $cluster", it)
            0x0FFFFFFF // Return EOF on error
        }
    }
    
    /**
     * Append a new cluster to an existing cluster chain
     */
    private fun appendClusterToChain(lastCluster: Int, newCluster: Int) {
        val bs = bootSector ?: return
        val fatStartSector = bs.reservedSectors
        
        try {
            // Collect all FAT sector modifications into a batch map,
            // then use batchWriteFATSectors to write both FAT copies efficiently.
            val fatUpdates = mutableMapOf<Int, ByteArray>()
            
            // Update the last cluster to point to the new cluster
            val entryOffset = lastCluster * 4
            val fatSectorOffset = entryOffset / SECTOR_SIZE
            val offsetInSector = entryOffset % SECTOR_SIZE
            
            val fatSector = fatUpdates.getOrPut(fatSectorOffset) {
                fatSectorCache[fatSectorOffset]?.copyOf()
                    ?: volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
            }
            ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(newCluster)
            
            // Mark new cluster as EOF
            val newEntryOffset = newCluster * 4
            val newFatSectorOffset = newEntryOffset / SECTOR_SIZE
            val newOffsetInSector = newEntryOffset % SECTOR_SIZE
            
            val newFatSector = fatUpdates.getOrPut(newFatSectorOffset) {
                fatSectorCache[newFatSectorOffset]?.copyOf()
                    ?: volumeReader.readSector((fatStartSector + newFatSectorOffset).toLong()).getOrThrow()
            }
            ByteBuffer.wrap(newFatSector, newOffsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0x0FFFFFFF)
            
            // Batch write all modified FAT sectors to both FAT copies
            batchWriteFATSectors(fatUpdates)
            
            Log.d(TAG, "appendClusterToChain: chained $lastCluster -> $newCluster")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to append cluster to chain", e)
        }
    }
    
    /**
     * Copy a file within the same volume by reading decrypted data in batches and writing
     * to a newly allocated cluster chain. Avoids pipe overhead and dynamic allocation
     * by pre-allocating the exact number of clusters needed.
     *
     * @param sourcePath Path of the source file
     * @param targetParentPath Path of the target parent directory
     * @param targetName Name of the new file
     * @return Result with the path of the copied file
     */
    fun copyFileDirect(sourcePath: String, targetParentPath: String, targetName: String): Result<String> {
        // Phase 1: get source info and create target entry (under write lock)
        val bs = bootSector ?: return Result.failure(Exception("File system not initialized"))
        val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
        val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
        
        val sourceInfo = getFileInfoWithCluster(sourcePath).getOrThrow()
        if (sourceInfo.isDirectory) return Result.failure(Exception("Use copyDirectory for directories"))
        if (sourceInfo.size == 0L) {
            // Empty file — just create entry
            val newEntry = createFile(targetParentPath, targetName).getOrThrow()
            return Result.success(newEntry.path)
        }
        
        val sourceChain = getClusterChain(sourceInfo.firstCluster, Int.MAX_VALUE)
        val clustersNeeded = ((sourceInfo.size + clusterSize - 1) / clusterSize).toInt()
        
        // Allocate destination clusters and create directory entry (under write lock)
        data class CopyAllocation(val destClusters: List<Int>, val destPath: String)
        
        val allocation = writeLock.withLock {
            val newEntry = createDirectoryEntry(targetParentPath, targetName, isDirectory = false)
            val destClusters = allocateClusters(clustersNeeded)
            if (destClusters.isEmpty()) throw Exception("Failed to allocate clusters for copy")
            
            // Write cluster chain and update directory entry size
            writeClusterChain(destClusters)
            
            // Update the file's directory entry with cluster and size
            updateFileEntryClusterAndSize(newEntry.path, destClusters[0], sourceInfo.size)
            
            // Clear caches
            directoryCache.remove(normalizePath(targetParentPath))
            invalidateFreeSpaceCache()
            
            CopyAllocation(destClusters, newEntry.path)
        }
        
        // Phase 2: batch-copy data (no write lock needed — clusters are reserved)
        return try {
            val targetBatchBytes = 8 * 1024 * 1024
            val clustersPerBatch = (targetBatchBytes / clusterSize).coerceAtLeast(1)
            var bytesRemaining = sourceInfo.size
            var clusterIdx = 0
            
            while (clusterIdx < clustersNeeded) {
                val batchCount = minOf(clustersPerBatch, clustersNeeded - clusterIdx)
                val batchBytes = batchCount * clusterSize
                
                // Read source clusters in contiguous runs
                val batchBuffer = ByteArray(batchBytes)
                var batchOffset = 0
                var srcIdx = clusterIdx
                
                while (srcIdx < clusterIdx + batchCount) {
                    var runLen = 1
                    while (srcIdx + runLen < clusterIdx + batchCount &&
                           sourceChain[srcIdx + runLen] == sourceChain[srcIdx + runLen - 1] + 1) {
                        runLen++
                    }
                    val srcSector = firstDataSector.toLong() + ((sourceChain[srcIdx] - 2).toLong() * bs.sectorsPerCluster)
                    val srcData = volumeReader.readSectors(srcSector, runLen * bs.sectorsPerCluster).getOrThrow()
                    System.arraycopy(srcData, 0, batchBuffer, batchOffset * clusterSize, srcData.size)
                    batchOffset += runLen
                    srcIdx += runLen
                }
                
                // Write to destination clusters in contiguous runs
                var dstIdx = clusterIdx
                var bufOff = 0
                while (dstIdx < clusterIdx + batchCount) {
                    var runLen = 1
                    while (dstIdx + runLen < clusterIdx + batchCount &&
                           allocation.destClusters[dstIdx + runLen] == allocation.destClusters[dstIdx + runLen - 1] + 1) {
                        runLen++
                    }
                    val dstSector = firstDataSector.toLong() + ((allocation.destClusters[dstIdx] - 2).toLong() * bs.sectorsPerCluster)
                    val runBytes = runLen * clusterSize
                    volumeReader.writeSectorsInPlace(dstSector, batchBuffer, bufOff, runBytes).getOrThrow()
                    bufOff += runBytes
                    dstIdx += runLen
                }
                
                clusterIdx += batchCount
                bytesRemaining -= batchBytes
            }
            
            volumeReader.sync()
            Result.success(allocation.destPath)
        } catch (e: Exception) {
            Log.e(TAG, "Failed direct copy: $sourcePath -> $targetParentPath/$targetName", e)
            Result.failure(e)
        }
    }
    
    /**
     * Update a file's directory entry with a new first cluster and file size.
     */
    private fun updateFileEntryClusterAndSize(path: String, firstCluster: Int, fileSize: Long) {
        val bs = bootSector ?: return
        val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
        val parentPath = path.substringBeforeLast('/', "/")
        val fileName = path.substringAfterLast('/')
        
        val parentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
            bs.rootDirFirstCluster
        } else {
            getFileInfoWithCluster(parentPath).getOrThrow().firstCluster
        }
        
        var currentCluster = parentCluster
        while (currentCluster >= 2 && currentCluster < 0x0FFFFFF8) {
            val firstSectorOfCluster = ((currentCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
            val clusterData = volumeReader.readSectors(firstSectorOfCluster, bs.sectorsPerCluster).getOrThrow()
            
            var offset = 0
            var lfnName = ""
            while (offset < clusterData.size) {
                val firstByte = clusterData[offset].toInt() and 0xFF
                if (firstByte == 0x00) break
                if (firstByte == 0xE5) { offset += 32; continue }
                
                val attr = clusterData[offset + 11].toInt() and 0xFF
                if (attr == ATTR_LONG_NAME) {
                    lfnName = parseLongFileName(clusterData, offset) + lfnName
                    offset += 32; continue
                }
                
                val shortName = parseShortFileName(clusterData, offset)
                val entryName = if (lfnName.isNotEmpty()) lfnName else shortName
                lfnName = ""
                
                if (entryName.equals(fileName, ignoreCase = true)) {
                    ByteBuffer.wrap(clusterData, offset + 26, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((firstCluster and 0xFFFF).toShort())
                    ByteBuffer.wrap(clusterData, offset + 20, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((firstCluster shr 16).toShort())
                    ByteBuffer.wrap(clusterData, offset + 28, 4).order(ByteOrder.LITTLE_ENDIAN).putInt((fileSize and 0xFFFFFFFFL).toInt())
                    volumeReader.writeSectors(firstSectorOfCluster, clusterData).getOrThrow()
                    return
                }
                offset += 32
            }
            currentCluster = readFATEntry(currentCluster).getOrElse { break }
        }
    }

    override fun createFile(parentPath: String, name: String): Result<FileEntry> {
        return writeLock.withLock {
            try {
                val bs = bootSector ?: return@withLock Result.failure(Exception("File system not initialized"))
                
                // Validate name
                if (name.isEmpty() || name.contains('/')) {
                    return@withLock Result.failure(Exception("Invalid file name"))
                }
                
                // Check if file already exists
                val fullPath = if (parentPath == "/") "/$name" else "$parentPath/$name"
                if (exists(fullPath)) {
                    if (DEBUG_LOGGING) Log.d(TAG, "createFile: File already exists: $fullPath")
                    return@withLock Result.failure(Exception("File already exists"))
                }
                
                if (DEBUG_LOGGING) Log.d(TAG, "createFile: Creating $name in $parentPath")
                
                // Create directory entry
                val newEntry = createDirectoryEntry(parentPath, name, isDirectory = false)
                
                if (DEBUG_LOGGING) Log.d(TAG, "createFile: Successfully created entry for $fullPath")
                
                // Clear parent directory cache so it gets re-read
                directoryCache.remove(normalizePath(parentPath))
                // Cache the new entry immediately
                fileCache[normalizePath(newEntry.path)] = newEntry
                // Invalidate free space cache
                invalidateFreeSpaceCache()
                
                Result.success(newEntry)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create file", e)
                Result.failure(e)
            }
        }
    }
    
    /**
     * Move a file or directory entry from one parent to another in O(1) time.
     * This only relocates the directory entry — the file's data clusters remain untouched.
     * Much faster than copy+delete for large files.
     *
     * @param sourcePath Full path of the source file/directory
     * @param targetParentPath Full path of the target parent directory
     * @return Result with the new path of the moved entry
     */
    fun moveEntry(sourcePath: String, targetParentPath: String): Result<String> {
        return writeLock.withLock {
            try {
                val fileName = sourcePath.substringAfterLast('/')
                
                // 1. Read the source entry's metadata (cluster, size, attributes, timestamps)
                val sourceInfo = getFileInfoWithCluster(sourcePath).getOrThrow()
                
                // 2. Read the raw 8.3 directory entry bytes from the source parent
                val sourceParentPath = sourcePath.substringBeforeLast('/', "/")
                val bs = bootSector ?: return@withLock Result.failure(Exception("File system not initialized"))
                val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
                
                val sourceParentCluster = if (sourceParentPath == "/" || sourceParentPath.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    getFileInfoWithCluster(sourceParentPath).getOrThrow().firstCluster
                }
                
                var rawEntryBytes: ByteArray? = null
                var currentCluster = sourceParentCluster
                
                outerFind@ while (currentCluster >= 2 && currentCluster < 0x0FFFFFF8) {
                    val firstSectorOfCluster = ((currentCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
                    val clusterData = volumeReader.readSectors(firstSectorOfCluster, bs.sectorsPerCluster).getOrThrow()
                    
                    var offset = 0
                    var lfnName = ""
                    while (offset < clusterData.size) {
                        val firstByte = clusterData[offset].toInt() and 0xFF
                        if (firstByte == 0x00) break
                        if (firstByte == 0xE5) { offset += 32; continue }
                        
                        val attr = clusterData[offset + 11].toInt() and 0xFF
                        if (attr == ATTR_LONG_NAME) {
                            lfnName = parseLongFileName(clusterData, offset) + lfnName
                            offset += 32; continue
                        }
                        
                        val shortName = parseShortFileName(clusterData, offset)
                        val entryName = if (lfnName.isNotEmpty()) lfnName else shortName
                        
                        if (entryName.equals(fileName, ignoreCase = true)) {
                            rawEntryBytes = clusterData.copyOfRange(offset, offset + 32)
                            break@outerFind
                        }
                        lfnName = ""
                        offset += 32
                    }
                    currentCluster = readFATEntry(currentCluster).getOrElse { break }
                }
                
                if (rawEntryBytes == null) {
                    return@withLock Result.failure(Exception("Source entry not found: $sourcePath"))
                }
                
                // 3. Delete the source directory entry (marks LFN + 8.3 entries as 0xE5)
                deleteDirectoryEntry(sourcePath)
                
                // 4. Create a new entry in the target parent directory
                val targetParentCluster = if (targetParentPath == "/" || targetParentPath.isEmpty()) {
                    bs.rootDirFirstCluster
                } else {
                    getFileInfoWithCluster(targetParentPath).getOrThrow().firstCluster
                }
                
                val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
                
                // Determine if we need LFN
                val needsLfn = fileName.length > 12 || (fileName.contains('.') && (
                    fileName.substringBeforeLast('.').length > 8 || 
                    fileName.substringAfterLast('.').length > 3))
                val lfnEntriesNeeded = if (needsLfn) ((fileName.length + 12) / 13) else 0
                val totalEntriesNeeded = lfnEntriesNeeded + 1
                
                // Find space in target directory
                var tgtCluster = targetParentCluster
                var lastTgtCluster = tgtCluster
                var freeOffset = -1
                var targetCluster = -1
                var tgtClusterData = ByteArray(clusterSize)
                
                while (tgtCluster >= 2 && tgtCluster < 0x0FFFFFF8) {
                    lastTgtCluster = tgtCluster
                    val firstSectorOfCluster = ((tgtCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
                    tgtClusterData = volumeReader.readSectors(firstSectorOfCluster, bs.sectorsPerCluster).getOrThrow()
                    
                    var consecutiveFree = 0
                    var foundOffset = -1
                    for (off in 0 until tgtClusterData.size step 32) {
                        val fb = tgtClusterData[off].toInt() and 0xFF
                        if (fb == 0x00 || fb == 0xE5) {
                            if (consecutiveFree == 0) foundOffset = off
                            consecutiveFree++
                            if (consecutiveFree >= totalEntriesNeeded) {
                                freeOffset = foundOffset
                                targetCluster = tgtCluster
                                break
                            }
                        } else {
                            consecutiveFree = 0
                            foundOffset = -1
                        }
                    }
                    if (freeOffset != -1) break
                    tgtCluster = getNextCluster(tgtCluster)
                }
                
                if (freeOffset == -1) {
                    val newClusters = allocateClusters(1)
                    if (newClusters.isEmpty()) throw Exception("Failed to allocate cluster for target directory")
                    val newCluster = newClusters[0]
                    appendClusterToChain(lastTgtCluster, newCluster)
                    tgtClusterData = ByteArray(clusterSize)
                    val newClusterFirstSector = ((newCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
                    volumeReader.writeSectors(newClusterFirstSector, tgtClusterData).getOrThrow()
                    targetCluster = newCluster
                    freeOffset = 0
                }
                
                val targetFirstSector = ((targetCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
                tgtClusterData = volumeReader.readSectors(targetFirstSector, bs.sectorsPerCluster).getOrThrow()
                
                // Write LFN entries if needed
                if (needsLfn) {
                    val checksum = calculateLfnChecksum(rawEntryBytes.copyOfRange(0, 11))
                    val nameChars = fileName.toCharArray()
                    val chunks = mutableListOf<List<Char>>()
                    var charIndex = 0
                    while (charIndex < nameChars.size) {
                        val chunk = mutableListOf<Char>()
                        for (i in 0 until 13) {
                            if (charIndex < nameChars.size) chunk.add(nameChars[charIndex++])
                            else if (i == 0) { chunk.add('\u0000'); break }
                            else chunk.add('\uFFFF')
                        }
                        chunks.add(chunk)
                    }
                    
                    var currentOffset = freeOffset
                    for (lfnIndex in chunks.size downTo 1) {
                        val lfnEntry = ByteArray(32)
                        lfnEntry[0] = if (lfnIndex == chunks.size) (lfnIndex or 0x40).toByte() else lfnIndex.toByte()
                        val chars = chunks[lfnIndex - 1]
                        val offsets = listOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
                        for (i in 0 until minOf(13, chars.size)) {
                            val c = chars[i].code
                            lfnEntry[offsets[i]] = (c and 0xFF).toByte()
                            lfnEntry[offsets[i] + 1] = (c shr 8).toByte()
                        }
                        for (i in chars.size until 13) {
                            lfnEntry[offsets[i]] = 0xFF.toByte()
                            lfnEntry[offsets[i] + 1] = 0xFF.toByte()
                        }
                        lfnEntry[11] = 0x0F; lfnEntry[12] = 0; lfnEntry[13] = checksum
                        lfnEntry[26] = 0; lfnEntry[27] = 0
                        System.arraycopy(lfnEntry, 0, tgtClusterData, currentOffset, 32)
                        currentOffset += 32
                    }
                    System.arraycopy(rawEntryBytes, 0, tgtClusterData, currentOffset, 32)
                } else {
                    System.arraycopy(rawEntryBytes, 0, tgtClusterData, freeOffset, 32)
                }
                
                volumeReader.writeSectors(targetFirstSector, tgtClusterData).getOrThrow()
                
                // Update ".." entry if moving a directory
                if (sourceInfo.isDirectory && sourceInfo.firstCluster >= 2) {
                    val dirFirstSector = ((sourceInfo.firstCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
                    val dirData = volumeReader.readSectors(dirFirstSector, bs.sectorsPerCluster).getOrThrow()
                    if (dirData[32] == '.'.code.toByte() && dirData[33] == '.'.code.toByte()) {
                        ByteBuffer.wrap(dirData, 32 + 26, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((targetParentCluster and 0xFFFF).toShort())
                        ByteBuffer.wrap(dirData, 32 + 20, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((targetParentCluster shr 16).toShort())
                        volumeReader.writeSectors(dirFirstSector, dirData).getOrThrow()
                    }
                }
                
                // 5. Invalidate caches for both old and new parents
                directoryCache.remove(sourceParentPath)
                directoryCache.remove(targetParentPath)
                directoryCache.remove(sourcePath)
                fileCache.remove(sourcePath)
                if (sourceParentPath == "/" || sourceParentPath.isEmpty()) {
                    directoryCache.remove(""); directoryCache.remove("/")
                }
                if (targetParentPath == "/" || targetParentPath.isEmpty()) {
                    directoryCache.remove(""); directoryCache.remove("/")
                }
                
                val newPath = if (targetParentPath == "/") "/$fileName" else "$targetParentPath/$fileName"
                if (DEBUG_LOGGING) Log.d(TAG, "moveEntry: Moved $sourcePath -> $newPath (O(1) directory entry relocation)")
                
                Result.success(newPath)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to move entry: $sourcePath -> $targetParentPath", e)
                Result.failure(e)
            }
        }
    }
    
    override fun createDirectory(parentPath: String, name: String): Result<FileEntry> {
        return writeLock.withLock {
            try {
                if (DEBUG_LOGGING) Log.d(TAG, "createDirectory: name=$name, parentPath=$parentPath")
                val bs = bootSector ?: return@withLock Result.failure(Exception("File system not initialized"))
                
                // Validate name
                if (name.isEmpty() || name.contains('/')) {
                    return@withLock Result.failure(Exception("Invalid directory name"))
                }
                
                // Check if directory already exists
                val fullPath = if (parentPath == "/") "/$name" else "$parentPath/$name"
                if (exists(fullPath)) {
                    return@withLock Result.failure(Exception("Directory already exists"))
                }
                
                // Create directory entry
                val newEntry = createDirectoryEntry(parentPath, name, isDirectory = true)
                if (DEBUG_LOGGING) Log.d(TAG, "createDirectory: created entry at ${newEntry.path}, firstCluster=${newEntry.firstCluster}")
                
                // Clear parent directory cache so it gets re-read
                directoryCache.remove(normalizePath(parentPath))
                // Also clear the new directory from cache to force re-read
                directoryCache.remove(normalizePath(fullPath))
                // Cache the new entry immediately
                fileCache[normalizePath(newEntry.path)] = newEntry
                // Invalidate free space cache
                invalidateFreeSpaceCache()
                
                Result.success(newEntry)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create directory", e)
                Result.failure(e)
            }
        }
    }
    
    override fun delete(path: String): Result<Unit> {
        return writeLock.withLock {
            try {
                if (DEBUG_LOGGING) Log.d(TAG, "delete: Starting deletion of $path")
                
                if (path == "/") {
                    return@withLock Result.failure(Exception("Cannot delete root directory"))
                }
                
                // Clear caches first
                directoryCache.remove(path)
                fileCache.remove(path)
                
                val fileInfo = getFileInfo(path).getOrThrow()
                if (DEBUG_LOGGING) Log.d(TAG, "delete: Found entry, isDirectory=${fileInfo.isDirectory}")
                
                // For directories, recursively delete contents first
                if (fileInfo.isDirectory) {
                    val entries = listDirectory(path).getOrThrow()
                    if (DEBUG_LOGGING) Log.d(TAG, "delete: Directory has ${entries.size} entries to delete")
                    for (entry in entries) {
                        // Recursively delete each child
                        val childResult = deleteRecursive(entry.path)
                        if (childResult.isFailure) {
                            return@withLock childResult
                        }
                    }
                    // Clear cache again after deleting children
                    directoryCache.remove(path)
                }
                
                // Mark directory entry as deleted
                if (DEBUG_LOGGING) Log.d(TAG, "delete: Now deleting the entry itself at $path")
                deleteDirectoryEntry(path)
                
                // Clear caches - handle both "/" and "" as root path representations
                val parentPath = path.substringBeforeLast('/', "/")
                directoryCache.remove(parentPath)
                directoryCache.remove(path)
                fileCache.remove(path)
                // Also clear root under both possible keys
                if (parentPath == "" || parentPath == "/") {
                    directoryCache.remove("")
                    directoryCache.remove("/")
                }
                // Invalidate free space cache
                invalidateFreeSpaceCache()
                
                if (DEBUG_LOGGING) Log.d(TAG, "delete: Successfully deleted")
                Result.success(Unit)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to delete", e)
                Result.failure(e)
            }
        }
    }
    
    /**
     * Recursively delete a file or directory (internal, called within write lock)
     */
    private fun deleteRecursive(path: String): Result<Unit> {
        try {
            // Clear cache for this path first to get fresh info
            directoryCache.remove(path)
            fileCache.remove(path)
            
            val fileInfo = getFileInfo(path).getOrThrow()
            
            // For directories, recursively delete contents first
            if (fileInfo.isDirectory) {
                val entries = listDirectory(path).getOrThrow()
                for (entry in entries) {
                    val childResult = deleteRecursive(entry.path)
                    if (childResult.isFailure) {
                        return childResult
                    }
                }
                // Clear directory cache again after deleting children
                directoryCache.remove(path)
            }
            
            // Mark directory entry as deleted
            if (DEBUG_LOGGING) Log.d(TAG, "deleteRecursive: Deleting entry")
            deleteDirectoryEntry(path)
            
            // Clear caches - handle both "/" and "" as root path representations
            val parentPath = path.substringBeforeLast('/', "/")
            directoryCache.remove(parentPath)
            directoryCache.remove(path)
            fileCache.remove(path)
            // Also clear root under both possible keys
            if (parentPath == "" || parentPath == "/") {
                directoryCache.remove("")
                directoryCache.remove("/")
            }
            
            if (DEBUG_LOGGING) Log.d(TAG, "deleteRecursive: Successfully deleted")
            return Result.success(Unit)
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete recursively", e)
            return Result.failure(e)
        }
    }
    
    /**
     * Create a directory entry in the parent directory
     */
    private fun createDirectoryEntry(parentPath: String, name: String, isDirectory: Boolean): FileEntry {
        val bs = bootSector ?: throw Exception("File system not initialized")
        
        // Get parent directory cluster
        val parentFirstCluster = if (parentPath == "/" || parentPath.isEmpty()) {
            bs.rootDirFirstCluster
        } else {
            val parentInfo = getFileInfoWithCluster(parentPath).getOrThrow()
            if (parentInfo.firstCluster == 0) {
                throw Exception("Parent directory has no cluster allocated: $parentPath")
            }
            parentInfo.firstCluster
        }
        
        // Calculate first sector of parent cluster
        val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
        val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
        
        // Check if we need LFN entries (name longer than 8.3)
        val needsLfn = name.length > 12 || (name.contains('.') && (
            name.substringBeforeLast('.').length > 8 || 
            name.substringAfterLast('.').length > 3))
        
        val lfnEntriesNeeded = if (needsLfn) {
            ((name.length + 12) / 13) // Each LFN entry holds 13 characters
        } else {
            0
        }
        
        val totalEntriesNeeded = lfnEntriesNeeded + 1 // LFN entries + 8.3 entry
        
        // Follow the cluster chain to find free entries or allocate new cluster
        var currentCluster = parentFirstCluster
        var lastCluster = currentCluster
        var freeOffset = -1
        var targetCluster = -1
        var clusterData = ByteArray(clusterSize)
        
        while (currentCluster != 0 && currentCluster < 0x0FFFFFF8) {
            lastCluster = currentCluster
            
            // Read this cluster in one bulk operation
            val firstSectorOfCluster = ((currentCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
            clusterData = volumeReader.readSectors(firstSectorOfCluster, bs.sectorsPerCluster).getOrThrow()
            
            // Look for free entries in this cluster
            var consecutiveFree = 0
            var foundOffset = -1
            for (offset in 0 until clusterData.size step 32) {
                val firstByte = clusterData[offset].toInt() and 0xFF
                if (firstByte == 0x00 || firstByte == 0xE5) {
                    if (consecutiveFree == 0) {
                        foundOffset = offset
                    }
                    consecutiveFree++
                    if (consecutiveFree >= totalEntriesNeeded) {
                        freeOffset = foundOffset
                        targetCluster = currentCluster
                        break
                    }
                } else {
                    consecutiveFree = 0
                    foundOffset = -1
                }
            }
            
            if (freeOffset != -1) {
                break // Found space in this cluster
            }
            
            // Get next cluster from FAT
            currentCluster = getNextCluster(currentCluster)
        }
        
        // If no space found, allocate a new cluster for the directory
        if (freeOffset == -1) {
            Log.d(TAG, "createDirectoryEntry: No space in existing clusters, allocating new cluster for directory")
            val newClusters = allocateClusters(1)
            if (newClusters.isEmpty()) {
                val freeBytes = getFreeSpaceBytes()
                if (freeBytes == 0L) {
                    throw Exception("Disk full - no free space available in the container")
                } else {
                    throw Exception("Failed to allocate cluster for directory (${freeBytes / 1024} KB free)")
                }
            }
            
            val newCluster = newClusters[0]
            Log.d(TAG, "createDirectoryEntry: Allocated new cluster $newCluster, chaining to $lastCluster")
            
            // Chain the new cluster to the last cluster of the directory
            appendClusterToChain(lastCluster, newCluster)
            
            // Initialize the new cluster with zeros (all entries free)
            clusterData = ByteArray(clusterSize)
            val newClusterFirstSector = ((newCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
            volumeReader.writeSectors(newClusterFirstSector, clusterData).getOrThrow()
            
            targetCluster = newCluster
            freeOffset = 0 // First entry in the new cluster
        }
        
        // Now we have freeOffset and targetCluster set
        // Re-read the target cluster if needed
        if (targetCluster != lastCluster || freeOffset == 0) {
            val firstSectorOfCluster = ((targetCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
            clusterData = volumeReader.readSectors(firstSectorOfCluster, bs.sectorsPerCluster).getOrThrow()
        }
        
        // Create 8.3 short name
        val shortName: String
        val ext: String
        if (name.contains('.')) {
            val namePart = name.substringBeforeLast('.')
            ext = name.substringAfterLast('.').take(3).uppercase().padEnd(3, ' ')
            shortName = namePart.take(8).uppercase().padEnd(8, ' ')
        } else {
            shortName = name.take(8).uppercase().padEnd(8, ' ')
            ext = "   "
        }
        
        // Create main 8.3 directory entry
        val entryData = ByteArray(32)
        System.arraycopy(shortName.toByteArray(), 0, entryData, 0, 8)
        System.arraycopy(ext.toByteArray(), 0, entryData, 8, 3)
        
        // Attributes
        entryData[11] = if (isDirectory) ATTR_DIRECTORY.toByte() else ATTR_ARCHIVE.toByte()
        
        // Creation/modification time and date (use current time)
        val now = System.currentTimeMillis()
        val calendar = java.util.Calendar.getInstance().apply { timeInMillis = now }
        val fatDate = encodeFATDate(calendar)
        val fatTime = encodeFATTime(calendar)
        
        // Write date/time
        ByteBuffer.wrap(entryData, 22, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(fatTime.toShort())
        ByteBuffer.wrap(entryData, 24, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(fatDate.toShort())
        
        // Allocate cluster for directories
        var dirFirstCluster = 0
        if (isDirectory) {
            // Allocate one cluster for the new directory
            val clusters = allocateClusters(1)
            if (clusters.isEmpty()) {
                throw Exception("Failed to allocate cluster for new directory")
            }
            dirFirstCluster = clusters[0]
            
            // Mark the cluster as EOF in the FAT (important!)
            writeClusterChain(clusters)
            
            // Write cluster number to entry (low word at offset 26, high word at offset 20)
            ByteBuffer.wrap(entryData, 26, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((dirFirstCluster and 0xFFFF).toShort())
            ByteBuffer.wrap(entryData, 20, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((dirFirstCluster shr 16).toShort())
            
            // Initialize the directory cluster with "." and ".." entries
            initializeDirectoryCluster(dirFirstCluster, parentFirstCluster, fatDate, fatTime)
        } else {
            // First cluster (0 for new empty file)
            entryData[26] = 0
            entryData[27] = 0
            entryData[20] = 0
            entryData[21] = 0
        }
        
        // File size (0 for directories and new files)
        ByteBuffer.wrap(entryData, 28, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0)
        
        // Write LFN entries if needed (in reverse order)
        if (needsLfn) {
            val checksum = calculateLfnChecksum(shortName.toByteArray() + ext.toByteArray())
            var currentOffset = freeOffset
            
            // Split name into 13-character chunks FIRST
            val nameChars = name.toCharArray()
            val chunks = mutableListOf<List<Char>>()
            var charIndex = 0
            
            while (charIndex < nameChars.size) {
                val chunk = mutableListOf<Char>()
                for (i in 0 until 13) {
                    if (charIndex < nameChars.size) {
                        chunk.add(nameChars[charIndex++])
                    } else if (i == 0) {
                        chunk.add('\u0000') // Null terminator after last char
                        break
                    } else {
                        chunk.add('\uFFFF') // Padding
                    }
                }
                chunks.add(chunk)
            }
            
            // Write LFN entries in REVERSE order (last chunk first)
            for (lfnIndex in chunks.size downTo 1) {
                val lfnEntry = ByteArray(32)
                
                // Sequence number (with 0x40 flag on last entry)
                lfnEntry[0] = if (lfnIndex == chunks.size) {
                    (lfnIndex or 0x40).toByte()
                } else {
                    lfnIndex.toByte()
                }
                
                // Get the characters for this LFN entry
                val chars = chunks[lfnIndex - 1]
                
                // Write characters at specific offsets
                val offsets = listOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
                for (i in 0 until minOf(13, chars.size)) {
                    val c = chars[i].code
                    lfnEntry[offsets[i]] = (c and 0xFF).toByte()
                    lfnEntry[offsets[i] + 1] = (c shr 8).toByte()
                }
                
                // Fill remaining slots with 0xFFFF if needed
                for (i in chars.size until 13) {
                    lfnEntry[offsets[i]] = 0xFF.toByte()
                    lfnEntry[offsets[i] + 1] = 0xFF.toByte()
                }
                
                // Attributes (0x0F = LFN)
                lfnEntry[11] = 0x0F
                
                // Type (always 0 for LFN)
                lfnEntry[12] = 0
                
                // Checksum
                lfnEntry[13] = checksum
                
                // First cluster (always 0 for LFN)
                lfnEntry[26] = 0
                lfnEntry[27] = 0
                
                // Copy LFN entry to cluster data
                System.arraycopy(lfnEntry, 0, clusterData, currentOffset, 32)
                currentOffset += 32
            }
            
            // Now write the 8.3 entry after LFN entries
            System.arraycopy(entryData, 0, clusterData, currentOffset, 32)
        } else {
            // Just write the 8.3 entry
            System.arraycopy(entryData, 0, clusterData, freeOffset, 32)
        }
        
        // Write back modified cluster to the target cluster
        val targetSectorOfCluster = ((targetCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
        if (DEBUG_LOGGING) Log.d(TAG, "createDirectoryEntry: Writing to cluster=$targetCluster sector=$targetSectorOfCluster freeOffset=$freeOffset totalEntries=$totalEntriesNeeded needsLfn=$needsLfn")
        volumeReader.writeSectors(targetSectorOfCluster, clusterData).getOrThrow()
        
        // Verify write by reading back (only in debug mode to avoid extra I/O)
        if (DEBUG_LOGGING) {
            val verifyData = volumeReader.readSectors(targetSectorOfCluster, bs.sectorsPerCluster).getOrThrow()
            val entryCheckOffset = if (needsLfn) freeOffset + (lfnEntriesNeeded * 32) else freeOffset
            val verifyByte0 = verifyData[entryCheckOffset].toInt() and 0xFF
            val verifyAttr = verifyData[entryCheckOffset + 11].toInt() and 0xFF
            val verifyMatchesWrite = verifyData.contentEquals(clusterData)
            Log.d(TAG, "createDirectoryEntry: VERIFY readback at offset=$entryCheckOffset byte0=0x${verifyByte0.toString(16)} attr=0x${verifyAttr.toString(16)} fullMatch=$verifyMatchesWrite")
        }
        
        // Return the original long name if LFN was used, otherwise the short name
        val actualName = if (needsLfn) name else parseShortFileName(entryData, 0)
        val fullPath = if (parentPath == "/") "/$actualName" else "$parentPath/$actualName"
        
        return FileEntry(
            name = actualName,
            path = fullPath,
            isDirectory = isDirectory,
            size = 0,
            lastModified = now,
            mimeType = if (isDirectory) "vnd.android.document/directory" else guessMimeType(name),
            firstCluster = dirFirstCluster
        )
    }
    
    /**
     * Initialize a directory cluster with "." and ".." entries
     */
    private fun initializeDirectoryCluster(cluster: Int, parentCluster: Int, fatDate: Int, fatTime: Int) {
        val bs = bootSector ?: throw Exception("File system not initialized")
        
        Log.d(TAG, "initializeDirectoryCluster: cluster=$cluster, parentCluster=$parentCluster")
        
        val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
        val firstSectorOfCluster = ((cluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
        
        // Create cluster data, initially all zeros (important - marks end of directory)
        val clusterData = ByteArray(bs.sectorsPerCluster * SECTOR_SIZE)
        
        // Create "." entry (points to this directory)
        val dotEntry = ByteArray(32)
        dotEntry[0] = '.'.code.toByte()
        for (i in 1 until 11) dotEntry[i] = ' '.code.toByte()
        dotEntry[11] = ATTR_DIRECTORY.toByte()
        ByteBuffer.wrap(dotEntry, 22, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(fatTime.toShort())
        ByteBuffer.wrap(dotEntry, 24, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(fatDate.toShort())
        ByteBuffer.wrap(dotEntry, 26, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((cluster and 0xFFFF).toShort())
        ByteBuffer.wrap(dotEntry, 20, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((cluster shr 16).toShort())
        
        // Create ".." entry (points to parent directory)
        val dotDotEntry = ByteArray(32)
        dotDotEntry[0] = '.'.code.toByte()
        dotDotEntry[1] = '.'.code.toByte()
        for (i in 2 until 11) dotDotEntry[i] = ' '.code.toByte()
        dotDotEntry[11] = ATTR_DIRECTORY.toByte()
        ByteBuffer.wrap(dotDotEntry, 22, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(fatTime.toShort())
        ByteBuffer.wrap(dotDotEntry, 24, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(fatDate.toShort())
        // For "..", if parent is root directory, cluster should be 0 (per FAT32 spec)
        val parentClusterValue = if (parentCluster == bs.rootDirFirstCluster) 0 else parentCluster
        ByteBuffer.wrap(dotDotEntry, 26, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((parentClusterValue and 0xFFFF).toShort())
        ByteBuffer.wrap(dotDotEntry, 20, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((parentClusterValue shr 16).toShort())
        
        // Copy entries to cluster data
        System.arraycopy(dotEntry, 0, clusterData, 0, 32)
        System.arraycopy(dotDotEntry, 0, clusterData, 32, 32)
        
        Log.d(TAG, "initializeDirectoryCluster: dotEntry[0]=0x${dotEntry[0].toInt().and(0xFF).toString(16)}, dotDotEntry[0]=0x${dotDotEntry[0].toInt().and(0xFF).toString(16)}")
        
        // Write cluster data in one bulk write
        volumeReader.writeSectors(firstSectorOfCluster, clusterData).getOrThrow()
        
        // Verify write by reading back (only in debug mode to avoid extra I/O)
        if (DEBUG_LOGGING) {
            val verifyData = volumeReader.readSector(firstSectorOfCluster).getOrThrow()
            val verifyByte0 = verifyData[0].toInt() and 0xFF
            val verifyByte32 = verifyData[32].toInt() and 0xFF
            Log.d(TAG, "initializeDirectoryCluster: VERIFY - byte[0]=0x${verifyByte0.toString(16)}, byte[32]=0x${verifyByte32.toString(16)}")
            if (verifyByte0 != 0x2E || verifyByte32 != 0x2E) {
                Log.e(TAG, "initializeDirectoryCluster: VERIFICATION FAILED! Expected 0x2E but got 0x${verifyByte0.toString(16)} and 0x${verifyByte32.toString(16)}")
            }
        }
        
        Log.d(TAG, "Initialized directory cluster $cluster with . and .. entries")
    }
    
    /**
     * Delete a directory entry by marking it as deleted (0xE5)
     * Also marks associated LFN entries as deleted
     */
    private fun deleteDirectoryEntry(path: String) {
        val bs = bootSector ?: throw Exception("File system not initialized")
        
        val parentPath = path.substringBeforeLast('/', "/")
        val fileName = path.substringAfterLast('/')
        
        // Get parent directory cluster
        var currentCluster = if (parentPath == "/" || parentPath.isEmpty()) {
            bs.rootDirFirstCluster
        } else {
            getFileInfoWithCluster(parentPath).getOrThrow().firstCluster
        }
        
        val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
        val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
        var found = false
        
        // Follow cluster chain
        while (currentCluster >= 2 && currentCluster < 0x0FFFFFF8 && !found) {
            val firstSectorOfCluster = ((currentCluster - 2).toLong() * bs.sectorsPerCluster) + firstDataSector
            
            // Read cluster data in one bulk read
            val clusterData = volumeReader.readSectors(firstSectorOfCluster, bs.sectorsPerCluster).getOrThrow()
            
            // Parse directory entries, tracking LFN entries
            var offset = 0
            var lfnName = ""
            var lfnStartOffset = -1  // Track where LFN sequence started
            
            while (offset < clusterData.size) {
                val firstByte = clusterData[offset].toInt() and 0xFF
                
                // End of directory
                if (firstByte == 0x00) break
                
                // Deleted entry - reset LFN tracking
                if (firstByte == 0xE5) {
                    lfnName = ""
                    lfnStartOffset = -1
                    offset += 32
                    continue
                }
                
                val attr = clusterData[offset + 11].toInt() and 0xFF
                
                // Long file name entry
                if (attr == ATTR_LONG_NAME) {
                    // Check if this is the last (first in sequence) LFN entry
                    val ordinal = firstByte and 0x3F
                    val isLast = (firstByte and 0x40) != 0
                    if (isLast) {
                        lfnStartOffset = offset  // Start of LFN sequence
                    }
                    lfnName = parseLongFileName(clusterData, offset) + lfnName
                    offset += 32
                    continue
                }
                
                // Skip volume label
                if ((attr and ATTR_VOLUME_ID) != 0) {
                    lfnName = ""
                    lfnStartOffset = -1
                    offset += 32
                    continue
                }
                
                // This is a short (8.3) entry - check if it matches
                val shortName = parseShortFileName(clusterData, offset)
                val entryName = if (lfnName.isNotEmpty()) lfnName else shortName
                
                if (entryName.equals(fileName, ignoreCase = true)) {
                    // Mark short entry as deleted
                    clusterData[offset] = 0xE5.toByte()
                    
                    // Mark all associated LFN entries as deleted
                    if (lfnStartOffset >= 0) {
                        var lfnOffset = lfnStartOffset
                        while (lfnOffset < offset) {
                            val lfnAttr = clusterData[lfnOffset + 11].toInt() and 0xFF
                            if (lfnAttr == ATTR_LONG_NAME) {
                                clusterData[lfnOffset] = 0xE5.toByte()
                            }
                            lfnOffset += 32
                        }
                    }
                    
                    found = true
                    
                    // Write back modified cluster in one bulk write
                    volumeReader.writeSectors(firstSectorOfCluster, clusterData).getOrThrow()
                    break
                }
                
                // Reset for next entry
                lfnName = ""
                lfnStartOffset = -1
                offset += 32
            }
            
            if (!found) {
                // Move to next cluster in chain
                currentCluster = getNextCluster(currentCluster)
            }
        }
        
        if (!found) {
            throw Exception("Entry not found: $fileName")
        }
    }
    
    private fun encodeFATDate(calendar: java.util.Calendar): Int {
        val year = calendar.get(java.util.Calendar.YEAR) - 1980
        val month = calendar.get(java.util.Calendar.MONTH) + 1
        val day = calendar.get(java.util.Calendar.DAY_OF_MONTH)
        return ((year and 0x7F) shl 9) or ((month and 0x0F) shl 5) or (day and 0x1F)
    }
    
    private fun encodeFATTime(calendar: java.util.Calendar): Int {
        val hour = calendar.get(java.util.Calendar.HOUR_OF_DAY)
        val minute = calendar.get(java.util.Calendar.MINUTE)
        val second = calendar.get(java.util.Calendar.SECOND) / 2
        return ((hour and 0x1F) shl 11) or ((minute and 0x3F) shl 5) or (second and 0x1F)
    }
    
    /**
     * Calculate LFN checksum for 8.3 name
     */
    private fun calculateLfnChecksum(shortName: ByteArray): Byte {
        var checksum = 0
        for (i in 0 until 11) {
            checksum = ((checksum and 1) shl 7) + (checksum shr 1) + (shortName[i].toInt() and 0xFF)
            checksum = checksum and 0xFF
        }
        return checksum.toByte()
    }
}
