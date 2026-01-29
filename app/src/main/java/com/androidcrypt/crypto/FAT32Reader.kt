package com.androidcrypt.crypto

import android.util.Log
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.Charset
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
    // Using ConcurrentHashMap for thread safety during parallel reads
    private val fatSectorCache = java.util.concurrent.ConcurrentHashMap<Int, ByteArray>()
    private val maxFatCacheSize = 256 // Cache up to 256 FAT sectors (128KB typical) for better performance
    
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
    
    /**
     * Get the file system info (returns null if not initialized)
     */
    fun getFileSystemInfo(): FileSystemInfo? = fsInfo
    
    /**
     * Normalize path for cache keys - FAT32 is case-insensitive
     */
    private fun normalizePath(path: String): String {
        return path.lowercase().trimEnd('/')
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
            
            Result.success(fsInfo!!)
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize FAT32 reader", e)
            Result.failure(e)
        }
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
                Log.d(TAG, "LISTDIR: '$path' cache hit after lock (${System.currentTimeMillis() - listStart}ms)")
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
                Log.d(TAG, "LISTDIR: '$path' loaded ${entries.size} entries in ${System.currentTimeMillis() - listStart}ms")
                Result.success(entries)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to list directory: $path", e)
                Result.failure(e)
            }
        }
    }
    
    private fun readDirectoryCluster(startCluster: Int, parentPath: String = "/"): List<FileEntry> {
        val bs = bootSector ?: return emptyList()
        val entries = mutableListOf<FileEntry>()
        
        try {
            val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
            var currentCluster = startCluster
            var lfnName = ""
            var clusterCount = 0
            
            if (DEBUG_LOGGING) Log.d(TAG, "readDirectoryCluster: Starting to read directory at cluster $startCluster for path $parentPath")
            
            // Follow the cluster chain for directories that span multiple clusters
            while (currentCluster >= 2 && currentCluster < 0x0FFFFFF8) {
                clusterCount++
                val firstSectorOfCluster = ((currentCluster - 2) * bs.sectorsPerCluster) + firstDataSector
                
                // Read all sectors in this cluster in one bulk read
                val clusterData = volumeReader.readSectors(firstSectorOfCluster.toLong(), bs.sectorsPerCluster).getOrNull()
                    ?: break
                
                // Parse directory entries (32 bytes each)
                var offset = 0
                
                while (offset < clusterData.size) {
                    val firstByte = clusterData[offset].toInt() and 0xFF
                    
                    // End of entries in this cluster (0x00 means no more entries)
                    // But we still need to check if there are more clusters in the chain
                    if (firstByte == 0x00) {
                        // Skip remaining entries in this cluster and move to next cluster
                        break
                    }
                    
                    // Deleted entry
                    if (firstByte == 0xE5) {
                        offset += 32
                        continue
                    }
                    
                    val attr = clusterData[offset + 11].toInt() and 0xFF
                    
                    // Long file name entry
                    if (attr == ATTR_LONG_NAME) {
                        lfnName = parseLongFileName(clusterData, offset) + lfnName
                        offset += 32
                        continue
                    }
                    
                    // Skip volume label and hidden system files
                    if ((attr and ATTR_VOLUME_ID) != 0) {
                        offset += 32
                        continue
                    }
                    
                    // Parse short file name
                    val shortName = parseShortFileName(clusterData, offset)
                    val name = if (lfnName.isNotEmpty()) lfnName else shortName
                    lfnName = ""
                    
                    // Skip "." and ".." entries
                    if (name == "." || name == "..") {
                        offset += 32
                        continue
                    }
                    
                    val isDirectory = (attr and ATTR_DIRECTORY) != 0
                    val size = ByteBuffer.wrap(clusterData, offset + 28, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    
                    // Parse first cluster number (high word at offset 20, low word at offset 26)
                    val clusterLo = ByteBuffer.wrap(clusterData, offset + 26, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                    val clusterHi = ByteBuffer.wrap(clusterData, offset + 20, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                    val entryFirstCluster = (clusterHi shl 16) or clusterLo
                    
                    // Parse date/time (simplified)
                    val modDate = ByteBuffer.wrap(clusterData, offset + 24, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                    val modTime = ByteBuffer.wrap(clusterData, offset + 22, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                    val lastModified = parseFATDateTime(modDate, modTime)
                    
                    val mimeType = if (isDirectory) {
                        "vnd.android.document/directory"
                    } else {
                        guessMimeType(name)
                    }
                    
                    // Build the full path
                    val fullPath = if (parentPath == "/") "/$name" else "$parentPath/$name"
                    
                    entries.add(FileEntry(
                        name = name,
                        path = fullPath,
                        isDirectory = isDirectory,
                        size = size,
                        lastModified = lastModified,
                        mimeType = mimeType,
                        firstCluster = entryFirstCluster
                    ))
                    
                    offset += 32
                }
                
                // Get next cluster in the chain from FAT - bypass cache to get fresh data
                val prevCluster = currentCluster
                currentCluster = readFATEntry(currentCluster, bypassCache = true).getOrElse { 
                    if (DEBUG_LOGGING) Log.w(TAG, "readDirectoryCluster: Failed to read FAT entry for cluster $currentCluster")
                    break 
                }
                if (DEBUG_LOGGING) Log.d(TAG, "readDirectoryCluster: Cluster $prevCluster -> next cluster $currentCluster (EOF check: ${currentCluster >= 0x0FFFFFF8})")
            }
            
            if (DEBUG_LOGGING) Log.d(TAG, "readDirectoryCluster: Read $clusterCount clusters, found ${entries.size} entries for $parentPath")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error reading directory cluster $startCluster", e)
        }
        
        return entries
    }
    
    private fun parseShortFileName(data: ByteArray, offset: Int): String {
        val nameBytes = data.copyOfRange(offset, offset + 8)
        val extBytes = data.copyOfRange(offset + 8, offset + 11)
        
        val name = String(nameBytes, Charset.forName("ASCII")).trim()
        val ext = String(extBytes, Charset.forName("ASCII")).trim()
        
        return if (ext.isNotEmpty()) "$name.$ext" else name
    }
    
    private fun parseLongFileName(data: ByteArray, offset: Int): String {
        val chars = mutableListOf<Char>()
        
        // LFN entries have characters at specific offsets (Unicode LE)
        val offsets = listOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
        
        for (o in offsets) {
            if (offset + o + 1 < data.size) {
                val c1 = data[offset + o].toInt() and 0xFF
                val c2 = data[offset + o + 1].toInt() and 0xFF
                val char = ((c2 shl 8) or c1).toChar()
                if (char == '\u0000' || char == '\uFFFF') break
                chars.add(char)
            }
        }
        
        return chars.joinToString("")
    }
    
    private fun parseFATDateTime(date: Int, time: Int): Long {
        // FAT date: bits 15-9: year (1980+), 8-5: month, 4-0: day
        // FAT time: bits 15-11: hour, 10-5: minute, 4-0: second/2
        val year = 1980 + ((date shr 9) and 0x7F)
        val month = (date shr 5) and 0x0F
        val day = date and 0x1F
        val hour = (time shr 11) and 0x1F
        val minute = (time shr 5) and 0x3F
        val second = (time and 0x1F) * 2
        
        // Convert to Unix timestamp (simplified, ignores timezone)
        return java.util.Calendar.getInstance().apply {
            set(year, month - 1, day, hour, minute, second)
        }.timeInMillis
    }
    
    private fun guessMimeType(fileName: String): String {
        val ext = fileName.substringAfterLast('.', "").lowercase()
        return when (ext) {
            "txt", "log" -> "text/plain"
            "pdf" -> "application/pdf"
            "jpg", "jpeg" -> "image/jpeg"
            "png" -> "image/png"
            "gif" -> "image/gif"
            "mp4" -> "video/mp4"
            "mp3" -> "audio/mpeg"
            "zip" -> "application/zip"
            "doc", "docx" -> "application/msword"
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
                Log.e(TAG, "readFile: File '$path' has size=${fileInfo.size} but no clusters allocated!")
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
                val batchSectorStart = firstDataSector + ((firstClusterInBatch - 2) * bs.sectorsPerCluster)
                val sectorsToRead = runLength * bs.sectorsPerCluster
                
                val batchData = volumeReader.readSectors(batchSectorStart.toLong(), sectorsToRead).getOrThrow()
                
                // Copy only actual file data (not padding)
                val bytesToCopy = minOf(batchData.size, actualFileSize.toInt() - bytesRead)
                System.arraycopy(batchData, 0, fileData, bytesRead, bytesToCopy)
                bytesRead += bytesToCopy
                
                chainIndex += runLength
            }
            
            if (DEBUG_LOGGING) Log.d(TAG, "readFile: Returning ${fileData.size} bytes")
            
            Result.success(fileData)
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read file: $path", e)
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
            val offsetInSector = entryOffset % SECTOR_SIZE
            
            val fatSector: ByteArray
            if (bypassCache) {
                // Read fresh from disk, then update cache
                fatSector = volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
                fatSectorCache[fatSectorOffset] = fatSector
            } else {
                // Check FAT sector cache first - ConcurrentHashMap handles thread safety
                fatSector = fatSectorCache[fatSectorOffset] ?: run {
                    // Evict some entries if cache is full (approximate, doesn't need to be exact)
                    if (fatSectorCache.size >= maxFatCacheSize) {
                        val keysToRemove = fatSectorCache.keys.take(maxFatCacheSize / 4)
                        keysToRemove.forEach { fatSectorCache.remove(it) }
                    }
                    
                    // Pre-fetch multiple FAT sectors at once (32 sectors = 16KB, covers 4096 clusters)
                    val prefetchCount = 32
                    val prefetchData = volumeReader.readSectors(
                        (fatStartSector + fatSectorOffset).toLong(), 
                        prefetchCount
                    ).getOrNull()
                    
                    if (prefetchData != null) {
                        // Cache all prefetched sectors
                        for (i in 0 until prefetchCount) {
                            val sectorData = prefetchData.copyOfRange(i * SECTOR_SIZE, (i + 1) * SECTOR_SIZE)
                            fatSectorCache.putIfAbsent(fatSectorOffset + i, sectorData)
                        }
                        fatSectorCache[fatSectorOffset]!!
                    } else {
                        // Fallback to single sector read
                        val newSector = volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
                        fatSectorCache.putIfAbsent(fatSectorOffset, newSector) ?: newSector
                    }
                }
            }
            
            // Read FAT entry (4 bytes for FAT32)
            val entry = ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).int and 0x0FFFFFFF
            
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
            
            val bs = bootSector ?: return Result.failure(Exception("File system not initialized"))
            val clusterSize = bs.sectorsPerCluster * SECTOR_SIZE
            val firstDataSector = bs.reservedSectors + (bs.numberOfFATs * bs.sectorsPerFAT)
            
            // Clamp to file size
            val actualLength = minOf(length.toLong(), fileInfo.size - offset).toInt()
            if (actualLength <= 0 || offset >= fileInfo.size) {
                return Result.success(ByteArray(0))
            }
            
            // Calculate which clusters we need
            val startClusterIndex = (offset / clusterSize).toInt()
            val endClusterIndex = ((offset + actualLength - 1) / clusterSize).toInt()
            val clustersNeeded = endClusterIndex - startClusterIndex + 1
            
            // Build cluster chain (or use cached one if we already have it)
            val clusterChain = getClusterChain(fileInfo.firstCluster, endClusterIndex + 1)
            
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
                val clusterStartOffset = i.toLong() * clusterSize
                
                // Calculate offset within this cluster
                val offsetInCluster = if (i == startClusterIndex) {
                    (offset - clusterStartOffset).toInt()
                } else 0
                
                // Calculate how many bytes to read from this cluster
                val bytesInCluster = minOf(clusterSize - offsetInCluster, bytesRemaining)
                
                // Check if we can batch consecutive clusters (only if starting at cluster boundary)
                var consecutiveCount = 1
                if (offsetInCluster == 0) {
                    while (i + consecutiveCount <= endClusterIndex && 
                           i + consecutiveCount < clusterChain.size &&
                           clusterChain[i + consecutiveCount] == cluster + consecutiveCount &&
                           consecutiveCount < 64) { // Max 64 clusters per batch
                        consecutiveCount++
                    }
                }
                
                if (consecutiveCount > 1) {
                    // Read multiple consecutive clusters at once
                    val batchSectorStart = firstDataSector + ((cluster - 2) * bs.sectorsPerCluster)
                    val sectorsToRead = consecutiveCount * bs.sectorsPerCluster
                    val batchData = volumeReader.readSectors(batchSectorStart.toLong(), sectorsToRead).getOrThrow()
                    
                    val bytesToCopy = minOf(batchData.size, bytesRemaining)
                    System.arraycopy(batchData, 0, result, resultOffset, bytesToCopy)
                    resultOffset += bytesToCopy
                    bytesRemaining -= bytesToCopy
                    
                    // Skip past the clusters we just read
                    i += consecutiveCount
                } else {
                    // Read single cluster
                    val sectorStart = firstDataSector + ((cluster - 2) * bs.sectorsPerCluster)
                    val clusterData = volumeReader.readSectors(sectorStart.toLong(), bs.sectorsPerCluster).getOrThrow()
                    
                    System.arraycopy(clusterData, offsetInCluster, result, resultOffset, bytesInCluster)
                    resultOffset += bytesInCluster
                    bytesRemaining -= bytesInCluster
                    
                    i++
                }
            }
            
            Result.success(result)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read file range: $path at offset $offset, length $length", e)
            Result.failure(e)
        }
    }
    
    // Cache for cluster chains to avoid rebuilding for sequential reads
    private val clusterChainCache = java.util.concurrent.ConcurrentHashMap<Int, List<Int>>()
    
    private fun getClusterChain(firstCluster: Int, maxClusters: Int): List<Int> {
        // Check cache
        clusterChainCache[firstCluster]?.let { cached ->
            if (cached.size >= maxClusters) return cached.take(maxClusters)
        }
        
        // Build chain
        val chain = mutableListOf<Int>()
        var cluster = firstCluster
        while (cluster >= 2 && cluster < 0x0FFFFFF8 && chain.size < maxClusters) {
            chain.add(cluster)
            cluster = readFATEntry(cluster).getOrElse { break }
        }
        
        // Cache it
        clusterChainCache[firstCluster] = chain
        
        // Evict old entries if cache gets too large
        if (clusterChainCache.size > 100) {
            val keysToRemove = clusterChainCache.keys.take(50)
            keysToRemove.forEach { clusterChainCache.remove(it) }
        }
        
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
                val batchSectorStart = firstDataSector + ((firstClusterInBatch - 2) * bs.sectorsPerCluster)
                val sectorsToRead = runLength * bs.sectorsPerCluster
                
                val batchData = volumeReader.readSectors(batchSectorStart.toLong(), sectorsToRead).getOrThrow()
                
                // Write only the actual file data (not padding at end)
                val bytesToWrite = minOf(batchData.size.toLong(), actualFileSize - bytesWritten).toInt()
                bufferedOutput.write(batchData, 0, bytesToWrite)
                bytesWritten += bytesToWrite
                
                chainIndex += runLength
            }
            
            bufferedOutput.flush()
            val streamTime = System.currentTimeMillis() - streamStart
            val totalTime = System.currentTimeMillis() - totalStart
            // Log timing breakdown - always log for debugging slow performance
            Log.d(TAG, "STREAM: ${bytesWritten/1024}KB total=${totalTime}ms (fileInfo=${fileInfoTime}ms, fatChain=${fatChainTime}ms, stream=${streamTime}ms, clusters=${clusterChain.size})")
            Result.success(bytesWritten)
            
        } catch (e: java.io.IOException) {
            // EPIPE (Broken pipe) is normal when reader closes stream early (e.g., video seeking)
            val isBrokenPipe = e.message?.contains("EPIPE") == true || e.cause?.message?.contains("EPIPE") == true
            if (isBrokenPipe) {
                if (DEBUG_LOGGING) Log.d(TAG, "Stream closed by reader for: $path (normal for seeking)")
            } else {
                Log.e(TAG, "Failed to stream file: $path", e)
            }
            Result.failure(e)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stream file: $path", e)
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
            Log.e(TAG, "Failed to get file info with cluster: $path", e)
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
    
    override fun writeFile(path: String, data: ByteArray): Result<Unit> {
        return writeLock.withLock {
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
                val firstSectorOfCluster = ((currentDirCluster - 2) * bs.sectorsPerCluster) + firstDataSector
                
                // Read this directory cluster
                val clusterData = ByteArray(bs.sectorsPerCluster * SECTOR_SIZE)
                for (i in 0 until bs.sectorsPerCluster) {
                    val sectorData = volumeReader.readSector(firstSectorOfCluster.toLong() + i).getOrThrow()
                    System.arraycopy(sectorData, 0, clusterData, i * SECTOR_SIZE, SECTOR_SIZE)
                }
                
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
                // File already has clusters - for simplicity, reallocate
                // TODO: Could reuse existing clusters if enough space
                freeClusters(fileFirstCluster)
                allocateClusters(clustersNeeded)
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
            for (i in 0 until bs.sectorsPerCluster) {
                val sectorData = clusterData.copyOfRange(i * SECTOR_SIZE, (i + 1) * SECTOR_SIZE)
                volumeReader.writeSector(firstSectorOfCluster + i, sectorData).getOrThrow()
            }
            
            // Create cluster chain in FAT
            writeClusterChain(clusters)
            
            // Write file data across clusters
            var dataOffset = 0
            for (cluster in clusters) {
                val clusterSector = firstDataSector + ((cluster - 2) * bs.sectorsPerCluster)
                val remaining = data.size - dataOffset
                val toWrite = minOf(remaining, clusterSize)
                
                // Prepare cluster data (pad if needed)
                val clusterBuffer = ByteArray(clusterSize)
                System.arraycopy(data, dataOffset, clusterBuffer, 0, toWrite)
                
                // Write entire cluster in one bulk operation
                volumeReader.writeSectors(clusterSector.toLong(), clusterBuffer).getOrThrow()
                
                dataOffset += toWrite
            }
            
            // Clear any cached info for this file since its size/contents changed
            fileCache.remove(path)
            directoryCache.clear()
            // Invalidate free space cache
            invalidateFreeSpaceCache()
            
            Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to write file: $path", e)
                Result.failure(e)
            }
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
        return writeLock.withLock {
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
                    val firstSectorOfCluster = ((currentDirCluster - 2) * bs.sectorsPerCluster) + firstDataSector
                    
                    // Read this directory cluster in one bulk read
                    val clusterData = volumeReader.readSectors(firstSectorOfCluster.toLong(), bs.sectorsPerCluster).getOrThrow()
                    
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
                            foundFirstSectorOfCluster = firstSectorOfCluster.toLong()
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
                    freeClusters(fileFirstCluster)
                    allocateClusters(clustersNeeded)
                }
                
                if (clusters.isEmpty()) {
                    return@withLock Result.failure(Exception("Failed to allocate clusters"))
                }
                
                // Update directory entry with new cluster and size
                val newFirstCluster = clusters[0]
                java.nio.ByteBuffer.wrap(clusterData, dirEntryOffset + 26, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).putShort((newFirstCluster and 0xFFFF).toShort())
                java.nio.ByteBuffer.wrap(clusterData, dirEntryOffset + 20, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).putShort((newFirstCluster shr 16).toShort())
                java.nio.ByteBuffer.wrap(clusterData, dirEntryOffset + 28, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(fileSize.toInt())
                
                // Write back modified directory
                for (i in 0 until bs.sectorsPerCluster) {
                    val sectorData = clusterData.copyOfRange(i * SECTOR_SIZE, (i + 1) * SECTOR_SIZE)
                    volumeReader.writeSector(firstSectorOfCluster.toLong() + i, sectorData).getOrThrow()
                }
                
                // Create cluster chain in FAT
                writeClusterChain(clusters)
                
                // Stream file data across clusters with larger buffer for performance
                // Process 64 clusters (256KB typical) at a time for better throughput
                val clustersPerBatch = 64
                val batchSize = clusterSize * clustersPerBatch
                val batchBuffer = ByteArray(batchSize)
                
                var bytesWritten = 0L
                var clusterIndex = 0
                
                while (clusterIndex < clusters.size) {
                    val batchClusters = minOf(clustersPerBatch, clusters.size - clusterIndex)
                    val batchBytes = batchClusters * clusterSize
                    val remaining = fileSize - bytesWritten
                    val toRead = minOf(remaining.toInt(), batchBytes)
                    
                    // Read data from input stream into batch buffer
                    var totalRead = 0
                    while (totalRead < toRead) {
                        val read = inputStream.read(batchBuffer, totalRead, toRead - totalRead)
                        if (read == -1) break
                        totalRead += read
                    }
                    
                    // Pad with zeros if needed
                    if (totalRead < batchBytes) {
                        java.util.Arrays.fill(batchBuffer, totalRead, batchBytes, 0.toByte())
                    }
                    
                    // Check if clusters are contiguous for bulk write
                    var contiguousCount = 1
                    for (i in 1 until batchClusters) {
                        if (clusters[clusterIndex + i] == clusters[clusterIndex + i - 1] + 1) {
                            contiguousCount++
                        } else {
                            break
                        }
                    }
                    
                    if (contiguousCount == batchClusters && batchClusters > 1) {
                        // All clusters are contiguous - write in one bulk operation
                        val firstClusterSector = firstDataSector + ((clusters[clusterIndex] - 2) * bs.sectorsPerCluster)
                        val dataToWrite = if (totalRead < batchBytes) {
                            batchBuffer.copyOf(batchClusters * clusterSize)
                        } else {
                            batchBuffer.copyOf(batchBytes)
                        }
                        volumeReader.writeSectors(firstClusterSector.toLong(), dataToWrite).getOrThrow()
                    } else {
                        // Write clusters individually (non-contiguous)
                        for (i in 0 until batchClusters) {
                            val cluster = clusters[clusterIndex + i]
                            val clusterSector = firstDataSector + ((cluster - 2) * bs.sectorsPerCluster)
                            val clusterData = batchBuffer.copyOfRange(i * clusterSize, (i + 1) * clusterSize)
                            volumeReader.writeSectors(clusterSector.toLong(), clusterData).getOrThrow()
                        }
                    }
                    
                    bytesWritten += totalRead
                    clusterIndex += batchClusters
                    onProgress?.invoke(bytesWritten)
                }
                
                // Clear caches
                fileCache.remove(path)
                directoryCache.clear()
                // Invalidate free space cache
                invalidateFreeSpaceCache()
                
                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to write file streaming: $path", e)
                Result.failure(e)
            }
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
            var currentFatSector = -1
            var fatSectorData: ByteArray? = null
            
            // Start from cluster 2 (0,1 are reserved)
            for (clusterIndex in 2..totalClusters) {
                val entryOffset = clusterIndex * 4
                val fatSectorOffset = entryOffset / SECTOR_SIZE
                val offsetInSector = entryOffset % SECTOR_SIZE
                
                // Use FAT cache first, then read if needed
                if (fatSectorOffset != currentFatSector) {
                    currentFatSector = fatSectorOffset
                    fatSectorData = fatSectorCache[fatSectorOffset]
                    if (fatSectorData == null) {
                        fatSectorData = volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrNull()
                            ?: break
                        // Cache the sector
                        if (fatSectorCache.size < maxFatCacheSize) {
                            fatSectorCache[fatSectorOffset] = fatSectorData
                        }
                    }
                }
                
                val entry = ByteBuffer.wrap(fatSectorData!!, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).int and 0x0FFFFFFF
                if (entry == 0) {
                    freeClusters++
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
            Thread {
                try {
                    val freeClusters = countFreeClusters()
                    cachedFreeSpaceBytes = freeClusters.toLong() * clusterSize
                    Log.d(TAG, "Background free space calculation complete: $cachedFreeSpaceBytes bytes")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to calculate free space in background", e)
                } finally {
                    isFreeSpaceBeingCalculated = false
                }
            }.start()
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
            if (count > totalClusters - 1) { // -1 for root directory at cluster 2
                Log.e(TAG, "Not enough clusters: need $count, have ${totalClusters - 1}")
                return emptyList()
            }
            
            // Start from last allocated cluster hint (avoids rescanning from beginning)
            var clusterIndex = lastAllocatedCluster
            var currentFatSector = -1
            var fatSectorData: ByteArray? = null
            var wrapped = false
            
            while (clusters.size < count) {
                // Wrap around if we reached the end
                if (clusterIndex > totalClusters) {
                    if (wrapped) break // Already wrapped once, no more free clusters
                    clusterIndex = 2
                    wrapped = true
                }
                
                // Stop if we've wrapped back to start point
                if (wrapped && clusterIndex >= lastAllocatedCluster) break
                
                // Calculate which FAT sector contains this cluster entry
                val entryOffset = clusterIndex * 4
                val fatSectorOffset = entryOffset / SECTOR_SIZE
                val offsetInSector = entryOffset % SECTOR_SIZE
                
                // Check FAT cache first, then read if needed
                if (fatSectorOffset != currentFatSector) {
                    currentFatSector = fatSectorOffset
                    fatSectorData = fatSectorCache[fatSectorOffset]
                    if (fatSectorData == null) {
                        fatSectorData = volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrNull()
                        if (fatSectorData == null) {
                            Log.e(TAG, "Failed to read FAT sector at offset $fatSectorOffset")
                            break
                        }
                        // Cache the sector
                        if (fatSectorCache.size >= maxFatCacheSize) {
                            fatSectorCache.keys.take(maxFatCacheSize / 4).forEach { fatSectorCache.remove(it) }
                        }
                        fatSectorCache[fatSectorOffset] = fatSectorData
                    }
                }
                
                // Check if cluster is free (entry is 0x00000000)
                val entry = ByteBuffer.wrap(fatSectorData!!, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).int and 0x0FFFFFFF
                if (entry == 0) {
                    clusters.add(clusterIndex)
                    // Update hint for next allocation
                    lastAllocatedCluster = clusterIndex + 1
                }
                
                clusterIndex++
            }
            
            if (clusters.size < count) {
                Log.e(TAG, "Not enough free clusters: found ${clusters.size}, needed $count")
                return emptyList()
            }
            
            // Decrement cached free cluster count
            if (cachedFreeClusters >= 0) {
                cachedFreeClusters -= clusters.size
            }
            
            return clusters
        } catch (e: Exception) {
            Log.e(TAG, "Failed to allocate clusters", e)
            return emptyList()
        }
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
                
                // Get or read FAT sector
                val fatSector = fatUpdates.getOrPut(fatSectorOffset) {
                    volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
                }
                
                // Write next cluster value
                ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(nextCluster)
            }
            
            // Write all modified FAT sectors to both FAT copies
            for ((sectorOffset, data) in fatUpdates) {
                // Write to first FAT
                volumeReader.writeSector((fatStartSector + sectorOffset).toLong(), data).getOrThrow()
                
                // Write to second FAT
                val secondFATStart = fatStartSector + bs.sectorsPerFAT
                volumeReader.writeSector((secondFATStart + sectorOffset).toLong(), data).getOrThrow()
                
                // Update FAT sector cache with written data
                fatSectorCache[sectorOffset] = data.copyOf()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write cluster chain", e)
        }
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
                
                // Get or read FAT sector
                val fatSector = fatUpdates.getOrPut(fatSectorOffset) {
                    volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
                }
                
                // Read next cluster before we overwrite
                val nextCluster = ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).int
                
                // Mark cluster as free
                ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0)
                
                cluster = nextCluster
            }
            
            // Write all modified FAT sectors to both FAT copies
            for ((sectorOffset, data) in fatUpdates) {
                // Write to first FAT
                volumeReader.writeSector((fatStartSector + sectorOffset).toLong(), data).getOrThrow()
                
                // Write to second FAT
                val secondFATStart = fatStartSector + bs.sectorsPerFAT
                volumeReader.writeSector((secondFATStart + sectorOffset).toLong(), data).getOrThrow()
                
                // Update FAT sector cache
                fatSectorCache[sectorOffset] = data.copyOf()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to free clusters", e)
        }
    }
    
    /**
     * Get the next cluster in the chain from the FAT
     */
    private fun getNextCluster(cluster: Int): Int {
        val bs = bootSector ?: return 0x0FFFFFFF
        val fatStartSector = bs.reservedSectors
        
        try {
            val entryOffset = cluster * 4
            val fatSectorOffset = entryOffset / SECTOR_SIZE
            val offsetInSector = entryOffset % SECTOR_SIZE
            
            val fatSector = volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
            return ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).int
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get next cluster for $cluster", e)
            return 0x0FFFFFFF // Return EOF on error
        }
    }
    
    /**
     * Append a new cluster to an existing cluster chain
     */
    private fun appendClusterToChain(lastCluster: Int, newCluster: Int) {
        val bs = bootSector ?: return
        val fatStartSector = bs.reservedSectors
        
        try {
            // Update the last cluster to point to the new cluster
            val entryOffset = lastCluster * 4
            val fatSectorOffset = entryOffset / SECTOR_SIZE
            val offsetInSector = entryOffset % SECTOR_SIZE
            
            val fatSector = volumeReader.readSector((fatStartSector + fatSectorOffset).toLong()).getOrThrow()
            ByteBuffer.wrap(fatSector, offsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(newCluster)
            
            // Write to first FAT
            volumeReader.writeSector((fatStartSector + fatSectorOffset).toLong(), fatSector).getOrThrow()
            
            // Update FAT sector cache with the modified data
            fatSectorCache[fatSectorOffset] = fatSector.copyOf()
            
            // Write to second FAT
            val secondFATStart = fatStartSector + bs.sectorsPerFAT
            volumeReader.writeSector((secondFATStart + fatSectorOffset).toLong(), fatSector).getOrThrow()
            
            // Mark new cluster as EOF
            val newEntryOffset = newCluster * 4
            val newFatSectorOffset = newEntryOffset / SECTOR_SIZE
            val newOffsetInSector = newEntryOffset % SECTOR_SIZE
            
            val newFatSector = volumeReader.readSector((fatStartSector + newFatSectorOffset).toLong()).getOrThrow()
            ByteBuffer.wrap(newFatSector, newOffsetInSector, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0x0FFFFFFF)
            
            // Write to first FAT
            volumeReader.writeSector((fatStartSector + newFatSectorOffset).toLong(), newFatSector).getOrThrow()
            
            // Update FAT sector cache with the modified data for new cluster
            fatSectorCache[newFatSectorOffset] = newFatSector.copyOf()
            
            // Write to second FAT
            volumeReader.writeSector((secondFATStart + newFatSectorOffset).toLong(), newFatSector).getOrThrow()
            
            Log.d(TAG, "appendClusterToChain: chained $lastCluster -> $newCluster")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to append cluster to chain", e)
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
                    Log.d(TAG, "createFile: File already exists: $fullPath")
                    return@withLock Result.failure(Exception("File already exists"))
                }
                
                Log.d(TAG, "createFile: Creating $name in $parentPath")
                
                // Create directory entry
                val newEntry = createDirectoryEntry(parentPath, name, isDirectory = false)
                
                Log.d(TAG, "createFile: Successfully created entry for $fullPath")
                
                // Clear parent directory cache so it gets re-read
                directoryCache.remove(normalizePath(parentPath))
                // Cache the new entry immediately
                fileCache[normalizePath(newEntry.path)] = newEntry
                // Invalidate free space cache
                invalidateFreeSpaceCache()
                
                Result.success(newEntry)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create file: $name in $parentPath", e)
                Result.failure(e)
            }
        }
    }
    
    override fun createDirectory(parentPath: String, name: String): Result<FileEntry> {
        return writeLock.withLock {
            try {
                Log.d(TAG, "createDirectory: name=$name, parentPath=$parentPath")
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
                Log.d(TAG, "createDirectory: created entry at ${newEntry.path}, firstCluster=${newEntry.firstCluster}")
                
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
                Log.e(TAG, "Failed to create directory: $name in $parentPath", e)
                Result.failure(e)
            }
        }
    }
    
    override fun delete(path: String): Result<Unit> {
        return writeLock.withLock {
            try {
                Log.d(TAG, "delete: Starting deletion of $path")
                
                if (path == "/") {
                    return@withLock Result.failure(Exception("Cannot delete root directory"))
                }
                
                // Clear caches first
                directoryCache.remove(path)
                fileCache.remove(path)
                
                val fileInfo = getFileInfo(path).getOrThrow()
                Log.d(TAG, "delete: Found entry, isDirectory=${fileInfo.isDirectory}")
                
                // For directories, recursively delete contents first
                if (fileInfo.isDirectory) {
                    val entries = listDirectory(path).getOrThrow()
                    Log.d(TAG, "delete: Directory has ${entries.size} entries to delete")
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
                Log.d(TAG, "delete: Now deleting the entry itself at $path")
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
                
                Log.d(TAG, "delete: Successfully deleted $path")
                Result.success(Unit)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to delete: $path", e)
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
            Log.d(TAG, "deleteRecursive: Deleting entry at $path")
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
            
            Log.d(TAG, "deleteRecursive: Successfully deleted $path")
            return Result.success(Unit)
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete recursively: $path", e)
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
            val firstSectorOfCluster = ((currentCluster - 2) * bs.sectorsPerCluster) + firstDataSector
            clusterData = volumeReader.readSectors(firstSectorOfCluster.toLong(), bs.sectorsPerCluster).getOrThrow()
            
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
            val newClusterFirstSector = ((newCluster - 2) * bs.sectorsPerCluster) + firstDataSector
            volumeReader.writeSectors(newClusterFirstSector.toLong(), clusterData).getOrThrow()
            
            targetCluster = newCluster
            freeOffset = 0 // First entry in the new cluster
        }
        
        // Now we have freeOffset and targetCluster set
        // Re-read the target cluster if needed
        if (targetCluster != lastCluster || freeOffset == 0) {
            val firstSectorOfCluster = ((targetCluster - 2) * bs.sectorsPerCluster) + firstDataSector
            clusterData = volumeReader.readSectors(firstSectorOfCluster.toLong(), bs.sectorsPerCluster).getOrThrow()
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
        val targetSectorOfCluster = ((targetCluster - 2) * bs.sectorsPerCluster) + firstDataSector
        volumeReader.writeSectors(targetSectorOfCluster.toLong(), clusterData).getOrThrow()
        
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
        val firstSectorOfCluster = ((cluster - 2) * bs.sectorsPerCluster) + firstDataSector
        
        Log.d(TAG, "initializeDirectoryCluster: writing to sector $firstSectorOfCluster")
        
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
        
        // Write cluster data
        for (i in 0 until bs.sectorsPerCluster) {
            val sectorData = clusterData.copyOfRange(i * SECTOR_SIZE, (i + 1) * SECTOR_SIZE)
            volumeReader.writeSector(firstSectorOfCluster.toLong() + i, sectorData).getOrThrow()
        }
        
        // Verify write by reading back
        val verifyData = volumeReader.readSector(firstSectorOfCluster.toLong()).getOrThrow()
        val verifyByte0 = verifyData[0].toInt() and 0xFF
        val verifyByte32 = verifyData[32].toInt() and 0xFF
        Log.d(TAG, "initializeDirectoryCluster: VERIFY - byte[0]=0x${verifyByte0.toString(16)}, byte[32]=0x${verifyByte32.toString(16)}")
        if (verifyByte0 != 0x2E || verifyByte32 != 0x2E) {
            Log.e(TAG, "initializeDirectoryCluster: VERIFICATION FAILED! Expected 0x2E but got 0x${verifyByte0.toString(16)} and 0x${verifyByte32.toString(16)}")
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
            val firstSectorOfCluster = ((currentCluster - 2) * bs.sectorsPerCluster) + firstDataSector
            
            // Read cluster data
            val clusterData = ByteArray(clusterSize)
            for (i in 0 until bs.sectorsPerCluster) {
                val sectorData = volumeReader.readSector(firstSectorOfCluster.toLong() + i).getOrThrow()
                System.arraycopy(sectorData, 0, clusterData, i * SECTOR_SIZE, SECTOR_SIZE)
            }
            
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
                    
                    // Write back modified cluster
                    for (i in 0 until bs.sectorsPerCluster) {
                        val sectorData = clusterData.copyOfRange(i * SECTOR_SIZE, (i + 1) * SECTOR_SIZE)
                        volumeReader.writeSector(firstSectorOfCluster.toLong() + i, sectorData).getOrThrow()
                    }
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
