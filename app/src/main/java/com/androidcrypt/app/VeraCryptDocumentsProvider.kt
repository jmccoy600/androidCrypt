package com.androidcrypt.app

import android.content.res.AssetFileDescriptor
import android.database.Cursor
import android.database.MatrixCursor
import android.graphics.Point
import android.os.CancellationSignal
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Path
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import android.util.Log
import android.webkit.MimeTypeMap
import com.androidcrypt.crypto.VolumeMountManager
import com.androidcrypt.crypto.FAT32Reader
import com.androidcrypt.crypto.FileEntry
import java.io.FileNotFoundException

/**
 * DocumentsProvider that exposes mounted VeraCrypt volumes to other apps
 * through Android's Storage Access Framework (SAF)
 */
class VeraCryptDocumentsProvider : DocumentsProvider() {
    
    companion object {
        private const val TAG = "VeraCryptProvider"
        private const val AUTHORITY = "com.androidcrypt.documents"
        private const val ROOT_ID_PREFIX = "veracrypt_"
        // Set to false to disable debug logging for better performance
        private const val DEBUG_LOGGING = false

        // Dedicated executor for background read-ahead — runs concurrently with onRead
        // so it never blocks the calling thread waiting for the next chunk.
        private val readAheadExecutor: java.util.concurrent.ExecutorService =
            java.util.concurrent.Executors.newFixedThreadPool(4)

        // Dedicated executor for background writes (openDocumentForWrite).
        // Kept separate from readAheadExecutor so that a long-running write
        // cannot starve read-ahead tasks (and vice-versa).
        private val writeExecutor: java.util.concurrent.ExecutorService =
            java.util.concurrent.Executors.newFixedThreadPool(2)

        // Shared pool of HandlerThreads for ProxyFileDescriptor callbacks.
        // openProxyFileDescriptor requires a Handler(Looper), so we need real Looper
        // threads. Instead of spawning one per file (50+ for thumbnails), we share a
        // small pool and round-robin across them.  Multiple callbacks can safely share
        // a single Looper — Android dispatches onRead/onRelease sequentially per Looper.
        private const val PROXY_HANDLER_POOL_SIZE = 4
        private val proxyHandlerThreads: Array<HandlerThread> = Array(PROXY_HANDLER_POOL_SIZE) { i ->
            HandlerThread("ProxyPool-$i").apply { start() }
        }
        private val proxyHandlerPool: Array<Handler> = Array(PROXY_HANDLER_POOL_SIZE) { i ->
            Handler(proxyHandlerThreads[i].looper)
        }
        private val proxyHandlerCounter = java.util.concurrent.atomic.AtomicInteger(0)
        
        /** Round-robin a shared proxy Handler instead of spawning a new thread. */
        private fun nextProxyHandler(): Handler {
            val idx = proxyHandlerCounter.getAndIncrement() % PROXY_HANDLER_POOL_SIZE
            return proxyHandlerPool[idx]
        }
        
        private val DEFAULT_ROOT_PROJECTION = arrayOf(
            Root.COLUMN_ROOT_ID,
            Root.COLUMN_FLAGS,
            Root.COLUMN_ICON,
            Root.COLUMN_TITLE,
            Root.COLUMN_DOCUMENT_ID,
            Root.COLUMN_AVAILABLE_BYTES
        )
        
        private val DEFAULT_DOCUMENT_PROJECTION = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_LAST_MODIFIED,
            Document.COLUMN_FLAGS,
            Document.COLUMN_SIZE
        )
        
        // SEPARATE CACHES for videos vs thumbnails to prevent eviction
        // Videos need persistence for looping; thumbnails are short-lived
        
        // Thumbnail cache: small files ending in -t.valv (typically ~30KB)
        private const val THUMBNAIL_CACHE_MAX_SIZE = 512 * 1024 // 512KB max per thumbnail
        private const val THUMBNAIL_CACHE_MAX_ENTRIES = 100 // Many thumbnails
        private const val THUMBNAIL_CACHE_TTL_MS = 30_000L // 30 second TTL
        private val thumbnailCache = object : LinkedHashMap<String, Pair<Long, ByteArray>>(
            THUMBNAIL_CACHE_MAX_ENTRIES, 0.75f, true
        ) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Pair<Long, ByteArray>>?): Boolean {
                return size > THUMBNAIL_CACHE_MAX_ENTRIES
            }
        }
        private val thumbnailCacheLock = Any()
        
        // Video cache: media files ending in -v.valv (typically 500KB-10MB)
        private const val VIDEO_CACHE_MAX_SIZE = 10 * 1024 * 1024 // 10MB max per video
        private const val VIDEO_CACHE_MAX_ENTRIES = 10 // Fewer but larger videos
        private const val VIDEO_CACHE_TTL_MS = 120_000L // 2 minute TTL for looping videos
        private val videoCache = object : LinkedHashMap<String, Pair<Long, ByteArray>>(
            VIDEO_CACHE_MAX_ENTRIES, 0.75f, true
        ) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Pair<Long, ByteArray>>?): Boolean {
                return size > VIDEO_CACHE_MAX_ENTRIES
            }
        }
        private val videoCacheLock = Any()
        
        private fun isVideoFile(key: String): Boolean {
            // Match Valv encrypted videos, paths containing /video, OR actual video extensions
            // Use ignoreCase to avoid allocating a lowercase copy
            return key.endsWith("-v.valv", ignoreCase = true) || 
                   key.contains("/video", ignoreCase = true) ||
                   key.endsWith(".mp4", ignoreCase = true) ||
                   key.endsWith(".mkv", ignoreCase = true) ||
                   key.endsWith(".avi", ignoreCase = true) ||
                   key.endsWith(".mov", ignoreCase = true) ||
                   key.endsWith(".webm", ignoreCase = true) ||
                   key.endsWith(".m4v", ignoreCase = true) ||
                   key.endsWith(".3gp", ignoreCase = true) ||
                   key.endsWith(".wmv", ignoreCase = true) ||
                   key.endsWith(".flv", ignoreCase = true)
        }
        
        private fun isThumbnailFile(key: String): Boolean {
            return key.endsWith("-t.valv", ignoreCase = true)
        }
        
        fun getCachedFile(key: String): ByteArray? {
            // Check video cache first for video files
            if (isVideoFile(key)) {
                synchronized(videoCacheLock) {
                    val entry = videoCache[key] ?: return null
                    if (System.currentTimeMillis() - entry.first > VIDEO_CACHE_TTL_MS) {
                        videoCache.remove(key)
                        return null
                    }
                    if (DEBUG_LOGGING) Log.d("VeraCryptProvider", "VIDEO CACHE HIT: $key (${entry.second.size / 1024}KB)")
                    return entry.second
                }
            }
            // Check thumbnail cache for thumbnails
            synchronized(thumbnailCacheLock) {
                val entry = thumbnailCache[key] ?: return null
                if (System.currentTimeMillis() - entry.first > THUMBNAIL_CACHE_TTL_MS) {
                    thumbnailCache.remove(key)
                    return null
                }
                return entry.second
            }
        }
        
        fun putCachedFile(key: String, data: ByteArray) {
            if (isVideoFile(key)) {
                if (data.size > VIDEO_CACHE_MAX_SIZE) return
                synchronized(videoCacheLock) {
                    videoCache[key] = Pair(System.currentTimeMillis(), data)
                    if (DEBUG_LOGGING) Log.d("VeraCryptProvider", "VIDEO CACHED: $key (${data.size / 1024}KB) - ${videoCache.size} videos in cache")
                }
            } else if (isThumbnailFile(key)) {
                if (data.size > THUMBNAIL_CACHE_MAX_SIZE) return
                synchronized(thumbnailCacheLock) {
                    thumbnailCache[key] = Pair(System.currentTimeMillis(), data)
                }
            }
            // Other files (non-thumbnail, non-video) are not cached to save memory
        }
    }
    
    // FAT32Reader caching is now handled centrally by VolumeMountManager
    // so that DocumentsProvider and CopyService share the same instance.
    
    override fun onCreate(): Boolean {
        Log.d(TAG, "VeraCryptDocumentsProvider created")
        return true
    }
    
    /**
     * Check if a document is a descendant of another
     */
    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
        try {
            // Parse both document IDs
            val (parentRootId, parentPath) = parseDocumentId(parentDocumentId)
            val (docRootId, docPath) = parseDocumentId(documentId)
            
            // Must be in the same root
            if (parentRootId != docRootId) {
                return false
            }
            
            // Check if docPath starts with parentPath
            return when {
                parentPath == "/" -> docPath.startsWith("/") && docPath != "/"
                docPath == parentPath -> false
                docPath.startsWith("$parentPath/") -> true
                else -> false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error checking child document", e)
            return false
        }
    }
    
    /**
     * Find the path from a root to a document
     * This is required for proper navigation in file managers
     */
    override fun findDocumentPath(parentDocumentId: String?, childDocumentId: String): Path {
        if (DEBUG_LOGGING) Log.d(TAG, "findDocumentPath: parent=$parentDocumentId, child=$childDocumentId")
        
        try {
            val (rootId, childPath) = parseDocumentId(childDocumentId)
            
            // Build the path from root to the child document
            val pathComponents = mutableListOf<String>()
            
            // Start with root document
            val rootDocumentId = getDocumentId(rootId, "/")
            
            if (parentDocumentId == null) {
                // Path from the root
                pathComponents.add(rootDocumentId)
            }
            
            // Add each path component
            if (childPath != "/") {
                val parts = childPath.split("/").filter { it.isNotEmpty() }
                var currentPath = ""
                for (part in parts) {
                    currentPath = "$currentPath/$part"
                    pathComponents.add(getDocumentId(rootId, currentPath))
                }
            } else if (parentDocumentId == null) {
                // Just the root, already added
            }
            
            return Path(rootId, pathComponents)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error finding document path", e)
            throw FileNotFoundException("Cannot find document path")
        }
    }
    
    /**
     * Return all mounted VeraCrypt volumes as roots
     */
    override fun queryRoots(projection: Array<out String>?): Cursor {
        Log.d(TAG, "queryRoots called")
        
        val result = MatrixCursor(projection ?: DEFAULT_ROOT_PROJECTION)
        
        try {
            // Get all mounted volumes
            val mountedVolumes = VolumeMountManager.getMountedVolumes()
            
            for (volumePath in mountedVolumes) {
                try {
                    val reader = VolumeMountManager.getVolumeReader(volumePath)
                    val volumeInfo = reader?.volumeInfo
                    
                    if (volumeInfo != null) {
                        // Get or create file system reader (already initialized)
                        val fsReader = getOrCreateFileSystemReader(volumePath)
                        val fsInfo = fsReader?.getFileSystemInfo()
                        
                        val rootId = getRootId(volumePath)
                        val documentId = getDocumentId(rootId, "/")
                        
                        // Calculate available space from FAT32 free clusters
                        val availableBytes = fsReader?.getFreeSpaceBytes() ?: volumeInfo.dataAreaSize
                        
                        val row = result.newRow()
                        row.add(Root.COLUMN_ROOT_ID, rootId)
                        row.add(Root.COLUMN_FLAGS, 
                            Root.FLAG_SUPPORTS_CREATE or 
                            Root.FLAG_SUPPORTS_IS_CHILD or 
                            Root.FLAG_LOCAL_ONLY or
                            Root.FLAG_SUPPORTS_RECENTS or
                            Root.FLAG_SUPPORTS_SEARCH
                        )
                        row.add(Root.COLUMN_ICON, android.R.drawable.ic_menu_save)
                        row.add(Root.COLUMN_TITLE, fsInfo?.label ?: "VeraCrypt Volume")
                        row.add(Root.COLUMN_SUMMARY, "Encrypted volume")
                        row.add(Root.COLUMN_DOCUMENT_ID, documentId)
                        row.add(Root.COLUMN_AVAILABLE_BYTES, availableBytes)
                        row.add(Root.COLUMN_CAPACITY_BYTES, volumeInfo.dataAreaSize)
                        
                        if (DEBUG_LOGGING) Log.d(TAG, "Added root: $rootId, available: $availableBytes bytes")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error processing volume", e)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in queryRoots", e)
        }
        
        return result
    }
    
    /**
     * Return metadata for a document (file or directory)
     */
    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        if (DEBUG_LOGGING) Log.d(TAG, "queryDocument: $documentId")
        
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        
        try {
            val (rootId, path) = parseDocumentId(documentId)
            val volumePath = getVolumePathFromRootId(rootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            val fileEntry = if (path == "/") {
                fsReader.getRootDirectory()
            } else {
                fsReader.getFileInfo(path).getOrThrow()
            }
            
            includeFile(result, documentId, fileEntry)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error querying document", e)
            throw FileNotFoundException("Cannot find document")
        }
        
        return result
    }
    
    /**
     * Get document MIME type - required by some file managers
     */
    override fun getDocumentType(documentId: String): String {
        if (DEBUG_LOGGING) Log.d(TAG, "getDocumentType: $documentId")
        
        try {
            val (rootId, path) = parseDocumentId(documentId)
            val volumePath = getVolumePathFromRootId(rootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            val fileEntry = if (path == "/") {
                fsReader.getRootDirectory()
            } else {
                fsReader.getFileInfo(path).getOrThrow()
            }
            
            return if (fileEntry.isDirectory) {
                DocumentsContract.Document.MIME_TYPE_DIR
            } else {
                fileEntry.mimeType ?: getMimeType(fileEntry)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting document type", e)
            return "application/octet-stream"
        }
    }
    
    /**
     * Return children of a directory
     */
    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        if (DEBUG_LOGGING) Log.d(TAG, "queryChildDocuments: $parentDocumentId")
        
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val queryStart = System.currentTimeMillis()
        
        try {
            val (rootId, path) = parseDocumentId(parentDocumentId)
            val volumePath = getVolumePathFromRootId(rootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            val entries = fsReader.listDirectory(path).getOrThrow()
                .sortedWith(compareBy<FileEntry> { !it.isDirectory }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.name })
            
            var includedCount = 0
            var skippedCount = 0
            for (entry in entries) {
                // Skip empty .valv files - these are incomplete/corrupted files that will
                // crash Valv when it tries to parse the encryption header from 0 bytes
                if (!entry.isDirectory && entry.name.endsWith(".valv", ignoreCase = true) && entry.size == 0L) {
                    skippedCount++
                    continue
                }
                
                val childDocId = getDocumentId(rootId, entry.path)
                includeFile(result, childDocId, entry)
                includedCount++
            }
            
            val elapsed = System.currentTimeMillis() - queryStart
            if (DEBUG_LOGGING) Log.d(TAG, "queryChildDocuments: $includedCount items in ${elapsed}ms")
            
            // Set notification URI so file manager can watch for changes
            val notifyUri = DocumentsContract.buildChildDocumentsUri(AUTHORITY, parentDocumentId)
            result.setNotificationUri(context?.contentResolver, notifyUri)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error querying child documents", e)
            // Return empty cursor on error
        }
        
        return result
    }
    
    /**
     * Open a document for reading or writing
     */
    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor {
        if (DEBUG_LOGGING) Log.d(TAG, "openDocument: documentId=$documentId, mode=$mode")
        
        try {
            val (rootId, path) = parseDocumentId(documentId)
            if (DEBUG_LOGGING) Log.d(TAG, "openDocument: parsed rootId=$rootId, path=$path")
            val volumePath = getVolumePathFromRootId(rootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            val fileEntry = fsReader.getFileInfoWithClusterPublic(path).getOrThrow()
            if (DEBUG_LOGGING) Log.d(TAG, "openDocument: got fileEntry name=${fileEntry.name}, isDir=${fileEntry.isDirectory}, size=${fileEntry.size}")
            
            if (fileEntry.isDirectory) {
                throw FileNotFoundException("Cannot open directory as file")
            }
            
            // Handle write mode
            if (mode.contains("w") || mode.contains("wt") || mode.contains("wa")) {
                return openDocumentForWrite(documentId, fsReader, path)
            }
            
            // Use ProxyFileDescriptor for on-demand reads - no buffering, instant response
            val storageManager = context?.getSystemService(StorageManager::class.java)
                ?: throw FileNotFoundException("StorageManager not available")

            // Share a small pool of Looper threads instead of spawning one per file.
            // Multiple ProxyFileDescriptorCallbacks safely share a single Handler.
            val handler = nextProxyHandler()
            val callback = EncryptedFileProxyCallback(fsReader, volumePath, path, fileEntry.size, fileEntry.firstCluster)
            return storageManager.openProxyFileDescriptor(
                ParcelFileDescriptor.MODE_READ_ONLY,
                callback,
                handler
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error opening document", e)
            throw FileNotFoundException("Cannot open document")
        }
    }
    
    /**
     * ProxyFileDescriptorCallback that reads encrypted data on demand
     * Optimized for video streaming with large read-ahead buffers
     * Uses global cache for small files (< 5MB) so looping videos don't re-read
     */
    private inner class EncryptedFileProxyCallback(
        private val fsReader: FAT32Reader,
        private val volumePath: String,
        private val path: String,
        private val fileSize: Long,
        private val firstCluster: Int  // Pre-resolved — avoids metadata lookup on every read
    ) : ProxyFileDescriptorCallback() {
        
        // Global cache key for this file
        private val globalCacheKey = "$volumePath:$path"
        
        // Video files (< 10MB) or thumbnails (< 512KB) get cached globally
        private val useGlobalCache = (isVideoFile(globalCacheKey) && fileSize <= VIDEO_CACHE_MAX_SIZE) ||
                                     (isThumbnailFile(globalCacheKey) && fileSize <= THUMBNAIL_CACHE_MAX_SIZE)
        
        // Local reference to cached data - avoids repeated global cache lookups
        // This is the KEY optimization for video loops - keeps data immediately available
        @Volatile private var localCachedData: ByteArray? = null
        
        init {
            // Pre-fetch from global cache immediately on construction
            // This eliminates any delay on the first onRead call
            if (useGlobalCache) {
                localCachedData = getCachedFile(globalCacheKey)
                if (localCachedData != null) {
                    if (DEBUG_LOGGING) Log.d(TAG, "PROXY CALLBACK: path=$path size=${fileSize/1024}KB PREFETCHED from cache")
                } else {
                    if (DEBUG_LOGGING) Log.d(TAG, "PROXY CALLBACK: path=$path size=${fileSize/1024}KB isVideo=${isVideoFile(globalCacheKey)} useGlobalCache=$useGlobalCache key=$globalCacheKey")
                }
            } else {
                if (DEBUG_LOGGING) Log.d(TAG, "PROXY CALLBACK: path=$path size=${fileSize/1024}KB isVideo=${isVideoFile(globalCacheKey)} useGlobalCache=false")
            }
        }
        
        // Pre-load entire small file into global cache on first access
        @Volatile private var globalCacheLoaded = false
        
        // Use larger buffers for video files to sustain high throughput
        private val isVideo = 
            path.endsWith(".mp4", ignoreCase = true) || path.endsWith(".mkv", ignoreCase = true) ||
            path.endsWith(".avi", ignoreCase = true) || path.endsWith(".mov", ignoreCase = true) ||
            path.endsWith(".webm", ignoreCase = true) || path.endsWith(".m4v", ignoreCase = true) ||
            path.endsWith(".valv", ignoreCase = true) // Valv encrypted video format
        
        // Cache window sizing:
        //   tiny  (<= 512KB): cache the whole file — eliminates every subsequent read
        //   medium (<= 5MB) : 2MB window  — 3 fills max for a 5MB image
        //   large (> 5MB)   : 4MB window  — sustains throughput for big files
        //   video            : 4MB window  — large bursts for smooth playback
        private val cacheSize = when {
            isVideo                              -> 4 * 1024 * 1024
            fileSize <= 512 * 1024              -> fileSize.toInt()
            fileSize <= 5 * 1024 * 1024         -> 2 * 1024 * 1024
            else                                -> 4 * 1024 * 1024
        }
        
        // Double-buffering: current cache and read-ahead cache
        @Volatile private var cachedData: ByteArray? = null
        @Volatile private var cachedOffset: Long = -1
        @Volatile private var readAheadData: ByteArray? = null
        @Volatile private var readAheadOffset: Long = -1
        @Volatile private var readAheadInProgress = false
        private val cacheLock = Any()
        
        override fun onGetSize(): Long = fileSize
        
        override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
            try {
                if (offset >= fileSize) return 0
                
                val bytesToRead = minOf(size, (fileSize - offset).toInt())
                
                // Fast path: use local cached reference (no lock, no lookup)
                localCachedData?.let { cached ->
                    if (offset < cached.size) {
                        val copySize = minOf(bytesToRead, (cached.size - offset).toInt())
                        if (copySize > 0) {
                            System.arraycopy(cached, offset.toInt(), data, 0, copySize)
                            return copySize
                        }
                    }
                }
                
                // Try global cache if local wasn't available
                if (useGlobalCache) {
                    val globalData = getCachedFile(globalCacheKey)
                    if (globalData != null) {
                        // Store locally for faster subsequent reads
                        localCachedData = globalData
                        val copySize = minOf(bytesToRead, (globalData.size - offset).toInt())
                        if (copySize > 0 && offset < globalData.size) {
                            System.arraycopy(globalData, offset.toInt(), data, 0, copySize)
                            return copySize
                        }
                    }
                    
                    // Cache miss - load entire file into global cache
                    if (!globalCacheLoaded) {
                        globalCacheLoaded = true
                        val readStart = System.currentTimeMillis()
                        val fullData = fsReader.readFileRangeByCluster(firstCluster, fileSize, 0, fileSize.toInt()).getOrNull()
                        if (fullData != null) {
                            putCachedFile(globalCacheKey, fullData)
                            localCachedData = fullData  // Also store locally
                            val readTime = System.currentTimeMillis() - readStart
                            if (DEBUG_LOGGING) Log.d(TAG, "PROXY: Cached ${fullData.size/1024}KB in ${readTime}ms for $path")
                            
                            val copySize = minOf(bytesToRead, (fullData.size - offset).toInt())
                            if (copySize > 0 && offset < fullData.size) {
                                System.arraycopy(fullData, offset.toInt(), data, 0, copySize)
                                return copySize
                            }
                        }
                    }
                }
                
                synchronized(cacheLock) {
                    // Check primary cache
                    var cached = cachedData
                    var cachedOff = cachedOffset
                    if (cached != null && cachedOff >= 0 &&
                        offset >= cachedOff && offset + bytesToRead <= cachedOff + cached.size) {
                        val cacheStart = (offset - cachedOff).toInt()
                        System.arraycopy(cached, cacheStart, data, 0, bytesToRead)
                        
                        // If we're near the end of the cache, swap in read-ahead if available
                        val cacheRemaining = (cachedOff + cached.size) - (offset + bytesToRead)
                        if (cacheRemaining < cacheSize / 4) {
                            val ahead = readAheadData
                            val aheadOff = readAheadOffset
                            if (ahead != null && aheadOff == cachedOff + cached.size) {
                                cachedData = ahead
                                cachedOffset = aheadOff
                                readAheadData = null
                                readAheadOffset = -1
                                // Trigger next read-ahead asynchronously
                                triggerReadAhead(aheadOff + ahead.size)
                            }
                        }
                        return bytesToRead
                    }
                    
                    // Check if read-ahead has what we need
                    val ahead = readAheadData
                    val aheadOff = readAheadOffset
                    if (ahead != null && aheadOff >= 0 &&
                        offset >= aheadOff && offset + bytesToRead <= aheadOff + ahead.size) {
                        // Promote read-ahead to primary cache
                        cachedData = ahead
                        cachedOffset = aheadOff
                        readAheadData = null
                        readAheadOffset = -1
                        
                        val cacheStart = (offset - aheadOff).toInt()
                        System.arraycopy(ahead, cacheStart, data, 0, bytesToRead)
                        
                        // Trigger next read-ahead
                        triggerReadAhead(aheadOff + ahead.size)
                        return bytesToRead
                    }
                }
                
                // Cache miss - read synchronously
                val readStart = System.currentTimeMillis()
                val readSize = minOf(cacheSize.toLong(), fileSize - offset).toInt()
                
                val readData = fsReader.readFileRangeByCluster(firstCluster, fileSize, offset, readSize).getOrThrow()
                val readTime = System.currentTimeMillis() - readStart
                if (DEBUG_LOGGING && readTime > 50) {
                    Log.d(TAG, "PROXY: ${readData.size/1024}KB read in ${readTime}ms for $path")
                }
                
                synchronized(cacheLock) {
                    cachedData = readData
                    cachedOffset = offset
                }
                
                val copySize = minOf(bytesToRead, readData.size)
                System.arraycopy(readData, 0, data, 0, copySize)
                
                // Trigger read-ahead for next chunk
                if (offset + readData.size < fileSize) {
                    triggerReadAhead(offset + readData.size)
                }
                
                return copySize
                
            } catch (e: Exception) {
                Log.e(TAG, "Error reading file at offset $offset", e)
                throw android.system.ErrnoException("onRead", android.system.OsConstants.EIO)
            }
        }
        
        private fun triggerReadAhead(nextOffset: Long) {
            if (nextOffset >= fileSize || readAheadInProgress) return
            
            readAheadInProgress = true
            // Use the shared read-ahead executor — NOT the proxy handler thread.
            // Posting to the proxy handler would queue behind pending onRead() calls,
            // making read-ahead arrive AFTER the data is already needed. The executor
            // runs this concurrently so the buffer is ready when onRead() needs it.
            readAheadExecutor.execute {
                try {
                    val readSize = minOf(cacheSize.toLong(), fileSize - nextOffset).toInt()
                    if (readSize > 0) {
                        val data = fsReader.readFileRangeByCluster(firstCluster, fileSize, nextOffset, readSize).getOrNull()
                        if (data != null) {
                            synchronized(cacheLock) {
                                readAheadData = data
                                readAheadOffset = nextOffset
                            }
                        }
                    }
                } finally {
                    readAheadInProgress = false
                }
            }
        }
        
        override fun onRelease() {
            // Zero decrypted data to prevent it lingering in memory
            localCachedData?.fill(0)
            localCachedData = null
            synchronized(cacheLock) {
                cachedData?.fill(0)
                cachedData = null
                cachedOffset = -1
                readAheadData?.fill(0)
                readAheadData = null
                readAheadOffset = -1
            }
            // HandlerThreads are pooled/shared — do NOT quit them here.
        }
    }

    /**
     * Open document for writing — uses streaming dynamic allocation so data
     * flows directly from the pipe to the encrypted volume without buffering
     * the entire file in memory first.
     */
    private fun openDocumentForWrite(documentId: String, fsReader: FAT32Reader, path: String): ParcelFileDescriptor {
        val pipe = ParcelFileDescriptor.createPipe()
        val readFd = pipe[0]
        val writeFd = pipe[1]
        
        // Stream data from pipe directly to the file system using dynamic allocation.
        // This avoids buffering the entire file in memory (which was causing slowness
        // and OOM for large files) by allocating clusters on-demand as data arrives.
        // Uses the dedicated write executor so writes never compete with read-ahead
        // for thread-pool slots.
        writeExecutor.execute {
            try {
                ParcelFileDescriptor.AutoCloseInputStream(readFd).use { input ->
                    // Use a large buffered stream for efficient pipe reads (1MB buffer)
                    val bufferedInput = java.io.BufferedInputStream(input, 1024 * 1024)
                    
                    fsReader.writeFileStreamingDynamic(path, bufferedInput) { bytesWritten ->
                        if (DEBUG_LOGGING && bytesWritten % (10 * 1024 * 1024) == 0L) {
                            Log.d(TAG, "openDocumentForWrite: ${bytesWritten / (1024 * 1024)}MB written to $path")
                        }
                    }.getOrThrow()
                    
                    if (DEBUG_LOGGING) Log.d(TAG, "openDocumentForWrite: completed writing to $path")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error writing to file", e)
            }
        }
        
        return writeFd
    }
    
    /**
     * Create a new document (file or directory)
     */
    override fun createDocument(
        parentDocumentId: String,
        mimeType: String,
        displayName: String
    ): String? {
        if (DEBUG_LOGGING) Log.d(TAG, "createDocument: parent=$parentDocumentId, mime=$mimeType, name=$displayName")
        
        try {
            val (rootId, parentPath) = parseDocumentId(parentDocumentId)
            val volumePath = getVolumePathFromRootId(rootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            val isDirectory = mimeType == DocumentsContract.Document.MIME_TYPE_DIR
            
            val newEntry = if (isDirectory) {
                fsReader.createDirectory(parentPath, displayName).getOrThrow()
            } else {
                fsReader.createFile(parentPath, displayName).getOrThrow()
            }
            
            // Don't call clearCache() here - createFile/createDirectory already
            // properly manage caches (remove parent directoryCache, add fileCache entry).
            // Calling clearCache() would wipe the fileCache entry that was just added,
            // causing the immediate queryDocument to fail with "File not found".
            
            val newDocumentId = getDocumentId(rootId, newEntry.path)
            
            // Notify parent changed
            val parentUri = DocumentsContract.buildDocumentUri(AUTHORITY, parentDocumentId)
            context?.contentResolver?.notifyChange(parentUri, null)
            
            if (DEBUG_LOGGING) Log.d(TAG, "Created document: $newDocumentId")
            
            return newDocumentId
            
        } catch (e: Exception) {
            Log.e(TAG, "Error creating document", e)
            throw FileNotFoundException("Cannot create document: ${e.message}")
        }
    }
    
    /**
     * Delete a document
     */
    override fun deleteDocument(documentId: String) {
        if (DEBUG_LOGGING) Log.d(TAG, "deleteDocument: $documentId")
        
        try {
            val (rootId, path) = parseDocumentId(documentId)
            val volumePath = getVolumePathFromRootId(rootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            fsReader.delete(path).getOrThrow()
            
            // Notify that the document was deleted
            val deletedUri = DocumentsContract.buildDocumentUri(AUTHORITY, documentId)
            context?.contentResolver?.notifyChange(deletedUri, null)
            
            // Notify parent directory changed
            val parentPath = path.substringBeforeLast('/', "/")
            val parentDocumentId = getDocumentId(rootId, parentPath)
            val parentUri = DocumentsContract.buildDocumentUri(AUTHORITY, parentDocumentId)
            context?.contentResolver?.notifyChange(parentUri, null)
            
            // Also notify children URI for the parent (file managers often use this)
            val childrenUri = DocumentsContract.buildChildDocumentsUri(AUTHORITY, parentDocumentId)
            context?.contentResolver?.notifyChange(childrenUri, null)
            
            if (DEBUG_LOGGING) Log.d(TAG, "Deleted document: $documentId, notified parent: $parentDocumentId")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting document", e)
            throw FileNotFoundException("Cannot delete document: ${e.message}")
        }
    }
    
    /**
     * Move a document to a new parent directory.
     * Uses O(1) directory entry relocation instead of copy+delete.
     */
    override fun moveDocument(
        sourceDocumentId: String,
        sourceParentDocumentId: String,
        targetParentDocumentId: String
    ): String? {
        if (DEBUG_LOGGING) Log.d(TAG, "moveDocument: source=$sourceDocumentId, from=$sourceParentDocumentId, to=$targetParentDocumentId")
        
        try {
            val (sourceRootId, sourcePath) = parseDocumentId(sourceDocumentId)
            val (targetRootId, targetParentPath) = parseDocumentId(targetParentDocumentId)
            
            // Cross-volume move falls back to copy+delete
            if (sourceRootId != targetRootId) {
                val newDocId = copyDocument(sourceDocumentId, targetParentDocumentId)
                if (newDocId != null) {
                    deleteDocument(sourceDocumentId)
                }
                return newDocId
            }
            
            val volumePath = getVolumePathFromRootId(sourceRootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            // O(1) move — relocate directory entry without touching data clusters
            val newPath = fsReader.moveEntry(sourcePath, targetParentPath).getOrThrow()
            val newDocId = "$sourceRootId:$newPath"
            
            // Notify changes
            val sourceUri = DocumentsContract.buildDocumentUri(AUTHORITY, sourceDocumentId)
            val targetUri = DocumentsContract.buildDocumentUri(AUTHORITY, newDocId)
            context?.contentResolver?.notifyChange(sourceUri, null)
            context?.contentResolver?.notifyChange(targetUri, null)
            
            return newDocId
        } catch (e: Exception) {
            Log.e(TAG, "Error moving document", e)
            throw FileNotFoundException("Cannot move document: ${e.message}")
        }
    }
    
    /**
     * Copy a document to a target directory
     */
    override fun copyDocument(sourceDocumentId: String, targetParentDocumentId: String): String? {
        if (DEBUG_LOGGING) Log.d(TAG, "copyDocument: source=$sourceDocumentId, targetParent=$targetParentDocumentId")
        
        try {
            val (sourceRootId, sourcePath) = parseDocumentId(sourceDocumentId)
            val (targetRootId, targetParentPath) = parseDocumentId(targetParentDocumentId)
            
            // For now, only support copy within the same volume
            if (sourceRootId != targetRootId) {
                Log.e(TAG, "Cross-volume copy not supported")
                throw UnsupportedOperationException("Cannot copy across volumes")
            }
            
            val volumePath = getVolumePathFromRootId(sourceRootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            val sourceEntry = fsReader.getFileInfo(sourcePath).getOrThrow()
            val fileName = sourceEntry.getDisplayName()
            
            return if (sourceEntry.isDirectory) {
                // Create the directory and recursively copy contents
                copyDirectoryRecursive(fsReader, sourcePath, targetParentPath, fileName, sourceRootId)
            } else {
                // Copy single file
                copyFile(fsReader, sourcePath, targetParentPath, fileName, sourceRootId)
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error copying document", e)
            throw FileNotFoundException("Cannot copy document: ${e.message}")
        }
    }
    
    private fun copyFile(fsReader: FAT32Reader, sourcePath: String, targetParentPath: String, fileName: String, rootId: String): String {
        if (DEBUG_LOGGING) Log.d(TAG, "copyFile: $sourcePath -> $targetParentPath/$fileName")
        
        // Direct intra-volume copy — pre-allocates clusters, reads+writes in 8MB batches.
        // Avoids pipe overhead and dynamic cluster allocation.
        val newPath = fsReader.copyFileDirect(sourcePath, targetParentPath, fileName).getOrThrow()
        
        val newDocumentId = getDocumentId(rootId, newPath)
        if (DEBUG_LOGGING) Log.d(TAG, "Copied file: $newDocumentId")
        
        // Notify parent changed
        val parentDocumentId = getDocumentId(rootId, targetParentPath)
        val parentUri = DocumentsContract.buildDocumentUri(AUTHORITY, parentDocumentId)
        context?.contentResolver?.notifyChange(parentUri, null)
        
        return newDocumentId
    }
    
    private fun copyDirectoryRecursive(fsReader: FAT32Reader, sourcePath: String, targetParentPath: String, dirName: String, rootId: String): String {
        if (DEBUG_LOGGING) Log.d(TAG, "copyDirectoryRecursive: $sourcePath -> $targetParentPath/$dirName")
        
        // Create the directory
        val newDir = fsReader.createDirectory(targetParentPath, dirName).getOrThrow()
        if (DEBUG_LOGGING) Log.d(TAG, "Created directory: ${newDir.path}")
        
        // Get source directory contents
        val children = fsReader.listDirectory(sourcePath).getOrThrow()
        if (DEBUG_LOGGING) Log.d(TAG, "Copying ${children.size} children")
        
        // Recursively copy all children
        for (child in children) {
            val childName = child.getDisplayName()
            if (child.isDirectory) {
                copyDirectoryRecursive(fsReader, child.path, newDir.path, childName, rootId)
            } else {
                copyFile(fsReader, child.path, newDir.path, childName, rootId)
            }
        }
        
        val newDocumentId = getDocumentId(rootId, newDir.path)
        if (DEBUG_LOGGING) Log.d(TAG, "Completed directory copy: $newDocumentId")
        
        // Notify parent changed
        val parentDocumentId = getDocumentId(rootId, targetParentPath)
        val parentUri = DocumentsContract.buildDocumentUri(AUTHORITY, parentDocumentId)
        context?.contentResolver?.notifyChange(parentUri, null)
        
        return newDocumentId
    }
    
    /**
     * Helper: Add file entry to cursor
     */
    private fun includeFile(result: MatrixCursor, documentId: String, fileEntry: FileEntry) {
        var flags = 0
        
        // Enable write operations for all documents
        flags = flags or Document.FLAG_SUPPORTS_DELETE or Document.FLAG_SUPPORTS_MOVE or Document.FLAG_SUPPORTS_COPY
        
        if (fileEntry.isDirectory) {
            // Directories can have files created inside them
            flags = flags or Document.FLAG_DIR_SUPPORTS_CREATE
        } else {
            // Files can be written to
            flags = flags or Document.FLAG_SUPPORTS_WRITE
        }
        
        val displayName = if (fileEntry.path == "/") "VeraCrypt Volume" else fileEntry.getDisplayName()
        val mimeType = if (fileEntry.isDirectory) DocumentsContract.Document.MIME_TYPE_DIR else (fileEntry.mimeType ?: getMimeType(fileEntry))
        
        val row = result.newRow()
        row.add(Document.COLUMN_DOCUMENT_ID, documentId)
        row.add(Document.COLUMN_DISPLAY_NAME, displayName)
        row.add(Document.COLUMN_SIZE, fileEntry.size)
        row.add(Document.COLUMN_MIME_TYPE, mimeType)
        row.add(Document.COLUMN_LAST_MODIFIED, fileEntry.lastModified)
        row.add(Document.COLUMN_FLAGS, flags)
    }
    
    /**
     * Helper: Get MIME type for file
     */
    private fun getMimeType(fileEntry: FileEntry): String {
        if (fileEntry.isDirectory) {
            return DocumentsContract.Document.MIME_TYPE_DIR
        }
        
        val extension = fileEntry.name.substringAfterLast('.', "")
        if (extension.isEmpty()) {
            return "application/octet-stream"
        }
        
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension.lowercase())
            ?: "application/octet-stream"
    }
    
    /**
     * Helper: Get or create file system reader for volume
     * 
     * Caches FAT32Reader instances for performance - each reader maintains its own
     * directory/file/FAT sector caches which dramatically speeds up repeated access.
     * Call invalidateReaderCache() after write operations to ensure fresh data.
     */
    private fun getOrCreateFileSystemReader(volumePath: String): FAT32Reader? {
        // Delegate to VolumeMountManager's shared cache so that
        // DocumentsProvider and CopyService share the same FAT32Reader.
        return VolumeMountManager.getOrCreateFileSystemReader(volumePath)
    }
    
    /**
     * Invalidate cached reader for a volume (call after writes)
     */
    fun invalidateReaderCache(volumePath: String? = null) {
        VolumeMountManager.invalidateFileSystemReader(volumePath)
    }
    
    /**
     * Helper: Get file system reader for root ID (uses cache)
     */
    private fun getFileSystemReader(rootId: String): FAT32Reader? {
        val volumePath = getVolumePathFromRootId(rootId)
        return getOrCreateFileSystemReader(volumePath)
    }
    
    /**
     * Helper: Generate root ID from volume path
     * Uses Base64-encoded path to avoid hashCode collisions
     */
    private fun getRootId(volumePath: String): String {
        val encoded = android.util.Base64.encodeToString(
            volumePath.toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE
        )
        return ROOT_ID_PREFIX + encoded
    }
    
    /**
     * Helper: Get volume path from root ID
     */
    private fun getVolumePathFromRootId(rootId: String): String {
        val encoded = rootId.removePrefix(ROOT_ID_PREFIX)
        val decoded = String(
            android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE),
            Charsets.UTF_8
        )
        // Verify the volume is actually mounted
        if (!VolumeMountManager.isMounted(decoded)) {
            throw FileNotFoundException("Volume not found for root: $rootId")
        }
        return decoded
    }
    
    /**
     * Helper: Generate document ID from root ID and path
     */
    private fun getDocumentId(rootId: String, path: String): String {
        return "$rootId:$path"
    }
    
    /**
     * Helper: Parse document ID into root ID and path
     */
    private fun parseDocumentId(documentId: String): Pair<String, String> {
        // Format: "veracrypt_XXXX:/path" - find the FIRST colon after "veracrypt_"
        val rootIdPrefix = "veracrypt_"
        if (!documentId.startsWith(rootIdPrefix)) {
            throw IllegalArgumentException("Invalid document ID")
        }
        
        // Find first colon after the veracrypt_ prefix
        val colonIndex = documentId.indexOf(':', rootIdPrefix.length)
        if (colonIndex == -1) {
            throw IllegalArgumentException("Invalid document ID")
        }
        
        val rootId = documentId.substring(0, colonIndex)
        val path = documentId.substring(colonIndex + 1)
        
        // Path traversal validation: reject null bytes, .. segments, and double slashes
        if (path.contains('\u0000') ||
            path.split('/').any { it == ".." } ||
            path.contains("//")) {
            throw SecurityException("Invalid path in document ID")
        }
        
        return Pair(rootId, path)
    }
    
    /**
     * Called when a volume is unmounted
     */
    fun notifyVolumeUnmounted(volumePath: String) {
        // VolumeMountManager handles reader cache cleanup on unmount
        
        // Clear decrypted data caches to prevent stale decrypted content from lingering
        val prefix = "$volumePath:"
        synchronized(thumbnailCacheLock) {
            val keysToRemove = thumbnailCache.keys.filter { it.startsWith(prefix) }
            for (key in keysToRemove) {
                thumbnailCache.remove(key)?.second?.fill(0)  // Zero decrypted data
            }
        }
        synchronized(videoCacheLock) {
            val keysToRemove = videoCache.keys.filter { it.startsWith(prefix) }
            for (key in keysToRemove) {
                videoCache.remove(key)?.second?.fill(0)  // Zero decrypted data
            }
        }
        
        val rootUri = DocumentsContract.buildRootsUri(AUTHORITY)
        context?.contentResolver?.notifyChange(rootUri, null)
    }
    
    /**
     * Called when a volume is mounted
     */
    fun notifyVolumeMounted(volumePath: String) {
        val rootUri = DocumentsContract.buildRootsUri(AUTHORITY)
        context?.contentResolver?.notifyChange(rootUri, null)
    }
}


