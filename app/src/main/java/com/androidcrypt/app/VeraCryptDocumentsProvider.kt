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
            val lowerKey = key.lowercase()
            // Match Valv encrypted videos, paths containing /video, OR actual video extensions
            return lowerKey.endsWith("-v.valv") || 
                   lowerKey.contains("/video") ||
                   lowerKey.endsWith(".mp4") ||
                   lowerKey.endsWith(".mkv") ||
                   lowerKey.endsWith(".avi") ||
                   lowerKey.endsWith(".mov") ||
                   lowerKey.endsWith(".webm") ||
                   lowerKey.endsWith(".m4v") ||
                   lowerKey.endsWith(".3gp") ||
                   lowerKey.endsWith(".wmv") ||
                   lowerKey.endsWith(".flv")
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
                    Log.d("VeraCryptProvider", "VIDEO CACHE HIT: $key (${entry.second.size / 1024}KB)")
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
                    Log.d("VeraCryptProvider", "VIDEO CACHED: $key (${data.size / 1024}KB) - ${videoCache.size} videos in cache")
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
    
    // Cache FAT32Reader instances to avoid reinitializing for every operation
    // This is critical for performance - each reader caches directory/file/FAT data
    private val readerCache = mutableMapOf<String, FAT32Reader>()
    private val readerCacheLock = java.util.concurrent.locks.ReentrantLock()
    
    // Handler thread for proxy file descriptor callbacks
    private val proxyHandlerThread = HandlerThread("ProxyFdHandler").apply { start() }
    private val proxyHandler = Handler(proxyHandlerThread.looper)
    
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
            Log.e(TAG, "Error checking child document: $parentDocumentId vs $documentId", e)
            return false
        }
    }
    
    /**
     * Find the path from a root to a document
     * This is required for proper navigation in file managers
     */
    override fun findDocumentPath(parentDocumentId: String?, childDocumentId: String): Path {
        Log.d(TAG, "findDocumentPath: parent=$parentDocumentId, child=$childDocumentId")
        
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
            Log.e(TAG, "Error finding document path: $childDocumentId", e)
            throw FileNotFoundException("Cannot find path for: $childDocumentId")
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
                        
                        Log.d(TAG, "Added root: $rootId, label: ${fsInfo?.label}, available: $availableBytes bytes")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error processing volume: $volumePath", e)
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
        Log.d(TAG, "queryDocument: $documentId")
        
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
            Log.e(TAG, "Error querying document: $documentId", e)
            throw FileNotFoundException("Cannot find document: $documentId")
        }
        
        return result
    }
    
    /**
     * Get document MIME type - required by some file managers
     */
    override fun getDocumentType(documentId: String): String {
        Log.d(TAG, "getDocumentType: $documentId")
        
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
            Log.e(TAG, "Error getting document type: $documentId", e)
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
        
        try {
            val (rootId, path) = parseDocumentId(parentDocumentId)
            val volumePath = getVolumePathFromRootId(rootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            val entries = fsReader.listDirectory(path).getOrThrow()
            
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
            
            if (DEBUG_LOGGING) Log.d(TAG, "Found ${entries.size} children in $path (included=$includedCount, skipped=$skippedCount empty .valv files)")
            
            // Set notification URI so file manager can watch for changes
            val notifyUri = DocumentsContract.buildChildDocumentsUri(AUTHORITY, parentDocumentId)
            result.setNotificationUri(context?.contentResolver, notifyUri)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error querying child documents: $parentDocumentId", e)
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
            
            val fileEntry = fsReader.getFileInfo(path).getOrThrow()
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
            
            val callback = EncryptedFileProxyCallback(fsReader, volumePath, path, fileEntry.size)
            return storageManager.openProxyFileDescriptor(
                ParcelFileDescriptor.MODE_READ_ONLY,
                callback,
                proxyHandler
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error opening document: $documentId", e)
            throw FileNotFoundException("Cannot open document: ${e.message}")
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
        private val fileSize: Long
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
                    Log.d(TAG, "PROXY CALLBACK: path=$path size=${fileSize/1024}KB PREFETCHED from cache")
                } else {
                    Log.d(TAG, "PROXY CALLBACK: path=$path size=${fileSize/1024}KB isVideo=${isVideoFile(globalCacheKey)} useGlobalCache=$useGlobalCache key=$globalCacheKey")
                }
            } else {
                Log.d(TAG, "PROXY CALLBACK: path=$path size=${fileSize/1024}KB isVideo=${isVideoFile(globalCacheKey)} useGlobalCache=false")
            }
        }
        
        // Pre-load entire small file into global cache on first access
        @Volatile private var globalCacheLoaded = false
        
        // Use larger buffers for video files to sustain high throughput
        private val isVideo = path.lowercase().let { 
            it.endsWith(".mp4") || it.endsWith(".mkv") || it.endsWith(".avi") || 
            it.endsWith(".mov") || it.endsWith(".webm") || it.endsWith(".m4v") ||
            it.endsWith(".valv") // Valv encrypted video format
        }
        
        // 1MB buffer for videos, 256KB for images/other files
        private val cacheSize = if (isVideo || fileSize > 5 * 1024 * 1024) 1024 * 1024 else 256 * 1024
        
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
                        val fullData = fsReader.readFileRange(path, 0, fileSize.toInt()).getOrNull()
                        if (fullData != null) {
                            putCachedFile(globalCacheKey, fullData)
                            localCachedData = fullData  // Also store locally
                            val readTime = System.currentTimeMillis() - readStart
                            Log.d(TAG, "PROXY: Cached ${fullData.size/1024}KB in ${readTime}ms for $path")
                            
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
                
                val readData = fsReader.readFileRange(path, offset, readSize).getOrThrow()
                val readTime = System.currentTimeMillis() - readStart
                if (readTime > 50) {
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
                Log.e(TAG, "Error reading $path at offset $offset", e)
                throw android.system.ErrnoException("onRead", android.system.OsConstants.EIO)
            }
        }
        
        private fun triggerReadAhead(nextOffset: Long) {
            if (nextOffset >= fileSize || readAheadInProgress) return
            
            readAheadInProgress = true
            proxyHandler.post {
                try {
                    val readSize = minOf(cacheSize.toLong(), fileSize - nextOffset).toInt()
                    if (readSize > 0) {
                        val data = fsReader.readFileRange(path, nextOffset, readSize).getOrNull()
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
            synchronized(cacheLock) {
                cachedData = null
                cachedOffset = -1
                readAheadData = null
                readAheadOffset = -1
            }
        }
    }

    /**
     * Open document for writing
     */
    private fun openDocumentForWrite(documentId: String, fsReader: FAT32Reader, path: String): ParcelFileDescriptor {
        val pipe = ParcelFileDescriptor.createPipe()
        val readFd = pipe[0]
        val writeFd = pipe[1]
        
        // Read data from pipe and write to file system
        Thread {
            try {
                ParcelFileDescriptor.AutoCloseInputStream(readFd).use { input ->
                    val data = input.readBytes()
                    fsReader.writeFile(path, data).getOrThrow()
                    // Clear caches after write to ensure fresh data on next read
                    fsReader.clearCache()
                    Log.d(TAG, "Wrote ${data.size} bytes to $path")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error writing to file: $path", e)
            }
        }.start()
        
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
        Log.d(TAG, "createDocument: parent=$parentDocumentId, mime=$mimeType, name=$displayName")
        
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
            
            // Clear caches after write to ensure fresh data
            fsReader.clearCache()
            
            val newDocumentId = getDocumentId(rootId, newEntry.path)
            
            // Notify parent changed
            val parentUri = DocumentsContract.buildDocumentUri(AUTHORITY, parentDocumentId)
            context?.contentResolver?.notifyChange(parentUri, null)
            
            Log.d(TAG, "Created document: $newDocumentId")
            
            return newDocumentId
            
        } catch (e: Exception) {
            Log.e(TAG, "Error creating document: $displayName", e)
            throw FileNotFoundException("Cannot create document: ${e.message}")
        }
    }
    
    /**
     * Delete a document
     */
    override fun deleteDocument(documentId: String) {
        Log.d(TAG, "deleteDocument: $documentId")
        
        try {
            val (rootId, path) = parseDocumentId(documentId)
            val volumePath = getVolumePathFromRootId(rootId)
            val fsReader = getOrCreateFileSystemReader(volumePath) ?: throw FileNotFoundException("Volume not mounted")
            
            fsReader.delete(path).getOrThrow()
            
            // Clear caches after delete to ensure fresh data
            fsReader.clearCache()
            
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
            
            Log.d(TAG, "Deleted document: $documentId, notified parent: $parentDocumentId")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting document: $documentId", e)
            throw FileNotFoundException("Cannot delete document: ${e.message}")
        }
    }
    
    /**
     * Move a document to a new parent directory
     */
    override fun moveDocument(
        sourceDocumentId: String,
        sourceParentDocumentId: String,
        targetParentDocumentId: String
    ): String? {
        Log.d(TAG, "moveDocument: source=$sourceDocumentId, from=$sourceParentDocumentId, to=$targetParentDocumentId")
        
        try {
            // Copy then delete (simple implementation)
            val newDocId = copyDocument(sourceDocumentId, targetParentDocumentId)
            if (newDocId != null) {
                deleteDocument(sourceDocumentId)
            }
            return newDocId
        } catch (e: Exception) {
            Log.e(TAG, "Error moving document: $sourceDocumentId", e)
            throw FileNotFoundException("Cannot move document: ${e.message}")
        }
    }
    
    /**
     * Copy a document to a target directory
     */
    override fun copyDocument(sourceDocumentId: String, targetParentDocumentId: String): String? {
        Log.d(TAG, "copyDocument: source=$sourceDocumentId, targetParent=$targetParentDocumentId")
        
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
            Log.e(TAG, "Error copying document: $sourceDocumentId", e)
            throw FileNotFoundException("Cannot copy document: ${e.message}")
        }
    }
    
    private fun copyFile(fsReader: FAT32Reader, sourcePath: String, targetParentPath: String, fileName: String, rootId: String): String {
        Log.d(TAG, "copyFile: $sourcePath -> $targetParentPath/$fileName")
        
        // Read source file content
        val content = fsReader.readFile(sourcePath).getOrThrow()
        
        // Create new file in target
        val newEntry = fsReader.createFile(targetParentPath, fileName).getOrThrow()
        
        // Write content to new file
        fsReader.writeFile(newEntry.path, content).getOrThrow()
        
        val newDocumentId = getDocumentId(rootId, newEntry.path)
        Log.d(TAG, "Copied file: $newDocumentId")
        
        // Notify parent changed
        val parentDocumentId = getDocumentId(rootId, targetParentPath)
        val parentUri = DocumentsContract.buildDocumentUri(AUTHORITY, parentDocumentId)
        context?.contentResolver?.notifyChange(parentUri, null)
        
        return newDocumentId
    }
    
    private fun copyDirectoryRecursive(fsReader: FAT32Reader, sourcePath: String, targetParentPath: String, dirName: String, rootId: String): String {
        Log.d(TAG, "copyDirectoryRecursive: $sourcePath -> $targetParentPath/$dirName")
        
        // Create the directory
        val newDir = fsReader.createDirectory(targetParentPath, dirName).getOrThrow()
        Log.d(TAG, "Created directory: ${newDir.path}")
        
        // Get source directory contents
        val children = fsReader.listDirectory(sourcePath).getOrThrow()
        Log.d(TAG, "Copying ${children.size} children from $sourcePath")
        
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
        Log.d(TAG, "Completed directory copy: $newDocumentId")
        
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
        
        Log.d(TAG, "includeFile: docId=$documentId, name=$displayName, isDir=${fileEntry.isDirectory}, size=${fileEntry.size}, flags=$flags, mime=$mimeType")
        
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
        readerCacheLock.lock()
        try {
            // Return cached reader if available
            readerCache[volumePath]?.let { return it }
            
            // Create new reader
            val reader = VolumeMountManager.getVolumeReader(volumePath)
            if (reader != null) {
                val fsReader = FAT32Reader(reader)
                // Initialize the file system reader
                val initResult = fsReader.initialize()
                if (initResult.isFailure) {
                    Log.e(TAG, "Failed to initialize file system for $volumePath", initResult.exceptionOrNull())
                    return null
                }
                // Cache for future use
                readerCache[volumePath] = fsReader
                return fsReader
            }
            
            return null
        } finally {
            readerCacheLock.unlock()
        }
    }
    
    /**
     * Invalidate cached reader for a volume (call after writes)
     */
    fun invalidateReaderCache(volumePath: String? = null) {
        readerCacheLock.lock()
        try {
            if (volumePath != null) {
                readerCache[volumePath]?.clearCache()
            } else {
                readerCache.values.forEach { it.clearCache() }
            }
        } finally {
            readerCacheLock.unlock()
        }
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
     */
    private fun getRootId(volumePath: String): String {
        return ROOT_ID_PREFIX + volumePath.hashCode().toString()
    }
    
    /**
     * Helper: Get volume path from root ID
     */
    private fun getVolumePathFromRootId(rootId: String): String {
        val hashCode = rootId.removePrefix(ROOT_ID_PREFIX).toInt()
        return VolumeMountManager.getMountedVolumes().find { it.hashCode() == hashCode }
            ?: throw FileNotFoundException("Volume not found for root: $rootId")
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
            throw IllegalArgumentException("Invalid document ID: $documentId")
        }
        
        // Find first colon after the veracrypt_ prefix
        val colonIndex = documentId.indexOf(':', rootIdPrefix.length)
        if (colonIndex == -1) {
            throw IllegalArgumentException("Invalid document ID: $documentId")
        }
        
        val rootId = documentId.substring(0, colonIndex)
        val path = documentId.substring(colonIndex + 1)
        return Pair(rootId, path)
    }
    
    /**
     * Called when a volume is unmounted
     */
    fun notifyVolumeUnmounted(volumePath: String) {
        // Remove cached reader for this volume
        readerCacheLock.lock()
        try {
            readerCache.remove(volumePath)
        } finally {
            readerCacheLock.unlock()
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
