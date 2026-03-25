package com.androidcrypt.crypto

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import com.androidcrypt.app.VolumeForegroundService

/**
 * Manages mounted volumes and provides file system operations
 */
object VolumeMountManager {
    private const val TAG = "VolumeMountManager"
    private const val DOCUMENTS_AUTHORITY = "com.androidcrypt.documents"
    private val mountedVolumes = java.util.concurrent.ConcurrentHashMap<String, VolumeReader>()
    private val fileSystemReaders = mutableMapOf<String, FAT32Reader>()
    private val fsReaderLock = java.util.concurrent.locks.ReentrantLock()
    private var appContext: Context? = null
    
    // Callbacks for mount/unmount events — CopyOnWriteArrayList is safe for
    // concurrent iteration + modification (add during forEach won't throw)
    private val mountCallbacks = java.util.concurrent.CopyOnWriteArrayList<(String) -> Unit>()
    private val unmountCallbacks = java.util.concurrent.CopyOnWriteArrayList<(String) -> Unit>()
    
    /**
     * Register callback for volume mount events
     */
    fun addMountCallback(callback: (String) -> Unit) {
        mountCallbacks.add(callback)
    }
    
    /**
     * Register callback for volume unmount events
     */
    fun addUnmountCallback(callback: (String) -> Unit) {
        unmountCallbacks.add(callback)
    }
    
    /**
     * Mount a volume from a content URI (recommended for Android 10+)
     * 
     * @param context Android context
     * @param uri Content URI of the container file
     * @param password User password (can be empty if using keyfiles)
     * @param pim Personal Iterations Multiplier (0 for default)
     * @param keyfileUris List of keyfile URIs (optional)
     * @param useHiddenVolume If true, prefer decrypting as a hidden volume
     * @param hiddenVolumeProtectionPassword If non-null, mount outer volume with
     *        hidden volume write protection using this password for the hidden header
     */
    fun mountVolumeFromUri(
        context: Context,
        uri: Uri,
        password: CharArray,
        pim: Int = 0,
        keyfileUris: List<Uri> = emptyList(),
        useHiddenVolume: Boolean = false,
        hiddenVolumeProtectionPassword: CharArray? = null
    ): Result<MountedVolumeInfo> {
        return try {
            val uriString = uri.toString()
            
            // Check if already mounted
            if (mountedVolumes.containsKey(uriString)) {
                return Result.failure(Exception("Volume already mounted"))
            }
            
            val reader = VolumeReader(
                containerPath = uriString,
                context = context,
                containerUri = uri
            )
            val result = reader.mount(password, pim, keyfileUris, useHiddenVolume, hiddenVolumeProtectionPassword)
            
            if (result.isSuccess) {
                mountedVolumes[uriString] = reader
                
                // Notify callbacks
                mountCallbacks.forEach { it(uriString) }
                
                // Notify DocumentsProvider that roots have changed
                notifyDocumentsProviderChanged(context)
                
                // Save app context for later notifications
                if (appContext == null) {
                    appContext = context.applicationContext
                }
                
                // Start foreground service to keep process alive while
                // DocumentsProvider is advertising mounted volume roots.
                // Without this Android may freeze the process and kill it
                // with "Sync transaction while frozen" when DocumentsUI
                // sends binder calls to the frozen provider.
                VolumeForegroundService.start(context.applicationContext)
            } else {
                reader.unmount()
            }
            
            result
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Mount a volume from file path (works on older Android versions or with special permissions)
     */
    fun mountVolume(
        containerPath: String,
        password: CharArray,
        pim: Int = 0,
        useHiddenVolume: Boolean = false,
        hiddenVolumeProtectionPassword: CharArray? = null
    ): Result<MountedVolumeInfo> {
        return try {
            // Check if already mounted
            if (mountedVolumes.containsKey(containerPath)) {
                return Result.failure(Exception("Volume already mounted"))
            }
            
            val reader = VolumeReader(containerPath)
            val result = reader.mount(password, pim, useHiddenVolume = useHiddenVolume, hiddenVolumeProtectionPassword = hiddenVolumeProtectionPassword)
            
            if (result.isSuccess) {
                mountedVolumes[containerPath] = reader
                
                // Notify callbacks
                mountCallbacks.forEach { it(containerPath) }
            } else {
                reader.unmount()
            }
            
            result
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Unmount a volume
     */
    fun unmountVolume(containerPath: String): Result<Unit> {
        return try {
            val reader = mountedVolumes[containerPath]
            if (reader == null) {
                return Result.failure(Exception("Volume not mounted"))
            }
            
            reader.unmount()
            mountedVolumes.remove(containerPath)
            // Remove shared file system reader
            fsReaderLock.lock()
            try { fileSystemReaders.remove(containerPath) } finally { fsReaderLock.unlock() }
            
            // Notify callbacks
            unmountCallbacks.forEach { it(containerPath) }
            
            // Notify DocumentsProvider
            appContext?.let { notifyDocumentsProviderChanged(it) }
            
            // Stop foreground service when no volumes remain mounted
            if (mountedVolumes.isEmpty()) {
                appContext?.let { VolumeForegroundService.stop(it) }
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Unmount all volumes
     */
    fun unmountAll() {
        val paths = mountedVolumes.keys.toList()
        mountedVolumes.values.forEach { it.unmount() }
        mountedVolumes.clear()
        // Clear all shared file system readers
        fsReaderLock.lock()
        try { fileSystemReaders.clear() } finally { fsReaderLock.unlock() }
        
        // Notify callbacks for each unmounted volume
        paths.forEach { path ->
            unmountCallbacks.forEach { callback -> callback(path) }
        }
        
        // Stop foreground service — no volumes remain
        appContext?.let { VolumeForegroundService.stop(it) }
    }
    
    /**
     * Get a mounted volume reader
     */
    fun getVolumeReader(containerPath: String): VolumeReader? {
        return mountedVolumes[containerPath]
    }
    
    /**
     * Check if a volume is mounted
     */
    fun isMounted(containerPath: String): Boolean {
        return mountedVolumes.containsKey(containerPath)
    }
    
    /**
     * Get list of mounted volumes
     */
    fun getMountedVolumes(): List<String> {
        return mountedVolumes.keys.toList()
    }
    
    /**
     * Get or create a shared FAT32Reader for the given volume.
     * This ensures CopyService and DocumentsProvider share the same reader
     * with warm caches, avoiding redundant FAT/directory reads.
     */
    fun getOrCreateFileSystemReader(volumePath: String): FAT32Reader? {
        fsReaderLock.lock()
        try {
            fileSystemReaders[volumePath]?.let { return it }
            
            val reader = mountedVolumes[volumePath] ?: return null
            val fsReader = FAT32Reader(reader)
            val initResult = fsReader.initialize()
            if (initResult.isFailure) {
                Log.e(TAG, "Failed to initialize file system reader", initResult.exceptionOrNull())
                return null
            }
            fileSystemReaders[volumePath] = fsReader
            return fsReader
        } finally {
            fsReaderLock.unlock()
        }
    }
    
    /**
     * Invalidate (clear caches of) the shared FAT32Reader for a volume.
     * Call after external write operations that may have changed the file system.
     */
    fun invalidateFileSystemReader(volumePath: String? = null) {
        fsReaderLock.lock()
        try {
            if (volumePath != null) {
                fileSystemReaders[volumePath]?.clearCache()
            } else {
                fileSystemReaders.values.forEach { it.clearCache() }
            }
        } finally {
            fsReaderLock.unlock()
        }
    }
    
    /**
     * Read data from a mounted volume
     */
    fun readData(containerPath: String, offset: Long, length: Int): Result<ByteArray> {
        val reader = mountedVolumes[containerPath]
            ?: return Result.failure(Exception("Volume not mounted"))
        
        return reader.readData(offset, length)
    }
    
    /**
     * Read a sector from a mounted volume
     */
    fun readSector(containerPath: String, sectorNumber: Long): Result<ByteArray> {
        val reader = mountedVolumes[containerPath]
            ?: return Result.failure(Exception("Volume not mounted"))
        
        return reader.readSector(sectorNumber)
    }
    
    /**
     * Read the first few sectors to inspect the file system.
     * Returns only structural metadata (OEM name, sector size, etc.),
     * never raw hex dumps of decrypted data.
     */
    fun inspectFileSystem(containerPath: String): Result<String> {
        return try {
            val reader = mountedVolumes[containerPath]
                ?: return Result.failure(Exception("Volume not mounted"))
            
            // Read first sector
            val firstSectorResult = reader.readSector(0)
            if (firstSectorResult.isFailure) {
                return Result.failure(firstSectorResult.exceptionOrNull()!!)
            }
            
            val firstSector = firstSectorResult.getOrThrow()
            val info = StringBuilder()
            info.append("File system inspection:\n")
            
            // Extract only structural metadata from FAT32 boot sector
            val oemName = String(firstSector, 3, 8).trim()
            val bytesPerSector = (firstSector[11].toInt() and 0xFF) or ((firstSector[12].toInt() and 0xFF) shl 8)
            val sectorsPerCluster = firstSector[13].toInt() and 0xFF
            val mediaDescriptor = firstSector[21].toInt() and 0xFF
            
            info.append("OEM Name: $oemName\n")
            info.append("Bytes per sector: $bytesPerSector\n")
            info.append("Sectors per cluster: $sectorsPerCluster\n")
            info.append("Media descriptor: 0x${String.format("%02X", mediaDescriptor)}\n")
            
            Result.success(info.toString())
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Notify the DocumentsProvider that roots have changed
     */
    private fun notifyDocumentsProviderChanged(context: Context) {
        try {
            val rootsUri = DocumentsContract.buildRootsUri(DOCUMENTS_AUTHORITY)
            context.contentResolver.notifyChange(rootsUri, null)
            Log.d(TAG, "Notified DocumentsProvider of roots change")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to notify DocumentsProvider", e)
        }
    }
}
