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
    private const val DEBUG_LOGGING = false
    private const val DOCUMENTS_AUTHORITY = "com.androidcrypt.documents"
    private val mountedVolumes = java.util.concurrent.ConcurrentHashMap<String, VolumeReader>()
    // FAT32 readers keyed by volume path (legacy)
    private val fileSystemReaders = mutableMapOf<String, FAT32Reader>()
    // exFAT readers keyed by volume path
    private val exFatReaders = mutableMapOf<String, ExFatReader>()
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
            // Remove shared file system readers
            fsReaderLock.lock()
            try {
                fileSystemReaders.remove(containerPath)
                exFatReaders.remove(containerPath)
            } finally { fsReaderLock.unlock() }
            
            // H-2: purge any decrypted plaintext for this volume that the
            // DocumentsProvider may still be holding in its video / GIF /
            // thumbnail caches.  Without this the caches keep the bytes alive
            // up to VIDEO_CACHE_TTL_MS (10 min, refresh-on-hit) after the
            // user has explicitly unmounted.
            try {
                com.androidcrypt.app.VeraCryptDocumentsProvider
                    .invalidateCachesForVolume(containerPath)
            } catch (_: Throwable) { /* provider may not be loaded in unit tests */ }
            
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
        try {
            fileSystemReaders.clear()
            exFatReaders.clear()
        } finally { fsReaderLock.unlock() }
        
        // H-2: purge every cached decrypted byte for each unmounted volume.
        try {
            for (p in paths) {
                com.androidcrypt.app.VeraCryptDocumentsProvider
                    .invalidateCachesForVolume(p)
            }
        } catch (_: Throwable) { /* provider may not be loaded in unit tests */ }
        
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
     * Detect the file system type of a mounted volume by reading the boot sector's
     * FileSystemName field. exFAT places "EXFAT   " at offset 3 (spec §3.1.2);
     * FAT32 has a 0x55AA signature at offset 510 with no exFAT magic.
     */
    private fun detectFileSystemType(reader: VolumeReader): FileSystemType {
        return try {
            val boot = reader.readSector(0).getOrNull() ?: return FileSystemType.UNKNOWN
            val magic = boot.copyOfRange(3, 11)
            if (magic.contentEquals("EXFAT   ".toByteArray(Charsets.US_ASCII))) {
                FileSystemType.EXFAT
            } else if ((boot[510].toInt() and 0xFF) == 0x55 &&
                       (boot[511].toInt() and 0xFF) == 0xAA) {
                FileSystemType.FAT32
            } else {
                FileSystemType.UNKNOWN
            }
        } catch (_: Exception) {
            FileSystemType.UNKNOWN
        }
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
            // Only hand out a FAT32Reader if the volume actually is FAT32.
            when (detectFileSystemType(reader)) {
                FileSystemType.FAT32, FileSystemType.FAT16, FileSystemType.FAT12, FileSystemType.UNKNOWN -> {
                    val fsReader = FAT32Reader(reader)
                    val initResult = fsReader.initialize()
                    if (initResult.isFailure) {
                        if (DEBUG_LOGGING) Log.e(TAG, "Failed to initialize FAT32 reader", initResult.exceptionOrNull())
                        return null
                    }
                    fileSystemReaders[volumePath] = fsReader
                    return fsReader
                }
                else -> {
                    if (DEBUG_LOGGING) Log.d(TAG, "Volume $volumePath is not FAT32 — use getOrCreateExFatReader")
                    return null
                }
            }
        } finally {
            fsReaderLock.unlock()
        }
    }

    /**
     * Get or create a shared ExFatReader for the given volume.
     * Returns null if the volume is not exFAT or initialization fails.
     */
    fun getOrCreateExFatReader(volumePath: String): ExFatReader? {
        fsReaderLock.lock()
        try {
            exFatReaders[volumePath]?.let { return it }

            val reader = mountedVolumes[volumePath] ?: return null
            if (detectFileSystemType(reader) != FileSystemType.EXFAT) return null
            val fsReader = ExFatReader(reader)
            val initResult = fsReader.initialize()
            if (initResult.isFailure) {
                if (DEBUG_LOGGING) Log.e(TAG, "Failed to initialize exFAT reader", initResult.exceptionOrNull())
                return null
            }
            exFatReaders[volumePath] = fsReader
            return fsReader
        } finally {
            fsReaderLock.unlock()
        }
    }

    /**
     * Get or create a shared [FileSystemReader] for the given volume, dispatching
     * to FAT32Reader or ExFatReader based on the boot-sector magic. Returns null
     * if the volume is not mounted or the FS type cannot be initialized.
     */
    fun getFileSystemReader(volumePath: String): FileSystemReader? {
        fsReaderLock.lock()
        try {
            // Already-cached?
            fileSystemReaders[volumePath]?.let { return it }
            exFatReaders[volumePath]?.let { return it }
            val reader = mountedVolumes[volumePath] ?: return null
            return when (detectFileSystemType(reader)) {
                FileSystemType.EXFAT -> getOrCreateExFatReader(volumePath)
                else -> getOrCreateFileSystemReader(volumePath)
            }
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
                exFatReaders[volumePath]?.clearCache()
            } else {
                fileSystemReaders.values.forEach { it.clearCache() }
                exFatReaders.values.forEach { it.clearCache() }
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

            val fsType = detectFileSystemType(reader)
            info.append("Detected file system: $fsType\n")

            if (fsType == FileSystemType.EXFAT) {
                // exFAT-specific Main Boot Sector fields (spec §3.1)
                val bytesPerSectorShift = firstSector[108].toInt() and 0xFF
                val sectorsPerClusterShift = firstSector[109].toInt() and 0xFF
                val numberOfFats = firstSector[110].toInt() and 0xFF
                info.append("Bytes per sector: ${1 shl bytesPerSectorShift}\n")
                info.append("Sectors per cluster: ${1 shl sectorsPerClusterShift}\n")
                info.append("Number of FATs: $numberOfFats\n")
            } else {
                // FAT32 boot sector metadata
                val oemName = String(firstSector, 3, 8).trim()
                val bytesPerSector = (firstSector[11].toInt() and 0xFF) or ((firstSector[12].toInt() and 0xFF) shl 8)
                val sectorsPerCluster = firstSector[13].toInt() and 0xFF
                val mediaDescriptor = firstSector[21].toInt() and 0xFF

                info.append("OEM Name: $oemName\n")
                info.append("Bytes per sector: $bytesPerSector\n")
                info.append("Sectors per cluster: $sectorsPerCluster\n")
                info.append("Media descriptor: 0x${String.format("%02X", mediaDescriptor)}\n")
            }
            
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
            if (DEBUG_LOGGING) Log.d(TAG, "Notified DocumentsProvider of roots change")
        } catch (e: Exception) {
            if (DEBUG_LOGGING) Log.e(TAG, "Failed to notify DocumentsProvider", e)
        }
    }
}
