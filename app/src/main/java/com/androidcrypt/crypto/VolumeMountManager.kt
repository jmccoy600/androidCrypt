package com.androidcrypt.crypto

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log

/**
 * Manages mounted volumes and provides file system operations
 */
object VolumeMountManager {
    private const val TAG = "VolumeMountManager"
    private const val DOCUMENTS_AUTHORITY = "com.androidcrypt.documents"
    private val mountedVolumes = mutableMapOf<String, VolumeReader>()
    private var appContext: Context? = null
    
    // Callbacks for mount/unmount events
    private val mountCallbacks = mutableListOf<(String) -> Unit>()
    private val unmountCallbacks = mutableListOf<(String) -> Unit>()
    
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
     */
    fun mountVolumeFromUri(
        context: Context,
        uri: Uri,
        password: String,
        pim: Int = 0,
        keyfileUris: List<Uri> = emptyList()
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
            val result = reader.mount(password, pim, keyfileUris)
            
            if (result.isSuccess) {
                mountedVolumes[uriString] = reader
                Log.d(TAG, "Volume mounted from URI: $uriString")
                
                // Notify callbacks
                mountCallbacks.forEach { it(uriString) }
                
                // Notify DocumentsProvider that roots have changed
                notifyDocumentsProviderChanged(context)
                
                // Save app context for later notifications
                if (appContext == null) {
                    appContext = context.applicationContext
                }
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
        password: String,
        pim: Int = 0
    ): Result<MountedVolumeInfo> {
        return try {
            // Check if already mounted
            if (mountedVolumes.containsKey(containerPath)) {
                return Result.failure(Exception("Volume already mounted"))
            }
            
            val reader = VolumeReader(containerPath)
            val result = reader.mount(password, pim)
            
            if (result.isSuccess) {
                mountedVolumes[containerPath] = reader
                Log.d(TAG, "Volume mounted: $containerPath")
                
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
            Log.d(TAG, "Volume unmounted: $containerPath")
            
            // Notify callbacks
            unmountCallbacks.forEach { it(containerPath) }
            
            // Notify DocumentsProvider
            appContext?.let { notifyDocumentsProviderChanged(it) }
            
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
        Log.d(TAG, "All volumes unmounted")
        
        // Notify callbacks for each unmounted volume
        paths.forEach { path ->
            unmountCallbacks.forEach { callback -> callback(path) }
        }
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
     * Read the first few sectors to inspect the file system
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
            info.append("First sector data (512 bytes):\n")
            info.append("Hex dump:\n")
            
            // Show first 256 bytes in hex
            for (i in 0 until minOf(256, firstSector.size)) {
                if (i % 16 == 0) {
                    info.append(String.format("\n%04X: ", i))
                }
                info.append(String.format("%02X ", firstSector[i]))
            }
            
            info.append("\n\nASCII representation:\n")
            for (i in 0 until minOf(256, firstSector.size)) {
                if (i % 64 == 0) {
                    info.append("\n")
                }
                val char = firstSector[i].toInt() and 0xFF
                info.append(if (char in 32..126) char.toChar() else '.')
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
            Log.d(TAG, "Notified DocumentsProvider of roots change")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to notify DocumentsProvider", e)
        }
    }
}
