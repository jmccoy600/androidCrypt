package com.androidcrypt.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.provider.DocumentsContract
import android.util.Log
import androidx.core.app.NotificationCompat
import com.androidcrypt.crypto.FAT32Reader
import com.androidcrypt.crypto.VolumeReader
import com.androidcrypt.crypto.VolumeMountManager
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Semaphore
import java.io.ByteArrayInputStream

/**
 * Foreground Service for copying files to/from encrypted volumes.
 * Allows file operations to continue when the app is in the background.
 */
class CopyService : Service() {
    
    companion object {
        private const val TAG = "CopyService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "copy_service_channel"
        
        // Action constants
        const val ACTION_COPY_FOLDER_TO_VOLUME = "copy_folder_to_volume"
        const val ACTION_COPY_FILE_TO_VOLUME = "copy_file_to_volume"
        const val ACTION_CANCEL = "cancel_copy"
        
        // Extra keys
        const val EXTRA_SOURCE_URI = "source_uri"
        const val EXTRA_VOLUME_PATH = "volume_path"
        const val EXTRA_FOLDER_NAME = "folder_name"
        
        // Singleton for accessing current state from Activity
        private val _copyState = MutableStateFlow<CopyState>(CopyState.Idle)
        val copyState: StateFlow<CopyState> = _copyState
        
        private val _progress = MutableStateFlow("")
        val progress: StateFlow<String> = _progress
        
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning
    }
    
    sealed class CopyState {
        object Idle : CopyState()
        data class Copying(val progress: String, val current: Int, val total: Int) : CopyState()
        data class Completed(val message: String, val success: Boolean) : CopyState()
        data class Error(val message: String) : CopyState()
    }
    
    private val binder = LocalBinder()
    private var copyJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var wakeLock: PowerManager.WakeLock? = null
    
    inner class LocalBinder : Binder() {
        fun getService(): CopyService = this@CopyService
    }
    
    override fun onBind(intent: Intent?): IBinder = binder
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}")
        when (intent?.action) {
            ACTION_CANCEL -> {
                Log.d(TAG, "Cancel action received")
                cancelCopy()
                return START_NOT_STICKY
            }
            ACTION_COPY_FOLDER_TO_VOLUME -> {
                val sourceUri = intent.getParcelableExtra<Uri>(EXTRA_SOURCE_URI)
                val volumePath = intent.getStringExtra(EXTRA_VOLUME_PATH)
                val folderName = intent.getStringExtra(EXTRA_FOLDER_NAME)
                
                if (sourceUri != null && volumePath != null && folderName != null) {
                    startForeground(NOTIFICATION_ID, createNotification("Preparing to copy..."))
                    acquireWakeLock()
                    startFolderCopy(sourceUri, volumePath, folderName)
                }
            }
            ACTION_COPY_FILE_TO_VOLUME -> {
                val sourceUri = intent.getParcelableExtra<Uri>(EXTRA_SOURCE_URI)
                val volumePath = intent.getStringExtra(EXTRA_VOLUME_PATH)
                
                if (sourceUri != null && volumePath != null) {
                    startForeground(NOTIFICATION_ID, createNotification("Preparing to copy..."))
                    acquireWakeLock()
                    startFileCopy(sourceUri, volumePath)
                }
            }
        }
        
        return START_NOT_STICKY
    }
    
    override fun onDestroy() {
        super.onDestroy()
        cancelCopy()
        releaseWakeLock()
        serviceScope.cancel()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "File Copy Operations",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows progress of file copy operations"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(progressText: String, current: Int = 0, total: Int = 0): Notification {
        val cancelIntent = Intent(this, CopyService::class.java).apply {
            action = ACTION_CANCEL
        }
        val cancelPendingIntent = PendingIntent.getService(
            this, 0, cancelIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val openAppPendingIntent = PendingIntent.getActivity(
            this, 0, openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Copying files to encrypted volume")
            .setContentText(progressText)
            .setSmallIcon(android.R.drawable.ic_menu_upload)
            .setOngoing(true)
            .setContentIntent(openAppPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Cancel", cancelPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
        
        if (total > 0) {
            builder.setProgress(total, current, false)
        } else {
            builder.setProgress(0, 0, true)
        }
        
        return builder.build()
    }
    
    private var lastNotificationTime = 0L
    private val notificationRateLimit = 500L // Update at most every 500ms
    
    private fun updateNotification(progressText: String, current: Int = 0, total: Int = 0, force: Boolean = false) {
        val now = System.currentTimeMillis()
        // Rate limit notification updates to avoid system throttling
        if (!force && now - lastNotificationTime < notificationRateLimit) {
            // Still update the StateFlow for UI, just skip the system notification
            _progress.value = progressText
            _copyState.value = CopyState.Copying(progressText, current, total)
            return
        }
        lastNotificationTime = now
        
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, createNotification(progressText, current, total))
        
        _progress.value = progressText
        _copyState.value = CopyState.Copying(progressText, current, total)
    }
    
    private fun acquireWakeLock() {
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "CopyService::WakeLock"
        ).apply {
            acquire(60 * 60 * 1000L) // 1 hour max
        }
    }
    
    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
            }
        }
        wakeLock = null
    }
    
    fun cancelCopy() {
        Log.d(TAG, "cancelCopy() called, copyJob=$copyJob")
        val job = copyJob
        copyJob = null
        
        // Only show cancelled message if job was actually running (not already completed)
        if (job != null && job.isActive) {
            job.cancel()
            _isRunning.value = false
            _copyState.value = CopyState.Error("Copy cancelled")
        }
        
        releaseWakeLock()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.d(TAG, "cancelCopy() complete")
    }
    
    private fun completeCopy(success: Boolean, message: String) {
        _isRunning.value = false
        _copyState.value = if (success) {
            CopyState.Completed(message, true)
        } else {
            CopyState.Error(message)
        }
        
        // Show completion notification
        val notificationManager = getSystemService(NotificationManager::class.java)
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(if (success) "Copy complete" else "Copy failed")
            .setContentText(message)
            .setSmallIcon(if (success) android.R.drawable.ic_menu_upload else android.R.drawable.ic_dialog_alert)
            .setAutoCancel(true)
            .build()
        
        notificationManager.notify(NOTIFICATION_ID + 1, notification)
        
        releaseWakeLock()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }
    
    private fun startFileCopy(sourceUri: Uri, volumePath: String) {
        if (_isRunning.value) {
            Log.w(TAG, "Copy already in progress")
            return
        }
        
        _isRunning.value = true
        _copyState.value = CopyState.Copying("Starting...", 0, 1)
        
        copyJob = serviceScope.launch {
            try {
                val volumeReader: VolumeReader? = VolumeMountManager.getVolumeReader(volumePath)
                if (volumeReader == null) {
                    completeCopy(false, "Volume not mounted")
                    return@launch
                }
                
                val reader = FAT32Reader(volumeReader)
                reader.initialize()
                
                // Get file name and size
                val fileName = getFileNameFromUri(sourceUri)
                val fileSize = getFileSizeFromUri(sourceUri)
                
                Log.d(TAG, "startFileCopy: fileName=$fileName, fileSize=$fileSize bytes (${fileSize / (1024 * 1024)} MB)")
                
                updateNotification("Copying: $fileName", 0, 1)
                
                // Open input stream for the file
                val inputStream = contentResolver.openInputStream(sourceUri)
                if (inputStream == null) {
                    completeCopy(false, "Could not open file")
                    return@launch
                }
                
                // Create file in volume
                val filePath = "/$fileName"
                if (!reader.exists(filePath)) {
                    Log.d(TAG, "startFileCopy: Creating file entry for $filePath")
                    reader.createFile("/", fileName).getOrThrow()
                }
                
                // Stream file directly to volume (no memory buffering)
                Log.d(TAG, "startFileCopy: Starting streaming write for $filePath")
                inputStream.use { stream ->
                    reader.writeFileStreaming(filePath, stream, fileSize) { bytesWritten ->
                        val percent = if (fileSize > 0) (bytesWritten * 100 / fileSize).toInt() else 0
                        if (bytesWritten % (50 * 1024 * 1024) < (256 * 1024)) { // Log every ~50MB
                            Log.d(TAG, "startFileCopy: Progress ${bytesWritten / (1024 * 1024)} MB / ${fileSize / (1024 * 1024)} MB ($percent%)")
                        }
                    }.getOrThrow()
                }
                
                Log.d(TAG, "startFileCopy: Streaming write completed for $filePath")
                updateNotification("Complete: $fileName", 1, 1)
                
                // Notify DocumentsProvider
                notifyVolumeChanged(volumePath)
                
                completeCopy(true, "File copied successfully!")
                
            } catch (e: CancellationException) {
                completeCopy(false, "Copy cancelled")
            } catch (e: Exception) {
                Log.e(TAG, "Copy failed", e)
                completeCopy(false, "Copy failed: ${e.message}")
            }
        }
    }
    
    private fun startFolderCopy(sourceUri: Uri, volumePath: String, folderName: String) {
        if (_isRunning.value) {
            Log.w(TAG, "Copy already in progress")
            return
        }
        
        _isRunning.value = true
        _copyState.value = CopyState.Copying("Counting files...", 0, 0)
        
        copyJob = serviceScope.launch {
            try {
                val volumeReader: VolumeReader? = VolumeMountManager.getVolumeReader(volumePath)
                if (volumeReader == null) {
                    completeCopy(false, "Volume not mounted")
                    return@launch
                }
                
                val reader = FAT32Reader(volumeReader)
                reader.initialize()
                
                updateNotification("Counting files...", 0, 0)
                
                // Count total files
                val totalFiles = countFilesInFolder(sourceUri)
                val counter = CopyCounter(totalFiles)
                
                updateNotification("Copying 0/$totalFiles files...", 0, totalFiles)
                
                // Copy folder
                copyFolderToVolume(sourceUri, "/", folderName, reader, counter) { progress ->
                    updateNotification(progress, counter.current, counter.total)
                }
                
                // Notify DocumentsProvider
                notifyVolumeChanged(volumePath)
                
                completeCopy(true, "Folder copied successfully! ($totalFiles files)")
                
            } catch (e: CancellationException) {
                completeCopy(false, "Copy cancelled")
            } catch (e: Exception) {
                Log.e(TAG, "Copy failed", e)
                completeCopy(false, "Copy failed: ${e.message}")
            }
        }
    }
    
    private fun notifyVolumeChanged(volumePath: String) {
        try {
            val authority = "com.androidcrypt.documents"
            val rootId = "veracrypt_${volumePath.hashCode()}"
            val rootDocId = "$rootId:/"
            val childrenUri = DocumentsContract.buildChildDocumentsUri(authority, rootDocId)
            contentResolver.notifyChange(childrenUri, null)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to notify volume change", e)
        }
    }
    
    private fun getFileNameFromUri(uri: Uri): String {
        var fileName: String? = null
        contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                fileName = cursor.getString(0)
            }
        }
        return fileName ?: uri.lastPathSegment ?: "unknown"
    }
    
    private fun getFileSizeFromUri(uri: Uri): Long {
        var size = 0L
        contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.SIZE), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                size = cursor.getLong(0)
            }
        }
        return size
    }
    
    private fun countFilesInFolder(folderUri: Uri): Int {
        var count = 0
        // Handle both tree URIs and document URIs
        val docId = try {
            DocumentsContract.getDocumentId(folderUri)
        } catch (e: Exception) {
            DocumentsContract.getTreeDocumentId(folderUri)
        }
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(folderUri, docId)
        
        contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_MIME_TYPE
            ),
            null, null, null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val docId = cursor.getString(0)
                val mimeType = cursor.getString(1)
                
                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    // Recursively count subfolder
                    val subFolderUri = DocumentsContract.buildChildDocumentsUriUsingTree(folderUri, docId)
                    count += countFilesInSubFolder(folderUri, docId)
                } else {
                    count++
                }
            }
        }
        
        return count
    }
    
    private fun countFilesInSubFolder(treeUri: Uri, folderId: String): Int {
        var count = 0
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, folderId)
        
        contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_MIME_TYPE
            ),
            null, null, null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val docId = cursor.getString(0)
                val mimeType = cursor.getString(1)
                
                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    count += countFilesInSubFolder(treeUri, docId)
                } else {
                    count++
                }
            }
        }
        
        return count
    }
    
    // Data class for pre-read files (small files only)
    private data class PreReadFile(
        val name: String,
        val targetPath: String,
        val data: ByteArray,
        val size: Long
    )
    
    // Data class for large files that need streaming
    private data class LargeFileInfo(
        val docId: String,
        val name: String,
        val targetPath: String,
        val size: Long
    )
    
    // Threshold for streaming vs buffering (20MB)
    // With 4 parallel readers + 8 buffer capacity, we could have ~12 files in memory
    // 256MB heap limit / 12 = ~21MB max per file to be safe
    private val LARGE_FILE_THRESHOLD = 20 * 1024 * 1024L
    
    // Counter class for progress tracking
    class CopyCounter(val total: Int) {
        var current: Int = 0
            private set
        
        fun increment() {
            current++
        }
        
        fun progressString(): String = "$current/$total"
    }
    
    private suspend fun copyFolderToVolume(
        folderUri: Uri,
        targetPath: String,
        folderName: String,
        reader: FAT32Reader,
        counter: CopyCounter,
        onProgress: (String) -> Unit
    ): Unit = coroutineScope {
        // Create the folder in the volume
        val newFolderPath = if (targetPath == "/") "/$folderName" else "$targetPath/$folderName"
        
        if (!reader.exists(newFolderPath)) {
            reader.createDirectory(targetPath, folderName).getOrThrow()
        }
        
        // Handle both tree URIs and document URIs
        val docId = try {
            DocumentsContract.getDocumentId(folderUri)
        } catch (e: Exception) {
            DocumentsContract.getTreeDocumentId(folderUri)
        }
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(folderUri, docId)
        
        val smallFiles: MutableList<Triple<String, String, Long>> = mutableListOf()
        val largeFiles: MutableList<LargeFileInfo> = mutableListOf()
        val subdirs: MutableList<Pair<String, String>> = mutableListOf()
        
        contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE
            ),
            null, null, null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val docId = cursor.getString(0)
                val name = cursor.getString(1)
                val mimeType = cursor.getString(2)
                val size = cursor.getLong(3)
                
                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    subdirs.add(docId to name)
                } else {
                    val filePath = if (newFolderPath == "/") "/$name" else "$newFolderPath/$name"
                    var shouldCopy = true
                    if (reader.exists(filePath)) {
                        // Check if existing file is 0 bytes - if so, delete it and copy the new file
                        val existingInfo = reader.getFileInfo(filePath).getOrNull()
                        if (existingInfo != null && existingInfo.size == 0L && size > 0) {
                            Log.d(TAG, "Deleting 0-byte file to overwrite: $filePath")
                            reader.delete(filePath)
                            // Don't skip - allow the copy to proceed
                        } else {
                            counter.increment()
                            onProgress("Skipping ${counter.progressString()}: $name (exists)")
                            shouldCopy = false
                        }
                    }
                    if (shouldCopy) {
                        if (size > LARGE_FILE_THRESHOLD) {
                            // Large files will be streamed directly
                            largeFiles.add(LargeFileInfo(docId, name, newFolderPath, size))
                        } else {
                            smallFiles.add(Triple(docId, name, size))
                        }
                    }
                }
            }
        }
        
        // Process small files with parallel buffered reading
        val fileChannel = Channel<PreReadFile>(capacity = 8)
        val readSemaphore = Semaphore(4)
        
        // Producer runs as child of current coroutine so cancel propagates
        val producer = launch(Dispatchers.IO) {
            val readJobs: List<Job> = smallFiles.map { (docId, name, size) ->
                launch {
                    readSemaphore.acquire()
                    try {
                        ensureActive() // Check if we should continue
                        val fileUri = DocumentsContract.buildDocumentUriUsingTree(folderUri, docId)
                        contentResolver.openInputStream(fileUri)?.use { inputStream ->
                            val data = inputStream.readBytes()
                            if (isActive) { // Only send if we're still running
                                fileChannel.send(PreReadFile(name, newFolderPath, data, size))
                            }
                        }
                    } catch (e: CancellationException) {
                        // Don't log cancellation as error - it's expected on cancel
                        throw e
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to read: $name", e)
                    } finally {
                        readSemaphore.release()
                    }
                }
            }
            readJobs.forEach { it.join() }
            fileChannel.close()
        }
        
        // Consumer: write small files
        var filesWritten = 0
        for (preRead in fileChannel) {
            counter.increment()
            onProgress("Copying ${counter.progressString()}: ${preRead.name}")
            
            val newFilePath = if (preRead.targetPath == "/") "/${preRead.name}" else "${preRead.targetPath}/${preRead.name}"
            
            try {
                reader.createFile(preRead.targetPath, preRead.name).getOrThrow()
                reader.writeFileStreaming(newFilePath, ByteArrayInputStream(preRead.data), preRead.data.size.toLong(), null).getOrThrow()
                filesWritten++
            } catch (e: CancellationException) {
                // Re-throw cancellation to properly propagate
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Failed to write file: $newFilePath", e)
                // Clean up 0-byte file that was created before the write failed
                try {
                    if (reader.exists(newFilePath)) {
                        reader.delete(newFilePath)
                        Log.d(TAG, "Cleaned up failed file: $newFilePath")
                    }
                } catch (cleanupEx: Exception) {
                    Log.w(TAG, "Failed to clean up 0-byte file: $newFilePath", cleanupEx)
                }
            }
        }
        
        producer.join()
        
        // Process large files sequentially with streaming (no memory buffering)
        for (largeFile in largeFiles) {
            counter.increment()
            onProgress("Copying ${counter.progressString()}: ${largeFile.name} (${largeFile.size / (1024 * 1024)}MB)")
            
            val newFilePath = if (largeFile.targetPath == "/") "/${largeFile.name}" else "${largeFile.targetPath}/${largeFile.name}"
            
            try {
                val fileUri = DocumentsContract.buildDocumentUriUsingTree(folderUri, largeFile.docId)
                contentResolver.openInputStream(fileUri)?.use { inputStream ->
                    reader.createFile(largeFile.targetPath, largeFile.name).getOrThrow()
                    reader.writeFileStreaming(newFilePath, inputStream, largeFile.size, null).getOrThrow()
                    filesWritten++
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Failed to write large file: $newFilePath", e)
                // Clean up 0-byte file that was created before the write failed
                try {
                    if (reader.exists(newFilePath)) {
                        reader.delete(newFilePath)
                        Log.d(TAG, "Cleaned up failed large file: $newFilePath")
                    }
                } catch (cleanupEx: Exception) {
                    Log.w(TAG, "Failed to clean up 0-byte file: $newFilePath", cleanupEx)
                }
            }
        }
        
        Log.d(TAG, "copyFolderToVolume: Wrote $filesWritten files to $newFolderPath")
        
        // Process subdirectories
        Log.d(TAG, "copyFolderToVolume: Processing ${subdirs.size} subdirectories in $newFolderPath")
        for ((docId, name) in subdirs) {
            Log.d(TAG, "copyFolderToVolume: Entering subfolder: $name (docId=$docId)")
            copySubFolder(folderUri, docId, newFolderPath, name, reader, counter, onProgress)
        }
    }
    
    private suspend fun copySubFolder(
        treeUri: Uri,
        folderId: String,
        targetPath: String,
        folderName: String,
        reader: FAT32Reader,
        counter: CopyCounter,
        onProgress: (String) -> Unit
    ): Unit = coroutineScope {
        val newFolderPath = if (targetPath == "/") "/$folderName" else "$targetPath/$folderName"
        
        if (!reader.exists(newFolderPath)) {
            reader.createDirectory(targetPath, folderName).getOrThrow()
        }
        
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, folderId)
        
        val smallFiles: MutableList<Triple<String, String, Long>> = mutableListOf()
        val largeFiles: MutableList<LargeFileInfo> = mutableListOf()
        val subdirs: MutableList<Pair<String, String>> = mutableListOf()
        
        contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE
            ),
            null, null, null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val docId = cursor.getString(0)
                val name = cursor.getString(1)
                val mimeType = cursor.getString(2)
                val size = cursor.getLong(3)
                
                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    subdirs.add(docId to name)
                } else {
                    val filePath = if (newFolderPath == "/") "/$name" else "$newFolderPath/$name"
                    var shouldCopy = true
                    if (reader.exists(filePath)) {
                        // Check if existing file is 0 bytes - if so, delete it and copy the new file
                        val existingInfo = reader.getFileInfo(filePath).getOrNull()
                        if (existingInfo != null && existingInfo.size == 0L && size > 0) {
                            Log.d(TAG, "Deleting 0-byte file to overwrite: $filePath")
                            reader.delete(filePath)
                            // Don't skip - allow the copy to proceed
                        } else {
                            counter.increment()
                            onProgress("Skipping ${counter.progressString()}: $name (exists)")
                            shouldCopy = false
                        }
                    }
                    if (shouldCopy) {
                        if (size > LARGE_FILE_THRESHOLD) {
                            largeFiles.add(LargeFileInfo(docId, name, newFolderPath, size))
                        } else {
                            smallFiles.add(Triple(docId, name, size))
                        }
                    }
                }
            }
        }
        
        val fileChannel = Channel<PreReadFile>(capacity = 8)
        val readSemaphore = Semaphore(4)
        
        // Producer runs as child of current coroutine so cancel propagates
        val producer = launch(Dispatchers.IO) {
            val readJobs: List<Job> = smallFiles.map { (docId, name, size) ->
                launch {
                    readSemaphore.acquire()
                    try {
                        ensureActive() // Check if we should continue
                        val fileUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                        contentResolver.openInputStream(fileUri)?.use { inputStream ->
                            val data = inputStream.readBytes()
                            if (isActive) { // Only send if we're still running
                                fileChannel.send(PreReadFile(name, newFolderPath, data, size))
                            }
                        }
                    } catch (e: CancellationException) {
                        // Don't log cancellation as error - it's expected on cancel
                        throw e
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to read: $name", e)
                    } finally {
                        readSemaphore.release()
                    }
                }
            }
            readJobs.forEach { it.join() }
            fileChannel.close()
        }
        
        // Process small files
        for (preRead in fileChannel) {
            counter.increment()
            onProgress("Copying ${counter.progressString()}: ${preRead.name}")
            
            val newFilePath = if (preRead.targetPath == "/") "/${preRead.name}" else "${preRead.targetPath}/${preRead.name}"
            
            try {
                reader.createFile(preRead.targetPath, preRead.name).getOrThrow()
                reader.writeFileStreaming(newFilePath, ByteArrayInputStream(preRead.data), preRead.data.size.toLong(), null).getOrThrow()
            } catch (e: CancellationException) {
                // Re-throw cancellation to properly propagate
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "copySubFolder: Failed to write file: $newFilePath", e)
                // Clean up 0-byte file that was created before the write failed
                try {
                    if (reader.exists(newFilePath)) {
                        reader.delete(newFilePath)
                        Log.d(TAG, "copySubFolder: Cleaned up failed file: $newFilePath")
                    }
                } catch (cleanupEx: Exception) {
                    Log.w(TAG, "copySubFolder: Failed to clean up 0-byte file: $newFilePath", cleanupEx)
                }
            }
        }
        
        producer.join()
        
        // Process large files sequentially with streaming
        for (largeFile in largeFiles) {
            counter.increment()
            onProgress("Copying ${counter.progressString()}: ${largeFile.name} (${largeFile.size / (1024 * 1024)}MB)")
            
            val newFilePath = if (largeFile.targetPath == "/") "/${largeFile.name}" else "${largeFile.targetPath}/${largeFile.name}"
            
            try {
                val fileUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, largeFile.docId)
                contentResolver.openInputStream(fileUri)?.use { inputStream ->
                    reader.createFile(largeFile.targetPath, largeFile.name).getOrThrow()
                    reader.writeFileStreaming(newFilePath, inputStream, largeFile.size, null).getOrThrow()
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "copySubFolder: Failed to write large file: $newFilePath", e)
                // Clean up 0-byte file that was created before the write failed
                try {
                    if (reader.exists(newFilePath)) {
                        reader.delete(newFilePath)
                        Log.d(TAG, "copySubFolder: Cleaned up failed large file: $newFilePath")
                    }
                } catch (cleanupEx: Exception) {
                    Log.w(TAG, "copySubFolder: Failed to clean up 0-byte file: $newFilePath", cleanupEx)
                }
            }
        }
        
        Log.d(TAG, "copySubFolder: Processing ${subdirs.size} subdirectories in $newFolderPath")
        for ((docId, name) in subdirs) {
            Log.d(TAG, "copySubFolder: Entering subfolder: $name (docId=$docId)")
            copySubFolder(treeUri, docId, newFolderPath, name, reader, counter, onProgress)
        }
    }
}
