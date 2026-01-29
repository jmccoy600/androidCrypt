package com.androidcrypt.crypto

/**
 * Interface for reading file systems from mounted volumes
 */
interface FileSystemReader {
    
    /**
     * Initialize and detect file system type
     */
    fun initialize(): Result<FileSystemInfo>
    
    /**
     * List files and directories in a path
     */
    fun listDirectory(path: String): Result<List<FileEntry>>
    
    /**
     * Read file contents
     */
    fun readFile(path: String): Result<ByteArray>
    
    /**
     * Read partial file contents
     */
    fun readFile(path: String, offset: Long, length: Int): Result<ByteArray>
    
    /**
     * Get file metadata
     */
    fun getFileInfo(path: String): Result<FileEntry>
    
    /**
     * Check if path exists
     */
    fun exists(path: String): Boolean
    
    /**
     * Get root directory
     */
    fun getRootDirectory(): FileEntry
    
    /**
     * Write file contents
     */
    fun writeFile(path: String, data: ByteArray): Result<Unit>
    
    /**
     * Write file contents from input stream (for large files)
     * @param path The path to write to
     * @param inputStream The input stream to read from
     * @param fileSize The total size of the file
     * @param onProgress Optional callback for progress updates (bytes written so far)
     */
    fun writeFileStreaming(
        path: String, 
        inputStream: java.io.InputStream, 
        fileSize: Long,
        onProgress: ((Long) -> Unit)? = null
    ): Result<Unit>
    
    /**
     * Create a new file
     */
    fun createFile(parentPath: String, name: String): Result<FileEntry>
    
    /**
     * Create a new directory
     */
    fun createDirectory(parentPath: String, name: String): Result<FileEntry>
    
    /**
     * Delete a file or directory
     */
    fun delete(path: String): Result<Unit>
}

/**
 * File system information
 */
data class FileSystemInfo(
    val type: FileSystemType,
    val label: String,
    val totalSpace: Long,
    val freeSpace: Long,
    val clusterSize: Int
)

/**
 * Supported file system types
 */
enum class FileSystemType {
    FAT12,
    FAT16,
    FAT32,
    NTFS,
    EXT4,
    UNKNOWN
}

/**
 * File or directory entry
 */
data class FileEntry(
    val name: String,
    val path: String,
    val isDirectory: Boolean,
    val size: Long,
    val lastModified: Long,
    val mimeType: String? = null,
    val firstCluster: Int = 0  // FAT32 first cluster number for this entry
) {
    fun getDisplayName(): String {
        return if (path == "/") "Root" else name
    }
}
