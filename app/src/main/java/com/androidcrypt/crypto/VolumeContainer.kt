package com.androidcrypt.crypto

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer

/**
 * VeraCrypt container file manager
 * Handles creating and accessing encrypted container files
 */
class VolumeContainer(private val file: File) {
    private var headerData: VolumeHeaderData? = null
    private var masterKey: ByteArray? = null
    private var xtsMode: XTSMode? = null
    
    /**
     * Open and decrypt an existing volume container
     */
    fun open(password: String, pim: Int = 0): Boolean {
        if (!file.exists()) {
            throw IllegalArgumentException("Container file does not exist: ${file.absolutePath}")
        }
        
        RandomAccessFile(file, "r").use { raf ->
            // Read header
            val headerBytes = ByteArray(VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE)
            raf.seek(0)
            raf.readFully(headerBytes)
            
            // Parse and decrypt header
            val parser = VolumeHeaderParser()
            val header = parser.parseHeader(headerBytes, password, pim)
                ?: return false
            
            headerData = header
            masterKey = header.masterKey
            xtsMode = XTSMode(header.masterKey, header.encryptionAlgorithm)
            
            return true
        }
    }
    
    /**
     * Create a new encrypted volume container
     */
    fun create(
        password: String,
        sizeBytes: Long,
        pim: Int = 0,
        encryptionAlg: EncryptionAlgorithm = EncryptionAlgorithm.AES,
        hashAlg: HashAlgorithm = HashAlgorithm.SHA512
    ) {
        // Validate size
        val minSize = VolumeConstants.VOLUME_HEADER_GROUP_SIZE + 1024 * 1024 // At least 1MB data area
        require(sizeBytes >= minSize) {
            "Volume size must be at least $minSize bytes"
        }
        
        // Calculate data area size
        val dataAreaSize = sizeBytes - VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        
        // Create header
        val parser = VolumeHeaderParser()
        val header = parser.createHeader(
            password = password,
            pim = pim,
            volumeSize = dataAreaSize,
            encryptionAlg = encryptionAlg,
            hashAlg = hashAlg
        )
        
        // Create file and write header
        RandomAccessFile(file, "rw").use { raf ->
            // Write primary header at offset 0
            raf.seek(0)
            raf.write(header)
            
            // Pad to full header size (64KB)
            val padding = ByteArray(VolumeConstants.VOLUME_HEADER_SIZE.toInt() - header.size)
            raf.write(padding)
            
            // Write backup header at offset 64KB
            raf.seek(VolumeConstants.VOLUME_HEADER_SIZE)
            raf.write(header)
            raf.write(padding)
            
            // Initialize data area with random data (or zeros for quick format)
            // For production, you might want to fill with random data for security
            val blockSize = 1024 * 1024 // 1MB blocks
            val zeroBlock = ByteArray(blockSize)
            
            var remaining = dataAreaSize
            while (remaining > 0) {
                val toWrite = minOf(remaining, blockSize.toLong()).toInt()
                raf.write(zeroBlock, 0, toWrite)
                remaining -= toWrite
            }
        }
        
        // Open the newly created volume
        open(password, pim)
    }
    
    /**
     * Read decrypted data from the volume
     * @param offset Offset within the data area (not including headers)
     * @param length Number of bytes to read
     * @return Decrypted data
     */
    fun read(offset: Long, length: Int): ByteArray {
        requireOpened()
        
        val header = headerData!!
        val xts = xtsMode!!
        
        // Calculate file offset (add header size)
        val fileOffset = VolumeConstants.VOLUME_HEADER_GROUP_SIZE + offset
        
        // Align to sector boundaries
        val sectorSize = header.sectorSize
        val startSector = offset / sectorSize
        val endSector = (offset + length + sectorSize - 1) / sectorSize
        val alignedOffset = startSector * sectorSize
        val alignedLength = ((endSector - startSector) * sectorSize).toInt()
        
        // Read encrypted data
        val encryptedData = ByteArray(alignedLength)
        RandomAccessFile(file, "r").use { raf ->
            raf.seek(VolumeConstants.VOLUME_HEADER_GROUP_SIZE + alignedOffset)
            raf.readFully(encryptedData)
        }
        
        // Decrypt
        val decrypted = xts.decrypt(encryptedData, startSector, 0)
        
        // Extract requested portion
        val startOffset = (offset - alignedOffset).toInt()
        return decrypted.copyOfRange(startOffset, startOffset + length)
    }
    
    /**
     * Write data to the volume (encrypted)
     * @param offset Offset within the data area (not including headers)
     * @param data Data to write
     */
    fun write(offset: Long, data: ByteArray) {
        requireOpened()
        
        val header = headerData!!
        val xts = xtsMode!!
        val sectorSize = header.sectorSize
        
        // For simplicity, this implementation requires sector-aligned writes
        // A full implementation would handle partial sector writes
        require(offset % sectorSize == 0L) {
            "Offset must be sector-aligned ($sectorSize bytes)"
        }
        require(data.size % sectorSize == 0) {
            "Data size must be multiple of sector size ($sectorSize bytes)"
        }
        
        // Calculate sector number
        val startSector = offset / sectorSize
        
        // Encrypt data
        val encrypted = xts.encrypt(data, startSector, 0)
        
        // Write to file
        RandomAccessFile(file, "rw").use { raf ->
            raf.seek(VolumeConstants.VOLUME_HEADER_GROUP_SIZE + offset)
            raf.write(encrypted)
        }
    }
    
    /**
     * Get volume information
     */
    fun getInfo(): VolumeInfo? {
        return headerData?.let {
            VolumeInfo(
                sizeBytes = it.volumeSize,
                encryptionAlgorithm = it.encryptionAlgorithm.algorithmName,
                hashAlgorithm = it.hashAlgorithm.algorithmName,
                sectorSize = it.sectorSize,
                creationTime = it.volumeCreationTime,
                isSystemEncrypted = it.isSystemEncrypted
            )
        }
    }
    
    /**
     * Close the volume and clear sensitive data
     */
    fun close() {
        masterKey?.fill(0)
        masterKey = null
        xtsMode = null
        headerData = null
    }
    
    private fun requireOpened() {
        require(headerData != null) {
            "Volume is not opened. Call open() first."
        }
    }
}

/**
 * Volume information
 */
data class VolumeInfo(
    val sizeBytes: Long,
    val encryptionAlgorithm: String,
    val hashAlgorithm: String,
    val sectorSize: Int,
    val creationTime: Long,
    val isSystemEncrypted: Boolean
)
