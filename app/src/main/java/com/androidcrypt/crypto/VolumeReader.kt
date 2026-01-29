package com.androidcrypt.crypto

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.util.concurrent.Executors
import java.util.concurrent.Future
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Reads and mounts VeraCrypt-compatible encrypted containers
 * Supports both file paths and content URIs for Android compatibility
 */
class VolumeReader(
    private val containerPath: String,
    private val context: Context? = null,
    private val containerUri: Uri? = null
) {
    
    private var volumeFile: RandomAccessFile? = null
    private var parcelFd: ParcelFileDescriptor? = null
    private var masterKey: ByteArray? = null
    private var encryptionAlgorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES
    private var xtsMode: XTSMode? = null  // Cached XTS instance for performance
    private var volumeSize: Long = 0
    private var dataAreaOffset: Long = 0
    private var dataAreaSize: Long = 0
    
    // Lock for I/O operations only - decryption happens outside this lock
    private val ioLock = java.util.concurrent.locks.ReentrantLock()
    
    // Thread-local timing for accurate per-operation measurements
    private val threadLocalTiming = ThreadLocal<LongArray>()
    
    private fun getTiming(): LongArray {
        return threadLocalTiming.get() ?: LongArray(3).also { threadLocalTiming.set(it) }
    }
    
    fun resetTiming() {
        val t = getTiming()
        t[0] = 0 // I/O time
        t[1] = 0 // Decrypt time  
        t[2] = 0 // I/O call count
    }
    
    fun logTiming(tag: String) {
        val t = getTiming()
        Log.d("VolumeReader", "$tag: I/O=${t[0]}ms (${t[2].toInt()} calls), Decrypt=${t[1]}ms")
        resetTiming()
    }
    
    var volumeInfo: MountedVolumeInfo? = null
        private set
    
    // Thread pool for parallel encryption (use available processors)
    private val encryptionExecutor = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors().coerceIn(2, 8)
    )

    companion object {
        private const val TAG = "VolumeReader"
        private const val SECTOR_SIZE = 512
        private const val HEADER_SIZE = 448  // Encrypted portion size (512 - 64 salt)
        private const val SALT_SIZE = 64
        // Number of sectors to process in parallel (64KB chunks = 128 sectors)
        private const val PARALLEL_SECTOR_BATCH = 128
        // Set to false to disable debug logging for better performance
        private const val DEBUG_LOGGING = false
    }
    
    /**
     * Open and mount a container with the given password and optional keyfiles
     * 
     * @param password User password (can be empty if using keyfiles)
     * @param pim Personal Iterations Multiplier (0 for default)
     * @param keyfileUris List of keyfile URIs (optional)
     */
    fun mount(
        password: String,
        pim: Int = 0,
        keyfileUris: List<Uri> = emptyList()
    ): Result<MountedVolumeInfo> {
        return try {
            // Handle content URI or file path
            if (containerUri != null && context != null) {
                mountFromUri(password, pim, keyfileUris)
            } else {
                mountFromPath(password, pim, keyfileUris)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error mounting container", e)
            unmount()
            Result.failure(e)
        }
    }
    
    private fun mountFromUri(password: String, pim: Int, keyfileUris: List<Uri>): Result<MountedVolumeInfo> {
        val ctx = context ?: return Result.failure(Exception("Context is null"))
        val uri = containerUri ?: return Result.failure(Exception("URI is null"))
        
        // Get file descriptor from content resolver - keep it open for read/write operations
        parcelFd = ctx.contentResolver.openFileDescriptor(uri, "rw")
            ?: return Result.failure(Exception("Cannot open file descriptor"))
        
        // Get file size
        volumeSize = parcelFd!!.statSize
        
        if (DEBUG_LOGGING) Log.d(TAG, "Opening container URI: $uri, size: $volumeSize bytes")
        
        // Read header using ParcelFileDescriptor
        val headerBytes = ByteArray(SALT_SIZE + HEADER_SIZE)
        val fd = parcelFd!!.fileDescriptor
        val fis = FileInputStream(fd)
        val channel = fis.channel
        channel.position(0)
        val buffer = ByteBuffer.wrap(headerBytes)
        var read = 0
        while (read < headerBytes.size) {
            val r = channel.read(buffer)
            if (r < 0) break
            read += r
        }
        
        // Continue with common mount logic
        return finishMount(headerBytes, password, pim, keyfileUris, ctx)
    }
    
    private fun mountFromPath(password: String, pim: Int, keyfileUris: List<Uri>): Result<MountedVolumeInfo> {
        val file = File(containerPath)
        if (!file.exists()) {
            return Result.failure(Exception("Container file does not exist"))
        }
        
        volumeFile = RandomAccessFile(file, "rw")
        volumeSize = file.length()
        
        if (DEBUG_LOGGING) Log.d(TAG, "Opening container: $containerPath, size: $volumeSize bytes")
        
        // Read the header (salt + encrypted header = 64 + 448 = 512 bytes total)
        val fullHeader = ByteArray(SALT_SIZE + HEADER_SIZE)
        volumeFile?.seek(0)
        volumeFile?.readFully(fullHeader)
        
        return finishMount(fullHeader, password, pim, keyfileUris, context)
    }
    
    private fun finishMount(
        fullHeader: ByteArray, 
        password: String, 
        pim: Int,
        keyfileUris: List<Uri>,
        ctx: Context?
    ): Result<MountedVolumeInfo> {
        // Extract salt (first 64 bytes)
        val salt = fullHeader.copyOfRange(0, SALT_SIZE)
            
        // Extract encrypted header (next 448 bytes)
        val encryptedHeaderData = fullHeader.copyOfRange(SALT_SIZE, SALT_SIZE + HEADER_SIZE)
        
        // Apply keyfiles to password if any
        val passwordBytes: ByteArray = if (keyfileUris.isNotEmpty() && ctx != null) {
            if (DEBUG_LOGGING) Log.d(TAG, "Applying ${keyfileUris.size} keyfile(s)...")
            val result = KeyfileProcessor.applyKeyfilesFromUris(password, keyfileUris, ctx)
            if (result.isFailure) {
                return Result.failure(result.exceptionOrNull() ?: Exception("Failed to process keyfiles"))
            }
            result.getOrThrow()
        } else {
            password.toByteArray(Charsets.UTF_8)
        }
        
        if (DEBUG_LOGGING) Log.d(TAG, "Deriving key from password...")
        
        // Derive key from password using our custom PBKDF2 (supports byte arrays)
        val iterations = if (pim > 0) {
            15000 + (pim * 1000)
        } else {
            500000  // Default for normal volumes
        }
        
        // Use custom PBKDF2 that accepts byte arrays (required for keyfile support)
        val derivedKey = PBKDF2.deriveKey(
            password = passwordBytes,
            salt = salt,
            iterations = iterations,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 64  // 64 bytes for AES-256 in XTS mode
        )
        
        // Try to decrypt and validate header
        val decryptedHeader = decryptHeader(encryptedHeaderData, derivedKey)
        
        // Validate magic bytes
        if (decryptedHeader[0] != 'V'.code.toByte() ||
            decryptedHeader[1] != 'E'.code.toByte() ||
            decryptedHeader[2] != 'R'.code.toByte() ||
            decryptedHeader[3] != 'A'.code.toByte()) {
            Log.e(TAG, "Header validation failed - magic bytes mismatch")
            return Result.failure(Exception("Invalid password or corrupted header"))
        }
        
        if (DEBUG_LOGGING) Log.d(TAG, "Header decrypted successfully")
        
        // Extract volume information
        dataAreaOffset = readLong(decryptedHeader, 44)
        dataAreaSize = readLong(decryptedHeader, 52)
        val sectorSize = readInt(decryptedHeader, 64)
        
        // Extract master key from decrypted header
        masterKey = decryptedHeader.copyOfRange(192, 192 + 64)
        
        // Cache XTS mode instance and algorithm for performance
        encryptionAlgorithm = EncryptionAlgorithm.AES
        xtsMode = XTSMode(masterKey!!, encryptionAlgorithm)
        
        if (DEBUG_LOGGING) Log.d(TAG, "Volume info - Data offset: $dataAreaOffset, size: $dataAreaSize, sector: $sectorSize")
        
        volumeInfo = MountedVolumeInfo(
            path = containerUri?.toString() ?: containerPath,
            totalSize = volumeSize,
            dataAreaOffset = dataAreaOffset,
            dataAreaSize = dataAreaSize,
            sectorSize = sectorSize,
            isMounted = true
        )
        
        return Result.success(volumeInfo!!)
    }
    
    /**
     * Decrypt volume header
     */
    private fun decryptHeader(encryptedHeaderData: ByteArray, derivedKey: ByteArray): ByteArray {
        // Decrypt using XTS-AES mode with the full 64-byte derived key
        // Header is treated as sector 0
        val xts = XTSMode(derivedKey, EncryptionAlgorithm.AES)
        val decryptedHeader = xts.decrypt(encryptedHeaderData, 0)
        
        return decryptedHeader
    }
    
    /**
     * Read a sector from the encrypted volume
     * Uses ioLock only for file I/O, decryption happens outside the lock
     */
    fun readSector(sectorNumber: Long): Result<ByteArray> {
        return try {
            if (masterKey == null) {
                Log.e(TAG, "Cannot read sector: masterKey is null, volume not properly mounted")
                return Result.failure(Exception("Volume not mounted"))
            }
            
            if (volumeFile == null && parcelFd == null) {
                Log.e(TAG, "Cannot read sector: no file handle available")
                return Result.failure(Exception("Volume file not open"))
            }
            
            val sectorOffset = dataAreaOffset + (sectorNumber * SECTOR_SIZE)
            if (sectorOffset + SECTOR_SIZE > volumeSize) {
                return Result.failure(Exception("Sector out of bounds"))
            }
            
            // Read encrypted sector - lock only during I/O
            val encryptedSector = ByteArray(SECTOR_SIZE)
            
            ioLock.lock()
            try {
                if (volumeFile != null) {
                    // File path mode
                    volumeFile?.seek(sectorOffset)
                    volumeFile?.readFully(encryptedSector)
                } else if (parcelFd != null) {
                    // URI mode using ParcelFileDescriptor
                    // Use Os.pread for atomic positioned read (no seek needed)
                    val fd = parcelFd!!.fileDescriptor
                    var read = 0
                    while (read < SECTOR_SIZE) {
                        val r = Os.pread(fd, encryptedSector, read, SECTOR_SIZE - read, sectorOffset + read)
                        if (r <= 0) break
                        read += r
                    }
                }
            } finally {
                ioLock.unlock()
            }
            
            // Decrypt using XTS mode OUTSIDE the lock (thread-safe version)
            // XTS sector number is absolute from start of volume, not relative to data area
            val xtsSectorNumber = (dataAreaOffset / SECTOR_SIZE) + sectorNumber
            val decryptedSector = xtsMode!!.decryptSectorThreadSafe(encryptedSector, xtsSectorNumber)
            
            Result.success(decryptedSector)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error reading sector $sectorNumber", e)
            Result.failure(e)
        }
    }
    
    /**
     * Read multiple sectors efficiently (single I/O and parallel decryption)
     * Uses ioLock only for file I/O, decryption happens outside the lock
     */
    fun readSectors(startSector: Long, count: Int): Result<ByteArray> {
        return try {
            if (masterKey == null || xtsMode == null) {
                return Result.failure(Exception("Volume not mounted"))
            }
            
            if (volumeFile == null && parcelFd == null) {
                return Result.failure(Exception("Volume file not open"))
            }
            
            val totalBytes = count * SECTOR_SIZE
            val startOffset = dataAreaOffset + (startSector * SECTOR_SIZE)
            
            if (startOffset + totalBytes > volumeSize) {
                return Result.failure(Exception("Read would exceed volume bounds"))
            }
            
            // Read all encrypted data in one I/O operation - lock only for I/O
            val encryptedData = ByteArray(totalBytes)
            
            val ioStart = System.currentTimeMillis()
            ioLock.lock()
            try {
                if (volumeFile != null) {
                    volumeFile?.seek(startOffset)
                    volumeFile?.readFully(encryptedData)
                } else if (parcelFd != null) {
                    val fd = parcelFd!!.fileDescriptor
                    var read = 0
                    while (read < totalBytes) {
                        val r = Os.pread(fd, encryptedData, read, totalBytes - read, startOffset + read)
                        if (r <= 0) break
                        read += r
                    }
                }
            } finally {
                ioLock.unlock()
            }
            val t = getTiming()
            t[0] += System.currentTimeMillis() - ioStart
            t[2]++
            
            // Decrypt all sectors OUTSIDE the lock - use parallel batch decryption
            val decryptedData = ByteArray(totalBytes)
            val baseTweakSector = (dataAreaOffset / SECTOR_SIZE) + startSector
            
            val decryptStart = System.currentTimeMillis()
            if (count >= 16) {
                // Parallel batch decryption using thread pool (no thread creation overhead)
                val numThreads = minOf(Runtime.getRuntime().availableProcessors(), 8)
                val sectorsPerThread = count / numThreads
                val latch = java.util.concurrent.CountDownLatch(numThreads)
                
                for (th in 0 until numThreads) {
                    val startIdx = th * sectorsPerThread
                    val sectorCountForThread = if (th == numThreads - 1) count - startIdx else sectorsPerThread
                    
                    encryptionExecutor.execute {
                        try {
                            xtsMode!!.decryptBatchThreadSafe(
                                encryptedData,
                                baseTweakSector + startIdx,
                                SECTOR_SIZE,
                                decryptedData,
                                startIdx * SECTOR_SIZE,
                                sectorCountForThread
                            )
                        } finally {
                            latch.countDown()
                        }
                    }
                }
                
                // Wait for all tasks to complete
                latch.await()
            } else {
                // Sequential decryption for small reads - use batch for efficiency
                xtsMode!!.decryptBatchThreadSafe(
                    encryptedData,
                    baseTweakSector,
                    SECTOR_SIZE,
                    decryptedData,
                    0,
                    count
                )
            }
            t[1] += System.currentTimeMillis() - decryptStart
            
            Result.success(decryptedData)
        } catch (e: Exception) {
            Log.e(TAG, "Error reading sectors starting at $startSector", e)
            Result.failure(e)
        }
    }
    
    /**
     * Write a sector to the encrypted volume
     * Uses ioLock only for file I/O, encryption happens outside the lock
     */
    fun writeSector(sectorNumber: Long, data: ByteArray): Result<Unit> {
        return try {
            if (masterKey == null) {
                return Result.failure(Exception("Volume not mounted"))
            }
            
            if (volumeFile == null && parcelFd == null) {
                return Result.failure(Exception("Volume file not open"))
            }
            
            if (data.size != SECTOR_SIZE) {
                return Result.failure(Exception("Data must be exactly $SECTOR_SIZE bytes"))
            }
            
            val sectorOffset = dataAreaOffset + (sectorNumber * SECTOR_SIZE)
            if (sectorOffset + SECTOR_SIZE > volumeSize) {
                return Result.failure(Exception("Sector out of bounds"))
            }
            
            // Encrypt using XTS mode OUTSIDE the lock (thread-safe version)
            // XTS sector number is absolute from start of volume, not relative to data area
            val xtsSectorNumber = (dataAreaOffset / SECTOR_SIZE) + sectorNumber
            val encryptedSector = xtsMode!!.encryptSectorThreadSafe(data, xtsSectorNumber)
            
            // Write encrypted sector - lock only for I/O
            ioLock.lock()
            try {
                if (volumeFile != null) {
                    // File path mode
                    volumeFile?.seek(sectorOffset)
                    volumeFile?.write(encryptedSector)
                } else if (parcelFd != null) {
                    // URI mode using ParcelFileDescriptor
                    // Use Os.pwrite for atomic positioned write (no seek needed)
                    val fd = parcelFd!!.fileDescriptor
                    var written = 0
                    while (written < SECTOR_SIZE) {
                        val w = Os.pwrite(fd, encryptedSector, written, SECTOR_SIZE - written, sectorOffset + written)
                        if (w <= 0) break
                        written += w
                    }
                }
            } finally {
                ioLock.unlock()
            }
            
            Result.success(Unit)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error writing sector $sectorNumber", e)
            Result.failure(e)
        }
    }
    
    /**
     * Write multiple sectors efficiently with parallel encryption
     * Uses ioLock only for file I/O, encryption happens outside the lock
     */
    fun writeSectors(startSector: Long, data: ByteArray): Result<Unit> {
        return try {
            if (data.size % SECTOR_SIZE != 0) {
                return Result.failure(Exception("Data size must be a multiple of $SECTOR_SIZE"))
            }
            
            if (masterKey == null || xtsMode == null) {
                return Result.failure(Exception("Volume not mounted"))
            }
            
            if (volumeFile == null && parcelFd == null) {
                return Result.failure(Exception("Volume file not open"))
            }
            
            val sectorCount = data.size / SECTOR_SIZE
            val startOffset = dataAreaOffset + (startSector * SECTOR_SIZE)
            
            if (startOffset + data.size > volumeSize) {
                return Result.failure(Exception("Write would exceed volume bounds"))
            }
            
            // Encrypt all sectors OUTSIDE the lock
            val encryptedData = ByteArray(data.size)
            val baseTweakSector = (dataAreaOffset / SECTOR_SIZE) + startSector
            
            // Use parallel encryption for writes (more than 8 sectors = 4KB)
            if (sectorCount > 8) {
                val numThreads = Runtime.getRuntime().availableProcessors().coerceIn(2, 8)
                val sectorsPerThread = (sectorCount + numThreads - 1) / numThreads
                
                val futures = mutableListOf<Future<*>>()
                
                for (threadIdx in 0 until numThreads) {
                    val startIdx = threadIdx * sectorsPerThread
                    val endIdx = minOf(startIdx + sectorsPerThread, sectorCount)
                    
                    if (startIdx >= sectorCount) break
                    
                    val future = encryptionExecutor.submit {
                        for (i in startIdx until endIdx) {
                            val sectorData = ByteArray(SECTOR_SIZE)
                            System.arraycopy(data, i * SECTOR_SIZE, sectorData, 0, SECTOR_SIZE)
                            // Use thread-safe method
                            val encryptedSector = xtsMode!!.encryptSectorThreadSafe(sectorData, baseTweakSector + i)
                            System.arraycopy(encryptedSector, 0, encryptedData, i * SECTOR_SIZE, SECTOR_SIZE)
                        }
                    }
                    futures.add(future)
                }
                
                // Wait for all encryption threads to complete
                futures.forEach { it.get() }
            } else {
                // Sequential encryption for small writes (thread-safe method still ok)
                for (i in 0 until sectorCount) {
                    val sectorData = ByteArray(SECTOR_SIZE)
                    System.arraycopy(data, i * SECTOR_SIZE, sectorData, 0, SECTOR_SIZE)
                    val encryptedSector = xtsMode!!.encrypt(sectorData, baseTweakSector + i)
                    System.arraycopy(encryptedSector, 0, encryptedData, i * SECTOR_SIZE, SECTOR_SIZE)
                }
            }
            
            // Write all encrypted data in one I/O operation - lock only for I/O
            ioLock.lock()
            try {
                if (volumeFile != null) {
                    volumeFile?.seek(startOffset)
                    volumeFile?.write(encryptedData)
                } else if (parcelFd != null) {
                    val fd = parcelFd!!.fileDescriptor
                    var written = 0
                    while (written < encryptedData.size) {
                        val w = Os.pwrite(fd, encryptedData, written, encryptedData.size - written, startOffset + written)
                        if (w <= 0) break
                        written += w
                    }
                }
            } finally {
                ioLock.unlock()
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Error writing sectors starting at $startSector", e)
            Result.failure(e)
        }
    }
    
    /**
     * Write data at a specific offset
     */
    fun writeData(offset: Long, data: ByteArray): Result<Unit> {
        return try {
            val startSector = offset / SECTOR_SIZE
            val endSector = (offset + data.size - 1) / SECTOR_SIZE
            val sectorCount = (endSector - startSector + 1).toInt()
            
            // Read existing sectors
            val sectorsResult = readSectors(startSector, sectorCount)
            if (sectorsResult.isFailure) {
                return Result.failure(sectorsResult.exceptionOrNull()!!)
            }
            
            val sectors = sectorsResult.getOrThrow()
            val startOffset = (offset % SECTOR_SIZE).toInt()
            
            // Update sectors with new data
            System.arraycopy(data, 0, sectors, startOffset, data.size)
            
            // Write back modified sectors
            writeSectors(startSector, sectors)
            
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Read data at a specific offset
     */
    fun readData(offset: Long, length: Int): Result<ByteArray> {
        return try {
            val startSector = offset / SECTOR_SIZE
            val endSector = (offset + length - 1) / SECTOR_SIZE
            val sectorCount = (endSector - startSector + 1).toInt()
            
            val sectorsResult = readSectors(startSector, sectorCount)
            if (sectorsResult.isFailure) {
                return sectorsResult
            }
            
            val sectors = sectorsResult.getOrThrow()
            val startOffset = (offset % SECTOR_SIZE).toInt()
            
            Result.success(sectors.copyOfRange(startOffset, startOffset + length))
            
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Unmount and close the volume
     */
    fun unmount() {
        try {
            volumeFile?.close()
            volumeFile = null
            parcelFd?.close()
            parcelFd = null
            masterKey = null
            xtsMode = null  // Clear cached XTS instance
            volumeInfo = null
            // Note: Don't shutdown executor as it may be reused
            Log.d(TAG, "Volume unmounted")
        } catch (e: Exception) {
            Log.e(TAG, "Error unmounting volume", e)
        }
    }
    
    private fun readLong(buffer: ByteArray, offset: Int): Long {
        // Read as BIG-ENDIAN (VeraCrypt header format)
        return ((buffer[offset].toLong() and 0xFF) shl 56) or
                ((buffer[offset + 1].toLong() and 0xFF) shl 48) or
                ((buffer[offset + 2].toLong() and 0xFF) shl 40) or
                ((buffer[offset + 3].toLong() and 0xFF) shl 32) or
                ((buffer[offset + 4].toLong() and 0xFF) shl 24) or
                ((buffer[offset + 5].toLong() and 0xFF) shl 16) or
                ((buffer[offset + 6].toLong() and 0xFF) shl 8) or
                (buffer[offset + 7].toLong() and 0xFF)
    }
    
    private fun readInt(buffer: ByteArray, offset: Int): Int {
        // Read as BIG-ENDIAN (VeraCrypt header format)
        return ((buffer[offset].toInt() and 0xFF) shl 24) or
                ((buffer[offset + 1].toInt() and 0xFF) shl 16) or
                ((buffer[offset + 2].toInt() and 0xFF) shl 8) or
                (buffer[offset + 3].toInt() and 0xFF)
    }
}

/**
 * Information about a mounted volume
 */
data class MountedVolumeInfo(
    val path: String,
    val totalSize: Long,
    val dataAreaOffset: Long,
    val dataAreaSize: Long,
    val sectorSize: Int,
    val isMounted: Boolean
) {
    fun getDataAreaSizeMB(): Long = dataAreaSize / (1024 * 1024)
}
