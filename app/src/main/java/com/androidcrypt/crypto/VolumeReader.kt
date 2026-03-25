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
    
    // ReadWriteLock for I/O operations — reads use readLock (pread is thread-safe
    // for concurrent reads at different offsets), writes use writeLock (exclusive).
    // This allows multiple files / thumbnails to read concurrently.
    private val ioRwLock = java.util.concurrent.locks.ReentrantReadWriteLock()
    private val ioReadLock = ioRwLock.readLock()
    private val ioWriteLock = ioRwLock.writeLock()
    
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
        if (DEBUG_LOGGING) {
            val t = getTiming()
            Log.d("VolumeReader", "$tag: I/O=${t[0]}ms (${t[2].toInt()} calls), Decrypt=${t[1]}ms")
        }
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
     * @param useHiddenVolume If true, try hidden header offset first (user knows they have a hidden volume)
     * @param hiddenVolumeProtectionPassword If non-null, mount the outer volume but also decrypt
     *   the hidden volume header to determine its boundaries and protect those sectors from writes.
     */
    fun mount(
        password: CharArray,
        pim: Int = 0,
        keyfileUris: List<Uri> = emptyList(),
        useHiddenVolume: Boolean = false,
        hiddenVolumeProtectionPassword: CharArray? = null
    ): Result<MountedVolumeInfo> {
        return try {
            // Handle content URI or file path
            if (containerUri != null && context != null) {
                mountFromUri(password, pim, keyfileUris, useHiddenVolume, hiddenVolumeProtectionPassword)
            } else {
                mountFromPath(password, pim, keyfileUris, useHiddenVolume, hiddenVolumeProtectionPassword)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error mounting container", e)
            unmount()
            Result.failure(e)
        } finally {
            password.fill('\u0000')  // Always zero password CharArrays
            hiddenVolumeProtectionPassword?.fill('\u0000')
        }
    }
    
    private fun mountFromUri(password: CharArray, pim: Int, keyfileUris: List<Uri>,
                              useHiddenVolume: Boolean, hiddenVolumeProtectionPassword: CharArray?): Result<MountedVolumeInfo> {
        val ctx = context ?: return Result.failure(Exception("Context is null"))
        val uri = containerUri ?: return Result.failure(Exception("URI is null"))
        
        // Get file descriptor from content resolver - keep it open for read/write operations
        parcelFd = ctx.contentResolver.openFileDescriptor(uri, "rw")
            ?: return Result.failure(Exception("Cannot open file descriptor"))
        
        // Get file size
        volumeSize = parcelFd!!.statSize
        
        if (DEBUG_LOGGING) Log.d(TAG, "Opening container URI: $uri, size: $volumeSize bytes")
        
        // Read both normal header AND hidden header area (first 128KB covers both)
        val headerReadSize = (VolumeConstants.VOLUME_HEADER_GROUP_SIZE).toInt().coerceAtMost(volumeSize.toInt())
        val headerBytes = ByteArray(headerReadSize)
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
        return finishMount(headerBytes, password, pim, keyfileUris, ctx, useHiddenVolume, hiddenVolumeProtectionPassword)
    }
    
    private fun mountFromPath(password: CharArray, pim: Int, keyfileUris: List<Uri>,
                               useHiddenVolume: Boolean, hiddenVolumeProtectionPassword: CharArray?): Result<MountedVolumeInfo> {
        val file = File(containerPath)
        if (!file.exists()) {
            return Result.failure(Exception("Container file does not exist"))
        }
        
        volumeFile = RandomAccessFile(file, "rw")
        volumeSize = file.length()
        
        if (DEBUG_LOGGING) Log.d(TAG, "Opening container: $containerPath, size: $volumeSize bytes")
        
        // Read enough for both normal header (offset 0) and hidden header (offset 64KB)
        val headerReadSize = (VolumeConstants.VOLUME_HEADER_GROUP_SIZE).toInt().coerceAtMost(volumeSize.toInt())
        val fullHeader = ByteArray(headerReadSize)
        volumeFile?.seek(0)
        volumeFile?.readFully(fullHeader)
        
        return finishMount(fullHeader, password, pim, keyfileUris, context, useHiddenVolume, hiddenVolumeProtectionPassword)
    }
    
    private fun finishMount(
        fullHeader: ByteArray, 
        password: CharArray, 
        pim: Int,
        keyfileUris: List<Uri>,
        ctx: Context?,
        useHiddenVolume: Boolean = false,
        hiddenVolumeProtectionPassword: CharArray? = null
    ): Result<MountedVolumeInfo> {
        // Apply keyfiles to password if any
        val passwordBytes: ByteArray = if (keyfileUris.isNotEmpty() && ctx != null) {
            if (DEBUG_LOGGING) Log.d(TAG, "Applying ${keyfileUris.size} keyfile(s)...")
            val result = KeyfileProcessor.applyKeyfilesFromUris(password, keyfileUris, ctx)
            if (result.isFailure) {
                return Result.failure(result.exceptionOrNull() ?: Exception("Failed to process keyfiles"))
            }
            result.getOrThrow()
        } else {
            charArrayToUtf8Bytes(password)
        }
        
        if (DEBUG_LOGGING) Log.d(TAG, "Deriving key from password...")
        
        // Derive key from password using our custom PBKDF2 (supports byte arrays)
        val iterations = if (pim > 0) {
            15000 + (pim * 1000)
        } else {
            500000  // Default for normal volumes
        }
        
        // Derive max key length needed across all algorithms
        val maxDkLen = EncryptionAlgorithm.entries.maxOf { it.keySize }
        val derivedKey = PBKDF2.deriveKey(
            password = passwordBytes,
            salt = fullHeader.copyOfRange(0, SALT_SIZE),  // Normal header salt at offset 0
            iterations = iterations,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = maxDkLen
        )
        
        // VeraCrypt hidden volume layout (from src/Common/Volumes.h):
        //   Normal header:   offset 0
        //   Hidden header:   offset TC_VOLUME_HEADER_SIZE (65536 = 64KB)
        //   Data area:       offset TC_VOLUME_HEADER_GROUP_SIZE (128KB)
        //   Backup hidden header: offset (end - TC_HIDDEN_VOLUME_HEADER_OFFSET) = end - 64KB
        //   Backup normal header: offset (end - TC_VOLUME_HEADER_GROUP_SIZE) = end - 128KB
        //
        // When a password is supplied, VeraCrypt tries BOTH header positions.
        // If the normal header decrypts -> normal volume.
        // If the hidden header decrypts -> hidden volume.
        // An adversary cannot tell which header (if any) the password unlocks.
        
        // Build list of (headerOffset, isHidden) to try
        // VeraCrypt tries hidden header at offset 64KB within the volume file
        val headerPositions = if (useHiddenVolume) {
            // User explicitly wants hidden volume — try hidden first, then normal
            listOf(
                Pair(VolumeConstants.HIDDEN_VOLUME_HEADER_OFFSET.toInt(), true),
                Pair(0, false)
            )
        } else {
            // Normal mode — try normal first, then hidden (password
            // might unlock either one; VeraCrypt always tries both)
            listOf(
                Pair(0, false),
                Pair(VolumeConstants.HIDDEN_VOLUME_HEADER_OFFSET.toInt(), true)
            )
        }
        
        var decryptedHeader: ByteArray? = null
        var matchedAlgorithm: EncryptionAlgorithm? = null
        var isHiddenVolume = false
        
        for ((headerOffset, hidden) in headerPositions) {
            // Ensure we have enough data for this header position
            if (headerOffset + SALT_SIZE + HEADER_SIZE > fullHeader.size) continue
            
            // Extract salt and encrypted data at this offset
            val salt = fullHeader.copyOfRange(headerOffset, headerOffset + SALT_SIZE)
            val encryptedHeaderData = fullHeader.copyOfRange(
                headerOffset + SALT_SIZE, 
                headerOffset + SALT_SIZE + HEADER_SIZE
            )
            
            // Derive key with this salt
            val dk = PBKDF2.deriveKey(
                password = passwordBytes,
                salt = salt,
                iterations = iterations,
                hashAlgorithm = HashAlgorithm.SHA512,
                dkLen = maxDkLen
            )
            
            // Try each algorithm
            for (algo in EncryptionAlgorithm.entries) {
                val algoKey = dk.copyOfRange(0, algo.keySize)
                val candidate = decryptHeader(encryptedHeaderData, algoKey, algo)
                if (candidate[0] == 'V'.code.toByte() &&
                    candidate[1] == 'E'.code.toByte() &&
                    candidate[2] == 'R'.code.toByte() &&
                    candidate[3] == 'A'.code.toByte()) {
                    decryptedHeader = candidate
                    matchedAlgorithm = algo
                    isHiddenVolume = hidden
                    algoKey.fill(0)
                    break
                }
                algoKey.fill(0)  // Zero failed attempt key
            }
            dk.fill(0)  // Zero derived key after trying all algorithms
            if (decryptedHeader != null) break
        }
        
        // Zero password bytes — no longer needed
        passwordBytes.fill(0)
        derivedKey.fill(0)
        
        if (decryptedHeader == null || matchedAlgorithm == null) {
            Log.e(TAG, "Header validation failed - no algorithm produced valid magic bytes")
            return Result.failure(Exception("Invalid password or corrupted header"))
        }
        
        if (DEBUG_LOGGING) Log.d(TAG, "Header decrypted successfully with ${matchedAlgorithm.algorithmName}" +
                if (isHiddenVolume) " (hidden volume)" else " (normal volume)")
        
        // Extract volume information from decrypted header
        dataAreaOffset = readLong(decryptedHeader, 44)  // EncryptedAreaStart
        dataAreaSize = readLong(decryptedHeader, 52)     // EncryptedAreaLength
        val sectorSize = readInt(decryptedHeader, 64)
        val hiddenVolumeSize = readLong(decryptedHeader, 28)  // HiddenVolumeSize field
        
        // Extract master key from decrypted header
        masterKey = decryptedHeader.copyOfRange(192, 192 + matchedAlgorithm.keySize)
        
        // Zero decrypted header — master key has been extracted
        decryptedHeader.fill(0)
        
        // Cache XTS mode instance and algorithm for performance
        encryptionAlgorithm = matchedAlgorithm
        xtsMode = XTSMode(masterKey!!, encryptionAlgorithm)
        
        if (DEBUG_LOGGING) Log.d(TAG, "Volume info - Data offset: $dataAreaOffset, size: $dataAreaSize, " +
                "sector: $sectorSize, hidden: $isHiddenVolume, hiddenSize: $hiddenVolumeSize")
        
        // Hidden volume protection: when mounting the outer volume, also decrypt the
        // hidden header to discover the hidden volume's data area boundaries.
        // Then writeSectors/writeSector can refuse writes that would overwrite hidden data.
        var outerVolumeProtectedSize = 0L
        if (!isHiddenVolume && hiddenVolumeProtectionPassword != null) {
            outerVolumeProtectedSize = resolveHiddenVolumeProtection(
                fullHeader, hiddenVolumeProtectionPassword, pim, ctx
            )
            if (outerVolumeProtectedSize > 0) {
                if (DEBUG_LOGGING) Log.d(TAG, "Hidden volume protection enabled")
            }
        }
        
        volumeInfo = MountedVolumeInfo(
            path = containerUri?.toString() ?: containerPath,
            totalSize = volumeSize,
            dataAreaOffset = dataAreaOffset,
            dataAreaSize = dataAreaSize,
            sectorSize = sectorSize,
            isMounted = true,
            isHiddenVolume = isHiddenVolume,
            hiddenVolumeSize = hiddenVolumeSize,
            outerVolumeProtectedSize = outerVolumeProtectedSize
        )
        
        return Result.success(volumeInfo!!)
    }
    
    /**
     * Resolve hidden volume protection by attempting to decrypt the hidden header
     * with the given password. Returns the size of the protected area (hidden data area),
     * or 0 if the hidden header couldn't be decrypted.
     */
    private fun resolveHiddenVolumeProtection(
        fullHeader: ByteArray,
        hiddenPassword: CharArray,
        pim: Int,
        ctx: Context?
    ): Long {
        val hiddenHeaderOffset = VolumeConstants.HIDDEN_VOLUME_HEADER_OFFSET.toInt()
        if (hiddenHeaderOffset + SALT_SIZE + HEADER_SIZE > fullHeader.size) return 0
        
        val salt = fullHeader.copyOfRange(hiddenHeaderOffset, hiddenHeaderOffset + SALT_SIZE)
        val encryptedData = fullHeader.copyOfRange(
            hiddenHeaderOffset + SALT_SIZE,
            hiddenHeaderOffset + SALT_SIZE + HEADER_SIZE
        )
        
        val iterations = if (pim > 0) 15000 + (pim * 1000) else 500000
        val maxDkLen = EncryptionAlgorithm.entries.maxOf { it.keySize }
        val passwordBytes = charArrayToUtf8Bytes(hiddenPassword)
        
        val dk = PBKDF2.deriveKey(
            password = passwordBytes,
            salt = salt,
            iterations = iterations,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = maxDkLen
        )
        
        try {
            for (algo in EncryptionAlgorithm.entries) {
                val algoKey = dk.copyOfRange(0, algo.keySize)
                val candidate = decryptHeader(encryptedData, algoKey, algo)
                if (candidate[0] == 'V'.code.toByte() &&
                    candidate[1] == 'E'.code.toByte() &&
                    candidate[2] == 'R'.code.toByte() &&
                    candidate[3] == 'A'.code.toByte()) {
                    // Successfully decrypted hidden header — extract its data area size
                    val protectedSize = readLong(candidate, 52)  // EncryptedAreaLength of hidden volume
                    candidate.fill(0)
                    algoKey.fill(0)
                    return protectedSize
                }
                algoKey.fill(0)
            }
            return 0
        } finally {
            // Always zero sensitive material
            passwordBytes.fill(0)
            dk.fill(0)
        }
    }
    
    /**
     * Decrypt volume header
     */
    private fun decryptHeader(encryptedHeaderData: ByteArray, derivedKey: ByteArray, algorithm: EncryptionAlgorithm): ByteArray {
        // Decrypt using XTS mode with the full 64-byte derived key
        // Header is treated as sector 0
        val xts = XTSMode(derivedKey, algorithm)
        val decryptedHeader = xts.decrypt(encryptedHeaderData, 0)
        xts.close()
        
        return decryptedHeader
    }
    
    /**
     * Read a sector from the encrypted volume.
     * Delegates to readSectors for consistent I/O and decryption path.
     */
    fun readSector(sectorNumber: Long): Result<ByteArray> {
        return readSectors(sectorNumber, 1)
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
            
            // Single buffer: read encrypted data in, decrypt in-place.
            // decryptBatchThreadSafe copies each sector to a scratch buffer before
            // writing output, so using the same array for input and output is safe.
            val data = ByteArray(totalBytes)
            
            val ioStart = System.currentTimeMillis()
            ioReadLock.lock()
            try {
                if (volumeFile != null) {
                    // Positional read via FileChannel — thread-safe, no seek needed
                    val channel = volumeFile!!.channel
                    val buf = ByteBuffer.wrap(data)
                    var read = 0
                    while (read < totalBytes) {
                        val r = channel.read(buf, startOffset + read)
                        if (r <= 0) break
                        read += r
                    }
                } else if (parcelFd != null) {
                    val fd = parcelFd!!.fileDescriptor
                    var read = 0
                    while (read < totalBytes) {
                        val r = Os.pread(fd, data, read, totalBytes - read, startOffset + read)
                        if (r <= 0) break
                        read += r
                    }
                }
            } finally {
                ioReadLock.unlock()
            }
            val t = getTiming()
            t[0] += System.currentTimeMillis() - ioStart
            t[2]++
            
            // Decrypt in-place OUTSIDE the lock - use parallel batch decryption
            val baseTweakSector = (dataAreaOffset / SECTOR_SIZE) + startSector
            
            val decryptStart = System.currentTimeMillis()
            if (count >= 32) {
                // Parallel batch decryption using thread pool (no thread creation overhead)
                // Threshold of 32 sectors (16KB) avoids overhead of CountDownLatch + thread dispatch
                // for small reads where sequential is faster
                val numThreads = minOf(Runtime.getRuntime().availableProcessors(), 8, count)
                val sectorsPerThread = count / numThreads
                val latch = java.util.concurrent.CountDownLatch(numThreads)
                
                for (th in 0 until numThreads) {
                    val startIdx = th * sectorsPerThread
                    val sectorCountForThread = if (th == numThreads - 1) count - startIdx else sectorsPerThread
                    
                    encryptionExecutor.execute {
                        try {
                            xtsMode!!.decryptBatchThreadSafe(
                                data,
                                baseTweakSector + startIdx,
                                SECTOR_SIZE,
                                data,
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
                // Sequential decryption for small reads (1-31 sectors) — avoids thread pool overhead
                xtsMode!!.decryptBatchThreadSafe(
                    data,
                    baseTweakSector,
                    SECTOR_SIZE,
                    data,
                    0,
                    count
                )
            }
            t[1] += System.currentTimeMillis() - decryptStart
            
            Result.success(data)
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
            
            // Hidden volume protection: refuse writes into the protected area
            val protectedSize = volumeInfo?.outerVolumeProtectedSize ?: 0
            if (protectedSize > 0) {
                val protectedStart = dataAreaSize - protectedSize
                val writeEnd = (sectorNumber + 1) * SECTOR_SIZE
                if (writeEnd > protectedStart) {
                    return Result.failure(Exception(
                        "Write blocked: would damage hidden volume (sector $sectorNumber overlaps protected area)"
                    ))
                }
            }
            
            // Encrypt using XTS mode OUTSIDE the lock (thread-safe version)
            // XTS sector number is absolute from start of volume, not relative to data area
            val xtsSectorNumber = (dataAreaOffset / SECTOR_SIZE) + sectorNumber
            val encryptedSector = xtsMode!!.encryptSectorThreadSafe(data, xtsSectorNumber)
            
            // Write encrypted sector - writeLock for exclusive I/O
            ioWriteLock.lock()
            try {
                if (volumeFile != null) {
                    // Positional write via FileChannel — thread-safe
                    val channel = volumeFile!!.channel
                    val buf = ByteBuffer.wrap(encryptedSector)
                    var written = 0
                    while (written < SECTOR_SIZE) {
                        val w = channel.write(buf, sectorOffset + written)
                        if (w <= 0) break
                        written += w
                    }
                } else if (parcelFd != null) {
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
                ioWriteLock.unlock()
            }
            
            Result.success(Unit)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error writing sector $sectorNumber", e)
            Result.failure(e)
        }
    }
    
    /**
     * Write multiple sectors efficiently with parallel encryption.
     * Encrypts in-place using a scratch buffer inside encryptBatchThreadSafe,
     * avoiding a full data.copyOf() allocation. The caller's array IS modified
     * (overwritten with ciphertext). Callers that need to preserve the original
     * data must make their own copy before calling this method.
     * Uses ioLock only for file I/O, encryption happens outside the lock.
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
            
            // Hidden volume protection: refuse writes into the protected area
            val protectedSize = volumeInfo?.outerVolumeProtectedSize ?: 0
            if (protectedSize > 0) {
                val protectedStart = dataAreaSize - protectedSize
                val writeEnd = (startSector + sectorCount) * SECTOR_SIZE
                if (writeEnd > protectedStart) {
                    return Result.failure(Exception(
                        "Write blocked: would damage hidden volume (sectors $startSector-${startSector + sectorCount - 1} overlap protected area)"
                    ))
                }
            }
            
            // Copy input so the caller's buffer is not modified (metadata writes
            // are small — a few KB at most — and callers like batchWriteFATSectors
            // reuse the same buffer for FAT1 and FAT2 writes).
            // Large file-data writes already use writeSectorsInPlace() which
            // encrypts the caller's buffer directly with zero extra allocation.
            val encryptedData = data.copyOf()
            val baseTweakSector = (dataAreaOffset / SECTOR_SIZE) + startSector
            
            // Use parallel batch encryption for writes (32+ sectors)
            // encryptBatchThreadSafe processes sectors in bulk — one cipher call per sector,
            // no per-sector ByteArray allocation, uses ThreadLocal cached ciphers
            if (sectorCount >= 32) {
                val numThreads = Runtime.getRuntime().availableProcessors().coerceIn(2, 8).coerceAtMost(sectorCount)
                val sectorsPerThread = sectorCount / numThreads
                val latch = java.util.concurrent.CountDownLatch(numThreads)
                
                for (threadIdx in 0 until numThreads) {
                    val startIdx = threadIdx * sectorsPerThread
                    val sectorCountForThread = if (threadIdx == numThreads - 1) sectorCount - startIdx else sectorsPerThread
                    
                    encryptionExecutor.execute {
                        try {
                            xtsMode!!.encryptBatchThreadSafe(
                                encryptedData,
                                baseTweakSector + startIdx,
                                SECTOR_SIZE,
                                encryptedData,
                                startIdx * SECTOR_SIZE,
                                sectorCountForThread
                            )
                        } finally {
                            latch.countDown()
                        }
                    }
                }
                
                // Wait for all encryption threads to complete
                latch.await()
            } else {
                // Sequential batch encryption for small writes (1-31 sectors)
                xtsMode!!.encryptBatchThreadSafe(
                    encryptedData,
                    baseTweakSector,
                    SECTOR_SIZE,
                    encryptedData,
                    0,
                    sectorCount
                )
            }
            
            // Write all encrypted data in one I/O operation - writeLock for exclusive I/O
            ioWriteLock.lock()
            try {
                if (volumeFile != null) {
                    // Positional write via FileChannel — thread-safe
                    val channel = volumeFile!!.channel
                    val buf = ByteBuffer.wrap(encryptedData)
                    var written = 0
                    while (written < encryptedData.size) {
                        val w = channel.write(buf, startOffset + written)
                        if (w <= 0) break
                        written += w
                    }
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
                ioWriteLock.unlock()
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Error writing sectors starting at $startSector", e)
            Result.failure(e)
        }
    }
    
    /**
     * Write sectors from a sub-range of a byte array, encrypting IN-PLACE.
     * This avoids allocating a separate encryption output buffer (saves ~256KB–1MB per call).
     * WARNING: The data in data[dataOffset..dataOffset+dataLength] is DESTROYED
     * (overwritten with ciphertext). The caller must not need this data afterward.
     *
     * encryptBatchThreadSafe reads each sector into a scratch buffer before writing
     * output, so using the same array for input and output is safe — even with
     * parallel threads, each thread operates on non-overlapping sector ranges.
     */
    fun writeSectorsInPlace(startSector: Long, data: ByteArray, dataOffset: Int, dataLength: Int): Result<Unit> {
        return try {
            if (dataLength % SECTOR_SIZE != 0) {
                return Result.failure(Exception("Data length must be a multiple of $SECTOR_SIZE"))
            }
            
            if (masterKey == null || xtsMode == null) {
                return Result.failure(Exception("Volume not mounted"))
            }
            
            if (volumeFile == null && parcelFd == null) {
                return Result.failure(Exception("Volume file not open"))
            }
            
            val sectorCount = dataLength / SECTOR_SIZE
            val volumeOffset = dataAreaOffset + (startSector * SECTOR_SIZE)
            
            if (volumeOffset + dataLength > volumeSize) {
                return Result.failure(Exception("Write would exceed volume bounds"))
            }
            
            // Hidden volume protection: refuse writes into the protected area
            val protectedSize = volumeInfo?.outerVolumeProtectedSize ?: 0
            if (protectedSize > 0) {
                val protectedStart = dataAreaSize - protectedSize
                val writeEnd = (startSector + sectorCount) * SECTOR_SIZE
                if (writeEnd > protectedStart) {
                    return Result.failure(Exception(
                        "Write blocked: would damage hidden volume (sectors $startSector-${startSector + sectorCount - 1} overlap protected area)"
                    ))
                }
            }
            
            // Encrypt in-place — data serves as both input and output
            val baseTweakSector = (dataAreaOffset / SECTOR_SIZE) + startSector
            
            if (sectorCount >= 32) {
                val numThreads = minOf(Runtime.getRuntime().availableProcessors().coerceIn(2, 8), sectorCount)
                val sectorsPerThread = sectorCount / numThreads
                val latch = java.util.concurrent.CountDownLatch(numThreads)
                
                for (threadIdx in 0 until numThreads) {
                    val startIdx = threadIdx * sectorsPerThread
                    val threadSectors = if (threadIdx == numThreads - 1) sectorCount - startIdx else sectorsPerThread
                    
                    encryptionExecutor.execute {
                        try {
                            xtsMode!!.encryptBatchThreadSafe(
                                data,
                                baseTweakSector + startIdx,
                                SECTOR_SIZE,
                                data,
                                dataOffset + startIdx * SECTOR_SIZE,
                                threadSectors
                            )
                        } finally {
                            latch.countDown()
                        }
                    }
                }
                
                latch.await()
            } else {
                xtsMode!!.encryptBatchThreadSafe(
                    data,
                    baseTweakSector,
                    SECTOR_SIZE,
                    data,
                    dataOffset,
                    sectorCount
                )
            }
            
            // Write the encrypted range
            ioWriteLock.lock()
            try {
                if (volumeFile != null) {
                    val channel = volumeFile!!.channel
                    val buf = ByteBuffer.wrap(data, dataOffset, dataLength)
                    var written = 0
                    while (written < dataLength) {
                        val w = channel.write(buf, volumeOffset + written)
                        if (w <= 0) break
                        written += w
                    }
                } else if (parcelFd != null) {
                    val fd = parcelFd!!.fileDescriptor
                    var written = 0
                    while (written < dataLength) {
                        val w = Os.pwrite(fd, data, dataOffset + written, dataLength - written, volumeOffset + written)
                        if (w <= 0) break
                        written += w
                    }
                }
            } finally {
                ioWriteLock.unlock()
            }
            
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Error writing sectors in-place starting at $startSector", e)
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
            masterKey?.fill(0)  // Securely zero master key before releasing
            masterKey = null
            xtsMode?.close()  // Release native XTS context (zeros key schedules)
            xtsMode = null
            volumeInfo = null
            // Shutdown executor to release threads that may hold references to key material
            encryptionExecutor.shutdownNow()
            Log.d(TAG, "Volume unmounted")
        } catch (e: Exception) {
            Log.e(TAG, "Error unmounting volume", e)
        }
    }
    
    /**
     * Flush buffered writes to the underlying storage device.
     * Uses fdatasync to flush data without metadata (faster than fsync).
     */
    fun sync() {
        try {
            val fd = parcelFd?.fileDescriptor ?: return
            Os.fdatasync(fd)
        } catch (e: Exception) {
            Log.w(TAG, "fdatasync failed", e)
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
    val isMounted: Boolean,
    val isHiddenVolume: Boolean = false,
    val hiddenVolumeSize: Long = 0,
    val outerVolumeProtectedSize: Long = 0  // when mounting outer with hidden-vol protection
) {
    fun getDataAreaSizeMB(): Long = dataAreaSize / (1024 * 1024)
    
    /** Override to prevent auto-generated toString() from leaking path and offsets */
    override fun toString(): String =
        "MountedVolumeInfo(mounted=$isMounted, sizeMB=${getDataAreaSizeMB()})"
}
