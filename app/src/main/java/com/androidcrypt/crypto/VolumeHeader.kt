package com.androidcrypt.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

/**
 * VeraCrypt Volume Header Constants
 * Based on VeraCrypt source: src/Common/Volumes.h
 */
object VolumeConstants {
    // Volume header magic identifier (VERA in ASCII)
    const val HEADER_MAGIC = 0x56455241
    
    // Header sizes
    const val VOLUME_HEADER_SIZE = 65536L  // 64KB
    const val VOLUME_HEADER_EFFECTIVE_SIZE = 512
    const val VOLUME_HEADER_GROUP_SIZE = VOLUME_HEADER_SIZE * 2
    
    // Header field offsets (in encrypted portion)
    const val HEADER_OFFSET_MAGIC = 64
    const val HEADER_OFFSET_VERSION = 68
    const val HEADER_OFFSET_REQUIRED_VERSION = 70
    const val HEADER_OFFSET_KEY_AREA_CRC = 72
    const val HEADER_OFFSET_VOLUME_CREATION_TIME = 76
    const val HEADER_OFFSET_MODIFICATION_TIME = 84
    const val HEADER_OFFSET_HIDDEN_VOLUME_SIZE = 92
    const val HEADER_OFFSET_VOLUME_SIZE = 100
    const val HEADER_OFFSET_ENCRYPTED_AREA_START = 108
    const val HEADER_OFFSET_ENCRYPTED_AREA_LENGTH = 116
    const val HEADER_OFFSET_FLAGS = 124
    const val HEADER_OFFSET_SECTOR_SIZE = 128
    const val HEADER_OFFSET_HEADER_CRC = 252
    
    // Salt
    const val SALT_OFFSET = 0
    const val SALT_SIZE = 64
    const val ENCRYPTED_DATA_OFFSET = SALT_SIZE
    const val ENCRYPTED_DATA_SIZE = VOLUME_HEADER_EFFECTIVE_SIZE - ENCRYPTED_DATA_OFFSET
    
    // Master key data
    const val MASTER_KEYDATA_OFFSET = 256
    const val MAX_PASSWORD_LENGTH = 64
    
    // Volume version
    const val VOLUME_HEADER_VERSION_NUM = 0x0005
    const val TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION = 0x010b
}

/**
 * Encryption algorithms supported
 */
enum class EncryptionAlgorithm(val keySize: Int, val blockSize: Int, val algorithmName: String) {
    AES(64, 16, "AES");           // XTS: 32 bytes encryption + 32 bytes tweak
    
    fun getDerivedKeySize(): Int = keySize
}

/**
 * Hash algorithms for PKCS#5 (PBKDF2) key derivation
 */
enum class HashAlgorithm(val algorithmName: String, val outputSize: Int) {
    SHA256("SHA-256", 32),
    SHA512("SHA-512", 64),
    WHIRLPOOL("Whirlpool", 64),
    BLAKE2S("Blake2s", 32),
    STREEBOG("Streebog", 64);
    
    fun getIterationCount(pim: Int, isSystemEncryption: Boolean = false): Int {
        return when (this) {
            SHA512 -> if (isSystemEncryption) {
                if (pim <= 0) 200000 else pim * 2048
            } else {
                if (pim <= 0) 500000 else 15000 + (pim * 1000)
            }
            SHA256 -> if (isSystemEncryption) {
                if (pim <= 0) 200000 else pim * 2048
            } else {
                if (pim <= 0) 500000 else 15000 + (pim * 1000)
            }
            WHIRLPOOL -> if (isSystemEncryption) {
                if (pim <= 0) 200000 else pim * 2048
            } else {
                if (pim <= 0) 500000 else 15000 + (pim * 1000)
            }
            BLAKE2S -> if (isSystemEncryption) {
                if (pim <= 0) 200000 else pim * 2048
            } else {
                if (pim <= 0) 500000 else 15000 + (pim * 1000)
            }
            STREEBOG -> if (isSystemEncryption) {
                if (pim <= 0) 200000 else pim * 2048
            } else {
                if (pim <= 0) 500000 else 15000 + (pim * 1000)
            }
        }
    }
}

/**
 * CRC32 implementation for header validation
 */
object Crc32 {
    private val table = IntArray(256)
    
    init {
        for (i in 0..255) {
            var crc = i
            for (j in 0..7) {
                if (crc and 1 != 0) {
                    crc = (crc ushr 1) xor 0xEDB88320.toInt()
                } else {
                    crc = crc ushr 1
                }
            }
            table[i] = crc
        }
    }
    
    fun calculate(data: ByteArray, offset: Int = 0, length: Int = data.size): Int {
        var crc = 0xFFFFFFFF.toInt()
        for (i in offset until offset + length) {
            val index = (crc xor data[i].toInt()) and 0xFF
            crc = (crc ushr 8) xor table[index]
        }
        return crc xor 0xFFFFFFFF.toInt()
    }
}

/**
 * XTS (XEX-based tweaked-codebook mode with ciphertext stealing) mode implementation
 * This is the encryption mode used by VeraCrypt
 * Optimized for performance with pre-allocated buffers and cached cipher instances
 */
class XTSMode(private val key: ByteArray, private val algorithm: EncryptionAlgorithm) {
    private val key1: ByteArray
    private val key2: ByteArray
    
    // Cached cipher instances for performance (single-threaded use)
    private val encryptCipher: Cipher
    private val decryptCipher: Cipher
    private val tweakCipher: Cipher
    
    // Pre-allocated buffers for block operations (16 bytes for AES)
    private val blockBuffer = ByteArray(16)
    private val tweakBuffer = ByteArray(16)
    
    // ThreadLocal cipher cache for parallel decryption (avoids creating ciphers per batch)
    // Also caches scratch buffers to avoid allocation per-call
    private data class ThreadCiphers(
        val decrypt: Cipher, 
        val tweak: Cipher,
        val sectorXored: ByteArray = ByteArray(512),  // Default sector size
        val tweakBytes: ByteArray = ByteArray(16),
        val tweaksLo: LongArray = LongArray(32),  // 512/16 blocks
        val tweaksHi: LongArray = LongArray(32)
    )
    private val threadCiphers = ThreadLocal<ThreadCiphers>()
    
    init {
        // Accept both AES-128 (32 bytes total) and AES-256 (64 bytes total)
        require(key.size == 32 || key.size == 64) {
            "Key size must be 32 bytes (AES-128) or 64 bytes (AES-256) for XTS mode, got ${key.size}"
        }
        
        // For XTS mode, the master key is split in half: first half for encryption, second half for tweak
        val halfKeySize = key.size / 2
        key1 = key.copyOfRange(0, halfKeySize)
        key2 = key.copyOfRange(halfKeySize, key.size)
        
        // Pre-create cipher instances
        val keySpec1 = SecretKeySpec(key1, "AES")
        val keySpec2 = SecretKeySpec(key2, "AES")
        
        encryptCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, keySpec1)
        }
        decryptCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, keySpec1)
        }
        tweakCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, keySpec2)
        }
    }
    
    /**
     * Encrypt data using XTS mode
     * @param data The data to encrypt (must be multiple of block size)
     * @param dataUnitNo The data unit number (sector number)
     * @param startOffset Offset within the data unit
     */
    @Synchronized
    fun encrypt(data: ByteArray, dataUnitNo: Long, startOffset: Long = 0): ByteArray {
        require(data.size % algorithm.blockSize == 0) {
            "Data size must be multiple of block size (${algorithm.blockSize})"
        }
        
        val result = ByteArray(data.size)
        val blockSize = algorithm.blockSize
        
        // Initialize tweak with data unit number
        java.util.Arrays.fill(tweakBuffer, 0.toByte())
        val tweakBuf = ByteBuffer.wrap(tweakBuffer).order(ByteOrder.LITTLE_ENDIAN)
        tweakBuf.putLong(dataUnitNo + (startOffset / blockSize))
        
        // Encrypt tweak with key2
        tweakCipher.doFinal(tweakBuffer, 0, blockSize, tweakBuffer, 0)
        
        // Encrypt each block
        var i = 0
        while (i < data.size) {
            // Copy block and XOR with tweak
            for (j in 0 until blockSize) {
                blockBuffer[j] = (data[i + j] xor tweakBuffer[j]).toByte()
            }
            
            // Encrypt in place
            encryptCipher.doFinal(blockBuffer, 0, blockSize, blockBuffer, 0)
            
            // XOR with tweak and store result
            for (j in 0 until blockSize) {
                result[i + j] = (blockBuffer[j] xor tweakBuffer[j]).toByte()
            }
            
            // Multiply tweak by alpha in GF(2^128)
            multiplyByAlpha(tweakBuffer)
            
            i += blockSize
        }
        
        return result
    }
    
    /**
     * Decrypt data using XTS mode
     */
    @Synchronized
    fun decrypt(data: ByteArray, dataUnitNo: Long, startOffset: Long = 0): ByteArray {
        require(data.size % algorithm.blockSize == 0) {
            "Data size must be multiple of block size (${algorithm.blockSize})"
        }
        
        val result = ByteArray(data.size)
        val blockSize = algorithm.blockSize
        
        // Initialize tweak with data unit number
        java.util.Arrays.fill(tweakBuffer, 0.toByte())
        val tweakBuf = ByteBuffer.wrap(tweakBuffer).order(ByteOrder.LITTLE_ENDIAN)
        tweakBuf.putLong(dataUnitNo + (startOffset / blockSize))
        
        // Encrypt tweak with key2 (always encrypt, even for decrypt)
        tweakCipher.doFinal(tweakBuffer, 0, blockSize, tweakBuffer, 0)
        
        // Decrypt each block
        var i = 0
        while (i < data.size) {
            // Copy block and XOR with tweak
            for (j in 0 until blockSize) {
                blockBuffer[j] = (data[i + j] xor tweakBuffer[j]).toByte()
            }
            
            // Decrypt in place
            decryptCipher.doFinal(blockBuffer, 0, blockSize, blockBuffer, 0)
            
            // XOR with tweak and store result
            for (j in 0 until blockSize) {
                result[i + j] = (blockBuffer[j] xor tweakBuffer[j]).toByte()
            }
            
            // Multiply tweak by alpha in GF(2^128)
            multiplyByAlpha(tweakBuffer)
            
            i += blockSize
        }
        
        return result
    }
    
    /**
     * Thread-safe decrypt for a single sector - uses ThreadLocal cached ciphers
     * Use this for parallel decryption of multiple sectors
     * NOTE: For batch operations, use decryptBatchThreadSafe instead for better performance
     */
    fun decryptSectorThreadSafe(data: ByteArray, dataUnitNo: Long): ByteArray {
        require(data.size % algorithm.blockSize == 0) {
            "Data size must be multiple of block size (${algorithm.blockSize})"
        }
        
        val result = ByteArray(data.size)
        val blockSize = algorithm.blockSize
        
        // Use cached cipher instances from ThreadLocal (avoid creating per-call)
        val ciphers = threadCiphers.get() ?: run {
            val keySpec1 = SecretKeySpec(key1, "AES")
            val keySpec2 = SecretKeySpec(key2, "AES")
            val decryptCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, keySpec1)
            }
            val tweakCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, keySpec2)
            }
            ThreadCiphers(
                decryptCipher, 
                tweakCipher,
                ByteArray(512),
                ByteArray(16),
                LongArray(32),
                LongArray(32)
            ).also { threadCiphers.set(it) }
        }
        val localDecryptCipher = ciphers.decrypt
        val localTweakCipher = ciphers.tweak
        val localTweakBuffer = ciphers.tweakBytes
        val localBlockBuffer = ByteArray(16) // Small, keep local
        
        // Initialize tweak with data unit number
        java.util.Arrays.fill(localTweakBuffer, 0.toByte())
        val tweakBuf = ByteBuffer.wrap(localTweakBuffer).order(ByteOrder.LITTLE_ENDIAN)
        tweakBuf.putLong(dataUnitNo)
        
        // Encrypt tweak with key2
        localTweakCipher.doFinal(localTweakBuffer, 0, blockSize, localTweakBuffer, 0)
        
        // Decrypt each block
        var i = 0
        while (i < data.size) {
            // Copy block and XOR with tweak
            for (j in 0 until blockSize) {
                localBlockBuffer[j] = (data[i + j] xor localTweakBuffer[j]).toByte()
            }
            
            // Decrypt in place
            localDecryptCipher.doFinal(localBlockBuffer, 0, blockSize, localBlockBuffer, 0)
            
            // XOR with tweak and store result
            for (j in 0 until blockSize) {
                result[i + j] = (localBlockBuffer[j] xor localTweakBuffer[j]).toByte()
            }
            
            // Multiply tweak by alpha in GF(2^128)
            multiplyByAlpha(localTweakBuffer)
            
            i += blockSize
        }
        
        return result
    }
    
    /**
     * Thread-safe encrypt for a single sector - creates its own buffers
     * Use this for parallel encryption of multiple sectors
     */
    fun encryptSectorThreadSafe(data: ByteArray, dataUnitNo: Long): ByteArray {
        require(data.size % algorithm.blockSize == 0) {
            "Data size must be multiple of block size (${algorithm.blockSize})"
        }
        
        val result = ByteArray(data.size)
        val blockSize = algorithm.blockSize
        
        // Create local buffers for thread safety
        val localTweakBuffer = ByteArray(16)
        val localBlockBuffer = ByteArray(16)
        
        // Create local cipher instances for thread safety
        val keySpec1 = SecretKeySpec(key1, "AES")
        val keySpec2 = SecretKeySpec(key2, "AES")
        val localEncryptCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, keySpec1)
        }
        val localTweakCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, keySpec2)
        }
        
        // Initialize tweak with data unit number
        val tweakBuf = ByteBuffer.wrap(localTweakBuffer).order(ByteOrder.LITTLE_ENDIAN)
        tweakBuf.putLong(dataUnitNo)
        
        // Encrypt tweak with key2
        localTweakCipher.doFinal(localTweakBuffer, 0, blockSize, localTweakBuffer, 0)
        
        // Encrypt each block
        var i = 0
        while (i < data.size) {
            // Copy block and XOR with tweak
            for (j in 0 until blockSize) {
                localBlockBuffer[j] = (data[i + j] xor localTweakBuffer[j]).toByte()
            }
            
            // Encrypt in place
            localEncryptCipher.doFinal(localBlockBuffer, 0, blockSize, localBlockBuffer, 0)
            
            // XOR with tweak and store result
            for (j in 0 until blockSize) {
                result[i + j] = (localBlockBuffer[j] xor localTweakBuffer[j]).toByte()
            }
            
            // Multiply tweak by alpha in GF(2^128)
            multiplyByAlpha(localTweakBuffer)
            
            i += blockSize
        }
        
        return result
    }
    
    /**
     * Thread-safe batch decrypt for multiple consecutive sectors
     * Optimized: creates cipher instances once, bulk XOR operations, minimal allocations
     * 
     * @param encryptedData All encrypted sector data concatenated
     * @param startSectorNo The sector number of the first sector
     * @param sectorSize Size of each sector (typically 512)
     * @param decryptedData Output array to write decrypted data
     * @param startOffset Offset in encryptedData/decryptedData to start from
     * @param sectorCount Number of sectors to decrypt
     */
    fun decryptBatchThreadSafe(
        encryptedData: ByteArray,
        startSectorNo: Long,
        sectorSize: Int,
        decryptedData: ByteArray,
        startOffset: Int,
        sectorCount: Int
    ) {
        val blockSize = 16
        val blocksPerSector = sectorSize / blockSize
        
        // Use cached cipher instances and buffers from ThreadLocal (avoid creating per-call)
        val ciphers = threadCiphers.get() ?: run {
            val keySpec1 = SecretKeySpec(key1, "AES")
            val keySpec2 = SecretKeySpec(key2, "AES")
            val decryptCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, keySpec1)
            }
            val tweakCipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, keySpec2)
            }
            ThreadCiphers(
                decryptCipher, 
                tweakCipher,
                ByteArray(sectorSize),
                ByteArray(16),
                LongArray(blocksPerSector),
                LongArray(blocksPerSector)
            ).also { threadCiphers.set(it) }
        }
        val decryptCipher = ciphers.decrypt
        val tweakCipher = ciphers.tweak
        val sectorXored = ciphers.sectorXored
        val tweakBytes = ciphers.tweakBytes
        val tweaksLo = ciphers.tweaksLo
        val tweaksHi = ciphers.tweaksHi
        
        val tweakBuf = ByteBuffer.wrap(tweakBytes).order(ByteOrder.LITTLE_ENDIAN)
        
        // Process each sector
        for (s in 0 until sectorCount) {
            val sectorOffset = startOffset + (s * sectorSize)
            val sectorNo = startSectorNo + s
            
            // Initialize first tweak with sector number and encrypt
            java.util.Arrays.fill(tweakBytes, 0.toByte())
            tweakBuf.clear()
            tweakBuf.putLong(sectorNo)
            tweakCipher.doFinal(tweakBytes, 0, 16, tweakBytes, 0)
            
            // Pre-compute ALL tweaks for this sector
            tweakBuf.clear()
            var tLo = tweakBuf.long
            var tHi = tweakBuf.long
            
            for (b in 0 until blocksPerSector) {
                tweaksLo[b] = tLo
                tweaksHi[b] = tHi
                
                // Multiply by alpha for next tweak
                val carry = if (tHi < 0) 135L else 0L
                tHi = (tHi shl 1) or (tLo ushr 63)
                tLo = (tLo shl 1) xor carry
            }
            
            // XOR entire sector with tweaks (fast 64-bit operations)
            for (b in 0 until blocksPerSector) {
                val blockOff = b * 16
                val dataOff = sectorOffset + blockOff
                
                // Read input as longs
                val dLo = readLongLE(encryptedData, dataOff)
                val dHi = readLongLE(encryptedData, dataOff + 8)
                
                // XOR with tweak and store in buffer
                writeLongLE(sectorXored, blockOff, dLo xor tweaksLo[b])
                writeLongLE(sectorXored, blockOff + 8, dHi xor tweaksHi[b])
            }
            
            // Decrypt entire sector in ONE cipher call (bulk AES)
            decryptCipher.doFinal(sectorXored, 0, sectorSize, sectorXored, 0)
            
            // XOR decrypted data with tweaks and write to output
            for (b in 0 until blocksPerSector) {
                val blockOff = b * 16
                val dataOff = sectorOffset + blockOff
                
                val dLo = readLongLE(sectorXored, blockOff) xor tweaksLo[b]
                val dHi = readLongLE(sectorXored, blockOff + 8) xor tweaksHi[b]
                
                writeLongLE(decryptedData, dataOff, dLo)
                writeLongLE(decryptedData, dataOff + 8, dHi)
            }
        }
    }
    
    // Fast little-endian Long read (inline for performance)
    private fun readLongLE(data: ByteArray, off: Int): Long {
        return (data[off].toLong() and 0xFF) or
               ((data[off + 1].toLong() and 0xFF) shl 8) or
               ((data[off + 2].toLong() and 0xFF) shl 16) or
               ((data[off + 3].toLong() and 0xFF) shl 24) or
               ((data[off + 4].toLong() and 0xFF) shl 32) or
               ((data[off + 5].toLong() and 0xFF) shl 40) or
               ((data[off + 6].toLong() and 0xFF) shl 48) or
               ((data[off + 7].toLong() and 0xFF) shl 56)
    }
    
    // Fast little-endian Long write (inline for performance)
    private fun writeLongLE(data: ByteArray, off: Int, value: Long) {
        data[off] = value.toByte()
        data[off + 1] = (value shr 8).toByte()
        data[off + 2] = (value shr 16).toByte()
        data[off + 3] = (value shr 24).toByte()
        data[off + 4] = (value shr 32).toByte()
        data[off + 5] = (value shr 40).toByte()
        data[off + 6] = (value shr 48).toByte()
        data[off + 7] = (value shr 56).toByte()
    }
    
    /**
     * Multiply by alpha (x) in GF(2^128) for XTS mode
     */
    private fun multiplyByAlpha(block: ByteArray) {
        // Read as two 64-bit little-endian integers
        var low = (block[0].toLong() and 0xFF) or
                  ((block[1].toLong() and 0xFF) shl 8) or
                  ((block[2].toLong() and 0xFF) shl 16) or
                  ((block[3].toLong() and 0xFF) shl 24) or
                  ((block[4].toLong() and 0xFF) shl 32) or
                  ((block[5].toLong() and 0xFF) shl 40) or
                  ((block[6].toLong() and 0xFF) shl 48) or
                  ((block[7].toLong() and 0xFF) shl 56)
        
        var high = (block[8].toLong() and 0xFF) or
                   ((block[9].toLong() and 0xFF) shl 8) or
                   ((block[10].toLong() and 0xFF) shl 16) or
                   ((block[11].toLong() and 0xFF) shl 24) or
                   ((block[12].toLong() and 0xFF) shl 32) or
                   ((block[13].toLong() and 0xFF) shl 40) or
                   ((block[14].toLong() and 0xFF) shl 48) or
                   ((block[15].toLong() and 0xFF) shl 56)
        
        // Check bit 127 for carry
        val finalCarry = if (high < 0) 135L else 0L
        
        // Shift high left, propagate bit 63 of low
        high = (high shl 1) or (low ushr 63)
        
        // Shift low left and XOR with carry
        low = (low shl 1) xor finalCarry
        
        // Write back as little-endian
        block[0] = low.toByte()
        block[1] = (low shr 8).toByte()
        block[2] = (low shr 16).toByte()
        block[3] = (low shr 24).toByte()
        block[4] = (low shr 32).toByte()
        block[5] = (low shr 40).toByte()
        block[6] = (low shr 48).toByte()
        block[7] = (low shr 56).toByte()
        block[8] = high.toByte()
        block[9] = (high shr 8).toByte()
        block[10] = (high shr 16).toByte()
        block[11] = (high shr 24).toByte()
        block[12] = (high shr 32).toByte()
        block[13] = (high shr 40).toByte()
        block[14] = (high shr 48).toByte()
        block[15] = (high shr 56).toByte()
    }
}
