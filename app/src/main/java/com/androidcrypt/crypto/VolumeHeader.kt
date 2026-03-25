package com.androidcrypt.crypto

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
    
    // Hidden volume constants (from VeraCrypt src/Common/Volumes.h)
    // The hidden volume header is stored at offset 64KB (= VOLUME_HEADER_SIZE) within
    // the outer volume.  Its backup header sits at (end - 64KB).
    // The hidden volume data area occupies the tail of the outer volume's data area,
    // right before the backup header group.
    const val HIDDEN_VOLUME_HEADER_OFFSET = VOLUME_HEADER_SIZE  // 65536
    const val TOTAL_VOLUME_HEADERS_SIZE = 4 * VOLUME_HEADER_SIZE  // 256KB for all 4 headers
    
    // Small-volume threshold (2 MB) – hidden volumes in containers below this
    // size use a smaller reserved end-area so they can still fit.
    const val VOLUME_SMALL_SIZE_THRESHOLD = 2L * 1024 * 1024
    
    // Reserved area at the end of the outer FS that the hidden volume must not
    // overwrite.  FAT fills the last sector with 0x00 on quick-format;
    // reserving this space avoids false hidden-volume-protection triggers.
    const val HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE = 4096L           // for small volumes
    const val HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH = VOLUME_HEADER_GROUP_SIZE  // 128KB for large volumes
    
    // Minimum sizes
    const val MIN_FAT_FS_SIZE = 9L * 4096   // 9 × max-sector
    const val MIN_HIDDEN_VOLUME_SIZE = MIN_FAT_FS_SIZE + HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE
}

/**
 * Encryption algorithms supported
 */
enum class EncryptionAlgorithm(val keySize: Int, val blockSize: Int, val algorithmName: String) {
    AES(64, 16, "AES"),                              // XTS: 32 bytes encryption + 32 bytes tweak
    SERPENT(64, 16, "Serpent"),                       // XTS: 32 bytes encryption + 32 bytes tweak
    TWOFISH(64, 16, "Twofish"),                       // XTS: 32 bytes encryption + 32 bytes tweak
    AES_TWOFISH_SERPENT(192, 16, "AES-Twofish-Serpent"), // Cascade: 3×32 primary + 3×32 secondary
    SERPENT_TWOFISH_AES(192, 16, "Serpent-Twofish-AES"); // Cascade: 3×32 primary + 3×32 secondary
    
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
    private var nativeHandle: Long = 0L

    init {
        require(key.size == algorithm.keySize) {
            "Invalid key size for XTS mode"
        }
        val halfKeySize = key.size / 2
        key1 = key.copyOfRange(0, halfKeySize)
        key2 = key.copyOfRange(halfKeySize, key.size)
        nativeHandle = when (algorithm) {
            EncryptionAlgorithm.AES -> NativeXTS.createContext(key1, key2)
            EncryptionAlgorithm.SERPENT -> NativeSerpentXTS.createContext(key1, key2)
            EncryptionAlgorithm.TWOFISH -> NativeTwofishXTS.createContext(key1, key2)
            EncryptionAlgorithm.AES_TWOFISH_SERPENT -> NativeCascadeXTS.createContext(key1, key2)
            EncryptionAlgorithm.SERPENT_TWOFISH_AES -> NativeCascadeSTA_XTS.createContext(key1, key2)
        }
    }

    /** Release the native XTS context and zero JVM-side key material. Safe to call multiple times. */
    fun close() {
        // Zero JVM-side key copies first
        key1.fill(0)
        key2.fill(0)
        val h = nativeHandle
        if (h != 0L) {
            nativeHandle = 0L
            when (algorithm) {
                EncryptionAlgorithm.AES -> NativeXTS.destroyContext(h)
                EncryptionAlgorithm.SERPENT -> NativeSerpentXTS.destroyContext(h)
                EncryptionAlgorithm.TWOFISH -> NativeTwofishXTS.destroyContext(h)
                EncryptionAlgorithm.AES_TWOFISH_SERPENT -> NativeCascadeXTS.destroyContext(h)
                EncryptionAlgorithm.SERPENT_TWOFISH_AES -> NativeCascadeSTA_XTS.destroyContext(h)
            }
        }
    }
    
    /**
     * Encrypt data using XTS mode
     * @param data The data to encrypt (must be multiple of block size)
     * @param dataUnitNo The data unit number (sector number)
     * @param startOffset Offset within the data unit
     */
    fun encrypt(data: ByteArray, dataUnitNo: Long, startOffset: Long = 0): ByteArray {
        require(data.size % algorithm.blockSize == 0) {
            "Data size must be aligned to block size"
        }
        val result = data.copyOf()
        val tweakSector = dataUnitNo + (startOffset / algorithm.blockSize)
        when (algorithm) {
            EncryptionAlgorithm.AES ->
                NativeXTS.encryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
            EncryptionAlgorithm.SERPENT ->
                NativeSerpentXTS.encryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
            EncryptionAlgorithm.TWOFISH ->
                NativeTwofishXTS.encryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
            EncryptionAlgorithm.AES_TWOFISH_SERPENT ->
                NativeCascadeXTS.encryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
            EncryptionAlgorithm.SERPENT_TWOFISH_AES ->
                NativeCascadeSTA_XTS.encryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
        }
        return result
    }
    
    /**
     * Decrypt data using XTS mode
     */
    fun decrypt(data: ByteArray, dataUnitNo: Long, startOffset: Long = 0): ByteArray {
        require(data.size % algorithm.blockSize == 0) {
            "Data size must be aligned to block size"
        }
        val result = data.copyOf()
        val tweakSector = dataUnitNo + (startOffset / algorithm.blockSize)
        when (algorithm) {
            EncryptionAlgorithm.AES ->
                NativeXTS.decryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
            EncryptionAlgorithm.SERPENT ->
                NativeSerpentXTS.decryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
            EncryptionAlgorithm.TWOFISH ->
                NativeTwofishXTS.decryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
            EncryptionAlgorithm.AES_TWOFISH_SERPENT ->
                NativeCascadeXTS.decryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
            EncryptionAlgorithm.SERPENT_TWOFISH_AES ->
                NativeCascadeSTA_XTS.decryptSectors(nativeHandle, result, 0, tweakSector, data.size, 1)
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
            "Data size must be aligned to block size"
        }
        val result = data.copyOf()
        when (algorithm) {
            EncryptionAlgorithm.AES ->
                NativeXTS.decryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
            EncryptionAlgorithm.SERPENT ->
                NativeSerpentXTS.decryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
            EncryptionAlgorithm.TWOFISH ->
                NativeTwofishXTS.decryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
            EncryptionAlgorithm.AES_TWOFISH_SERPENT ->
                NativeCascadeXTS.decryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
            EncryptionAlgorithm.SERPENT_TWOFISH_AES ->
                NativeCascadeSTA_XTS.decryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
        }
        return result
    }
    
    /**
     * Thread-safe encrypt for a single sector.
     * Use this for parallel encryption of multiple sectors.
     */
    fun encryptSectorThreadSafe(data: ByteArray, dataUnitNo: Long): ByteArray {
        require(data.size % algorithm.blockSize == 0) {
            "Data size must be aligned to block size"
        }
        val result = data.copyOf()
        when (algorithm) {
            EncryptionAlgorithm.AES ->
                NativeXTS.encryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
            EncryptionAlgorithm.SERPENT ->
                NativeSerpentXTS.encryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
            EncryptionAlgorithm.TWOFISH ->
                NativeTwofishXTS.encryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
            EncryptionAlgorithm.AES_TWOFISH_SERPENT ->
                NativeCascadeXTS.encryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
            EncryptionAlgorithm.SERPENT_TWOFISH_AES ->
                NativeCascadeSTA_XTS.encryptSectors(nativeHandle, result, 0, dataUnitNo, data.size, 1)
        }
        return result
    }
    
    /**
     * Thread-safe batch encrypt for multiple consecutive sectors
     * Optimized: creates cipher instances once, bulk XOR operations, minimal allocations
     * Mirrors decryptBatchThreadSafe for write operations.
     */
    fun encryptBatchThreadSafe(
        plainData: ByteArray,
        startSectorNo: Long,
        sectorSize: Int,
        encryptedData: ByteArray,
        startOffset: Int,
        sectorCount: Int
    ) {
        if (plainData !== encryptedData) {
            System.arraycopy(plainData, startOffset, encryptedData, startOffset, sectorCount * sectorSize)
        }
        when (algorithm) {
            EncryptionAlgorithm.AES ->
                NativeXTS.encryptSectors(nativeHandle, encryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
            EncryptionAlgorithm.SERPENT ->
                NativeSerpentXTS.encryptSectors(nativeHandle, encryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
            EncryptionAlgorithm.TWOFISH ->
                NativeTwofishXTS.encryptSectors(nativeHandle, encryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
            EncryptionAlgorithm.AES_TWOFISH_SERPENT ->
                NativeCascadeXTS.encryptSectors(nativeHandle, encryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
            EncryptionAlgorithm.SERPENT_TWOFISH_AES ->
                NativeCascadeSTA_XTS.encryptSectors(nativeHandle, encryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
        }
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
        if (encryptedData !== decryptedData) {
            System.arraycopy(encryptedData, startOffset, decryptedData, startOffset, sectorCount * sectorSize)
        }
        when (algorithm) {
            EncryptionAlgorithm.AES ->
                NativeXTS.decryptSectors(nativeHandle, decryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
            EncryptionAlgorithm.SERPENT ->
                NativeSerpentXTS.decryptSectors(nativeHandle, decryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
            EncryptionAlgorithm.TWOFISH ->
                NativeTwofishXTS.decryptSectors(nativeHandle, decryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
            EncryptionAlgorithm.AES_TWOFISH_SERPENT ->
                NativeCascadeXTS.decryptSectors(nativeHandle, decryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
            EncryptionAlgorithm.SERPENT_TWOFISH_AES ->
                NativeCascadeSTA_XTS.decryptSectors(nativeHandle, decryptedData, startOffset, startSectorNo, sectorSize, sectorCount)
        }
    }
}
