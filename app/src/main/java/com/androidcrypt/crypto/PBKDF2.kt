package com.androidcrypt.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * PKCS#5 PBKDF2 key derivation implementation
 * Based on VeraCrypt's Pkcs5Kdf classes
 */
object PBKDF2 {
    
    /**
     * Derive encryption key from password using PBKDF2-HMAC
     * 
     * @param password The password bytes
     * @param salt The salt (64 bytes for VeraCrypt)
     * @param iterations Number of PBKDF2 iterations
     * @param hashAlgorithm The hash algorithm to use
     * @param dkLen Desired derived key length in bytes
     * @return The derived key
     */
    fun deriveKey(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        hashAlgorithm: HashAlgorithm,
        dkLen: Int
    ): ByteArray {
        val hmacAlgorithm = "Hmac${hashAlgorithm.algorithmName.replace("-", "")}"
        val mac = Mac.getInstance(hmacAlgorithm)
        val keySpec = SecretKeySpec(password, hmacAlgorithm)
        mac.init(keySpec)
        
        val hLen = hashAlgorithm.outputSize
        val l = (dkLen + hLen - 1) / hLen
        val r = dkLen - (l - 1) * hLen
        
        val derivedKey = ByteArray(dkLen)
        var offset = 0
        
        for (i in 1..l) {
            val block = deriveBlock(mac, salt, iterations, i)
            val blockSize = if (i == l && r != 0) r else hLen
            System.arraycopy(block, 0, derivedKey, offset, blockSize)
            offset += blockSize
        }
        
        return derivedKey
    }
    
    private fun deriveBlock(mac: Mac, salt: ByteArray, iterations: Int, blockIndex: Int): ByteArray {
        mac.reset()
        
        // First iteration: HMAC(password, salt || INT(i))
        mac.update(salt)
        mac.update(ByteBuffer.allocate(4).putInt(blockIndex).array())
        var u = mac.doFinal()
        val result = u.copyOf()
        
        // Remaining iterations
        for (i in 2..iterations) {
            mac.reset()
            u = mac.doFinal(u)
            for (j in result.indices) {
                result[j] = (result[j].toInt() xor u[j].toInt()).toByte()
            }
        }
        
        return result
    }
}

/**
 * VeraCrypt Volume Header parser and creator
 */
class VolumeHeaderParser {
    
    /**
     * Parse and decrypt a VeraCrypt volume header
     * 
     * @param headerData The encrypted header data (512 bytes)
     * @param password The password string
     * @param pim Personal Iterations Multiplier (0 for default)
     * @return Parsed header data or null if decryption failed
     */
    fun parseHeader(
        headerData: ByteArray,
        password: String,
        pim: Int = 0
    ): VolumeHeaderData? {
        require(headerData.size >= VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE) {
            "Header data must be at least ${VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE} bytes"
        }
        
        // Extract salt
        val salt = headerData.copyOfRange(
            VolumeConstants.SALT_OFFSET,
            VolumeConstants.SALT_OFFSET + VolumeConstants.SALT_SIZE
        )
        
        // Extract encrypted portion
        val encryptedData = headerData.copyOfRange(
            VolumeConstants.ENCRYPTED_DATA_OFFSET,
            VolumeConstants.ENCRYPTED_DATA_OFFSET + VolumeConstants.ENCRYPTED_DATA_SIZE
        )
        
        // Try all combinations of hash algorithms and encryption algorithms
        for (hashAlg in HashAlgorithm.values()) {
            for (encAlg in listOf(EncryptionAlgorithm.AES)) { // Start with AES only
                try {
                    val decrypted = tryDecrypt(
                        encryptedData,
                        password.toByteArray(Charsets.UTF_8),
                        salt,
                        pim,
                        hashAlg,
                        encAlg
                    )
                    
                    if (decrypted != null) {
                        return decrypted
                    }
                } catch (e: Exception) {
                    // Try next combination
                    continue
                }
            }
        }
        
        return null
    }
    
    private fun tryDecrypt(
        encryptedData: ByteArray,
        password: ByteArray,
        salt: ByteArray,
        pim: Int,
        hashAlg: HashAlgorithm,
        encAlg: EncryptionAlgorithm
    ): VolumeHeaderData? {
        // Derive key
        val iterations = hashAlg.getIterationCount(pim, isSystemEncryption = false)
        val derivedKey = PBKDF2.deriveKey(
            password,
            salt,
            iterations,
            hashAlg,
            encAlg.getDerivedKeySize()
        )
        
        // Decrypt header
        val xts = XTSMode(derivedKey, encAlg)
        val decrypted = xts.decrypt(encryptedData, 0)
        
        // Validate header
        return validateAndParse(decrypted, encAlg, hashAlg)
    }
    
    private fun validateAndParse(
        decryptedData: ByteArray,
        encAlg: EncryptionAlgorithm,
        hashAlg: HashAlgorithm
    ): VolumeHeaderData? {
        val buffer = ByteBuffer.wrap(decryptedData).order(ByteOrder.LITTLE_ENDIAN)
        
        // Check magic number
        buffer.position(VolumeConstants.HEADER_OFFSET_MAGIC)
        val magic = buffer.int
        if (magic != VolumeConstants.HEADER_MAGIC) {
            return null
        }
        
        // Validate CRC of the encrypted portion
        buffer.position(VolumeConstants.HEADER_OFFSET_KEY_AREA_CRC)
        val storedKeyCrc = buffer.int
        val calculatedKeyCrc = Crc32.calculate(
            decryptedData,
            VolumeConstants.MASTER_KEYDATA_OFFSET,
            decryptedData.size - VolumeConstants.MASTER_KEYDATA_OFFSET
        )
        
        if (storedKeyCrc != calculatedKeyCrc) {
            return null
        }
        
        // Validate header CRC
        buffer.position(VolumeConstants.HEADER_OFFSET_HEADER_CRC)
        val storedHeaderCrc = buffer.int
        
        // Calculate CRC of header (excluding CRC field itself)
        val headerForCrc = decryptedData.copyOf()
        ByteBuffer.wrap(headerForCrc).order(ByteOrder.LITTLE_ENDIAN).apply {
            position(VolumeConstants.HEADER_OFFSET_HEADER_CRC)
            putInt(0)
        }
        val calculatedHeaderCrc = Crc32.calculate(
            headerForCrc,
            0,
            VolumeConstants.MASTER_KEYDATA_OFFSET
        )
        
        if (storedHeaderCrc != calculatedHeaderCrc) {
            return null
        }
        
        // Extract header fields
        buffer.position(VolumeConstants.HEADER_OFFSET_VERSION)
        val version = buffer.short.toInt() and 0xFFFF
        
        buffer.position(VolumeConstants.HEADER_OFFSET_REQUIRED_VERSION)
        val requiredVersion = buffer.short.toInt() and 0xFFFF
        
        buffer.position(VolumeConstants.HEADER_OFFSET_VOLUME_CREATION_TIME)
        val volumeCreationTime = buffer.long
        
        buffer.position(VolumeConstants.HEADER_OFFSET_HIDDEN_VOLUME_SIZE)
        val hiddenVolumeSize = buffer.long
        
        buffer.position(VolumeConstants.HEADER_OFFSET_VOLUME_SIZE)
        val volumeSize = buffer.long
        
        buffer.position(VolumeConstants.HEADER_OFFSET_ENCRYPTED_AREA_START)
        val encryptedAreaStart = buffer.long
        
        buffer.position(VolumeConstants.HEADER_OFFSET_ENCRYPTED_AREA_LENGTH)
        val encryptedAreaLength = buffer.long
        
        buffer.position(VolumeConstants.HEADER_OFFSET_FLAGS)
        val flags = buffer.int
        
        buffer.position(VolumeConstants.HEADER_OFFSET_SECTOR_SIZE)
        val sectorSize = buffer.int
        
        // Extract master key
        buffer.position(VolumeConstants.MASTER_KEYDATA_OFFSET)
        val masterKey = ByteArray(encAlg.keySize)
        buffer.get(masterKey)
        
        return VolumeHeaderData(
            encryptionAlgorithm = encAlg,
            hashAlgorithm = hashAlg,
            version = version,
            requiredVersion = requiredVersion,
            volumeCreationTime = volumeCreationTime,
            hiddenVolumeSize = hiddenVolumeSize,
            volumeSize = volumeSize,
            encryptedAreaStart = encryptedAreaStart,
            encryptedAreaLength = encryptedAreaLength,
            flags = flags,
            sectorSize = sectorSize,
            masterKey = masterKey
        )
    }
    
    /**
     * Create a new VeraCrypt volume header
     */
    fun createHeader(
        password: String,
        pim: Int = 0,
        volumeSize: Long,
        encryptionAlg: EncryptionAlgorithm = EncryptionAlgorithm.AES,
        hashAlg: HashAlgorithm = HashAlgorithm.SHA512,
        sectorSize: Int = 512
    ): ByteArray {
        // Generate random salt
        val salt = ByteArray(VolumeConstants.SALT_SIZE)
        java.security.SecureRandom().nextBytes(salt)
        
        // Generate random master key
        val masterKey = ByteArray(encryptionAlg.keySize)
        java.security.SecureRandom().nextBytes(masterKey)
        
        // Create header data
        val headerData = ByteArray(VolumeConstants.ENCRYPTED_DATA_SIZE)
        val buffer = ByteBuffer.wrap(headerData).order(ByteOrder.LITTLE_ENDIAN)
        
        // Magic number
        buffer.position(VolumeConstants.HEADER_OFFSET_MAGIC)
        buffer.putInt(VolumeConstants.HEADER_MAGIC)
        
        // Version
        buffer.position(VolumeConstants.HEADER_OFFSET_VERSION)
        buffer.putShort(VolumeConstants.VOLUME_HEADER_VERSION_NUM.toShort())
        
        // Required version
        buffer.position(VolumeConstants.HEADER_OFFSET_REQUIRED_VERSION)
        buffer.putShort(VolumeConstants.TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION.toShort())
        
        // Volume creation time
        buffer.position(VolumeConstants.HEADER_OFFSET_VOLUME_CREATION_TIME)
        buffer.putLong(System.currentTimeMillis() / 1000)
        
        // Hidden volume size (0 for normal volumes)
        buffer.position(VolumeConstants.HEADER_OFFSET_HIDDEN_VOLUME_SIZE)
        buffer.putLong(0)
        
        // Volume size
        buffer.position(VolumeConstants.HEADER_OFFSET_VOLUME_SIZE)
        buffer.putLong(volumeSize)
        
        // Encrypted area start
        buffer.position(VolumeConstants.HEADER_OFFSET_ENCRYPTED_AREA_START)
        buffer.putLong(VolumeConstants.VOLUME_HEADER_GROUP_SIZE)
        
        // Encrypted area length
        buffer.position(VolumeConstants.HEADER_OFFSET_ENCRYPTED_AREA_LENGTH)
        buffer.putLong(volumeSize - VolumeConstants.VOLUME_HEADER_GROUP_SIZE)
        
        // Flags (0 for normal volumes)
        buffer.position(VolumeConstants.HEADER_OFFSET_FLAGS)
        buffer.putInt(0)
        
        // Sector size
        buffer.position(VolumeConstants.HEADER_OFFSET_SECTOR_SIZE)
        buffer.putInt(sectorSize)
        
        // Master key
        buffer.position(VolumeConstants.MASTER_KEYDATA_OFFSET)
        buffer.put(masterKey)
        
        // Calculate and store key area CRC
        val keyCrc = Crc32.calculate(
            headerData,
            VolumeConstants.MASTER_KEYDATA_OFFSET,
            headerData.size - VolumeConstants.MASTER_KEYDATA_OFFSET
        )
        buffer.position(VolumeConstants.HEADER_OFFSET_KEY_AREA_CRC)
        buffer.putInt(keyCrc)
        
        // Calculate and store header CRC
        val headerForCrc = headerData.copyOf()
        ByteBuffer.wrap(headerForCrc).order(ByteOrder.LITTLE_ENDIAN).apply {
            position(VolumeConstants.HEADER_OFFSET_HEADER_CRC)
            putInt(0)
        }
        val headerCrc = Crc32.calculate(headerForCrc, 0, VolumeConstants.MASTER_KEYDATA_OFFSET)
        buffer.position(VolumeConstants.HEADER_OFFSET_HEADER_CRC)
        buffer.putInt(headerCrc)
        
        // Derive encryption key from password
        val iterations = hashAlg.getIterationCount(pim, isSystemEncryption = false)
        val headerKey = PBKDF2.deriveKey(
            password.toByteArray(Charsets.UTF_8),
            salt,
            iterations,
            hashAlg,
            encryptionAlg.getDerivedKeySize()
        )
        
        // Encrypt header
        val xts = XTSMode(headerKey, encryptionAlg)
        val encryptedHeader = xts.encrypt(headerData, 0)
        
        // Combine salt and encrypted header
        val fullHeader = ByteArray(VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE)
        System.arraycopy(salt, 0, fullHeader, VolumeConstants.SALT_OFFSET, salt.size)
        System.arraycopy(encryptedHeader, 0, fullHeader, VolumeConstants.ENCRYPTED_DATA_OFFSET, encryptedHeader.size)
        
        return fullHeader
    }
}

/**
 * Parsed volume header data
 */
data class VolumeHeaderData(
    val encryptionAlgorithm: EncryptionAlgorithm,
    val hashAlgorithm: HashAlgorithm,
    val version: Int,
    val requiredVersion: Int,
    val volumeCreationTime: Long,
    val hiddenVolumeSize: Long,
    val volumeSize: Long,
    val encryptedAreaStart: Long,
    val encryptedAreaLength: Long,
    val flags: Int,
    val sectorSize: Int,
    val masterKey: ByteArray
) {
    val isSystemEncrypted: Boolean
        get() = (flags and 0x1) != 0
    
    val isNonSystemInPlaceEncrypted: Boolean
        get() = (flags and 0x2) != 0
}
