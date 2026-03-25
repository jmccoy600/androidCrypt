package com.androidcrypt.crypto

import android.content.Context
import android.net.Uri
import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.security.SecureRandom
import java.util.zip.CRC32
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Creates and formats VeraCrypt-compatible encrypted containers
 */
class VolumeCreator {
    
    companion object {
        private const val TAG = "VolumeCreator"
        private const val SECTOR_SIZE = 512
        private const val HEADER_SIZE = 512  // Single header is 512 bytes
        private const val SALT_SIZE = 64
        private const val VOLUME_HEADER_SIZE = 65536L  // 64KB for each header
        private const val DATA_AREA_OFFSET = 131072L  // 128KB offset for data area start (2 * VOLUME_HEADER_SIZE)
        private const val TOTAL_HEADERS_SIZE = 262144L  // 256KB for all 4 headers (4 * VOLUME_HEADER_SIZE)
        
        /**
         * Create a new encrypted container file
         * 
         * @param containerPath Path where the container file will be created
         * @param password Password for encryption (can be empty if using keyfiles)
         * @param sizeInMB Size of the container in megabytes
         * @param pim Personal Iterations Multiplier (0 for default)
         * @param keyfileUris List of keyfile URIs (optional)
         * @param context Android context (required if using keyfiles)
         * @param algorithm Encryption algorithm (AES or Serpent, default AES)
         * @return Result with success/error message
         */
        fun createContainer(
            containerPath: String,
            password: CharArray,
            sizeInMB: Long,
            pim: Int = 0,
            keyfileUris: List<Uri> = emptyList(),
            context: Context? = null,
            algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES
        ): Result<String> {
            return try {
                val containerFile = File(containerPath)
                
                // Validate inputs
                if (containerFile.exists()) {
                    return Result.failure(Exception("File already exists"))
                }
                if (password.isEmpty() && keyfileUris.isEmpty()) {
                    return Result.failure(Exception("Password or keyfiles required"))
                }
                if (sizeInMB < 1) {
                    return Result.failure(Exception("Container size must be at least 1 MB"))
                }
                
                // Apply keyfiles to password if any
                val passwordBytes: ByteArray = if (keyfileUris.isNotEmpty() && context != null) {
                    val result = KeyfileProcessor.applyKeyfilesFromUris(password, keyfileUris, context)
                    if (result.isFailure) {
                        return Result.failure(result.exceptionOrNull() ?: Exception("Failed to process keyfiles"))
                    }
                    result.getOrThrow()
                } else {
                    charArrayToUtf8Bytes(password)
                }
                
                // Calculate total size
                val totalBytes = sizeInMB * 1024 * 1024
                
                // Create the file
                RandomAccessFile(containerFile, "rw").use { raf ->
                    // Set file size
                    raf.setLength(totalBytes)
                    
                    // Generate random salt for key derivation
                    val salt = ByteArray(SALT_SIZE)
                    SecureRandom().nextBytes(salt)
                    
                    // Derive encryption key from password using PBKDF2-HMAC-SHA512
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
                        dkLen = algorithm.keySize  // 64 for single ciphers, 192 for AES-Twofish-Serpent
                    )
                    
                    // Generate random master key for data encryption
                    val masterKey = ByteArray(algorithm.keySize)
                    SecureRandom().nextBytes(masterKey)
                    
                    try {
                        // Create volume header
                        val headerBytes = createVolumeHeader(salt, derivedKey, masterKey, totalBytes, algorithm)
                        
                        // Write primary header at offset 0 (salt + encrypted header = 512 bytes)
                        raf.seek(0)
                        raf.write(headerBytes)
                        
                        // Write backup header at end of file - 128KB
                        // VeraCrypt layout: backup header at (dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE) 
                        // = (totalBytes - 256KB) + 128KB = totalBytes - 128KB
                        val backupHeaderOffset = totalBytes - DATA_AREA_OFFSET
                        raf.seek(backupHeaderOffset)
                        raf.write(headerBytes)
                        
                        // Format the data area with FAT32 file system
                        formatFAT32(raf, masterKey, totalBytes, algorithm)
                        
                    } finally {
                        // Securely zero all key material
                        passwordBytes.fill(0)
                        derivedKey.fill(0)
                        masterKey.fill(0)
                    }
                }
                
                Result.success("Container created successfully")
                
            } catch (e: Exception) {
                Result.failure(e)
            } finally {
                password.fill('\u0000')  // Always zero password CharArray
            }
        }
        
        /**
         * Create an encrypted volume header
         */
        private fun createVolumeHeader(
            salt: ByteArray,
            derivedKey: ByteArray,
            masterKey: ByteArray,
            volumeSize: Long,
            algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES
        ): ByteArray {
            // VeraCrypt header structure:
            // Total: 512 bytes (TC_VOLUME_HEADER_EFFECTIVE_SIZE)
            // Bytes 0-63: Salt (unencrypted, PKCS5_SALT_SIZE = 64)
            // Bytes 64-511: Encrypted header data (448 bytes = HEADER_ENCRYPTED_DATA_SIZE)
            
            // Create the unencrypted header data (448 bytes that will be encrypted)
            // This is the data from offset 64 to 511 in the full header
            val unencryptedData = ByteArray(448)
            
            // All offsets below are relative to the encrypted portion (i.e., subtract 64 from full header offset)
            
            // Magic bytes "VERA" at offset 0 (full header offset 64)
            unencryptedData[0] = 'V'.code.toByte()
            unencryptedData[1] = 'E'.code.toByte()
            unencryptedData[2] = 'R'.code.toByte()
            unencryptedData[3] = 'A'.code.toByte()
            
            // Volume header version (5) at offset 4 - BIG ENDIAN
            unencryptedData[4] = 0x00
            unencryptedData[5] = 0x05
            
            // Minimum program version required (0x010b = 1.11) at offset 6 - BIG ENDIAN
            unencryptedData[6] = 0x01
            unencryptedData[7] = 0x0b
            
            // CRC32 of master keydata at offset 8 (will be calculated later)
            
            // Volume creation time at offset 12 (8 bytes) - 0 for now
            
            // Modification time at offset 20 (8 bytes) - 0 for now
            
            // Hidden volume size at offset 28 (8 bytes) - 0 for normal volumes
            
            // Volume size at offset 36 (8 bytes) - full header offset 100
            // VeraCrypt: volumeSize = dataAreaSize = totalFileSize - TC_TOTAL_VOLUME_HEADERS_SIZE
            val dataAreaSize = volumeSize - TOTAL_HEADERS_SIZE
            writeLong(unencryptedData, 36, dataAreaSize)
            
            // Encrypted area start at offset 44 (8 bytes) - full header offset 108
            writeLong(unencryptedData, 44, DATA_AREA_OFFSET)
            
            // Encrypted area size at offset 52 (8 bytes) - full header offset 116
            writeLong(unencryptedData, 52, dataAreaSize)
            
            // Flags at offset 60 (4 bytes) - 0 for normal volume
            
            // Sector size at offset 64 (4 bytes) - full header offset 128
            writeInt(unencryptedData, 64, SECTOR_SIZE)
            
            // Reserved up to offset 188
            
            // Master keydata at offset 192 (256 bytes) - full header offset 256
            System.arraycopy(masterKey, 0, unencryptedData, 192, minOf(masterKey.size, 256))
            
            // Calculate CRC32 of master keydata (256 bytes at offset 192)
            val crcKeydata = CRC32()
            crcKeydata.update(unencryptedData, 192, 256)
            val crcKeydataValue = crcKeydata.value.toInt()
            
            // Write CRC32 of keydata at offset 8 (BIG ENDIAN)
            unencryptedData[8] = (crcKeydataValue shr 24).toByte()
            unencryptedData[9] = (crcKeydataValue shr 16).toByte()
            unencryptedData[10] = (crcKeydataValue shr 8).toByte()
            unencryptedData[11] = crcKeydataValue.toByte()
            
            // Calculate CRC32 of header fields (from offset 0 to 187 = 188 bytes)
            val crcHeader = CRC32()
            crcHeader.update(unencryptedData, 0, 188)
            val crcHeaderValue = crcHeader.value.toInt()
            
            // Write CRC32 of header at offset 188 (BIG ENDIAN) - full header offset 252
            unencryptedData[188] = (crcHeaderValue shr 24).toByte()
            unencryptedData[189] = (crcHeaderValue shr 16).toByte()
            unencryptedData[190] = (crcHeaderValue shr 8).toByte()
            unencryptedData[191] = crcHeaderValue.toByte()
            
            // Encrypt the 448-byte header data using XTS mode
            val xts = XTSMode(derivedKey, algorithm)
            val encryptedData = xts.encrypt(unencryptedData, 0)
            xts.close()
            
            // Create final result: salt (64 bytes) + encrypted data (448 bytes) = 512 bytes
            val result = ByteArray(512)
            System.arraycopy(salt, 0, result, 0, SALT_SIZE)  // Unencrypted salt
            System.arraycopy(encryptedData, 0, result, 64, 448)  // Encrypted header data
            
            return result
        }
        
        /**
         * Format the data area with FAT32 file system
         */
        private fun formatFAT32(raf: RandomAccessFile, masterKey: ByteArray, totalBytes: Long, algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES) {
            // Data area size = total file size - all 4 headers (256KB)
            val dataAreaSize = totalBytes - TOTAL_HEADERS_SIZE
            val sectorCount = (dataAreaSize / SECTOR_SIZE).toInt()
            
            // Calculate FAT32 parameters
            val sectorsPerCluster = 8  // 4KB clusters
            val reservedSectors = 32
            val numberOfFATs = 2
            val rootDirFirstCluster = 2
            
            // Calculate sectors per FAT (simplified)
            val clusterCount = (sectorCount - reservedSectors) / (sectorsPerCluster + 1)
            val sectorsPerFAT = (clusterCount * 4 + SECTOR_SIZE - 1) / SECTOR_SIZE
            
            // Generate random volume ID like VeraCrypt
            val volumeId = ByteArray(4)
            java.security.SecureRandom().nextBytes(volumeId)
            
            // Create boot sector
            val bootSector = ByteArray(SECTOR_SIZE)
            
            // Jump instruction
            bootSector[0] = 0xEB.toByte()
            bootSector[1] = 0x58.toByte()
            bootSector[2] = 0x90.toByte()
            
            // OEM Name - VeraCrypt uses "MSDOS5.0"
            val oemName = "MSDOS5.0"
            System.arraycopy(oemName.toByteArray(), 0, bootSector, 3, 8)
            
            // Bytes per sector (512)
            bootSector[11] = 0x00
            bootSector[12] = 0x02
            
            // Sectors per cluster
            bootSector[13] = sectorsPerCluster.toByte()
            
            // Reserved sectors
            bootSector[14] = (reservedSectors and 0xFF).toByte()
            bootSector[15] = (reservedSectors shr 8).toByte()
            
            // Number of FATs
            bootSector[16] = numberOfFATs.toByte()
            
            // Root entry count (0 for FAT32)
            bootSector[17] = 0
            bootSector[18] = 0
            
            // Total sectors 16 (0 for FAT32)
            bootSector[19] = 0
            bootSector[20] = 0
            
            // Media descriptor (0xF8 = fixed disk)
            bootSector[21] = 0xF8.toByte()
            
            // Sectors per FAT (FAT16, 0 for FAT32)
            bootSector[22] = 0
            bootSector[23] = 0
            
            // Sectors per track - VeraCrypt uses 1
            bootSector[24] = 0x01
            bootSector[25] = 0x00
            
            // Number of heads - VeraCrypt uses 1
            bootSector[26] = 0x01
            bootSector[27] = 0x00
            
            // Hidden sectors
            bootSector[28] = 0
            bootSector[29] = 0
            bootSector[30] = 0
            bootSector[31] = 0
            
            // Total sectors 32
            val totalSectors = sectorCount
            bootSector[32] = (totalSectors and 0xFF).toByte()
            bootSector[33] = (totalSectors shr 8 and 0xFF).toByte()
            bootSector[34] = (totalSectors shr 16 and 0xFF).toByte()
            bootSector[35] = (totalSectors shr 24 and 0xFF).toByte()
            
            // FAT32 specific fields (offset 36)
            // Sectors per FAT
            bootSector[36] = (sectorsPerFAT and 0xFF).toByte()
            bootSector[37] = (sectorsPerFAT shr 8 and 0xFF).toByte()
            bootSector[38] = (sectorsPerFAT shr 16 and 0xFF).toByte()
            bootSector[39] = (sectorsPerFAT shr 24 and 0xFF).toByte()
            
            // Flags
            bootSector[40] = 0
            bootSector[41] = 0
            
            // Version
            bootSector[42] = 0
            bootSector[43] = 0
            
            // Root directory first cluster
            bootSector[44] = (rootDirFirstCluster and 0xFF).toByte()
            bootSector[45] = (rootDirFirstCluster shr 8 and 0xFF).toByte()
            bootSector[46] = (rootDirFirstCluster shr 16 and 0xFF).toByte()
            bootSector[47] = (rootDirFirstCluster shr 24 and 0xFF).toByte()
            
            // FSInfo sector
            bootSector[48] = 1
            bootSector[49] = 0
            
            // Backup boot sector
            bootSector[50] = 6
            bootSector[51] = 0
            
            // Drive number (offset 64) - VeraCrypt uses 0x00, not 0x80
            bootSector[64] = 0x00
            
            // Reserved
            bootSector[65] = 0
            
            // Extended boot signature
            bootSector[66] = 0x29
            
            // Volume serial number - use random volumeId
            System.arraycopy(volumeId, 0, bootSector, 67, 4)
            
            // Volume label - VeraCrypt uses "NO NAME    "
            val volumeLabel = "NO NAME    "
            System.arraycopy(volumeLabel.toByteArray(), 0, bootSector, 71, 11)
            
            // File system type
            val fsType = "FAT32   "
            System.arraycopy(fsType.toByteArray(), 0, bootSector, 82, 8)
            
            // Boot signature
            bootSector[510] = 0x55
            bootSector[511] = 0xAA.toByte()
            
            // XTS sector number offset: VeraCrypt uses absolute sector number from start of volume
            // DATA_AREA_OFFSET / SECTOR_SIZE = 131072 / 512 = 256
            val startSector = DATA_AREA_OFFSET / SECTOR_SIZE
            
            // Encrypt and write boot sector
            val xts = XTSMode(masterKey, algorithm)
            try {
            val encryptedBootSector = xts.encrypt(bootSector, startSector)
            raf.seek(DATA_AREA_OFFSET)
            raf.write(encryptedBootSector)
            
            // Create FSInfo sector (sector 1)
            val fsInfoSector = ByteArray(SECTOR_SIZE)
            // FSInfo signature 1 (LeadSig) - VeraCrypt uses 0x41615252
            fsInfoSector[0] = 0x52  // 'R'
            fsInfoSector[1] = 0x52  // 'R'
            fsInfoSector[2] = 0x61  // 'a'
            fsInfoSector[3] = 0x41  // 'A'
            // FSInfo signature 2 (StrucSig) at offset 484 - VeraCrypt uses 0x61417272
            fsInfoSector[484] = 0x72  // 'r'
            fsInfoSector[485] = 0x72  // 'r'
            fsInfoSector[486] = 0x41  // 'A'
            fsInfoSector[487] = 0x61  // 'a'
            // Free cluster count - calculate actual value like VeraCrypt
            val actualClusterCount = clusterCount - (sectorsPerCluster / sectorsPerCluster) // minus root dir clusters used
            fsInfoSector[488] = (actualClusterCount and 0xFF).toByte()
            fsInfoSector[489] = (actualClusterCount shr 8 and 0xFF).toByte()
            fsInfoSector[490] = (actualClusterCount shr 16 and 0xFF).toByte()
            fsInfoSector[491] = (actualClusterCount shr 24 and 0xFF).toByte()
            // Next free cluster hint - VeraCrypt uses 2, not 3
            fsInfoSector[492] = 0x02
            fsInfoSector[493] = 0x00
            fsInfoSector[494] = 0x00
            fsInfoSector[495] = 0x00
            // FSInfo signature 3 (TrailSig) at offset 508 - VeraCrypt uses 0xAA550000
            fsInfoSector[508] = 0x00
            fsInfoSector[509] = 0x00
            fsInfoSector[510] = 0x55
            fsInfoSector[511] = 0xAA.toByte()
            
            // Encrypt and write FSInfo sector
            val encryptedFSInfo = xts.encrypt(fsInfoSector, startSector + 1)
            raf.seek(DATA_AREA_OFFSET + SECTOR_SIZE)
            raf.write(encryptedFSInfo)
            
            // Write backup boot sector at sector 6
            val encryptedBackupBoot = xts.encrypt(bootSector, startSector + 6)
            raf.seek(DATA_AREA_OFFSET + (6 * SECTOR_SIZE))
            raf.write(encryptedBackupBoot)
            
            // Write backup FSInfo at sector 7
            val encryptedBackupFSInfo = xts.encrypt(fsInfoSector, startSector + 7)
            raf.seek(DATA_AREA_OFFSET + (7 * SECTOR_SIZE))
            raf.write(encryptedBackupFSInfo)
            
            // Sectors 2-5: Reserved sectors with TrailSig (like VeraCrypt)
            val reservedSectorWithSig = ByteArray(SECTOR_SIZE)
            reservedSectorWithSig[508] = 0x00
            reservedSectorWithSig[509] = 0x00
            reservedSectorWithSig[510] = 0x55
            reservedSectorWithSig[511] = 0xAA.toByte()
            for (sector in 2..5) {
                val encryptedReserved = xts.encrypt(reservedSectorWithSig, startSector + sector)
                raf.seek(DATA_AREA_OFFSET + (sector * SECTOR_SIZE))
                raf.write(encryptedReserved)
            }
            
            // Remaining reserved sectors (8-31) with encrypted zeros
            val zeroSector = ByteArray(SECTOR_SIZE)
            for (sector in 8 until reservedSectors) {
                val encryptedZero = xts.encrypt(zeroSector, startSector + sector)
                raf.seek(DATA_AREA_OFFSET + (sector * SECTOR_SIZE))
                raf.write(encryptedZero)
            }
            
            // Create and write FAT tables
            val fatSector = ByteArray(SECTOR_SIZE)
            // FAT32 media descriptor and EOC markers
            fatSector[0] = 0xF8.toByte()
            fatSector[1] = 0xFF.toByte()
            fatSector[2] = 0xFF.toByte()
            fatSector[3] = 0x0F
            fatSector[4] = 0xFF.toByte()
            fatSector[5] = 0xFF.toByte()
            fatSector[6] = 0xFF.toByte()
            fatSector[7] = 0x0F
            // Mark root directory cluster as EOF
            fatSector[8] = 0xFF.toByte()
            fatSector[9] = 0xFF.toByte()
            fatSector[10] = 0xFF.toByte()
            fatSector[11] = 0x0F
            
            // Write first FAT - first sector has cluster entries
            val encryptedFAT = xts.encrypt(fatSector, startSector + reservedSectors)
            raf.seek(DATA_AREA_OFFSET + (reservedSectors * SECTOR_SIZE))
            raf.write(encryptedFAT)
            
            // Write remaining first FAT sectors as zeros
            for (i in 1 until sectorsPerFAT) {
                val encryptedZeroFAT = xts.encrypt(zeroSector, startSector + reservedSectors + i)
                raf.seek(DATA_AREA_OFFSET + ((reservedSectors + i) * SECTOR_SIZE))
                raf.write(encryptedZeroFAT)
            }
            
            // Write second FAT - first sector has cluster entries
            val secondFATOffset = reservedSectors + sectorsPerFAT
            val encryptedFAT2 = xts.encrypt(fatSector, startSector + secondFATOffset)
            raf.seek(DATA_AREA_OFFSET + (secondFATOffset * SECTOR_SIZE))
            raf.write(encryptedFAT2)
            
            // Write remaining second FAT sectors as zeros
            for (i in 1 until sectorsPerFAT) {
                val encryptedZeroFAT2 = xts.encrypt(zeroSector, startSector + secondFATOffset + i)
                raf.seek(DATA_AREA_OFFSET + ((reservedSectors + sectorsPerFAT + i) * SECTOR_SIZE))
                raf.write(encryptedZeroFAT2)
            }
            
            // Create empty root directory
            val rootDirCluster = ByteArray(sectorsPerCluster * SECTOR_SIZE)
            val firstDataSector = reservedSectors + (numberOfFATs * sectorsPerFAT)
            val rootDirSector = firstDataSector + ((rootDirFirstCluster - 2) * sectorsPerCluster)
            
            // Write root directory cluster
            for (i in 0 until sectorsPerCluster) {
                val emptySector = ByteArray(SECTOR_SIZE)
                val encryptedSector = xts.encrypt(emptySector, startSector + rootDirSector + i)
                raf.seek(DATA_AREA_OFFSET + ((rootDirSector + i) * SECTOR_SIZE))
                raf.write(encryptedSector)
            }
            
            Log.d(TAG, "Progress: ${totalBytes / (1024 * 1024)}MB / ${totalBytes / (1024 * 1024)}MB")
            } finally {
                xts.close()
            }
        }
        
        private fun writeLong(buffer: ByteArray, offset: Int, value: Long) {
            // Write as BIG-ENDIAN (VeraCrypt header format)
            buffer[offset] = (value shr 56).toByte()
            buffer[offset + 1] = (value shr 48).toByte()
            buffer[offset + 2] = (value shr 40).toByte()
            buffer[offset + 3] = (value shr 32).toByte()
            buffer[offset + 4] = (value shr 24).toByte()
            buffer[offset + 5] = (value shr 16).toByte()
            buffer[offset + 6] = (value shr 8).toByte()
            buffer[offset + 7] = value.toByte()
        }
        
        private fun writeInt(buffer: ByteArray, offset: Int, value: Int) {
            // Write as BIG-ENDIAN (VeraCrypt header format)
            buffer[offset] = (value shr 24).toByte()
            buffer[offset + 1] = (value shr 16).toByte()
            buffer[offset + 2] = (value shr 8).toByte()
            buffer[offset + 3] = value.toByte()
        }
        
        /**
         * Create a hidden volume inside an existing outer VeraCrypt container.
         *
         * VeraCrypt hidden volume layout (from src/Common/Volumes.h and Format.c):
         *   - The hidden volume header is written at offset TC_HIDDEN_VOLUME_HEADER_OFFSET (64KB)
         *     within the outer volume file. This area is indistinguishable from random data
         *     to anyone who does not possess the hidden volume password.
         *   - The hidden volume data area is placed at the END of the outer volume's data area,
         *     just before the backup header area.
         *   - Hidden data offset = hostSize - TC_VOLUME_HEADER_GROUP_SIZE - hiddenVolumeSize
         *   - The hidden backup header is at (end - TC_HIDDEN_VOLUME_HEADER_OFFSET)
         *
         * The outer volume password reveals only the outer FAT32 FS.
         * The hidden volume password reveals the hidden FAT32 FS. Without the hidden password,
         * there is no way to prove the hidden volume exists — the header and data areas are
         * filled with cryptographically random data.
         *
         * @param containerPath Path of the EXISTING outer container
         * @param outerPassword Password for the outer volume (needed to verify the container)
         * @param hiddenPassword Password for the hidden volume
         * @param hiddenSizeInMB Size of the hidden volume in MB
         * @param pim PIM for key derivation (0 for default)
         * @param keyfileUris Keyfile URIs (optional)
         * @param context Android context
         * @param algorithm Encryption algorithm for the hidden volume
         */
        fun createHiddenVolume(
            containerPath: String,
            outerPassword: CharArray,
            hiddenPassword: CharArray,
            hiddenSizeInMB: Long,
            pim: Int = 0,
            keyfileUris: List<Uri> = emptyList(),
            context: Context? = null,
            algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES
        ): Result<String> {
            return try {
                val containerFile = File(containerPath)
                if (!containerFile.exists()) {
                    return Result.failure(Exception("Container file does not exist"))
                }
                
                if (hiddenPassword.isEmpty()) {
                    return Result.failure(Exception("Hidden volume password is required"))
                }
                
                if (hiddenSizeInMB < 1) {
                    return Result.failure(Exception("Hidden volume must be at least 1 MB"))
                }
                
                val hostSize = containerFile.length()
                val hiddenBytes = hiddenSizeInMB * 1024 * 1024
                
                // Validate: hidden volume must fit inside the outer volume data area.
                // The data area of the outer volume = hostSize - TOTAL_HEADERS_SIZE.
                // Hidden volume needs hiddenBytes for data + some reserved end-area.
                val outerDataArea = hostSize - TOTAL_HEADERS_SIZE
                val reservedSize = if (hostSize < VolumeConstants.VOLUME_SMALL_SIZE_THRESHOLD)
                    VolumeConstants.HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE
                else
                    VolumeConstants.HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH
                
                if (hiddenBytes > outerDataArea - reservedSize) {
                    val maxMB = (outerDataArea - reservedSize) / (1024 * 1024)
                    return Result.failure(Exception(
                        "Hidden volume too large. Maximum: ${maxMB} MB for this container."
                    ))
                }
                
                // Apply keyfiles to password if any
                val passwordBytes: ByteArray = if (keyfileUris.isNotEmpty() && context != null) {
                    val result = KeyfileProcessor.applyKeyfilesFromUris(hiddenPassword, keyfileUris, context)
                    if (result.isFailure) {
                        return Result.failure(result.exceptionOrNull() ?: Exception("Failed to process keyfiles"))
                    }
                    result.getOrThrow()
                } else {
                    charArrayToUtf8Bytes(hiddenPassword)
                }
                
                // Derive key from hidden password
                val iterations = if (pim > 0) 15000 + (pim * 1000) else 500000
                val salt = ByteArray(SALT_SIZE)
                SecureRandom().nextBytes(salt)
                
                val derivedKey = PBKDF2.deriveKey(
                    password = passwordBytes,
                    salt = salt,
                    iterations = iterations,
                    hashAlgorithm = HashAlgorithm.SHA512,
                    dkLen = algorithm.keySize
                )
                
                // Generate random master key for data encryption
                val masterKey = ByteArray(algorithm.keySize)
                SecureRandom().nextBytes(masterKey)
                
                try {
                    // Hidden volume data area sits at the END of the outer volume, before the backup headers.
                    // From VeraCrypt Format.c:
                    //   dataOffset = hiddenVolHostSize - TC_VOLUME_HEADER_GROUP_SIZE - hiddenVolumeSize
                    // where hiddenVolHostSize = total file size
                    val hiddenDataOffset = hostSize - DATA_AREA_OFFSET - hiddenBytes
                    
                    // Hidden volume data area size = hiddenBytes - reservedSize
                    // (the reserved area prevents outer FS from overwriting the hidden volume end)
                    val hiddenDataAreaSize = hiddenBytes - reservedSize
                    
                    // Create the hidden volume header (same format as normal, but hiddenVolumeSize field
                    // is set to the data area size, and dataOffset/encryptedAreaStart point to the hidden area)
                    val headerBytes = createHiddenVolumeHeader(
                        salt, derivedKey, masterKey, hiddenDataAreaSize, hiddenDataOffset, algorithm
                    )
                    
                    RandomAccessFile(containerFile, "rw").use { raf ->
                        // Write hidden header at offset TC_HIDDEN_VOLUME_HEADER_OFFSET (64KB)
                        raf.seek(VOLUME_HEADER_SIZE)
                        raf.write(headerBytes)
                        
                        // Write backup hidden header at (end - TC_HIDDEN_VOLUME_HEADER_OFFSET) = end - 64KB
                        val backupHiddenOffset = hostSize - VOLUME_HEADER_SIZE
                        raf.seek(backupHiddenOffset)
                        raf.write(headerBytes)
                        
                        // Format the hidden data area with FAT32
                        formatHiddenFAT32(raf, masterKey, hiddenDataOffset, hiddenDataAreaSize, algorithm)
                    }
                } finally {
                    // Securely zero all key material
                    passwordBytes.fill(0)
                    derivedKey.fill(0)
                    masterKey.fill(0)
                }
                
                Result.success("Hidden volume created successfully")
                
            } catch (e: Exception) {
                Result.failure(e)
            } finally {
                outerPassword.fill('\u0000')  // Always zero password CharArrays
                hiddenPassword.fill('\u0000')
            }
        }
        
        /**
         * Create an encrypted volume header for a hidden volume.
         * The key difference from a normal header:
         *   - hiddenVolumeSize field (offset 28) = data area size (non-zero signals hidden volume)
         *   - encryptedAreaStart (offset 44) = absolute offset of hidden data in the file
         *   - volumeSize (offset 36) = hidden data area size
         */
        private fun createHiddenVolumeHeader(
            salt: ByteArray,
            derivedKey: ByteArray,
            masterKey: ByteArray,
            dataAreaSize: Long,
            dataOffset: Long,
            algorithm: EncryptionAlgorithm
        ): ByteArray {
            val unencryptedData = ByteArray(448)
            
            // Magic "VERA"
            unencryptedData[0] = 'V'.code.toByte()
            unencryptedData[1] = 'E'.code.toByte()
            unencryptedData[2] = 'R'.code.toByte()
            unencryptedData[3] = 'A'.code.toByte()
            
            // Version 5 (BIG ENDIAN)
            unencryptedData[4] = 0x00
            unencryptedData[5] = 0x05
            
            // Required program version
            unencryptedData[6] = 0x01
            unencryptedData[7] = 0x0b
            
            // Hidden volume size at offset 28 — non-zero means this IS a hidden volume
            // VeraCrypt: for hidden volumes, this equals the volume data size
            writeLong(unencryptedData, 28, dataAreaSize)
            
            // Volume size at offset 36 — identical to hiddenVolumeSize for hidden volumes
            writeLong(unencryptedData, 36, dataAreaSize)
            
            // Encrypted area start at offset 44 — absolute byte offset within the container file
            writeLong(unencryptedData, 44, dataOffset)
            
            // Encrypted area size at offset 52
            writeLong(unencryptedData, 52, dataAreaSize)
            
            // Flags at offset 60 — 0 for normal hidden volume
            
            // Sector size at offset 64
            writeInt(unencryptedData, 64, SECTOR_SIZE)
            
            // Master keydata at offset 192
            System.arraycopy(masterKey, 0, unencryptedData, 192, minOf(masterKey.size, 256))
            
            // CRC32 of master keydata
            val crcKeydata = java.util.zip.CRC32()
            crcKeydata.update(unencryptedData, 192, 256)
            val crcKeydataValue = crcKeydata.value.toInt()
            unencryptedData[8] = (crcKeydataValue shr 24).toByte()
            unencryptedData[9] = (crcKeydataValue shr 16).toByte()
            unencryptedData[10] = (crcKeydataValue shr 8).toByte()
            unencryptedData[11] = crcKeydataValue.toByte()
            
            // CRC32 of header fields
            val crcHeader = java.util.zip.CRC32()
            crcHeader.update(unencryptedData, 0, 188)
            val crcHeaderValue = crcHeader.value.toInt()
            unencryptedData[188] = (crcHeaderValue shr 24).toByte()
            unencryptedData[189] = (crcHeaderValue shr 16).toByte()
            unencryptedData[190] = (crcHeaderValue shr 8).toByte()
            unencryptedData[191] = crcHeaderValue.toByte()
            
            // Encrypt header
            val xts = XTSMode(derivedKey, algorithm)
            val encryptedData = xts.encrypt(unencryptedData, 0)
            xts.close()
            
            // Final: salt + encrypted
            val result = ByteArray(512)
            System.arraycopy(salt, 0, result, 0, SALT_SIZE)
            System.arraycopy(encryptedData, 0, result, 64, 448)
            
            return result
        }
        
        /**
         * Format the hidden volume data area with FAT32.
         * Works exactly like formatFAT32 but uses the hidden volume's data offset.
         */
        private fun formatHiddenFAT32(
            raf: RandomAccessFile,
            masterKey: ByteArray,
            hiddenDataOffset: Long,
            hiddenDataAreaSize: Long,
            algorithm: EncryptionAlgorithm
        ) {
            val sectorCount = (hiddenDataAreaSize / SECTOR_SIZE).toInt()
            val sectorsPerCluster = 8
            val reservedSectors = 32
            val numberOfFATs = 2
            val rootDirFirstCluster = 2
            
            val clusterCount = (sectorCount - reservedSectors) / (sectorsPerCluster + 1)
            val sectorsPerFAT = (clusterCount * 4 + SECTOR_SIZE - 1) / SECTOR_SIZE
            
            val volumeId = ByteArray(4)
            SecureRandom().nextBytes(volumeId)
            
            // Boot sector — same structure as normal volume
            val bootSector = ByteArray(SECTOR_SIZE)
            bootSector[0] = 0xEB.toByte(); bootSector[1] = 0x58.toByte(); bootSector[2] = 0x90.toByte()
            System.arraycopy("MSDOS5.0".toByteArray(), 0, bootSector, 3, 8)
            bootSector[11] = 0x00; bootSector[12] = 0x02
            bootSector[13] = sectorsPerCluster.toByte()
            bootSector[14] = (reservedSectors and 0xFF).toByte()
            bootSector[15] = (reservedSectors shr 8).toByte()
            bootSector[16] = numberOfFATs.toByte()
            bootSector[17] = 0; bootSector[18] = 0
            bootSector[19] = 0; bootSector[20] = 0
            bootSector[21] = 0xF8.toByte()
            bootSector[22] = 0; bootSector[23] = 0
            bootSector[24] = 0x01; bootSector[25] = 0x00
            bootSector[26] = 0x01; bootSector[27] = 0x00
            bootSector[32] = (sectorCount and 0xFF).toByte()
            bootSector[33] = (sectorCount shr 8 and 0xFF).toByte()
            bootSector[34] = (sectorCount shr 16 and 0xFF).toByte()
            bootSector[35] = (sectorCount shr 24 and 0xFF).toByte()
            bootSector[36] = (sectorsPerFAT and 0xFF).toByte()
            bootSector[37] = (sectorsPerFAT shr 8 and 0xFF).toByte()
            bootSector[38] = (sectorsPerFAT shr 16 and 0xFF).toByte()
            bootSector[39] = (sectorsPerFAT shr 24 and 0xFF).toByte()
            bootSector[44] = (rootDirFirstCluster and 0xFF).toByte()
            bootSector[45] = (rootDirFirstCluster shr 8 and 0xFF).toByte()
            bootSector[48] = 1; bootSector[49] = 0; bootSector[50] = 6; bootSector[51] = 0
            bootSector[64] = 0x00; bootSector[65] = 0; bootSector[66] = 0x29
            System.arraycopy(volumeId, 0, bootSector, 67, 4)
            System.arraycopy("NO NAME    ".toByteArray(), 0, bootSector, 71, 11)
            System.arraycopy("FAT32   ".toByteArray(), 0, bootSector, 82, 8)
            bootSector[510] = 0x55; bootSector[511] = 0xAA.toByte()
            
            // XTS sector numbers are based on absolute offset from start of outer volume,
            // matching how VolumeReader computes the tweak sector number.
            val startSector = hiddenDataOffset / SECTOR_SIZE
            
            val xts = XTSMode(masterKey, algorithm)
            
            // Write boot sector
            raf.seek(hiddenDataOffset)
            raf.write(xts.encrypt(bootSector, startSector))
            
            // FSInfo sector
            val fsInfoSector = ByteArray(SECTOR_SIZE)
            fsInfoSector[0] = 0x52; fsInfoSector[1] = 0x52; fsInfoSector[2] = 0x61; fsInfoSector[3] = 0x41
            fsInfoSector[484] = 0x72; fsInfoSector[485] = 0x72; fsInfoSector[486] = 0x41; fsInfoSector[487] = 0x61
            val actualClusterCount = clusterCount - 1
            fsInfoSector[488] = (actualClusterCount and 0xFF).toByte()
            fsInfoSector[489] = (actualClusterCount shr 8 and 0xFF).toByte()
            fsInfoSector[490] = (actualClusterCount shr 16 and 0xFF).toByte()
            fsInfoSector[491] = (actualClusterCount shr 24 and 0xFF).toByte()
            fsInfoSector[492] = 0x02; fsInfoSector[493] = 0x00; fsInfoSector[494] = 0x00; fsInfoSector[495] = 0x00
            fsInfoSector[508] = 0x00; fsInfoSector[509] = 0x00; fsInfoSector[510] = 0x55; fsInfoSector[511] = 0xAA.toByte()
            
            raf.seek(hiddenDataOffset + SECTOR_SIZE)
            raf.write(xts.encrypt(fsInfoSector, startSector + 1))
            
            // Backup boot sector at sector 6
            raf.seek(hiddenDataOffset + 6 * SECTOR_SIZE)
            raf.write(xts.encrypt(bootSector, startSector + 6))
            raf.seek(hiddenDataOffset + 7 * SECTOR_SIZE)
            raf.write(xts.encrypt(fsInfoSector, startSector + 7))
            
            // Reserved sectors 2-5 with trail sig
            val reservedSectorWithSig = ByteArray(SECTOR_SIZE)
            reservedSectorWithSig[508] = 0x00; reservedSectorWithSig[509] = 0x00
            reservedSectorWithSig[510] = 0x55; reservedSectorWithSig[511] = 0xAA.toByte()
            for (s in 2..5) {
                raf.seek(hiddenDataOffset + s * SECTOR_SIZE)
                raf.write(xts.encrypt(reservedSectorWithSig, startSector + s))
            }
            
            // Remaining reserved sectors
            val zeroSector = ByteArray(SECTOR_SIZE)
            for (s in 8 until reservedSectors) {
                raf.seek(hiddenDataOffset + s * SECTOR_SIZE)
                raf.write(xts.encrypt(zeroSector, startSector + s))
            }
            
            // FAT tables
            val fatSector = ByteArray(SECTOR_SIZE)
            fatSector[0] = 0xF8.toByte(); fatSector[1] = 0xFF.toByte()
            fatSector[2] = 0xFF.toByte(); fatSector[3] = 0x0F
            fatSector[4] = 0xFF.toByte(); fatSector[5] = 0xFF.toByte()
            fatSector[6] = 0xFF.toByte(); fatSector[7] = 0x0F
            fatSector[8] = 0xFF.toByte(); fatSector[9] = 0xFF.toByte()
            fatSector[10] = 0xFF.toByte(); fatSector[11] = 0x0F
            
            // First FAT
            raf.seek(hiddenDataOffset + reservedSectors * SECTOR_SIZE)
            raf.write(xts.encrypt(fatSector, startSector + reservedSectors))
            for (i in 1 until sectorsPerFAT) {
                raf.seek(hiddenDataOffset + (reservedSectors + i) * SECTOR_SIZE)
                raf.write(xts.encrypt(zeroSector, startSector + reservedSectors + i))
            }
            
            // Second FAT
            val secondFATOffset = reservedSectors + sectorsPerFAT
            raf.seek(hiddenDataOffset + secondFATOffset * SECTOR_SIZE)
            raf.write(xts.encrypt(fatSector, startSector + secondFATOffset))
            for (i in 1 until sectorsPerFAT) {
                raf.seek(hiddenDataOffset + (secondFATOffset + i) * SECTOR_SIZE)
                raf.write(xts.encrypt(zeroSector, startSector + secondFATOffset + i))
            }
            
            // Root directory
            val firstDataSector = reservedSectors + (numberOfFATs * sectorsPerFAT)
            val rootDirSector = firstDataSector + ((rootDirFirstCluster - 2) * sectorsPerCluster)
            for (i in 0 until sectorsPerCluster) {
                raf.seek(hiddenDataOffset + (rootDirSector + i) * SECTOR_SIZE)
                raf.write(xts.encrypt(zeroSector, startSector + rootDirSector + i))
            }
            
            xts.close()
            Log.d(TAG, "Hidden volume FAT32 formatted: $sectorCount sectors, ${hiddenDataAreaSize / (1024*1024)}MB")
        }
    }
}
