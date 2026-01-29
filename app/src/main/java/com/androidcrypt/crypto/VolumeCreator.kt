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
         * @return Result with success/error message
         */
        fun createContainer(
            containerPath: String,
            password: String,
            sizeInMB: Long,
            pim: Int = 0,
            keyfileUris: List<Uri> = emptyList(),
            context: Context? = null
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
                
                Log.d(TAG, "Creating container: $containerPath, size: ${sizeInMB}MB")
                
                // Apply keyfiles to password if any
                val passwordBytes: ByteArray = if (keyfileUris.isNotEmpty() && context != null) {
                    Log.d(TAG, "Applying ${keyfileUris.size} keyfile(s)...")
                    val result = KeyfileProcessor.applyKeyfilesFromUris(password, keyfileUris, context)
                    if (result.isFailure) {
                        return Result.failure(result.exceptionOrNull() ?: Exception("Failed to process keyfiles"))
                    }
                    result.getOrThrow()
                } else {
                    password.toByteArray(Charsets.UTF_8)
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
                    
                    Log.d(TAG, "Deriving key from password...")
                    
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
                        dkLen = 64  // 64 bytes for AES-256 in XTS mode (2 x 32-byte keys)
                    )
                    
                    // Generate random master key for data encryption
                    val masterKey = ByteArray(64)
                    SecureRandom().nextBytes(masterKey)
                    
                    // Create volume header
                    val headerBytes = createVolumeHeader(salt, derivedKey, masterKey, totalBytes)
                    
                    // Write primary header at offset 0 (salt + encrypted header = 512 bytes)
                    raf.seek(0)
                    raf.write(headerBytes)
                    
                    // Write backup header at end of file - 128KB
                    // VeraCrypt layout: backup header at (dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE) 
                    // = (totalBytes - 256KB) + 128KB = totalBytes - 128KB
                    val backupHeaderOffset = totalBytes - DATA_AREA_OFFSET
                    raf.seek(backupHeaderOffset)
                    raf.write(headerBytes)
                    
                    Log.d(TAG, "Primary header at offset 0, backup header at offset $backupHeaderOffset")
                    
                    // Format the data area with FAT32 file system
                    formatFAT32(raf, masterKey, totalBytes)
                    
                    Log.d(TAG, "FAT32 file system created")
                }
                
                Log.d(TAG, "Container created successfully")
                Result.success("Container created successfully at $containerPath")
                
            } catch (e: Exception) {
                Log.e(TAG, "Error creating container", e)
                Result.failure(e)
            }
        }
        
        /**
         * Create an encrypted volume header
         */
        private fun createVolumeHeader(
            salt: ByteArray,
            derivedKey: ByteArray,
            masterKey: ByteArray,
            volumeSize: Long
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
            
            // Encrypt the 448-byte header data using XTS-AES mode
            val xts = XTSMode(derivedKey, EncryptionAlgorithm.AES)
            val encryptedData = xts.encrypt(unencryptedData, 0)
            
            // Create final result: salt (64 bytes) + encrypted data (448 bytes) = 512 bytes
            val result = ByteArray(512)
            System.arraycopy(salt, 0, result, 0, SALT_SIZE)  // Unencrypted salt
            System.arraycopy(encryptedData, 0, result, 64, 448)  // Encrypted header data
            
            return result
        }
        
        /**
         * Format the data area with FAT32 file system
         */
        private fun formatFAT32(raf: RandomAccessFile, masterKey: ByteArray, totalBytes: Long) {
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
            val xts = XTSMode(masterKey, EncryptionAlgorithm.AES)
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
    }
}
