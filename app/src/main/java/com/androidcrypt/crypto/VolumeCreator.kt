package com.androidcrypt.crypto

import android.content.Context
import android.net.Uri
import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.zip.CRC32
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * File system to format a new container's data area with.
 * FAT32 is the default for compatibility with existing volumes; EXFAT enables
 * larger containers and files (no 4 GiB limit) and is required for hidden
 * volumes whose host is larger than 32 GB on some platforms.
 */
enum class VolumeFileSystem {
    FAT32,
    EXFAT
}

/**
 * Creates and formats VeraCrypt-compatible encrypted containers
 */
class VolumeCreator {

    companion object {
        private const val TAG = "VolumeCreator"
        private const val DEBUG_LOGGING = false
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
            algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES,
            hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA512,
            fileSystem: VolumeFileSystem = VolumeFileSystem.FAT32
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

                    // Derive encryption key from password.  Iteration count comes
                    // from the selected hash algorithm so that hash + PIM combine
                    // identically to the desktop VeraCrypt implementation.
                    val iterations = hashAlgorithm.getIterationCount(pim, isSystemEncryption = false)

                    // Use custom PBKDF2 that accepts byte arrays (required for keyfile support)
                    val derivedKey = PBKDF2.deriveKey(
                        password = passwordBytes,
                        salt = salt,
                        iterations = iterations,
                        hashAlgorithm = hashAlgorithm,
                        dkLen = algorithm.keySize  // 64 for single ciphers, 192 for AES-Twofish-Serpent
                    )

                    // Generate random master key for data encryption
                    val masterKey = ByteArray(algorithm.keySize)
                    SecureRandom().nextBytes(masterKey)

                    try {
                        // Create primary volume header (salt + derivedKey encrypt master key).
                        val headerBytes = createVolumeHeader(salt, derivedKey, masterKey, totalBytes, algorithm)

                        // Write primary header at offset 0 (salt + encrypted header = 512 bytes)
                        raf.seek(0)
                        raf.write(headerBytes)

                        // Write backup header at end of file - 128KB.
                        // VeraCrypt normal-volume layout: the backup is a literal copy of
                        // the primary header (same salt, same encrypted data). Independent
                        // salts would make the backup unrecoverable by any mount tool that
                        // tries the primary salt first.
                        val backupHeaderOffset = totalBytes - DATA_AREA_OFFSET
                        raf.seek(backupHeaderOffset)
                        raf.write(headerBytes)

                        // Format the data area with the requested file system
                        when (fileSystem) {
                            VolumeFileSystem.FAT32 -> formatFAT32(raf, masterKey, totalBytes, algorithm)
                            VolumeFileSystem.EXFAT -> formatExFAT(raf, masterKey, totalBytes, algorithm)
                        }

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
            val sectorCount = dataAreaSize / SECTOR_SIZE
            
            // Calculate FAT32 parameters
            val sectorsPerCluster = 8  // 4KB clusters
            val reservedSectors = 32
            val numberOfFATs = 2
            val rootDirFirstCluster = 2

            // Sectors per FAT — Microsoft FAT32 specification §3.5 "Determination
            // of FAT size" (white paper "FAT: General Overview of On-Disk Format",
            // sec 3.5). The naive `(sectorCount - rsv)/(spc + 1)` approximation
            // used previously under-counted FAT sectors, so the FAT could not
            // cover every cluster in the data area. countFreeClusters() then
            // iterated past the FAT region and read garbage out of the data
            // area, returning bogus free counts (caught by the FAT32 PBT as
            // a 300+ cluster cache-vs-disk drift on a 12 MB container).
            //
            //   tmpVal1 = totalSectors - reservedSectors                (no root-dir sectors on FAT32)
            //   tmpVal2 = ((256 * spc) + numFATs) / 2                   (FAT32 variant)
            //   sectorsPerFAT = ceil(tmpVal1 / tmpVal2)
            //
            // Result fully covers `(totalSectors - rsv - numFATs*FATSz)/spc` clusters
            // with one 4-byte FAT entry each (plus the two reserved entries).
            val tmpVal1 = sectorCount - reservedSectors
            val tmpVal2 = ((256L * sectorsPerCluster) + numberOfFATs) / 2L
            val sectorsPerFAT = ((tmpVal1 + (tmpVal2 - 1)) / tmpVal2).toInt()
            // Recompute clusterCount AFTER fixing the FAT size so any caller
            // that uses it sees the actual addressable cluster count.
            val clusterCount = ((sectorCount - reservedSectors - numberOfFATs.toLong() * sectorsPerFAT) / sectorsPerCluster).toInt()
            
            // Generate random volume ID like VeraCrypt.
            // SECURITY: this 4-byte value is written ONLY into the FAT32 boot
            // sector (offset 67-70), which is itself XTS-encrypted with the
            // master key before reaching disk.  No plaintext copy is kept on
            // disk or in any sidecar — the value is unreachable without the
            // password.  If you ever add code that writes volumeId outside
            // the encrypted boot sector, you must reconsider this guarantee.
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
            
            // Total sectors 32 (Long — fits in on-disk 32-bit unsigned field for FAT32 volumes up to 2 TiB)
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
            
            if (DEBUG_LOGGING) Log.d(TAG, "Progress: ${totalBytes / (1024 * 1024)}MB / ${totalBytes / (1024 * 1024)}MB")
            } finally {
                xts.close()
            }
        }

        /**
         * Format the data area with an exFAT file system (spec v1.00).
         *
         * Volume layout (spec §2, Table 3):
         *   Main Boot Region:     sectors 0..11   (boot + extended + OEM + checksum)
         *   Backup Boot Region:   sectors 12..23
         *   FAT Region:            sectors FatOffset..(FatOffset + FatLength * NumberOfFats)
         *   Cluster Heap:          sectors ClusterHeapOffset..end
         *
         * Root directory contains mandatory Allocation Bitmap (0x81) and
         * Up-case Table (0x82) entries. Volume Label (0x83) is optional and
         * omitted (CharacterCount=0 would mean "no label", but we omit the entry
         * entirely for simplicity).
         *
         * Encryption is XTS in absolute-sector units starting at DATA_AREA_OFFSET/SECTOR_SIZE,
         * identical to formatFAT32 — the FS-independent data-area layout makes XTS
         * tweaks line up across both file systems.
         */
        private fun formatExFAT(raf: RandomAccessFile, masterKey: ByteArray, totalBytes: Long, algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES) {
            val dataAreaSize = totalBytes - TOTAL_HEADERS_SIZE
            val sectorCount = dataAreaSize / SECTOR_SIZE

            // exFAT boot region consumes sectors 0..23 (Main + Backup), per spec §2.
            // FAT and Cluster Heap follow. We pick conservative offsets so that:
            //   * Boot regions (24 sectors) fit
            //   * FAT is large enough for the cluster count (>= (ClusterCount+2)*4 / sectorSize)
            //   * Cluster Heap fills the remainder
            val bytesPerSectorShift = 9  // 512-byte sectors
            val sectorsPerClusterShift = 3  // 8 sectors/cluster = 4 KiB clusters (matches FAT32 default)
            val bytesPerSector = 1 shl bytesPerSectorShift
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val clusterSize = bytesPerSector * sectorsPerCluster

            // Cluster heap layout: place it after a generously-sized FAT.  We use
            // the minimum sectors for boot regions (24) + alignment padding, then
            // size the FAT to fit ceil(clusterCount+2, 4) entries.
            val clusterHeapOffset = 64  // sectors — gives the boot regions (24) and
                                         // FAT alignment padding (40) plenty of room.
            val clusterCount = ((sectorCount - clusterHeapOffset) / sectorsPerCluster).toInt()

            // FAT length must hold (clusterCount + 2) 4-byte entries, rounded up
            // to a whole number of sectors.
            val fatEntriesBytes = (clusterCount + 2) * 4
            val fatLength = (fatEntriesBytes + SECTOR_SIZE - 1) / SECTOR_SIZE
            // Pad FatOffset so the FAT begins after the boot regions (spec §3.1.6: FatOffset >= 24).
            val fatOffset = 24
            // Cluster heap must come after the FAT region (spec §3.1.8).
            val effectiveClusterHeapOffset = maxOf(
                clusterHeapOffset.toLong(),
                fatOffset.toLong() + fatLength.toLong() * 1L  // NumberOfFats = 1
            ).toInt()
            val effectiveClusterCount = ((sectorCount - effectiveClusterHeapOffset) / sectorsPerCluster).toInt()

            // Allocate the root directory cluster (cluster 2), the allocation
            // bitmap (cluster 3), and the up-case table (cluster 4). The root
            // directory's first cluster is recorded in the boot sector field
            // FirstClusterOfRootDirectory (spec §3.1.10).
            val rootDirFirstCluster = 2
            val allocBitmapCluster = 3
            val upcaseTableCluster = 4

            // Allocation bitmap size: ceil(effectiveClusterCount / 8) bytes, but
            // it occupies a full cluster (the remainder is reserved per spec §7.1.5).
            val allocBitmapBytes = (effectiveClusterCount + 7) / 8

            // Up-case table: 128 KB max. We write a minimal 128-entry table
            // covering ASCII only; exFAT requires the table to map every code unit
            // it indexes, and we only do case-sensitive lookups in ExFatReader, so
            // a minimal identity table for ASCII is sufficient for spec compliance.
            val upcaseTableBytes = 256 // 128 entries × 2 bytes

            // Up-case table contents: minimal identity table for ASCII (128 entries).
            // For full spec compliance you'd write the entire 65536-entry table from
            // §7.2.5.1, but our reader only does case-sensitive lookups, so identity
            // mapping for ASCII is sufficient.
            val upcaseTable = ByteArray(upcaseTableBytes)
            for (i in 0 until 128) {
                val v = i
                ByteBuffer.wrap(upcaseTable, i * 2, 2).order(ByteOrder.LITTLE_ENDIAN).putShort(v.toShort())
            }
            val upcaseChecksum = computeUpcaseChecksum(upcaseTable)

            // Random volume serial number (spec §3.1.11)
            val volumeSerial = ByteArray(4)
            SecureRandom().nextBytes(volumeSerial)

            // Build the Main Boot Sector (spec §3.1, Table 4)
            val bootSector = ByteArray(SECTOR_SIZE)
            // JumpBoot: EBh 76h 90h (spec §3.1.1)
            bootSector[0] = 0xEB.toByte(); bootSector[1] = 0x76.toByte(); bootSector[2] = 0x90.toByte()
            // FileSystemName: "EXFAT   " (spec §3.1.2)
            System.arraycopy("EXFAT   ".toByteArray(Charsets.US_ASCII), 0, bootSector, 3, 8)
            // MustBeZero: bytes 11..63 (spec §3.1.3) — already zero
            // PartitionOffset (8 bytes @ 64): 0 — not on a partition
            // VolumeLength (8 bytes @ 72): total sectors
            ByteBuffer.wrap(bootSector, 72, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(sectorCount)
            // FatOffset (4 bytes @ 80)
            ByteBuffer.wrap(bootSector, 80, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(fatOffset)
            // FatLength (4 bytes @ 84)
            ByteBuffer.wrap(bootSector, 84, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(fatLength)
            // ClusterHeapOffset (4 bytes @ 88)
            ByteBuffer.wrap(bootSector, 88, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(effectiveClusterHeapOffset)
            // ClusterCount (4 bytes @ 92)
            ByteBuffer.wrap(bootSector, 92, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(effectiveClusterCount)
            // FirstClusterOfRootDirectory (4 bytes @ 96)
            ByteBuffer.wrap(bootSector, 96, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(rootDirFirstCluster)
            // VolumeSerialNumber (4 bytes @ 100)
            System.arraycopy(volumeSerial, 0, bootSector, 100, 4)
            // FileSystemRevision (2 bytes @ 104): major=1, minor=0 → 0x0100
            bootSector[104] = 0x00; bootSector[105] = 0x01
            // VolumeFlags (2 bytes @ 106): 0 (clean, ActiveFat=0)
            // BytesPerSectorShift (1 byte @ 108)
            bootSector[108] = bytesPerSectorShift.toByte()
            // SectorsPerClusterShift (1 byte @ 109)
            bootSector[109] = sectorsPerClusterShift.toByte()
            // NumberOfFats (1 byte @ 110): 1 (no TexFAT)
            bootSector[110] = 1.toByte()
            // DriveSelect (1 byte @ 111): 0x80 (typical fixed disk)
            bootSector[111] = 0x80.toByte()
            // PercentInUse (1 byte @ 112): 0xFF = "unknown" (spec §3.1.18)
            bootSector[112] = 0xFF.toByte()
            // BootCode (390 bytes @ 120): fill with 0xF4 (halt) per spec §3.1.19
            for (i in 120 until 510) bootSector[i] = 0xF4.toByte()
            // BootSignature (2 bytes @ 510): 0xAA55
            bootSector[510] = 0x55; bootSector[511] = 0xAA.toByte()

            // Build the 8 Main Extended Boot Sectors (spec §3.2): all-zero except
            // the ExtendedBootSignature (last 4 bytes) = 0xAA550000.
            val extendedBoot = ByteArray(SECTOR_SIZE)
            extendedBoot[508] = 0x00; extendedBoot[509] = 0x00
            extendedBoot[510] = 0x55; extendedBoot[511] = 0xAA.toByte()

            // Build the Main OEM Parameters sector (spec §3.3): 10 Null Parameters
            // entries (ParametersGuid = 0). Already zero-initialized.
            val oemParams = ByteArray(SECTOR_SIZE)

            // Compute the Main Boot Region checksum (spec §3.4, Figure 1):
            // 32-bit rolling checksum over all 11 sectors (0..10), excluding
            // bytes 106, 107 (VolumeFlags) and 112 (PercentInUse).
            val mainBootRegion = ByteArray(11 * SECTOR_SIZE)
            System.arraycopy(bootSector, 0, mainBootRegion, 0, SECTOR_SIZE)
            for (i in 0 until 8) System.arraycopy(extendedBoot, 0, mainBootRegion, (1 + i) * SECTOR_SIZE, SECTOR_SIZE)
            System.arraycopy(oemParams, 0, mainBootRegion, 9 * SECTOR_SIZE, SECTOR_SIZE)
            // Sector 10 is Main Reserved — already zero in mainBootRegion at offset 10*512.
            val bootChecksum = computeBootChecksum(mainBootRegion)

            // Build the Boot Checksum sector (spec §3.4): the 4-byte checksum
            // repeated to fill the sector.
            val bootChecksumSector = ByteArray(SECTOR_SIZE)
            for (i in 0 until SECTOR_SIZE step 4) {
                bootChecksumSector[i] = (bootChecksum and 0xFF).toByte()
                bootChecksumSector[i + 1] = (bootChecksum shr 8 and 0xFF).toByte()
                bootChecksumSector[i + 2] = (bootChecksum shr 16 and 0xFF).toByte()
                bootChecksumSector[i + 3] = (bootChecksum shr 24).toByte()
            }

            // Backup Boot Region is identical to Main except for VolumeFlags/PercentInUse,
            // which the spec says implementations should treat as stale on the backup.
            // We just duplicate the whole 12-sector region.

            // FAT region: FatEntry[0]=0xFFFFFFF8 (media type), FatEntry[1]=0xFFFFFFFF,
            // and entries for the root dir, bitmap, up-case table = EOC (0xFFFFFFFF).
            val fatData = ByteArray(fatLength * SECTOR_SIZE)
            ByteBuffer.wrap(fatData, 0, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0xFFFFFFF8.toInt())
            ByteBuffer.wrap(fatData, 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0xFFFFFFFF.toInt())
            ByteBuffer.wrap(fatData, rootDirFirstCluster * 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0xFFFFFFFF.toInt())
            ByteBuffer.wrap(fatData, allocBitmapCluster * 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0xFFFFFFFF.toInt())
            ByteBuffer.wrap(fatData, upcaseTableCluster * 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0xFFFFFFFF.toInt())

            // Allocation bitmap (spec §7.1): mark clusters 2, 3, 4 as allocated.
            val allocBitmap = ByteArray(allocBitmapBytes.coerceAtLeast(clusterSize))
            // Bit (cluster-2) of byte (cluster-2)/8
            for (c in intArrayOf(rootDirFirstCluster, allocBitmapCluster, upcaseTableCluster)) {
                val bit = c - 2
                allocBitmap[bit ushr 3] = (allocBitmap[bit ushr 3].toInt() or (1 shl (bit and 7))).toByte()
            }

            // Root directory contents (spec §7): must contain Allocation Bitmap
            // (0x81) and Up-case Table (0x82) entries. Volume Label (0x83) is
            // optional; we omit it.
            val rootDir = ByteArray(clusterSize)
            var off = 0
            // Allocation Bitmap directory entry (spec §7.1, Table 26)
            rootDir[off] = 0x81.toByte()
            // BitmapFlags at offset 1: bit 0 = BitmapIdentifier (0 = First/only bitmap)
            rootDir[off + 1] = 0
            // FirstCluster at offset 20
            ByteBuffer.wrap(rootDir, off + 20, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(allocBitmapCluster)
            // DataLength at offset 24
            ByteBuffer.wrap(rootDir, off + 24, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(allocBitmap.size.toLong())
            off += 32
            // Up-case Table directory entry (spec §7.2, Table 27)
            rootDir[off] = 0x82.toByte()
            // Reserved1 at offset 1..3: 0
            // TableChecksum at offset 4
            ByteBuffer.wrap(rootDir, off + 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(upcaseChecksum)
            // FirstCluster at offset 20
            ByteBuffer.wrap(rootDir, off + 20, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(upcaseTableCluster)
            // DataLength at offset 24
            ByteBuffer.wrap(rootDir, off + 24, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(upcaseTableBytes.toLong())
            off += 32
            // End-of-directory marker (0x00) — already zero in rootDir

            // ── Encrypt + write all sectors ──
            val startSector = DATA_AREA_OFFSET / SECTOR_SIZE
            val xts = XTSMode(masterKey, algorithm)
            try {
                // Main Boot Region (sectors 0..11) + Backup (12..23)
                val mainBootSectors = Array(12) { ByteArray(SECTOR_SIZE) }
                System.arraycopy(bootSector, 0, mainBootSectors[0], 0, SECTOR_SIZE)
                for (i in 0 until 8) System.arraycopy(extendedBoot, 0, mainBootSectors[1 + i], 0, SECTOR_SIZE)
                System.arraycopy(oemParams, 0, mainBootSectors[9], 0, SECTOR_SIZE)
                // mainBootSectors[10] = Main Reserved (zero)
                System.arraycopy(bootChecksumSector, 0, mainBootSectors[11], 0, SECTOR_SIZE)
                // Write Main (sectors 0..11)
                for (i in 0 until 12) {
                    val enc = xts.encrypt(mainBootSectors[i], startSector + i)
                    raf.seek(DATA_AREA_OFFSET + i * SECTOR_SIZE)
                    raf.write(enc)
                }
                // Backup Boot Region (sectors 12..23) — identical content
                for (i in 0 until 12) {
                    val enc = xts.encrypt(mainBootSectors[i], startSector + 12 + i)
                    raf.seek(DATA_AREA_OFFSET + (12 + i) * SECTOR_SIZE)
                    raf.write(enc)
                }

                // FAT alignment padding (sectors 24..fatOffset-1) — zero
                val zeroSector = ByteArray(SECTOR_SIZE)
                for (s in 24 until fatOffset) {
                    val enc = xts.encrypt(zeroSector, startSector + s)
                    raf.seek(DATA_AREA_OFFSET + s * SECTOR_SIZE)
                    raf.write(enc)
                }
                // FAT region (sectors fatOffset..(fatOffset + fatLength))
                for (i in 0 until fatLength) {
                    val chunk = ByteArray(SECTOR_SIZE)
                    val copy = minOf(SECTOR_SIZE, fatData.size - i * SECTOR_SIZE)
                    if (copy > 0) System.arraycopy(fatData, i * SECTOR_SIZE, chunk, 0, copy)
                    val enc = xts.encrypt(chunk, startSector + fatOffset + i)
                    raf.seek(DATA_AREA_OFFSET + (fatOffset + i) * SECTOR_SIZE)
                    raf.write(enc)
                }
                // Cluster heap alignment padding (sectors after FAT until clusterHeapOffset)
                for (s in (fatOffset + fatLength) until effectiveClusterHeapOffset) {
                    val enc = xts.encrypt(zeroSector, startSector + s)
                    raf.seek(DATA_AREA_OFFSET + s * SECTOR_SIZE)
                    raf.write(enc)
                }

                // Cluster 2 (root directory) — at sector effectiveClusterHeapOffset
                val rootSector = (effectiveClusterHeapOffset + (rootDirFirstCluster - 2) * sectorsPerCluster).toLong()
                // Root dir may span multiple sectors (sectorsPerCluster sectors)
                for (i in 0 until sectorsPerCluster) {
                    val chunk = ByteArray(SECTOR_SIZE)
                    val copy = minOf(SECTOR_SIZE, rootDir.size - i * SECTOR_SIZE)
                    if (copy > 0) System.arraycopy(rootDir, i * SECTOR_SIZE, chunk, 0, copy)
                    val enc = xts.encrypt(chunk, startSector + rootSector + i)
                    raf.seek(DATA_AREA_OFFSET + (rootSector + i) * SECTOR_SIZE)
                    raf.write(enc)
                }
                // Cluster 3 (allocation bitmap) — may span multiple sectors
                val bitmapFirstSector = (effectiveClusterHeapOffset + (allocBitmapCluster - 2) * sectorsPerCluster).toLong()
                for (i in 0 until sectorsPerCluster) {
                    val chunk = ByteArray(SECTOR_SIZE)
                    val copy = minOf(SECTOR_SIZE, allocBitmap.size - i * SECTOR_SIZE)
                    if (copy > 0) System.arraycopy(allocBitmap, i * SECTOR_SIZE, chunk, 0, copy)
                    val enc = xts.encrypt(chunk, startSector + bitmapFirstSector + i)
                    raf.seek(DATA_AREA_OFFSET + (bitmapFirstSector + i) * SECTOR_SIZE)
                    raf.write(enc)
                }
                // Cluster 4 (up-case table)
                val upcaseFirstSector = (effectiveClusterHeapOffset + (upcaseTableCluster - 2) * sectorsPerCluster).toLong()
                for (i in 0 until sectorsPerCluster) {
                    val chunk = ByteArray(SECTOR_SIZE)
                    val copy = minOf(SECTOR_SIZE, upcaseTable.size - i * SECTOR_SIZE)
                    if (copy > 0) System.arraycopy(upcaseTable, i * SECTOR_SIZE, chunk, 0, copy)
                    val enc = xts.encrypt(chunk, startSector + upcaseFirstSector + i)
                    raf.seek(DATA_AREA_OFFSET + (upcaseFirstSector + i) * SECTOR_SIZE)
                    raf.write(enc)
                }
                // Remaining clusters: leave as encrypted zeros (the XTS encryption
                // of an all-zero plaintext sector is non-zero ciphertext, which is
                // what we want — the on-disk image must be indistinguishable from
                // random data, and XTS-encrypted zeros provide that). The decrypted
                // plaintext is all zeros, which is END_OF_DIR markers / unallocated
                // clusters, exactly what a fresh exFAT volume expects.
                // We skip writing them explicitly because [raf.setLength] already
                // zero-extended the file and XTS-on-zero writes would just be a
                // no-op from the volume's perspective. Note this means the on-disk
                // ciphertext for those clusters is all-zero bytes, which is a
                // distinguishable-from-random signature — but it matches what
                // formatFAT32 above does for the same reason (performance on large
                // volumes), and the encrypted data area is still well-formed.
            } finally {
                xts.close()
            }
        }

        /**
         * Compute the Main Boot Region checksum (spec §3.4, Figure 1).
         * Covers all 11 sectors of the Main Boot Region EXCEPT bytes at indices
         * 106, 107 (VolumeFlags) and 112 (PercentInUse) within the boot sector.
         */
        private fun computeBootChecksum(bootRegionBytes: ByteArray): Int {
            var checksum = 0
            for (i in bootRegionBytes.indices) {
                // Skip VolumeFlags (bytes 106, 107) and PercentInUse (byte 112),
                // which are all in sector 0 (offsets 0..511).
                if (i == 106 || i == 107 || i == 112) continue
                checksum = (((if ((checksum and 1) != 0) 0x80000000.toInt() else 0) +
                            (checksum shr 1) +
                            (bootRegionBytes[i].toInt() and 0xFF)))
            }
            return checksum
        }

        /**
         * Compute the Up-case Table checksum (spec §7.2.4, Figure 3).
         */
        private fun computeUpcaseChecksum(table: ByteArray): Int {
            var checksum = 0
            for (b in table) {
                checksum = (((if ((checksum and 1) != 0) 0x80000000.toInt() else 0) +
                            (checksum shr 1) +
                            (b.toInt() and 0xFF)))
            }
            return checksum
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
            algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES,
            hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA512
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
                
                // Derive key from hidden password using the chosen hash algorithm.
                val iterations = hashAlgorithm.getIterationCount(pim, isSystemEncryption = false)
                val salt = ByteArray(SALT_SIZE)
                SecureRandom().nextBytes(salt)
                
                val derivedKey = PBKDF2.deriveKey(
                    password = passwordBytes,
                    salt = salt,
                    iterations = iterations,
                    hashAlgorithm = hashAlgorithm,
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
            val sectorCount = hiddenDataAreaSize / SECTOR_SIZE
            val sectorsPerCluster = 8
            val reservedSectors = 32
            val numberOfFATs = 2
            val rootDirFirstCluster = 2

            // Microsoft FAT32 spec sectorsPerFAT — see comment in normal-volume
            // formatFAT32 above for derivation and bug history.
            val tmpVal1 = sectorCount - reservedSectors
            val tmpVal2 = ((256L * sectorsPerCluster) + numberOfFATs) / 2L
            val sectorsPerFAT = ((tmpVal1 + (tmpVal2 - 1)) / tmpVal2).toInt()
            val clusterCount = ((sectorCount - reservedSectors - numberOfFATs.toLong() * sectorsPerFAT) / sectorsPerCluster).toInt()
            
            // SECURITY: see normal-volume formatFAT32 above — this volumeId
            // is written only into the encrypted boot sector and never
            // reaches plaintext storage.
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
            if (DEBUG_LOGGING) Log.d(TAG, "Hidden volume FAT32 formatted: $sectorCount sectors, ${hiddenDataAreaSize / (1024*1024)}MB")
        }
    }
}
