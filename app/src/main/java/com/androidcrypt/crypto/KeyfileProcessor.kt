package com.androidcrypt.crypto

import android.content.Context
import android.net.Uri
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.InputStream

/**
 * Processes keyfiles according to VeraCrypt specification.
 * 
 * Algorithm:
 * 1. Initialize a keyfile pool (64 or 128 bytes) to zeros
 * 2. For each keyfile:
 *    - Read up to 1MB of data
 *    - For each byte, update CRC32 and add the 4 CRC bytes to the pool (with wrapping)
 * 3. Mix the pool into the password by addition (mod 256)
 */
object KeyfileProcessor {
    
    private const val TAG = "KeyfileProcessor"
    
    // Constants matching VeraCrypt
    private const val KEYFILE_POOL_LEGACY_SIZE = 64  // For passwords <= 64 chars
    private const val KEYFILE_POOL_SIZE = 128        // For longer passwords
    private const val KEYFILE_MAX_READ_LEN = 1024 * 1024  // 1MB max per keyfile
    
    // CRC32 lookup table (same as VeraCrypt's crc_32_tab)
    private val CRC32_TABLE = intArrayOf(
        0x00000000.toInt(), 0x77073096, 0xee0e612c.toInt(), 0x990951ba.toInt(),
        0x076dc419, 0x706af48f, 0xe963a535.toInt(), 0x9e6495a3.toInt(),
        0x0edb8832, 0x79dcb8a4, 0xe0d5e91e.toInt(), 0x97d2d988.toInt(),
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07.toInt(), 0x90bf1d91.toInt(),
        0x1db71064, 0x6ab020f2, 0xf3b97148.toInt(), 0x84be41de.toInt(),
        0x1adad47d, 0x6ddde4eb, 0xf4d4b551.toInt(), 0x83d385c7.toInt(),
        0x136c9856, 0x646ba8c0, 0xfd62f97a.toInt(), 0x8a65c9ec.toInt(),
        0x14015c4f, 0x63066cd9, 0xfa0f3d63.toInt(), 0x8d080df5.toInt(),
        0x3b6e20c8, 0x4c69105e, 0xd56041e4.toInt(), 0xa2677172.toInt(),
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd.toInt(), 0xa50ab56b.toInt(),
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6.toInt(), 0xacbcf940.toInt(),
        0x32d86ce3, 0x45df5c75, 0xdcd60dcf.toInt(), 0xabd13d59.toInt(),
        0x26d930ac, 0x51de003a, 0xc8d75180.toInt(), 0xbfd06116.toInt(),
        0x21b4f4b5, 0x56b3c423, 0xcfba9599.toInt(), 0xb8bda50f.toInt(),
        0x2802b89e, 0x5f058808, 0xc60cd9b2.toInt(), 0xb10be924.toInt(),
        0x2f6f7c87, 0x58684c11, 0xc1611dab.toInt(), 0xb6662d3d.toInt(),
        0x76dc4190, 0x01db7106, 0x98d220bc.toInt(), 0xefd5102a.toInt(),
        0x71b18589, 0x06b6b51f, 0x9fbfe4a5.toInt(), 0xe8b8d433.toInt(),
        0x7807c9a2, 0x0f00f934, 0x9609a88e.toInt(), 0xe10e9818.toInt(),
        0x7f6a0dbb, 0x086d3d2d, 0x91646c97.toInt(), 0xe6635c01.toInt(),
        0x6b6b51f4, 0x1c6c6162, 0x856530d8.toInt(), 0xf262004e.toInt(),
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1.toInt(), 0xf50fc457.toInt(),
        0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea.toInt(), 0xfcb9887c.toInt(),
        0x62dd1ddf, 0x15da2d49, 0x8cd37cf3.toInt(), 0xfbd44c65.toInt(),
        0x4db26158, 0x3ab551ce, 0xa3bc0074.toInt(), 0xd4bb30e2.toInt(),
        0x4adfa541, 0x3dd895d7, 0xa4d1c46d.toInt(), 0xd3d6f4fb.toInt(),
        0x4369e96a, 0x346ed9fc, 0xad678846.toInt(), 0xda60b8d0.toInt(),
        0x44042d73, 0x33031de5, 0xaa0a4c5f.toInt(), 0xdd0d7cc9.toInt(),
        0x5005713c, 0x270241aa, 0xbe0b1010.toInt(), 0xc90c2086.toInt(),
        0x5768b525, 0x206f85b3, 0xb966d409.toInt(), 0xce61e49f.toInt(),
        0x5edef90e, 0x29d9c998, 0xb0d09822.toInt(), 0xc7d7a8b4.toInt(),
        0x59b33d17, 0x2eb40d81, 0xb7bd5c3b.toInt(), 0xc0ba6cad.toInt(),
        0xedb88320.toInt(), 0x9abfb3b6.toInt(), 0x03b6e20c, 0x74b1d29a,
        0xead54739.toInt(), 0x9dd277af.toInt(), 0x04db2615, 0x73dc1683,
        0xe3630b12.toInt(), 0x94643b84.toInt(), 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b.toInt(), 0x9309ff9d.toInt(), 0x0a00ae27, 0x7d079eb1,
        0xf00f9344.toInt(), 0x8708a3d2.toInt(), 0x1e01f268, 0x6906c2fe,
        0xf762575d.toInt(), 0x806567cb.toInt(), 0x196c3671, 0x6e6b06e7,
        0xfed41b76.toInt(), 0x89d32be0.toInt(), 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f.toInt(), 0x8ebeeff9.toInt(), 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8.toInt(), 0xa1d1937e.toInt(), 0x38d8c2c4, 0x4fdff252,
        0xd1bb67f1.toInt(), 0xa6bc5767.toInt(), 0x3fb506dd, 0x48b2364b,
        0xd80d2bda.toInt(), 0xaf0a1b4c.toInt(), 0x36034af6, 0x41047a60,
        0xdf60efc3.toInt(), 0xa867df55.toInt(), 0x316e8eef, 0x4669be79,
        0xcb61b38c.toInt(), 0xbc66831a.toInt(), 0x256fd2a0, 0x5268e236,
        0xcc0c7795.toInt(), 0xbb0b4703.toInt(), 0x220216b9, 0x5505262f,
        0xc5ba3bbe.toInt(), 0xb2bd0b28.toInt(), 0x2bb45a92, 0x5cb36a04,
        0xc2d7ffa7.toInt(), 0xb5d0cf31.toInt(), 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0.toInt(), 0xec63f226.toInt(), 0x756aa39c, 0x026d930a,
        0x9c0906a9.toInt(), 0xeb0e363f.toInt(), 0x72076785, 0x05005713,
        0x95bf4a82.toInt(), 0xe2b87a14.toInt(), 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b.toInt(), 0xe5d5be0d.toInt(), 0x7cdcefb7, 0x0bdbdf21,
        0x86d3d2d4.toInt(), 0xf1d4e242.toInt(), 0x68ddb3f8, 0x1fda836e,
        0x81be16cd.toInt(), 0xf6b9265b.toInt(), 0x6fb077e1, 0x18b74777,
        0x88085ae6.toInt(), 0xff0f6a70.toInt(), 0x66063bca, 0x11010b5c,
        0x8f659eff.toInt(), 0xf862ae69.toInt(), 0x616bffd3, 0x166ccf45,
        0xa00ae278.toInt(), 0xd70dd2ee.toInt(), 0x4e048354, 0x3903b3c2,
        0xa7672661.toInt(), 0xd06016f7.toInt(), 0x4969474d, 0x3e6e77db,
        0xaed16a4a.toInt(), 0xd9d65adc.toInt(), 0x40df0b66, 0x37d83bf0,
        0xa9bcae53.toInt(), 0xdebb9ec5.toInt(), 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c.toInt(), 0xcabac28a.toInt(), 0x53b39330, 0x24b4a3a6,
        0xbad03605.toInt(), 0xcdd70693.toInt(), 0x54de5729, 0x23d967bf,
        0xb3667a2e.toInt(), 0xc4614ab8.toInt(), 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37.toInt(), 0xc30c8ea1.toInt(), 0x5a05df1b, 0x2d02ef8d
    )
    
    /**
     * Update CRC32 with a single byte (UPDC32 macro from VeraCrypt)
     */
    private fun updateCrc32(octet: Byte, crc: Int): Int {
        return CRC32_TABLE[(crc xor (octet.toInt() and 0xFF)) and 0xFF] xor (crc ushr 8)
    }
    
    /**
     * Process keyfiles and apply them to the password.
     * Returns the modified password bytes that should be used for key derivation.
     * 
     * @param password The user's password (can be empty if only using keyfiles)
     * @param keyfiles List of keyfile paths or URIs
     * @param context Android context (required for content:// URIs)
     * @return The password bytes with keyfiles applied
     */
    fun applyKeyfiles(
        password: String,
        keyfiles: List<String>,
        context: Context? = null
    ): Result<ByteArray> {
        return try {
            if (keyfiles.isEmpty()) {
                // No keyfiles, just return password bytes
                return Result.success(password.toByteArray(Charsets.UTF_8))
            }
            
            val passwordBytes = password.toByteArray(Charsets.UTF_8)
            
            // Determine pool size based on password length (VeraCrypt behavior)
            val keyPoolSize = if (passwordBytes.size <= 64) {
                KEYFILE_POOL_LEGACY_SIZE
            } else {
                KEYFILE_POOL_SIZE
            }
            
            // Initialize keyfile pool to zeros
            val keyPool = ByteArray(keyPoolSize)
            
            Log.d(TAG, "Processing ${keyfiles.size} keyfile(s), pool size: $keyPoolSize")
            
            // Process each keyfile
            for (keyfilePath in keyfiles) {
                val result = processKeyfile(keyfilePath, keyPool, keyPoolSize, context)
                if (result.isFailure) {
                    Log.e(TAG, "Failed to process keyfile: $keyfilePath", result.exceptionOrNull())
                    return Result.failure(result.exceptionOrNull() ?: Exception("Failed to process keyfile"))
                }
            }
            
            // Mix the keyfile pool into the password
            // The result length is max(passwordLength, keyPoolSize)
            val resultLength = maxOf(passwordBytes.size, keyPoolSize)
            val result = ByteArray(resultLength)
            
            for (i in 0 until resultLength) {
                val passwordByte = if (i < passwordBytes.size) passwordBytes[i].toInt() and 0xFF else 0
                val poolByte = if (i < keyPoolSize) keyPool[i].toInt() and 0xFF else 0
                result[i] = ((passwordByte + poolByte) and 0xFF).toByte()
            }
            
            Log.d(TAG, "Keyfiles applied, result length: ${result.size}")
            
            Result.success(result)
        } catch (e: Exception) {
            Log.e(TAG, "Error applying keyfiles", e)
            Result.failure(e)
        }
    }
    
    /**
     * Process keyfiles from URIs (for Android SAF compatibility)
     */
    fun applyKeyfilesFromUris(
        password: String,
        keyfileUris: List<Uri>,
        context: Context
    ): Result<ByteArray> {
        return try {
            if (keyfileUris.isEmpty()) {
                return Result.success(password.toByteArray(Charsets.UTF_8))
            }
            
            val passwordBytes = password.toByteArray(Charsets.UTF_8)
            
            val keyPoolSize = if (passwordBytes.size <= 64) {
                KEYFILE_POOL_LEGACY_SIZE
            } else {
                KEYFILE_POOL_SIZE
            }
            
            val keyPool = ByteArray(keyPoolSize)
            
            Log.d(TAG, "Processing ${keyfileUris.size} keyfile URI(s), pool size: $keyPoolSize")
            
            for (uri in keyfileUris) {
                val result = processKeyfileFromUri(uri, keyPool, keyPoolSize, context)
                if (result.isFailure) {
                    Log.e(TAG, "Failed to process keyfile URI: $uri", result.exceptionOrNull())
                    return Result.failure(result.exceptionOrNull() ?: Exception("Failed to process keyfile"))
                }
            }
            
            val resultLength = maxOf(passwordBytes.size, keyPoolSize)
            val result = ByteArray(resultLength)
            
            for (i in 0 until resultLength) {
                val passwordByte = if (i < passwordBytes.size) passwordBytes[i].toInt() and 0xFF else 0
                val poolByte = if (i < keyPoolSize) keyPool[i].toInt() and 0xFF else 0
                result[i] = ((passwordByte + poolByte) and 0xFF).toByte()
            }
            
            Result.success(result)
        } catch (e: Exception) {
            Log.e(TAG, "Error applying keyfiles from URIs", e)
            Result.failure(e)
        }
    }
    
    /**
     * Process a single keyfile and add its contribution to the pool
     */
    private fun processKeyfile(
        keyfilePath: String,
        keyPool: ByteArray,
        keyPoolSize: Int,
        context: Context?
    ): Result<Unit> {
        return try {
            val inputStream: InputStream = if (keyfilePath.startsWith("content://")) {
                // Content URI - need context
                if (context == null) {
                    return Result.failure(Exception("Context required for content:// URIs"))
                }
                val uri = Uri.parse(keyfilePath)
                context.contentResolver.openInputStream(uri)
                    ?: return Result.failure(Exception("Cannot open keyfile URI: $keyfilePath"))
            } else {
                // File path
                FileInputStream(File(keyfilePath))
            }
            
            processInputStream(inputStream, keyPool, keyPoolSize)
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Process a keyfile from a content URI
     */
    private fun processKeyfileFromUri(
        uri: Uri,
        keyPool: ByteArray,
        keyPoolSize: Int,
        context: Context
    ): Result<Unit> {
        return try {
            val inputStream = context.contentResolver.openInputStream(uri)
                ?: return Result.failure(Exception("Cannot open keyfile URI: $uri"))
            
            processInputStream(inputStream, keyPool, keyPoolSize)
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Process an input stream and add its contribution to the keyfile pool.
     * This implements the core VeraCrypt keyfile algorithm.
     */
    private fun processInputStream(
        inputStream: InputStream,
        keyPool: ByteArray,
        keyPoolSize: Int
    ) {
        inputStream.use { stream ->
            var crc = 0xFFFFFFFF.toInt()  // Initial CRC value
            var writePos = 0
            var totalRead = 0L
            val buffer = ByteArray(64 * 1024)  // 64KB read buffer
            
            while (totalRead < KEYFILE_MAX_READ_LEN) {
                val bytesToRead = minOf(buffer.size, (KEYFILE_MAX_READ_LEN - totalRead).toInt())
                val bytesRead = stream.read(buffer, 0, bytesToRead)
                
                if (bytesRead <= 0) break
                
                for (i in 0 until bytesRead) {
                    if (totalRead >= KEYFILE_MAX_READ_LEN) break
                    
                    // Update CRC32 with this byte
                    crc = updateCrc32(buffer[i], crc)
                    
                    // Add the 4 CRC bytes to the pool (with addition, not XOR)
                    // This matches VeraCrypt's implementation exactly
                    keyPool[writePos] = ((keyPool[writePos].toInt() and 0xFF) + ((crc ushr 24) and 0xFF)).toByte()
                    writePos++
                    if (writePos >= keyPoolSize) writePos = 0
                    
                    keyPool[writePos] = ((keyPool[writePos].toInt() and 0xFF) + ((crc ushr 16) and 0xFF)).toByte()
                    writePos++
                    if (writePos >= keyPoolSize) writePos = 0
                    
                    keyPool[writePos] = ((keyPool[writePos].toInt() and 0xFF) + ((crc ushr 8) and 0xFF)).toByte()
                    writePos++
                    if (writePos >= keyPoolSize) writePos = 0
                    
                    keyPool[writePos] = ((keyPool[writePos].toInt() and 0xFF) + (crc and 0xFF)).toByte()
                    writePos++
                    if (writePos >= keyPoolSize) writePos = 0
                    
                    totalRead++
                }
            }
            
        }
    }
}
