package com.androidcrypt.crypto

import android.util.Log

/**
 * JNI wrapper for the native XTS cascade (Serpent-Twofish-AES) implementation.
 *
 * Implements VeraCrypt-compatible cascade encryption where each cipher runs a
 * full independent XTS pass over the buffer:
 *   Encrypt: Serpent → Twofish → AES
 *   Decrypt: AES → Twofish → Serpent
 *
 * Each cipher has its own 32-byte primary key and 32-byte secondary (tweak) key,
 * for a total of 192 bytes (96 primary + 96 secondary).
 *
 * Thread safety: the native context is read-only after creation (key schedules)
 * and all per-call state lives on the native stack, so [encryptSectors] /
 * [decryptSectors] can be called concurrently from multiple threads.
 */
object NativeCascadeSTA_XTS {
    private const val TAG = "NativeCascadeSTA_XTS"
    private var loaded = false

    init {
        try {
            System.loadLibrary("xts_aes_native")
            loaded = true
            Log.i(TAG, "Native cascade STA XTS library loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native cascade STA XTS library not available", e)
        }
    }

    /** True when the native library is loaded and functional. */
    fun isAvailable(): Boolean = loaded

    // ---- JNI functions ----

    /**
     * Create a native cascade XTS context from the two 96-byte key halves.
     * @param key1 Primary keys (96 bytes): Serpent[0–31] | Twofish[32–63] | AES[64–95]
     * @param key2 Secondary (tweak) keys (96 bytes): same layout
     * @return Opaque handle (non-zero on success, 0 on failure)
     */
    external fun createContext(key1: ByteArray, key2: ByteArray): Long

    /**
     * Destroy a previously created context and wipe key material.
     */
    external fun destroyContext(handle: Long)

    /**
     * Decrypt sectors in-place (AES → Twofish → Serpent).
     * @param handle    Context handle from [createContext]
     * @param data      Byte array containing encrypted sector data
     * @param startOffset Byte offset into [data] where sector data begins
     * @param startSectorNo XTS data-unit (sector) number of the first sector
     * @param sectorSize Size of each sector in bytes (must be multiple of 16)
     * @param sectorCount Number of consecutive sectors to decrypt
     */
    external fun decryptSectors(
        handle: Long,
        data: ByteArray,
        startOffset: Int,
        startSectorNo: Long,
        sectorSize: Int,
        sectorCount: Int
    )

    /**
     * Encrypt sectors in-place (Serpent → Twofish → AES).
     * @see [decryptSectors] for parameter descriptions
     */
    external fun encryptSectors(
        handle: Long,
        data: ByteArray,
        startOffset: Int,
        startSectorNo: Long,
        sectorSize: Int,
        sectorCount: Int
    )
}
