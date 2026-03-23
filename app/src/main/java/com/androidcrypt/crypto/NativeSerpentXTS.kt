package com.androidcrypt.crypto

import android.util.Log

/**
 * JNI wrapper for the native XTS-Serpent implementation.
 *
 * Uses the unmodified VeraCrypt Serpent block cipher (Crypto/Serpent.c) compiled
 * into the xts_aes_native shared library, with XTS mode logic ported from
 * VeraCrypt's src/Common/Xts.c (identical GF(2^128) tweak derivation).
 *
 * Thread safety: the native context is read-only after creation (key schedules)
 * and all per-call state lives on the native stack, so [encryptSectors] /
 * [decryptSectors] can be called concurrently from multiple threads without
 * synchronisation.
 */
object NativeSerpentXTS {
    private const val TAG = "NativeSerpentXTS"
    private var loaded = false

    init {
        try {
            System.loadLibrary("xts_aes_native")
            loaded = true
            Log.i(TAG, "Native Serpent-XTS library loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native Serpent-XTS library not available", e)
        }
    }

    /** True when the native library is loaded and functional. */
    fun isAvailable(): Boolean = loaded

    // ---- JNI functions ----

    /**
     * Create a native XTS-Serpent context from the two 256-bit keys.
     * @param key1 Data encryption key (32 bytes)
     * @param key2 Tweak encryption key (32 bytes)
     * @return Opaque handle (non-zero on success, 0 on failure)
     */
    external fun createContext(key1: ByteArray, key2: ByteArray): Long

    /**
     * Destroy a previously created context and wipe key material.
     */
    external fun destroyContext(handle: Long)

    /**
     * Decrypt sectors in-place.
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
     * Encrypt sectors in-place.
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
