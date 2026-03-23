package com.androidcrypt.crypto

// Twofish block cipher – Dr Brian Gladman's implementation
// Adapted for TrueCrypt / VeraCrypt
// Bridged to Kotlin via JNI — the actual cipher runs as the unmodified C code
// in app/src/main/cpp/Twofish.c, compiled into the xts_aes_native shared library.

/**
 * Twofish block cipher backed by the native C implementation from
 * VeraCrypt's Crypto/Twofish.c (see app/src/main/cpp/Twofish.c).
 *
 * The C file is compiled verbatim into the xts_aes_native NDK library.
 * This class is a thin JNI wrapper — no cipher logic lives in Kotlin.
 *
 * Block size : 128 bits (16 bytes)
 * Key size   : 256 bits (32 bytes)
 */
class Twofish : AutoCloseable {

    // Opaque pointer to the native TwofishInstance allocation.
    private var handle: Long = 0L

    /**
     * Expand a 256-bit key into the native key schedule.
     *
     * @param key        32-byte key
     * @param forEncrypt ignored — Twofish uses the same key schedule for both
     *                   directions, matching VeraCrypt behaviour
     */
    fun init(key: ByteArray, @Suppress("UNUSED_PARAMETER") forEncrypt: Boolean = true) {
        require(key.size == 32) { "Twofish requires a 256-bit (32-byte) key" }
        if (handle != 0L) TwofishJNI.nativeDestroyKey(handle)
        handle = TwofishJNI.nativeSetKey(key)
        check(handle != 0L) { "twofish_set_key native allocation failed" }
    }

    /**
     * Encrypt a single 16-byte block.
     */
    fun encrypt(inBlock: ByteArray): ByteArray {
        checkInitialised()
        val out = ByteArray(16)
        TwofishJNI.nativeEncryptBlock(handle, inBlock, out)
        return out
    }

    /**
     * Decrypt a single 16-byte block.
     */
    fun decrypt(inBlock: ByteArray): ByteArray {
        checkInitialised()
        val out = ByteArray(16)
        TwofishJNI.nativeDecryptBlock(handle, inBlock, out)
        return out
    }

    /** Release the native key schedule and wipe key material. */
    override fun close() {
        if (handle != 0L) {
            TwofishJNI.nativeDestroyKey(handle)
            handle = 0L
        }
    }

    @Suppress("ProtectedInFinal")
    protected fun finalize() = close()

    private fun checkInitialised() =
        check(handle != 0L) { "Twofish not initialised — call init() first" }
}

/**
 * JNI declarations for the Twofish functions exported from xts_aes_native.so.
 * Maps to the four C functions added to xts_aes_native.cpp.
 */
object TwofishJNI {
    init {
        System.loadLibrary("xts_aes_native")
    }

    /** Allocate a native key schedule and run twofish_set_key. Returns a handle (non-zero on success). */
    external fun nativeSetKey(key: ByteArray): Long

    /** Zero and free a key schedule previously returned by [nativeSetKey]. */
    external fun nativeDestroyKey(handle: Long)

    /** Encrypt one 16-byte block via twofish_encrypt. */
    external fun nativeEncryptBlock(handle: Long, inBlock: ByteArray, outBlock: ByteArray)

    /** Decrypt one 16-byte block via twofish_decrypt. */
    external fun nativeDecryptBlock(handle: Long, inBlock: ByteArray, outBlock: ByteArray)
}
