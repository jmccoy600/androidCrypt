package com.androidcrypt.crypto

import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/**
 * Convert a CharArray to UTF-8 encoded ByteArray without creating an intermediate String.
 *
 * This is critical for password handling: String objects are immutable and cannot be
 * reliably zeroed from memory on the JVM, while CharArray and ByteArray can be
 * explicitly filled with zeros when no longer needed.
 *
 * The caller is responsible for zeroing both the input CharArray and the returned
 * ByteArray when they are no longer needed.
 */
fun charArrayToUtf8Bytes(chars: CharArray): ByteArray {
    if (chars.isEmpty()) return ByteArray(0)
    val encoder = Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
    val charBuffer = CharBuffer.wrap(chars)
    val byteBuffer = encoder.encode(charBuffer)
    val result = ByteArray(byteBuffer.remaining())
    byteBuffer.get(result)
    // Zero the ByteBuffer's backing array to prevent password bytes lingering in heap
    if (byteBuffer.hasArray()) {
        byteBuffer.array().fill(0)
    }
    return result
}
