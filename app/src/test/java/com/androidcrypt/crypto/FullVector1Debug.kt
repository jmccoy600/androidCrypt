package com.androidcrypt.crypto

import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class FullVector1Debug {
    
    @Test
    fun debugFullVector1() {
        println("=== Debugging full Vector 1 (32 bytes) ===")
        
        val key1 = ByteArray(16) { 0x00 }
        val key2 = ByteArray(16) { 0x00 }
        val fullKey = ByteArray(32)
        System.arraycopy(key1, 0, fullKey, 0, 16)
        System.arraycopy(key2, 0, fullKey, 16, 16)
        
        val xts = XTSMode(fullKey, EncryptionAlgorithm.AES)
        val plaintext = ByteArray(32) { 0x00 }
        val ciphertext = xts.encrypt(plaintext, 0L)
        
        println("Ciphertext: ${ciphertext.joinToString("") { "%02x".format(it) }}")
        println("Expected:   917cf69ebd68b2ec9b9fe9a3eadda692cd43d7483778ab52a85c4674d79a8c21")
        
        println("\nBlock 0 (bytes 0-15):")
        println("  Got:      ${ciphertext.copyOfRange(0, 16).joinToString("") { "%02x".format(it) }}")
        println("  Expected: 917cf69ebd68b2ec9b9fe9a3eadda692")
        
        println("\nBlock 1 (bytes 16-31):")
        println("  Got:      ${ciphertext.copyOfRange(16, 32).joinToString("") { "%02x".format(it) }}")
        println("  Expected: cd43d7483778ab52a85c4674d79a8c21")
    }
}
