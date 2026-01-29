package com.androidcrypt.crypto

import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class XTSManualTest {
    
    @Test
    fun testXTSManualCalculation() {
        // Key1
        val key1 = byteArrayOf(
            0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90.toByte(), 0x45,
            0x23, 0x53, 0x60, 0x28, 0x74, 0x71, 0x35, 0x26,
            0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93.toByte(), 0x69,
            0x99.toByte(), 0x59, 0x57, 0x49, 0x66, 0x96.toByte(), 0x76, 0x27
        )
        
        // Encrypted tweak (already computed)
        val encryptedTweak = byteArrayOf(
            0x42, 0xa7.toByte(), 0x51, 0xf7.toByte(), 0xb3.toByte(), 0x75, 0x30, 0xfd.toByte(),
            0x3a, 0x02, 0xf8.toByte(), 0xed.toByte(), 0x3f, 0x86.toByte(), 0x2f, 0xd1.toByte()
        )
        
        // First block of plaintext
        val plaintext = byteArrayOf(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        )
        
        // Step 1: XOR plaintext with tweak
        val step1 = ByteArray(16)
        for (i in 0..15) {
            step1[i] = (plaintext[i].toInt() xor encryptedTweak[i].toInt()).toByte()
        }
        println("Step 1 (plaintext XOR tweak): " + step1.joinToString(" ") { "%02x".format(it) })
        
        // Step 2: Encrypt with key1
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        val keySpec = SecretKeySpec(key1, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        val step2 = cipher.doFinal(step1)
        println("Step 2 (AES encrypt):         " + step2.joinToString(" ") { "%02x".format(it) })
        
        // Step 3: XOR with tweak again
        val ciphertext = ByteArray(16)
        for (i in 0..15) {
            ciphertext[i] = (step2[i].toInt() xor encryptedTweak[i].toInt()).toByte()
        }
        println("Step 3 (XOR with tweak):      " + ciphertext.joinToString(" ") { "%02x".format(it) })
        println("Expected ciphertext:          1c 3b 3a 10 2f 77 03 86 e4 83 6c 99 e3 70 cf 9b")
    }
}
