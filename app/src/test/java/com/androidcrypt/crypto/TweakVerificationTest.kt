package com.androidcrypt.crypto

import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class TweakVerificationTest {
    
    @Test
    fun testAESEncryption() {
        // Key2 from test vector
        val key2 = byteArrayOf(
            0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97.toByte(), 0x93.toByte(),
            0x23, 0x84.toByte(), 0x62, 0x64, 0x33, 0x83.toByte(), 0x27, 0x95.toByte(),
            0x02, 0x88.toByte(), 0x41, 0x97.toByte(), 0x16, 0x93.toByte(), 0x99.toByte(), 0x37,
            0x51, 0x05, 0x82.toByte(), 0x09, 0x74, 0x94.toByte(), 0x45, 0x92.toByte()
        )
        
        // Initial tweak (data unit 0xff in little-endian)
        val tweak = byteArrayOf(
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff.toByte(),
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        
        println("Key2: " + key2.joinToString(" ") { "%02x".format(it) })
        println("Initial tweak: " + tweak.joinToString(" ") { "%02x".format(it) })
        
        // Encrypt with AES-256
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        val keySpec = SecretKeySpec(key2, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        
        val encryptedTweak = cipher.doFinal(tweak)
        println("Encrypted tweak (Java Cipher): " + encryptedTweak.joinToString(" ") { "%02x".format(it) })
    }
}
