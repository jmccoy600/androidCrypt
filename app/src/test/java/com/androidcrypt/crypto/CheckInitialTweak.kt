package com.androidcrypt.crypto

import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class CheckInitialTweak {
    
    @Test
    fun testInitialTweakEncryption() {
        println("=== Checking initial tweak encryption ===")
        
        // Key 2 (all zeros for Vector 1)
        val key2 = ByteArray(16)
        
        // Data unit 0
        val dataUnit = ByteArray(16)
        
        // Encrypt with AES
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key2, "AES"))
        val encryptedTweak = cipher.doFinal(dataUnit)
        
        println("Data unit: ${dataUnit.joinToString("") { "%02x".format(it) }}")
        println("Key 2: ${key2.joinToString("") { "%02x".format(it) }}")
        println("Encrypted tweak: ${encryptedTweak.joinToString("") { "%02x".format(it) }}")
        
        // This should be 66e94bd4ef8a2c3b884cfa59ca342b2e
        println("Expected:        66e94bd4ef8a2c3b884cfa59ca342b2e")
    }
}
