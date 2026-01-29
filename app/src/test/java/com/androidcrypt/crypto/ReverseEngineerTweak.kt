package com.androidcrypt.crypto

import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class ReverseEngineerTweak {
    
    @Test
    fun findCorrectTweak() {
        println("=== Reverse engineering correct tweak for block 1 ===")
        
        val key1 = ByteArray(16) { 0x00 }
        
        // Expected ciphertext for block 1
        val expectedCipherBlock1 = byteArrayOf(
            0xcd.toByte(), 0x43, 0xd7.toByte(), 0x48,
            0x37, 0x78, 0xab.toByte(), 0x52,
            0xa8.toByte(), 0x5c, 0x46, 0x74,
            0xd7.toByte(), 0x9a.toByte(), 0x8c.toByte(), 0x21
        )
        
        // XTS: ciphertext = AES(plaintext XOR tweak) XOR tweak
        // So: AES_decrypt(ciphertext XOR tweak) XOR tweak = plaintext (all zeros)
        // Let tweak_xor_cipher = ciphertext XOR tweak
        // Then: AES_decrypt(tweak_xor_cipher) = plaintext XOR tweak = 0 XOR tweak = tweak
        // So: tweak = AES_decrypt(ciphertext XOR tweak)
        
        // But we need to find tweak. Let's use the fact that plaintext is all zeros.
        // ciphertext = AES(0 XOR tweak) XOR tweak = AES(tweak) XOR tweak
        // So: AES_decrypt(ciphertext XOR tweak) = tweak
        // And: ciphertext XOR AES_decrypt(ciphertext XOR tweak) = cipher XOR tweak
        
        // Actually, for plaintext = 0:
        // cipher = AES(tweak) XOR tweak
        // So: AES_decrypt(cipher XOR tweak) = tweak
        // cipher XOR tweak = AES_encrypt(tweak)
        // So: AES_decrypt(cipher) XOR cipher = ???
        
        // Let me try: since plaintext=0, we have:
        // Post-whitening: encrypted XOR tweak = cipher
        // Pre-whitening: plaintext XOR tweak = tweak (since plaintext=0)
        // AES(tweak) XOR tweak = cipher
        
        //  So: cipher XOR tweak = AES(tweak)
        // And: AES_decrypt(cipher XOR tweak) = tweak
        
        // But I don't know tweak! Let me try a different approach.
        // I know what my multiply produces. Let me see what AES encryption of that produces:
        
        val myTweak = byteArrayOf(
            0xcc.toByte(), 0xd2.toByte(), 0x97.toByte(), 0xa8.toByte(),
            0xdf.toByte(), 0x15, 0x59, 0x76,
            0x10, 0x99.toByte(), 0xf4.toByte(), 0xb3.toByte(),
            0x94.toByte(), 0x69, 0x56, 0x5c
        )
        
        println("My tweak: ${myTweak.joinToString("") { "%02x".format(it) }}")
        
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key1, "AES"))
        val aesOfMyTweak = cipher.doFinal(myTweak)
        
        println("AES(my tweak): ${aesOfMyTweak.joinToString("") { "%02x".format(it) }}")
        
        // XOR with tweak to get ciphertext
        val myResult = ByteArray(16)
        for (i in 0 until 16) {
            myResult[i] = (aesOfMyTweak[i].toInt() xor myTweak[i].toInt()).toByte()
        }
        
        println("My result:     ${myResult.joinToString("") { "%02x".format(it) }}")
        println("Expected:      ${expectedCipherBlock1.joinToString("") { "%02x".format(it) }}")
    }
}
