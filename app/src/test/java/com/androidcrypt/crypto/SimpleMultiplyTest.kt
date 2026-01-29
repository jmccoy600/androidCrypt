package com.androidcrypt.crypto

import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.nio.ByteOrder

class SimpleMultiplyTest {
    
    @Test
    fun testVector1BothBlocks() {
        println("=== Testing both blocks of Vector 1 ===")
        
        val key1 = ByteArray(16) { 0x00 }
        val key2 = ByteArray(16) { 0x00 }
        val plaintext = ByteArray(32) { 0x00 }
        
        // Expected ciphertext for both blocks from IEEE P1619
        val expected = byteArrayOf(
            0x91.toByte(), 0x7c, 0xf6.toByte(), 0x9e.toByte(),
            0xbd.toByte(), 0x68, 0xb2.toByte(), 0xec.toByte(),
            0x9b.toByte(), 0x9f.toByte(), 0xe9.toByte(), 0xa3.toByte(),
            0xea.toByte(), 0xdd.toByte(), 0xa6.toByte(), 0x92.toByte(),
            0xcd.toByte(), 0x43, 0xd7.toByte(), 0x48,
            0x37, 0x78, 0xab.toByte(), 0x52,
            0xa8.toByte(), 0x5c, 0x46, 0x74,
            0xd7.toByte(), 0x9a.toByte(), 0x8c.toByte(), 0x21
        )
        
        // Initialize tweak
        val tweak = ByteArray(16)
        ByteBuffer.wrap(tweak).order(ByteOrder.LITTLE_ENDIAN).putLong(0L)
        
        // Encrypt tweak with key2
        val tweakCipher = Cipher.getInstance("AES/ECB/NoPadding")
        tweakCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key2, "AES"))
        val encryptedTweak = tweakCipher.doFinal(tweak)
        
        println("Initial encrypted tweak: " + encryptedTweak.joinToString("") { "%02x".format(it) })
        
        // Encrypt block 0
        val dataCipher = Cipher.getInstance("AES/ECB/NoPadding")
        dataCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key1, "AES"))
        
        val block0 = ByteArray(16)
        for (i in 0 until 16) {
            block0[i] = (plaintext[i].toInt() xor encryptedTweak[i].toInt()).toByte()
        }
        val encrypted0 = dataCipher.doFinal(block0)
        val ciphertext0 = ByteArray(16)
        for (i in 0 until 16) {
            ciphertext0[i] = (encrypted0[i].toInt() xor encryptedTweak[i].toInt()).toByte()
        }
        
        println("Block 0 ciphertext: " + ciphertext0.joinToString("") { "%02x".format(it) })
        println("Block 0 expected:   " + expected.copyOfRange(0, 16).joinToString("") { "%02x".format(it) })
        println("Block 0 match: " + ciphertext0.contentEquals(expected.copyOfRange(0, 16)))
        println()
        
        // Multiply tweak by alpha for block 1
        val tweakCopy = encryptedTweak.copyOf()
        val finalCarry = if ((tweakCopy[15].toInt() and 0x80) != 0) 0x87 else 0
        var carry = 0
        for (i in 0 until 16) {
            val newCarry = (tweakCopy[i].toInt() and 0x80) ushr 7
            tweakCopy[i] = (((tweakCopy[i].toInt() and 0xFF) shl 1) or carry).toByte()
            carry = newCarry
        }
        tweakCopy[0] = (tweakCopy[0].toInt() xor finalCarry).toByte()
        
        println("Tweak for block 1: " + tweakCopy.joinToString("") { "%02x".format(it) })
        
        // Encrypt block 1
        val block1 = ByteArray(16)
        for (i in 0 until 16) {
            block1[i] = (plaintext[16 + i].toInt() xor tweakCopy[i].toInt()).toByte()
        }
        val encrypted1 = dataCipher.doFinal(block1)
        val ciphertext1 = ByteArray(16)
        for (i in 0 until 16) {
            ciphertext1[i] = (encrypted1[i].toInt() xor tweakCopy[i].toInt()).toByte()
        }
        
        println("Block 1 ciphertext: " + ciphertext1.joinToString("") { "%02x".format(it) })
        println("Block 1 expected:   " + expected.copyOfRange(16, 32).joinToString("") { "%02x".format(it) })
        println("Block 1 match: " + ciphertext1.contentEquals(expected.copyOfRange(16, 32)))
    }
}
