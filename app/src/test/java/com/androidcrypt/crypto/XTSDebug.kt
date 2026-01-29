package com.androidcrypt.crypto

import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.nio.ByteOrder

class XTSDebug {
    
    @Test
    fun debugXTSVector1() {
        println("=== XTS-AES Vector 1 Debug ===")
        
        // Keys - IEEE P1619 Vector 1 is for XTS-AES-128 (16-byte keys each)
        val key1 = ByteArray(16) { 0x00 }
        val key2 = ByteArray(16) { 0x00 }
        
        println("Key1: ${key1.toHexString()}")
        println("Key2: ${key2.toHexString()}")
        
        // Data unit 0
        val dataUnitNo = 0L
        val plaintext = ByteArray(16) { 0x00 }  // First block only
        
        println("\nPlaintext block 0: ${plaintext.toHexString()}")
        
        // Step 1: Create tweak
        val tweak = ByteArray(16)
        val tweakBuffer = ByteBuffer.wrap(tweak).order(ByteOrder.LITTLE_ENDIAN)
        tweakBuffer.putLong(dataUnitNo)
        println("\nTweak before encryption: ${tweak.toHexString()}")
        
        // Step 2: Encrypt tweak with key2
        val tweakCipher = Cipher.getInstance("AES/ECB/NoPadding")
        tweakCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key2, "AES"))
        val encryptedTweak = tweakCipher.doFinal(tweak)
        println("Encrypted tweak: ${encryptedTweak.toHexString()}")
        
        // Step 3: XOR plaintext with encrypted tweak
        val preEncrypt = ByteArray(16)
        for (i in preEncrypt.indices) {
            preEncrypt[i] = (plaintext[i].toInt() xor encryptedTweak[i].toInt()).toByte()
        }
        println("\nAfter XOR with tweak: ${preEncrypt.toHexString()}")
        
        // Step 4: Encrypt with key1
        val dataCipher = Cipher.getInstance("AES/ECB/NoPadding")
        dataCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key1, "AES"))
        val encrypted = dataCipher.doFinal(preEncrypt)
        println("After AES encrypt: ${encrypted.toHexString()}")
        
        // Step 5: XOR with tweak again
        val ciphertext = ByteArray(16)
        for (i in ciphertext.indices) {
            ciphertext[i] = (encrypted[i].toInt() xor encryptedTweak[i].toInt()).toByte()
        }
        println("Final ciphertext: ${ciphertext.toHexString()}")
        
        // Expected from IEEE P1619 test vector 1
        val expected = "917cf69ebd68b2ec9b9fe9a3eadda692"
        println("\nExpected ciphertext: $expected")
        println("Match: ${ciphertext.toHexString() == expected}")
    }
    
    @Test
    fun debugXTSVector10FirstBlock() {
        println("=== XTS-AES Vector 10 First Block Debug ===")
        
        // Try with FULL 32-byte keys (AES-256) - IEEE P1619 vectors 10-18 are for AES-256
        val key1_full = byteArrayOf(
            0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90.toByte(), 0x45,
            0x23, 0x53, 0x60, 0x28, 0x74, 0x71, 0x35, 0x26,
            0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93.toByte(), 0x69,
            0x99.toByte(), 0x59, 0x57, 0x49, 0x66, 0x96.toByte(), 0x76, 0x27
        )
        
        val key2_full = byteArrayOf(
            0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97.toByte(), 0x93.toByte(),
            0x23, 0x84.toByte(), 0x62, 0x64, 0x33, 0x83.toByte(), 0x27, 0x95.toByte(),
            0x02, 0x88.toByte(), 0x41, 0x97.toByte(), 0x16, 0x93.toByte(), 0x99.toByte(), 0x37,
            0x51, 0x05, 0x82.toByte(), 0x09, 0x74, 0x94.toByte(), 0x45, 0x92.toByte()
        )
        
        val dataUnitNo = 0xffL
        val plaintext = ByteArray(16) { it.toByte() }  // 0x00 to 0x0F
        
        println("Testing with 32-byte keys (AES-256):")
        println("Plaintext: ${plaintext.toHexString()}")
        
        val tweak = ByteArray(16)
        val tweakBuffer = ByteBuffer.wrap(tweak).order(ByteOrder.LITTLE_ENDIAN)
        tweakBuffer.putLong(dataUnitNo)
        println("Tweak before encryption: ${tweak.toHexString()}")
        
        val tweakCipher = Cipher.getInstance("AES/ECB/NoPadding")
        tweakCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key2_full, "AES"))
        val encryptedTweak = tweakCipher.doFinal(tweak)
        println("Encrypted tweak: ${encryptedTweak.toHexString()}")
        
        val preEncrypt = ByteArray(16)
        for (i in preEncrypt.indices) {
            preEncrypt[i] = (plaintext[i].toInt() xor encryptedTweak[i].toInt()).toByte()
        }
        println("After XOR with tweak: ${preEncrypt.toHexString()}")
        
        val dataCipher = Cipher.getInstance("AES/ECB/NoPadding")
        dataCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key1_full, "AES"))
        val encrypted = dataCipher.doFinal(preEncrypt)
        println("After AES encrypt: ${encrypted.toHexString()}")
        
        val ciphertext = ByteArray(16)
        for (i in ciphertext.indices) {
            ciphertext[i] = (encrypted[i].toInt() xor encryptedTweak[i].toInt()).toByte()
        }
        println("Ciphertext: ${ciphertext.toHexString()}")
        
        val expected = "1c3b3a102f770386e4836c99e370cf9b"
        println("Expected:   $expected")
        println("Match: ${ciphertext.toHexString() == expected}")
    }
    
    @Test
    fun debugMultiplyByAlpha() {
        println("=== Testing multiplyByAlpha ===")
        
        // Start with a simple test: all zeros
        val tweakZero = ByteArray(16) { 0x00 }
        println("Test 1 - All zeros:")
        println("  Before: ${tweakZero.toHexString()}")
        
        val xtsClass = Class.forName("com.androidcrypt.crypto.XTSMode")
        val key = ByteArray(32)
        val xtsInstance = xtsClass.getConstructor(
            ByteArray::class.java,
            Class.forName("com.androidcrypt.crypto.EncryptionAlgorithm")
        ).newInstance(key, Class.forName("com.androidcrypt.crypto.EncryptionAlgorithm").enumConstants!![0])
        
        val multiplyMethod = xtsClass.getDeclaredMethod("multiplyByAlpha", ByteArray::class.java)
        multiplyMethod.isAccessible = true
        multiplyMethod.invoke(xtsInstance, tweakZero)
        
        println("  After:  ${tweakZero.toHexString()}")
        println("  Expected: all zeros (0 * 2 = 0)")
        println()
        
        // Test 2: value that will trigger XOR with 0x87
        val tweakHigh = byteArrayOf(
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80.toByte()  // bit 127 set
        )
        println("Test 2 - High bit set (will overflow):")
        println("  Before: ${tweakHigh.toHexString()}")
        multiplyMethod.invoke(xtsInstance, tweakHigh)
        println("  After:  ${tweakHigh.toHexString()}")
        println("  Expected: 87000000000000000000000000000000 (overflow triggers XOR with 0x87)")
        println()
        
        // Test 3: The actual encrypted tweak from Vector 1
        val tweak = byteArrayOf(
            0x66.toByte(), 0xe9.toByte(), 0x4b, 0xd4.toByte(),
            0xef.toByte(), 0x8a.toByte(), 0x2c, 0x3b,
            0x88.toByte(), 0x4c, 0xfa.toByte(), 0x59,
            0xca.toByte(), 0x34, 0x2b, 0x2e
        )
        
        println("Test 3 - Vector 1 encrypted tweak:")
        println("  Before: ${tweak.toHexString()}")
        multiplyMethod.invoke(xtsInstance, tweak)
        println("  After:  ${tweak.toHexString()}")
        
        // Calculate what it should be by doing the second block of Vector 1
        println("\nLet me verify by encrypting the second block of Vector 1...")
    }
    
    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }
}
