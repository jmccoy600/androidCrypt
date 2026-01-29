package com.androidcrypt.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream

class KeyfileProcessorTest {
    
    @Test
    fun testKeyfileProcessing_SimpleASCII() {
        // Test 1: Simple ASCII keyfile
        verifyKeyfile(
            keyfileData = "testdata\n".toByteArray(),
            password = "mypassword",
            expectedHex = "e70e15b83b203b94f4245905278081f36e4c86669e0ad9251cf26bbb661ac9a1416260a900000000000000000000000000000000000000000000000000000000"
        )
    }
    
    @Test
    fun testKeyfileProcessing_EmptyPassword() {
        // Test 2: Empty password with keyfile only
        verifyKeyfile(
            keyfileData = "testdata\n".toByteArray(),
            password = "",
            expectedHex = "7a95a557c8adc42582c05905278081f36e4c86669e0ad9251cf26bbb661ac9a1416260a900000000000000000000000000000000000000000000000000000000"
        )
    }
    
    @Test
    fun testKeyfileProcessing_BinaryData() {
        // Test 3: Binary keyfile data (0x00-0x0F)
        verifyKeyfile(
            keyfileData = ByteArray(16) { it.toByte() },
            password = "test",
            expectedHex = "a16283e6c921dd96f7ab768074467 9ecaea52c33cf1430b552a7f60677559760431ebcfdba9328b952d2711e6d8f369a1901b9479610a9375f9398a131311d77"
        )
    }
    
    @Test
    fun testKeyfileProcessing_SingleByte() {
        // Test 4: Single byte keyfile
        verifyKeyfile(
            keyfileData = "A".toByteArray(),
            password = "password",
            expectedHex = "9c87d4e7776f72640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        )
    }
    
    private fun verifyKeyfile(keyfileData: ByteArray, password: String, expectedHex: String) {
        val cleanExpectedHex = expectedHex.replace(" ", "")
        val expected = cleanExpectedHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        
        val passwordBytes = password.toByteArray(Charsets.UTF_8)
        val keyPoolSize = if (passwordBytes.size <= 64) 64 else 128
        val keyPool = ByteArray(keyPoolSize)
        
        processKeyfileData(keyfileData, keyPool, keyPoolSize)
        
        val resultLen = maxOf(passwordBytes.size, keyPoolSize)
        val result = ByteArray(resultLen)
        for (i in 0 until resultLen) {
            val pwdByte = if (i < passwordBytes.size) passwordBytes[i].toInt() and 0xFF else 0
            val poolByte = if (i < keyPoolSize) keyPool[i].toInt() and 0xFF else 0
            result[i] = ((pwdByte + poolByte) and 0xFF).toByte()
        }
        
        val resultHex = result.joinToString("") { "%02x".format(it) }
        println("Expected: $cleanExpectedHex")
        println("Got:      $resultHex")
        
        assertEquals("Keyfile processing mismatch", cleanExpectedHex, resultHex)
    }
    
    private fun processKeyfileData(keyfileData: ByteArray, keyPool: ByteArray, keyPoolSize: Int) {
        var crc = 0xFFFFFFFF.toInt()
        var writePos = 0
        
        for (byte in keyfileData) {
            crc = updateCrc32(byte, crc)
            
            keyPool[writePos] = ((keyPool[writePos].toInt() and 0xFF) + ((crc ushr 24) and 0xFF)).toByte()
            writePos = (writePos + 1) % keyPoolSize
            
            keyPool[writePos] = ((keyPool[writePos].toInt() and 0xFF) + ((crc ushr 16) and 0xFF)).toByte()
            writePos = (writePos + 1) % keyPoolSize
            
            keyPool[writePos] = ((keyPool[writePos].toInt() and 0xFF) + ((crc ushr 8) and 0xFF)).toByte()
            writePos = (writePos + 1) % keyPoolSize
            
            keyPool[writePos] = ((keyPool[writePos].toInt() and 0xFF) + (crc and 0xFF)).toByte()
            writePos = (writePos + 1) % keyPoolSize
        }
    }
    
    private fun updateCrc32(octet: Byte, crc: Int): Int {
        return CRC32_TABLE[(crc xor (octet.toInt() and 0xFF)) and 0xFF] xor (crc ushr 8)
    }
    
    companion object {
        private val CRC32_TABLE = intArrayOf(
            0x00000000, 0x77073096, 0xee0e612c.toInt(), 0x990951ba.toInt(), 0x076dc419, 0x706af48f, 0xe963a535.toInt(), 0x9e6495a3.toInt(),
            0x0edb8832, 0x79dcb8a4, 0xe0d5e91e.toInt(), 0x97d2d988.toInt(), 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07.toInt(), 0x90bf1d91.toInt(),
            0x1db71064, 0x6ab020f2, 0xf3b97148.toInt(), 0x84be41de.toInt(), 0x1adad47d, 0x6ddde4eb, 0xf4d4b551.toInt(), 0x83d385c7.toInt(),
            0x136c9856, 0x646ba8c0, 0xfd62f97a.toInt(), 0x8a65c9ec.toInt(), 0x14015c4f, 0x63066cd9, 0xfa0f3d63.toInt(), 0x8d080df5.toInt(),
            0x3b6e20c8, 0x4c69105e, 0xd56041e4.toInt(), 0xa2677172.toInt(), 0x3c03e4d1, 0x4b04d447, 0xd20d85fd.toInt(), 0xa50ab56b.toInt(),
            0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6.toInt(), 0xacbcf940.toInt(), 0x32d86ce3, 0x45df5c75, 0xdcd60dcf.toInt(), 0xabd13d59.toInt(),
            0x26d930ac, 0x51de003a, 0xc8d75180.toInt(), 0xbfd06116.toInt(), 0x21b4f4b5, 0x56b3c423, 0xcfba9599.toInt(), 0xb8bda50f.toInt(),
            0x2802b89e, 0x5f058808, 0xc60cd9b2.toInt(), 0xb10be924.toInt(), 0x2f6f7c87, 0x58684c11, 0xc1611dab.toInt(), 0xb6662d3d.toInt(),
            0x76dc4190, 0x01db7106, 0x98d220bc.toInt(), 0xefd5102a.toInt(), 0x71b18589, 0x06b6b51f, 0x9fbfe4a5.toInt(), 0xe8b8d433.toInt(),
            0x7807c9a2, 0x0f00f934, 0x9609a88e.toInt(), 0xe10e9818.toInt(), 0x7f6a0dbb, 0x086d3d2d, 0x91646c97.toInt(), 0xe6635c01.toInt(),
            0x6b6b51f4, 0x1c6c6162, 0x856530d8.toInt(), 0xf262004e.toInt(), 0x6c0695ed, 0x1b01a57b, 0x8208f4c1.toInt(), 0xf50fc457.toInt(),
            0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea.toInt(), 0xfcb9887c.toInt(), 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3.toInt(), 0xfbd44c65.toInt(),
            0x4db26158, 0x3ab551ce, 0xa3bc0074.toInt(), 0xd4bb30e2.toInt(), 0x4adfa541, 0x3dd895d7, 0xa4d1c46d.toInt(), 0xd3d6f4fb.toInt(),
            0x4369e96a, 0x346ed9fc, 0xad678846.toInt(), 0xda60b8d0.toInt(), 0x44042d73, 0x33031de5, 0xaa0a4c5f.toInt(), 0xdd0d7cc9.toInt(),
            0x5005713c, 0x270241aa, 0xbe0b1010.toInt(), 0xc90c2086.toInt(), 0x5768b525, 0x206f85b3, 0xb966d409.toInt(), 0xce61e49f.toInt(),
            0x5edef90e, 0x29d9c998, 0xb0d09822.toInt(), 0xc7d7a8b4.toInt(), 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b.toInt(), 0xc0ba6cad.toInt(),
            0xedb88320.toInt(), 0x9abfb3b6.toInt(), 0x03b6e20c, 0x74b1d29a, 0xead54739.toInt(), 0x9dd277af.toInt(), 0x04db2615, 0x73dc1683,
            0xe3630b12.toInt(), 0x94643b84.toInt(), 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b.toInt(), 0x9309ff9d.toInt(), 0x0a00ae27, 0x7d079eb1,
            0xf00f9344.toInt(), 0x8708a3d2.toInt(), 0x1e01f268, 0x6906c2fe, 0xf762575d.toInt(), 0x806567cb.toInt(), 0x196c3671, 0x6e6b06e7,
            0xfed41b76.toInt(), 0x89d32be0.toInt(), 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f.toInt(), 0x8ebeeff9.toInt(), 0x17b7be43, 0x60b08ed5,
            0xd6d6a3e8.toInt(), 0xa1d1937e.toInt(), 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1.toInt(), 0xa6bc5767.toInt(), 0x3fb506dd, 0x48b2364b,
            0xd80d2bda.toInt(), 0xaf0a1b4c.toInt(), 0x36034af6, 0x41047a60, 0xdf60efc3.toInt(), 0xa867df55.toInt(), 0x316e8eef, 0x4669be79,
            0xcb61b38c.toInt(), 0xbc66831a.toInt(), 0x256fd2a0, 0x5268e236, 0xcc0c7795.toInt(), 0xbb0b4703.toInt(), 0x220216b9, 0x5505262f,
            0xc5ba3bbe.toInt(), 0xb2bd0b28.toInt(), 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7.toInt(), 0xb5d0cf31.toInt(), 0x2cd99e8b, 0x5bdeae1d,
            0x9b64c2b0.toInt(), 0xec63f226.toInt(), 0x756aa39c, 0x026d930a, 0x9c0906a9.toInt(), 0xeb0e363f.toInt(), 0x72076785, 0x05005713,
            0x95bf4a82.toInt(), 0xe2b87a14.toInt(), 0x7bb12bae, 0x0cb61b38, 0x92d28e9b.toInt(), 0xe5d5be0d.toInt(), 0x7cdcefb7, 0x0bdbdf21,
            0x86d3d2d4.toInt(), 0xf1d4e242.toInt(), 0x68ddb3f8, 0x1fda836e, 0x81be16cd.toInt(), 0xf6b9265b.toInt(), 0x6fb077e1, 0x18b74777,
            0x88085ae6.toInt(), 0xff0f6a70.toInt(), 0x66063bca, 0x11010b5c, 0x8f659eff.toInt(), 0xf862ae69.toInt(), 0x616bffd3, 0x166ccf45,
            0xa00ae278.toInt(), 0xd70dd2ee.toInt(), 0x4e048354, 0x3903b3c2, 0xa7672661.toInt(), 0xd06016f7.toInt(), 0x4969474d, 0x3e6e77db,
            0xaed16a4a.toInt(), 0xd9d65adc.toInt(), 0x40df0b66, 0x37d83bf0, 0xa9bcae53.toInt(), 0xdebb9ec5.toInt(), 0x47b2cf7f, 0x30b5ffe9,
            0xbdbdf21c.toInt(), 0xcabac28a.toInt(), 0x53b39330, 0x24b4a3a6, 0xbad03605.toInt(), 0xcdd70693.toInt(), 0x54de5729, 0x23d967bf,
            0xb3667a2e.toInt(), 0xc4614ab8.toInt(), 0x5d681b02, 0x2a6f2b94, 0xb40bbe37.toInt(), 0xc30c8ea1.toInt(), 0x5a05df1b, 0x2d02ef8d
        )
    }
}
