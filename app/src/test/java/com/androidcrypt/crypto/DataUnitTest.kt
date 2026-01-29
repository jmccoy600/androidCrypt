package com.androidcrypt.crypto

import org.junit.Test

class DataUnitTest {
    
    @Test
    fun testDataUnitEncoding() {
        println("=== Testing data unit encoding ===")
        
        // VeraCrypt has: { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff }
        // This is little-endian, so byte 0 is LSB
        
        // As a 64-bit little-endian number, this is:
        // 0xff in position 7 (MSB) = 0xff << 56
        val dataUnitFromBytes = 0xffL shl 56
        println("Data unit from bytes (0xff << 56): 0x%016x = %d".format(dataUnitFromBytes, dataUnitFromBytes))
        
        // If we just use 0xff:
        val simpleFF = 0xffL
        println("Simple 0xff: 0x%016x = %d".format(simpleFF, simpleFF))
        
        // Convert back to little-endian bytes
        val buffer = java.nio.ByteBuffer.allocate(16).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buffer.putLong(dataUnitFromBytes)
        buffer.putLong(0)
        val bytes = buffer.array()
        
        println("Bytes for data unit 0x%016x:".format(dataUnitFromBytes))
        println("  ${bytes.copyOfRange(0, 8).joinToString(" ") { "%02x".format(it) }}")
        println("Expected: 00 00 00 00 00 00 00 ff")
    }
}
