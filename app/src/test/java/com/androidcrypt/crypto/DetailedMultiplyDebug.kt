package com.androidcrypt.crypto

import org.junit.Test

class DetailedMultiplyDebug {
    
    @Test
    fun testMultiplyWithDetailedOutput() {
        println("=== Detailed multiply debug ===")
        
        val tweak = byteArrayOf(
            0x66.toByte(), 0xe9.toByte(), 0x4b.toByte(), 0xd4.toByte(), 
            0xef.toByte(), 0x8a.toByte(), 0x2c.toByte(), 0x3b.toByte(),
            0x88.toByte(), 0x4c.toByte(), 0xfa.toByte(), 0x59.toByte(), 
            0xca.toByte(), 0x34.toByte(), 0x2b.toByte(), 0x2e.toByte()
        )
        
        println("Input: ${tweak.joinToString("") { "%02x".format(it) }}")
        
        val buffer = java.nio.ByteBuffer.wrap(tweak).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        
        val low = buffer.getLong(0)
        var high = buffer.getLong(8)
        
        println("Low:  0x%016x (< 0: %b)".format(low, low < 0))
        println("High: 0x%016x (< 0: %b)".format(high, high < 0))
        
        // Step 1
        val finalCarry = if (high < 0) 135 else 0
        println("Final carry: $finalCarry")
        
        // Step 2
        val highBefore = high
        high = high shl 1
        println("High shifted: 0x%016x (was 0x%016x)".format(high, highBefore))
        
        // Step 3 & 4
        val lowHasBit63 = low < 0
        println("Low has bit 63 set: $lowHasBit63")
        if (lowHasBit63) {
            high = high or 1
            println("Set bit 0 of high: 0x%016x".format(high))
        }
        
        // Step 5
        val lowShifted = low shl 1
        println("Low shifted: 0x%016x (was 0x%016x)".format(lowShifted, low))
        
        // Step 6
        val lowFinal = lowShifted xor finalCarry.toLong()
        println("Low after XOR: 0x%016x".format(lowFinal))
        
        buffer.putLong(0, lowFinal)
        buffer.putLong(8, high)
        
        println("Result: ${tweak.joinToString("") { "%02x".format(it) }}")
        println("Expected something different for block 1 to work...")
    }
}
