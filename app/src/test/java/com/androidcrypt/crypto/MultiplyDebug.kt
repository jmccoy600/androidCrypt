package com.androidcrypt.crypto

import org.junit.Test

class MultiplyDebug {
    
    @Test
    fun testMultiplyStepByStep() {
        println("=== Step by step multiply ===")
        
        // Initial tweak: 66e94bd4ef8a2c3b884cfa59ca342b2e
        val tweak = byteArrayOf(
            0x66.toByte(), 0xe9.toByte(), 0x4b.toByte(), 0xd4.toByte(), 
            0xef.toByte(), 0x8a.toByte(), 0x2c.toByte(), 0x3b.toByte(),
            0x88.toByte(), 0x4c.toByte(), 0xfa.toByte(), 0x59.toByte(), 
            0xca.toByte(), 0x34.toByte(), 0x2b.toByte(), 0x2e.toByte()
        )
        
        println("Initial: ${tweak.joinToString("") { "%02x".format(it) }}")
        
        // Read as 64-bit little-endian words
        var low = 0L
        for (i in 0 until 8) {
            low = low or ((tweak[i].toLong() and 0xFF) shl (i * 8))
        }
        
        var high = 0L
        for (i in 8 until 16) {
            high = high or ((tweak[i].toLong() and 0xFF) shl ((i - 8) * 8))
        }
        
        println("Low  (bytes 0-7):  0x%016x".format(low))
        println("High (bytes 8-15): 0x%016x".format(high))
        println("High < 0: ${high < 0}")
        println("Low < 0: ${low < 0}")
        
        // Check bit 63 of high word
        val finalCarry = if (high < 0) 135 else 0
        println("FinalCarry: $finalCarry")
        
        // Shift high word left
        val highBefore = high
        high = high shl 1
        println("High after shift: 0x%016x (was 0x%016x)".format(high, highBefore))
        
        // Carry from low to high
        if (low < 0) {
            high = high or 1
            println("Low had carry, set bit 0 of high")
        }
        println("High after carry check: 0x%016x".format(high))
        
        // Shift low word left
        val lowBefore = low
        low = low shl 1
        println("Low after shift: 0x%016x (was 0x%016x)".format(low, lowBefore))
        
        // XOR with finalCarry
        low = low xor finalCarry.toLong()
        println("Low after XOR: 0x%016x".format(low))
        
        // Write back
        val result = ByteArray(16)
        for (i in 0 until 8) {
            result[i] = ((low ushr (i * 8)) and 0xFF).toByte()
        }
        for (i in 8 until 16) {
            result[i] = ((high ushr ((i - 8) * 8)) and 0xFF).toByte()
        }
        
        println("Result: ${result.joinToString("") { "%02x".format(it) }}")
    }
}
