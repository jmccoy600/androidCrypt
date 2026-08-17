package com.androidcrypt.crypto

import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.AssumptionViolatedException
import org.junit.Test
import java.io.File

/**
 * **ExFAT-T9 — Long name boundary property test.**
 *
 * Mirrors [FAT32LongNameBoundaryPropertyTest]. Tests that names at every
 * 15-char File Name entry boundary round-trip correctly.
 *
 * exFAT stores file names in File Name entries (0xC1), each holding 15 UTF-16
 * chars. Boundaries are at 15, 30, 45, ..., 240, 255 chars.
 */
class ExFatLongNameBoundaryPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_lname")
    private val password = "ExFatLName!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto"); true
    } catch (_: UnsatisfiedLinkError) { false }

    private fun assumeNative() { if (!nativeAvailable) throw AssumptionViolatedException("native lib") }

    private data class Setup(
        val container: File, val reader: VolumeReader, val fs: ExFatReader
    )

    private fun setUp(): Setup {
        testDir.mkdirs()
        val container = File(testDir, "ln_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 8L,
            fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
        val reader = VolumeReader(container.absolutePath)
        reader.mount(password.copyOf()).getOrThrow()
        val fs = ExFatReader(reader); fs.initialize().getOrThrow()
        return Setup(container, reader, fs)
    }

    private fun tearDown(s: Setup) { s.reader.unmount(); s.container.delete(); testDir.delete() }

    /** T21: Names at every 15-char boundary round-trip. */
    @Test
    fun `names at every 15-char File Name entry boundary round-trip`() {
        assumeNative()
        val s = setUp()
        try {
            // Pivots at 15-char boundaries: 1, 14, 15, 16, 29, 30, 31, 44, 45, 46, 130, 200, 250, 254, 255
            val pivots = intArrayOf(1, 14, 15, 16, 29, 30, 31, 44, 45, 46, 130, 200, 250, 254, 255)
            for (len in pivots) {
                val name = "a".repeat(len)
                try {
                    s.fs.createFile("/", name).getOrThrow()
                    assertTrue("name of length $len exists", s.fs.exists("/$name"))
                    val entries = s.fs.listDirectory("/").getOrThrow()
                    assertTrue("name of length $len in listing", entries.any { it.name == name })
                } catch (e: Exception) {
                    // Skip if name violates spec (shouldn't for pure 'a' chars)
                    throw AssertionError("Failed for length $len: ${e.message}", e)
                }
            }
        } finally { tearDown(s) }
    }

    /** T21b: Names with extensions at boundary lengths. */
    @Test
    fun `names with extensions at boundary lengths round-trip`() {
        assumeNative()
        val s = setUp()
        try {
            val pivots = intArrayOf(5, 14, 15, 16, 29, 30, 100, 200, 250, 254, 255)
            for (stemLen in pivots) {
                val stem = "a".repeat(stemLen - 4)
                val name = if (stem.isNotEmpty()) "${stem}.bin" else ".bin"
                if (name.length > 255) continue
                try {
                    s.fs.createFile("/", name).getOrThrow()
                    assertTrue("'$name' exists", s.fs.exists("/$name"))
                    val entries = s.fs.listDirectory("/").getOrThrow()
                    assertTrue("'$name' in listing", entries.any { it.name == name })
                } catch (e: Exception) {
                    throw AssertionError("Failed for name '$name' (len=${name.length}): ${e.message}", e)
                }
            }
        } finally { tearDown(s) }
    }

    /** T22: Names with special 8.3-reserved chars round-trip via UTF-16 entries. */
    @Test
    fun `names with reserved 8 dot 3 chars round-trip via File Name entries`() {
        assumeNative()
        val s = setUp()
        try {
            val reservedChars = listOf('+', ',', ';', '=', '[', ']')
            for (ch in reservedChars) {
                val name = "name${ch.toString().repeat(3)}stem.dat"
                s.fs.createFile("/", name).getOrThrow()
                assertTrue("'$name' exists", s.fs.exists("/$name"))
                val entries = s.fs.listDirectory("/").getOrThrow()
                assertTrue("'$name' in listing verbatim", entries.any { it.name == name })
            }
        } finally { tearDown(s) }
    }
}