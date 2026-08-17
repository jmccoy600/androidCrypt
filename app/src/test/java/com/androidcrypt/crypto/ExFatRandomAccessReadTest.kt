package com.androidcrypt.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.AssumptionViolatedException
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * **ExFAT-T7 — Random access read test.**
 *
 * Mirrors [FAT32RandomAccessReadTest]. Tests `readFile(path, offset, length)`
 * across cluster boundaries, partial-cluster reads, EOF clamping, and
 * concurrent random reads.
 *
 * Uses a deterministic 512 KB payload with position-dependent bytes.
 */
class ExFatRandomAccessReadTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_random")
    private val password = "ExFatRandom!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto"); true
    } catch (_: UnsatisfiedLinkError) { false }

    private fun assumeNative() { if (!nativeAvailable) throw AssumptionViolatedException("native lib") }

    companion object {
        private const val FILE_SIZE = 512 * 1024 // 512 KB
    }

    private fun payload(): ByteArray = ByteArray(FILE_SIZE) { ((it * 31 + 17) and 0xFF).toByte() }

    private fun sha256(b: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(b).joinToString("") { "%02x".format(it) }
    }

    private data class Setup(
        val container: File, val reader: VolumeReader, val fs: ExFatReader, val payload: ByteArray
    )

    private fun setUp(): Setup {
        testDir.mkdirs()
        val container = File(testDir, "rr_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 10L,
            fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
        val reader = VolumeReader(container.absolutePath)
        reader.mount(password.copyOf()).getOrThrow()
        val fs = ExFatReader(reader)
        fs.initialize().getOrThrow()
        val pl = payload()
        fs.createFile("/", "blob.bin").getOrThrow()
        fs.writeFile("/blob.bin", pl).getOrThrow()
        return Setup(container, reader, fs, pl)
    }

    private fun tearDown(s: Setup) {
        s.reader.unmount(); s.container.delete(); testDir.delete()
    }

    @Test fun `readFile entire file correctly`() {
        assumeNative(); val s = setUp(); try {
            val data = s.fs.readFile("/blob.bin").getOrThrow()
            assertEquals(FILE_SIZE, data.size)
            assertArrayEquals(s.payload, data)
        } finally { tearDown(s) }
    }

    @Test fun `readFile with zero length returns empty`() {
        assumeNative(); val s = setUp(); try {
            val data = s.fs.readFile("/blob.bin", 0, 0).getOrThrow()
            assertEquals(0, data.size)
        } finally { tearDown(s) }
    }

    @Test fun `readFile past EOF returns empty`() {
        assumeNative(); val s = setUp(); try {
            val data = s.fs.readFile("/blob.bin", FILE_SIZE.toLong(), 100).getOrThrow()
            assertEquals(0, data.size)
        } finally { tearDown(s) }
    }

    @Test fun `readFile clamps reads that straddle EOF`() {
        assumeNative(); val s = setUp(); try {
            val data = s.fs.readFile("/blob.bin", (FILE_SIZE - 100).toLong(), 4096).getOrThrow()
            assertEquals(100, data.size)
            assertArrayEquals(s.payload.copyOfRange(FILE_SIZE - 100, FILE_SIZE), data)
        } finally { tearDown(s) }
    }

    @Test fun `random-offset reads return correct bytes`() {
        assumeNative(); val s = setUp(); try {
            // Deterministic pseudo-random seek pattern (simulates GIF decoder)
            var seed = 42L
            for (i in 0 until 100) {
                seed = (seed * 6364136223846793005L + 1)
                val offset = ((seed ushr 11) % FILE_SIZE).toInt()
                seed = (seed * 6364136223846793005L + 1)
                val length = ((seed ushr 11) % 8192).toInt() + 1
                val clampedLen = minOf(length, FILE_SIZE - offset)
                val data = s.fs.readFile("/blob.bin", offset.toLong(), length).getOrThrow()
                assertEquals(clampedLen, data.size)
                assertArrayEquals(s.payload.copyOfRange(offset, offset + clampedLen), data)
            }
        } finally { tearDown(s) }
    }

    @Test fun `backward seeks return correct bytes`() {
        assumeNative(); val s = setUp(); try {
            // Walk file backward in 4 KB chunks
            var offset = FILE_SIZE - 4096
            while (offset >= 0) {
                val data = s.fs.readFile("/blob.bin", offset.toLong(), 4096).getOrThrow()
                val expectedLen = minOf(4096, FILE_SIZE - offset)
                assertEquals(expectedLen, data.size)
                assertArrayEquals(s.payload.copyOfRange(offset, offset + expectedLen), data)
                offset -= 4096
            }
        } finally { tearDown(s) }
    }

    @Test fun `intra-cluster offsets are honored`() {
        assumeNative(); val s = setUp(); try {
            // Test offsets that are within a single cluster (4 KB)
            val offsets = intArrayOf(1, 7, 511, 513, 4095, 4097, 8000)
            for (off in offsets) {
                if (off >= FILE_SIZE) continue
                val data = s.fs.readFile("/blob.bin", off.toLong(), 333).getOrThrow()
                val expectedLen = minOf(333, FILE_SIZE - off)
                assertEquals(expectedLen, data.size)
                assertArrayEquals(s.payload.copyOfRange(off, off + expectedLen), data)
            }
        } finally { tearDown(s) }
    }

    @Test fun `concurrent random reads from multiple threads return correct bytes`() {
        assumeNative(); val s = setUp(); try {
            val errors = java.util.concurrent.ConcurrentLinkedQueue<String>()
            val threads = (0 until 4).map {
                Thread {
                    try {
                        var seed = it * 1000L
                        for (i in 0 until 25) {
                            seed = (seed * 6364136223846793005L + 1)
                            val offset = ((seed ushr 11) % FILE_SIZE).toInt()
                            seed = (seed * 6364136223846793005L + 1)
                            val length = ((seed ushr 11) % 4096).toInt() + 1
                            val data = s.fs.readFile("/blob.bin", offset.toLong(), length).getOrThrow()
                            val expectedLen = minOf(length, FILE_SIZE - offset)
                            if (data.size != expectedLen) {
                                errors.add("size mismatch at $offset len $length: ${data.size} != $expectedLen")
                                return@Thread
                            }
                            if (!data.contentEquals(s.payload.copyOfRange(offset, offset + expectedLen))) {
                                errors.add("content mismatch at $offset len $length")
                                return@Thread
                            }
                        }
                    } catch (e: Exception) {
                        errors.add("exception: ${e.message}")
                    }
                }
            }
            threads.forEach { it.start() }
            threads.forEach { it.join() }
            assertTrue("errors: ${errors.joinToString("\n")}", errors.isEmpty())
        } finally { tearDown(s) }
    }
}