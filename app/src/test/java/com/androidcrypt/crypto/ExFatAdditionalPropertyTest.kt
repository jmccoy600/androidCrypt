package com.androidcrypt.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.AssumptionViolatedException
import org.junit.Test
import java.io.File

/**
 * **ExFAT-T10 — Additional property tests.**
 *
 * Mirrors [FAT32AdditionalPropertyTests]. Tests:
 *   - writeFile and writeFileStreaming produce identical bytes
 *   - Nested directory trees with mixed files and directories
 *   - Concurrent reader observes only complete writes (no torn reads)
 */
class ExFatAdditionalPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_addl")
    private val password = "ExFatAddl!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto"); true
    } catch (_: UnsatisfiedLinkError) { false }

    private fun assumeNative() { if (!nativeAvailable) throw AssumptionViolatedException("native lib") }

    private data class Setup(
        val container: File, val reader: VolumeReader, val fs: ExFatReader
    )

    private fun setUp(sizeMb: Long = 12L): Setup {
        testDir.mkdirs()
        val container = File(testDir, "addl_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(container.absolutePath, password.copyOf(), sizeMb,
            fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
        val reader = VolumeReader(container.absolutePath)
        reader.mount(password.copyOf()).getOrThrow()
        val fs = ExFatReader(reader); fs.initialize().getOrThrow()
        return Setup(container, reader, fs)
    }

    private fun tearDown(s: Setup) { s.reader.unmount(); s.container.delete(); testDir.delete() }

    @Test
    fun `writeFile and writeFileStreaming produce identical bytes`() {
        assumeNative()
        val s = setUp()
        try {
            val payload = ByteArray(8192) { (it and 0xFF).toByte() }

            // Write via writeFile
            s.fs.createFile("/", "sync.dat").getOrThrow()
            s.fs.writeFile("/sync.dat", payload).getOrThrow()
            val readSync = s.fs.readFile("/sync.dat").getOrThrow()

            // Write via writeFileStreaming
            s.fs.createFile("/", "stream.dat").getOrThrow()
            s.fs.writeFileStreaming("/stream.dat", payload.inputStream(), payload.size.toLong(), null).getOrThrow()
            val readStream = s.fs.readFile("/stream.dat").getOrThrow()

            assertArrayEquals("writeFile and writeFileStreaming match", readSync, readStream)
            assertArrayEquals("writeFile matches payload", payload, readSync)
        } finally { tearDown(s) }
    }

    @Test
    fun `nested directory tree with mixed files and directories`() {
        assumeNative()
        val s = setUp()
        try {
            // Create a tree:
            //   /dir1/
            //     file1.dat (100 bytes)
            //     file2.dat (4096 bytes)
            //   /dir1/subdir/
            //     nested.dat (200 bytes)
            //   /dir2/
            //     deep.dat (50 bytes)

            s.fs.createDirectory("/", "dir1").getOrThrow()
            s.fs.createDirectory("/", "dir2").getOrThrow()

            s.fs.createFile("/dir1", "file1.dat").getOrThrow()
            s.fs.writeFile("/dir1/file1.dat", ByteArray(100) { 1 }).getOrThrow()

            s.fs.createFile("/dir1", "file2.dat").getOrThrow()
            s.fs.writeFile("/dir1/file2.dat", ByteArray(4096) { 2 }).getOrThrow()

            s.fs.createDirectory("/dir1", "subdir").getOrThrow()
            s.fs.createFile("/dir1/subdir", "nested.dat").getOrThrow()
            s.fs.writeFile("/dir1/subdir/nested.dat", ByteArray(200) { 3 }).getOrThrow()

            s.fs.createFile("/dir2", "deep.dat").getOrThrow()
            s.fs.writeFile("/dir2/deep.dat", ByteArray(50) { 4 }).getOrThrow()

            // Verify tree structure
            val root = s.fs.listDirectory("/").getOrThrow()
            assertEquals(2, root.size)

            val dir1 = s.fs.listDirectory("/dir1").getOrThrow()
            assertEquals(3, dir1.size) // file1, file2, subdir

            val subdir = s.fs.listDirectory("/dir1/subdir").getOrThrow()
            assertEquals(1, subdir.size)

            val dir2 = s.fs.listDirectory("/dir2").getOrThrow()
            assertEquals(1, dir2.size)

            // Verify file contents
            assertEquals(100L, s.fs.getFileInfo("/dir1/file1.dat").getOrThrow().size)
            assertEquals(4096L, s.fs.getFileInfo("/dir1/file2.dat").getOrThrow().size)
            assertEquals(200L, s.fs.getFileInfo("/dir1/subdir/nested.dat").getOrThrow().size)
            assertEquals(50L, s.fs.getFileInfo("/dir2/deep.dat").getOrThrow().size)

            // Unmount and remount — tree must survive
            s.reader.unmount()
            val reader2 = VolumeReader(s.container.absolutePath)
            reader2.mount(password.copyOf()).getOrThrow()
            val fs2 = ExFatReader(reader2); fs2.initialize().getOrThrow()

            assertTrue("dir1 exists after remount", fs2.exists("/dir1"))
            assertTrue("dir1/file1.dat exists after remount", fs2.exists("/dir1/file1.dat"))
            assertTrue("dir1/subdir/nested.dat exists after remount", fs2.exists("/dir1/subdir/nested.dat"))
            assertEquals(100L, fs2.getFileInfo("/dir1/file1.dat").getOrThrow().size)
            reader2.unmount()
        } finally { tearDown(s) }
    }

    @Test
    fun `concurrent reader observes only complete writes`() {
        assumeNative()
        val s = setUp()
        try {
            val payloadA = ByteArray(8192) { 0x41 } // 'A'
            val payloadB = ByteArray(8192) { 0x42 } // 'B'

            s.fs.createFile("/", "torn.dat").getOrThrow()
            s.fs.writeFile("/torn.dat", payloadA).getOrThrow()

            val errors = java.util.concurrent.ConcurrentLinkedQueue<String>()
            val running = java.util.concurrent.atomic.AtomicBoolean(true)

            // Writer: alternates A/B
            val writer = Thread {
                try {
                    var isA = true
                    while (running.get()) {
                        val payload = if (isA) payloadA else payloadB
                        s.fs.writeFile("/torn.dat", payload).getOrThrow()
                        isA = !isA
                    }
                } catch (e: Exception) {
                    errors.add("writer: ${e.message}")
                }
            }

            // Reader: every read must be all-A or all-B
            val reader = Thread {
                try {
                    while (running.get()) {
                        val data = s.fs.readFile("/torn.dat").getOrNull()
                        if (data != null && data.isNotEmpty()) {
                            val first = data[0]
                            for (b in data) {
                                if (b != first) {
                                    errors.add("torn read: mixed $first and $b")
                                    return@Thread
                                }
                            }
                        }
                    }
                } catch (e: Exception) {
                    errors.add("reader: ${e.message}")
                }
            }

            writer.start()
            reader.start()
            Thread.sleep(2000) // run for 2 seconds
            running.set(false)
            writer.join(5000)
            reader.join(5000)

            assertTrue("errors: ${errors.joinToString("\n")}", errors.isEmpty())
        } finally { tearDown(s) }
    }
}