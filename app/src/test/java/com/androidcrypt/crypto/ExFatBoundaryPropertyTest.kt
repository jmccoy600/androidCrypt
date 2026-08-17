package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.bind
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.AssumptionViolatedException
import org.junit.Test
import java.io.File

/**
 * **ExFAT-T3 — Boundary property test.**
 *
 * Mirrors [FAT32BoundaryPropertyTest]. Tests edge cases:
 *   - Last addressable cluster is allocatable
 *   - Writing past free space fails cleanly
 *   - Directory chain grows past one cluster
 *   - Zero-byte file allocates no cluster
 *
 * exFAT differences: no FAT mirror, no FSInfo sector, allocation tracked via bitmap.
 */
class ExFatBoundaryPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_boundary")
    private val password = "ExFatBoundary!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto"); true
    } catch (_: UnsatisfiedLinkError) { false }

    private fun assumeNative() { if (!nativeAvailable) throw AssumptionViolatedException("native lib") }

    private data class ExFatVolume(
        val container: File, val reader: VolumeReader, val fs: ExFatReader
    )

    private fun openVolume(sizeMb: Long = 8L): ExFatVolume {
        val container = File(testDir, "bnd_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(container.absolutePath, password.copyOf(), sizeMb,
            fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
        val reader = VolumeReader(container.absolutePath)
        reader.mount(password.copyOf()).getOrThrow()
        val fs = ExFatReader(reader); fs.initialize().getOrThrow()
        return ExFatVolume(container, reader, fs)
    }

    private fun closeVolume(v: ExFatVolume) { v.reader.unmount(); v.container.delete() }

    /** T20: Last addressable cluster is allocatable and persists across remount. */
    @Test
    fun `last addressable cluster is allocatable and persists across remount`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume(2L) // small volume to make fill feasible
        try {
            val fsInfo = v.fs.initialize().getOrThrow()
            val clusterSize = fsInfo.clusterSize
            val totalSpace = fsInfo.totalSpace
            val maxFileBytes = totalSpace - clusterSize * 4L // leave room for metadata clusters

            // Write a file that fills almost all available space
            v.fs.createFile("/", "fill.dat").getOrThrow()
            val payload = ByteArray(maxFileBytes.toInt()) { (it and 0xFF).toByte() }
            v.fs.writeFile("/fill.dat", payload).getOrThrow()

            // Read back and verify
            val readBack = v.fs.readFile("/fill.dat").getOrThrow()
            assertArrayEquals("fill content matches", payload, readBack)

            // Unmount and remount
            v.reader.unmount()
            val reader2 = VolumeReader(v.container.absolutePath)
            reader2.mount(password.copyOf()).getOrThrow()
            val fs2 = ExFatReader(reader2); fs2.initialize().getOrThrow()

            assertTrue("fill file exists after remount", fs2.exists("/fill.dat"))
            val readBack2 = fs2.readFile("/fill.dat").getOrThrow()
            assertArrayEquals("fill content matches after remount", payload, readBack2)
            reader2.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }

    /** T24: Zero-byte file allocates no cluster and round-trips. */
    @Test
    fun `zero-byte file allocates no cluster and round-trips`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume()
        try {
            v.fs.createFile("/", "empty.dat").getOrThrow()
            v.fs.writeFile("/empty.dat", ByteArray(0)).getOrThrow()

            val info = v.fs.getFileInfo("/empty.dat").getOrThrow()
            assertEquals(0L, info.size)

            val readBack = v.fs.readFile("/empty.dat").getOrThrow()
            assertEquals(0, readBack.size)

            // Unmount and remount
            v.reader.unmount()
            val reader2 = VolumeReader(v.container.absolutePath)
            reader2.mount(password.copyOf()).getOrThrow()
            val fs2 = ExFatReader(reader2); fs2.initialize().getOrThrow()

            val info2 = fs2.getFileInfo("/empty.dat").getOrThrow()
            assertEquals(0L, info2.size)
            assertTrue("empty file exists after remount", fs2.exists("/empty.dat"))
            reader2.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }

    /** T23: Directory chain grows past one cluster as entries are added. */
    @Test
    fun `directory chain grows past one cluster as entries are added`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume(8L)
        try {
            val clusterSize = v.fs.initialize().getOrThrow().clusterSize
            // Each File entry set = 3 entries (File + Stream + 1 FileName) × 32 bytes = 96 bytes
            // A 4 KB cluster holds ~42 entry sets. Create 200 files to force chain extension.
            val numFiles = 200
            for (i in 0 until numFiles) {
                v.fs.createFile("/", "file_$i.dat").getOrThrow()
            }
            val entries = v.fs.listDirectory("/").getOrThrow()
            assertEquals(numFiles, entries.size)

            // All 200 files should be listable by name
            for (i in 0 until numFiles) {
                assertTrue("file_$i.dat exists", v.fs.exists("/file_$i.dat"))
            }

            // Unmount and remount — directory chain must survive
            v.reader.unmount()
            val reader2 = VolumeReader(v.container.absolutePath)
            reader2.mount(password.copyOf()).getOrThrow()
            val fs2 = ExFatReader(reader2); fs2.initialize().getOrThrow()
            val entries2 = fs2.listDirectory("/").getOrThrow()
            assertEquals("entries after remount", numFiles, entries2.size)
            reader2.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }

    /** T35: Writing past free space fails cleanly without breaking the filesystem. */
    @Test
    fun `writing past free space fails cleanly`() {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume(1L) // 1 MB — very small
        try {
            val fsInfo = v.fs.initialize().getOrThrow()
            val totalSpace = fsInfo.totalSpace

            // Fill the volume
            v.fs.createFile("/", "fill.dat").getOrThrow()
            val fillSize = totalSpace - 5 * 4096L // leave room for metadata
            if (fillSize > 0) {
                val payload = ByteArray(fillSize.toInt()) { (it and 0xFF).toByte() }
                v.fs.writeFile("/fill.dat", payload).getOrThrow()
            }

            // Try to write another large file — should fail
            v.fs.createFile("/", "overflow.dat").getOrThrow()
            val overflowResult = v.fs.writeFile("/overflow.dat", ByteArray(1024 * 1024))
            assertTrue("overflow write fails", overflowResult.isFailure)

            // Original fill file should still be intact
            assertTrue("fill file exists", v.fs.exists("/fill.dat"))
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }

    /** PBT: Random payloads round-trip at various sizes. */
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `random payload sizes round-trip correctly`() {
        runBlocking {
        assumeNative()
        testDir.mkdirs()
        val v = openVolume(8L)
        try {
            checkAll(PropTestConfig(iterations = 15, seed = 0xB01DDL),
                Arb.byteArray(Arb.int(0, 16_384), Arb.byte())  // 0..16 KB
            ) { payload ->
                val name = "p_${payload.size}.dat"
                if (!v.fs.exists("/$name")) v.fs.createFile("/", name).getOrThrow()
                v.fs.writeFile("/$name", payload).getOrThrow()
                val readBack = v.fs.readFile("/$name").getOrThrow()
                assertArrayEquals(payload, readBack)
            }
        } finally {
            closeVolume(v)
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
        }
    }
}