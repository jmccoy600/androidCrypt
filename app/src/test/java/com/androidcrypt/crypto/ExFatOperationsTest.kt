package com.androidcrypt.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.AssumptionViolatedException
import org.junit.Test
import java.io.File

/**
 * **ExFAT-T5 — Operations test.**
 *
 * Mirrors [FAT32OperationsTest]. Direct unit tests covering the public FS API
 * surface and error paths. No property-based testing — just deterministic
 * assertions for each operation.
 *
 * exFAT-specific differences from FAT32:
 *   - No reserved DOS device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
 *   - No 8.3 short name — names are UTF-16 directly
 *   - No LFN — all names up to 255 UTF-16 chars stored in File Name entries
 *   - No trailing dot/space stripping (exFAT forbids them in spec Table 35)
 */
class ExFatOperationsTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_ops")
    private val password = "ExFatOps!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto"); true
    } catch (_: UnsatisfiedLinkError) { false }

    private fun assumeNative() { if (!nativeAvailable) throw AssumptionViolatedException("native lib") }

    private lateinit var container: File
    private lateinit var reader: VolumeReader
    private lateinit var fs: ExFatReader

    private fun setUp() {
        testDir.mkdirs()
        container = File(testDir, "ops_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 10L,
            fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
        reader = VolumeReader(container.absolutePath)
        reader.mount(password.copyOf()).getOrThrow()
        fs = ExFatReader(reader)
        fs.initialize().getOrThrow()
    }

    private fun tearDown() {
        reader.unmount()
        container.delete()
        testDir.delete()
    }

    // ── Directory operations ──────────────────────────────────────────────────

    @Test fun `create directory in root`() { assumeNative(); setUp(); try {
        val result = fs.createDirectory("/", "testdir")
        assertTrue(result.isSuccess)
        assertTrue(fs.exists("/testdir"))
    } finally { tearDown() } }

    @Test fun `create nested directories`() { assumeNative(); setUp(); try {
        fs.createDirectory("/", "dir1").getOrThrow()
        fs.createDirectory("/dir1", "dir2").getOrThrow()
        assertTrue(fs.exists("/dir1/dir2"))
    } finally { tearDown() } }

    @Test fun `create file in subdirectory`() { assumeNative(); setUp(); try {
        fs.createDirectory("/", "sub").getOrThrow()
        fs.createFile("/sub", "file.txt").getOrThrow()
        assertTrue(fs.exists("/sub/file.txt"))
    } finally { tearDown() } }

    @Test fun `list root directory`() { assumeNative(); setUp(); try {
        fs.createFile("/", "a.txt").getOrThrow()
        fs.createFile("/", "b.txt").getOrThrow()
        val entries = fs.listDirectory("/").getOrThrow()
        assertEquals(2, entries.size)
    } finally { tearDown() } }

    @Test fun `list subdirectory`() { assumeNative(); setUp(); try {
        fs.createDirectory("/", "sub").getOrThrow()
        fs.createFile("/sub", "a.txt").getOrThrow()
        fs.createFile("/sub", "b.txt").getOrThrow()
        val entries = fs.listDirectory("/sub").getOrThrow()
        assertEquals(2, entries.size)
    } finally { tearDown() } }

    // ── Delete operations ─────────────────────────────────────────────────────

    @Test fun `delete file`() { assumeNative(); setUp(); try {
        fs.createFile("/", "del.txt").getOrThrow()
        assertTrue(fs.exists("/del.txt"))
        fs.delete("/del.txt").getOrThrow()
        assertFalse(fs.exists("/del.txt"))
    } finally { tearDown() } }

    @Test fun `delete empty directory`() { assumeNative(); setUp(); try {
        fs.createDirectory("/", "emptydir").getOrThrow()
        fs.delete("/emptydir").getOrThrow()
        assertFalse(fs.exists("/emptydir"))
    } finally { tearDown() } }

    @Test fun `delete directory with contents`() { assumeNative(); setUp(); try {
        fs.createDirectory("/", "parent").getOrThrow()
        fs.createFile("/parent", "child.txt").getOrThrow()
        fs.delete("/parent").getOrThrow()
        assertFalse(fs.exists("/parent"))
    } finally { tearDown() } }

    @Test fun `delete root fails`() { assumeNative(); setUp(); try {
        val result = fs.delete("/")
        assertTrue("delete root fails", result.isFailure)
    } finally { tearDown() } }

    // ── Name validation ──────────────────────────────────────────────────────

    @Test fun `reject empty name`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name with slash`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "a/b").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name with backslash`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "a\\b").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name with colon`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "a:b").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name with asterisk`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "a*b").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name with question mark`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "a?b").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name with angle brackets`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "a<b").isFailure)
        assertTrue(fs.createFile("/", "a>b").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name with pipe`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "a|b").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name with double quotes`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "a\"b").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name with control character`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/", "a\u0001b").isFailure)
    } finally { tearDown() } }

    @Test fun `reject name exceeding 255 characters`() { assumeNative(); setUp(); try {
        val longName = "a".repeat(256)
        assertTrue(fs.createFile("/", longName).isFailure)
    } finally { tearDown() } }

    @Test fun `accept name at exactly 255 characters`() { assumeNative(); setUp(); try {
        val name = "a".repeat(255)
        val result = fs.createFile("/", name)
        assertTrue("255-char name accepted", result.isSuccess)
    } finally { tearDown() } }

    // ── Multi-cluster files ──────────────────────────────────────────────────

    @Test fun `write and read multi-cluster file`() { assumeNative(); setUp(); try {
        val payload = ByteArray(32 * 1024) { (it and 0xFF).toByte() } // 32 KB = 8 clusters @ 4 KB
        fs.createFile("/", "multi.dat").getOrThrow()
        fs.writeFile("/multi.dat", payload).getOrThrow()
        val readBack = fs.readFile("/multi.dat").getOrThrow()
        org.junit.Assert.assertArrayEquals(payload, readBack)
    } finally { tearDown() } }

    @Test fun `write and read 100KB file`() { assumeNative(); setUp(); try {
        val payload = ByteArray(100 * 1024) { (it and 0xFF).toByte() }
        fs.createFile("/", "big.dat").getOrThrow()
        fs.writeFile("/big.dat", payload).getOrThrow()
        val readBack = fs.readFile("/big.dat").getOrThrow()
        org.junit.Assert.assertArrayEquals(payload, readBack)
    } finally { tearDown() } }

    @Test fun `write and read 1MB file`() { assumeNative(); setUp(); try {
        val payload = ByteArray(1024 * 1024) { (it and 0xFF).toByte() }
        fs.createFile("/", "mb.dat").getOrThrow()
        fs.writeFile("/mb.dat", payload).getOrThrow()
        val readBack = fs.readFile("/mb.dat").getOrThrow()
        org.junit.Assert.assertArrayEquals(payload, readBack)
    } finally { tearDown() } }

    // ── File info ────────────────────────────────────────────────────────────

    @Test fun `getFileInfo returns correct size`() { assumeNative(); setUp(); try {
        fs.createFile("/", "info.dat").getOrThrow()
        fs.writeFile("/info.dat", ByteArray(1234)).getOrThrow()
        val info = fs.getFileInfo("/info.dat").getOrThrow()
        assertEquals(1234L, info.size)
    } finally { tearDown() } }

    @Test fun `getFileInfo for directory`() { assumeNative(); setUp(); try {
        fs.createDirectory("/", "dir").getOrThrow()
        val info = fs.getFileInfo("/dir").getOrThrow()
        assertTrue(info.isDirectory)
    } finally { tearDown() } }

    @Test fun `getFileInfo for nonexistent path fails`() { assumeNative(); setUp(); try {
        assertTrue(fs.getFileInfo("/nonexistent").isFailure)
    } finally { tearDown() } }

    // ── Edge cases ────────────────────────────────────────────────────────────

    @Test fun `duplicate file name fails`() { assumeNative(); setUp(); try {
        fs.createFile("/", "dup.txt").getOrThrow()
        assertTrue(fs.createFile("/", "dup.txt").isFailure)
    } finally { tearDown() } }

    @Test fun `duplicate directory name fails`() { assumeNative(); setUp(); try {
        fs.createDirectory("/", "dup").getOrThrow()
        assertTrue(fs.createDirectory("/", "dup").isFailure)
    } finally { tearDown() } }

    @Test fun `write empty file`() { assumeNative(); setUp(); try {
        fs.createFile("/", "empty.dat").getOrThrow()
        fs.writeFile("/empty.dat", ByteArray(0)).getOrThrow()
        val info = fs.getFileInfo("/empty.dat").getOrThrow()
        assertEquals(0L, info.size)
    } finally { tearDown() } }

    @Test fun `case insensitive file access`() { assumeNative(); setUp(); try {
        fs.createFile("/", "MixedCase.TXT").getOrThrow()
        assertTrue(fs.exists("/mixedcase.txt"))
        assertTrue(fs.exists("/MIXEDCASE.Txt"))
    } finally { tearDown() } }

    @Test fun `many files in one directory`() { assumeNative(); setUp(); try {
        for (i in 0 until 50) {
            fs.createFile("/", "file_$i.dat").getOrThrow()
        }
        val entries = fs.listDirectory("/").getOrThrow()
        assertEquals(50, entries.size)
    } finally { tearDown() } }

    @Test fun `read file with offset and length`() { assumeNative(); setUp(); try {
        val payload = ByteArray(4096) { (it and 0xFF).toByte() }
        fs.createFile("/", "range.dat").getOrThrow()
        fs.writeFile("/range.dat", payload).getOrThrow()
        val partial = fs.readFile("/range.dat", 100, 200).getOrThrow()
        assertEquals(200, partial.size)
        org.junit.Assert.assertArrayEquals(
            payload.copyOfRange(100, 300),
            partial
        )
    } finally { tearDown() } }

    @Test fun `filesystem info after initialization`() { assumeNative(); setUp(); try {
        val info = fs.initialize().getOrThrow()
        assertEquals(FileSystemType.EXFAT, info.type)
        assertTrue(info.clusterSize > 0)
        assertTrue(info.totalSpace > 0)
    } finally { tearDown() } }

    // ── Overwrite ─────────────────────────────────────────────────────────────

    @Test fun `overwrite existing file with new content`() { assumeNative(); setUp(); try {
        fs.createFile("/", "ow.dat").getOrThrow()
        fs.writeFile("/ow.dat", "original".toByteArray()).getOrThrow()
        fs.writeFile("/ow.dat", "replaced".toByteArray()).getOrThrow()
        val readBack = fs.readFile("/ow.dat").getOrThrow()
        org.junit.Assert.assertArrayEquals("replaced".toByteArray(), readBack)
    } finally { tearDown() } }

    @Test fun `overwrite with larger content`() { assumeNative(); setUp(); try {
        fs.createFile("/", "grow.dat").getOrThrow()
        fs.writeFile("/grow.dat", ByteArray(100)).getOrThrow()
        fs.writeFile("/grow.dat", ByteArray(500)).getOrThrow()
        val info = fs.getFileInfo("/grow.dat").getOrThrow()
        assertEquals(500L, info.size)
    } finally { tearDown() } }

    @Test fun `overwrite with smaller content`() { assumeNative(); setUp(); try {
        fs.createFile("/", "shrink.dat").getOrThrow()
        fs.writeFile("/shrink.dat", ByteArray(500)).getOrThrow()
        fs.writeFile("/shrink.dat", ByteArray(100)).getOrThrow()
        val info = fs.getFileInfo("/shrink.dat").getOrThrow()
        assertEquals(100L, info.size)
        val readBack = fs.readFile("/shrink.dat").getOrThrow()
        assertEquals(100, readBack.size)
    } finally { tearDown() } }

    // ── Error paths ───────────────────────────────────────────────────────────

    @Test fun `createFile in nonexistent parent returns failure`() { assumeNative(); setUp(); try {
        assertTrue(fs.createFile("/nonexistent", "file.txt").isFailure)
    } finally { tearDown() } }

    @Test fun `createDirectory in nonexistent parent returns failure`() { assumeNative(); setUp(); try {
        assertTrue(fs.createDirectory("/nonexistent", "sub").isFailure)
    } finally { tearDown() } }

    @Test fun `delete nonexistent file returns failure`() { assumeNative(); setUp(); try {
        assertTrue(fs.delete("/nonexistent").isFailure)
    } finally { tearDown() } }

    @Test fun `listDirectory on nonexistent path returns failure`() { assumeNative(); setUp(); try {
        assertTrue(fs.listDirectory("/nonexistent").isFailure)
    } finally { tearDown() } }

    @Test fun `exists returns false for nonexistent file`() { assumeNative(); setUp(); try {
        assertFalse(fs.exists("/nonexistent"))
    } finally { tearDown() } }

    @Test fun `readFile on nonexistent file returns failure`() { assumeNative(); setUp(); try {
        assertTrue(fs.readFile("/nonexistent").isFailure)
    } finally { tearDown() } }

    @Test fun `readFile on directory returns failure`() { assumeNative(); setUp(); try {
        fs.createDirectory("/", "dir").getOrThrow()
        assertTrue(fs.readFile("/dir").isFailure)
    } finally { tearDown() } }

    // ── Unicode names ─────────────────────────────────────────────────────────

    @Test fun `unicode file name`() { assumeNative(); setUp(); try {
        val name = "ファイル.txt"
        val result = fs.createFile("/", name)
        if (result.isSuccess) {
            assertTrue(fs.exists("/$name"))
            val entries = fs.listDirectory("/").getOrThrow()
            assertTrue(entries.any { it.name == name })
        }
    } finally { tearDown() } }

    @Test fun `file name with spaces and special chars`() { assumeNative(); setUp(); try {
        val name = "my file name (1).dat"
        fs.createFile("/", name).getOrThrow()
        assertTrue(fs.exists("/$name"))
    } finally { tearDown() } }
}