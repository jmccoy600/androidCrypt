package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
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
 * **ExFAT-T11 — Path normalization property test.**
 *
 * Mirrors [FAT32PathNormalizationPropertyTest]. Tests that case and slash
 * variations of a path resolve identically (exFAT is case-insensitive per spec).
 */
class ExFatPathNormalizationPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_path")
    private val password = "ExFatPath!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto"); true
    } catch (_: UnsatisfiedLinkError) { false }

    private fun assumeNative() { if (!nativeAvailable) throw AssumptionViolatedException("native lib") }

    private fun mutate(path: String, mode: Int): String = when (mode) {
        0 -> path // canonical
        1 -> path.uppercase()
        2 -> { // mixed case: every other char uppercased
            path.mapIndexed { i, c -> if (i % 2 == 0) c.uppercaseChar() else c.lowercaseChar() }.joinToString("")
        }
        3 -> if (path.startsWith("/")) "//" + path.substring(1) else path // leading double slash
        else -> path
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `case and slash variations of a path resolve identically`() = runBlocking {
        assumeNative()
        testDir.mkdirs()
        val container = File(testDir, "path_${System.nanoTime()}.hc")
        try {
            VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 8L,
                fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
            val reader = VolumeReader(container.absolutePath)
            reader.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader)
            fs.initialize().getOrThrow()

            checkAll(PropTestConfig(iterations = 6, seed = 0x9A75CA5EL),
                Arb.bind(
                    Arb.choice(Arb.constant("alpha"), Arb.constant("dir1"), Arb.constant("subdir")),
                    Arb.choice(Arb.constant("file"), Arb.constant("doc"), Arb.constant("note")),
                    Arb.int(0, 99)
                ) { dir, file, n -> Triple(dir, file, n) }
            ) { (dir, file, n) ->
                val dirName = "${dir}_$n"
                val fileName = "${file}_$n.txt"
                val canonicalDir = "/$dirName"
                val canonicalPath = "/$dirName/$fileName"
                val payload = "data_$n".toByteArray()

                try {
                    fs.createDirectory("/", dirName).getOrThrow()
                    fs.createFile(canonicalDir, fileName).getOrThrow()
                    fs.writeFile(canonicalPath, payload).getOrThrow()
                } catch (_: Exception) { return@checkAll }

                // For each mutation mode, the path should still resolve to the same file
                for (mode in 0..3) {
                    val mutant = mutate(canonicalPath, mode)
                    assertTrue("exists mode=$mode: $mutant", fs.exists(mutant))
                    val info = fs.getFileInfo(mutant).getOrThrow()
                    assertEquals("size mode=$mode for $mutant", payload.size.toLong(), info.size)
                    val readBack = fs.readFile(mutant).getOrThrow()
                    assertArrayEquals("content mode=$mode for $mutant", payload, readBack)
                }
            }
            reader.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }
}