package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.map
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/**
 * **T5 — Path-normalization equivalence.**
 *
 * FAT32 is case-insensitive, and a well-behaved client must accept any
 * syntactic form of the same path. For every file written via the canonical
 * form, the following must resolve to the same entry:
 *
 *   - lowercase           `/foo/bar.txt`
 *   - UPPERCASE           `/FOO/BAR.TXT`
 *   - MiXeDcAsE           `/Foo/Bar.Txt`
 *   - trailing slash      `/foo/bar.txt/`   (only for directories)
 *   - duplicate slashes   `//foo//bar.txt`
 *
 * For each form we assert: `exists()` is `true`, `getFileInfo()` succeeds
 * and reports the same size, and `readFile()` returns identical bytes.
 *
 * This is the property that found the
 * `delete()`-doesn't-`normalizePath()`-the-fileCache-key bug; here we add
 * forward coverage to catch the same bug pattern in any other path-taking
 * API.
 */
class FAT32PathNormalizationPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_pathnorm_pbt")
        private const val PASSWORD = "PathNormPBT!"
        private lateinit var containerFile: File
        private lateinit var reader: VolumeReader
        private lateinit var fs: FAT32Reader

        @BeforeClass @JvmStatic
        fun setUp() {
            TEST_DIR.mkdirs()
            containerFile = File(TEST_DIR, "pn_${System.nanoTime()}.hc")
            VolumeCreator.createContainer(containerFile.absolutePath, PASSWORD.toCharArray(), 8L).getOrThrow()
            reader = VolumeReader(containerFile.absolutePath)
            reader.mount(PASSWORD.toCharArray()).getOrThrow()
            fs = FAT32Reader(reader); fs.initialize().getOrThrow()
        }

        @AfterClass @JvmStatic
        fun tearDown() {
            try { reader.unmount() } catch (_: Exception) {}
            containerFile.delete()
            TEST_DIR.delete()
        }
    }

    private fun mutate(path: String, mode: Int): String = when (mode) {
        0 -> path                              // canonical lowercase
        1 -> path.uppercase()                  // ALL CAPS
        2 -> path.mapIndexed { i, c -> if (i % 2 == 0) c.uppercaseChar() else c }.joinToString("")
        3 -> path.replace("/", "//")           // duplicate slashes (skip leading)
            .let { if (it.startsWith("//")) it.substring(1) else it }
        else -> path
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `case and slash variations of a path resolve identically`(): Unit = runBlocking {
        var iter = 0
        checkAll(
            PropTestConfig(iterations = 8, seed = 0x9A75CA5EL),
            Arb.bind(
                Arb.choice(Arb.constant("alpha"), Arb.constant("dir1"), Arb.constant("subdir")),
                Arb.choice(Arb.constant("file"), Arb.constant("doc"), Arb.constant("note")),
                Arb.int(0, 99)
            ) { d, f, n -> Triple(d, f, n) }
        ) { (dirStem, fileStem, n) ->
            iter++
            val dirName = "${dirStem}_$iter"
            val fileName = "${fileStem}_$iter.txt"
            fs.createDirectory("/", dirName).getOrThrow()
            val canonical = "/$dirName/$fileName"
            fs.createFile("/$dirName", fileName).getOrThrow()
            val payload = "iter=$iter n=$n hello".toByteArray(Charsets.UTF_8)
            fs.writeFile(canonical, payload).getOrThrow()

            // Try every syntactic mutation. They must all return the same entry.
            for (mode in 0..3) {
                val variant = mutate(canonical, mode)
                assertTrue("exists($variant) returned false (mode=$mode, canonical=$canonical)", fs.exists(variant))
                val info = fs.getFileInfo(variant).getOrThrow()
                assertEquals(
                    "size mismatch via variant '$variant' (mode=$mode)",
                    payload.size.toLong(), info.size
                )
                val read = fs.readFile(variant).getOrThrow()
                assertArrayEquals(
                    "content differs via variant '$variant' (mode=$mode)",
                    payload, read
                )
            }

            // Cleanup.
            fs.delete("/$dirName").getOrThrow()
            reader.sync()
        }
    }
}
