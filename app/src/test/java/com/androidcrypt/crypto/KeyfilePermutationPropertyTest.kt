package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.io.File

/**
 * **T8 — Keyfile permutation invariance.**
 *
 * VeraCrypt's keyfile mixing algorithm XORs (actually adds) each keyfile's
 * CRC stream into a fixed-size pool starting at position 0. The result is
 * therefore *commutative*: any permutation of the same set of keyfiles
 * MUST produce the exact same derived password bytes.
 *
 * If a future refactor accidentally introduces an ordering dependency
 * (e.g. carrying `writePos` between files, or chaining the CRC seed), this
 * property fires immediately.
 *
 * Equally important: a *different* set of keyfiles MUST produce a different
 * password (sanity).
 */
class KeyfilePermutationPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_keyfile_perm_pbt")

    private fun writeKeyfile(name: String, content: ByteArray): String {
        val f = File(testDir, name)
        f.writeBytes(content)
        return f.absolutePath
    }

    private fun derive(password: CharArray, paths: List<String>): ByteArray =
        KeyfileProcessor.applyKeyfiles(password, paths, context = null).getOrThrow()

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `derived password is invariant under keyfile order`(): Unit = runBlocking {
        testDir.mkdirs()
        try {
            checkAll(
                PropTestConfig(iterations = 20, seed = 0xCAFEFACEL),
                Arb.list(Arb.byteArray(Arb.int(64, 4096), Arb.byte()), 2..5)
            ) { keyfileContents ->
                val pw = "perm-test-pw".toCharArray()
                val paths = keyfileContents.mapIndexed { i, c ->
                    writeKeyfile("kf_${System.nanoTime()}_$i.bin", c)
                }
                try {
                    val ref = derive(pw.copyOf(), paths)
                    // Try a few permutations.
                    val perms = listOf(
                        paths.reversed(),
                        paths.shuffled(java.util.Random(0xDEADBEEFL)),
                        paths.shuffled(java.util.Random(0x1234567L)),
                    ).distinct()
                    for (perm in perms) {
                        val candidate = derive(pw.copyOf(), perm)
                        assertArrayEquals(
                            "keyfile order changed derived password " +
                                    "(orig=${paths.map { File(it).name }}, perm=${perm.map { File(it).name }})",
                            ref, candidate
                        )
                    }
                } finally {
                    paths.forEach { File(it).delete() }
                }
            }
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `removing or replacing a keyfile changes the derived password`(): Unit = runBlocking {
        testDir.mkdirs()
        try {
            checkAll(
                PropTestConfig(iterations = 12, seed = 0x5A1759E4L),
                Arb.byteArray(Arb.int(64, 2048), Arb.byte()),
                Arb.byteArray(Arb.int(64, 2048), Arb.byte()),
                Arb.byteArray(Arb.int(64, 2048), Arb.byte())
            ) { a, b, c ->
                // a and b must not be identical (would yield same pool addition)
                if (a.contentEquals(b) || b.contentEquals(c) || a.contentEquals(c)) return@checkAll
                val pa = writeKeyfile("a_${System.nanoTime()}.bin", a)
                val pb = writeKeyfile("b_${System.nanoTime()}.bin", b)
                val pc = writeKeyfile("c_${System.nanoTime()}.bin", c)
                try {
                    val pw = "diff-test".toCharArray()
                    val k_ab = derive(pw.copyOf(), listOf(pa, pb))
                    val k_abc = derive(pw.copyOf(), listOf(pa, pb, pc))
                    val k_ac = derive(pw.copyOf(), listOf(pa, pc))
                    assertNotEquals("adding a keyfile must change the derived key",
                        k_ab.toList(), k_abc.toList())
                    assertNotEquals("replacing a keyfile must change the derived key",
                        k_ab.toList(), k_ac.toList())
                    // And length must equal max(pwLen, poolSize) — for the
                    // empty-pw case here, equals poolSize. Just sanity-check
                    // it's non-trivial.
                    assertEquals("derived length not stable across calls",
                        k_ab.size, k_ac.size)
                } finally {
                    File(pa).delete(); File(pb).delete(); File(pc).delete()
                }
            }
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }
}
