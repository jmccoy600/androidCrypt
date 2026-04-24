package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.map
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * **T2 — Mount/unmount round-trip.**
 *
 * For a random sequence of filesystem operations, build a shadow model
 * (`Map<String, ByteArray>`), apply the operations live, then `unmount()`,
 * open a fresh `VolumeReader`, `mount()` again, and assert that the file
 * tree and every file's bytes are byte-identical to the shadow model.
 *
 * This is the only property in the suite that catches:
 *   - dirty cache entries not flushed on unmount,
 *   - cluster allocations not persisted,
 *   - directory entries written only into the cache,
 *   - sector writes accumulated in memory but never fsync'd.
 *
 * Because each iteration creates a *new* container (mount/unmount must be
 * exercised end-to-end), iteration counts are kept low.
 */
class FAT32MountRoundTripPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_mount_rt_pbt")
    private val password = "MountRoundTripPBT!".toCharArray()

    private sealed class Op {
        data class Mkdir(val path: String) : Op()
        data class Write(val path: String, val data: ByteArray) : Op()
        data class Delete(val path: String) : Op()
    }

    private fun stemArb(): Arb<String> =
        Arb.bind(
            Arb.choice(Arb.constant("a"), Arb.constant("b"), Arb.constant("doc")),
            Arb.int(0, 5)
        ) { s, n -> "$s$n.dat" }

    private fun dirArb(): Arb<String> = Arb.int(0, 2).map { "d$it" }
    private fun payloadArb(): Arb<ByteArray> = Arb.byteArray(Arb.int(0, 4096), Arb.byte())

    private fun opArb(): Arb<Op> = Arb.choice(
        dirArb().map { Op.Mkdir("/$it") },
        Arb.bind(stemArb(), payloadArb()) { n, p -> Op.Write("/$n", p) },
        Arb.bind(dirArb(), stemArb(), payloadArb()) { d, n, p -> Op.Write("/$d/$n", p) },
        stemArb().map { Op.Delete("/$it") }
    )

    private fun ensureParent(fs: FAT32Reader, path: String) {
        val parent = path.substringBeforeLast('/', "/")
        if (parent != "/" && parent.isNotEmpty() && !fs.exists(parent)) {
            val parentParent = parent.substringBeforeLast('/', "/")
            val name = parent.substringAfterLast('/')
            fs.createDirectory(parentParent.ifEmpty { "/" }, name)
        }
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `filesystem state survives unmount and remount byte-for-byte`(): Unit = runBlocking {
        testDir.mkdirs()
        try {
            checkAll(
                PropTestConfig(iterations = 6, seed = 0xB00710A1L),
                Arb.list(opArb(), 3..10)
            ) { ops ->
                val container = File(testDir, "rt_${System.nanoTime()}.hc")
                VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 8L)
                    .getOrThrow()

                val model = HashMap<String, ByteArray>()
                val mkdirs = HashSet<String>()

                // ── Phase 1: mount, apply, unmount ──
                run {
                    val r = VolumeReader(container.absolutePath)
                    r.mount(password.copyOf()).getOrThrow()
                    val fs = FAT32Reader(r); fs.initialize().getOrThrow()
                    for (op in ops) {
                        try {
                            when (op) {
                                is Op.Mkdir -> {
                                    val parent = op.path.substringBeforeLast('/', "/").ifEmpty { "/" }
                                    val name = op.path.substringAfterLast('/')
                                    if (!fs.exists(op.path)) {
                                        fs.createDirectory(parent, name).getOrThrow()
                                        mkdirs.add(op.path)
                                    }
                                }
                                is Op.Write -> {
                                    ensureParent(fs, op.path)
                                    if (!fs.exists(op.path)) {
                                        val parent = op.path.substringBeforeLast('/', "/").ifEmpty { "/" }
                                        val name = op.path.substringAfterLast('/')
                                        fs.createFile(parent, name).getOrThrow()
                                    }
                                    fs.writeFile(op.path, op.data).getOrThrow()
                                    model[op.path] = op.data
                                }
                                is Op.Delete -> {
                                    if (fs.exists(op.path)) {
                                        fs.delete(op.path).getOrThrow()
                                        model.remove(op.path)
                                    }
                                }
                            }
                        } catch (_: Exception) {
                            // Skip unapplicable ops (parent missing, name clash, etc.)
                        }
                    }
                    r.unmount()
                }

                // ── Phase 2: re-open, verify ──
                val r2 = VolumeReader(container.absolutePath)
                r2.mount(password.copyOf()).getOrThrow()
                val fs2 = FAT32Reader(r2); fs2.initialize().getOrThrow()

                for ((path, expected) in model) {
                    assertTrue("file $path missing after remount", fs2.exists(path))
                    val actual = fs2.readFile(path).getOrThrow()
                    assertEquals("size mismatch for $path after remount", expected.size, actual.size)
                    assertArrayEquals("content mismatch for $path after remount", expected, actual)
                }
                // Directories created should still exist.
                for (d in mkdirs) {
                    assertTrue("directory $d missing after remount", fs2.exists(d))
                }
                r2.unmount()
                container.delete()
            }
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }
}
