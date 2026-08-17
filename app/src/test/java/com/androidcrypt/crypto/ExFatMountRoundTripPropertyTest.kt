package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.byteArray
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
 * **ExFAT-T1 — Mount/unmount round-trip.**
 *
 * Mirrors [FAT32MountRoundTripPropertyTest] but exercises an exFAT-formatted
 * container via [VolumeCreator.createContainer] with [VolumeFileSystem.EXFAT].
 *
 * Each iteration:
 *  1. Creates a fresh exFAT container
 *  2. Applies a random sequence of mkdir/write/delete operations
 *  3. Unmounts, re-mounts, and asserts every model file's bytes round-trip exactly
 *
 * Catches: SetChecksum bugs, FAT chain errors, allocation bitmap drift,
 * directory-entry corruption, and unmount-flush regressions specific to exFAT.
 */
class ExFatMountRoundTripPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_rt_pbt")
    private val password = "ExFatRoundTripPBT!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto")
        true
    } catch (_: UnsatisfiedLinkError) {
        false
    }

    private fun assumeNative() {
        if (!nativeAvailable) {
            throw AssumptionViolatedException("Native library veracrypt_crypto not available")
        }
    }

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

    private fun ensureParent(fs: ExFatReader, path: String) {
        val parent = path.substringBeforeLast('/', "/")
        if (parent != "/" && parent.isNotEmpty() && !fs.exists(parent)) {
            val parentParent = parent.substringBeforeLast('/', "/")
            val name = parent.substringAfterLast('/')
            fs.createDirectory(parentParent.ifEmpty { "/" }, name)
        }
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `exfat filesystem state survives unmount and remount byte-for-byte`() {
        runBlocking {
            assumeNative()
            testDir.mkdirs()
            try {
                checkAll(
                    PropTestConfig(iterations = 4, seed = 0xE7F4AL),
                    Arb.list(opArb(), 3..8)
                ) { ops ->
                    val container = File(testDir, "exfat_rt_${System.nanoTime()}.hc")
                    VolumeCreator.createContainer(
                        container.absolutePath, password.copyOf(), 8L,
                        fileSystem = VolumeFileSystem.EXFAT
                    ).getOrThrow()

                    val model = HashMap<String, ByteArray>()
                    val mkdirs = HashSet<String>()

                    // ── Phase 1: mount, apply, unmount ──
                    run {
                        val r = VolumeReader(container.absolutePath)
                        r.mount(password.copyOf()).getOrThrow()
                        val fs = ExFatReader(r); fs.initialize().getOrThrow()
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
                                // Skip unapplicable ops
                            }
                        }
                        r.unmount()
                    }

                    // ── Phase 2: re-open, verify ──
                    val r2 = VolumeReader(container.absolutePath)
                    r2.mount(password.copyOf()).getOrThrow()
                    val fs2 = ExFatReader(r2); fs2.initialize().getOrThrow()

                    for ((path, expected) in model) {
                        assertTrue("file $path missing after remount", fs2.exists(path))
                        val actual = fs2.readFile(path).getOrThrow()
                        assertEquals("size mismatch for $path after remount", expected.size, actual.size)
                        assertArrayEquals("content mismatch for $path after remount", expected, actual)
                    }
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
}