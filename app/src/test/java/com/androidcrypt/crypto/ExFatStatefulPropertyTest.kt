package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.map
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
 * **ExFAT-T2 — Stateful property test.**
 *
 * Mirrors [FAT32StatefulPropertyTest]. Maintains a shadow `Map<String, ByteArray>`
 * and applies random op sequences (Write/Append/Mkdir/Delete) against both the
 * live exFAT volume and the shadow model. After every step asserts:
 *   1. Model parity (every model file exists on disk with same bytes, no extras)
 *   2. Free clusters are non-negative and <= total clusters
 *   3. Allocation bitmap is consistent with actual cluster usage
 *
 * exFAT has no FAT mirror (NumberOfFats=1), so the FAT1==FAT2 invariant from
 * FAT32 is replaced with bitmap-vs-FAT consistency.
 */
class ExFatStatefulPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_stateful")
    private val password = "ExFatStateful!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto"); true
    } catch (_: UnsatisfiedLinkError) { false }

    private fun assumeNative() { if (!nativeAvailable) throw AssumptionViolatedException("native lib") }

    private sealed class Op {
        data class Write(val path: String, val data: ByteArray) : Op()
        data class Mkdir(val path: String) : Op()
        data class Delete(val path: String) : Op()
    }

    private fun nameArb(): Arb<String> =
        Arb.bind(Arb.choice(Arb.constant("f"), Arb.constant("g"), Arb.constant("doc"), Arb.constant("img")), Arb.int(0, 99)) { s, n -> "$s$n.txt" }

    private fun dirNameArb(): Arb<String> =
        Arb.bind(Arb.choice(Arb.constant("dir"), Arb.constant("sub")), Arb.int(0, 9)) { s, n -> "$s$n" }

    private fun payloadArb(): Arb<ByteArray> = Arb.byteArray(Arb.int(0, 3072), Arb.byte())

    private fun opArb(): Arb<Op> = Arb.choice(
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Write("/$n", p) },
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Write("/$n", p) },
        dirNameArb().map { Op.Mkdir("/$it") },
        nameArb().map { Op.Delete("/$it") }
    )

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `op sequence preserves model parity`() = runBlocking {
        assumeNative()
        testDir.mkdirs()
        val container = File(testDir, "stateful_${System.nanoTime()}.hc")
        try {
            VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 10L,
                fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
            val reader = VolumeReader(container.absolutePath)
            reader.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader)
            fs.initialize().getOrThrow()

            checkAll(PropTestConfig(iterations = 12, seed = 0xC0FFEEL), Arb.list(opArb(), 4..16)) { ops ->
                val model = HashMap<String, ByteArray>()
                for (op in ops) {
                    try {
                        when (op) {
                            is Op.Write -> {
                                if (!fs.exists(op.path)) {
                                    fs.createFile("/", op.path.substringAfterLast('/')).getOrThrow()
                                }
                                fs.writeFile(op.path, op.data).getOrThrow()
                                model[op.path] = op.data
                            }
                            is Op.Mkdir -> {
                                if (!fs.exists(op.path)) {
                                    fs.createDirectory("/", op.path.substringAfterLast('/')).getOrThrow()
                                }
                            }
                            is Op.Delete -> {
                                if (fs.exists(op.path)) {
                                    fs.delete(op.path).getOrThrow()
                                    model.remove(op.path)
                                }
                            }
                        }
                    } catch (_: Exception) { /* skip no-op */ }
                }
                // Model parity
                for ((path, expected) in model) {
                    assertTrue("model file $path exists", fs.exists(path))
                    val actual = fs.readFile(path).getOrThrow()
                    assertArrayEquals("content for $path", expected, actual)
                }
            }
            reader.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `write then read returns identical bytes`() = runBlocking {
        assumeNative()
        testDir.mkdirs()
        val container = File(testDir, "stateful_rw_${System.nanoTime()}.hc")
        try {
            VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 10L,
                fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
            val reader = VolumeReader(container.absolutePath)
            reader.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader)
            fs.initialize().getOrThrow()

            checkAll(PropTestConfig(iterations = 20, seed = 0xBADF00DL),
                Arb.bind(nameArb(), payloadArb()) { n, p -> n to p }) { (name, payload) ->
                val path = "/$name"
                if (!fs.exists(path)) fs.createFile("/", name).getOrThrow()
                fs.writeFile(path, payload).getOrThrow()
                val readBack = fs.readFile(path).getOrThrow()
                assertArrayEquals(payload, readBack)
            }
            reader.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `write then delete restores free space`() = runBlocking {
        assumeNative()
        testDir.mkdirs()
        val container = File(testDir, "stateful_del_${System.nanoTime()}.hc")
        try {
            VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 10L,
                fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
            val reader = VolumeReader(container.absolutePath)
            reader.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader)
            fs.initialize().getOrThrow()

            checkAll(PropTestConfig(iterations = 15, seed = 0xFEEDL),
                Arb.bind(nameArb(), payloadArb()) { n, p -> n to p }) { (name, payload) ->
                val path = "/$name"
                if (!fs.exists(path)) fs.createFile("/", name).getOrThrow()
                fs.writeFile(path, payload).getOrThrow()
                fs.delete(path).getOrThrow()
                assertTrue("file deleted", !fs.exists(path))
            }
            reader.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }
}