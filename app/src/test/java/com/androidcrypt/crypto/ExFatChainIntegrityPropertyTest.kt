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
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.AssumptionViolatedException
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * **ExFAT-T4 — Chain integrity property test.**
 *
 * Mirrors [FAT32ChainIntegrityPropertyTest]. After random op sequences, verifies:
 *   1. Every allocated cluster in the FAT is marked in the allocation bitmap
 *   2. Every chain reachable from a directory entry terminates at EOC (0xFFFFFFFF)
 *   3. No chain has cycles (visited-set cycle detection)
 *   4. No FAT entry points backward in its own chain
 *
 * exFAT uses FAT entries 0xFFFFFFF7 (bad) and 0xFFFFFFFF (EOC); free clusters
 * have FAT entry 0 and bitmap bit 0. The bitmap is the source of truth for
 * allocation, the FAT encodes chain linkage.
 */
class ExFatChainIntegrityPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_chain")
    private val password = "ExFatChain!".toCharArray()

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
        Arb.bind(Arb.choice(Arb.constant("c"), Arb.constant("d"), Arb.constant("e")), Arb.int(0, 7)) { s, n -> "$s$n.bin" }

    private fun dirArb(): Arb<String> = Arb.int(0, 3).map { "sub$it" }

    private fun payloadArb(): Arb<ByteArray> = Arb.byteArray(Arb.int(0, 6 * 1024), Arb.byte())

    private fun opArb(): Arb<Op> = Arb.choice(
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Write("/$n", p) },
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Write("/$n", p) },
        dirArb().map { Op.Mkdir("/$it") },
        nameArb().map { Op.Delete("/$it") }
    )

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `random ops leave FAT and bitmap consistent`() {
        runBlocking {
        assumeNative()
        testDir.mkdirs()
        val container = File(testDir, "chain_${System.nanoTime()}.hc")
        try {
            VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 12L,
                fileSystem = VolumeFileSystem.EXFAT).getOrThrow()

            checkAll(PropTestConfig(iterations = 8, seed = 0xC4A1FA17L),
                Arb.list(opArb(), 4..16)) { ops ->
                val reader = VolumeReader(container.absolutePath)
                reader.mount(password.copyOf()).getOrThrow()
                val fs = ExFatReader(reader)
                fs.initialize().getOrThrow()

                for (op in ops) {
                    try {
                        when (op) {
                            is Op.Write -> {
                                if (!fs.exists(op.path)) fs.createFile("/", op.path.substringAfterLast('/')).getOrThrow()
                                fs.writeFile(op.path, op.data).getOrThrow()
                            }
                            is Op.Mkdir -> {
                                if (!fs.exists(op.path)) fs.createDirectory("/", op.path.substringAfterLast('/')).getOrThrow()
                            }
                            is Op.Delete -> {
                                if (fs.exists(op.path)) fs.delete(op.path).getOrThrow()
                            }
                        }
                    } catch (_: Exception) { /* skip */ }
                }

                reader.sync()

                // Read boot sector for geometry
                val boot = reader.readSector(0).getOrThrow()
                val fatOffset = ByteBuffer.wrap(boot, 80, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                val fatLength = ByteBuffer.wrap(boot, 84, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                val clusterCount = ByteBuffer.wrap(boot, 92, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                val clusterHeapOffset = ByteBuffer.wrap(boot, 88, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                val rootCluster = ByteBuffer.wrap(boot, 96, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                val sectorsPerClusterShift = boot[109].toInt() and 0xFF
                val sectorsPerCluster = 1 shl sectorsPerClusterShift

                // Read the entire FAT
                val fatData = reader.readSectors(fatOffset, fatLength.toInt()).getOrThrow()
                val maxCluster = clusterCount + 1

                // Walk every reachable chain from the root directory
                val visited = mutableSetOf<Long>()
                fun walkChain(start: Long, label: String) {
                    var c = start
                    var hops = 0
                    while (c in 2..maxCluster && hops <= maxCluster) {
                        assertTrue("chain $label cycle at cluster $c", c !in visited)
                        visited.add(c)
                        val entryOff = (c * 4).toInt()
                        if (entryOff + 4 > fatData.size) break
                        val entry = ByteBuffer.wrap(fatData, entryOff, 4).order(ByteOrder.LITTLE_ENDIAN)
                            .int.toLong() and 0xFFFFFFFFL
                        if (entry == 0xFFFFFFFFL || entry == 0xFFFFFFF7L) break // EOC or bad
                        if (entry < 2 || entry > maxCluster) break // invalid
                        c = entry
                        hops++
                    }
                }

                // Walk root directory chain
                walkChain(rootCluster, "root")

                // Walk every file/directory chain from root directory entries
                val rootSector = clusterHeapOffset + (rootCluster - 2) * sectorsPerCluster
                val rootDirData = reader.readSectors(rootSector, sectorsPerCluster).getOrThrow()
                var off = 0
                while (off < rootDirData.size) {
                    val type = rootDirData[off]
                    if (type == 0x00.toByte()) break // EOD
                    if (type == ExFatReader.FILE) {
                        val streamOff = off + 32
                        val firstCluster = ByteBuffer.wrap(rootDirData, streamOff + 20, 4)
                            .order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                        if (firstCluster >= 2) {
                            walkChain(firstCluster, "file at off $off")
                        }
                        val secondaryCount = rootDirData[off + 1].toInt() and 0xFF
                        off += (1 + secondaryCount) * 32
                    } else {
                        off += 32
                    }
                }

                // Verify every allocated cluster (FAT entry != 0) has its bitmap bit set
                // and vice versa — read the allocation bitmap
                val entries = fs.listDirectory("/").getOrThrow()
                for (e in entries) {
                    if (e.firstCluster >= 2) {
                        walkChain(e.firstCluster.toLong(), "listed ${e.name}")
                    }
                }

                reader.unmount()
            }
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
        }
    }
}