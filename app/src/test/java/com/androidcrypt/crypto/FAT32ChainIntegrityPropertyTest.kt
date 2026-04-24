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
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * **T1 — Cluster-chain integrity** (the strongest correctness invariant a
 * FAT32 implementation can satisfy).
 *
 * After any sequence of create / write / append / delete operations, walk the
 * whole on-disk filesystem and assert:
 *
 *   1. **Conservation** — `freeClusters + Σ(reachable chain lengths) ==
 *      totalClusters` (no leaks, no double-counting).
 *   2. **No sharing** — no FAT entry appears in two distinct chains.
 *   3. **No dangling pointer** — every link in every chain points to either
 *      an EOC marker (`>= 0x0FFFFFF8`) or an entry whose value is non-zero
 *      (a free cluster reached from a chain means the chain points into a
 *      free cluster, which is corruption).
 *   4. **No cycles** — every chain terminates within `totalClusters` steps.
 *   5. **Cached free count == on-disk scan** — the cached free-cluster count
 *      matches a fresh FAT scan (regression for the off-by-one fixed in
 *      `prefetchFAT`).
 *
 * These five together exactly characterise a well-formed FAT.
 */
class FAT32ChainIntegrityPropertyTest {

    companion object {
        private val TEST_DIR =
            File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_chain_pbt")
        private const val PASSWORD = "ChainIntegrityPBT!"
        private lateinit var containerFile: File
        private lateinit var reader: VolumeReader
        private lateinit var fs: FAT32Reader
        private var bytesPerSector: Int = 0
        private var sectorsPerCluster: Int = 0
        private var reservedSectors: Int = 0
        private var numFATs: Int = 0
        private var sectorsPerFAT: Long = 0
        private var totalSectors: Long = 0
        private var totalClusters: Int = 0

        @BeforeClass @JvmStatic
        fun setUp() {
            TEST_DIR.mkdirs()
            containerFile = File(TEST_DIR, "chain_${System.nanoTime()}.hc")
            VolumeCreator.createContainer(
                containerFile.absolutePath, PASSWORD.toCharArray(), 12L
            ).getOrThrow()
            reader = VolumeReader(containerFile.absolutePath)
            reader.mount(PASSWORD.toCharArray()).getOrThrow()
            fs = FAT32Reader(reader)
            fs.initialize().getOrThrow()

            val bs = reader.readSector(0).getOrThrow()
            bytesPerSector = (bs[11].toInt() and 0xFF) or ((bs[12].toInt() and 0xFF) shl 8)
            sectorsPerCluster = bs[13].toInt() and 0xFF
            reservedSectors = (bs[14].toInt() and 0xFF) or ((bs[15].toInt() and 0xFF) shl 8)
            numFATs = bs[16].toInt() and 0xFF
            sectorsPerFAT = ByteBuffer.wrap(bs, 36, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong()
            totalSectors = ByteBuffer.wrap(bs, 32, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong()
            val firstDataSector = reservedSectors + numFATs * sectorsPerFAT
            totalClusters = ((totalSectors - firstDataSector) / sectorsPerCluster).toInt()
        }

        @AfterClass @JvmStatic
        fun tearDown() {
            try { reader.unmount() } catch (_: Exception) {}
            containerFile.delete()
            TEST_DIR.delete()
        }
    }

    private sealed class Op {
        data class Mkdir(val name: String) : Op()
        data class Write(val name: String, val data: ByteArray) : Op()
        data class Append(val name: String, val data: ByteArray) : Op()
        data class Delete(val name: String) : Op()
    }

    private fun nameArb(): Arb<String> =
        Arb.bind(
            Arb.choice(Arb.constant("c"), Arb.constant("d"), Arb.constant("e")),
            Arb.int(0, 7)
        ) { p, n -> "$p$n.bin" }

    private fun dirArb(): Arb<String> =
        Arb.int(0, 3).map { "sub$it" }

    private fun payloadArb(): Arb<ByteArray> =
        Arb.byteArray(Arb.int(0, 6 * 1024), Arb.byte())

    private fun opArb(): Arb<Op> = Arb.choice(
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Write(n, p) },
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Write(n, p) },
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Append(n, p) },
        dirArb().map { Op.Mkdir(it) },
        nameArb().map { Op.Delete(it) }
    )

    /** Read the entire FAT (FAT1) into a flat IntArray indexed 0..totalClusters+1. */
    private fun readFat(): IntArray {
        val fatSizeBytes = (sectorsPerFAT * bytesPerSector).toInt()
        val sectorsToRead = sectorsPerFAT.toInt()
        val fatStartSector = reservedSectors.toLong()
        // Read in 32-sector chunks to keep memory reasonable
        val fat = ByteArray(fatSizeBytes)
        var done = 0
        var sec = 0L
        while (done < fatSizeBytes) {
            val n = minOf(32, sectorsToRead - sec.toInt())
            val data = reader.readSectors(fatStartSector + sec, n).getOrThrow()
            System.arraycopy(data, 0, fat, done, n * bytesPerSector)
            done += n * bytesPerSector
            sec += n
        }
        val entries = IntArray(totalClusters + 2)
        val buf = ByteBuffer.wrap(fat).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until totalClusters + 2) {
            entries[i] = buf.int and 0x0FFFFFFF
        }
        return entries
    }

    /** Walk every directory (DFS) and return the set of first-cluster ints
     *  (only files/dirs with at least one cluster — empty files have first=0
     *  and own no clusters). */
    private fun collectFileFirstClusters(root: String, fat: IntArray): List<Int> {
        val out = mutableListOf<Int>()
        val stack = ArrayDeque<String>()
        stack.addLast(root)
        while (stack.isNotEmpty()) {
            val path = stack.removeLast()
            val entries = fs.listDirectory(path).getOrThrow()
            for (e in entries) {
                val fullPath = if (path == "/") "/${e.name}" else "$path/${e.name}"
                if (e.isDirectory) {
                    val info = fs.getFileInfoWithClusterPublic(fullPath).getOrNull()
                    val fc = info?.firstCluster ?: 0
                    if (fc >= 2) out.add(fc)
                    stack.addLast(fullPath)
                } else {
                    val info = fs.getFileInfoWithClusterPublic(fullPath).getOrNull()
                    val fc = info?.firstCluster ?: 0
                    if (fc >= 2) out.add(fc)
                }
            }
        }
        return out
    }

    private fun walkChain(start: Int, fat: IntArray): List<Int> {
        val visited = mutableListOf<Int>()
        val seen = HashSet<Int>()
        var c = start
        var hops = 0
        while (c in 2..(totalClusters + 1) && c < 0x0FFFFFF8) {
            assertTrue("cycle detected at cluster $c", seen.add(c))
            visited.add(c)
            c = fat[c]
            hops++
            assertTrue("chain longer than totalClusters — likely a cycle", hops <= totalClusters + 1)
        }
        // Final c must be EOC marker (>= 0x0FFFFFF8). A bare 0 here means a
        // chain pointer that walked into a free cluster: corruption.
        assertTrue(
            "chain from $start ended at non-EOC entry $c (corruption: dangling chain pointer)",
            c >= 0x0FFFFFF8
        )
        return visited
    }

    private fun applyOps(workDir: String, ops: List<Op>) {
        for (op in ops) {
            try {
                when (op) {
                    is Op.Mkdir -> fs.createDirectory(workDir, op.name)
                    is Op.Write -> {
                        val full = "$workDir/${op.name}"
                        if (!fs.exists(full)) fs.createFile(workDir, op.name)
                        fs.writeFile(full, op.data)
                    }
                    is Op.Append -> {
                        val full = "$workDir/${op.name}"
                        val existing = if (fs.exists(full))
                            fs.readFile(full).getOrElse { ByteArray(0) }
                        else {
                            fs.createFile(workDir, op.name)
                            ByteArray(0)
                        }
                        fs.writeFile(full, existing + op.data)
                    }
                    is Op.Delete -> {
                        val full = "$workDir/${op.name}"
                        if (fs.exists(full)) fs.delete(full)
                    }
                }
            } catch (_: Exception) {
                // Skip ops that can't be applied (e.g. delete of nonexistent);
                // the property is about the on-disk state being consistent
                // *after* whatever sequence actually executed.
            }
        }
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `random ops leave the FAT chain-integrity invariants intact`(): Unit = runBlocking {
        var iter = 0
        checkAll(
            PropTestConfig(iterations = 12, seed = 0xC4A1FA17L),
            Arb.list(opArb(), 4..18)
        ) { ops ->
            iter++
            val workDir = "/chain_$iter"
            fs.createDirectory("/", "chain_$iter")

            applyOps(workDir, ops)
            // Don't sync — the property must hold for the in-memory state too,
            // but FAT-mirror checks read from disk so we do sync to flush.
            reader.sync()

            val fat = readFat()

            // (5) Cached free-cluster count must equal a fresh on-disk scan.
            val cachedFree = fs.countFreeClusters()
            var scannedFree = 0
            // Valid FAT32 data-cluster numbers are 2..N+1 where N=totalClusters.
            for (i in 2..totalClusters + 1) if (fat[i] == 0) scannedFree++
            assertEquals(
                "cached free-cluster count drifted from on-disk scan (iter=$iter, ops=${ops.size})",
                scannedFree, cachedFree
            )

            // Walk every reachable chain and accumulate visited clusters.
            val starts = collectFileFirstClusters("/", fat)
            // Also include directory chains whose first cluster lives in the
            // FAT (root is special-cased and may be a fixed cluster — skip 2
            // explicitly only when bs.rootDirFirstCluster is known; for our
            // fresh containers root is cluster 2 and is also walked as
            // collectFileFirstClusters returns it implicitly via its parent's
            // entry — but the root has no parent entry, so we must add it
            // manually).
            val rootFirst = readBootRootCluster()
            val allStarts = (starts + rootFirst).distinct()

            val seenInChain = HashMap<Int, Int>() // cluster -> chain start (for sharing detection)
            var totalReachable = 0
            for (start in allStarts) {
                val chain = walkChain(start, fat)
                totalReachable += chain.size
                for (c in chain) {
                    val prevOwner = seenInChain.put(c, start)
                    assertTrue(
                        "cluster $c shared between chains $prevOwner and $start (cross-link)",
                        prevOwner == null
                    )
                }
            }

            // (1) Conservation: free + reachable == totalClusters.
            assertEquals(
                "conservation violated (iter=$iter): free=$scannedFree reachable=$totalReachable totalClusters=$totalClusters",
                totalClusters, scannedFree + totalReachable
            )

            // (3) No reachable cluster is itself marked free.
            for (c in seenInChain.keys) {
                assertFalse(
                    "cluster $c reachable from chain ${seenInChain[c]} but marked free in FAT",
                    fat[c] == 0
                )
            }

            // Cleanup: best-effort remove the per-iteration tree.
            try { fs.delete(workDir) } catch (_: Exception) {}
            reader.sync()
        }
    }

    private fun readBootRootCluster(): Int {
        val bs = reader.readSector(0).getOrThrow()
        return ByteBuffer.wrap(bs, 44, 4).order(ByteOrder.LITTLE_ENDIAN).int
    }
}
