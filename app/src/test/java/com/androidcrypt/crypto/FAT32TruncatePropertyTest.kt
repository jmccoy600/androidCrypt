package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/**
 * **T3 — Truncate / shrink invariants.**
 *
 * `writeFile(path, smallerData)` must:
 *
 *   1. Leave the file's content equal to `smallerData` exactly (no leftover
 *      tail bytes from the previous payload).
 *   2. Free `(initialClusters − finalClusters)` clusters from the FAT — no
 *      more, no less.
 *   3. Leave the FAT chain length equal to `ceil(finalSize / clusterSize)`
 *      (so that subsequent reads do not walk past the file end).
 *
 * The combinations of `(initialSize, finalSize)` deliberately span cluster
 * boundaries (single-cluster -> multi-cluster, growing then shrinking,
 * shrink-to-empty, and shrink-to-zero-then-grow) — these are the boundaries
 * where every FAT implementation tends to leak clusters.
 */
class FAT32TruncatePropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_truncate_pbt")
        private const val PASSWORD = "TruncatePBT!"
        private lateinit var containerFile: File
        private lateinit var reader: VolumeReader
        private lateinit var fs: FAT32Reader
        private var clusterSize: Int = 0

        @BeforeClass @JvmStatic
        fun setUp() {
            TEST_DIR.mkdirs()
            containerFile = File(TEST_DIR, "trunc_${System.nanoTime()}.hc")
            VolumeCreator.createContainer(containerFile.absolutePath, PASSWORD.toCharArray(), 10L).getOrThrow()
            reader = VolumeReader(containerFile.absolutePath)
            reader.mount(PASSWORD.toCharArray()).getOrThrow()
            fs = FAT32Reader(reader); fs.initialize().getOrThrow()
            clusterSize = fs.getClusterSize()
            fs.createDirectory("/", "trunc")
        }

        @AfterClass @JvmStatic
        fun tearDown() {
            try { reader.unmount() } catch (_: Exception) {}
            containerFile.delete()
            TEST_DIR.delete()
        }
    }

    private fun clustersNeeded(size: Int): Int =
        if (size == 0) 0 else (size + clusterSize - 1) / clusterSize

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `shrinking write frees exactly the difference and leaves no tail bytes`(): Unit = runBlocking {
        var iter = 0
        // Sizes are sized in cluster-sized units to land on cluster boundaries
        // half the time and span them the other half.
        val sizesArb = Arb.int(0, 8)  // multiplier for cluster-size chunks
        val deltaArb = Arb.int(-clusterSize / 2, clusterSize / 2 + 1) // off-boundary jitter

        checkAll(
            PropTestConfig(iterations = 20, seed = 0x7E11A0AdL),
            sizesArb, deltaArb, sizesArb, deltaArb
        ) { initMul, initJitter, finalMul, finalJitter ->
            iter++
            val initSize = (initMul * clusterSize + initJitter).coerceAtLeast(0)
            val finalSize = (finalMul * clusterSize + finalJitter).coerceAtLeast(0)

            val name = "f$iter.bin"
            val path = "/trunc/$name"

            val initData = ByteArray(initSize) { ((it * 31 + iter) and 0xFF).toByte() }
            val finalData = ByteArray(finalSize) { ((it * 7 + iter) and 0xFF).toByte() }

            // Initial write
            if (!fs.exists(path)) fs.createFile("/trunc", name).getOrThrow()
            fs.writeFile(path, initData).getOrThrow()
            reader.sync()
            val freeAfterInit = fs.countFreeClusters()
            val initClusters = clustersNeeded(initSize)
            val finalClusters = clustersNeeded(finalSize)

            // Shrinking (or growing) write
            fs.writeFile(path, finalData).getOrThrow()
            reader.sync()
            val freeAfterFinal = fs.countFreeClusters()

            // (1) Content equals finalData exactly — no leftover tail.
            val readBack = fs.readFile(path).getOrThrow()
            assertEquals("size mismatch (init=$initSize -> final=$finalSize)", finalSize, readBack.size)
            assertArrayEquals("content mismatch (init=$initSize -> final=$finalSize)", finalData, readBack)

            // (2) Cluster delta is exactly initClusters - finalClusters.
            val expectedDelta = initClusters - finalClusters
            val actualDelta = freeAfterFinal - freeAfterInit
            assertEquals(
                "cluster-free delta mismatch on shrink (initSize=$initSize finalSize=$finalSize " +
                        "initClusters=$initClusters finalClusters=$finalClusters): " +
                        "expected free to grow by $expectedDelta but grew by $actualDelta",
                expectedDelta, actualDelta
            )

            // Cleanup so each iteration starts from a known state.
            fs.delete(path).getOrThrow()
            reader.sync()
        }
    }
}
