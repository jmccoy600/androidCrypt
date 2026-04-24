package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.RandomSource
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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/**
 * Stateful property-based tests for [FAT32Reader].
 *
 * Each property generates a random sequence of filesystem operations
 * (mkdir / write / append / rename / delete) inside a fresh per-iteration
 * subdirectory of a shared container, replays them on the live FAT32
 * implementation while maintaining a *shadow model* (a plain Kotlin
 * `Map<String, ByteArray>`), and after every step asserts a small set of
 * algebraic invariants that any sane FAT32 implementation must satisfy:
 *
 * 1. **Model parity** — every file in the shadow model has the same byte
 *    content and size on disk; every on-disk file is in the model.
 * 2. **FAT mirror equality** — FAT1 and FAT2 are bit-identical (this is the
 *    invariant that the H-3 [VolumeReader.sync] hardening targets).
 * 3. **Free-space monotonicity within a step** — `countFreeClusters()` never
 *    returns a negative value or exceeds the total cluster count.
 * 4. **Round-trip readability** — every cluster chain in the directory walks
 *    cleanly to EOF without throwing.
 *
 * The container itself is created exactly once for the whole class
 * (creation is multi-second), and each property iteration operates inside
 * its own `/it_$n` subdirectory which is fully purged at the end. This
 * keeps the test in the seconds-not-minutes range.
 */
class FAT32StatefulPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_fat32_pbt")
        private const val PASSWORD = "FAT32PBTPass!"
        private lateinit var containerFile: File
        private lateinit var reader: VolumeReader
        private lateinit var fs: FAT32Reader

        // Boot-sector geometry, parsed once.
        private var bytesPerSector: Int = 0
        private var reservedSectors: Int = 0
        private var numFATs: Int = 0
        private var sectorsPerFAT: Long = 0
        private var sectorsPerCluster: Int = 0
        private var totalSectors: Long = 0

        @BeforeClass
        @JvmStatic
        fun classSetUp() {
            TEST_DIR.mkdirs()
            containerFile = File(TEST_DIR, "fat32_pbt_${System.nanoTime()}.hc")

            VolumeCreator.createContainer(
                containerFile.absolutePath, PASSWORD.toCharArray(), 10
            ).getOrThrow()

            reader = VolumeReader(containerFile.absolutePath)
            reader.mount(PASSWORD.toCharArray()).getOrThrow()
            fs = FAT32Reader(reader)
            fs.initialize().getOrThrow()

            // Parse the FAT32 geometry directly from sector 0.
            val bs = reader.readSector(0).getOrThrow()
            bytesPerSector = (bs[11].toInt() and 0xFF) or ((bs[12].toInt() and 0xFF) shl 8)
            sectorsPerCluster = bs[13].toInt() and 0xFF
            reservedSectors = (bs[14].toInt() and 0xFF) or ((bs[15].toInt() and 0xFF) shl 8)
            numFATs = bs[16].toInt() and 0xFF
            sectorsPerFAT = ((bs[36].toLong() and 0xFF)
                or ((bs[37].toLong() and 0xFF) shl 8)
                or ((bs[38].toLong() and 0xFF) shl 16)
                or ((bs[39].toLong() and 0xFF) shl 24))
            // total sectors at offset 32 (FAT32 always uses the 32-bit field).
            totalSectors = ((bs[32].toLong() and 0xFF)
                or ((bs[33].toLong() and 0xFF) shl 8)
                or ((bs[34].toLong() and 0xFF) shl 16)
                or ((bs[35].toLong() and 0xFF) shl 24))

            check(bytesPerSector == 512) { "expected 512-byte sectors, got $bytesPerSector" }
            check(numFATs == 2) { "expected 2 FAT mirrors, got $numFATs" }
            check(sectorsPerFAT > 0) { "sectorsPerFAT not parsed" }
        }

        @AfterClass
        @JvmStatic
        fun classTearDown() {
            try { reader.unmount() } catch (_: Exception) {}
            containerFile.delete()
            TEST_DIR.delete()
        }
    }

    // ── Operation algebra ───────────────────────────────────────────────────

    /** Shadow filesystem operations. Names are 8.3-safe ASCII. */
    private sealed class Op {
        data class Mkdir(val name: String) : Op()
        data class Write(val name: String, val payload: ByteArray) : Op()
        data class Append(val name: String, val payload: ByteArray) : Op()
        data class Rename(val name: String, val newName: String) : Op()
        data class Delete(val name: String) : Op()
    }

    private fun nameArb(): Arb<String> = Arb.int(0, 99).let { idArb ->
        Arb.bind(
            Arb.choice(
                Arb.constant("f"),
                Arb.constant("g"),
                Arb.constant("doc"),
                Arb.constant("img")
            ),
            idArb
        ) { stem, n -> "$stem$n.txt" }
    }

    private fun dirNameArb(): Arb<String> = Arb.int(0, 9).let { idArb ->
        Arb.bind(
            Arb.choice(Arb.constant("dir"), Arb.constant("sub")),
            idArb
        ) { stem, n -> "$stem$n" }
    }

    private fun payloadArb(): Arb<ByteArray> =
        // 0..3 KB. Small enough to keep the test fast, large enough to
        // exercise multi-cluster chains (cluster size is typically 4 KB or
        // less in a 10 MB container). Empty payloads are intentionally
        // included to exercise the truncate-to-empty fast path in writeFile.
        Arb.byteArray(Arb.int(0, 3072), Arb.byte())

    private fun opArb(): Arb<Op> = Arb.choice(
        // Bias towards writes/appends — they exercise allocation paths.
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Write(n, p) },
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Write(n, p) },
        Arb.bind(nameArb(), payloadArb()) { n, p -> Op.Append(n, p) },
        dirNameArb().map { Op.Mkdir(it) },
        Arb.bind(nameArb(), nameArb()) { a, b -> Op.Rename(a, b) },
        nameArb().map { Op.Delete(it) }
    )

    // ── Helper: read the FAT region twice and compare the two mirrors ───────

    private fun assertFatMirrorsEqual(stepLabel: String) {
        // Read both copies in chunks so we don't allocate megabytes.
        val chunkSectors = 32
        var sectorsRemaining = sectorsPerFAT
        var offset: Long = 0
        while (sectorsRemaining > 0) {
            val n = minOf(sectorsRemaining, chunkSectors.toLong()).toInt()
            val fat1 = reader.readSectors(reservedSectors + offset, n).getOrThrow()
            val fat2 = reader.readSectors(reservedSectors + sectorsPerFAT + offset, n).getOrThrow()
            if (!fat1.contentEquals(fat2)) {
                // Find the first differing sector for a useful failure.
                for (s in 0 until n) {
                    val a = fat1.copyOfRange(s * 512, (s + 1) * 512)
                    val b = fat2.copyOfRange(s * 512, (s + 1) * 512)
                    if (!a.contentEquals(b)) {
                        throw AssertionError(
                            "FAT mirror divergence at sector ${reservedSectors + offset + s} " +
                                "after $stepLabel"
                        )
                    }
                }
            }
            offset += n
            sectorsRemaining -= n
        }
    }

    private fun assertFreeClustersSane(stepLabel: String) {
        val firstDataSector = reservedSectors + numFATs * sectorsPerFAT
        val totalDataClusters = ((totalSectors - firstDataSector) / sectorsPerCluster).toInt()
        val free = fs.countFreeClusters()
        assertTrue(
            "free=$free outside [0, $totalDataClusters] after $stepLabel",
            free in 0..totalDataClusters
        )
    }

    private fun assertModelParity(workdir: String, model: Map<String, ByteArray>, stepLabel: String) {
        // FAT32 8.3 names are stored upper-case on disk; the shadow model uses
        // the original generated case. Compare case-insensitively.
        val entries = fs.listDirectory(workdir).getOrThrow()
        val listedFiles = entries.filter { !it.isDirectory }.map { it.name.uppercase() }.toSet()
        val modelUpper = model.mapKeys { it.key.uppercase() }
        // All model files must be present on disk.
        for ((nameU, expected) in modelUpper) {
            assertTrue(
                "missing $workdir/$nameU on disk after $stepLabel (listed=$listedFiles)",
                nameU in listedFiles
            )
            val actual = fs.readFile("$workdir/$nameU").getOrThrow()
            assertEquals(
                "size mismatch for $workdir/$nameU after $stepLabel",
                expected.size, actual.size
            )
            assertArrayEquals("content mismatch for $workdir/$nameU after $stepLabel", expected, actual)
        }
        // Every on-disk regular file must be in the model (subdirectories ignored).
        for (entry in entries) {
            if (entry.isDirectory) continue
            assertTrue(
                "extraneous file $workdir/${entry.name} on disk after $stepLabel",
                entry.name.uppercase() in modelUpper
            )
        }
    }

    private fun applyOp(workdir: String, op: Op, model: MutableMap<String, ByteArray>): String {
        // Returns a human-readable label for failure messages. Never throws —
        // ops that don't make sense in the current state (rename a missing
        // file, etc.) are silently skipped on both sides.
        return when (op) {
            is Op.Mkdir -> {
                val path = "$workdir/${op.name}"
                if (!fs.exists(path)) {
                    fs.createDirectory(workdir, op.name).getOrThrow()
                }
                "Mkdir(${op.name})"
            }
            is Op.Write -> {
                val path = "$workdir/${op.name}"
                if (!fs.exists(path)) {
                    fs.createFile(workdir, op.name).getOrThrow()
                }
                fs.writeFile(path, op.payload).getOrThrow()
                model[op.name] = op.payload.copyOf()
                "Write(${op.name}, ${op.payload.size}B)"
            }
            is Op.Append -> {
                val path = "$workdir/${op.name}"
                val existing = if (fs.exists(path)) {
                    fs.readFile(path).getOrThrow()
                } else {
                    fs.createFile(workdir, op.name).getOrThrow()
                    ByteArray(0)
                }
                val combined = existing + op.payload
                fs.writeFile(path, combined).getOrThrow()
                model[op.name] = combined
                "Append(${op.name}, +${op.payload.size}B)"
            }
            is Op.Rename -> {
                val srcPath = "$workdir/${op.name}"
                val dstPath = "$workdir/${op.newName}"
                if (fs.exists(srcPath) && !fs.exists(dstPath) && op.name != op.newName) {
                    // moveEntry only changes the parent dir; for in-place
                    // rename we delete+recreate. Using the simple path here.
                    val data = fs.readFile(srcPath).getOrThrow()
                    fs.delete(srcPath).getOrThrow()
                    fs.createFile(workdir, op.newName).getOrThrow()
                    fs.writeFile(dstPath, data).getOrThrow()
                    model[op.newName] = model.remove(op.name)!!
                }
                "Rename(${op.name} -> ${op.newName})"
            }
            is Op.Delete -> {
                val path = "$workdir/${op.name}"
                if (fs.exists(path) && model.containsKey(op.name)) {
                    fs.delete(path).getOrThrow()
                    model.remove(op.name)
                }
                "Delete(${op.name})"
            }
        }
    }

    private fun cleanWorkdir(workdir: String) {
        runCatching {
            for (e in fs.listDirectory(workdir).getOrThrow()) {
                fs.delete("$workdir/${e.name}")
            }
            fs.delete(workdir)
        }
    }

    // ── The properties ──────────────────────────────────────────────────────

    /**
     * Master invariant property: replay a random op sequence and verify model
     * parity, FAT mirror equality, and free-space sanity at every step.
     */
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `op sequence preserves invariants`() {
        runBlocking {
            val iterCounter = java.util.concurrent.atomic.AtomicInteger(0)
            checkAll(
                // Keep iteration count modest — every step does real disk I/O
                // through XTS-AES. 24 sequences * ~12 ops each is plenty to
                // exercise the mutation paths.
                PropTestConfig(iterations = 24, seed = 0xC0FFEEL),
                Arb.list(opArb(), 4..16)
            ) { ops ->
                val workdir = "/it_${iterCounter.incrementAndGet()}"
                fs.createDirectory("/", workdir.removePrefix("/")).getOrThrow()
                val model = mutableMapOf<String, ByteArray>()
                try {
                    for (op in ops) {
                        val label = applyOp(workdir, op, model)
                        assertFatMirrorsEqual(label)
                        assertFreeClustersSane(label)
                        assertModelParity(workdir, model, label)
                    }
                } finally {
                    cleanWorkdir(workdir)
                }
            }
        }
    }

    /**
     * Round-trip property: write any payload, read it back, get the same bytes.
     * A degenerate case of the master property, kept separate so that a
     * failure here points unambiguously at the I/O layer rather than at the
     * mutation algebra.
     */
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `write then read returns identical bytes`() {
        runBlocking {
            val workdir = "/rt_test"
            fs.createDirectory("/", "rt_test").getOrThrow()
            try {
                checkAll(
                    PropTestConfig(iterations = 30, seed = 0xBADF00DL),
                    payloadArb()
                ) { payload ->
                    val name = "rt.bin"
                    val path = "$workdir/$name"
                    if (fs.exists(path)) fs.delete(path).getOrThrow()
                    fs.createFile(workdir, name).getOrThrow()
                    fs.writeFile(path, payload).getOrThrow()
                    val readBack = fs.readFile(path).getOrThrow()
                    assertArrayEquals(payload, readBack)
                    assertFatMirrorsEqual("write-read of ${payload.size}B")
                }
            } finally {
                cleanWorkdir(workdir)
            }
        }
    }

    /**
     * Strict free-space conservation: every write+delete pair must restore
     * the free cluster count exactly. There is no per-iteration drift
     * tolerance — `delete()` is required to free the file's data cluster
     * chain (regression test for the bug where `deleteDirectoryEntry`
     * marked the dir entry 0xE5 but never touched the FAT, leaking the
     * entire cluster chain on every delete).
     */
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `write then delete restores free space`() {
        runBlocking {
            val workdir = "/fs_test"
            fs.createDirectory("/", "fs_test").getOrThrow()
            try {
                checkAll(
                    PropTestConfig(iterations = 20, seed = 0xFEEDL),
                    payloadArb()
                ) { payload ->
                    val name = "fs.bin"
                    val path = "$workdir/$name"
                    val before = fs.countFreeClusters()
                    fs.createFile(workdir, name).getOrThrow()
                    fs.writeFile(path, payload).getOrThrow()
                    fs.delete(path).getOrThrow()
                    val after = fs.countFreeClusters()
                    assertEquals(
                        "free clusters not restored after write+delete of ${payload.size}B",
                        before, after
                    )
                }
            } finally {
                cleanWorkdir(workdir)
            }
        }
    }
}
