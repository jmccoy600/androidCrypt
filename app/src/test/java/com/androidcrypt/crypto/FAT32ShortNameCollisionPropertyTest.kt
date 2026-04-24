package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * **T4 — Short-name (`~N`) collision handling.**
 *
 * For a directory containing many long names that all collapse to the same
 * 8.3 stem, the implementation must:
 *
 *   1. Generate **distinct** short names for every entry (no two files share
 *      the same 11-byte 8.3 form — Windows would refuse to mount a volume
 *      with that corruption).
 *   2. Make every long name retrievable via `listDirectory` *and*
 *      `getFileInfo` and `readFile` by its full long form.
 *   3. Make every long name's content survive byte-for-byte (the short-name
 *      collision logic must not corrupt the LFN entries that precede each
 *      8.3 entry).
 *
 * The `~N` counter logic is rarely exercised past N=2 or 3 in example-based
 * tests; here we ramp it past 20 to catch off-by-ones in the hex-suffix
 * fallback used after `~9`.
 */
class FAT32ShortNameCollisionPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_collision_pbt")
        private const val PASSWORD = "CollisionPBT!"
        private lateinit var containerFile: File
        private lateinit var reader: VolumeReader
        private lateinit var fs: FAT32Reader
        private var bytesPerSector = 0
        private var sectorsPerCluster = 0
        private var reservedSectors = 0
        private var numFATs = 0
        private var sectorsPerFAT = 0L

        @BeforeClass @JvmStatic
        fun setUp() {
            TEST_DIR.mkdirs()
            containerFile = File(TEST_DIR, "coll_${System.nanoTime()}.hc")
            VolumeCreator.createContainer(containerFile.absolutePath, PASSWORD.toCharArray(), 12L).getOrThrow()
            reader = VolumeReader(containerFile.absolutePath)
            reader.mount(PASSWORD.toCharArray()).getOrThrow()
            fs = FAT32Reader(reader); fs.initialize().getOrThrow()
            val bs = reader.readSector(0).getOrThrow()
            bytesPerSector = (bs[11].toInt() and 0xFF) or ((bs[12].toInt() and 0xFF) shl 8)
            sectorsPerCluster = bs[13].toInt() and 0xFF
            reservedSectors = (bs[14].toInt() and 0xFF) or ((bs[15].toInt() and 0xFF) shl 8)
            numFATs = bs[16].toInt() and 0xFF
            sectorsPerFAT = ByteBuffer.wrap(bs, 36, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong()
        }

        @AfterClass @JvmStatic
        fun tearDown() {
            try { reader.unmount() } catch (_: Exception) {}
            containerFile.delete()
            TEST_DIR.delete()
        }
    }

    /** Read the raw 11-byte short names for every non-LFN entry in [dirPath]. */
    private fun readShortNames(dirPath: String): List<ByteArray> {
        val info = fs.getFileInfoWithClusterPublic(dirPath).getOrThrow()
        val firstDataSector = reservedSectors + numFATs * sectorsPerFAT
        val out = mutableListOf<ByteArray>()
        var cluster = info.firstCluster
        var hops = 0
        while (cluster in 2..0x0FFFFFF7 && hops < 1024) {
            val firstSec = (cluster - 2).toLong() * sectorsPerCluster + firstDataSector
            val data = reader.readSectors(firstSec, sectorsPerCluster).getOrThrow()
            for (off in 0 until data.size step 32) {
                val first = data[off].toInt() and 0xFF
                if (first == 0x00) return out
                if (first == 0xE5) continue
                val attr = data[off + 11].toInt() and 0xFF
                if ((attr and 0x3F) == 0x0F) continue // LFN entry
                // Skip '.' and '..' entries that every subdirectory has.
                if (first == 0x2E) continue
                out.add(data.copyOfRange(off, off + 11))
            }
            // Walk to next cluster via FAT
            val fatOff = reservedSectors.toLong() + (cluster * 4) / bytesPerSector
            val sec = reader.readSector(fatOff).getOrThrow()
            val byteInSec = (cluster * 4) % bytesPerSector
            val v = ByteBuffer.wrap(sec, byteInSec, 4).order(ByteOrder.LITTLE_ENDIAN).int and 0x0FFFFFFF
            cluster = v
            hops++
        }
        return out
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `many long names sharing one 8 dot 3 stem all get unique short names`(): Unit = runBlocking {
        var iter = 0
        checkAll(
            PropTestConfig(iterations = 4, seed = 0xC011L),
            Arb.int(20, 30)  // number of colliding files
        ) { count ->
            iter++
            val dir = "/coll_$iter"
            fs.createDirectory("/", "coll_$iter").getOrThrow()

            // Every long name shares the same 8.3 prefix "Document of " and
            // an extension ".pdf" — 8.3 collapsing yields the same stem
            // "DOCUME~N.PDF" for every entry, forcing the ~N counter to go
            // past N=9 and fall back to hex-suffix mode.
            val longNames = (1..count).map { "Document of meeting $it.pdf" }
            for (n in longNames) {
                fs.createFile(dir, n).getOrThrow()
                fs.writeFile("$dir/$n", n.toByteArray(Charsets.UTF_8)).getOrThrow()
            }
            reader.sync()

            // (1) Distinct short names.
            val shortNames = readShortNames(dir)
            assertEquals(
                "expected one short-name entry per file (count=$count)",
                count, shortNames.size
            )
            val asStrings = shortNames.map { it.toString(Charsets.US_ASCII) }
            val unique = asStrings.toSet()
            assertEquals(
                "duplicate short names found: ${asStrings.groupingBy { it }.eachCount().filter { it.value > 1 }}",
                count, unique.size
            )

            // (2)+(3) Every long name retrievable and content intact.
            val listed = fs.listDirectory(dir).getOrThrow().map { it.name }.toSet()
            for (n in longNames) {
                assertTrue("long name '$n' missing from listDirectory", n in listed)
                val bytes = fs.readFile("$dir/$n").getOrThrow()
                assertArrayEquals(
                    "content corrupted for '$n' (LFN/8.3 chain damaged)",
                    n.toByteArray(Charsets.UTF_8), bytes
                )
            }

            fs.delete(dir).getOrThrow()
            reader.sync()
        }
    }
}
