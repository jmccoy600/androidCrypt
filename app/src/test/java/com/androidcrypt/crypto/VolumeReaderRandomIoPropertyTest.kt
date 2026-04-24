package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/**
 * **T9 — `VolumeReader` random-access I/O equivalence.**
 *
 * Apply a random sequence of `(offset, data)` writes to both:
 *
 *   - the encrypted [VolumeReader] (under test), via `writeData()`, and
 *   - a plain in-memory `ByteArray` model.
 *
 * After each step, read random byte ranges from both and assert
 * plaintext equality.
 *
 * This catches:
 *
 *   - off-by-ones at sector boundaries (writes that span 2 or 3 sectors),
 *   - read-after-write coherency bugs (the read path's caches not seeing
 *     the write path's pending sectors),
 *   - alignment bugs in `writeSectorsInPlace` and the read-modify-write
 *     path used by sector-unaligned writes.
 *
 * The model writes happen exclusively in the *data area* of the volume,
 * which begins at `VOLUME_HEADER_GROUP_SIZE` (128 KB). Reads/writes use
 * `VolumeReader.readData / writeData`, whose offsets are relative to that
 * data area — so model offset 0 corresponds to volume `writeData(0, …)`.
 */
class VolumeReaderRandomIoPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_volio_pbt")
        private const val PASSWORD = "VolIOPBT!"
        private lateinit var containerFile: File
        private lateinit var reader: VolumeReader
        private const val DATA_SIZE = 1L * 1024 * 1024  // 1 MB working area
        private lateinit var model: ByteArray

        @BeforeClass @JvmStatic
        fun setUp() {
            TEST_DIR.mkdirs()
            containerFile = File(TEST_DIR, "volio_${System.nanoTime()}.hc")
            // 4 MB container — 128KB headers each end + ~3.5MB data area.
            VolumeCreator.createContainer(containerFile.absolutePath, PASSWORD.toCharArray(), 4L).getOrThrow()
            reader = VolumeReader(containerFile.absolutePath)
            reader.mount(PASSWORD.toCharArray()).getOrThrow()
            // Initialize the model with whatever the freshly-formatted volume
            // already contains in its first 1 MB so that subsequent partial
            // writes can be diffed correctly.
            model = reader.readData(0L, DATA_SIZE.toInt()).getOrThrow()
        }

        @AfterClass @JvmStatic
        fun tearDown() {
            try { reader.unmount() } catch (_: Exception) {}
            containerFile.delete()
            TEST_DIR.delete()
        }
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `random writes followed by random reads agree with in-memory model`(): Unit = runBlocking {
        // Each iteration: one write step + a few read assertions.
        checkAll(
            PropTestConfig(iterations = 40, seed = 0x100A1010L),
            Arb.long(0L, DATA_SIZE - 1),                              // write offset
            Arb.byteArray(Arb.int(1, 4096), Arb.byte()),              // payload (spans sectors)
            Arb.list(
                Arb.bind(Arb.long(0L, DATA_SIZE - 1), Arb.int(1, 4096)) { o, l -> o to l },
                3..5
            )                                                          // read probes
        ) { writeOff, payload, probes ->
            // Truncate writes that would overflow the working area.
            val safeLen = minOf(payload.size.toLong(), DATA_SIZE - writeOff).toInt()
            if (safeLen <= 0) return@checkAll
            val w = if (safeLen == payload.size) payload else payload.copyOf(safeLen)

            reader.writeData(writeOff, w).getOrThrow()
            System.arraycopy(w, 0, model, writeOff.toInt(), safeLen)

            for ((rOff, rLen) in probes) {
                val safeReadLen = minOf(rLen.toLong(), DATA_SIZE - rOff).toInt()
                if (safeReadLen <= 0) continue
                val got = reader.readData(rOff, safeReadLen).getOrThrow()
                val expected = model.copyOfRange(rOff.toInt(), rOff.toInt() + safeReadLen)
                assertEquals("read length mismatch at off=$rOff len=$safeReadLen", expected.size, got.size)
                assertArrayEquals(
                    "data mismatch at off=$rOff len=$safeReadLen after writeOff=$writeOff len=$safeLen " +
                            "(model and disk diverged — likely cache coherency or sector-boundary bug)",
                    expected, got
                )
            }
        }
    }
}
