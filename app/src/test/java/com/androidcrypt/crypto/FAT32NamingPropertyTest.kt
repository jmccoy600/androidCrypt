package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.RandomSource
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/**
 * Property-based tests for the [FAT32Reader] naming and entry-relocation
 * paths that the existing PBT files don't exercise:
 *
 *  • [`long names round-trip exactly through createFile + listDirectory`]
 *      — Every legal long name (Unicode, mixed case, lengths from 1 to
 *      100 chars) must be retrievable verbatim after creation. This
 *      hardens the LFN encode/decode pair after the recent
 *      `needsLfn` trigger bug (silent truncation of `cc_parity` to
 *      `CC_PARIT`).
 *
 *  • [`many long-name files in one directory all retrievable`]
 *      — Stress directory-cluster expansion. A 4 KB directory cluster
 *      holds 128 raw entries; 25 long-name files (each ≈ 4 LFN+1 8.3 =
 *      5 entries) saturate one cluster and force a second. Every name
 *      must survive the chain extension.
 *
 *  • [`moveEntry preserves bytes and removes from source`]
 *      — `moveEntry` rewires the directory entry without touching the
 *      cluster chain. A bug there silently strands the data chain or
 *      duplicates the entry in two parents.
 *
 *  • [`copyFileDirect produces identical bytes`]
 *      — `copyFileDirect` allocates a fresh chain and bulk-copies
 *      cluster contents. Must be byte-equivalent to writeFile(readFile()).
 */
class FAT32NamingPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_naming_pbt")
        private const val PASSWORD = "NamingPBT!"
        private lateinit var containerFile: File
        private lateinit var reader: VolumeReader
        private lateinit var fs: FAT32Reader

        @BeforeClass
        @JvmStatic
        fun classSetUp() {
            TEST_DIR.mkdirs()
            containerFile = File(TEST_DIR, "naming_${System.nanoTime()}.hc")
            VolumeCreator.createContainer(
                containerFile.absolutePath, PASSWORD.toCharArray(), 12
            ).getOrThrow()
            reader = VolumeReader(containerFile.absolutePath)
            reader.mount(PASSWORD.toCharArray()).getOrThrow()
            fs = FAT32Reader(reader)
            fs.initialize().getOrThrow()
        }

        @AfterClass
        @JvmStatic
        fun classTearDown() {
            try { reader.unmount() } catch (_: Exception) {}
            containerFile.delete()
            TEST_DIR.delete()
        }
    }

    /**
     * The set of characters known to validate (validateFat32Name) and to
     * be representable as both 8.3 (when uppercase) and LFN (always).
     * Excludes: forbidden \\ / : * ? " < > | \0 and ASCII control chars,
     * trailing dot/space (we trim those at the end), and the small set of
     * reserved DOS device names (which we filter at the name level).
     *
     * Includes mixed case and a smattering of Unicode to exercise the
     * UTF-16 LFN path.
     */
    private fun nameCharArb(): Arb<Char> = Arb.element(
        // ASCII letters lower & upper, digits, common punctuation
        ('a'..'z').toList() + ('A'..'Z').toList() + ('0'..'9').toList() +
            listOf(' ', '_', '-', '!', '#', '$', '%', '&', '(', ')', '@', '+', ',', ';', '=',
                '[', ']', '^', '`', '{', '}', '~', '\'',
                // A handful of representative non-ASCII BMP code points
                'é', 'ñ', 'ü', 'ç', '日', '本', '€', 'Ω')
    )

    private val reservedDosNames = setOf(
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    )

    /** Generate a name that passes validateFat32Name and isn't all whitespace. */
    private fun longNameArb(): Arb<String> = Arb.bind(
        Arb.int(1, 100),
        Arb.list(nameCharArb(), 1..100),
    ) { len, chars ->
        // Build a name of the requested length, then sanitise.
        val base = chars.take(len).joinToString("")
        // Trim trailing dots and spaces (silently stripped on Windows; we
        // also reject them in validateFat32Name).
        var n = base.trimEnd('.', ' ')
        // Trim leading whitespace too — looks weird and not interesting.
        n = n.trimStart(' ')
        if (n.isEmpty()) n = "a"
        // Avoid reserved DOS device names by sticking a 'z' on the front
        // when matched (cheap and preserves the property the rest of
        // generation gives us).
        if (n.substringBefore('.').uppercase() in reservedDosNames) n = "z$n"
        // Cap at 100; LFN can encode up to 255 but containing 4KB worth
        // of LFN entries per name explodes test runtime.
        if (n.length > 100) n = n.substring(0, 100)
        n
    }.filter { it.isNotEmpty() && it != "." && it != ".." }

    private fun payloadArb(maxBytes: Int): Arb<ByteArray> =
        Arb.byteArray(Arb.int(0, maxBytes), Arb.byte())

    private fun cleanWorkdir(workdir: String) {
        runCatching {
            for (e in fs.listDirectory(workdir).getOrThrow()) {
                fs.delete("$workdir/${e.name}")
            }
            fs.delete(workdir)
        }
    }

    // ── Property: long names round-trip through create + list ──────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `long names round-trip exactly through createFile and listDirectory`(): Unit = runBlocking {
        val workdir = "/lfn_rt"
        if (fs.exists(workdir)) fs.delete(workdir).getOrThrow()
        fs.createDirectory("/", "lfn_rt").getOrThrow()
        try {
            checkAll(
                PropTestConfig(iterations = 30, seed = 0x10F0A001L),
                longNameArb(),
            ) { name ->
                val path = "$workdir/$name"
                // Pre-clean (a previous iteration may have generated the same
                // name, which is fine — case-insensitive equals catches it).
                if (fs.exists(path)) fs.delete(path).getOrThrow()

                fs.createFile(workdir, name).getOrThrow()
                val listing = fs.listDirectory(workdir).getOrThrow()
                val match = listing.find { it.name == name }

                // The on-disk listing MUST contain the name verbatim (case
                // and all). A case-insensitive match alone is not enough —
                // that would silently accept short-name truncation like
                // "Documents" → "DOCUMEN~1".
                assertNotNull(
                    "name=\"$name\" (len=${name.length}) was created but not " +
                        "found verbatim in listing. Got: ${listing.map { it.name }}",
                    match
                )
                assertEquals(
                    "case/Unicode mismatch on round-trip: created=\"$name\" " +
                        "listed=\"${match?.name}\"",
                    name, match?.name
                )

                // exists() must agree with the listing using the original
                // spelling (FAT32 lookups are case-insensitive but must
                // accept the exact case used on creation).
                assertTrue("exists($path) returned false after createFile", fs.exists(path))

                fs.delete(path).getOrThrow()
                assertFalse("exists($path) returned true after delete", fs.exists(path))
            }
        } finally {
            cleanWorkdir(workdir)
        }
    }

    // ── Property: many long names in one directory ─────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `many long-name files in one directory all retrievable`(): Unit = runBlocking {
        // A 4 KB cluster holds 128 raw 32-byte directory entries. Long
        // names eat ~5 entries each, so 25 names saturate one cluster and
        // 30+ force a chain extension. We seed a deterministic batch and
        // check every name is retrievable after the dir grows.
        val workdir = "/lfn_many"
        if (fs.exists(workdir)) fs.delete(workdir).getOrThrow()
        fs.createDirectory("/", "lfn_many").getOrThrow()
        try {
            val rs = RandomSource.seeded(0x10F0A002L)
            val names = (0 until 40).map { i ->
                // Use a length that guarantees LFN (>8 chars no dot, mixed
                // case, with a stable index suffix to keep them unique).
                val nm = longNameArb().sample(rs).value
                // Force uniqueness with index suffix (case-insensitive
                // collisions otherwise force the deduper into ~N rotation,
                // which the next test exercises explicitly).
                val core = nm.take(40).trimEnd('.', ' ').ifEmpty { "f" }
                "${core}_$i"
            }
            for (name in names) {
                fs.createFile(workdir, name).getOrThrow()
            }

            val listing = fs.listDirectory(workdir).getOrThrow().map { it.name }.toSet()
            val missing = names.filter { it !in listing }
            assertTrue(
                "missing ${missing.size}/${names.size} names after creating " +
                    "${names.size} long-name files: $missing",
                missing.isEmpty()
            )
            assertEquals(
                "extra entries appeared in directory listing",
                names.toSet(), listing
            )
        } finally {
            cleanWorkdir(workdir)
        }
    }

    // ── Property: moveEntry preserves bytes and removes source ─────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `moveEntry preserves bytes and removes from source`(): Unit = runBlocking {
        val srcDir = "/mv_src"
        val dstDir = "/mv_dst"
        if (fs.exists(srcDir)) fs.delete(srcDir).getOrThrow()
        if (fs.exists(dstDir)) fs.delete(dstDir).getOrThrow()
        fs.createDirectory("/", "mv_src").getOrThrow()
        fs.createDirectory("/", "mv_dst").getOrThrow()
        try {
            checkAll(
                PropTestConfig(iterations = 20, seed = 0x10F0A003L),
                payloadArb(maxBytes = 16 * 1024),
            ) { payload ->
                val name = "f.bin"
                val srcPath = "$srcDir/$name"
                val dstPath = "$dstDir/$name"
                if (fs.exists(srcPath)) fs.delete(srcPath).getOrThrow()
                if (fs.exists(dstPath)) fs.delete(dstPath).getOrThrow()

                fs.createFile(srcDir, name).getOrThrow()
                fs.writeFile(srcPath, payload).getOrThrow()
                val before = fs.readFile(srcPath).getOrThrow()
                assertArrayEquals("setup: source readback != written", payload, before)

                val moveResult = fs.moveEntry(srcPath, dstDir).getOrThrow()
                // moveEntry returns the new path; should equal dstPath.
                assertEquals("moveEntry returned wrong new path", dstPath, moveResult)

                // Source is gone.
                assertFalse("source path still exists after move", fs.exists(srcPath))
                // Destination has bytes equal to the original payload.
                assertTrue("destination missing after move", fs.exists(dstPath))
                val after = fs.readFile(dstPath).getOrThrow()
                assertArrayEquals(
                    "moved file content drifted (size=${payload.size})",
                    payload, after
                )

                // Source dir listing no longer contains the name.
                val srcListing = fs.listDirectory(srcDir).getOrThrow().map { it.name }
                assertFalse("source listing still contains $name: $srcListing", name in srcListing)
                val dstListing = fs.listDirectory(dstDir).getOrThrow().map { it.name }
                assertTrue("destination listing missing $name: $dstListing", name in dstListing)
            }
        } finally {
            cleanWorkdir(srcDir)
            cleanWorkdir(dstDir)
        }
    }

    // ── Property: copyFileDirect == writeFile(readFile()) ──────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `copyFileDirect produces byte-identical files`(): Unit = runBlocking {
        val workdir = "/cp_test"
        if (fs.exists(workdir)) fs.delete(workdir).getOrThrow()
        fs.createDirectory("/", "cp_test").getOrThrow()
        try {
            checkAll(
                PropTestConfig(iterations = 16, seed = 0x10F0A004L),
                payloadArb(maxBytes = 16 * 1024),
            ) { payload ->
                val srcName = "src.bin"
                val srcPath = "$workdir/$srcName"
                val cpName = "cp.bin"
                val cpPath = "$workdir/$cpName"
                if (fs.exists(srcPath)) fs.delete(srcPath).getOrThrow()
                if (fs.exists(cpPath)) fs.delete(cpPath).getOrThrow()

                fs.createFile(workdir, srcName).getOrThrow()
                fs.writeFile(srcPath, payload).getOrThrow()

                val newPath = fs.copyFileDirect(srcPath, workdir, cpName).getOrThrow()
                assertEquals("copyFileDirect returned wrong path", cpPath, newPath)

                val srcRead = fs.readFile(srcPath).getOrThrow()
                val cpRead = fs.readFile(cpPath).getOrThrow()
                assertArrayEquals(
                    "src changed after copy (size=${payload.size})",
                    payload, srcRead
                )
                assertArrayEquals(
                    "copy bytes != src bytes (size=${payload.size})",
                    payload, cpRead
                )
            }
        } finally {
            cleanWorkdir(workdir)
        }
    }
}
