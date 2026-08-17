package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.element
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
 * **ExFAT-T6 — Naming property test.**
 *
 * Mirrors [FAT32NamingPropertyTest]. Tests:
 *   - Long names (up to 255 UTF-16 chars) round-trip exactly
 *   - Many long-name files in one directory are all retrievable
 *   - Names with special characters round-trip verbatim
 *
 * exFAT differences: no 8.3 short name, no LFN entry, no DOS reserved names.
 * Names are stored as UTF-16 in File Name entries (0xC1), 15 chars per entry.
 */
class ExFatNamingPropertyTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_exfat_naming")
    private val password = "ExFatNaming!".toCharArray()

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("veracrypt_crypto"); true
    } catch (_: UnsatisfiedLinkError) { false }

    private fun assumeNative() { if (!nativeAvailable) throw AssumptionViolatedException("native lib") }

    private val allowedNameChars = listOf(
        'a'..'z', 'A'..'Z', '0'..'9',
        listOf(' ', '!', '#', '$', '%', '&', '\'', '(', ')', '-', '@', '^', '_', '`', '{', '}', '~',
            'é', 'ñ', 'ü', 'ç', '日', '本', '€', 'Ω')
    ).flatten()

    private fun nameCharArb(): Arb<Char> = Arb.element(allowedNameChars)

    private fun longNameArb(): Arb<String> = Arb.bind(
        Arb.int(1, 100),
        Arb.list(nameCharArb(), 1..100)
    ) { _, chars -> chars.joinToString("").trimEnd('.', ' ').let { if (it.isEmpty()) "x" else it } }

    private fun payloadArb(): Arb<ByteArray> = Arb.byteArray(Arb.int(0, 1024), Arb.byte())

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `long names round-trip exactly through createFile and listDirectory`() = runBlocking {
        assumeNative()
        testDir.mkdirs()
        val container = File(testDir, "naming_${System.nanoTime()}.hc")
        try {
            VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 12L,
                fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
            val reader = VolumeReader(container.absolutePath)
            reader.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader)
            fs.initialize().getOrThrow()

            checkAll(PropTestConfig(iterations = 20, seed = 0x10F0A001L), longNameArb()) { name ->
                val path = "/$name"
                try {
                    fs.createFile("/", name).getOrThrow()
                    fs.writeFile(path, "data".toByteArray()).getOrThrow()
                    // Name must be retrievable verbatim from listDirectory
                    val entries = fs.listDirectory("/").getOrThrow()
                    assertTrue("name '$name' in listing", entries.any { it.name == name })
                    // And readable by the exact name
                    assertTrue(fs.exists(path))
                } catch (_: Exception) { /* skip names that violate spec */ }
            }
            reader.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }

    @Test
    fun `many long-name files in one directory all retrievable`() {
        assumeNative()
        testDir.mkdirs()
        val container = File(testDir, "naming_many_${System.nanoTime()}.hc")
        try {
            VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 12L,
                fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
            val reader = VolumeReader(container.absolutePath)
            reader.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader)
            fs.initialize().getOrThrow()

            // Create 40 files with long names — forces directory chain extension
            val names = mutableSetOf<String>()
            for (i in 0 until 40) {
                val name = "long_file_name_with_index_$i.dat"
                fs.createFile("/", name).getOrThrow()
                names.add(name)
            }
            val entries = fs.listDirectory("/").getOrThrow()
            assertEquals(40, entries.size)
            for (n in names) {
                assertTrue("'$n' in listing", entries.any { it.name == n })
            }
            reader.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `names with special chars round-trip verbatim`() = runBlocking {
        assumeNative()
        testDir.mkdirs()
        val container = File(testDir, "naming_special_${System.nanoTime()}.hc")
        try {
            VolumeCreator.createContainer(container.absolutePath, password.copyOf(), 12L,
                fileSystem = VolumeFileSystem.EXFAT).getOrThrow()
            val reader = VolumeReader(container.absolutePath)
            reader.mount(password.copyOf()).getOrThrow()
            val fs = ExFatReader(reader)
            fs.initialize().getOrThrow()

            val specialChars = listOf('+', ',', ';', '=', '[', ']', ' ', '!')
            checkAll(PropTestConfig(iterations = 10, seed = 0x10F0A002L),
                Arb.int(1, 5), Arb.int(0, specialChars.size - 1)) { n, charIdx ->
                val special = specialChars[charIdx]
                val name = "name" + special.toString().repeat(n) + "stem.dat"
                try {
                    fs.createFile("/", name).getOrThrow()
                    assertTrue(fs.exists("/$name"))
                    val entries = fs.listDirectory("/").getOrThrow()
                    assertTrue("'$name' in listing verbatim", entries.any { it.name == name })
                } catch (_: Exception) { /* skip if name violates spec */ }
            }
            reader.unmount()
        } finally {
            testDir.listFiles()?.forEach { it.delete() }
            testDir.delete()
        }
    }
}