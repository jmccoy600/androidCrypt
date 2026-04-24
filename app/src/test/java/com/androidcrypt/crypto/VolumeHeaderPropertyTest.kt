package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.next
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Property-based tests for [VolumeHeaderParser]: createHeader / parseHeader
 * round-trip across arbitrary sizes, sector sizes, PIM values and
 * encryption algorithms; plus CRC tamper-detection. The deliberate-bit-flip
 * properties (1) target the M-2 hardening (header & key-area CRC checks):
 * any single bit flipped inside the encrypted region must, after
 * decryption, yield a CRC mismatch and `parseHeader` must reject.
 *
 * `pim` is fixed to a small value so the test runs in seconds rather than
 * minutes (default PBKDF2 iteration count is 500 000; pim=1 drops it to
 * 16 000 which is still cryptographically meaningful but ~30× faster).
 */
class VolumeHeaderPropertyTest {

    private val parser = VolumeHeaderParser()
    private val FAST_PIM = 1   // pim=1 => 16k iterations for SHA256/512

    private fun algoArb(): Arb<EncryptionAlgorithm> = Arb.element(
        EncryptionAlgorithm.AES,
        EncryptionAlgorithm.SERPENT,
        EncryptionAlgorithm.TWOFISH,
    )

    private fun hashArb(): Arb<HashAlgorithm> = Arb.element(
        HashAlgorithm.SHA256,
        HashAlgorithm.SHA512,
    )

    private fun volumeSizeArb(): Arb<Long> =
        Arb.long(1L * 1024 * 1024, 100L * 1024 * 1024)

    private fun sectorSizeArb(): Arb<Int> = Arb.element(512, 1024, 2048, 4096)

    /** Short ASCII passwords keep PBKDF2 fast and avoid pathological UTF-16. */
    private fun passwordArb(): Arb<CharArray> = Arb.element(
        "Password!", "p", "verylongpassword12345", "0123456789abcdef"
    ).let { strArb ->
        io.kotest.property.arbitrary.arbitrary { rs -> strArb.next(rs).toCharArray() }
    }

    // ── Round-trip across algorithm × hash × size × sector size ────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `header round-trip preserves every persisted field`(): Unit = runBlocking {
        checkAll(
            PropTestConfig(iterations = 12, seed = 0x70E08000L),
            algoArb(), hashArb(), volumeSizeArb(), sectorSizeArb(), passwordArb(),
        ) { algo, hash, vsize, ssize, password ->
            val header = parser.createHeader(
                password = password,
                pim = FAST_PIM,
                volumeSize = vsize,
                encryptionAlg = algo,
                hashAlg = hash,
                sectorSize = ssize,
            )
            assertEquals(VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE, header.size)
            val parsed = parser.parseHeader(header, password, pim = FAST_PIM)
            assertNotNull("parse failed for algo=$algo hash=$hash vsize=$vsize ssize=$ssize", parsed)
            with(parsed!!) {
                assertEquals(algo, encryptionAlgorithm)
                assertEquals(hash, hashAlgorithm)
                assertEquals(vsize, volumeSize)
                assertEquals(ssize, sectorSize)
                assertEquals(VolumeConstants.VOLUME_HEADER_VERSION_NUM, version)
            }
        }
    }

    // ── Wrong password is always rejected ───────────────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `wrong password is rejected`(): Unit = runBlocking {
        checkAll(
            PropTestConfig(iterations = 8, seed = 0x80E08001L),
            algoArb(), hashArb(),
        ) { algo, hash ->
            val realPw = "RealPassword".toCharArray()
            val header = parser.createHeader(
                password = realPw,
                pim = FAST_PIM,
                volumeSize = 5L * 1024 * 1024,
                encryptionAlg = algo,
                hashAlg = hash,
            )
            val wrong = parser.parseHeader(header, "WrongPassword".toCharArray(), pim = FAST_PIM)
            assertNull("wrong password unexpectedly parsed for $algo/$hash", wrong)
        }
    }

    // ── Wrong PIM is always rejected ────────────────────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `wrong PIM is rejected`(): Unit = runBlocking {
        checkAll(
            PropTestConfig(iterations = 6, seed = 0x90E08002L),
            algoArb(),
        ) { algo ->
            val pw = "Password".toCharArray()
            val header = parser.createHeader(
                password = pw,
                pim = FAST_PIM,
                volumeSize = 5L * 1024 * 1024,
                encryptionAlg = algo,
                hashAlg = HashAlgorithm.SHA256,
            )
            val wrong = parser.parseHeader(header, pw, pim = FAST_PIM + 5)
            assertNull("wrong PIM unexpectedly parsed for $algo", wrong)
        }
    }

    // ── Single-bit corruption in encrypted region is rejected (CRC) ────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `single-bit corruption in encrypted area is rejected`(): Unit = runBlocking {
        // The encrypted region runs from SALT_SIZE (=64) to 512 (=448 bytes).
        // Flipping a bit there will produce different plaintext on decrypt;
        // the embedded CRCs (HEADER_CRC over bytes 0..255 and KEY_AREA_CRC
        // over bytes 256..511 of the decrypted payload) will not match.
        val pw = "TamperTest".toCharArray()
        val baseHeader = parser.createHeader(
            password = pw,
            pim = FAST_PIM,
            volumeSize = 5L * 1024 * 1024,
            encryptionAlg = EncryptionAlgorithm.AES,
            hashAlg = HashAlgorithm.SHA256,
        )

        checkAll(
            PropTestConfig(iterations = 25, seed = 0xA0E08003L),
            // Bit offsets within the 448-byte encrypted region.
            Arb.int(VolumeConstants.ENCRYPTED_DATA_OFFSET, 511),
            Arb.int(0, 7),
        ) { byteOff, bitIdx ->
            val tampered = baseHeader.copyOf()
            tampered[byteOff] = (tampered[byteOff].toInt() xor (1 shl bitIdx)).toByte()
            val parsed = parser.parseHeader(tampered, pw, pim = FAST_PIM)
            assertNull(
                "tampered header at byte $byteOff bit $bitIdx unexpectedly parsed",
                parsed
            )
        }
    }

    // ── Salt corruption triggers wrong-key derivation ──────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `salt corruption is rejected`(): Unit = runBlocking {
        val pw = "SaltTest".toCharArray()
        val baseHeader = parser.createHeader(
            password = pw,
            pim = FAST_PIM,
            volumeSize = 5L * 1024 * 1024,
            encryptionAlg = EncryptionAlgorithm.AES,
            hashAlg = HashAlgorithm.SHA256,
        )

        checkAll(
            PropTestConfig(iterations = 12, seed = 0xB0E08004L),
            Arb.int(0, VolumeConstants.SALT_SIZE - 1),
            Arb.int(0, 7),
        ) { byteOff, bitIdx ->
            val tampered = baseHeader.copyOf()
            tampered[byteOff] = (tampered[byteOff].toInt() xor (1 shl bitIdx)).toByte()
            val parsed = parser.parseHeader(tampered, pw, pim = FAST_PIM)
            assertNull("tampered salt at byte $byteOff bit $bitIdx unexpectedly parsed", parsed)
        }
    }

    // ── Salt is not all-zero (sanity) ──────────────────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `salt is non-zero across many headers`(): Unit = runBlocking {
        checkAll(
            PropTestConfig(iterations = 20, seed = 0xC0E08005L),
            algoArb(), hashArb(),
        ) { algo, hash ->
            val header = parser.createHeader(
                password = "pw".toCharArray(),
                pim = FAST_PIM,
                volumeSize = 5L * 1024 * 1024,
                encryptionAlg = algo,
                hashAlg = hash,
            )
            val salt = header.copyOfRange(0, VolumeConstants.SALT_SIZE)
            assert(salt.any { it != 0.toByte() }) { "salt is all zero — RNG broken?" }
        }
    }
}
