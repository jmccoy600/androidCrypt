package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.next
import io.kotest.property.arbitrary.bind
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Property-based tests for XTS-AES (and the other XTS-mode ciphers exposed
 * via [XTSMode]). Targets the native (JNI) XTS implementations used for
 * volume sector encryption.
 *
 * Properties exercised:
 * 1. **Round-trip:** decrypt(encrypt(p, t)) == p for every payload p, tweak t.
 * 2. **Tweak diffusion:** encrypting the same plaintext with two different
 *    sector numbers must produce different ciphertext (otherwise XTS would
 *    leak position equality — fatal for disk encryption).
 * 3. **Plaintext diffusion:** flipping a single bit of the plaintext must
 *    change the ciphertext (avalanche within a sector).
 * 4. **Key independence:** the same plaintext under two different keys must
 *    produce different ciphertext (regression for any code path that ever
 *    silently fell back to a fixed/zero key).
 * 5. **Determinism:** encrypt(p, t) is a pure function — calling it twice
 *    yields identical ciphertext.
 *
 * The cascade ciphers (AES-Twofish-Serpent, Serpent-Twofish-AES) are
 * intentionally excluded here — they're covered by the per-algorithm
 * round-trip suite in [VolumeRoundTripPerHashTest] and adding them would
 * triple the runtime without exposing additional XTS-layer bugs.
 */
class XtsAesPropertyTest {

    /** Sector-aligned payloads: 1..16 sectors of 512 B each. */
    private fun payloadArb(): Arb<ByteArray> =
        Arb.int(1, 16).map { sectors ->
            ByteArray(sectors * 512).also { java.util.Random(sectors * 0x9E3779B9L).nextBytes(it) }
        }

    private fun tweakArb(): Arb<Long> = Arb.long(0L, 1L shl 30)

    private fun keyArb(size: Int): Arb<ByteArray> =
        Arb.byteArray(Arb.constant(size), Arb.byte())

    private fun <T> sample(arb: Arb<T>, salt: Long = 0L): T =
        arb.next(io.kotest.property.RandomSource.seeded(0xCAFEBABEL xor salt))

    /** Algorithms whose JNI lib is loaded in the unit-test classpath. */
    private fun algorithms(): List<EncryptionAlgorithm> = listOf(
        EncryptionAlgorithm.AES,
        EncryptionAlgorithm.SERPENT,
        EncryptionAlgorithm.TWOFISH,
    )

    // ── Property 1: round-trip ──────────────────────────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `encrypt then decrypt returns original`() = runBlocking {
        for (algo in algorithms()) {
            val key = sample(keyArb(algo.keySize), salt = algo.ordinal.toLong())
            val xts = XTSMode(key, algo)
            try {
                checkAll(
                    PropTestConfig(iterations = 30, seed = 0xA1ECABCDL),
                    payloadArb(),
                    tweakArb(),
                ) { plaintext, tweak ->
                    val ct = xts.encrypt(plaintext, tweak)
                    val pt = xts.decrypt(ct, tweak)
                    assertArrayEquals("round-trip failed for $algo @ tweak=$tweak", plaintext, pt)
                }
            } finally {
                xts.close()
            }
        }
    }

    // ── Property 2: tweak diffusion ─────────────────────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `different tweaks produce different ciphertext`() = runBlocking {
        for (algo in algorithms()) {
            val key = sample(keyArb(algo.keySize), salt = algo.ordinal.toLong())
            val xts = XTSMode(key, algo)
            try {
                checkAll(
                    PropTestConfig(iterations = 30, seed = 0xB2D1FF00L),
                    payloadArb(),
                    tweakArb(),
                    tweakArb(),
                ) { plaintext, t1, t2Raw ->
                    val t2 = if (t1 == t2Raw) t2Raw + 1 else t2Raw
                    val c1 = xts.encrypt(plaintext, t1)
                    val c2 = xts.encrypt(plaintext, t2)
                    // XTS is per-sector, so sectors at the same intra-payload
                    // position should differ across tweaks. Compare the first
                    // sector specifically — comparing the whole array is also
                    // fine but a per-sector check shrinks the failure window.
                    val firstSectorC1 = c1.copyOfRange(0, 512)
                    val firstSectorC2 = c2.copyOfRange(0, 512)
                    assertFalse(
                        "first-sector ciphertext collided across distinct tweaks " +
                            "(algo=$algo, t1=$t1, t2=$t2)",
                        firstSectorC1.contentEquals(firstSectorC2)
                    )
                }
            } finally {
                xts.close()
            }
        }
    }

    // ── Property 3: plaintext diffusion (avalanche) ─────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `single-bit plaintext change avalanches within sector`() = runBlocking {
        for (algo in algorithms()) {
            val key = sample(keyArb(algo.keySize), salt = algo.ordinal.toLong())
            val xts = XTSMode(key, algo)
            try {
                checkAll(
                    PropTestConfig(iterations = 30, seed = 0xC4A5CADEL),
                    payloadArb(),
                    tweakArb(),
                    Arb.int(0, 511),  // bit-flip offset within first sector
                    Arb.int(0, 7),
                ) { plaintext, tweak, byteIdx, bitIdx ->
                    val mutated = plaintext.copyOf()
                    mutated[byteIdx] = (mutated[byteIdx].toInt() xor (1 shl bitIdx)).toByte()
                    val c1 = xts.encrypt(plaintext, tweak)
                    val c2 = xts.encrypt(mutated, tweak)
                    val s1 = c1.copyOfRange(0, 512)
                    val s2 = c2.copyOfRange(0, 512)
                    // At minimum the affected sector must change. AES has full
                    // diffusion so practically every byte should differ; we
                    // just demand "not identical".
                    assertFalse(
                        "no avalanche for $algo on 1-bit plaintext flip",
                        s1.contentEquals(s2)
                    )
                }
            } finally {
                xts.close()
            }
        }
    }

    // ── Property 4: key independence ────────────────────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `different keys produce different ciphertext`() = runBlocking {
        for (algo in algorithms()) {
            checkAll(
                PropTestConfig(iterations = 20, seed = 0xD00D1E11L),
                payloadArb(),
                tweakArb(),
                keyArb(algo.keySize),
                keyArb(algo.keySize),
            ) { plaintext, tweak, k1, k2 ->
                if (k1.contentEquals(k2)) return@checkAll  // skip degenerate
                val x1 = XTSMode(k1, algo)
                val x2 = XTSMode(k2, algo)
                try {
                    val c1 = x1.encrypt(plaintext, tweak)
                    val c2 = x2.encrypt(plaintext, tweak)
                    assertFalse(
                        "ciphertexts collided across distinct keys for $algo",
                        c1.contentEquals(c2)
                    )
                } finally {
                    x1.close()
                    x2.close()
                }
            }
        }
    }

    // ── Property 5: determinism ─────────────────────────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `encrypt is deterministic`() = runBlocking {
        for (algo in algorithms()) {
            val key = sample(keyArb(algo.keySize), salt = algo.ordinal.toLong())
            val xts = XTSMode(key, algo)
            try {
                checkAll(
                    PropTestConfig(iterations = 20, seed = 0xE00DBEEFL),
                    payloadArb(),
                    tweakArb(),
                ) { plaintext, tweak ->
                    val c1 = xts.encrypt(plaintext, tweak)
                    val c2 = xts.encrypt(plaintext, tweak)
                    assertArrayEquals("encrypt() is non-deterministic for $algo", c1, c2)
                }
            } finally {
                xts.close()
            }
        }
    }

    // ── Property 6: ciphertext is not the plaintext (sanity) ───────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `ciphertext differs from plaintext for non-trivial inputs`() = runBlocking {
        for (algo in algorithms()) {
            val key = sample(keyArb(algo.keySize), salt = algo.ordinal.toLong())
            val xts = XTSMode(key, algo)
            try {
                checkAll(
                    PropTestConfig(iterations = 15, seed = 0xF00DBA11L),
                    payloadArb(),
                    tweakArb(),
                ) { plaintext, tweak ->
                    val ct = xts.encrypt(plaintext, tweak)
                    // Skip the all-zero-key + all-zero-plaintext degenerate case
                    // — not applicable since key is random per test class instance.
                    assertNotEquals(
                        "ciphertext equals plaintext for $algo (cipher silently no-op?)",
                        true,
                        ct.contentEquals(plaintext)
                    )
                    assertTrue("ciphertext size mismatch", ct.size == plaintext.size)
                }
            } finally {
                xts.close()
            }
        }
    }

    // ── Property 7: wrong-tweak decryption MUST NOT recover plaintext ───────
    //
    // T7 from the property-test design notes. Catches:
    //   (a) tweak ignored entirely (would let any sector decrypt to the
    //       same value as sector 0);
    //   (b) endianness bug in the tweak counter that happens to produce
    //       the same internal tweak value for adjacent sectors;
    //   (c) accidental tweak reuse across sectors.
    //
    // The check is intentionally not "ct1 == ct2" (that's already covered
    // by tweak-diffusion) but the stronger "decrypt(ct, wrongTweak) does
    // not equal plaintext", which catches degenerate ciphers that map
    // plaintext bijectively under a constant key but ignore the tweak.
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `decrypting with the wrong tweak does not recover plaintext`() = runBlocking {
        for (algo in algorithms()) {
            val key = sample(keyArb(algo.keySize), salt = algo.ordinal.toLong())
            val xts = XTSMode(key, algo)
            try {
                checkAll(
                    PropTestConfig(iterations = 30, seed = 0x710C7BADL),
                    payloadArb(),
                    tweakArb(),
                ) { plaintext, tweak ->
                    // Use a deliberately-similar wrong tweak (off by 1) — many
                    // tweak bugs survive a "completely different tweak" check
                    // but die on adjacent sectors.
                    val wrong = tweak xor 1L
                    val ct = xts.encrypt(plaintext, tweak)
                    val pt = xts.decrypt(ct, wrong)
                    assertFalse(
                        "decrypt with wrong tweak (off-by-one) recovered plaintext for $algo " +
                                "(tweak=$tweak, wrong=$wrong) — XTS tweak is being ignored or aliased",
                        pt.contentEquals(plaintext)
                    )
                }
            } finally {
                xts.close()
            }
        }
    }
}
