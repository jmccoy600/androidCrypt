/**
 * Native XTS-AES implementation for Android – VeraCrypt-compatible.
 *
 * XTS encrypt/decrypt logic is ported directly from VeraCrypt's src/Common/Xts.c
 * (EncryptBufferXTSParallel / DecryptBufferXTSParallel for the hw-accelerated path,
 *  EncryptBufferXTSNonParallel / DecryptBufferXTSNonParallel for portable).
 *
 * AES block cipher: ARMv8 crypto extensions on arm64, T-table fallback elsewhere.
 *
 * JNI bridge: createContext, destroyContext, encryptSectors, decryptSectors,
 *             isAvailable, hasHardwareAES.
 */
#include <jni.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <android/log.h>

#ifdef __aarch64__
#include <arm_neon.h>
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#endif

#define LOG_TAG "NativeXTS"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG, __VA_ARGS__)

#include "Serpent.h"
#define SERPENT_KS_WORDS 140   // 140 x uint32 = 560-byte key schedule

#include "Twofish.h"

/* -----------------------------------------------------------------------
   VeraCrypt-compatible constants (from src/Common/Crypto.h / Xts.h)
   ----------------------------------------------------------------------- */
#define ENCRYPTION_DATA_UNIT_SIZE  512
#define BYTES_PER_XTS_BLOCK        16
#define BLOCKS_PER_XTS_DATA_UNIT  (ENCRYPTION_DATA_UNIT_SIZE / BYTES_PER_XTS_BLOCK) /* 32 */

// ============================================================================
// Section 1 – AES constants (Rijndael S-box, inverse S-box, round constants)
// ============================================================================
namespace {

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

// AES round constants (first byte of each RCON word; rest are zero)
static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// ============================================================================
// Section 2 – T-tables (computed at init time from S-box / inverse S-box)
// ============================================================================

static uint32_t Te0[256], Te1[256], Te2[256], Te3[256];
static uint32_t Td0[256], Td1[256], Td2[256], Td3[256];
static std::once_flag g_tables_init;

static inline uint8_t xtime(uint8_t x) {
    return static_cast<uint8_t>((x << 1) ^ ((x >> 7) * 0x1b));
}

static void init_aes_tables() {
    for (int i = 0; i < 256; i++) {
        uint8_t s  = SBOX[i];
        uint8_t s2 = xtime(s);
        uint8_t s3 = s2 ^ s;
        Te0[i] = (uint32_t)s2 | ((uint32_t)s << 8)
               | ((uint32_t)s << 16) | ((uint32_t)s3 << 24);
        Te1[i] = (Te0[i] <<  8) | (Te0[i] >> 24);
        Te2[i] = (Te0[i] << 16) | (Te0[i] >> 16);
        Te3[i] = (Te0[i] << 24) | (Te0[i] >>  8);

        uint8_t si  = INV_SBOX[i];
        uint8_t si2 = xtime(si);
        uint8_t si4 = xtime(si2);
        uint8_t si8 = xtime(si4);
        uint8_t si9 = si8 ^ si;
        uint8_t sib = si8 ^ si2 ^ si;
        uint8_t sid = si8 ^ si4 ^ si;
        uint8_t sie = si8 ^ si4 ^ si2;
        Td0[i] = (uint32_t)sie | ((uint32_t)si9 << 8)
               | ((uint32_t)sid << 16) | ((uint32_t)sib << 24);
        Td1[i] = (Td0[i] <<  8) | (Td0[i] >> 24);
        Td2[i] = (Td0[i] << 16) | (Td0[i] >> 16);
        Td3[i] = (Td0[i] << 24) | (Td0[i] >>  8);
    }
}

static inline void ensure_tables() {
    std::call_once(g_tables_init, init_aes_tables);
}

// ============================================================================
// Section 3 – AES key schedule
// ============================================================================

static constexpr int MAX_RK_WORDS = 60;   // 15 x 4

struct AESKeySchedule {
    alignas(16) uint32_t enc[MAX_RK_WORDS];
    alignas(16) uint32_t dec[MAX_RK_WORDS];
    int rounds;
};

static inline uint32_t load_le32(const uint8_t* p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static inline void store_le32(uint8_t* p, uint32_t v) {
    memcpy(p, &v, 4);
}

static inline uint32_t sub_word(uint32_t w) {
    return (uint32_t)SBOX[w & 0xFF]
         | ((uint32_t)SBOX[(w >> 8) & 0xFF] << 8)
         | ((uint32_t)SBOX[(w >> 16) & 0xFF] << 16)
         | ((uint32_t)SBOX[(w >> 24) & 0xFF] << 24);
}

static inline uint32_t rot_word(uint32_t w) {
    return (w >> 8) | (w << 24);
}

static void aes_expand_key(AESKeySchedule* ks, const uint8_t* key, int keyLen) {
    ensure_tables();

    const int Nk = keyLen / 4;
    const int Nr = (Nk == 8) ? 14 : 10;
    const int totalWords = (Nr + 1) * 4;
    ks->rounds = Nr;

    for (int i = 0; i < Nk; i++) {
        ks->enc[i] = load_le32(key + i * 4);
    }

    for (int i = Nk; i < totalWords; i++) {
        uint32_t tmp = ks->enc[i - 1];
        if (i % Nk == 0) {
            tmp = sub_word(rot_word(tmp)) ^ (uint32_t)RCON[i / Nk - 1];
        } else if (Nk == 8 && (i % Nk == 4)) {
            tmp = sub_word(tmp);
        }
        ks->enc[i] = ks->enc[i - Nk] ^ tmp;
    }

    // Equivalent inverse cipher key schedule for decrypt
    for (int i = 0; i <= Nr; i++) {
        const int srcRound = Nr - i;
        const uint32_t* srcRk = &ks->enc[srcRound * 4];
        uint32_t* dstRk = &ks->dec[i * 4];

        if (i == 0 || i == Nr) {
            memcpy(dstRk, srcRk, 16);
        } else {
            for (int w = 0; w < 4; w++) {
                uint32_t v = srcRk[w];
                dstRk[w] = Td0[SBOX[v & 0xFF]]
                         ^ Td1[SBOX[(v >> 8) & 0xFF]]
                         ^ Td2[SBOX[(v >> 16) & 0xFF]]
                         ^ Td3[SBOX[(v >> 24) & 0xFF]];
            }
        }
    }
}

// ============================================================================
// Section 4 – Portable AES block encrypt / decrypt (T-table)
// ============================================================================

static void aes_encrypt_block(const AESKeySchedule* ks,
                               const uint8_t in[16], uint8_t out[16]) {
    const uint32_t* rk = ks->enc;
    const int Nr = ks->rounds;

    uint32_t s0 = load_le32(in +  0) ^ rk[0];
    uint32_t s1 = load_le32(in +  4) ^ rk[1];
    uint32_t s2 = load_le32(in +  8) ^ rk[2];
    uint32_t s3 = load_le32(in + 12) ^ rk[3];
    rk += 4;

    for (int r = 1; r < Nr; r++) {
        uint32_t t0 = Te0[s0 & 0xFF] ^ Te1[(s1 >>  8) & 0xFF]
                    ^ Te2[(s2 >> 16) & 0xFF] ^ Te3[(s3 >> 24) & 0xFF] ^ rk[0];
        uint32_t t1 = Te0[s1 & 0xFF] ^ Te1[(s2 >>  8) & 0xFF]
                    ^ Te2[(s3 >> 16) & 0xFF] ^ Te3[(s0 >> 24) & 0xFF] ^ rk[1];
        uint32_t t2 = Te0[s2 & 0xFF] ^ Te1[(s3 >>  8) & 0xFF]
                    ^ Te2[(s0 >> 16) & 0xFF] ^ Te3[(s1 >> 24) & 0xFF] ^ rk[2];
        uint32_t t3 = Te0[s3 & 0xFF] ^ Te1[(s0 >>  8) & 0xFF]
                    ^ Te2[(s1 >> 16) & 0xFF] ^ Te3[(s2 >> 24) & 0xFF] ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        rk += 4;
    }

    /* Last round: SubBytes + ShiftRows + AddRoundKey (no MixColumns).
       Parentheses ensure the ^ rk[n] applies to the full 32-bit word. */
    store_le32(out +  0,
        (((uint32_t)SBOX[ s0        & 0xFF])
       | ((uint32_t)SBOX[(s1 >>  8) & 0xFF] <<  8)
       | ((uint32_t)SBOX[(s2 >> 16) & 0xFF] << 16)
       | ((uint32_t)SBOX[(s3 >> 24) & 0xFF] << 24)) ^ rk[0]);
    store_le32(out +  4,
        (((uint32_t)SBOX[ s1        & 0xFF])
       | ((uint32_t)SBOX[(s2 >>  8) & 0xFF] <<  8)
       | ((uint32_t)SBOX[(s3 >> 16) & 0xFF] << 16)
       | ((uint32_t)SBOX[(s0 >> 24) & 0xFF] << 24)) ^ rk[1]);
    store_le32(out +  8,
        (((uint32_t)SBOX[ s2        & 0xFF])
       | ((uint32_t)SBOX[(s3 >>  8) & 0xFF] <<  8)
       | ((uint32_t)SBOX[(s0 >> 16) & 0xFF] << 16)
       | ((uint32_t)SBOX[(s1 >> 24) & 0xFF] << 24)) ^ rk[2]);
    store_le32(out + 12,
        (((uint32_t)SBOX[ s3        & 0xFF])
       | ((uint32_t)SBOX[(s0 >>  8) & 0xFF] <<  8)
       | ((uint32_t)SBOX[(s1 >> 16) & 0xFF] << 16)
       | ((uint32_t)SBOX[(s2 >> 24) & 0xFF] << 24)) ^ rk[3]);
}

static void aes_decrypt_block(const AESKeySchedule* ks,
                               const uint8_t in[16], uint8_t out[16]) {
    const uint32_t* rk = ks->dec;
    const int Nr = ks->rounds;

    uint32_t s0 = load_le32(in +  0) ^ rk[0];
    uint32_t s1 = load_le32(in +  4) ^ rk[1];
    uint32_t s2 = load_le32(in +  8) ^ rk[2];
    uint32_t s3 = load_le32(in + 12) ^ rk[3];
    rk += 4;

    for (int r = 1; r < Nr; r++) {
        uint32_t t0 = Td0[s0 & 0xFF] ^ Td1[(s3 >>  8) & 0xFF]
                    ^ Td2[(s2 >> 16) & 0xFF] ^ Td3[(s1 >> 24) & 0xFF] ^ rk[0];
        uint32_t t1 = Td0[s1 & 0xFF] ^ Td1[(s0 >>  8) & 0xFF]
                    ^ Td2[(s3 >> 16) & 0xFF] ^ Td3[(s2 >> 24) & 0xFF] ^ rk[1];
        uint32_t t2 = Td0[s2 & 0xFF] ^ Td1[(s1 >>  8) & 0xFF]
                    ^ Td2[(s0 >> 16) & 0xFF] ^ Td3[(s3 >> 24) & 0xFF] ^ rk[2];
        uint32_t t3 = Td0[s3 & 0xFF] ^ Td1[(s2 >>  8) & 0xFF]
                    ^ Td2[(s1 >> 16) & 0xFF] ^ Td3[(s0 >> 24) & 0xFF] ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        rk += 4;
    }

    /* Last round: InvSubBytes + InvShiftRows + AddRoundKey. */
    store_le32(out +  0,
        (((uint32_t)INV_SBOX[ s0        & 0xFF])
       | ((uint32_t)INV_SBOX[(s3 >>  8) & 0xFF] <<  8)
       | ((uint32_t)INV_SBOX[(s2 >> 16) & 0xFF] << 16)
       | ((uint32_t)INV_SBOX[(s1 >> 24) & 0xFF] << 24)) ^ rk[0]);
    store_le32(out +  4,
        (((uint32_t)INV_SBOX[ s1        & 0xFF])
       | ((uint32_t)INV_SBOX[(s0 >>  8) & 0xFF] <<  8)
       | ((uint32_t)INV_SBOX[(s3 >> 16) & 0xFF] << 16)
       | ((uint32_t)INV_SBOX[(s2 >> 24) & 0xFF] << 24)) ^ rk[1]);
    store_le32(out +  8,
        (((uint32_t)INV_SBOX[ s2        & 0xFF])
       | ((uint32_t)INV_SBOX[(s1 >>  8) & 0xFF] <<  8)
       | ((uint32_t)INV_SBOX[(s0 >> 16) & 0xFF] << 16)
       | ((uint32_t)INV_SBOX[(s3 >> 24) & 0xFF] << 24)) ^ rk[2]);
    store_le32(out + 12,
        (((uint32_t)INV_SBOX[ s3        & 0xFF])
       | ((uint32_t)INV_SBOX[(s2 >>  8) & 0xFF] <<  8)
       | ((uint32_t)INV_SBOX[(s1 >> 16) & 0xFF] << 16)
       | ((uint32_t)INV_SBOX[(s0 >> 24) & 0xFF] << 24)) ^ rk[3]);
}

// ============================================================================
// Section 5 – ARM64 hardware AES (ARMv8 crypto extensions)
// ============================================================================

#ifdef __aarch64__

static bool g_hw_aes_checked = false;
static bool g_hw_aes_available = false;

static bool detect_hw_aes() {
    if (!g_hw_aes_checked) {
        g_hw_aes_available = (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
        g_hw_aes_checked = true;
    }
    return g_hw_aes_available;
}

__attribute__((target("+crypto")))
static void hw_aes_encrypt_block(const AESKeySchedule* ks,
                                  const uint8_t in[16], uint8_t out[16]) {
    const int Nr = ks->rounds;
    const uint8_t* rk = reinterpret_cast<const uint8_t*>(ks->enc);

    uint8x16_t block = vld1q_u8(in);
    for (int r = 0; r < Nr - 1; r++) {
        uint8x16_t key = vld1q_u8(rk + r * 16);
        block = vaesmcq_u8(vaeseq_u8(block, key));
    }
    uint8x16_t key_last  = vld1q_u8(rk + (Nr - 1) * 16);
    uint8x16_t key_final = vld1q_u8(rk + Nr * 16);
    block = veorq_u8(vaeseq_u8(block, key_last), key_final);
    vst1q_u8(out, block);
}

__attribute__((target("+crypto")))
static void hw_aes_decrypt_block(const AESKeySchedule* ks,
                                  const uint8_t in[16], uint8_t out[16]) {
    const int Nr = ks->rounds;
    const uint8_t* rk = reinterpret_cast<const uint8_t*>(ks->dec);

    uint8x16_t block = vld1q_u8(in);
    for (int r = 0; r < Nr - 1; r++) {
        uint8x16_t key = vld1q_u8(rk + r * 16);
        block = vaesimcq_u8(vaesdq_u8(block, key));
    }
    uint8x16_t key_last  = vld1q_u8(rk + (Nr - 1) * 16);
    uint8x16_t key_final = vld1q_u8(rk + Nr * 16);
    block = veorq_u8(vaesdq_u8(block, key_last), key_final);
    vst1q_u8(out, block);
}

__attribute__((target("+crypto")))
static void hw_aes_encrypt_4blocks(const AESKeySchedule* ks,
                                    uint8x16_t& b0, uint8x16_t& b1,
                                    uint8x16_t& b2, uint8x16_t& b3) {
    const int Nr = ks->rounds;
    const uint8_t* rk = reinterpret_cast<const uint8_t*>(ks->enc);
    for (int r = 0; r < Nr - 1; r++) {
        uint8x16_t key = vld1q_u8(rk + r * 16);
        b0 = vaesmcq_u8(vaeseq_u8(b0, key));
        b1 = vaesmcq_u8(vaeseq_u8(b1, key));
        b2 = vaesmcq_u8(vaeseq_u8(b2, key));
        b3 = vaesmcq_u8(vaeseq_u8(b3, key));
    }
    uint8x16_t kl = vld1q_u8(rk + (Nr - 1) * 16);
    uint8x16_t kf = vld1q_u8(rk + Nr * 16);
    b0 = veorq_u8(vaeseq_u8(b0, kl), kf);
    b1 = veorq_u8(vaeseq_u8(b1, kl), kf);
    b2 = veorq_u8(vaeseq_u8(b2, kl), kf);
    b3 = veorq_u8(vaeseq_u8(b3, kl), kf);
}

__attribute__((target("+crypto")))
static void hw_aes_decrypt_4blocks(const AESKeySchedule* ks,
                                    uint8x16_t& b0, uint8x16_t& b1,
                                    uint8x16_t& b2, uint8x16_t& b3) {
    const int Nr = ks->rounds;
    const uint8_t* rk = reinterpret_cast<const uint8_t*>(ks->dec);
    for (int r = 0; r < Nr - 1; r++) {
        uint8x16_t key = vld1q_u8(rk + r * 16);
        b0 = vaesimcq_u8(vaesdq_u8(b0, key));
        b1 = vaesimcq_u8(vaesdq_u8(b1, key));
        b2 = vaesimcq_u8(vaesdq_u8(b2, key));
        b3 = vaesimcq_u8(vaesdq_u8(b3, key));
    }
    uint8x16_t kl = vld1q_u8(rk + (Nr - 1) * 16);
    uint8x16_t kf = vld1q_u8(rk + Nr * 16);
    b0 = veorq_u8(vaesdq_u8(b0, kl), kf);
    b1 = veorq_u8(vaesdq_u8(b1, kl), kf);
    b2 = veorq_u8(vaesdq_u8(b2, kl), kf);
    b3 = veorq_u8(vaesdq_u8(b3, kl), kf);
}

#else // !__aarch64__

static bool detect_hw_aes() { return false; }

#endif // __aarch64__

// ============================================================================
// Section 6 – XTS context
// ============================================================================

struct XTSContext {
    AESKeySchedule data_key;    // key1 – encrypt / decrypt data
    AESKeySchedule tweak_key;   // key2 – encrypt tweaks (always AES-encrypt)
    bool hw_aes;
};

// ============================================================================
// Section 7 – XTS encrypt / decrypt (VeraCrypt-compatible)
//
// Ported from VeraCrypt src/Common/Xts.c:
//   - Portable: EncryptBufferXTSNonParallel / DecryptBufferXTSNonParallel
//   - Hardware: EncryptBufferXTSParallel / DecryptBufferXTSParallel
//
// Parameters match VeraCrypt EncryptBufferXTS / DecryptBufferXTS:
//   buffer            – data to encrypt/decrypt in-place
//   length            – number of bytes; must be divisible by BYTES_PER_XTS_BLOCK
//   startDataUnitNo   – sequential number of the first data unit in the buffer
// ============================================================================

/* --------------- Portable (T-table) XTS encrypt --------------- */
/* Direct port of VeraCrypt EncryptBufferXTSNonParallel           */

static void EncryptBufferXTS_Portable(XTSContext* ctx, uint8_t* buffer,
                                       uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        // Encrypt the data unit number using the secondary key
        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        aes_encrypt_block(&ctx->tweak_key, whiteningValue, whiteningValue);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                // Pre-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                // Actual encryption
                aes_encrypt_block(&ctx->data_key,
                                  (uint8_t*)bufPtr, (uint8_t*)bufPtr);

                // Post-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            // Derive the next whitening value (GF(2^128) multiply by x)
            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    memset(whiteningValue, 0, sizeof(whiteningValue));
}

/* --------------- Portable (T-table) XTS decrypt --------------- */
/* Direct port of VeraCrypt DecryptBufferXTSNonParallel           */

static void DecryptBufferXTS_Portable(XTSContext* ctx, uint8_t* buffer,
                                       uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        // Encrypt the data unit number using the secondary key
        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        aes_encrypt_block(&ctx->tweak_key, whiteningValue, whiteningValue);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                // Post-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                // Actual decryption
                aes_decrypt_block(&ctx->data_key,
                                  (uint8_t*)bufPtr, (uint8_t*)bufPtr);

                // Pre-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            // Derive the next whitening value (GF(2^128) multiply by x)
            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    memset(whiteningValue, 0, sizeof(whiteningValue));
}

/* --------------- ARM64 hw-accelerated XTS encrypt --------------- */
/* Modelled on VeraCrypt EncryptBufferXTSParallel:                   */
/*   pre-compute whitening values, batch XOR, batch cipher, batch XOR */

#ifdef __aarch64__

__attribute__((target("+crypto")))
static void EncryptBufferXTS_HW(XTSContext* ctx, uint8_t* buffer,
                                 uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValues[ENCRYPTION_DATA_UNIT_SIZE];
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuesPtr64 = (uint64_t*)whiteningValues;
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    uint64_t* dataUnitBufPtr;
    unsigned int startBlock = 0, endBlock, block, countBlock;
    uint64_t remainingBlocks, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    remainingBlocks = length / BYTES_PER_XTS_BLOCK;

    while (remainingBlocks > 0) {
        if (remainingBlocks < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)remainingBlocks;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;
        countBlock = endBlock - startBlock;

        whiteningValuesPtr64 = (uint64_t*)whiteningValues;
        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        hw_aes_encrypt_block(&ctx->tweak_key, whiteningValue, whiteningValue);

        // Generate all whitening values for this data unit
        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                *whiteningValuesPtr64++ = *whiteningValuePtr64++;
                *whiteningValuesPtr64++ = *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        dataUnitBufPtr = bufPtr;
        whiteningValuesPtr64 = (uint64_t*)whiteningValues;

        // Pre-whitening XOR
        for (block = 0; block < countBlock; block++) {
            *bufPtr++ ^= *whiteningValuesPtr64++;
            *bufPtr++ ^= *whiteningValuesPtr64++;
        }

        // Actual encryption – 4 blocks at a time
        {
            uint8_t* p = (uint8_t*)dataUnitBufPtr;
            unsigned int cb = countBlock;
            while (cb >= 4) {
                uint8x16_t b0 = vld1q_u8(p);
                uint8x16_t b1 = vld1q_u8(p + 16);
                uint8x16_t b2 = vld1q_u8(p + 32);
                uint8x16_t b3 = vld1q_u8(p + 48);
                hw_aes_encrypt_4blocks(&ctx->data_key, b0, b1, b2, b3);
                vst1q_u8(p,      b0);
                vst1q_u8(p + 16, b1);
                vst1q_u8(p + 32, b2);
                vst1q_u8(p + 48, b3);
                p += 64; cb -= 4;
            }
            for (; cb > 0; cb--) {
                hw_aes_encrypt_block(&ctx->data_key, p, p);
                p += 16;
            }
        }

        // Post-whitening XOR
        bufPtr = dataUnitBufPtr;
        whiteningValuesPtr64 = (uint64_t*)whiteningValues;
        for (block = 0; block < countBlock; block++) {
            *bufPtr++ ^= *whiteningValuesPtr64++;
            *bufPtr++ ^= *whiteningValuesPtr64++;
        }

        remainingBlocks -= countBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    memset(whiteningValue, 0, sizeof(whiteningValue));
    memset(whiteningValues, 0, sizeof(whiteningValues));
}

/* --------------- ARM64 hw-accelerated XTS decrypt --------------- */
/* Modelled on VeraCrypt DecryptBufferXTSParallel                    */

__attribute__((target("+crypto")))
static void DecryptBufferXTS_HW(XTSContext* ctx, uint8_t* buffer,
                                 uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValues[ENCRYPTION_DATA_UNIT_SIZE];
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuesPtr64 = (uint64_t*)whiteningValues;
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    uint64_t* dataUnitBufPtr;
    unsigned int startBlock = 0, endBlock, block, countBlock;
    uint64_t remainingBlocks, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    remainingBlocks = length / BYTES_PER_XTS_BLOCK;

    while (remainingBlocks > 0) {
        if (remainingBlocks < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)remainingBlocks;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;
        countBlock = endBlock - startBlock;

        whiteningValuesPtr64 = (uint64_t*)whiteningValues;
        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        hw_aes_encrypt_block(&ctx->tweak_key, whiteningValue, whiteningValue);

        // Generate all whitening values for this data unit
        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                *whiteningValuesPtr64++ = *whiteningValuePtr64++;
                *whiteningValuesPtr64++ = *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        dataUnitBufPtr = bufPtr;
        whiteningValuesPtr64 = (uint64_t*)whiteningValues;

        // Pre-whitening XOR
        for (block = 0; block < countBlock; block++) {
            *bufPtr++ ^= *whiteningValuesPtr64++;
            *bufPtr++ ^= *whiteningValuesPtr64++;
        }

        // Actual decryption – 4 blocks at a time
        {
            uint8_t* p = (uint8_t*)dataUnitBufPtr;
            unsigned int cb = countBlock;
            while (cb >= 4) {
                uint8x16_t b0 = vld1q_u8(p);
                uint8x16_t b1 = vld1q_u8(p + 16);
                uint8x16_t b2 = vld1q_u8(p + 32);
                uint8x16_t b3 = vld1q_u8(p + 48);
                hw_aes_decrypt_4blocks(&ctx->data_key, b0, b1, b2, b3);
                vst1q_u8(p,      b0);
                vst1q_u8(p + 16, b1);
                vst1q_u8(p + 32, b2);
                vst1q_u8(p + 48, b3);
                p += 64; cb -= 4;
            }
            for (; cb > 0; cb--) {
                hw_aes_decrypt_block(&ctx->data_key, p, p);
                p += 16;
            }
        }

        // Post-whitening XOR
        bufPtr = dataUnitBufPtr;
        whiteningValuesPtr64 = (uint64_t*)whiteningValues;
        for (block = 0; block < countBlock; block++) {
            *bufPtr++ ^= *whiteningValuesPtr64++;
            *bufPtr++ ^= *whiteningValuesPtr64++;
        }

        remainingBlocks -= countBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    memset(whiteningValue, 0, sizeof(whiteningValue));
    memset(whiteningValues, 0, sizeof(whiteningValues));
}

#endif // __aarch64__

// ============================================================================
// Section 8 – Dispatchers
// ============================================================================

static void EncryptBufferXTS(XTSContext* ctx, uint8_t* buf,
                              uint64_t len, uint64_t startDataUnitNo) {
#ifdef __aarch64__
    if (ctx->hw_aes) {
        EncryptBufferXTS_HW(ctx, buf, len, startDataUnitNo);
        return;
    }
#endif
    EncryptBufferXTS_Portable(ctx, buf, len, startDataUnitNo);
}

static void DecryptBufferXTS(XTSContext* ctx, uint8_t* buf,
                              uint64_t len, uint64_t startDataUnitNo) {
#ifdef __aarch64__
    if (ctx->hw_aes) {
        DecryptBufferXTS_HW(ctx, buf, len, startDataUnitNo);
        return;
    }
#endif
    DecryptBufferXTS_Portable(ctx, buf, len, startDataUnitNo);
}

} // anonymous namespace

// ============================================================================
// Section 9 – JNI bridge
// ============================================================================

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_androidcrypt_crypto_NativeXTS_nativeIsAvailable(JNIEnv*, jclass) {
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_androidcrypt_crypto_NativeXTS_hasHardwareAES(JNIEnv*, jclass) {
    return detect_hw_aes() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeXTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    if ((key1Len != 16 && key1Len != 32) || (key2Len != 16 && key2Len != 32)) {
        LOGE("Invalid key lengths: key1=%d, key2=%d", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) XTSContext();
    if (!ctx) return 0;

    ctx->hw_aes = detect_hw_aes();

    uint8_t k1[32], k2[32];
    env->GetByteArrayRegion(key1, 0, key1Len, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, key2Len, reinterpret_cast<jbyte*>(k2));

    aes_expand_key(&ctx->data_key, k1, key1Len);
    aes_expand_key(&ctx->tweak_key, k2, key2Len);

    memset(k1, 0, sizeof(k1));
    memset(k2, 0, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeXTS_destroyContext(JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<XTSContext*>(handle);
    if (ctx) {
        memset(ctx, 0, sizeof(XTSContext));
        delete ctx;
    }
}

/**
 * Decrypt sectors in-place.
 *
 * Maps to VeraCrypt DecryptSectorsCurrentThread:
 *   DecryptBuffer(data, sectorCount * sectorSize,
 *                 sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE)
 */
JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeXTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<XTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

/**
 * Encrypt sectors in-place.
 *
 * Maps to VeraCrypt EncryptSectorsCurrentThread:
 *   EncryptBuffer(data, sectorCount * sectorSize,
 *                 sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE)
 */
JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeXTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<XTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

// ============================================================================
// Section 10 – Serpent XTS-mode  (mirrors the AES XTS sections above)
//
// Serpent is a 128-bit block cipher, same block size as AES, so the XTS
// mode logic is identical — only the block encrypt/decrypt calls change.
// The tweak key is always *encrypted* (never decrypted), matching VeraCrypt.
// ============================================================================

struct SerpentXTSContext {
    uint8_t data_ks[SERPENT_KS_WORDS * 4];   // key1 – encrypt / decrypt data
    uint8_t tweak_ks[SERPENT_KS_WORDS * 4];  // key2 – encrypt tweaks
};

/* --------------- Portable XTS-Serpent encrypt --------------- */
/* Direct mirror of EncryptBufferXTS_Portable with Serpent      */

static void EncryptBufferXTS_Serpent(SerpentXTSContext* ctx, uint8_t* buffer,
                                     uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        // Encrypt the data unit number using the secondary (tweak) key
        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        serpent_encrypt(whiteningValue, whiteningValue, ctx->tweak_ks);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                // Pre-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                // Actual encryption
                serpent_encrypt((uint8_t*)bufPtr, (uint8_t*)bufPtr, ctx->data_ks);

                // Post-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            // Derive the next whitening value (GF(2^128) multiply by x)
            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    memset(whiteningValue, 0, sizeof(whiteningValue));
}

/* --------------- Portable XTS-Serpent decrypt --------------- */
/* Direct mirror of DecryptBufferXTS_Portable with Serpent      */

static void DecryptBufferXTS_Serpent(SerpentXTSContext* ctx, uint8_t* buffer,
                                     uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        // Encrypt the data unit number using the secondary (tweak) key
        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        serpent_encrypt(whiteningValue, whiteningValue, ctx->tweak_ks);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                // Post-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                // Actual decryption
                serpent_decrypt((uint8_t*)bufPtr, (uint8_t*)bufPtr, ctx->data_ks);

                // Pre-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            // Derive the next whitening value (GF(2^128) multiply by x)
            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    memset(whiteningValue, 0, sizeof(whiteningValue));
}

// ============================================================================
// Section 11 – Serpent block-cipher JNI  (single-block encrypt/decrypt)
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_SerpentJNI_nativeSetKey(
        JNIEnv* env, jclass, jbyteArray key) {
    if (env->GetArrayLength(key) != 32) return 0;
    auto* ks = new(std::nothrow) uint8_t[SERPENT_KS_WORDS * 4];
    if (!ks) return 0;
    uint8_t k[32];
    env->GetByteArrayRegion(key, 0, 32, reinterpret_cast<jbyte*>(k));
    serpent_set_key(k, ks);
    memset(k, 0, sizeof(k));
    return reinterpret_cast<jlong>(ks);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_SerpentJNI_nativeDestroyKey(
        JNIEnv*, jclass, jlong handle) {
    auto* ks = reinterpret_cast<uint8_t*>(handle);
    if (ks) {
        memset(ks, 0, SERPENT_KS_WORDS * 4);
        delete[] ks;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_SerpentJNI_nativeEncryptBlock(
        JNIEnv* env, jclass, jlong handle, jbyteArray inBlock, jbyteArray outBlock) {
    auto* ks = reinterpret_cast<uint8_t*>(handle);
    if (!ks) return;
    uint8_t in_buf[16], out_buf[16];
    env->GetByteArrayRegion(inBlock, 0, 16, reinterpret_cast<jbyte*>(in_buf));
    serpent_encrypt(in_buf, out_buf, ks);
    env->SetByteArrayRegion(outBlock, 0, 16, reinterpret_cast<jbyte*>(out_buf));
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_SerpentJNI_nativeDecryptBlock(
        JNIEnv* env, jclass, jlong handle, jbyteArray inBlock, jbyteArray outBlock) {
    auto* ks = reinterpret_cast<uint8_t*>(handle);
    if (!ks) return;
    uint8_t in_buf[16], out_buf[16];
    env->GetByteArrayRegion(inBlock, 0, 16, reinterpret_cast<jbyte*>(in_buf));
    serpent_decrypt(in_buf, out_buf, ks);
    env->SetByteArrayRegion(outBlock, 0, 16, reinterpret_cast<jbyte*>(out_buf));
}

// ============================================================================
// Section 12 – Serpent XTS JNI bridge (NativeSerpentXTS)
//
// Same interface as NativeXTS: createContext, destroyContext,
// encryptSectors, decryptSectors.  The Kotlin class is NativeSerpentXTS.
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeSerpentXTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    if (key1Len != 32 || key2Len != 32) {
        LOGE("SerpentXTS: invalid key lengths: key1=%d, key2=%d", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) SerpentXTSContext();
    if (!ctx) return 0;

    uint8_t k1[32], k2[32];
    env->GetByteArrayRegion(key1, 0, 32, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, 32, reinterpret_cast<jbyte*>(k2));

    serpent_set_key(k1, ctx->data_ks);
    serpent_set_key(k2, ctx->tweak_ks);

    memset(k1, 0, sizeof(k1));
    memset(k2, 0, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeSerpentXTS_destroyContext(
        JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<SerpentXTSContext*>(handle);
    if (ctx) {
        memset(ctx, 0, sizeof(SerpentXTSContext));
        delete ctx;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeSerpentXTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<SerpentXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS_Serpent(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeSerpentXTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<SerpentXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS_Serpent(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

// ============================================================================
// Section 13 – Twofish XTS-mode  (mirrors the AES/Serpent XTS sections)
//
// Twofish is a 128-bit block cipher, same block size as AES and Serpent, so
// the XTS logic is identical — only the block encrypt/decrypt calls change.
// ============================================================================

struct TwofishXTSContext {
    TwofishInstance data_key;    // key1 – encrypt / decrypt data
    TwofishInstance tweak_key;   // key2 – encrypt tweaks
};

/* --------------- Portable XTS-Twofish encrypt --------------- */

static void EncryptBufferXTS_Twofish(TwofishXTSContext* ctx, uint8_t* buffer,
                                      uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        twofish_encrypt(&ctx->tweak_key, (u4byte*)whiteningValue, (u4byte*)whiteningValue);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                twofish_encrypt(&ctx->data_key, (u4byte*)bufPtr, (u4byte*)bufPtr);

                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    memset(whiteningValue, 0, sizeof(whiteningValue));
}

/* --------------- Portable XTS-Twofish decrypt --------------- */

static void DecryptBufferXTS_Twofish(TwofishXTSContext* ctx, uint8_t* buffer,
                                      uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        twofish_encrypt(&ctx->tweak_key, (u4byte*)whiteningValue, (u4byte*)whiteningValue);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                twofish_decrypt(&ctx->data_key, (u4byte*)bufPtr, (u4byte*)bufPtr);

                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    memset(whiteningValue, 0, sizeof(whiteningValue));
}

// ============================================================================
// Section 14 – Twofish block-cipher JNI (single-block encrypt/decrypt)
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_TwofishJNI_nativeSetKey(
        JNIEnv* env, jclass, jbyteArray key) {
    if (env->GetArrayLength(key) != 32) return 0;
    auto* inst = new(std::nothrow) TwofishInstance();
    if (!inst) return 0;
    uint8_t k[32];
    env->GetByteArrayRegion(key, 0, 32, reinterpret_cast<jbyte*>(k));
    twofish_set_key(inst, (const u4byte*)k);
    memset(k, 0, sizeof(k));
    return reinterpret_cast<jlong>(inst);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_TwofishJNI_nativeDestroyKey(
        JNIEnv*, jclass, jlong handle) {
    auto* inst = reinterpret_cast<TwofishInstance*>(handle);
    if (inst) {
        memset(inst, 0, sizeof(TwofishInstance));
        delete inst;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_TwofishJNI_nativeEncryptBlock(
        JNIEnv* env, jclass, jlong handle, jbyteArray inBlock, jbyteArray outBlock) {
    auto* inst = reinterpret_cast<TwofishInstance*>(handle);
    if (!inst) return;
    uint8_t in_buf[16], out_buf[16];
    env->GetByteArrayRegion(inBlock, 0, 16, reinterpret_cast<jbyte*>(in_buf));
    twofish_encrypt(inst, (const u4byte*)in_buf, (u4byte*)out_buf);
    env->SetByteArrayRegion(outBlock, 0, 16, reinterpret_cast<jbyte*>(out_buf));
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_TwofishJNI_nativeDecryptBlock(
        JNIEnv* env, jclass, jlong handle, jbyteArray inBlock, jbyteArray outBlock) {
    auto* inst = reinterpret_cast<TwofishInstance*>(handle);
    if (!inst) return;
    uint8_t in_buf[16], out_buf[16];
    env->GetByteArrayRegion(inBlock, 0, 16, reinterpret_cast<jbyte*>(in_buf));
    twofish_decrypt(inst, (const u4byte*)in_buf, (u4byte*)out_buf);
    env->SetByteArrayRegion(outBlock, 0, 16, reinterpret_cast<jbyte*>(out_buf));
}

// ============================================================================
// Section 15 – Twofish XTS JNI bridge (NativeTwofishXTS)
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeTwofishXTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    if (key1Len != 32 || key2Len != 32) {
        LOGE("TwofishXTS: invalid key lengths: key1=%d, key2=%d", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) TwofishXTSContext();
    if (!ctx) return 0;

    uint8_t k1[32], k2[32];
    env->GetByteArrayRegion(key1, 0, 32, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, 32, reinterpret_cast<jbyte*>(k2));

    twofish_set_key(&ctx->data_key, (const u4byte*)k1);
    twofish_set_key(&ctx->tweak_key, (const u4byte*)k2);

    memset(k1, 0, sizeof(k1));
    memset(k2, 0, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeTwofishXTS_destroyContext(
        JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<TwofishXTSContext*>(handle);
    if (ctx) {
        memset(ctx, 0, sizeof(TwofishXTSContext));
        delete ctx;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeTwofishXTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<TwofishXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS_Twofish(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeTwofishXTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<TwofishXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS_Twofish(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

// ============================================================================
// Section 16 – AES-Twofish-Serpent cascade XTS
//
// VeraCrypt cascade: each cipher runs a full independent XTS pass over the
// entire buffer with its own key pair.
//   Encrypt order: AES → Twofish → Serpent
//   Decrypt order: Serpent → Twofish → AES
//
// Key layout (192 bytes total):
//   Primary keys   [0–95]:   AES[0–31]  Twofish[32–63]  Serpent[64–95]
//   Secondary keys [96–191]: AES[96–127] Twofish[128–159] Serpent[160–191]
// ============================================================================

struct CascadeXTSContext {
    // AES keys (primary + tweak)
    AESKeySchedule  aes_data_key;
    AESKeySchedule  aes_tweak_key;
    bool            hw_aes;
    // Twofish keys (primary + tweak)
    TwofishInstance  tf_data_key;
    TwofishInstance  tf_tweak_key;
    // Serpent keys (primary + tweak)
    uint8_t          sp_data_ks[SERPENT_KS_WORDS * 4];
    uint8_t          sp_tweak_ks[SERPENT_KS_WORDS * 4];
};

static void EncryptBufferXTS_Cascade(CascadeXTSContext* ctx, uint8_t* buf,
                                      uint64_t len, uint64_t startDataUnitNo) {
    // Pass 1: AES (innermost)
    {
        XTSContext aesCtx;
        aesCtx.data_key  = ctx->aes_data_key;
        aesCtx.tweak_key = ctx->aes_tweak_key;
        aesCtx.hw_aes    = ctx->hw_aes;
        EncryptBufferXTS(&aesCtx, buf, len, startDataUnitNo);
    }
    // Pass 2: Twofish
    {
        TwofishXTSContext tfCtx;
        tfCtx.data_key  = ctx->tf_data_key;
        tfCtx.tweak_key = ctx->tf_tweak_key;
        EncryptBufferXTS_Twofish(&tfCtx, buf, len, startDataUnitNo);
    }
    // Pass 3: Serpent (outermost)
    {
        SerpentXTSContext spCtx;
        memcpy(spCtx.data_ks,  ctx->sp_data_ks,  sizeof(spCtx.data_ks));
        memcpy(spCtx.tweak_ks, ctx->sp_tweak_ks, sizeof(spCtx.tweak_ks));
        EncryptBufferXTS_Serpent(&spCtx, buf, len, startDataUnitNo);
    }
}

static void DecryptBufferXTS_Cascade(CascadeXTSContext* ctx, uint8_t* buf,
                                      uint64_t len, uint64_t startDataUnitNo) {
    // Pass 1: Serpent (peel outermost layer first)
    {
        SerpentXTSContext spCtx;
        memcpy(spCtx.data_ks,  ctx->sp_data_ks,  sizeof(spCtx.data_ks));
        memcpy(spCtx.tweak_ks, ctx->sp_tweak_ks, sizeof(spCtx.tweak_ks));
        DecryptBufferXTS_Serpent(&spCtx, buf, len, startDataUnitNo);
    }
    // Pass 2: Twofish
    {
        TwofishXTSContext tfCtx;
        tfCtx.data_key  = ctx->tf_data_key;
        tfCtx.tweak_key = ctx->tf_tweak_key;
        DecryptBufferXTS_Twofish(&tfCtx, buf, len, startDataUnitNo);
    }
    // Pass 3: AES (innermost)
    {
        XTSContext aesCtx;
        aesCtx.data_key  = ctx->aes_data_key;
        aesCtx.tweak_key = ctx->aes_tweak_key;
        aesCtx.hw_aes    = ctx->hw_aes;
        DecryptBufferXTS(&aesCtx, buf, len, startDataUnitNo);
    }
}

// ============================================================================
// Section 17 – Cascade XTS JNI bridge (NativeCascadeXTS)
//
// Key inputs: key1 = 96-byte primary keys, key2 = 96-byte secondary keys
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeCascadeXTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    if (key1Len != 96 || key2Len != 96) {
        LOGE("CascadeXTS: invalid key lengths: key1=%d, key2=%d (expected 96)", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) CascadeXTSContext();
    if (!ctx) return 0;
    memset(ctx, 0, sizeof(CascadeXTSContext));

    ctx->hw_aes = detect_hw_aes();

    uint8_t k1[96], k2[96];
    env->GetByteArrayRegion(key1, 0, 96, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, 96, reinterpret_cast<jbyte*>(k2));

    // Primary keys: AES[0–31], Twofish[32–63], Serpent[64–95]
    aes_expand_key(&ctx->aes_data_key, k1,      32);
    twofish_set_key(&ctx->tf_data_key, (const u4byte*)(k1 + 32));
    serpent_set_key(k1 + 64, ctx->sp_data_ks);

    // Secondary (tweak) keys: AES[0–31], Twofish[32–63], Serpent[64–95]
    aes_expand_key(&ctx->aes_tweak_key, k2,      32);
    twofish_set_key(&ctx->tf_tweak_key, (const u4byte*)(k2 + 32));
    serpent_set_key(k2 + 64, ctx->sp_tweak_ks);

    memset(k1, 0, sizeof(k1));
    memset(k2, 0, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeXTS_destroyContext(
        JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (ctx) {
        memset(ctx, 0, sizeof(CascadeXTSContext));
        delete ctx;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeXTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS_Cascade(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeXTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS_Cascade(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

// ============================================================================
// Section 18 – Serpent-Twofish-AES cascade XTS (reversed order)
//
// Encrypt: Serpent → Twofish → AES  (three independent full-buffer XTS passes)
// Decrypt: AES → Twofish → Serpent  (reverse order)
//
// Key layout (192 bytes total):
//   Primary keys   [0–95]:   Serpent[0–31] Twofish[32–63] AES[64–95]
//   Secondary keys [96–191]: Serpent[0–31] Twofish[32–63] AES[64–95]
// Reuses CascadeXTSContext struct from Section 16.
// ============================================================================

static void EncryptBufferXTS_CascadeSTA(CascadeXTSContext* ctx, uint8_t* buf,
                                         uint64_t len, uint64_t startDataUnitNo) {
    // Pass 1: Serpent (innermost)
    {
        SerpentXTSContext spCtx;
        memcpy(spCtx.data_ks,  ctx->sp_data_ks,  sizeof(spCtx.data_ks));
        memcpy(spCtx.tweak_ks, ctx->sp_tweak_ks, sizeof(spCtx.tweak_ks));
        EncryptBufferXTS_Serpent(&spCtx, buf, len, startDataUnitNo);
    }
    // Pass 2: Twofish
    {
        TwofishXTSContext tfCtx;
        tfCtx.data_key  = ctx->tf_data_key;
        tfCtx.tweak_key = ctx->tf_tweak_key;
        EncryptBufferXTS_Twofish(&tfCtx, buf, len, startDataUnitNo);
    }
    // Pass 3: AES (outermost)
    {
        XTSContext aesCtx;
        aesCtx.data_key  = ctx->aes_data_key;
        aesCtx.tweak_key = ctx->aes_tweak_key;
        aesCtx.hw_aes    = ctx->hw_aes;
        EncryptBufferXTS(&aesCtx, buf, len, startDataUnitNo);
    }
}

static void DecryptBufferXTS_CascadeSTA(CascadeXTSContext* ctx, uint8_t* buf,
                                         uint64_t len, uint64_t startDataUnitNo) {
    // Pass 1: AES (peel outermost layer first)
    {
        XTSContext aesCtx;
        aesCtx.data_key  = ctx->aes_data_key;
        aesCtx.tweak_key = ctx->aes_tweak_key;
        aesCtx.hw_aes    = ctx->hw_aes;
        DecryptBufferXTS(&aesCtx, buf, len, startDataUnitNo);
    }
    // Pass 2: Twofish
    {
        TwofishXTSContext tfCtx;
        tfCtx.data_key  = ctx->tf_data_key;
        tfCtx.tweak_key = ctx->tf_tweak_key;
        DecryptBufferXTS_Twofish(&tfCtx, buf, len, startDataUnitNo);
    }
    // Pass 3: Serpent (innermost)
    {
        SerpentXTSContext spCtx;
        memcpy(spCtx.data_ks,  ctx->sp_data_ks,  sizeof(spCtx.data_ks));
        memcpy(spCtx.tweak_ks, ctx->sp_tweak_ks, sizeof(spCtx.tweak_ks));
        DecryptBufferXTS_Serpent(&spCtx, buf, len, startDataUnitNo);
    }
}

// ============================================================================
// Section 19 – Serpent-Twofish-AES cascade JNI bridge (NativeCascadeSTA_XTS)
//
// Key inputs: key1 = 96-byte primary keys, key2 = 96-byte secondary keys
//   Layout: Serpent[0–31] | Twofish[32–63] | AES[64–95]
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeCascadeSTA_1XTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    if (key1Len != 96 || key2Len != 96) {
        LOGE("CascadeSTA_XTS: invalid key lengths: key1=%d, key2=%d (expected 96)", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) CascadeXTSContext();
    if (!ctx) return 0;
    memset(ctx, 0, sizeof(CascadeXTSContext));

    ctx->hw_aes = detect_hw_aes();

    uint8_t k1[96], k2[96];
    env->GetByteArrayRegion(key1, 0, 96, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, 96, reinterpret_cast<jbyte*>(k2));

    // Primary keys: Serpent[0–31], Twofish[32–63], AES[64–95]
    serpent_set_key(k1,      ctx->sp_data_ks);
    twofish_set_key(&ctx->tf_data_key, (const u4byte*)(k1 + 32));
    aes_expand_key(&ctx->aes_data_key, k1 + 64, 32);

    // Secondary (tweak) keys: Serpent[0–31], Twofish[32–63], AES[64–95]
    serpent_set_key(k2,      ctx->sp_tweak_ks);
    twofish_set_key(&ctx->tf_tweak_key, (const u4byte*)(k2 + 32));
    aes_expand_key(&ctx->aes_tweak_key, k2 + 64, 32);

    memset(k1, 0, sizeof(k1));
    memset(k2, 0, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeSTA_1XTS_destroyContext(
        JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (ctx) {
        memset(ctx, 0, sizeof(CascadeXTSContext));
        delete ctx;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeSTA_1XTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS_CascadeSTA(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeSTA_1XTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS_CascadeSTA(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

} // extern "C"
