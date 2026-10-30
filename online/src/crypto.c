#include "internal.h"

#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#else
/* Linux and Android have no system crypto API to call: portable SHA-1 and
 * DES, the same algorithms as the xrecomp kernel's Xc* exports
 * (src/kernel/kernel_crypto.rs). Only short inputs come here, so SHA-1 takes
 * its bytes one at a time. */
static uint32_t rol32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void sha1_block(uint32_t h[5], const uint8_t *p)
{
    uint32_t w[80], a, b, c, d, e;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (i = 16; i < 80; i++) w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (i = 0; i < 80; i++) {
        uint32_t f, k, t;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

/* SHA-1 of a followed by b. */
static void sha1_two(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, uint8_t out[20])
{
    uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    uint8_t block[64];
    size_t used = 0, total = alen + blen, i;
    uint64_t bits = (uint64_t)total * 8;
    for (i = 0; i < total; i++) {
        block[used++] = i < alen ? a[i] : b[i - alen];
        if (used == 64) { sha1_block(h, block); used = 0; }
    }
    block[used++] = 0x80;
    if (used > 56) { memset(block + used, 0, 64 - used); sha1_block(h, block); used = 0; }
    memset(block + used, 0, 56 - used);
    for (i = 0; i < 8; i++) block[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha1_block(h, block);
    for (i = 0; i < 20; i++) out[i] = (uint8_t)(h[i / 4] >> (24 - 8 * (i % 4)));
}

static void hmac_sha1(const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen, uint8_t out[20])
{
    uint8_t k[64] = { 0 }, pad[64], inner[20];
    size_t i;
    if (klen > 64) sha1_two(key, klen, NULL, 0, k); else memcpy(k, key, klen);
    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha1_two(pad, 64, data, dlen, inner);
    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    sha1_two(pad, 64, inner, 20, out);
}

static const uint8_t DES_IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40,
    32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63,
    55, 47, 39, 31, 23, 15, 7 };
static const uint8_t DES_FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53,
    21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1,
    41, 9, 49, 17, 57, 25 };
static const uint8_t DES_E[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20,
    21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
static const uint8_t DES_P[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11,
    4, 25 };
static const uint8_t DES_PC1[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63,
    55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
static const uint8_t DES_PC2[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
static const uint8_t DES_SHIFTS[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
static const uint8_t DES_SBOX[8][64] = {
    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
      4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
      13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
      10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
      4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
      9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
      1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
      7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
};

/* The 1-based, MSB-first DES bit permutation of the low `bits` of `in`. */
static uint64_t des_permute(uint64_t in, int bits, const uint8_t *table, int n)
{
    uint64_t out = 0;
    int i;
    for (i = 0; i < n; i++) out = (out << 1) | ((in >> (bits - table[i])) & 1);
    return out;
}

static void des_subkeys(const uint8_t key[8], uint64_t sub[16])
{
    uint64_t k = 0, cd;
    uint32_t c, d;
    int i;
    for (i = 0; i < 8; i++) k = (k << 8) | key[i];
    cd = des_permute(k, 64, DES_PC1, 56);
    c = (uint32_t)(cd >> 28);
    d = (uint32_t)(cd & 0x0FFFFFFF);
    for (i = 0; i < 16; i++) {
        c = ((c << DES_SHIFTS[i]) | (c >> (28 - DES_SHIFTS[i]))) & 0x0FFFFFFF;
        d = ((d << DES_SHIFTS[i]) | (d >> (28 - DES_SHIFTS[i]))) & 0x0FFFFFFF;
        sub[i] = des_permute(((uint64_t)c << 28) | d, 56, DES_PC2, 48);
    }
}

static uint64_t des_block(uint64_t block, const uint64_t sub[16], int encrypt)
{
    uint64_t x = des_permute(block, 64, DES_IP, 64), l = x >> 32, r = x & 0xFFFFFFFF;
    int round, i;
    for (round = 0; round < 16; round++) {
        uint64_t e = des_permute(r, 32, DES_E, 48) ^ sub[encrypt ? round : 15 - round], s = 0, t;
        for (i = 0; i < 8; i++) {
            unsigned six = (unsigned)(e >> (42 - 6 * i)) & 0x3F;
            s = (s << 4) | DES_SBOX[i][(((six & 0x20) >> 4) | (six & 1)) * 16 + ((six >> 1) & 0xF)];
        }
        t = r;
        r = l ^ des_permute(s, 32, DES_P, 32);
        l = t;
    }
    return des_permute((r << 32) | l, 64, DES_FP, 64);
}

/* 3DES EDE (K1, K2, K3) in CBC over two blocks, as BCrypt and CommonCrypto do. */
static void des3_cbc(const uint8_t key[24], const uint8_t iv[8], const uint8_t in[16], uint8_t out[16], int encrypt)
{
    uint64_t sub[3][16], chain = 0, b, x;
    int k, i;
    for (k = 0; k < 3; k++) des_subkeys(key + 8 * k, sub[k]);
    for (i = 0; i < 8; i++) chain = (chain << 8) | iv[i];
    for (k = 0; k < 2; k++) {
        b = 0;
        for (i = 0; i < 8; i++) b = (b << 8) | in[8 * k + i];
        if (encrypt) {
            x = des_block(des_block(des_block(b ^ chain, sub[0], 1), sub[1], 0), sub[2], 1);
            chain = x;
        } else {
            x = des_block(des_block(des_block(b, sub[2], 0), sub[1], 1), sub[0], 0) ^ chain;
            chain = b;
        }
        for (i = 0; i < 8; i++) out[8 * k + i] = (uint8_t)(x >> (56 - 8 * i));
    }
}
#endif

void xbl_rc4(const uint8_t *key, size_t klen,
             const uint8_t *in, uint8_t *out, size_t n)
{
    uint8_t s[256];
    uint8_t i = 0, j = 0;
    size_t k;
    if (!key || !klen || !out) return;
    for (k = 0; k < 256; k++) s[k] = (uint8_t)k;
    for (k = 0; k < 256; k++) {
        j = (uint8_t)(j + s[k] + key[k % klen]);
        { uint8_t t = s[k]; s[k] = s[j]; s[j] = t; }
    }
    i = 0;
    j = 0;
    for (k = 0; k < n; k++) {
        uint8_t t;
        i++;
        j = (uint8_t)(j + s[i]);
        t = s[i]; s[i] = s[j]; s[j] = t;
        out[k] = (uint8_t)((in ? in[k] : 0) ^ s[(uint8_t)(s[i] + s[j])]);
    }
}

int xbl_hmac_sha1(const uint8_t *key, size_t klen,
                  const uint8_t *data, size_t dlen, uint8_t out[20])
{
    if (!key || !out) return -1;
    if (!data && dlen) return -1;
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, NULL,
                                     BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st < 0) return -1;
    st = BCryptHash(alg, (PUCHAR)key, (ULONG)klen,
                    (PUCHAR)data, (ULONG)dlen, out, 20);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st < 0 ? -1 : 0;
#elif defined(__APPLE__)
    CCHmac(kCCHmacAlgSHA1, key, klen, data ? data : (const uint8_t *)"", dlen, out);
    return 0;
#else
    hmac_sha1(key, klen, data, dlen, out);
    return 0;
#endif
}

int xbl_des3_cbc(const uint8_t key[24], const uint8_t iv[8],
                 uint8_t block[16], int encrypt)
{
    uint8_t out[16];
    uint8_t iv_copy[8];
    if (!key || !iv || !block) return -1;
    memcpy(iv_copy, iv, 8);
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS st;
    ULONG n = 0;
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_3DES_ALGORITHM, NULL, 0);
    if (st < 0) return -1;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                           (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (st >= 0) {
        st = BCryptGenerateSymmetricKey(alg, &hkey, NULL, 0,
                                        (PUCHAR)key, 24, 0);
    }
    if (st >= 0) {
        if (encrypt) {
            st = BCryptEncrypt(hkey, block, 16, NULL, iv_copy, 8,
                               out, 16, &n, 0);
        } else {
            st = BCryptDecrypt(hkey, block, 16, NULL, iv_copy, 8,
                               out, 16, &n, 0);
        }
    }
    if (hkey) BCryptDestroyKey(hkey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (st < 0 || n != 16) return -1;
#elif defined(__APPLE__)
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(encrypt ? kCCEncrypt : kCCDecrypt,
                                 kCCAlgorithm3DES, 0,
                                 key, kCCKeySize3DES, iv_copy,
                                 block, 16, out, sizeof(out), &moved);
    if (st != kCCSuccess || moved != 16) return -1;
#else
    des3_cbc(key, iv_copy, block, out, encrypt);
#endif
    memcpy(block, out, 16);
    return 0;
}
