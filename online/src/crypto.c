#include "internal.h"

#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
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
#else
    CCHmac(kCCHmacAlgSHA1, key, klen, data ? data : (const uint8_t *)"", dlen, out);
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
#else
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(encrypt ? kCCEncrypt : kCCDecrypt,
                                 kCCAlgorithm3DES, 0,
                                 key, kCCKeySize3DES, iv_copy,
                                 block, 16, out, sizeof(out), &moved);
    if (st != kCCSuccess || moved != 16) return -1;
#endif
    memcpy(block, out, 16);
    return 0;
}
