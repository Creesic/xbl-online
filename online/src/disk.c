#include "internal.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/stat.h>
#endif

#define SECTOR 512
#define DATA   492
#define REC    120
#define BASE_LBA 8
#define BEGIN_SIG 0x79132568u
#define END_SIG   0xAA550000u
#define SIG_KEY   "Mar/2002 SDK"

static const uint8_t KEY_MORPH_1[16] = {
    0x2B, 0xB8, 0xD9, 0xEF, 0xD2, 0x04, 0x6D, 0x9D,
    0x1F, 0x39, 0xB1, 0x5B, 0x46, 0x58, 0x01, 0xD7
};
static const uint8_t KEY_MORPH_2[16] = {
    0x1E, 0x05, 0xD7, 0x3A, 0xA4, 0x20, 0x6A, 0x7B,
    0xA0, 0x5B, 0xCD, 0xDF, 0xAD, 0x26, 0xD3, 0xDE
};
static const uint8_t KEY_MORPH_IV[8] = {
    0x7B, 0x35, 0xA8, 0xB7, 0x27, 0xED, 0x43, 0x7A
};

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_u64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t xconfig_checksum(const uint8_t *b, uint32_t count)
{
    uint32_t eax = 0, ebx = 0, i, n = count / 4;
    for (i = 0; i < n; i++) {
        uint64_t t = (uint64_t)eax + get_u32(b + i * 4);
        eax = (uint32_t)t;
        if (t >> 32) ebx++;
    }
    {
        uint64_t t = (uint64_t)eax + ebx;
        eax = (uint32_t)t;
        if (t >> 32) eax++;
    }
    return eax;
}

static uint8_t odd_parity(uint8_t b)
{
    uint8_t masked = (uint8_t)(b & 0xFE);
    int ones = 0;
    uint8_t t;
    for (t = masked; t; t >>= 1) ones += (t & 1);
    return (ones & 1) ? masked : (uint8_t)(masked | 0x01);
}

static int morph_deskey(const uint8_t seed[16], uint8_t deskey[24])
{
    uint8_t d1[20], d2[20];
    int i;
    if (xbl_hmac_sha1(KEY_MORPH_1, 16, seed, 16, d1) != 0) return -1;
    if (xbl_hmac_sha1(KEY_MORPH_2, 16, seed, 16, d2) != 0) return -1;
    memcpy(deskey, d1, 4);
    memcpy(deskey + 4, d2, 20);
    for (i = 0; i < 24; i++) deskey[i] = odd_parity(deskey[i]);
    return 0;
}

static int morph_key(const uint8_t hdd[16], uint8_t key[16], const uint8_t iv[8], int encrypt)
{
    uint8_t deskey[24];
    if (morph_deskey(hdd, deskey) != 0) return -1;
    return xbl_des3_cbc(deskey, iv, key, encrypt);
}

static uint32_t signature_time(void)
{
    const uint64_t base = 0x01BF5C72FEFB6A60ULL;
    uint64_t ft = ((uint64_t)time(NULL) + 11644473600ULL) * 10000000ULL;
    uint64_t ticks;
    if (ft < base) return 1;
    ticks = (ft - base) / 20000000ULL;
    if (ticks > 0xFFFFFFFFu) ticks = 0xFFFFFFFFu;
    return ticks ? (uint32_t)ticks : 1;
}

static void finish_sector(uint8_t sec[SECTOR], const uint8_t data[DATA])
{
    uint32_t sum;
    memset(sec, 0, SECTOR);
    put_u32(sec + 0, BEGIN_SIG);
    put_u32(sec + 4, 1);
    put_u32(sec + 8, 1);
    memcpy(sec + 12, data, DATA);
    put_u32(sec + 0x1FC, END_SIG);
    sum = xconfig_checksum(sec, SECTOR);
    put_u32(sec + 0x1F8, ~sum);
}

/* 108-byte StoredAccount. HMAC covers the key in the clear, then the key
 * is 3DES-wrapped under the slot handle. This is the record games list. */
static int fill_and_sign_108(uint8_t rec[REC], const XblAccount *a,
                             const uint8_t hdd[16], const uint8_t *key,
                             const uint8_t iv[8])
{
    uint8_t digest[20];
    size_t n;
    memset(rec, 0, REC);
    put_u64(rec + 0x00, a->xuid);
    n = strlen(a->gamertag);
    if (n > 16) n = 16;
    memcpy(rec + 0x0C, a->gamertag, n);
    memcpy(rec + 0x24, "xb.live", 7);
    memcpy(rec + 0x38, "passport.net", 12);
    if (key) memcpy(rec + 0x50, key, 16);
    put_u32(rec + 0x60, signature_time());
    if (xbl_hmac_sha1(hdd, 16, rec, 0x64, digest) != 0) return -1;
    memcpy(rec + 0x64, digest, 8);
    if (morph_key(hdd, rec + 0x50, iv, 1) != 0) return -1;
    return 0;
}

static int verify_108(const uint8_t rec[REC], const uint8_t hdd[16], const uint8_t iv[8])
{
    uint8_t tmp[REC], digest[20];
    memcpy(tmp, rec, REC);
    if (morph_key(hdd, tmp + 0x50, iv, 0) != 0) return -1;
    if (xbl_hmac_sha1(hdd, 16, tmp, 0x64, digest) != 0) return -1;
    return memcmp(digest, rec + 0x64, 8) == 0 ? 0 : -1;
}

static void make_handle(const uint8_t hdd[16], const XblAccount *a, uint8_t out[8])
{
    uint8_t seed[32], digest[20];
    size_t n = 0;
    int i;
    for (i = 0; i < 8; i++) seed[n++] = (uint8_t)(a->xuid >> (8 * i));
    for (i = 0; a->gamertag[i] && n < sizeof(seed); i++)
        seed[n++] = (uint8_t)a->gamertag[i];
    if (xbl_hmac_sha1(hdd, 16, seed, n, digest) == 0)
        memcpy(out, digest, 8);
    else
        memcpy(out, seed, 8);
    if (!out[0] && !out[1] && !out[2] && !out[3]) out[0] = 1;
}

static void mkdir_p(const char *path)
{
    char tmp[640];
    size_t i, n;
    snprintf(tmp, sizeof(tmp), "%s", path);
    n = strlen(tmp);
    for (i = 1; i < n; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            tmp[i] = 0;
#ifdef _WIN32
            CreateDirectoryA(tmp, NULL);
#else
            mkdir(tmp, 0755);
#endif
            tmp[i] = '/';
        }
    }
#ifdef _WIN32
    CreateDirectoryA(tmp, NULL);
#else
    mkdir(tmp, 0755);
#endif
}

static int write_at(FILE *f, unsigned lba, const uint8_t sec[SECTOR])
{
    if (fseek(f, (long)lba * SECTOR, SEEK_SET) != 0) return -1;
    return fwrite(sec, 1, SECTOR, f) == SECTOR ? 0 : -1;
}

static int read_at(FILE *f, unsigned lba, uint8_t sec[SECTOR])
{
    if (fseek(f, (long)lba * SECTOR, SEEK_SET) != 0) return -1;
    return fread(sec, 1, SECTOR, f) == SECTOR ? 0 : -1;
}

int xbl_disk_install(const char *save_dir, const XblAccount *a, const XblConsole *console)
{
    char path[640];
    FILE *f;
    uint8_t data[DATA], sec[SECTOR], rec[REC], handle[8];
    size_t n;
    int slash;

    if (!save_dir || !save_dir[0] || !console) return -1;
    n = strlen(save_dir);
    slash = n && (save_dir[n - 1] == '/' || save_dir[n - 1] == '\\');
    snprintf(path, sizeof(path), slash ? "%sPartition0.img" : "%s/Partition0.img", save_dir);
    mkdir_p(save_dir);

    f = fopen(path, "r+b");
    if (!f) f = fopen(path, "w+b");
    if (!f) return -1;

    memset(data, 0, sizeof(data));
    memset(rec, 0, sizeof(rec));

    if (a && a->present && a->gamertag[0]) {
        make_handle(console->hdd_key, a, handle);

        /* Sector 3 is the index. A zero marker makes every reader skip the slot. */
        memset(data, 0, sizeof(data));
        put_u32(data + 0, 1);
        memcpy(data + 4, handle, 8);
        finish_sector(sec, data);
        if (write_at(f, BASE_LBA + 3, sec) != 0) { fclose(f); return -1; }

        if (fill_and_sign_108(rec, a, console->hdd_key,
                              a->has_user_key ? a->user_key : NULL, handle) != 0) {
            fclose(f);
            return -1;
        }
        memset(data, 0, sizeof(data));
        memcpy(data, rec, 108);
        finish_sector(sec, data);
        if (write_at(f, BASE_LBA + 4, sec) != 0) { fclose(f); return -1; }

        /* Read it back. A bad signature is the same as no account. */
        if (read_at(f, BASE_LBA + 4, sec) != 0 ||
            memcmp(sec + 12, rec, 108) != 0 ||
            verify_108(sec + 12, console->hdd_key, handle) != 0) {
            fclose(f);
            return -1;
        }

        /* Sector 2 is the 120-byte record the older enumerator reads.
         * Kingdom is left empty; the name sits at 0x0C. */
        memset(rec, 0, sizeof(rec));
        put_u64(rec + 0x00, a->xuid);
        n = strlen(a->gamertag);
        if (n > 16) n = 16;
        memcpy(rec + 0x0C, a->gamertag, n);
        memcpy(rec + 0x30, "xb.live", 7);
        memcpy(rec + 0x44, "passport.net", 12);
        if (a->has_user_key) memcpy(rec + 0x5C, a->user_key, 16);
        put_u32(rec + 0x6C, signature_time());
        {
            uint8_t digest[20];
            if (xbl_hmac_sha1((const uint8_t *)SIG_KEY, sizeof(SIG_KEY),
                              rec, 0x70, digest) != 0) {
                fclose(f);
                return -1;
            }
            memcpy(rec + 0x70, digest, 8);
        }
        memset(data, 0, sizeof(data));
        memcpy(data, rec, REC);
        finish_sector(sec, data);
        if (write_at(f, BASE_LBA + 2, sec) != 0) { fclose(f); return -1; }

        if (a->has_machine_key && console->serial[0]) {
            XblAccount machine;
            memset(&machine, 0, sizeof(machine));
            machine.present = 1;
            machine.xuid = 0;
            snprintf(machine.gamertag, sizeof(machine.gamertag), "SN.%s", console->serial);
            if (fill_and_sign_108(rec, &machine, console->hdd_key,
                                  a->machine_key, KEY_MORPH_IV) == 0) {
                memset(data, 0, sizeof(data));
                memcpy(data, rec, 108);
                finish_sector(sec, data);
                write_at(f, BASE_LBA + 1, sec);
            }
        }
    } else {
        unsigned i;
        memset(data, 0, sizeof(data));
        finish_sector(sec, data);
        for (i = 1; i <= 4; i++) {
            if (write_at(f, BASE_LBA + i, sec) != 0) { fclose(f); return -1; }
        }
    }

    fclose(f);
    return 0;
}
