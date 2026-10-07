#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>
#else
#include <sys/stat.h>
#endif

static void mkdir_one(const char *path)
{
#ifdef _WIN32
    CreateDirectoryA(path, NULL);
#else
    mkdir(path, 0755);
#endif
}

static void mkdir_p(const char *path)
{
    char tmp[512];
    size_t n, i;
    snprintf(tmp, sizeof(tmp), "%s", path);
    n = strlen(tmp);
    for (i = 1; i < n; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            tmp[i] = 0;
            mkdir_one(tmp);
            tmp[i] = '/';
        }
    }
    mkdir_one(tmp);
}

void xbl_profile_dir(char *out, size_t cap)
{
    const char *env = getenv("XBL_ONLINE_PROFILE");
    if (env && env[0]) {
        snprintf(out, cap, "%s", env);
        return;
    }
#ifdef _WIN32
    char base[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base)))
        snprintf(out, cap, "%s\\XBOnline", base);
    else
        snprintf(out, cap, "XBOnline");
#elif defined(__APPLE__)
    const char *home = getenv("HOME");
    snprintf(out, cap, "%s/Library/Application Support/XBOnline",
             home && home[0] ? home : ".");
#else
    const char *xdg = getenv("XDG_DATA_HOME");
    if (xdg && xdg[0])
        snprintf(out, cap, "%s/XBOnline", xdg);
    else {
        const char *home = getenv("HOME");
        snprintf(out, cap, "%s/.local/share/XBOnline", home && home[0] ? home : ".");
    }
#endif
}

void xbl_default_save_dir(char *out, size_t cap)
{
    const char *env = getenv("XBL_ONLINE_SAVE_DIR");
    if (env && env[0]) {
        snprintf(out, cap, "%s", env);
        return;
    }
#ifdef _WIN32
    char base[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base)))
        snprintf(out, cap, "%s\\xboxrecomp", base);
    else
        snprintf(out, cap, "xboxrecomp");
#else
    const char *xdg = getenv("XDG_DATA_HOME");
    if (xdg && xdg[0])
        snprintf(out, cap, "%s/xboxrecomp", xdg);
    else {
        const char *home = getenv("HOME");
        snprintf(out, cap, "%s/.local/share/xboxrecomp", home && home[0] ? home : ".");
    }
#endif
}

static int path_join(char *out, size_t cap, const char *dir, const char *name)
{
    size_t n = strlen(dir);
    int slash = n && (dir[n - 1] == '/' || dir[n - 1] == '\\');
    return snprintf(out, cap, slash ? "%s%s" : "%s/%s", dir, name) < (int)cap;
}

static int read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) return -1;
    n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = 0;
    return 0;
}

static const char *field(const char *text, const char *key, char *out, size_t cap)
{
    size_t klen = strlen(key);
    const char *p = text;
    out[0] = 0;
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > klen && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            size_t vlen = len - klen - 1;
            if (vlen && p[len - 1] == '\r') vlen--;
            if (vlen >= cap) vlen = cap - 1;
            memcpy(out, p + klen + 1, vlen);
            out[vlen] = 0;
            return out;
        }
        p = nl ? nl + 1 : NULL;
    }
    return NULL;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, uint8_t *out, size_t n)
{
    size_t i;
    if (!s || strlen(s) < n * 2) return -1;
    for (i = 0; i < n; i++) {
        int hi = hex_nibble(s[i * 2]);
        int lo = hex_nibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void hex_out(const uint8_t *p, size_t n, char *out)
{
    size_t i;
    for (i = 0; i < n; i++) sprintf(out + i * 2, "%02x", p[i]);
    out[n * 2] = 0;
}

static int random_bytes(uint8_t *p, size_t n)
{
#ifdef _WIN32
    return BCryptGenRandom(NULL, p, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0
           ? -1 : 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    if (fread(p, 1, n, f) != n) { fclose(f); return -1; }
    fclose(f);
    return 0;
#endif
}

static void console_path(char *out, size_t cap)
{
    char dir[512];
    xbl_profile_dir(dir, sizeof(dir));
    mkdir_p(dir);
    path_join(out, cap, dir, "console.txt");
}

static void account_path(char *out, size_t cap)
{
    char dir[512];
    xbl_profile_dir(dir, sizeof(dir));
    mkdir_p(dir);
    path_join(out, cap, dir, "account.txt");
}

int xbl_console_load(XblConsole *c)
{
    char path[640], text[512], mac[32], hk[40], ok[40];
    FILE *f;
    uint8_t rnd[16];
    memset(c, 0, sizeof(*c));
    console_path(path, sizeof(path));
    if (read_file(path, text, sizeof(text)) == 0 &&
        field(text, "serial", c->serial, sizeof(c->serial)) &&
        strlen(c->serial) == 12 &&
        field(text, "mac", mac, sizeof(mac)) &&
        field(text, "hdd_key", hk, sizeof(hk)) &&
        field(text, "online_key", ok, sizeof(ok)) &&
        parse_hex(hk, c->hdd_key, 16) == 0 &&
        parse_hex(ok, c->online_key, 16) == 0) {
        unsigned b[6];
        if (sscanf(mac, "%x:%x:%x:%x:%x:%x",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
            int i;
            for (i = 0; i < 6; i++) c->mac[i] = (uint8_t)b[i];
            return 0;
        }
    }
    if (random_bytes(rnd, sizeof(rnd)) != 0) return -1;
    {
        unsigned i;
        for (i = 0; i < 12; i++)
            c->serial[i] = (char)('0' + (rnd[i % 16] + i * 3) % 10);
        c->serial[12] = 0;
        if (c->serial[0] == '0') c->serial[0] = '1';
    }
    memcpy(c->mac, rnd, 6);
    c->mac[0] = (uint8_t)((c->mac[0] | 0x02) & 0xfe);
    memcpy(c->hdd_key, rnd, 16);
    if (random_bytes(c->online_key, 16) != 0) return -1;
    f = fopen(path, "wb");
    if (!f) return -1;
    hex_out(c->hdd_key, 16, hk);
    hex_out(c->online_key, 16, ok);
    fprintf(f, "serial=%s\nmac=%02x:%02x:%02x:%02x:%02x:%02x\nhdd_key=%s\nonline_key=%s\n",
            c->serial, c->mac[0], c->mac[1], c->mac[2], c->mac[3], c->mac[4], c->mac[5],
            hk, ok);
    fclose(f);
    return 0;
}

int xbl_account_load(XblAccount *a)
{
    char path[640], text[768], xs[40], uk[40], mk[40];
    memset(a, 0, sizeof(*a));
    account_path(path, sizeof(path));
    if (read_file(path, text, sizeof(text)) != 0) return -1;
    if (!field(text, "gamertag", a->gamertag, sizeof(a->gamertag)) || !a->gamertag[0])
        return -1;
    field(text, "email", a->email, sizeof(a->email));
    if (field(text, "xuid", xs, sizeof(xs)) && strlen(xs) == 16)
        a->xuid = strtoull(xs, NULL, 16);
    if (field(text, "user_key", uk, sizeof(uk)) && parse_hex(uk, a->user_key, 16) == 0)
        a->has_user_key = 1;
    if (field(text, "machine_key", mk, sizeof(mk)) && parse_hex(mk, a->machine_key, 16) == 0)
        a->has_machine_key = 1;
    a->present = 1;
    return 0;
}

int xbl_account_save(const XblAccount *a)
{
    char path[640], uk[40], mk[40];
    FILE *f;
    account_path(path, sizeof(path));
    f = fopen(path, "wb");
    if (!f) return -1;
    hex_out(a->user_key, 16, uk);
    hex_out(a->machine_key, 16, mk);
    fprintf(f, "gamertag=%s\nemail=%s\nxuid=%016llx\nuser_key=%s\nmachine_key=%s\n",
            a->gamertag, a->email, (unsigned long long)a->xuid,
            a->has_user_key ? uk : "",
            a->has_machine_key ? mk : "");
    fclose(f);
    return 0;
}

void xbl_account_clear(void)
{
    char path[640];
    account_path(path, sizeof(path));
    remove(path);
}
