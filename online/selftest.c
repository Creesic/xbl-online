#include "internal.h"
#include "xbl_online.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

static int fail(const char *msg)
{
    fprintf(stderr, "FAIL %s\n", msg);
    return 1;
}

int main(void)
{
    uint8_t mac[20];
    uint8_t block[16], key[24], iv[8];
    XblConsole console;
    XblAccount acct;
    char dir[] = "/tmp/xbl-online-selftest";
    const uint8_t *data = (const uint8_t *)"The quick brown fox jumps over the lazy dog";
    const uint8_t *hkey = (const uint8_t *)"key";
    static const uint8_t expect[20] = {
        0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a,
        0x7a, 0x36, 0xf7, 0x0a, 0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9
    };

    if (xbl_hmac_sha1(hkey, 3, data, 43, mac) != 0) return fail("hmac");
    if (memcmp(mac, expect, 20) != 0) return fail("hmac vector");

    memset(block, 0x5a, sizeof(block));
    memset(key, 0x11, sizeof(key));
    memset(iv, 0x22, sizeof(iv));
    if (xbl_des3_cbc(key, iv, block, 1) != 0) return fail("3des encrypt");
    if (xbl_des3_cbc(key, iv, block, 0) != 0) return fail("3des decrypt");
    if (block[0] != 0x5a || block[15] != 0x5a) return fail("3des roundtrip");

    mkdir(dir, 0755);
    setenv("XBL_ONLINE_PROFILE", dir, 1);
    setenv("XBL_ONLINE_SAVE_DIR", dir, 1);
    remove("/tmp/xbl-online-selftest/console.txt");
    remove("/tmp/xbl-online-selftest/account.txt");

    if (xbl_console_load(&console) != 0) return fail("console");
    if (strlen(console.serial) != 12 || console.serial[0] == '0') return fail("serial");
    if (memcmp(console.mac, console.hdd_key, 6) == 0) return fail("mac tied to hdd key");
    if (memcmp(console.hdd_key, console.online_key, 16) == 0) return fail("keys identical");
    {
        int i, any = 0;
        for (i = 0; i < 16; i++) any |= console.macs_key[i];
        if (!any) return fail("macs key");
    }
    {
        XblConsole again;
        if (xbl_console_load(&again) != 0) return fail("console reload");
        if (memcmp(again.hdd_key, console.hdd_key, 16) != 0) return fail("hdd key changed");
        if (memcmp(again.online_key, console.online_key, 16) != 0) return fail("online key changed");
        if (memcmp(again.mac, console.mac, 6) != 0) return fail("mac changed");
        if (memcmp(again.macs_key, console.macs_key, 16) != 0) return fail("macs key changed");
    }

    memset(&acct, 0, sizeof(acct));
    acct.present = 1;
    acct.xuid = 0x0009000000000042ULL;
    snprintf(acct.gamertag, sizeof(acct.gamertag), "TestTag");
    memcpy(acct.user_key, "0123456789abcdef", 16);
    acct.has_user_key = 1;
    if (xbl_disk_install(dir, &acct, &console) != 0) return fail("install");
    {
        /* Signed in or not, games get one XboxHDKey (zero) and the account
         * sectors verify under it. */
        char serial[12];
        uint8_t mac6[6], online[16], hdd[16], zero[16] = {0};
        XblConsole game;
        if (xbl_online_console(serial, mac6, online, hdd) != 0) return fail("game console");
        if (memcmp(hdd, zero, 16) != 0) return fail("game hdd key not zero");
        if (memcmp(serial, console.serial, 12) != 0) return fail("game serial");
        if (xbl_game_console(&game) != 0) return fail("game identity");
        if (memcmp(game.hdd_key, zero, 16) != 0) return fail("sector key not zero");
        if (xbl_disk_install(dir, &acct, &game) != 0) return fail("install zero key");
    }

    memset(&acct, 0, sizeof(acct));
    if (xbl_disk_install(dir, &acct, &console) != 0) return fail("clear");

    printf("ok\n");
    return 0;
}
