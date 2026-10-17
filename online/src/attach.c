#include "xbl_online.h"
#include "internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_save[512];
static int g_ready;

/* Referenced from the game link line so the linker keeps this file. */
int xbl_online_attach_anchor = 1;

/* XboxHDKey of every title on every PC: SHA-1("xrecomp XboxHDKey")[0..16], the
 * runtime kernel's GAME_HD_KEY (xrecomp src/kernel/kernel_xbox.rs). Titles sign
 * saves with XboxHDKey, so the identity's own key tied saves to one PC and to
 * being signed in. It is not zero because XAPI signs with the EEPROM's serial
 * and MAC (bytes 0x36..0x46) when XboxHDKey is zero. */
static const uint8_t GAME_HD_KEY[16] = {
    0x78, 0x2E, 0xA5, 0x47, 0x18, 0x02, 0xBD, 0x8D, 0x1A, 0x89, 0xDE, 0x22, 0x1E, 0x3A, 0x19, 0xD9,
};

/* The identity as the game sees it: its XboxHDKey is GAME_HD_KEY, and the
 * account sectors are signed with the same key. The server's machine account
 * key arrives on disk, so no title derives a key from the registered hdd_key. */
int xbl_game_console(XblConsole *c)
{
    if (xbl_console_load(c) != 0) return -1;
    memcpy(c->hdd_key, GAME_HD_KEY, sizeof(c->hdd_key));
    return 0;
}

/* The runtime hands these to its kernel before the title starts, so the
 * EEPROM and XboxHDKey the game reads match the account sectors. Writing
 * into guest memory from here would assume one toolkit's memory layout. */
int xbl_online_console(char serial[12], unsigned char mac[6],
                       unsigned char online_key[16], unsigned char hdd_key[16])
{
    XblConsole c;
    if (xbl_game_console(&c) != 0) return -1;
    memcpy(serial, c.serial, 12);
    memcpy(mac, c.mac, 6);
    memcpy(online_key, c.online_key, 16);
    memcpy(hdd_key, c.hdd_key, 16);
    return 0;
}

static void install_saved(const char *save_dir)
{
    XblConsole console;
    XblAccount acct;
    if (xbl_game_console(&console) != 0) {
        xbl_status_set("Could not prepare a console identity.");
        return;
    }
    if (xbl_account_load(&acct) != 0) memset(&acct, 0, sizeof(acct));
    if (xbl_disk_install(save_dir, &acct, &console) != 0) {
        xbl_status_set("Could not write Partition0.img for the game.");
        return;
    }
    if (acct.present)
        xbl_status_set("XB Online account is on disk.");
}

void xbl_online_attach(const char *save_dir)
{
    const char *env = getenv("XBL_ONLINE_DISABLE");
    if (env && env[0] == '1') return;
    if (save_dir && save_dir[0])
        snprintf(g_save, sizeof(g_save), "%s", save_dir);
    else
        xbl_default_save_dir(g_save, sizeof(g_save));
    install_saved(g_save);
#ifdef _WIN32
    _putenv_s("XBL_ONLINE_SAVE_DIR", g_save);
#else
    setenv("XBL_ONLINE_SAVE_DIR", g_save, 1);
#endif
    g_ready = 1;
    /* Sign-in UI is suspended for all games until the account flow is reworked. */
}

#ifndef XBL_ONLINE_NO_ATTACH
#ifdef _MSC_VER
#pragma section(".CRT$XCU", read)
static void xbl_ctor(void);
__declspec(allocate(".CRT$XCU")) static void (*xbl_ctor_slot)(void) = xbl_ctor;
#else
__attribute__((constructor))
#endif
static void xbl_ctor(void)
{
    xbl_online_attach(NULL);
}
#endif
