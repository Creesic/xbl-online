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

/* xboxrecomp's kernel data. Weak so a tool that links this file without the
 * toolkit still builds. The game provides the real symbols. */
#if defined(_MSC_VER)
extern unsigned char xbox_HDKey[16];
extern ptrdiff_t g_xbox_mem_offset;
#else
extern unsigned char xbox_HDKey[16] __attribute__((weak));
extern ptrdiff_t g_xbox_mem_offset __attribute__((weak));
#endif

#define XBL_GUEST_HD_KEY 0x00740100u

void xbl_keys_publish(void)
{
    XblConsole c;
#if !defined(_MSC_VER)
    if (!xbox_HDKey) return;
#endif
    if (xbl_console_load(&c) != 0) return;
    memcpy(xbox_HDKey, c.hdd_key, 16);
#if !defined(_MSC_VER)
    if (!&g_xbox_mem_offset || !g_xbox_mem_offset) return;
#else
    if (!g_xbox_mem_offset) return;
#endif
    memcpy((void *)((uintptr_t)XBL_GUEST_HD_KEY + (uintptr_t)g_xbox_mem_offset),
           c.hdd_key, 16);
}

static void install_saved(const char *save_dir)
{
    XblConsole console;
    XblAccount acct;
    if (xbl_console_load(&console) != 0) {
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
    xbl_ui_start();
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
