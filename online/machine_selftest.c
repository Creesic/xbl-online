/* The machine account a game saved after MACS survives the next install.
 * Windows: clang -Iinclude -Isrc machine_selftest.c src/crypto.c -lbcrypt */
#include "src/disk.c"

static uint64_t machine_xuid(const char *path)
{
    uint8_t b[8];
    uint64_t v = 0;
    int i;
    FILE *f = fopen(path, "rb");
    if (!f) return ~0ULL;
    fseek(f, (long)(BASE_LBA + 1) * SECTOR + 12, SEEK_SET);
    if (fread(b, 1, 8, f) != 8) v = ~0ULL;
    else for (i = 7; i >= 0; i--) v = v << 8 | b[i];
    fclose(f);
    return v;
}

int main(void)
{
    const char *dir = "xbl-machine-selftest";
    const char *img = "xbl-machine-selftest/Partition0.img";
    XblConsole console;
    XblAccount acct, machine;
    uint8_t rec[REC], data[DATA], sec[SECTOR];
    FILE *f;

    memset(&console, 0, sizeof(console));
    memcpy(console.serial, "123456789012", 12);
    memset(console.hdd_key, 0x78, 16);
    memset(&acct, 0, sizeof(acct));
    acct.present = 1;
    acct.xuid = 0x0009000000000042ULL;
    snprintf(acct.gamertag, sizeof(acct.gamertag), "TestTag");
    memset(acct.machine_key, 0x4D, 16);
    acct.has_machine_key = 1;
    remove(img);

    if (xbl_disk_install(dir, &acct, &console) != 0 || machine_xuid(img) != 0) {
        fprintf(stderr, "FAIL first install\n");
        return 1;
    }
    /* What XOnline's SaveMachineAccountConfig writes after MACS. */
    memset(&machine, 0, sizeof(machine));
    machine.xuid = 0x0009000000000041ULL;
    snprintf(machine.gamertag, sizeof(machine.gamertag), "SN.%s", console.serial);
    fill_and_sign_108(rec, &machine, console.hdd_key, acct.machine_key, KEY_MORPH_IV);
    memset(data, 0, sizeof(data));
    memcpy(data, rec, 108);
    finish_sector(sec, data);
    f = fopen(img, "r+b");
    if (!f || write_at(f, BASE_LBA + 1, sec) != 0) return 1;
    fclose(f);

    if (xbl_disk_install(dir, &acct, &console) != 0 || machine_xuid(img) != machine.xuid) {
        fprintf(stderr, "FAIL game machine account not kept\n");
        return 1;
    }
    memset(acct.machine_key, 0x4E, 16); /* another console's key: replace it */
    if (xbl_disk_install(dir, &acct, &console) != 0 || machine_xuid(img) != 0) {
        fprintf(stderr, "FAIL stale machine account kept\n");
        return 1;
    }
    printf("ok\n");
    return 0;
}
