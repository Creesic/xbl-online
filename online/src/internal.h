#ifndef XBL_INTERNAL_H
#define XBL_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#define XBL_GT_MAX 17

typedef struct {
    char     serial[13];
    uint8_t  mac[6];
    uint8_t  hdd_key[16];
    uint8_t  online_key[16];
    uint8_t  macs_key[16]; /* HMAC-SHA1 + RC4 of the two keys above */
} XblConsole;

typedef struct {
    int      present;
    uint64_t xuid;
    char     gamertag[XBL_GT_MAX];
    char     email[64];
    uint8_t  user_key[16];
    int      has_user_key;
    uint8_t  machine_key[16];
    int      has_machine_key;
} XblAccount;

int  xbl_hmac_sha1(const uint8_t *key, size_t klen,
                   const uint8_t *data, size_t dlen, uint8_t out[20]);
int  xbl_des3_cbc(const uint8_t key[24], const uint8_t iv[8],
                  uint8_t block[16], int encrypt);
void xbl_rc4(const uint8_t *key, size_t klen,
             const uint8_t *in, uint8_t *out, size_t n);

void xbl_profile_dir(char *out, size_t cap);
void xbl_default_save_dir(char *out, size_t cap);
int  xbl_console_load(XblConsole *c);
int  xbl_game_console(XblConsole *c);  /* the identity with the zero XboxHDKey games get */
int  xbl_account_load(XblAccount *a);
int  xbl_account_save(const XblAccount *a);
void xbl_account_clear(void);

/* Write the signed account into <save_dir>/Partition0.img.
 * a->present == 0 clears the user slots. Returns 0 on success. */
int  xbl_disk_install(const char *save_dir, const XblAccount *a,
                      const XblConsole *console);

int  xbl_http_post(const char *url, const char *json,
                   char *resp, size_t resp_cap, long *status);

int  xbl_signin_password(const char *email, const char *password, char *err, size_t err_cap);
int  xbl_signin_device_start(char *user_code, size_t code_cap,
                             char *poll_token, size_t token_cap,
                             char *err, size_t err_cap);
/* 1 approved and installed, 0 pending, -1 failed. */
int  xbl_signin_device_poll(const char *poll_token, char *err, size_t err_cap);

void xbl_ui_start(void);
void xbl_status_set(const char *msg);

#endif
