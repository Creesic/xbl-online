#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define popen _popen
#define pclose _pclose
#else
#include <unistd.h>
#endif

static int safe_url(const char *url)
{
    if (!url || strncmp(url, "https://", 8) != 0) {
        if (!url || strncmp(url, "http://", 7) != 0) return -1;
    }
    if (strpbrk(url, " \t\r\n\"'`$;|&<>")) return -1;
    return 0;
}

int xbl_http_post(const char *url, const char *json, char *resp, size_t resp_cap, long *status)
{
    char body_path[64], resp_path[64], cmd[768], code[16];
    FILE *bf, *pf;
    size_t n;
    long http = 0;

    if (status) *status = 0;
    if (resp && resp_cap) resp[0] = 0;
    if (safe_url(url) != 0 || !json) return -1;

#ifdef _WIN32
    snprintf(body_path, sizeof(body_path), "xbl-body-%lu.json", GetCurrentProcessId());
    snprintf(resp_path, sizeof(resp_path), "xbl-resp-%lu.txt", GetCurrentProcessId());
#else
    snprintf(body_path, sizeof(body_path), "/tmp/xbl-body-%d.json", (int)getpid());
    snprintf(resp_path, sizeof(resp_path), "/tmp/xbl-resp-%d.txt", (int)getpid());
#endif

    bf = fopen(body_path, "wb");
    if (!bf) return -1;
    fwrite(json, 1, strlen(json), bf);
    fclose(bf);

    snprintf(cmd, sizeof(cmd),
             "curl -sS --max-time 25 -o \"%s\" -w \"%%{http_code}\" "
             "-H \"Content-Type: application/json\" --data-binary @\"%s\" \"%s\"",
             resp_path, body_path, url);
    pf = popen(cmd, "r");
    if (!pf) {
        remove(body_path);
        return -1;
    }
    n = fread(code, 1, sizeof(code) - 1, pf);
    code[n] = 0;
    pclose(pf);
    http = strtol(code, NULL, 10);
    if (status) *status = http;

    if (resp && resp_cap) {
        FILE *rf = fopen(resp_path, "rb");
        if (rf) {
            n = fread(resp, 1, resp_cap - 1, rf);
            resp[n] = 0;
            fclose(rf);
        }
    }
    remove(body_path);
    remove(resp_path);
    return http > 0 ? 0 : -1;
}
