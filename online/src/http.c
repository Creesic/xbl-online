#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifdef _WIN32
/* Games are GUI programs: _popen would open a cmd.exe console window for
 * every request. curl runs directly, without a window, its stdout on a pipe. */
static void run_capture(char *cmd, char *out, size_t cap)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE rd, wr;
    DWORD got;
    size_t n = 0;

    out[0] = 0;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(rd);
        CloseHandle(wr);
        return;
    }
    CloseHandle(wr);
    while (n + 1 < cap && ReadFile(rd, out + n, (DWORD)(cap - 1 - n), &got, NULL) && got) n += got;
    out[n] = 0;
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(rd);
}
#else
static void run_capture(char *cmd, char *out, size_t cap)
{
    FILE *pf = popen(cmd, "r");
    size_t n = pf ? fread(out, 1, cap - 1, pf) : 0;
    out[n] = 0;
    if (pf) pclose(pf);
}
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
    FILE *bf;
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
    run_capture(cmd, code, sizeof(code));
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
