/*
 * HealthMonitor.c - lab agent service (one-time weakness).
 *
 * Runs as LocalSystem and executes every *.ps1 found in C:\ProgramData\HealthMonitor\checks.
 * That directory is writable by Users, which is the misconfiguration the chain abuses.
 *
 * Build: x86_64-w64-mingw32-gcc -O2 -o HealthMonitor.exe HealthMonitor.c
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#define CHECK_DIR L"C:\\ProgramData\\HealthMonitor\\checks"
#define DONE_DIR  L"C:\\ProgramData\\HealthMonitor\\done"
#define LOG_PATH  L"C:\\ProgramData\\HealthMonitor\\agent.log"

static SERVICE_STATUS_HANDLE g_ssh;
static SERVICE_STATUS g_status;
static volatile int g_stop = 0;

static void logline(const wchar_t *msg)
{
    FILE *f = _wfopen(LOG_PATH, L"a, ccs=UTF-8");
    if (f) { fwprintf(f, L"%s\n", msg); fclose(f); }
}

static void run_script(const wchar_t *path)
{
    wchar_t cmd[1024];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    _snwprintf(cmd, 1024, L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%s\"", path);
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5 * 60 * 1000);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
}

static void scan_once(void)
{
    wchar_t pattern[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    _snwprintf(pattern, MAX_PATH, L"%s\\*.ps1", CHECK_DIR);
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        wchar_t full[MAX_PATH], done[MAX_PATH], msg[MAX_PATH + 64];
        _snwprintf(full, MAX_PATH, L"%s\\%s", CHECK_DIR, fd.cFileName);
        _snwprintf(msg, MAX_PATH + 64, L"running %s", fd.cFileName);
        logline(msg);
        run_script(full);
        _snwprintf(done, MAX_PATH, L"%s\\%s", DONE_DIR, fd.cFileName);
        MoveFileExW(full, done, MOVEFILE_REPLACE_EXISTING);
        logline(L"done");
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void WINAPI handler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP) { g_stop = 1; g_status.dwCurrentState = SERVICE_STOP_PENDING; }
    SetServiceStatus(g_ssh, &g_status);
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv)
{
    (void)argc; (void)argv;
    g_ssh = RegisterServiceCtrlHandlerW(L"HealthMonitor", handler);
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = SERVICE_RUNNING;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_status.dwWin32ExitCode = 0;
    SetServiceStatus(g_ssh, &g_status);
    logline(L"agent started");
    while (!g_stop) {
        scan_once();
        Sleep(60 * 1000);
    }
    logline(L"agent stopped");
    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_ssh, &g_status);
}

int main(void)
{
    SERVICE_TABLE_ENTRYW table[] = { { L"HealthMonitor", service_main }, { NULL, NULL } };
    StartServiceCtrlDispatcherW(table);
    return 0;
}
