/*
 * locker_sim.c — argument-compatible, reversible stand-in for the Conti locker
 *
 * Accepts the deployment flag set produced by locker.bat:
 *
 *   <name>_locker.exe -m -net -size 10 -nomutex -p \\TARGET\C$
 *
 * Behaviour: renames files in the target tree by appending ".c0015" and writes readme.txt into
 * every directory it touches. Nothing is encrypted, no key material is generated, and every action
 * is reversed by removing the suffix and the note. The process command line, the note name, and the
 * file churn are the observables the lab needs; the cipher is intentionally absent.
 *
 * The network path argument is rendered as-is for command-line fidelity, then redirected to the
 * corpus root supplied in C0015_CORPUS. The simulator never writes to a share it was handed.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -o locker_sim.exe locker_sim.c
 *
 * Run (from the backup server):
 *   set C0015_CORPUS=C:\C0015\corpus
 *   locker_sim.exe -m -net -size 10 -nomutex -p \\FS01\C$
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NOTE_NAME L"readme.txt"
#define SUFFIX L".c0015"
#define MAX_FILES 20000

static const char *g_note =
    "All of your files are currently encrypted by CONTI strain.\r\n"
    "Contact: https://contirecovery.xyz/\r\n";

static int g_files = 0;
static int g_notes = 0;
static int g_skipped = 0;

static void join(wchar_t *out, size_t cch, const wchar_t *dir, const wchar_t *name)
{
    _snwprintf(out, cch, L"%s\\%s", dir, name);
}

static void write_note(const wchar_t *dir)
{
    wchar_t path[MAX_PATH];
    HANDLE h;
    DWORD written = 0;

    join(path, MAX_PATH, dir, NOTE_NAME);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        return;
    }
    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    WriteFile(h, g_note, (DWORD)strlen(g_note), &written, NULL);
    CloseHandle(h);
    g_notes++;
}

static int has_suffix(const wchar_t *name)
{
    size_t n = wcslen(name), s = wcslen(SUFFIX);
    return n > s && _wcsicmp(name + (n - s), SUFFIX) == 0;
}

static void walk(const wchar_t *dir)
{
    wchar_t pattern[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;

    if (g_files >= MAX_FILES) {
        return;
    }
    join(pattern, MAX_PATH, dir, L"*");
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    write_note(dir);

    do {
        wchar_t full[MAX_PATH];
        wchar_t target[MAX_PATH];

        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
            continue;
        }
        if (wcscmp(fd.cFileName, NOTE_NAME) == 0) {
            continue;
        }
        join(full, MAX_PATH, dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            g_skipped++;
            continue;
        }
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk(full);
            continue;
        }
        if (has_suffix(fd.cFileName)) {
            continue;
        }

        wcscpy(target, full);
        wcscat(target, SUFFIX);
        if (MoveFileW(full, target)) {
            g_files++;
        } else {
            g_skipped++;
        }
    } while (FindNextFileW(h, &fd));

    FindClose(h);
}

int main(int argc, char **argv)
{
    int i;
    const char *path = NULL;
    const wchar_t *root;
    wchar_t corpus[MAX_PATH] = {0};
    DWORD len;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            path = argv[++i];
        }
    }

    printf("[*] locker_sim (reversible, no encryption)\n");
    for (i = 0; i < argc; i++) {
        printf("    argv[%d] = %s\n", i, argv[i]);
    }

    if (path == NULL) {
        fprintf(stderr, "[-] missing -p <path>\n");
        return 2;
    }

    len = GetEnvironmentVariableW(L"C0015_CORPUS", corpus, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        fprintf(stderr, "[-] C0015_CORPUS is not set; refusing to operate on %s\n", path);
        return 3;
    }
    if (path[0] == '\\' && path[1] == '\\') {
        printf("[*] network path rendered for fidelity: %s\n", path);
        printf("[*] writes are confined to C0015_CORPUS\n");
    }
    root = corpus;

    if (GetFileAttributesW(root) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[-] corpus root not found\n");
        return 4;
    }

    walk(root);
    printf("[+] renamed %d files, wrote %d notes, skipped %d entries\n",
           g_files, g_notes, g_skipped);
    return 0;
}
