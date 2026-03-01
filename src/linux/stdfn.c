/* Linux stub: stdfn.c - standard functions (stub for porting) */
#include "rufus.h"
#include <string.h>
#include <stdlib.h>


/* Hash tables */
BOOL htab_create(uint32_t nel, htab_table* htab) {
    (void)nel;
    if (!htab) return FALSE;
    memset(htab, 0, sizeof(*htab));
    return TRUE;
}
void htab_destroy(htab_table* htab) {
    if (!htab) return;
    free(htab->table);
    memset(htab, 0, sizeof(*htab));
}
uint32_t htab_hash(char* str, htab_table* htab) { (void)str;(void)htab; return 0; }

/* String arrays */
void StrArrayCreate(StrArray* arr, uint32_t initial_size) {
    if (!arr) return;
    arr->Max = initial_size;
    arr->Index = 0;
    arr->String = (char**)calloc(initial_size, sizeof(char*));
}
int32_t StrArrayAdd(StrArray* arr, const char* str, BOOL dup) {
    (void)dup;
    if (!arr || !str || arr->Index >= arr->Max) return -1;
    arr->String[arr->Index] = strdup(str);
    return (int32_t)arr->Index++;
}
int32_t StrArrayAddUnique(StrArray* arr, const char* str, BOOL dup) {
    int32_t i = StrArrayFind(arr, str);
    return (i >= 0) ? i : StrArrayAdd(arr, str, dup);
}
int32_t StrArrayFind(StrArray* arr, const char* str) {
    if (!arr || !str) return -1;
    for (uint32_t i = 0; i < arr->Index; i++)
        if (arr->String[i] && strcmp(arr->String[i], str) == 0) return (int32_t)i;
    return -1;
}
void StrArrayClear(StrArray* arr) {
    if (!arr) return;
    for (uint32_t i = 0; i < arr->Index; i++) { free(arr->String[i]); arr->String[i] = NULL; }
    arr->Index = 0;
}
void StrArrayDestroy(StrArray* arr) {
    StrArrayClear(arr);
    free(arr->String);
    arr->String = NULL;
    arr->Max = 0;
}

/* Misc stubs */
BOOL    isSMode(void)                                             { return FALSE; }
void    GetWindowsVersion(windows_version_t* wv)                  { if(wv) memset(wv,0,sizeof(*wv)); }
version_t* GetExecutableVersion(const char* path)                 { (void)path; return NULL; }BOOL    FileIO(enum file_io_type io_type, char* path, char** buf, DWORD* size) { (void)io_type;(void)path;(void)buf;(void)size; return FALSE; }
uint8_t* GetResource(HMODULE m, char* n, char* t, const char* d, DWORD* l, BOOL dup) { (void)m;(void)n;(void)t;(void)d;(void)l;(void)dup; return NULL; }
DWORD   GetResourceSize(HMODULE m, char* n, char* t, const char* d) { (void)m;(void)n;(void)t;(void)d; return 0; }
DWORD   RunCommandWithProgress(const char* cmd, const char* dir, BOOL log, int msg, const char* pat) { (void)cmd;(void)dir;(void)log;(void)msg;(void)pat; return 0; }
BOOL    IsFontAvailable(const char* fn)                           { (void)fn; return FALSE; }
DWORD WINAPI SetLGPThread(LPVOID param)                           { (void)param; return 0; }
BOOL    SetLGP(BOOL r, BOOL* ek, const char* p, const char* pol, DWORD v) { (void)r;(void)ek;(void)p;(void)pol;(void)v; return FALSE; }
BOOL    SetThreadAffinity(DWORD_PTR* ta, size_t n)               { (void)ta;(void)n; return TRUE; }
BOOL    IsCurrentProcessElevated(void)                            { return (geteuid() == 0); }
char*   ToLocaleName(DWORD lang_id)                              { (void)lang_id; return "en"; }
BOOL    SetPrivilege(HANDLE hToken, LPCWSTR priv, BOOL enable)   { (void)hToken;(void)priv;(void)enable; return FALSE; }
BOOL    MountRegistryHive(const HKEY k, const char* n, const char* p) { (void)k;(void)n;(void)p; return FALSE; }
BOOL    UnmountRegistryHive(const HKEY k, const char* n)         { (void)k;(void)n; return FALSE; }
BOOL    TakeOwnership(LPCSTR lpszOwnFile)                        { (void)lpszOwnFile; return FALSE; }

/* Hash function arrays */
