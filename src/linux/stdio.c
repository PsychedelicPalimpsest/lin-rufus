/* Linux stub: stdio.c - I/O utilities (stub for porting) */
#include "rufus.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>


void uprintf(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void wuprintf(const wchar_t* format, ...) {
    va_list ap;
    va_start(ap, format);
    vfwprintf(stderr, format, ap);
    va_end(ap);
    fputwc(L'\n', stderr);
}

void uprintfs(const char* str) { if(str) fputs(str, stderr); }

void uprint_progress(uint64_t cur, uint64_t max) { (void)cur;(void)max; }

uint32_t read_file(const char* path, uint8_t** buf) {
    FILE* f = fopen(path, "rb");
    if (!f || !buf) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    *buf = (uint8_t*)malloc(sz);
    if (!*buf) { fclose(f); return 0; }
    uint32_t r = (uint32_t)fread(*buf, 1, sz, f);
    fclose(f);
    return r;
}

uint32_t write_file(const char* path, const uint8_t* buf, const uint32_t size) {
    FILE* f = fopen(path, "wb");
    if (!f || !buf) return 0;
    uint32_t w = (uint32_t)fwrite(buf, 1, size, f);
    fclose(f);
    return w;
}

char* _printbits(size_t const size, void const* const ptr, int lz) {
    (void)size;(void)ptr;(void)lz;
    return NULL;
}

void DumpBufferHex(void* buf, size_t size) { (void)buf;(void)size; }

const char* WindowsErrorString(void) { return strerror(errno); }
const char* _StrError(DWORD code)    { return strerror((int)code); }
const char* StrError(DWORD code, BOOL use_default) { (void)use_default; return strerror((int)code); }

DWORD WINAPI CreateFileWithTimeoutThread(void* params)            { (void)params; return 0; }
DWORD WaitForSingleObjectWithMessages(HANDLE h, DWORD ms)         { (void)h;(void)ms; return 0; }
BOOL  CALLBACK EnumSymProc(void* info, ULONG sz, PVOID ctx)       { (void)info;(void)sz;(void)ctx; return FALSE; }
uint32_t ResolveDllAddress(dll_resolver_t* resolver)                        { (void)resolver; return 0; }
BOOL  ExtractZip(const char* src, const char* dst)                { (void)src;(void)dst; return FALSE; }
DWORD ListDirectoryContent(StrArray* arr, char* dir, uint8_t type) { (void)arr;(void)dir;(void)type; return 0; }
BOOL  WriteFileWithRetry(HANDLE h, const void* buf, DWORD n, DWORD* written, DWORD retries) {
    (void)h;(void)buf;(void)n;(void)written;(void)retries;
    return FALSE;
}

char* SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units)
{
    static char str[32];
    static const char* suffix[] = { "B", "KB", "MB", "GB", "TB", "PB" };
    double hr = (double)size;
    int s = 0;
    const double div = fake_units ? 1000.0 : 1024.0;
    (void)copy_to_log;
    while (s < 5 && hr >= div) { hr /= div; s++; }
    if (s == 0)
        snprintf(str, sizeof(str), "%d %s", (int)hr, suffix[s]);
    else
        snprintf(str, sizeof(str), (hr - (int)hr < 0.05) ? "%.0f %s" : "%.1f %s", hr, suffix[s]);
    return str;
}
