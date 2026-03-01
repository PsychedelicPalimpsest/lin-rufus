/*
 * syslinux_linux_glue.c — Stubs for symbols used by drive.c and syslinux.c
 * that are normally provided by ui_gtk.c or other production files but are
 * not needed functionally by the syslinux unit tests.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

void UpdateProgress(int op, float pct)
{
    (void)op; (void)pct;
}

void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL f)
{
    (void)op; (void)msg; (void)cur; (void)tot; (void)f;
}

/* IsFileInDB / IsBufferInDB — stub: always return FALSE in tests */
BOOL IsFileInDB(const char *path)   { (void)path;  return FALSE; }
BOOL IsBufferInDB(const unsigned char *buf, const size_t len)
    { (void)buf; (void)len; return FALSE; }

void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s) { (void)s; }
void uprint_progress(uint64_t c, uint64_t m) { (void)c; (void)m; }

uint32_t read_file(const char *p, uint8_t **b)   { (void)p;(void)b; return 0; }
uint32_t write_file(const char *p, const uint8_t *b, const uint32_t s)
    { (void)p;(void)b;(void)s; return 0; }

char *GuidToString(const GUID *guid, BOOL bDecorated)
    { (void)guid; (void)bDecorated; return NULL; }

const char *WindowsErrorString(void) { return ""; }
BOOL WriteFileWithRetry(HANDLE h, const void *buf, DWORD size, DWORD *written, DWORD retries)
{
    (void)h; (void)buf; (void)size; (void)written; (void)retries;
    return FALSE;
}

/* ---- globals.c ---- */
char *ini_file = NULL;

/* ---- stdio.c ---- */
GUID *StringToGuid(const char *str) { (void)str; return NULL; }

