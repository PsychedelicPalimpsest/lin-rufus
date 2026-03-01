/*
 * verify_linux_glue.c — stubs for symbols needed by verify.c in the
 * test_verify_linux binary but not provided by the test file itself.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

/* stdfn.c symbols */
DWORD _win_last_error = 0;

BOOL CompareGUID(const GUID *g1, const GUID *g2)
{
    if (!g1 || !g2) return FALSE;
    return (__builtin_memcmp(g1, g2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}

/* parser.c / settings symbols needed by rufus.h includes */
windows_version_t WindowsVersion = { 0 };

char *get_token_data_file_indexed(const char *token, const char *filename,
                                   const int index)
{
    (void)token; (void)filename; (void)index; return NULL;
}

/* lmprintf: returns format string as-is (no real localization needed) */
char *lmprintf(int msg_id, ...)
{
    (void)msg_id; return (char*)"(verify error)";
}

/* uprintf: log to stderr (so test failures are visible) */
void uprintf(const char *fmt, ...)
{
    (void)fmt;
}
