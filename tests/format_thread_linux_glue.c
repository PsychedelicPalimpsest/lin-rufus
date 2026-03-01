/*
 * format_thread_linux_glue.c — stubs for symbols needed by drive.c that
 * are not defined by test_format_thread_linux.c's own stub section.
 *
 * These symbols live in stdio.c and stdfn.c in production but are not
 * needed functionally by the format-thread tests.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

char *GuidToString(const GUID *guid, BOOL bDecorated)
{
    (void)guid; (void)bDecorated; return NULL;
}

BOOL CompareGUID(const GUID *g1, const GUID *g2)
{
    if (!g1 || !g2) return FALSE;
    return (__builtin_memcmp(g1, g2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}
