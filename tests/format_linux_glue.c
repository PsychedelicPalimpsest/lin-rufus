/*
 * format_linux_glue.c — stubs for symbols needed by format.c and drive.c
 * that are not defined by test_format_linux.c's own stub section.
 *
 * These symbols come from globals.c, ui.c, iso.c, stdfn.c, and stdio.c
 * in production but are not needed functionally by the format tests.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

/* ---- globals.c ---- */
RUFUS_IMG_REPORT img_report  = { 0 };
BOOL             use_rufus_mbr = TRUE;

/* ---- ui.c ---- */
void UpdateProgress(int op, float percent)
{
    (void)op; (void)percent;
}

/* ---- iso.c ---- */
BOOL ExtractISO(const char *src, const char *dst, BOOL scan_only)
{
    (void)src; (void)dst; (void)scan_only; return TRUE;
}

/* ---- stdio.c ---- */
char *GuidToString(const GUID *guid, BOOL bDecorated)
{
    (void)guid; (void)bDecorated; return NULL;
}

/* ---- stdfn.c ---- */
BOOL CompareGUID(const GUID *g1, const GUID *g2)
{
    if (!g1 || !g2) return FALSE;
    return (__builtin_memcmp(g1, g2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}
