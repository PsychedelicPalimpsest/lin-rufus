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
BOOL             quick_format   = TRUE;
BOOL             enable_bad_blocks = FALSE;
int              nb_passes_sel  = 0;

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
GUID *StringToGuid(const char *str)
{
    (void)str; return NULL;
}
DWORD RunCommandWithProgress(const char *cmd, const char *dir,
                             BOOL log, int msg, const char *pattern)
{
    (void)cmd; (void)dir; (void)log; (void)msg; (void)pattern;
    return ERROR_NOT_SUPPORTED;
}

/* ---- stdfn.c ---- */
DWORD _win_last_error = 0;
BOOL CompareGUID(const GUID *g1, const GUID *g2)
{
    if (!g1 || !g2) return FALSE;
    return (__builtin_memcmp(g1, g2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}
char *get_token_data_file_indexed(const char *token, const char *filename, int index)
{ (void)token; (void)filename; (void)index; return NULL; }

/* ---- badblocks.c ---- */
typedef struct { int bb_count; } badblocks_report;
BOOL BadBlocks(HANDLE hDrive, ULONGLONG disk_size, int nb_passes,
               int flash_type, badblocks_report *report, FILE *fd)
{ (void)hDrive; (void)disk_size; (void)nb_passes; (void)flash_type;
  (void)report; (void)fd; return TRUE; }

/* ---- stdlg.c ---- */
int NotificationEx(int type, const char *setting, const notification_info *info,
                   const char *title, const char *fmt, ...)
{ (void)type; (void)setting; (void)info; (void)title; (void)fmt; return IDOK; }

/* ---- syslinux.c ---- */
BOOL InstallSyslinux(DWORD drive_index, char drive_letter, int file_system)
{ (void)drive_index; (void)drive_letter; (void)file_system; return TRUE; }
