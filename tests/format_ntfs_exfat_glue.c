/*
 * format_ntfs_exfat_glue.c — stubs for test_format_ntfs_exfat_linux
 *
 * Provides RunCommandWithProgress, which wraps system() so external tools
 * (mkntfs, mkfs.exfat) can actually be called in tests.
 * All other stubs are defined directly in the test file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

/* ---- stdio.c: RunCommandWithProgress ----
 *
 * For tests we just call system() directly and return the exit code.
 * This exercises the external tool without the pipe/fork infrastructure. */
DWORD RunCommandWithProgress(const char *cmd, const char *dir,
                              BOOL log, int msg, const char *pattern)
{
    (void)dir; (void)log; (void)msg; (void)pattern;
    if (!cmd) return (DWORD)-1;
    int rc = system(cmd);
    if (rc < 0) return (DWORD)1;
    /* non-zero exit → failure */
    return (DWORD)(rc == 0 ? 0 : 1);
}

/* ---- format.c needs these ---- */
void UpdateProgress(int op, float percent) { (void)op; (void)percent; }
BOOL ExtractISO(const char *src, const char *dst, BOOL scan_only)
{ (void)src; (void)dst; (void)scan_only; return TRUE; }
BOOL InstallSyslinux(DWORD di, char dl, int fs)
{ (void)di; (void)dl; (void)fs; return FALSE; }

/* ---- settings.h / drive.c ---- */
char *get_token_data_file_indexed(const char *token, const char *filename,
                                   const int index)
{ (void)token; (void)filename; (void)index; return NULL; }
GUID *StringToGuid(const char *str) { (void)str; return NULL; }
