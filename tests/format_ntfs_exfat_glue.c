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

/* ---- globals added in bad-blocks integration (not in test file stubs) ---- */
BOOL enable_bad_blocks = FALSE;
int  nb_passes_sel     = 0;
DWORD _win_last_error  = 0;

/* ---- format.c needs these ---- */
void UpdateProgress(int op, float percent) { (void)op; (void)percent; }
BOOL ExtractISO(const char *src, const char *dst, BOOL scan_only)
{ (void)src; (void)dst; (void)scan_only; return TRUE; }
BOOL InstallSyslinux(DWORD di, char dl, int fs)
{ (void)di; (void)dl; (void)fs; return FALSE; }

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

/* ---- settings.h / drive.c ---- */
char *get_token_data_file_indexed(const char *token, const char *filename,
                                   int index)
{ (void)token; (void)filename; (void)index; return NULL; }
GUID *StringToGuid(const char *str) { (void)str; return NULL; }

/* ---- verify.c / wue.c stubs ---- */
BOOL enable_verify_write = FALSE;
uint64_t persistence_size = 0;
BOOL verify_write_pass(const char *source_path, int device_fd, uint64_t written_size)
{ (void)source_path; (void)device_fd; (void)written_size; return TRUE; }
int  unattend_xml_flags = 0;
char *unattend_xml_path = NULL;
void wue_set_mount_path(const char *path) { (void)path; }
BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{ (void)drive_letter; (void)flags; return FALSE; }
