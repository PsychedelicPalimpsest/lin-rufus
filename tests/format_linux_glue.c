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
BOOL             enable_verify_write = FALSE;
DWORD            selected_cluster_size = 0;
BOOL             use_old_bios_fixes = FALSE;
BOOL             use_extended_label = FALSE;
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

/* ---- verify.c ---- */
BOOL verify_write_pass(const char *source_path, int device_fd, uint64_t written_size)
{ (void)source_path; (void)device_fd; (void)written_size; return TRUE; }

/* ---- wue.c globals / functions ---- */
int  unattend_xml_flags = 0;
int  wintogo_index = -1;
char *unattend_xml_path = NULL;
void wue_set_mount_path(const char *path) { (void)path; }
BOOL SetupWinPE(char drive_letter)
{ (void)drive_letter; return TRUE; }
BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{ (void)drive_letter; (void)flags; return FALSE; }
BOOL SetupWinToGo(DWORD di, const char *dn, BOOL use_esp)
{ (void)di; (void)dn; (void)use_esp; return TRUE; }

BOOL ExtractDOS(const char *path) { (void)path; return TRUE; }

/* vhd.c symbols needed when vhd.c is linked into format tests */
BOOL   ignore_boot_marker = FALSE;
BOOL   has_ffu_support    = FALSE;
FILE*    fd_md5sum    = NULL;
uint64_t total_blocks = 0, extra_blocks = 0, nb_blocks = 0, last_nb_blocks = 0;
BOOL HashFile(unsigned type, const char* path, uint8_t* sum)
{ (void)type; (void)path; (void)sum; return FALSE; }
void wuprintf(const wchar_t *fmt, ...) { (void)fmt; }

/* ExtractISOFile stub — format_linux tests don't exercise KolibriOS loader
 * installation; return 0 (not found) so format.c just logs a warning. */
#include <stdint.h>
int64_t ExtractISOFile(const char *iso, const char *iso_file,
                       const char *dest_file, uint32_t attributes)
{ (void)iso; (void)iso_file; (void)dest_file; (void)attributes; return 0; }

/* UpdateMD5Sum stub — hash.c is not linked in format_linux tests. */
void UpdateMD5Sum(const char *dest_dir, const char *md5sum_name_arg)
{ (void)dest_dir; (void)md5sum_name_arg; }

/* CopySKUSiPolicy stub — wue.c is not linked in format_linux tests. */
BOOL CopySKUSiPolicy(const char *drive_name) { (void)drive_name; return FALSE; }
/* ExtractZip stub — stdio.c is not linked in format_linux tests. */
BOOL ExtractZip(const char* src_zip, const char* dest_dir)
{ (void)src_zip; (void)dest_dir; return TRUE; }
/* SetAutorun stub — icon.c is not linked in format_linux tests. */
BOOL SetAutorun(const char *path) { (void)path; return TRUE; }
BOOL ExtractAppIcon(const char *path, BOOL bSilent) { (void)path; (void)bSilent; return FALSE; }
