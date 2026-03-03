/*
 * badblocks_integration_glue.c
 *
 * Stubs needed by the format.c / drive.c compilation unit in the
 * test_badblocks_integration_linux binary.  The symbols that are
 * test-specific (BadBlocks, NotificationEx, enable_bad_blocks,
 * nb_passes_sel, InstallSyslinux, RunCommandWithProgress) are
 * defined directly in test_badblocks_integration_linux.c.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

char *GuidToString(const GUID *guid, BOOL bDecorated)
{
    (void)guid; (void)bDecorated; return NULL;
}

GUID *StringToGuid(const char *str)
{
    (void)str; return NULL;
}

BOOL CompareGUID(const GUID *g1, const GUID *g2)
{
    if (!g1 || !g2) return FALSE;
    return (__builtin_memcmp(g1, g2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}

windows_version_t WindowsVersion = { 0 };

char *get_token_data_file_indexed(const char *token, const char *filename,
                                   const int index)
{
    (void)token; (void)filename; (void)index; return NULL;
}

/* _win_last_error — owned by stdfn.c in production */
DWORD _win_last_error = 0;

/* WUE stubs for format.c */
char *unattend_xml_path = NULL;
int   unattend_xml_flags = 0;

/* Format-thread globals not defined in test_badblocks_integration_linux.c */
BOOL use_old_bios_fixes = FALSE;
BOOL use_extended_label = FALSE;

void wue_set_mount_path(const char *path) { (void)path; }

BOOL SetupWinPE(char drive_letter)
{ (void)drive_letter; return TRUE; }

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{
    (void)drive_letter; (void)flags; return TRUE;
}

BOOL ExtractDOS(const char *path) { (void)path; return TRUE; }

/* RunNtfsFix stub */
BOOL RunNtfsFix(const char *partition_path) { (void)partition_path; return TRUE; }
/* SetAutorun stub — icon.c is not linked in these tests. */
BOOL SetAutorun(const char *path) { (void)path; return TRUE; }
BOOL ExtractAppIcon(const char *path, BOOL bSilent) { (void)path; (void)bSilent; return FALSE; }

/* ExtractISOFile stub — iso.c is not linked in badblocks integration tests. */
int64_t ExtractISOFile(const char *iso, const char *iso_file,
                       const char *dest_file, DWORD attributes)
{ (void)iso; (void)iso_file; (void)dest_file; (void)attributes; return 0; }

/* UpdateMD5Sum stub — hash.c is not linked. */
void UpdateMD5Sum(const char *dest_dir, const char *md5sum_name_arg)
{ (void)dest_dir; (void)md5sum_name_arg; }

/* CopySKUSiPolicy stub — wue.c is not linked. */
BOOL CopySKUSiPolicy(const char *drive_name) { (void)drive_name; return FALSE; }

/* SetupWinToGo stub */
BOOL SetupWinToGo(DWORD di, const char *dn, BOOL use_esp)
{ (void)di; (void)dn; (void)use_esp; return TRUE; }

/* ExtractZip stub — stdio.c is not linked here. */
BOOL ExtractZip(const char *src, const char *dst)
{ (void)src; (void)dst; return TRUE; }

/* VHD globals needed by vhd.c */
BOOL has_ffu_support = FALSE;
BOOL ignore_boot_marker = FALSE;

/* hash.c globals needed by vhd.c */
FILE*    fd_md5sum    = NULL;
uint64_t total_blocks = 0, extra_blocks = 0, nb_blocks = 0, last_nb_blocks = 0;
BOOL HashFile(unsigned type, const char* path, uint8_t* sum)
{ (void)type; (void)path; (void)sum; return FALSE; }

/* wuprintf stub — stdio.c is not linked in badblocks integration tests. */
#include <stdarg.h>
#include <wchar.h>
void wuprintf(const wchar_t *fmt, ...) { (void)fmt; }
