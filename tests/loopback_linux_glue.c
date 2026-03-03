/*
 * loopback_linux_glue.c — stubs for symbols needed by drive.c / format.c
 * that are not defined by test_loopback_linux.c's own inline stub section.
 *
 * Mirrors format_thread_linux_glue.c but for the loopback integration tests.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/windows/badblocks.h"

DWORD _win_last_error = 0;

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

/*
 * RunCommandWithProgress — for loopback tests we want external formatters
 * (NTFS, exFAT, UDF) to run normally so we forward to the real popen-based
 * implementation.  We only stub it here to satisfy the linker; the real
 * function is provided by format_ext_tools.c in FORMAT_THREAD_LINUX_SRC.
 * If that source is not present, this stub makes the linker happy with a
 * no-op.  Since FORMAT_THREAD_LINUX_SRC includes format_ext_tools.c, this
 * stub is intentionally a weak symbol fallback.
 */
__attribute__((weak))
DWORD RunCommandWithProgress(const char *cmd, const char *dir,
                              BOOL log, int msg, const char *pattern)
{
	(void)cmd; (void)dir; (void)log; (void)msg; (void)pattern;
	return 1;
}

BOOL InstallSyslinux(DWORD drive_index, char drive_letter, int file_system)
{
	(void)drive_index; (void)drive_letter; (void)file_system;
	return FALSE;
}

BOOL enable_bad_blocks = FALSE;
BOOL enable_verify_write = FALSE;
int  nb_passes_sel     = 0;

BOOL BadBlocks(HANDLE hPhysicalDrive, ULONGLONG disk_size, int nb_passes,
               int flash_type, badblocks_report *report, FILE *fd)
{
	(void)hPhysicalDrive; (void)disk_size; (void)nb_passes;
	(void)flash_type; (void)fd;
	if (report) {
		report->bb_count             = 0;
		report->num_read_errors      = 0;
		report->num_write_errors     = 0;
		report->num_corruption_errors = 0;
	}
	return TRUE;
}

int NotificationEx(int type, const char *dont_display_setting,
                   const notification_info *more_info, const char *title,
                   const char *format, ...)
{
	(void)type; (void)dont_display_setting; (void)more_info;
	(void)title; (void)format;
	return IDOK;
}

char *unattend_xml_path = NULL;
int   unattend_xml_flags = 0;

void wue_set_mount_path(const char *path) { (void)path; }

BOOL SetupWinPE(char drive_letter)
{ (void)drive_letter; return TRUE; }

BOOL SetupWinToGo(DWORD di, const char *dn, BOOL use_esp)
{ (void)di; (void)dn; (void)use_esp; return TRUE; }

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{
	(void)drive_letter; (void)flags; return TRUE;
}

BOOL ExtractDOS(const char *path) { (void)path; return TRUE; }

/* vhd.c/wimlib symbols needed when vhd.c is linked but globals.c/stdio.c are not */
BOOL   ignore_boot_marker = FALSE;
BOOL   has_ffu_support    = FALSE;
FILE*    fd_md5sum    = NULL;
uint64_t total_blocks = 0, extra_blocks = 0, nb_blocks = 0, last_nb_blocks = 0;
BOOL HashFile(unsigned type, const char* path, uint8_t* sum)
{ (void)type; (void)path; (void)sum; return FALSE; }
void wuprintf(const wchar_t *fmt, ...) { (void)fmt; }

/* ExtractISOFile stub — loopback tests use real ExtractISO (via iso.c) but
 * ExtractISOFile is not linked here; return 0 so format.c logs a warning. */
#include <stdint.h>
int64_t ExtractISOFile(const char *iso, const char *iso_file,
                       const char *dest_file, uint32_t attributes)
{ (void)iso; (void)iso_file; (void)dest_file; (void)attributes; return 0; }

/* UpdateMD5Sum stub — hash.c is not linked in loopback tests. */
void UpdateMD5Sum(const char *dest_dir, const char *md5sum_name_arg)
{ (void)dest_dir; (void)md5sum_name_arg; }

/* CopySKUSiPolicy stub — wue.c is not linked in loopback tests. */
BOOL CopySKUSiPolicy(const char *drive_name) { (void)drive_name; return FALSE; }
/* ExtractZip stub — stdio.c is not linked in loopback tests. */
BOOL ExtractZip(const char* src_zip, const char* dest_dir)
{ (void)src_zip; (void)dest_dir; return TRUE; }
/* RunNtfsFix stub — ntfsfix.c is not linked in loopback tests. */
BOOL RunNtfsFix(const char *partition_path) { (void)partition_path; return TRUE; }
