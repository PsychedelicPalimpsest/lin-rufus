/*
 * e2e_linux_glue.c — stubs for symbols needed by the E2E tests that are not
 * provided by FORMAT_THREAD_LINUX_SRC, DOS_LINUX_SRC, or freedos_data.c.
 *
 * Unlike loopback_linux_glue.c / format_thread_linux_glue.c, this file MUST
 * NOT define symbols that are already supplied by:
 *   - globals.c    (_win_last_error, WindowsVersion, all bool/int globals)
 *   - stdfn.c      (GuidToString/StringToGuid via common/stdfn.c, CompareGUID,
 *                   get_token_data_file_indexed, GetResource)
 *   - stdio.c      (uprintf, WindowsErrorString, SizeToHumanReadable, …)
 *   - format_ext_tools.c  (RunCommandWithProgress)
 */
#include <stdarg.h>
#include <stdint.h>
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/windows/localization.h"
#include "../src/windows/badblocks.h"

/* ------------------------------------------------------------------ */
/* Progress / log stubs                                                */
/* ------------------------------------------------------------------ */

char *lmprintf(uint32_t msg_id, ...) { (void)msg_id; return (char *)""; }
void UpdateProgress(int op, float percent) { (void)op; (void)percent; }
void _UpdateProgressWithInfo(int op, int msg, uint64_t processed,
                             uint64_t total, BOOL force)
{
	(void)op; (void)msg; (void)processed; (void)total; (void)force;
}

/* ------------------------------------------------------------------ */
/* InstallSyslinux stub                                                */
/* ------------------------------------------------------------------ */

BOOL InstallSyslinux(DWORD drive_index, char drive_letter, int file_system)
{
	(void)drive_index; (void)drive_letter; (void)file_system;
	return FALSE;
}

/* ------------------------------------------------------------------ */
/* BadBlocks stub                                                      */
/* ------------------------------------------------------------------ */

BOOL BadBlocks(HANDLE hPhysicalDrive, ULONGLONG disk_size, int nb_passes,
               int flash_type, badblocks_report *report, FILE *fd)
{
	(void)hPhysicalDrive; (void)disk_size; (void)nb_passes;
	(void)flash_type; (void)fd;
	if (report) {
		report->bb_count              = 0;
		report->num_read_errors       = 0;
		report->num_write_errors      = 0;
		report->num_corruption_errors = 0;
	}
	return TRUE;
}

/* ------------------------------------------------------------------ */
/* NotificationEx stub — always OK                                     */
/* ------------------------------------------------------------------ */

int NotificationEx(int type, const char *dont_display_setting,
                   const notification_info *more_info, const char *title,
                   const char *format, ...)
{
	(void)type; (void)dont_display_setting; (void)more_info;
	(void)title; (void)format;
	return IDOK;
}

/* ------------------------------------------------------------------ */
/* WUE stubs (wue.c not linked in tests)                               */
/* ------------------------------------------------------------------ */

int  unattend_xml_flags = 0;
int  wintogo_index      = -1;
int  wininst_index      = 0;
int  unattend_xml_mask  = 0;
char *unattend_xml_path = NULL;
char unattend_username[64] = "";

void wue_set_mount_path(const char *path) { (void)path; }

BOOL SetupWinPE(char drive_letter)
{ (void)drive_letter; return TRUE; }

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{ (void)drive_letter; (void)flags; return TRUE; }

BOOL SetupWinToGo(DWORD di, const char *dn, BOOL use_esp)
{ (void)di; (void)dn; (void)use_esp; return TRUE; }

/* ------------------------------------------------------------------ */
/* ExtractISO stub — only called for BT_IMAGE + non-write_as_image;    */
/* E2E tests that exercise ExtractISO are out of scope here.           */
/* ------------------------------------------------------------------ */

BOOL ExtractISO(const char *src, const char *dst, BOOL scan_only)
{
	(void)src; (void)dst; (void)scan_only;
	return TRUE;
}

/* ------------------------------------------------------------------ */
/* Misc / alert stubs                                                  */
/* ------------------------------------------------------------------ */

void alert_set_hook(BOOL (*hook)(int type)) { (void)hook; }
void alert_clear_hook(void) {}
void set_preselected_fs(int fs) { (void)fs; }

/* ------------------------------------------------------------------ */
/* UI / messaging stubs                                                */
/* ------------------------------------------------------------------ */

#include <stdarg.h>
void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration,
                     int msg_id, ...)
{
	(void)info; (void)debug; (void)duration; (void)msg_id;
}

void InitProgress(BOOL bOnlyFormat) { (void)bOnlyFormat; }

LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return 0; }

BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return FALSE; }

LONG GetEntryWidth(HWND h, const char *e) { (void)h; (void)e; return 0; }

/* iso.c/hash.c symbols needed when vhd.c is linked but iso.c is not */
FILE*    fd_md5sum    = NULL;
uint64_t total_blocks = 0, extra_blocks = 0, nb_blocks = 0, last_nb_blocks = 0;
BOOL HashFile(unsigned type, const char* path, uint8_t* sum)
{ (void)type; (void)path; (void)sum; return FALSE; }

/* RunNtfsFix stub — ntfsfix.c is not linked in e2e tests. */
BOOL RunNtfsFix(const char *partition_path) { (void)partition_path; return TRUE; }
/* SetAutorun stub — icon.c is not linked in these tests. */
BOOL SetAutorun(const char *path) { (void)path; return TRUE; }
BOOL ExtractAppIcon(const char *path, BOOL bSilent) { (void)path; (void)bSilent; return FALSE; }

/* ExtractISOFile stub — iso.c is not linked in e2e tests. */
int64_t ExtractISOFile(const char *iso, const char *iso_file,
                       const char *dest_file, DWORD attributes)
{ (void)iso; (void)iso_file; (void)dest_file; (void)attributes; return 0; }

/* UpdateMD5Sum stub — hash.c is not linked in e2e tests. */
void UpdateMD5Sum(const char *dest_dir, const char *md5sum_name_arg)
{ (void)dest_dir; (void)md5sum_name_arg; }

/* CopySKUSiPolicy stub — wue.c is not linked in e2e tests. */
BOOL CopySKUSiPolicy(const char *drive_name) { (void)drive_name; return FALSE; }

/* md5sum_name global — defined in iso.c which is not linked in e2e tests. */
const char *md5sum_name[2] = { "md5sum.txt", "md5sum.txt~rufus" };

/* ImageScanThread stub — image_scan.c is not linked in E2E tests.
 * Sets img_report.is_iso via the existing ExtractISO stub so that FormatThread
 * sees a valid ISO report when cli_run() calls ImageScanThread before format. */
DWORD WINAPI ImageScanThread(LPVOID param)
{
	(void)param;
	if (image_path != NULL) {
		memset(&img_report, 0, sizeof(img_report));
		img_report.is_iso = (BOOLEAN)ExtractISO(image_path, "", TRUE);
	}
	ExitThread(0);
}

/* GetDevices stub — dev.c is not in E2E_LINUX_SRC but cli.c calls it for
 * --list-devices.  rufus_drive[] comes from globals.c already. */
BOOL GetDevices(DWORD devnum) { (void)devnum; return FALSE; }

/* Localization stubs — cli.c calls these for --locale; the e2e tests
 * exercise FormatThread, not locale selection, so no-op stubs suffice.
 * find_loc_file() is defined in src/linux/rufus.c which is not linked here.
 * _init_localization(), get_locale_from_name() are in src/common/localization.c.
 * get_supported_locales(), get_loc_data_file() are in src/common/parser.c. */
const char *find_loc_file(void) { return NULL; }
void _init_localization(BOOL reinit) { (void)reinit; }
BOOL get_supported_locales(const char *filename) { (void)filename; return FALSE; }
loc_cmd *get_locale_from_name(char *locale_name, BOOL fallback)
    { (void)locale_name; (void)fallback; return NULL; }
BOOL get_loc_data_file(const char *filename, loc_cmd *lcmd)
    { (void)filename; (void)lcmd; return FALSE; }
