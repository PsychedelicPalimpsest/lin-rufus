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
