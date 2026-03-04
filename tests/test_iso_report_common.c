/*
 * test_iso_report_common.c — Cross-platform tests for log_iso_report()
 *
 * Tests the portable ISO scan results logger from src/common/iso_report.c.
 * These tests compile and run on both Linux (GCC) and Windows/Wine (MinGW).
 *
 * All stubs (uprintf/log-capture, SizeToHumanReadable, Notification, etc.)
 * are provided inline, so no separate glue file is needed.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "framework.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include "../src/windows/rufus.h"
#include "../src/windows/missing.h"
#include "../src/windows/localization.h"
#else
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#endif

#include "../src/common/iso_report.h"

/* ---- Globals required by iso_report.c --------------------------------- */

RUFUS_IMG_REPORT img_report = { 0 };
const char *old_c32_name[NB_OLD_C32] = OLD_C32_NAMES;

/* ---- Log capture infrastructure --------------------------------------- */

#define CAP_BUF_SZ 8192
static char g_captured[CAP_BUF_SZ];
static int  g_call_count;

static void (*g_log_handler)(const char *msg) = NULL;

void rufus_set_log_handler(void (*fn)(const char *msg))
{
	g_log_handler = fn;
}

void uprintf(const char *fmt, ...)
{
	char buf[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	buf[sizeof(buf) - 1] = '\0';
	if (g_log_handler) {
		g_log_handler(buf);
	}
}

void uprintfs(const char *s) { (void)s; }

static void capture_handler(const char *msg)
{
	size_t used = strlen(g_captured);
	size_t avail = CAP_BUF_SZ - used - 2;
	if (avail > 0) {
		strncat(g_captured, msg, avail);
		g_captured[used + avail] = '\0';
		if (strlen(g_captured) < CAP_BUF_SZ - 1)
			strcat(g_captured, "\n");
	}
	g_call_count++;
}

static void reset_capture(void)
{
	g_captured[0] = '\0';
	g_call_count  = 0;
	rufus_set_log_handler(capture_handler);
}

static void stop_capture(void)
{
	rufus_set_log_handler(NULL);
}

static int has(const char *needle)
{
	return strstr(g_captured, needle) != NULL;
}

/* ---- Additional stubs required by iso_report.c ----------------------- */

char *SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units)
{
	static char str[32];
	static const char *suffix[] = { "B", "KB", "MB", "GB", "TB", "PB" };
	double hr = (double)size;
	int s = 0;
	const double div = fake_units ? 1000.0 : 1024.0;
	(void)copy_to_log;
	while (s < 5 && hr >= div) { hr /= div; s++; }
	if (s == 0)
		snprintf(str, sizeof(str), "%d %s", (int)hr, suffix[s]);
	else
		snprintf(str, sizeof(str),
		         (hr - (int)hr < 0.05) ? "%.0f %s" : "%.1f %s",
		         hr, suffix[s]);
	return str;
}

char *lmprintf(uint32_t msg_id, ...) { (void)msg_id; return ""; }

/* NotificationEx: tracks calls so tests can assert on modal dialogs */
static int g_notification_calls = 0;

int NotificationEx(int type, const char *dont_display_setting,
                   const notification_info *more_info,
                   const char *title, const char *format, ...)
{
	(void)type; (void)dont_display_setting; (void)more_info;
	(void)title; (void)format;
	g_notification_calls++;
	return 0;
}

static void reset_notification_calls(void) { g_notification_calls = 0; }

/* ---- Helper ----------------------------------------------------------- */

static RUFUS_IMG_REPORT make_empty(void)
{
	RUFUS_IMG_REPORT r;
	memset(&r, 0, sizeof(r));
	return r;
}

#define MAKE_SL_VERSION(major, minor) ((uint16_t)(((major) << 8) | (minor)))

/* ======================================================================
 * Tests
 * ====================================================================== */

TEST(label_is_logged)
{
	img_report = make_empty();
	strncpy(img_report.label, "UBUNTU_22", sizeof(img_report.label) - 1);
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("UBUNTU_22"), "ISO label must appear in log");
}

TEST(projected_size_logged)
{
	img_report = make_empty();
	img_report.projected_size = (uint64_t)128 * 1024 * 1024;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Size:"), "projected size must be logged");
	CHECK_MSG(has("128"), "128 MiB must appear in output");
}

TEST(no_size_when_zero)
{
	img_report = make_empty();
	img_report.projected_size = 0;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(!has("Size:"), "no Size: line when projected_size == 0");
}

TEST(windows_version_with_minor)
{
	img_report = make_empty();
	img_report.win_version.major    = 10;
	img_report.win_version.minor    = 0;
	img_report.win_version.build    = 19041;
	img_report.win_version.revision = 1;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Windows 10"), "Windows major version must appear");
	CHECK_MSG(has("19041"), "build number must appear");
}

TEST(windows_version_no_minor)
{
	img_report = make_empty();
	img_report.win_version.major    = 11;
	img_report.win_version.minor    = 0;
	img_report.win_version.build    = 22621;
	img_report.win_version.revision = 0;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Windows 11"), "Windows 11 must appear");
	CHECK_MSG(has("22621"), "build number must appear");
}

TEST(mismatch_truncated_logged)
{
	img_report = make_empty();
	img_report.mismatch_size = (int64_t)512 * 1024;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("ERROR") || has("truncated"),
	          "truncation error must be logged");
}

TEST(mismatch_truncated_shows_notification)
{
	img_report = make_empty();
	img_report.mismatch_size = (int64_t)512 * 1024;
	reset_notification_calls();
	log_iso_report();
	CHECK_MSG(g_notification_calls > 0,
	          "truncated ISO must trigger a Notification dialog");
}

TEST(mismatch_larger_logged)
{
	img_report = make_empty();
	img_report.mismatch_size = -(int64_t)(512 * 1024);
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("larger"), "larger-than-ISO note must be logged");
}

TEST(mismatch_larger_no_notification)
{
	img_report = make_empty();
	img_report.mismatch_size = -(int64_t)(512 * 1024);
	reset_notification_calls();
	log_iso_report();
	CHECK_MSG(g_notification_calls == 0,
	          "larger-than-ISO must NOT trigger a Notification dialog");
}

TEST(has_4gb_file_logged)
{
	img_report = make_empty();
	img_report.has_4GB_file = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("4GB"), "4GB file flag must be logged");
}

TEST(has_long_filename_logged)
{
	img_report = make_empty();
	img_report.has_long_filename = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("64 chars"), "long filename flag must be logged");
}

TEST(has_deep_directories_logged)
{
	img_report = make_empty();
	img_report.has_deep_directories = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("deep directory") || has("Rock Ridge"),
	          "deep directories flag must be logged");
}

TEST(syslinux_version_logged)
{
	img_report = make_empty();
	img_report.sl_version = MAKE_SL_VERSION(6, 3);
	strncpy(img_report.sl_version_str, "6.03",
	        sizeof(img_report.sl_version_str) - 1);
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Syslinux") || has("Isolinux"),
	          "Syslinux must be logged");
	CHECK_MSG(has("6.03"), "Syslinux version string must appear");
}

TEST(old_c32_logged)
{
	img_report = make_empty();
	img_report.sl_version = MAKE_SL_VERSION(4, 7);
	strncpy(img_report.sl_version_str, "4.07",
	        sizeof(img_report.sl_version_str) - 1);
	img_report.has_old_c32[0] = TRUE;
	img_report.has_old_c32[1] = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("menu.c32"), "old menu.c32 must be logged for syslinux v4");
	CHECK_MSG(has("vesamenu.c32"),
	          "old vesamenu.c32 must be logged for syslinux v4");
}

TEST(old_c32_not_logged_syslinux_v5)
{
	img_report = make_empty();
	img_report.sl_version = MAKE_SL_VERSION(5, 0);
	strncpy(img_report.sl_version_str, "5.00",
	        sizeof(img_report.sl_version_str) - 1);
	img_report.has_old_c32[0] = TRUE;
	img_report.has_old_c32[1] = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(!has("menu.c32"), "old c32 NOT logged for syslinux v5+");
}

TEST(kolibrios_logged)
{
	img_report = make_empty();
	img_report.has_kolibrios = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("KolibriOS"), "KolibriOS must be logged");
}

TEST(reactos_logged)
{
	img_report = make_empty();
	strncpy(img_report.reactos_path, "/loader/setupldr.sys",
	        sizeof(img_report.reactos_path) - 1);
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("ReactOS"), "ReactOS must be logged");
}

TEST(grub4dos_logged)
{
	img_report = make_empty();
	img_report.has_grub4dos = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Grub4DOS"), "Grub4DOS must be logged");
}

TEST(grub2_version_logged)
{
	img_report = make_empty();
	img_report.has_grub2 = TRUE;
	strncpy(img_report.grub2_version, "2.12",
	        sizeof(img_report.grub2_version) - 1);
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("GRUB2"), "GRUB2 must be logged");
	CHECK_MSG(has("2.12"), "GRUB2 version must appear");
}

TEST(efi_via_img_logged)
{
	img_report = make_empty();
	img_report.has_efi = 0x80;
	strncpy(img_report.efi_img_path, "/efi/boot/bootx64.img",
	        sizeof(img_report.efi_img_path) - 1);
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("EFI"), "EFI must be logged");
	CHECK_MSG(has("bootx64.img"), "EFI img path must appear");
}

TEST(efi_standard_logged)
{
	img_report = make_empty();
	img_report.has_efi = 1;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("EFI"), "EFI must be logged");
}

TEST(bootmgr_bios_only_logged)
{
	img_report = make_empty();
	img_report.has_bootmgr     = TRUE;
	img_report.has_bootmgr_efi = FALSE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Bootmgr"), "Bootmgr must be logged");
	CHECK_MSG(has("BIOS only"), "BIOS only must appear");
}

TEST(bootmgr_efi_only_logged)
{
	img_report = make_empty();
	img_report.has_bootmgr     = FALSE;
	img_report.has_bootmgr_efi = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Bootmgr"), "Bootmgr must be logged");
	CHECK_MSG(has("UEFI only"), "UEFI only must appear");
}

TEST(bootmgr_bios_and_efi_logged)
{
	img_report = make_empty();
	img_report.has_bootmgr     = TRUE;
	img_report.has_bootmgr_efi = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Bootmgr"), "Bootmgr must be logged");
	CHECK_MSG(has("BIOS and UEFI"), "BIOS and UEFI must appear");
}

TEST(winpe_i386_logged)
{
	img_report = make_empty();
	img_report.winpe = WINPE_I386;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("WinPE"), "WinPE must be logged");
}

TEST(winpe_amd64_logged)
{
	img_report = make_empty();
	img_report.winpe = WINPE_AMD64;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("WinPE"), "WinPE must be logged");
}

TEST(winpe_minint_logged)
{
	img_report = make_empty();
	img_report.winpe = WINPE_MININT;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("WinPE"), "WinPE must be logged");
}

TEST(winpe_with_minint_suffix)
{
	img_report = make_empty();
	img_report.winpe       = WINPE_I386;
	img_report.uses_minint = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("WinPE"), "WinPE must be logged");
	CHECK_MSG(has("/minint"), "uses_minint must produce /minint in output");
}

TEST(wininst_esd_logged)
{
	img_report = make_empty();
	img_report.wininst_index   = 1;
	img_report.wininst_version = (10 << 24) | (0 << 16) | (19041 << 8);
	strncpy(img_report.wininst_path[0], "/sources/install.esd",
	        sizeof(img_report.wininst_path[0]) - 1);
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Install") || has("install"),
	          "Install file must be logged");
	CHECK_MSG(has("esd"), "install.esd extension must appear");
}

TEST(wininst_wim_logged)
{
	img_report = make_empty();
	img_report.wininst_index   = 1;
	img_report.wininst_version = (10 << 24) | (0 << 16) | (19041 << 8);
	strncpy(img_report.wininst_path[0], "/sources/install.wim",
	        sizeof(img_report.wininst_path[0]) - 1);
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("Install") || has("install"),
	          "Install file must be logged");
	CHECK_MSG(has("wim"), "install.wim extension must appear");
}

TEST(needs_ntfs_logged)
{
	img_report = make_empty();
	img_report.needs_ntfs = TRUE;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("ntfs") || has("NTFS"),
	          "NTFS requirement must be logged");
}

TEST(symlinks_rr_logged)
{
	img_report = make_empty();
	img_report.has_symlinks = SYMLINKS_RR;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("symbolic links") || has("symlink"),
	          "symlink note must be logged");
}

TEST(symlinks_udf_logged)
{
	img_report = make_empty();
	img_report.has_symlinks = SYMLINKS_UDF;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(has("symbolic links") || has("symlink"),
	          "UDF symlink note must be logged");
}

TEST(no_winpe_line_when_not_set)
{
	img_report = make_empty();
	img_report.winpe = 0;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(!has("WinPE"), "WinPE must NOT be logged when winpe==0");
}

TEST(no_wininst_when_not_set)
{
	img_report = make_empty();
	img_report.wininst_index = 0;
	reset_capture();
	log_iso_report();
	stop_capture();
	CHECK_MSG(!has("Install"), "wininst must NOT be logged when wininst_index==0");
}

int main(void)
{
	printf("=== iso_report common ===\n\n");

	RUN(label_is_logged);
	RUN(projected_size_logged);
	RUN(no_size_when_zero);
	RUN(windows_version_with_minor);
	RUN(windows_version_no_minor);
	RUN(mismatch_truncated_logged);
	RUN(mismatch_truncated_shows_notification);
	RUN(mismatch_larger_logged);
	RUN(mismatch_larger_no_notification);
	RUN(has_4gb_file_logged);
	RUN(has_long_filename_logged);
	RUN(has_deep_directories_logged);
	RUN(syslinux_version_logged);
	RUN(old_c32_logged);
	RUN(old_c32_not_logged_syslinux_v5);
	RUN(kolibrios_logged);
	RUN(reactos_logged);
	RUN(grub4dos_logged);
	RUN(grub2_version_logged);
	RUN(efi_via_img_logged);
	RUN(efi_standard_logged);
	RUN(bootmgr_bios_only_logged);
	RUN(bootmgr_efi_only_logged);
	RUN(bootmgr_bios_and_efi_logged);
	RUN(winpe_i386_logged);
	RUN(winpe_amd64_logged);
	RUN(winpe_minint_logged);
	RUN(winpe_with_minint_suffix);
	RUN(wininst_esd_logged);
	RUN(wininst_wim_logged);
	RUN(needs_ntfs_logged);
	RUN(symlinks_rr_logged);
	RUN(symlinks_udf_logged);
	RUN(no_winpe_line_when_not_set);
	RUN(no_wininst_when_not_set);

	TEST_RESULTS();
}
