/*
 * common/iso_report.c — log_iso_report()
 *
 * Portable logging of ISO scan results from the global img_report.
 * Extracted from DisplayISOProps() in windows/rufus.c.
 *
 * Required externals (provided by each platform):
 *   RUFUS_IMG_REPORT  img_report         — populated by ExtractISO()
 *   const char*       old_c32_name[]     — defined in {linux,windows}/iso.c
 *   void uprintf(const char *fmt, ...)   — platform log function
 *   char* SizeToHumanReadable(uint64_t, BOOL, BOOL)
 *
 * Windows-only (guarded with #ifdef _WIN32):
 *   char* lmprintf(uint32_t msg_id, ...)
 *   void  Notification(UINT, const char*, const char*)
 *
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rufus.h"       /* RUFUS_IMG_REPORT, HAS_* macros, WINPE_*, NB_OLD_C32 */
#include "iso_report.h"
#ifdef _WIN32
#include "localization.h"  /* lmprintf() */
#include "resource.h"      /* MSG_xxx constants */
#endif

/* Helper: log a line if condition is true */
#define PRINT_ISO_PROP(b, ...) do { if (b) uprintf(__VA_ARGS__); } while (0)

/* Provided by {linux,windows}/iso.c */
extern const char* old_c32_name[NB_OLD_C32];

/* Provided by the platform stdio implementation */
extern char* SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units);

/* Global populated by ExtractISO() */
extern RUFUS_IMG_REPORT img_report;

void log_iso_report(void)
{
	static char inst_str[] = " [1/#]";
	int i;

	uprintf("ISO label: '%s'", img_report.label);

	if (img_report.win_version.major != 0) {
		if (img_report.win_version.minor == 0)
			uprintf("  Detected: Windows %d ISO (Build %d.%d)",
				img_report.win_version.major,
				img_report.win_version.build,
				img_report.win_version.revision);
		else
			uprintf("  Detected: Windows %d.%d ISO (Build %d.%d)",
				img_report.win_version.major,
				img_report.win_version.minor,
				img_report.win_version.build,
				img_report.win_version.revision);
	}

	if (img_report.projected_size > 0)
		uprintf("  Size: %s (Projected)",
			SizeToHumanReadable(img_report.projected_size, FALSE, FALSE));

	if (img_report.mismatch_size > 0) {
		uprintf("  ERROR: Detected that file on disk has been truncated by %s!",
			SizeToHumanReadable((uint64_t)img_report.mismatch_size, FALSE, FALSE));
#ifdef _WIN32
		Notification(MB_OK | MB_ICONWARNING, lmprintf(MSG_297),
			lmprintf(MSG_298,
				SizeToHumanReadable((uint64_t)img_report.mismatch_size, FALSE, FALSE)));
#endif
	} else if (img_report.mismatch_size < 0) {
		uprintf("  Note: File on disk is larger than reported ISO size by %s...",
			SizeToHumanReadable((uint64_t)(-img_report.mismatch_size), FALSE, FALSE));
	}

	PRINT_ISO_PROP(img_report.has_4GB_file,       "  Has a >4GB file");
	PRINT_ISO_PROP(img_report.has_long_filename,   "  Has a >64 chars filename");
	PRINT_ISO_PROP(img_report.has_deep_directories,"  Has a Rock Ridge deep directory");
	PRINT_ISO_PROP(HAS_SYSLINUX(img_report),       "  Uses: Syslinux/Isolinux v%s",
		img_report.sl_version_str);

	if (HAS_SYSLINUX(img_report) && (SL_MAJOR(img_report.sl_version) < 5)) {
		for (i = 0; i < NB_OLD_C32; i++)
			PRINT_ISO_PROP(img_report.has_old_c32[i],
				"    With an old %s", old_c32_name[i]);
	}

	PRINT_ISO_PROP(HAS_KOLIBRIOS(img_report), "  Uses: KolibriOS");
	PRINT_ISO_PROP(HAS_REACTOS(img_report),   "  Uses: ReactOS");
	PRINT_ISO_PROP(img_report.has_grub4dos,   "  Uses: Grub4DOS");
	PRINT_ISO_PROP(img_report.has_grub2,      "  Uses: GRUB2 (%s)", img_report.grub2_version);

	if (img_report.has_efi == 0x80)
		uprintf("  Uses: EFI (through '%s')", img_report.efi_img_path);
	else
		PRINT_ISO_PROP(img_report.has_efi,    "  Uses: EFI %s",
			HAS_WIN7_EFI(img_report) ? "(win7_x64)" : "");

	PRINT_ISO_PROP(HAS_BOOTMGR(img_report), "  Uses: Bootmgr (%s)",
		HAS_BOOTMGR_BIOS(img_report)
			? (HAS_BOOTMGR_EFI(img_report) ? "BIOS and UEFI" : "BIOS only")
			: "UEFI only");

	PRINT_ISO_PROP(HAS_WINPE(img_report), "  Uses: WinPE %s",
		img_report.uses_minint ? "(with /minint)" : "");

	if (HAS_WININST(img_report)) {
		inst_str[4] = '0' + img_report.wininst_index;
		uprintf("  Uses: Install.%s%s (version %d.%d.%d%s)",
			&img_report.wininst_path[0][strlen(img_report.wininst_path[0]) - 3],
			(img_report.wininst_index > 1) ? inst_str : "",
			(img_report.wininst_version >> 24) & 0xff,
			(img_report.wininst_version >> 16) & 0xff,
			(img_report.wininst_version >>  8) & 0xff,
			(img_report.wininst_version >= SPECIAL_WIM_VERSION) ? "+" : "");
	}

	if (img_report.needs_ntfs) {
		uprintf("  Note: This ISO uses symbolic links and was not designed to work without them.\r\n"
			"  Because of this, only NTFS will be allowed as the target file system.");
	} else {
		PRINT_ISO_PROP(img_report.has_symlinks,
			"  Note: This ISO uses symbolic links, which may not be replicated due to file system");
		PRINT_ISO_PROP((img_report.has_symlinks == SYMLINKS_RR),
			"  limitations. Because of this, some features from this image may not work...");
		PRINT_ISO_PROP((img_report.has_symlinks == SYMLINKS_UDF),
			"  limitations. Because of this, the size required for the target media may be much\r\n"
			"  larger than size of the ISO...");
	}
}
