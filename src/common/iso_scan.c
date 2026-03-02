/*
 * iso_scan.c — Portable ISO buffer-scanning helpers
 *
 * Contains GetGrubVersion, GetGrubFs, and GetEfiBootInfo — pure buffer-
 * scanning routines shared between the Linux and Windows ISO scan paths.
 * No OS-specific I/O is performed here.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <string.h>
#include <ctype.h>

#include "rufus.h"
#include "iso_scan.h"

/*
 * GetGrubVersion — Scan a binary buffer for a GRUB version string and
 * update img_report.grub2_version if not already set.
 *
 * Handles both the canonical "GRUB  version %s" (double-space) and the
 * IBM/Red-Hat/Fedora "GRUB version %s" (single-space) variants.
 * A version beginning with '0' is cleared (Kaspersky false-positive guard).
 * Non-standard suffixes ("-nonstandard", "-gdie", label) are appended as needed.
 */
void GetGrubVersion(char* buf, size_t buf_size, const char* source)
{
	const char* grub_version_str[] = { "GRUB  version %s", "GRUB version %s" };
	const char* grub_debug_is_enabled_str = "grub_debug_is_enabled";
	const size_t max_string_size = 32;
	char grub_version[192] = { 0 };
	size_t i, j;
	BOOL has_grub_debug_is_enabled = FALSE;

	if (buf_size > max_string_size) {
		for (i = 0; i < buf_size - max_string_size; i++) {
			for (j = 0; j < ARRAYSIZE(grub_version_str); j++) {
				size_t fmt_len    = strlen(grub_version_str[j]);
				/* strip the trailing " %s" (3 chars) to get actual prefix */
				size_t prefix_len = fmt_len - 3;
				if (memcmp(&buf[i], grub_version_str[j], prefix_len) == 0) {
					/* skip past prefix + one char (the space before version) */
					if (buf[i + prefix_len + 1] == '\0')
						i++;
					safe_strcpy(grub_version, sizeof(grub_version),
					            &buf[i + prefix_len + 1]);
				}
			}
			if (memcmp(&buf[i], grub_debug_is_enabled_str,
			           strlen(grub_debug_is_enabled_str)) == 0)
				has_grub_debug_is_enabled = TRUE;
		}
	}

	uprintf("  Detected GRUB version: %s (from '%s')", grub_version, source);

	if (img_report.grub2_version[0] != 0)
		return;

	safe_strcpy(img_report.grub2_version, sizeof(img_report.grub2_version),
	            grub_version);

	/* Kaspersky false-positive: versions starting with '0' are spurious */
	if (img_report.grub2_version[0] == '0')
		img_report.grub2_version[0] = 0;

	if (img_report.grub2_version[0] != 0) {
		BOOL append_label = (safe_strcmp(img_report.grub2_version, "2.06") == 0);
		if ((img_report.has_grub2 & 0x7f) > 1)
			safe_strcat(img_report.grub2_version,
			            sizeof(img_report.grub2_version), "-nonstandard");
		if (has_grub_debug_is_enabled)
			safe_strcat(img_report.grub2_version,
			            sizeof(img_report.grub2_version), "-gdie");
		if (append_label) {
			safe_strcat(img_report.grub2_version,
			            sizeof(img_report.grub2_version), "-");
			safe_strcat(img_report.grub2_version,
			            sizeof(img_report.grub2_version), img_report.label);
		}
		sanitize_label(img_report.grub2_version);
	}
}

/*
 * GetGrubFs — Scan a binary buffer for GRUB filesystem module entries
 * ("fshelp\0<name>\0") and add unique filesystem names to @filesystems.
 */
void GetGrubFs(char* buf, size_t buf_size, StrArray* filesystems)
{
	const char* grub_fshelp_str = "fshelp";
	const size_t max_string_size = 32;
	const size_t fshelp_len = 7; /* strlen("fshelp") + 1 for the NUL separator */
	size_t i, fs_len;

	if (!filesystems)
		return;

	if (buf_size > max_string_size) {
		for (i = 0; i < buf_size - max_string_size; i++) {
			if (memcmp(&buf[i], grub_fshelp_str, fshelp_len) == 0) {
				const char* fs_name = &buf[i + fshelp_len];
				fs_len = safe_strlen(fs_name);
				if (fs_len > 0 && fs_len < 12)
					StrArrayAddUnique(filesystems, fs_name, TRUE);
			}
		}
	}
}

/*
 * GetEfiBootInfo — Scan a binary buffer for known EFI bootloader signature
 * strings and log the detected version via uprintf.
 */
void GetEfiBootInfo(char* buf, size_t buf_size, const char* source)
{
	const struct { const char* label; const char* search_string; } boot_info[] = {
		{ "Shim",         "UEFI SHIM\n$Version: " },
		{ "systemd-boot", "#### LoaderInfo: systemd-boot " },
	};
	const size_t max_string_size = 64;
	size_t i, j, k;

	if (buf_size > max_string_size) {
		for (i = 0; i < buf_size - max_string_size; i++) {
			for (j = 0; j < ARRAYSIZE(boot_info); j++) {
				size_t slen = strlen(boot_info[j].search_string);
				if (memcmp(&buf[i], boot_info[j].search_string, slen) == 0) {
					i += slen;
					for (k = 0; k < 32 && i + k < buf_size - 1 &&
					     !isspace((unsigned char)buf[i + k]); k++);
					buf[i + k] = '\0';
					uprintf("  Detected %s version: %s (from '%s')",
					        boot_info[j].label, &buf[i], source);
					return;
				}
			}
		}
	}
}
