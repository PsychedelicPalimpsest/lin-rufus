/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: image_scan.c – ImageScanThread
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * ImageScanThread — scans an image file and populates img_report.
 *
 * On Windows this logic lives in rufus.c.  On Linux we keep it in its own
 * translation unit so it can be compiled and tested independently.
 *
 * Flow:
 *   1. Validate image_path (early exit if NULL).
 *   2. Zero img_report.
 *   3. Call ExtractISO(…, TRUE)  – scan mode: populate img_report.is_iso,
 *      img_report.label, img_report.image_size, bootloader flags, etc.
 *   4. Call IsBootableImage() to detect dd-writable disk images.
 *   5. If it is a Windows image, call PopulateWindowsVersion().
 *   6. Post UM_IMAGE_SCANNED so the GTK main thread can refresh the UI.
 */

#include <string.h>

#include "rufus.h"
#include "missing.h"
#include "resource.h"

/* ---- externs provided by other translation units ---- */
extern char             *image_path;
extern RUFUS_IMG_REPORT  img_report;
extern HWND              hMainDialog;

/* ---- forward declarations ---- */
BOOL     ExtractISO(const char* src_iso, const char* dest_dir, BOOL scan);
int8_t   IsBootableImage(const char* path);
BOOL     PopulateWindowsVersion(void);
uint32_t ReadISOFileToBuffer(const char* iso, const char* iso_file, uint8_t** buf);
BOOL     IsSignedBySecureBootAuthority(uint8_t* buf, uint32_t len);
int      IsBootloaderRevoked(uint8_t* buf, uint32_t len);

/* -----------------------------------------------------------------------
 * GetBootladerInfo
 *
 * Analyses the UEFI bootloaders listed in img_report.efi_boot_entry[]:
 *   - Reads each EFI binary from the ISO.
 *   - Checks whether it is signed by a Secure Boot authority.
 *   - Checks whether it has been revoked (DBX / SBAT / SVN).
 *   - Updates img_report.has_secureboot_bootloader:
 *       bit 0 → at least one bootloader is signed by a SB authority
 *       bit r → bootloader has been revoked (r = IsBootloaderRevoked() result)
 *
 * Matches the Windows implementation in rufus.c::GetBootladerInfo().
 * ----------------------------------------------------------------------- */
void GetBootladerInfo(void)
{
	static const char *revocation_type[] = {
		"UEFI DBX", "Windows SSP", "Linux SBAT", "Windows SVN", "Cert DBX"
	};
	BOOL     sb_signed;
	uint32_t i, len;
	int      r;
	uint8_t *buf = NULL;

	if (!IS_EFI_BOOTABLE(img_report))
		return;

	PrintStatus(0, MSG_351);
	uprintf("UEFI bootloaders analysis:");

	for (i = 0; i < ARRAYSIZE(img_report.efi_boot_entry)
	     && img_report.efi_boot_entry[i].path[0] != '\0'; i++) {

		len = ReadISOFileToBuffer(image_path, img_report.efi_boot_entry[i].path, &buf);
		if (len == 0) {
			uprintf("  Warning: Failed to extract '%s' to check for UEFI Secure Boot info",
			        img_report.efi_boot_entry[i].path);
			continue;
		}

		sb_signed = IsSignedBySecureBootAuthority(buf, len);
		if (sb_signed)
			img_report.has_secureboot_bootloader |= 1;

		uprintf("  • %s%s", img_report.efi_boot_entry[i].path, sb_signed ? "*" : "");

		r = IsBootloaderRevoked(buf, len);
		if (r > 0) {
			uprintf("  WARNING: '%s' has been revoked by %s",
			        img_report.efi_boot_entry[i].path,
			        (r - 1) < (int)ARRAYSIZE(revocation_type)
			          ? revocation_type[r - 1] : "unknown authority");
			img_report.has_secureboot_bootloader |= (uint8_t)(1 << r);
		}
		safe_free(buf);
	}
}

/* -----------------------------------------------------------------------
 * ImageScanThread
 *
 * Runs as a background thread started by on_select_clicked() (ui_gtk.c)
 * whenever the user selects a new image file.  Posts UM_IMAGE_SCANNED
 * when done so the GTK idle loop can refresh the UI safely.
 * ----------------------------------------------------------------------- */
DWORD WINAPI ImageScanThread(LPVOID param)
{
	(void)param;

	if (image_path == NULL)
		goto out_no_msg;

	memset(&img_report, 0, sizeof(img_report));

	/* Scan the image — this populates img_report fields: is_iso, label,
	 * image_size, has_grub2, has_syslinux, has_efi, is_windows_img, … */
	img_report.is_iso          = (BOOLEAN)ExtractISO(image_path, "", TRUE);
	img_report.is_bootable_img = IsBootableImage(image_path);

	/* Analyse UEFI bootloaders for Secure Boot signature and revocation */
	if (img_report.is_iso)
		GetBootladerInfo();

	/* If a Windows installation image was detected, gather version info */
	if (img_report.wininst_index > 0 || img_report.is_windows_img)
		PopulateWindowsVersion();

	/* Notify the GTK main thread; it will refresh all dependent combos. */
	PostMessage(hMainDialog, UM_IMAGE_SCANNED, 0, 0);

out_no_msg:
	ExitThread(0);
}
