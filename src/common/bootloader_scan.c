/*
 * bootloader_scan.c — Portable UEFI bootloader analysis
 *
 * Implements GetBootladerInfo(): reads the EFI binaries embedded in an ISO
 * image and updates img_report.has_secureboot_bootloader based on Secure Boot
 * authority signatures and DBX/SBAT/SVN revocation status.
 *
 * This file contains no OS-specific I/O.  All platform dependencies are
 * resolved through declarations in rufus.h:
 *   - img_report        (extern RUFUS_IMG_REPORT)
 *   - image_path        (extern char*)
 *   - ReadISOFileToBuffer()
 *   - IsSignedBySecureBootAuthority()
 *   - IsBootloaderRevoked()
 *   - PrintStatus() / uprintf()
 *   - safe_free()
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rufus.h"
#include "resource.h"
#include "bootloader_scan.h"

/*
 * GetBootladerInfo — analyse UEFI bootloaders embedded in the scanned ISO.
 *
 * Iterates over img_report.efi_boot_entry[], reads each EFI binary with
 * ReadISOFileToBuffer(), then:
 *   - Sets bit 0 of has_secureboot_bootloader when a bootloader is signed by
 *     a known Secure Boot authority.
 *   - Sets bit r (r = 1..5) when IsBootloaderRevoked() returns r, and logs
 *     a warning message identifying the revocation authority.
 *
 * Note: The function name preserves the historical typo ("Bootlader").
 */
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

		len = ReadISOFileToBuffer(image_path, img_report.efi_boot_entry[i].path,
		                          &buf);
		if (len == 0) {
			uprintf("  Warning: Failed to extract '%s' to check for UEFI Secure Boot info",
			        img_report.efi_boot_entry[i].path);
			continue;
		}

		sb_signed = IsSignedBySecureBootAuthority(buf, len);
		if (sb_signed)
			img_report.has_secureboot_bootloader |= 1;

		uprintf("  \xe2\x80\xa2 %s%s", img_report.efi_boot_entry[i].path,
		        sb_signed ? "*" : "");

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
