/*
 * bootloader_scan.h — Portable UEFI bootloader analysis
 *
 * Declares GetBootladerInfo(), which reads each EFI binary listed in
 * img_report.efi_boot_entry[], checks Secure Boot authority signatures and
 * DBX/SBAT/SVN revocation, and updates img_report.has_secureboot_bootloader.
 *
 * The function is OS-neutral: all I/O is delegated to ReadISOFileToBuffer(),
 * IsSignedBySecureBootAuthority(), and IsBootloaderRevoked() — all declared
 * in rufus.h and implemented per-platform.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

/*
 * GetBootladerInfo — analyse the UEFI bootloaders listed in img_report.
 *
 * For each non-empty path in img_report.efi_boot_entry[]:
 *   1. Reads the EFI binary via ReadISOFileToBuffer(image_path, path, &buf).
 *   2. Checks IsSignedBySecureBootAuthority(buf, len): if TRUE, sets bit 0 of
 *      img_report.has_secureboot_bootloader.
 *   3. Checks IsBootloaderRevoked(buf, len): if r > 0, sets bit r of
 *      img_report.has_secureboot_bootloader and logs a warning.
 *
 * Stops at the first entry with an empty path.  If ReadISOFileToBuffer()
 * returns 0 the entry is skipped (with a warning) and processing continues.
 *
 * Note: The function name preserves the historical typo ("Bootlader") that
 * exists in both the Windows and Linux codebases.
 */
void GetBootladerInfo(void);
