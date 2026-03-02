/*
 * Rufus: The Reliable USB Formatting Utility
 * ISO config-file patching — portable declarations
 * Copyright © 2012-2025 Pete Batard <pete@akeo.ie>
 * Copyright © 2025 Rufus contributors
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

#pragma once

#include "../rufus.h"   /* NB_OLD_C32, BOOL, StrArray, uint64_t, BT_* */

/*
 * Per-file properties accumulated by check_iso_props() during ISO extraction.
 * Defined here so both iso.c platforms and the common iso_config.c can use it.
 */
typedef struct {
	BOOLEAN is_cfg;
	BOOLEAN is_conf;
	BOOLEAN is_syslinux_cfg;
	BOOLEAN is_grub_cfg;
	BOOLEAN is_menu_cfg;
	BOOLEAN is_old_c32[NB_OLD_C32];
} EXTRACT_PROPS;

/*
 * Platform-specific file copy callback.
 * src → dst, do not overwrite if dst already exists (bFailIfExists semantics).
 * Returns TRUE on success (or if dst already existed), FALSE on error.
 */
typedef BOOL (*iso_copy_fn)(const char *src, const char *dst);

/*
 * Apply all post-extraction patches to a config file that was just written to
 * disk during ISO extraction.
 *
 * Patches applied:
 *   1. Persistence kernel option injection (Ubuntu/Mint/Debian, Syslinux+GRUB).
 *   2. ISO volume-label → USB volume-label replacement in kernel command lines.
 *   3. Red Hat inst.stage2 → inst.repo replacement for RHEL 8+ derivatives.
 *   4. FreeNAS cd9660:/dev/iso9660/<label> → msdosfs:/dev/msdosfs/<label>.
 *   5. Tails dual BIOS+EFI workaround: copy /EFI/syslinux/isolinux.cfg →
 *      /EFI/syslinux/syslinux.cfg when no native EFI syslinux config exists.
 *
 * Parameters:
 *   file_path        Path to the file on disk (already extracted).
 *   psz_path         ISO directory of the file (e.g. "/EFI/syslinux").
 *   psz_basename     Filename portion (e.g. "isolinux.cfg").
 *   props            Flags set by check_iso_props() for this file.
 *   boot_type        BT_IMAGE / BT_SYSLINUX_V4 / etc.
 *   persistence_size Bytes of persistence partition (0 = disabled).
 *   has_persistence  Pre-computed: HAS_PERSISTENCE(img_report).
 *   rh8_derivative   img_report.rh8_derivative.
 *   has_efi_syslinux img_report.has_efi_syslinux.
 *   iso_label        img_report.label  (ISO volume label).
 *   usb_label        img_report.usb_label (destination USB label).
 *   image_path       Path to the source ISO (used to skip netinst images).
 *   modified_files   StrArray that receives the path of every patched file.
 *   copy_fn          Platform copy: NULL to skip the tails workaround.
 *
 * Returns TRUE if at least one patch was applied, FALSE otherwise.
 */
BOOL iso_patch_config_file(
	const char   *file_path,
	const char   *psz_path,
	const char   *psz_basename,
	EXTRACT_PROPS *props,
	int           boot_type,
	uint64_t      persistence_size,
	BOOL          has_persistence,
	BOOL          rh8_derivative,
	BOOL          has_efi_syslinux,
	const char   *iso_label,
	const char   *usb_label,
	const char   *image_path,
	StrArray     *modified_files,
	iso_copy_fn   copy_fn
);
