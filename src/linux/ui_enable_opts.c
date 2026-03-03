/*
 * ui_enable_opts.c - Pure-C predicates for advanced-options checkbox sensitivity
 *
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ui_enable_opts.h"

/*
 * Note: the IS_* macros in rufus.h use value semantics (r.field).
 * When r is a pointer we must write IS_EFI_BOOTABLE((*r)) so that
 * the token-paste expands to ((*r).has_efi) and NOT (*(r.has_efi)).
 */

/* Mirrors the Windows EnableOldBiosFixes() condition. */
BOOL should_enable_old_bios(int partition_type, int target_type,
                             int boot_type, RUFUS_IMG_REPORT *r)
{
	if (r == NULL)
		return FALSE;
	if (partition_type != PARTITION_STYLE_MBR)
		return FALSE;
	if (target_type != TT_BIOS)
		return FALSE;
	if (boot_type == BT_NON_BOOTABLE)
		return FALSE;
	if ((boot_type == BT_IMAGE) && (!IS_BIOS_BOOTABLE((*r)) || IS_DD_ONLY((*r))))
		return FALSE;
	return TRUE;
}

/* Mirrors the Windows EnableUefiValidation() condition. */
BOOL should_enable_uefi_validation(int boot_type, int target_type,
                                   int image_options, int imop_sel,
                                   BOOL allow_dual, RUFUS_IMG_REPORT *r)
{
	if (r == NULL)
		return FALSE;
	if (boot_type != BT_IMAGE)
		return FALSE;
	if (!IS_EFI_BOOTABLE((*r)))
		return FALSE;
	if (IS_DD_ONLY((*r)))
		return FALSE;
	if ((image_options & IMOP_WINTOGO) && (imop_sel == IMOP_WIN_TO_GO))
		return FALSE;
	if ((target_type == TT_BIOS) && HAS_WINDOWS((*r)) && (!allow_dual))
		return FALSE;
	return TRUE;
}

/* Mirrors the Windows EnableExtendedLabel() condition. */
BOOL should_enable_extended_label(int fs_type, int boot_type, RUFUS_IMG_REPORT *r)
{
	if (r == NULL)
		return FALSE;
	if (IS_EXT(fs_type))
		return FALSE;
	if ((boot_type == BT_IMAGE) && IS_DD_ONLY((*r)))
		return FALSE;
	return TRUE;
}

/* Mirrors the Windows EnableQuickFormat() base condition. */
BOOL should_enable_quick_format(int fs_type, int boot_type,
                                BOOL force_large_fat32, uint64_t disk_size,
                                RUFUS_IMG_REPORT *r)
{
	if (r == NULL)
		return FALSE;
	if ((boot_type == BT_IMAGE) && IS_DD_ONLY((*r)))
		return FALSE;
	if (should_force_quick_format(fs_type, force_large_fat32, disk_size))
		return FALSE;
	return TRUE;
}

/* Returns TRUE when quick format must be forced on (large FAT32 or ReFS). */
BOOL should_force_quick_format(int fs_type, BOOL force_large_fat32, uint64_t disk_size)
{
	if ((fs_type == FS_FAT32) && (disk_size > LARGE_FAT32_SIZE || force_large_fat32))
		return TRUE;
	if (fs_type == FS_REFS)
		return TRUE;
	return FALSE;
}
