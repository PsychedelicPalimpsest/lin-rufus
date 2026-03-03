/*
 * Rufus: The Reliable USB Formatting Utility
 * Boot-time pre-format validation predicates (Linux port)
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
#include "boot_validation.h"
#include "compat/winioctl.h"   /* PARTITION_STYLE_GPT */

BOOL boot_check_is_pure_dd(RUFUS_IMG_REPORT r)
{
	return IS_DD_BOOTABLE(r) && !r.is_iso;
}

BOOL boot_check_can_write_as_esp(RUFUS_IMG_REPORT r, int partition_type, int fs_type)
{
	return (r.projected_size < MAX_ISO_TO_ESP_SIZE)
	    && HAS_REGULAR_EFI(r)
	    && (partition_type == PARTITION_STYLE_GPT)
	    && IS_FAT(fs_type);
}

BOOL boot_check_uefi_compat_fails(RUFUS_IMG_REPORT r, int target_type)
{
	return (target_type == TT_UEFI) && !IS_EFI_BOOTABLE(r);
}

BOOL boot_check_fat_4gb_fails(RUFUS_IMG_REPORT r, int fs_type)
{
	return IS_FAT(fs_type) && (r.has_4GB_file != 0) && (r.has_4GB_file != 0x11);
}

BOOL boot_check_fat_compat_fails(RUFUS_IMG_REPORT r, int fs_type,
                                  int target_type, BOOL allow_dual_uefi_bios)
{
	(void)target_type;   /* not used in this clause but kept for future expansion */
	if ((fs_type == FS_NTFS) && !HAS_WINDOWS(r) && !HAS_GRUB(r)
	    && (!HAS_SYSLINUX(r) || (SL_MAJOR(r.sl_version) <= 5)))
		return TRUE;
	if (IS_FAT(fs_type) && !HAS_SYSLINUX(r) && !allow_dual_uefi_bios
	    && !IS_EFI_BOOTABLE(r) && !HAS_REACTOS(r) && !HAS_KOLIBRIOS(r)
	    && !HAS_GRUB(r))
		return TRUE;
	if (IS_FAT(fs_type) && (HAS_WINDOWS(r) || HAS_WININST(r))
	    && !allow_dual_uefi_bios)
		return TRUE;
	return FALSE;
}

BOOL boot_check_fat16_kolibrios_fails(RUFUS_IMG_REPORT r, int fs_type)
{
	return (fs_type == FS_FAT16) && HAS_KOLIBRIOS(r);
}
