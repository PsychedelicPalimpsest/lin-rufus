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
#pragma once
#include "../windows/rufus.h"

/*
 * Pure predicate helpers for the start-clicked validation path.
 * All functions are side-effect free and take only value parameters so
 * they can be tested without GTK.
 */

/*
 * Returns TRUE when the image is a "pure DD" image (has an MBR signature
 * but is NOT an ISO).  Such images must be written in raw DD mode without
 * prompting the user.
 */
BOOL boot_check_is_pure_dd(RUFUS_IMG_REPORT r);

/*
 * Returns TRUE when the selected image can be written as an ESP partition
 * (ISO small enough for GPT+FAT+EFI target).
 */
BOOL boot_check_can_write_as_esp(RUFUS_IMG_REPORT r, int partition_type, int fs_type);

/*
 * Returns TRUE when the UEFI target is selected but the ISO has no EFI
 * bootloader.  Caller should show MSG_090/MSG_091 error.
 */
BOOL boot_check_uefi_compat_fails(RUFUS_IMG_REPORT r, int target_type);

/*
 * Returns TRUE when a FAT filesystem is selected but the image contains a
 * file > 4 GB.  Caller should show MSG_099/MSG_100 error.
 * (Exception: has_4GB_file == 0x11 means the 4 GB "file" is a split WIM
 *  pair that Windows format.c splices — fine on Linux too for that special
 *  value, so we keep the same exemption as Windows.)
 */
BOOL boot_check_fat_4gb_fails(RUFUS_IMG_REPORT r, int fs_type);

/*
 * Returns TRUE when the chosen filesystem is incompatible with the image's
 * boot requirements.  Mirrors the three-clause compound check in
 * Windows BootCheckThread (rufus.c lines ~1545-1556).
 *
 * Caller should show MSG_092/MSG_096 error.
 */
BOOL boot_check_fat_compat_fails(RUFUS_IMG_REPORT r, int fs_type,
                                  int target_type, BOOL allow_dual_uefi_bios);

/*
 * Returns TRUE when FAT16 is selected for a KolibriOS image (unsupported).
 * Caller should show MSG_099/MSG_189 error.
 */
BOOL boot_check_fat16_kolibrios_fails(RUFUS_IMG_REPORT r, int fs_type);
