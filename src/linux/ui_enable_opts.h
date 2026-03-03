/*
 * ui_enable_opts.h - Pure-C predicates for advanced-options checkbox sensitivity
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

#pragma once

#include "../windows/rufus.h"
#include "compat/winioctl.h"  /* PARTITION_STYLE_MBR/GPT/RAW */

/* Returns TRUE if the "Add fixes for old BIOS" checkbox should be enabled.
 * Mirrors Windows EnableOldBiosFixes() condition check. */
BOOL should_enable_old_bios(int partition_type, int target_type,
                             int boot_type, RUFUS_IMG_REPORT *r);

/* Returns TRUE if the "Enable UEFI media validation" checkbox should be enabled.
 * Mirrors Windows EnableUefiValidation() condition check.
 * imop_sel is the currently selected image option value (e.g. IMOP_WIN_TO_GO).
 * image_options is the IMOP_* bitmask. */
BOOL should_enable_uefi_validation(int boot_type, int target_type,
                                   int image_options, int imop_sel,
                                   BOOL allow_dual, RUFUS_IMG_REPORT *r);

/* Returns TRUE if the "Create extended label and icon files" checkbox should be enabled.
 * Mirrors Windows EnableExtendedLabel() condition check. */
BOOL should_enable_extended_label(int fs_type, int boot_type, RUFUS_IMG_REPORT *r);

/* Returns TRUE if the "Quick format" checkbox should be enabled.
 * Mirrors Windows EnableQuickFormat() base condition check.
 * Note: when should_force_quick_format() is TRUE, the checkbox is also
 * force-checked AND disabled. */
BOOL should_enable_quick_format(int fs_type, int boot_type,
                                BOOL force_large_fat32, uint64_t disk_size,
                                RUFUS_IMG_REPORT *r);

/* Returns TRUE if Quick Format must be forced on (large FAT32 or ReFS).
 * When this returns TRUE, the checkbox is checked AND disabled. */
BOOL should_force_quick_format(int fs_type, BOOL force_large_fat32, uint64_t disk_size);
