/*
 * ui_combo_logic.h — smart combo-box population based on image/boot type.
 *
 * populate_fs_combo() / populate_cluster_combo() fill the FS and cluster-size
 * combo boxes from scratch.  SetFSFromISO() calls populate_fs_combo() and then
 * intelligently selects the best FS based on img_report flags.
 * SetPartitionSchemeAndTargetSystem() rebuilds the Partition Scheme and Target
 * System combos based on boot_type and img_report.
 *
 * All implementations live in ui_combo_logic.c and have no GTK dependency —
 * they use only the combo_bridge message API, so they can be exercised in
 * unit tests without a display.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "../linux/compat/windows.h"

/*
 * SetComboEntry  —  find the combo entry whose item-data value equals `data`
 * and select it.  Falls back to the first item if no match is found.
 * Provided by ui_gtk.c (GTK build) or the test harness.
 */
void SetComboEntry(HWND hDlg, int data);

/*
 * populate_fs_combo  —  reset the hFileSystem combo and fill it with every
 * filesystem that is supported on this machine (FAT32 always; NTFS, exFAT,
 * UDF, ext2/3/4 conditionally on tool availability).  Defaults to FAT32.
 */
void populate_fs_combo(void);

/*
 * populate_cluster_combo  —  reset hClusterSize and fill it with common
 * cluster sizes for the given filesystem type.
 */
void populate_cluster_combo(int fs);

/*
 * SetFSFromISO  —  select the most appropriate File System from the *existing*
 * hFileSystem combo entries based on img_report flags.  The combo must already
 * be populated (call populate_fs_combo first).  Returns immediately without
 * change if image_path is NULL.
 */
void SetFSFromISO(void);

/*
 * SetPartitionSchemeAndTargetSystem  —  repopulate the Partition Scheme and
 * (always) the Target System combo based on the current boot_type and
 * img_report.  When only_target is TRUE the Partition Scheme combo is left
 * unchanged; otherwise it is also rebuilt.
 */
void SetPartitionSchemeAndTargetSystem(BOOL only_target);
