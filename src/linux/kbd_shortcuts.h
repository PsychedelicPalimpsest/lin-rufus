/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * src/linux/kbd_shortcuts.h — keyboard shortcut toggle functions
 *
 * Copyright © 2025 Rufus contributors
 *
 * Pure-C helper functions that implement Alt+key cheat-mode toggles.
 * Each function toggles one global flag (and optionally persists it to the
 * INI settings file).  They have no GTK dependency and are fully
 * unit-testable.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * kbdshortcut_result - describes what happened when a shortcut fires.
 */
typedef struct {
	int  new_value;     /* new value of the global (0 or 1 for BOOLs) */
	int  refresh_devs;  /* non-zero → call GetDevices(0) after toggle  */
	int  refresh_part;  /* non-zero → call SetPartitionScheme… after   */
} kbdshortcut_result_t;

/* ---- toggle functions ---- */

kbdshortcut_result_t kbdshortcut_toggle_rufus_mbr        (int *use_rufus_mbr);
kbdshortcut_result_t kbdshortcut_toggle_detect_fakes     (int *detect_fakes);
kbdshortcut_result_t kbdshortcut_toggle_dual_uefi_bios   (int *allow_dual_uefi_bios);
kbdshortcut_result_t kbdshortcut_toggle_vhds             (int *enable_VHDs);
kbdshortcut_result_t kbdshortcut_toggle_extra_hashes     (int *enable_extra_hashes);
kbdshortcut_result_t kbdshortcut_toggle_iso              (int *enable_iso);
kbdshortcut_result_t kbdshortcut_toggle_large_fat32      (int *force_large_fat32);
kbdshortcut_result_t kbdshortcut_toggle_boot_marker      (int *ignore_boot_marker);
kbdshortcut_result_t kbdshortcut_toggle_ntfs_compression (int *enable_ntfs_compression);
kbdshortcut_result_t kbdshortcut_toggle_size_check       (int *size_check);
kbdshortcut_result_t kbdshortcut_toggle_preserve_ts      (int *preserve_timestamps);
kbdshortcut_result_t kbdshortcut_toggle_proper_units     (int *use_fake_units);
kbdshortcut_result_t kbdshortcut_toggle_vmdk             (int *enable_vmdk);
kbdshortcut_result_t kbdshortcut_toggle_force_update     (int *force_update);

/*
 * kbdshortcut_zero_drive - prepare for zero-drive operation.
 * Sets *zero_drive = 1, *fast_zeroing = 0 (Alt+Z).
 */
void kbdshortcut_zero_drive      (int *zero_drive, int *fast_zeroing);

/*
 * kbdshortcut_fast_zero_drive - prepare for fast zero-drive (skip empty blocks).
 * Sets *zero_drive = 1, *fast_zeroing = 1 (Ctrl+Alt+Z).
 */
void kbdshortcut_fast_zero_drive (int *zero_drive, int *fast_zeroing);

/*
 * kbdshortcut_size_check_fails - returns non-zero when the image is too large
 * to fit on the target drive and the size check is enabled.
 *
 * @param  size_check      1 = size enforcement active, 0 = bypassed (Alt+S)
 * @param  projected_size  image size in bytes
 * @param  disk_size       target drive capacity in bytes
 */
int kbdshortcut_size_check_fails (int size_check,
                                  unsigned long long projected_size,
                                  unsigned long long disk_size);

#ifdef __cplusplus
}
#endif
