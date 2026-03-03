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

/* Ctrl+Alt+Y — force update with strict mode (force_update=2 ignores timestamp errors) */
kbdshortcut_result_t kbdshortcut_toggle_force_update_strict (int *force_update);

/* Alt+. (period) — toggle USB enumeration debug (sets refresh_devs=1) */
kbdshortcut_result_t kbdshortcut_toggle_usb_debug        (int *usb_debug);

/* Alt+, (comma) — toggle physical drive locking */
kbdshortcut_result_t kbdshortcut_toggle_lock_drive       (int *lock_drive);

/* Alt+Q — toggle file indexing */
kbdshortcut_result_t kbdshortcut_toggle_file_indexing    (int *enable_file_indexing);

/*
 * Ctrl+Alt+F — toggle listing of non-USB removable drives.
 * Saves/restores enable_hdds as described; sets refresh_devs=1.
 */
kbdshortcut_result_t kbdshortcut_toggle_non_usb_removable(int *list_non_usb_removable,
                                                            int *enable_hdds,
                                                            int *prev_enable_hdds);

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
 * kbdshortcut_toggle_persistent_log - toggle persistent log on/off (Ctrl+P).
 * Toggles *persistent_log and returns result.  Does not do I/O itself;
 * the caller is responsible for persisting the value and showing the status.
 */
kbdshortcut_result_t kbdshortcut_toggle_persistent_log(int *persistent_log);

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
