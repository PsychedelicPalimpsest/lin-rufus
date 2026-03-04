/* tests/test_kbd_shortcuts_linux.c — tests for kbd_shortcuts.c
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * These tests cover the pure-C keyboard shortcut toggle functions.
 * No GTK, no display, no settings I/O.
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "framework.h"

/* Pull in the implementation directly (no separate compilation needed) */
#include "../src/linux/kbd_shortcuts.c"

/* ===================================================================== *
 * Alt+A — use_rufus_mbr                                                 *
 * ===================================================================== */

TEST(toggle_rufus_mbr_off)
{
	int v = 1;  /* default: Rufus MBR enabled */
	kbdshortcut_result_t r = kbdshortcut_toggle_rufus_mbr(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
	CHECK_INT_EQ(0, r.refresh_devs);
	CHECK_INT_EQ(0, r.refresh_part);
}

TEST(toggle_rufus_mbr_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_rufus_mbr(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_rufus_mbr_double_returns_original)
{
	int v = 1;
	kbdshortcut_toggle_rufus_mbr(&v);
	kbdshortcut_toggle_rufus_mbr(&v);
	CHECK_INT_EQ(1, v);
}

/* ===================================================================== *
 * Alt+B — detect_fakes                                                  *
 * ===================================================================== */

TEST(toggle_detect_fakes_off)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_detect_fakes(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_detect_fakes_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_detect_fakes(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_detect_fakes_double_returns_original)
{
	int v = 1;
	kbdshortcut_toggle_detect_fakes(&v);
	kbdshortcut_toggle_detect_fakes(&v);
	CHECK_INT_EQ(1, v);
}

/* ===================================================================== *
 * Alt+E — allow_dual_uefi_bios (must set refresh_part)                  *
 * ===================================================================== */

TEST(toggle_dual_uefi_bios_sets_refresh_part)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_dual_uefi_bios(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.refresh_part);
}

TEST(toggle_dual_uefi_bios_new_value_reflected)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_dual_uefi_bios(&v);
	CHECK_INT_EQ(0, r.new_value);
	CHECK_INT_EQ(0, v);
}

TEST(toggle_dual_uefi_bios_double_returns_original)
{
	int v = 0;
	kbdshortcut_toggle_dual_uefi_bios(&v);
	kbdshortcut_toggle_dual_uefi_bios(&v);
	CHECK_INT_EQ(0, v);
}

/* ===================================================================== *
 * Alt+G — enable_VHDs (must request device list refresh)                *
 * ===================================================================== */

TEST(toggle_vhds_requests_refresh)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_vhds(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(1, r.refresh_devs);
}

TEST(toggle_vhds_new_value)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_vhds(&v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_vhds_double_returns_original)
{
	int v = 1;
	kbdshortcut_toggle_vhds(&v);
	kbdshortcut_toggle_vhds(&v);
	CHECK_INT_EQ(1, v);
}

/* ===================================================================== *
 * Alt+H — enable_extra_hashes                                           *
 * ===================================================================== */

TEST(toggle_extra_hashes_basic)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_extra_hashes(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
	CHECK_INT_EQ(0, r.refresh_devs);
}

TEST(toggle_extra_hashes_double)
{
	int v = 0;
	kbdshortcut_toggle_extra_hashes(&v);
	kbdshortcut_toggle_extra_hashes(&v);
	CHECK_INT_EQ(0, v);
}

/* ===================================================================== *
 * Alt+I — enable_iso                                                    *
 * ===================================================================== */

TEST(toggle_iso_off)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_iso(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_iso_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_iso(&v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_iso_double)
{
	int v = 1;
	kbdshortcut_toggle_iso(&v);
	kbdshortcut_toggle_iso(&v);
	CHECK_INT_EQ(1, v);
}

/* ===================================================================== *
 * Alt+L — force_large_fat32 (must request device list refresh)          *
 * ===================================================================== */

TEST(toggle_large_fat32_requests_refresh)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_large_fat32(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.refresh_devs);
}

TEST(toggle_large_fat32_double)
{
	int v = 0;
	kbdshortcut_toggle_large_fat32(&v);
	kbdshortcut_toggle_large_fat32(&v);
	CHECK_INT_EQ(0, v);
}

/* ===================================================================== *
 * Alt+M — ignore_boot_marker                                            *
 * ===================================================================== */

TEST(toggle_boot_marker_basic)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_boot_marker(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
	CHECK_INT_EQ(0, r.refresh_devs);
}

TEST(toggle_boot_marker_double)
{
	int v = 0;
	kbdshortcut_toggle_boot_marker(&v);
	kbdshortcut_toggle_boot_marker(&v);
	CHECK_INT_EQ(0, v);
}

/* ===================================================================== *
 * Alt+N — enable_ntfs_compression                                       *
 * ===================================================================== */

TEST(toggle_ntfs_compression_basic)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_ntfs_compression(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_ntfs_compression_double)
{
	int v = 1;
	kbdshortcut_toggle_ntfs_compression(&v);
	kbdshortcut_toggle_ntfs_compression(&v);
	CHECK_INT_EQ(1, v);
}

/* ===================================================================== *
 * Alt+S — size_check                                                    *
 * ===================================================================== */

TEST(toggle_size_check_default_on)
{
	/* Default is size_check=1; toggling should disable it */
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_size_check(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_size_check_re_enable)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_size_check(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_size_check_double)
{
	int v = 1;
	kbdshortcut_toggle_size_check(&v);
	kbdshortcut_toggle_size_check(&v);
	CHECK_INT_EQ(1, v);
}

/* ===================================================================== *
 * Alt+T — preserve_timestamps                                           *
 * ===================================================================== */

TEST(toggle_preserve_ts_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_preserve_ts(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_preserve_ts_double)
{
	int v = 0;
	kbdshortcut_toggle_preserve_ts(&v);
	kbdshortcut_toggle_preserve_ts(&v);
	CHECK_INT_EQ(0, v);
}

/* ===================================================================== *
 * Alt+U — use_fake_units (must request device list refresh)             *
 * ===================================================================== */

TEST(toggle_proper_units_requests_refresh)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_proper_units(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.refresh_devs);
}

TEST(toggle_proper_units_double)
{
	int v = 0;
	kbdshortcut_toggle_proper_units(&v);
	kbdshortcut_toggle_proper_units(&v);
	CHECK_INT_EQ(0, v);
}

/* ===================================================================== *
 * Alt+W — enable_vmdk (must request device list refresh)                *
 * ===================================================================== */

TEST(toggle_vmdk_requests_refresh)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_vmdk(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.refresh_devs);
}

TEST(toggle_vmdk_double)
{
	int v = 1;
	kbdshortcut_toggle_vmdk(&v);
	kbdshortcut_toggle_vmdk(&v);
	CHECK_INT_EQ(1, v);
}

/* ===================================================================== *
 * Alt+Y — force_update (0 → 1, >0 → 0)                                 *
 * ===================================================================== */

TEST(toggle_force_update_zero_to_one)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_force_update(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_force_update_one_to_zero)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_force_update(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_force_update_large_to_zero)
{
	int v = 5;
	kbdshortcut_result_t r = kbdshortcut_toggle_force_update(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_force_update_double_returns_one)
{
	int v = 0;
	kbdshortcut_toggle_force_update(&v);
	kbdshortcut_toggle_force_update(&v);
	CHECK_INT_EQ(0, v);
}

/* ===================================================================== *
 * Ctrl+Alt+Y — force_update strict (value = 2)                         *
 * ===================================================================== */

TEST(toggle_force_update_strict_zero_to_two)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_force_update_strict(&v);
	CHECK_INT_EQ(2, v);
	CHECK_INT_EQ(2, r.new_value);
}

TEST(toggle_force_update_strict_nonzero_to_zero)
{
	int v = 2;
	kbdshortcut_result_t r = kbdshortcut_toggle_force_update_strict(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_force_update_strict_differs_from_normal)
{
	int vn = 0, vs = 0;
	kbdshortcut_toggle_force_update(&vn);
	kbdshortcut_toggle_force_update_strict(&vs);
	assert(vn != vs);
}

/* ===================================================================== *
 * Alt+. (period) — usb_debug                                           *
 * ===================================================================== */

TEST(toggle_usb_debug_off_to_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_usb_debug(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
	CHECK_INT_EQ(1, r.refresh_devs);
}

TEST(toggle_usb_debug_on_to_off)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_usb_debug(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
	CHECK_INT_EQ(1, r.refresh_devs);
}

TEST(toggle_usb_debug_no_partition_refresh)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_usb_debug(&v);
	CHECK_INT_EQ(0, r.refresh_part);
}

/* ===================================================================== *
 * Alt+, (comma) — lock_drive                                           *
 * ===================================================================== */

TEST(toggle_lock_drive_on_to_off)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_lock_drive(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_lock_drive_off_to_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_lock_drive(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_lock_drive_no_refresh)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_lock_drive(&v);
	CHECK_INT_EQ(0, r.refresh_devs);
	CHECK_INT_EQ(0, r.refresh_part);
}

TEST(toggle_lock_drive_double)
{
	int v = 1;
	kbdshortcut_toggle_lock_drive(&v);
	kbdshortcut_toggle_lock_drive(&v);
	CHECK_INT_EQ(1, v);
}

/* ===================================================================== *
 * Alt+Q — enable_file_indexing                                         *
 * ===================================================================== */

TEST(toggle_file_indexing_off_to_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_file_indexing(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_file_indexing_on_to_off)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_file_indexing(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_file_indexing_no_refresh)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_file_indexing(&v);
	CHECK_INT_EQ(0, r.refresh_devs);
	CHECK_INT_EQ(0, r.refresh_part);
}

/* ===================================================================== *
 * Ctrl+Alt+F — list_non_usb_removable_drives                          *
 * ===================================================================== */

TEST(toggle_non_usb_removable_enable_saves_hdds)
{
	int list = 0, hdds = 0, prev = 0;
	kbdshortcut_toggle_non_usb_removable(&list, &hdds, &prev);
	CHECK_INT_EQ(1, list);
	CHECK_INT_EQ(1, hdds);
	CHECK_INT_EQ(0, prev);
}

TEST(toggle_non_usb_removable_enable_hdds_true)
{
	int list = 0, hdds = 1, prev = 0;
	kbdshortcut_toggle_non_usb_removable(&list, &hdds, &prev);
	CHECK_INT_EQ(1, hdds);
	CHECK_INT_EQ(1, prev);
}

TEST(toggle_non_usb_removable_disable_restores_hdds)
{
	int list = 1, hdds = 1, prev = 0;
	kbdshortcut_toggle_non_usb_removable(&list, &hdds, &prev);
	CHECK_INT_EQ(0, list);
	CHECK_INT_EQ(0, hdds);
}

TEST(toggle_non_usb_removable_disable_restores_true)
{
	int list = 1, hdds = 1, prev = 1;
	kbdshortcut_toggle_non_usb_removable(&list, &hdds, &prev);
	CHECK_INT_EQ(1, hdds);
}

TEST(toggle_non_usb_removable_requests_refresh)
{
	int list = 0, hdds = 0, prev = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_non_usb_removable(&list, &hdds, &prev);
	CHECK_INT_EQ(1, r.refresh_devs);
	CHECK_INT_EQ(0, r.refresh_part);
}

TEST(toggle_non_usb_removable_result_value_matches)
{
	int list = 0, hdds = 0, prev = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_non_usb_removable(&list, &hdds, &prev);
	CHECK_INT_EQ(1, r.new_value);
	r = kbdshortcut_toggle_non_usb_removable(&list, &hdds, &prev);
	CHECK_INT_EQ(0, r.new_value);
}

/* ===================================================================== *
 * Alt+Z — zero_drive                                                    *
 * ===================================================================== */

TEST(zero_drive_sets_flags)
{
	int zd = 0, fz = 1;
	kbdshortcut_zero_drive(&zd, &fz);
	CHECK_INT_EQ(1, zd);
	CHECK_INT_EQ(0, fz);
}

TEST(zero_drive_does_not_enable_fast)
{
	int zd = 0, fz = 0;
	kbdshortcut_zero_drive(&zd, &fz);
	CHECK_INT_EQ(0, fz);
}

/* ===================================================================== *
 * Ctrl+Alt+Z — fast zero_drive                                          *
 * ===================================================================== */

TEST(fast_zero_drive_sets_flags)
{
	int zd = 0, fz = 0;
	kbdshortcut_fast_zero_drive(&zd, &fz);
	CHECK_INT_EQ(1, zd);
	CHECK_INT_EQ(1, fz);
}

TEST(fast_zero_drive_overrides_false)
{
	int zd = 1, fz = 0;
	kbdshortcut_fast_zero_drive(&zd, &fz);
	CHECK_INT_EQ(1, zd);
	CHECK_INT_EQ(1, fz);
}

/* ===================================================================== *
 * kbdshortcut_size_check_fails                                          *
 * ===================================================================== */

TEST(size_check_fails_when_image_larger_and_check_enabled)
{
	/* 5 GiB image, 4 GiB drive — should fail */
	unsigned long long img  = 5ULL * 1024 * 1024 * 1024;
	unsigned long long disk = 4ULL * 1024 * 1024 * 1024;
	CHECK_INT_EQ(1, kbdshortcut_size_check_fails(1, img, disk));
}

TEST(size_check_passes_when_image_fits)
{
	/* 3 GiB image, 4 GiB drive — fits fine */
	unsigned long long img  = 3ULL * 1024 * 1024 * 1024;
	unsigned long long disk = 4ULL * 1024 * 1024 * 1024;
	CHECK_INT_EQ(0, kbdshortcut_size_check_fails(1, img, disk));
}

TEST(size_check_bypassed_when_disabled)
{
	/* 10 GiB image, 4 GiB drive — check disabled, so should pass */
	unsigned long long img  = 10ULL * 1024 * 1024 * 1024;
	unsigned long long disk =  4ULL * 1024 * 1024 * 1024;
	CHECK_INT_EQ(0, kbdshortcut_size_check_fails(0, img, disk));
}

TEST(size_check_exact_size_passes)
{
	/* Exact match — image fits exactly */
	unsigned long long sz = 8ULL * 1024 * 1024 * 1024;
	CHECK_INT_EQ(0, kbdshortcut_size_check_fails(1, sz, sz));
}

TEST(size_check_zero_image_passes)
{
	/* Zero-size image always fits */
	CHECK_INT_EQ(0, kbdshortcut_size_check_fails(1, 0, 4ULL * 1024 * 1024 * 1024));
}

TEST(size_check_zero_disk_fails_with_any_image)
{
	/* Disk size 0 (error case) — any non-zero image should fail */
	CHECK_INT_EQ(1, kbdshortcut_size_check_fails(1, 1024, 0));
}

/* ===================================================================== *
 * Ctrl+P — persistent_log                                               *
 * ===================================================================== */

TEST(toggle_persistent_log_off_to_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_persistent_log(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_persistent_log_on_to_off)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_persistent_log(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_persistent_log_double_returns_original)
{
	int v = 0;
	kbdshortcut_toggle_persistent_log(&v);
	kbdshortcut_toggle_persistent_log(&v);
	CHECK_INT_EQ(0, v);
}

TEST(toggle_persistent_log_no_refresh_devs)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_persistent_log(&v);
	CHECK_INT_EQ(0, r.refresh_devs);
}

TEST(toggle_persistent_log_no_refresh_part)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_persistent_log(&v);
	CHECK_INT_EQ(0, r.refresh_part);
}

/* ===================================================================== *
 * Alt+J — enable_joliet                                                 *
 * ===================================================================== */

TEST(toggle_joliet_off_to_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_joliet(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_joliet_on_to_off)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_joliet(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_joliet_double_returns_original)
{
	int v = 1;
	kbdshortcut_toggle_joliet(&v);
	kbdshortcut_toggle_joliet(&v);
	CHECK_INT_EQ(1, v);
}

TEST(toggle_joliet_no_refresh_devs)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_joliet(&v);
	CHECK_INT_EQ(0, r.refresh_devs);
}

TEST(toggle_joliet_no_refresh_part)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_joliet(&v);
	CHECK_INT_EQ(0, r.refresh_part);
}

/* ===================================================================== *
 * Alt+K — enable_rockridge                                              *
 * ===================================================================== */

TEST(toggle_rockridge_off_to_on)
{
	int v = 0;
	kbdshortcut_result_t r = kbdshortcut_toggle_rockridge(&v);
	CHECK_INT_EQ(1, v);
	CHECK_INT_EQ(1, r.new_value);
}

TEST(toggle_rockridge_on_to_off)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_rockridge(&v);
	CHECK_INT_EQ(0, v);
	CHECK_INT_EQ(0, r.new_value);
}

TEST(toggle_rockridge_double_returns_original)
{
	int v = 0;
	kbdshortcut_toggle_rockridge(&v);
	kbdshortcut_toggle_rockridge(&v);
	CHECK_INT_EQ(0, v);
}

TEST(toggle_rockridge_no_refresh_devs)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_rockridge(&v);
	CHECK_INT_EQ(0, r.refresh_devs);
}

TEST(toggle_rockridge_no_refresh_part)
{
	int v = 1;
	kbdshortcut_result_t r = kbdshortcut_toggle_rockridge(&v);
	CHECK_INT_EQ(0, r.refresh_part);
}

/* ===================================================================== *
 * Alt++/-  — default_thread_priority                                    *
 * ===================================================================== */

TEST(thread_priority_increment_from_normal)
{
	int v = THREAD_PRIORITY_NORMAL;
	kbdshortcut_result_t r = kbdshortcut_adjust_thread_priority(&v, +1);
	CHECK_INT_EQ(THREAD_PRIORITY_ABOVE_NORMAL, v);
	CHECK_INT_EQ(THREAD_PRIORITY_ABOVE_NORMAL, r.new_value);
}

TEST(thread_priority_decrement_from_above_normal)
{
	int v = THREAD_PRIORITY_ABOVE_NORMAL;
	kbdshortcut_result_t r = kbdshortcut_adjust_thread_priority(&v, -1);
	CHECK_INT_EQ(THREAD_PRIORITY_NORMAL, v);
	CHECK_INT_EQ(THREAD_PRIORITY_NORMAL, r.new_value);
}

TEST(thread_priority_clamped_at_highest)
{
	int v = THREAD_PRIORITY_HIGHEST;
	kbdshortcut_adjust_thread_priority(&v, +1);
	CHECK_INT_EQ(THREAD_PRIORITY_HIGHEST, v);
}

TEST(thread_priority_clamped_at_lowest)
{
	int v = THREAD_PRIORITY_LOWEST;
	kbdshortcut_adjust_thread_priority(&v, -1);
	CHECK_INT_EQ(THREAD_PRIORITY_LOWEST, v);
}

TEST(thread_priority_no_refresh_devs)
{
	int v = THREAD_PRIORITY_NORMAL;
	kbdshortcut_result_t r = kbdshortcut_adjust_thread_priority(&v, +1);
	CHECK_INT_EQ(0, r.refresh_devs);
}

TEST(thread_priority_no_refresh_part)
{
	int v = THREAD_PRIORITY_NORMAL;
	kbdshortcut_result_t r = kbdshortcut_adjust_thread_priority(&v, +1);
	CHECK_INT_EQ(0, r.refresh_part);
}

TEST(thread_priority_increment_stores_new_value)
{
	int v = THREAD_PRIORITY_BELOW_NORMAL;
	kbdshortcut_result_t r = kbdshortcut_adjust_thread_priority(&v, +1);
	CHECK_INT_EQ(THREAD_PRIORITY_NORMAL, r.new_value);
}

TEST(thread_priority_decrement_stores_new_value)
{
	int v = THREAD_PRIORITY_NORMAL;
	kbdshortcut_result_t r = kbdshortcut_adjust_thread_priority(&v, -1);
	CHECK_INT_EQ(THREAD_PRIORITY_BELOW_NORMAL, r.new_value);
}

/* ===================================================================== *
 * main                                                                  *
 * ===================================================================== */

int main(void)
{
	printf("=== Alt+A (use_rufus_mbr) ===\n");
	RUN(toggle_rufus_mbr_off);
	RUN(toggle_rufus_mbr_on);
	RUN(toggle_rufus_mbr_double_returns_original);

	printf("\n=== Alt+B (detect_fakes) ===\n");
	RUN(toggle_detect_fakes_off);
	RUN(toggle_detect_fakes_on);
	RUN(toggle_detect_fakes_double_returns_original);

	printf("\n=== Alt+E (allow_dual_uefi_bios) ===\n");
	RUN(toggle_dual_uefi_bios_sets_refresh_part);
	RUN(toggle_dual_uefi_bios_new_value_reflected);
	RUN(toggle_dual_uefi_bios_double_returns_original);

	printf("\n=== Alt+G (enable_VHDs) ===\n");
	RUN(toggle_vhds_requests_refresh);
	RUN(toggle_vhds_new_value);
	RUN(toggle_vhds_double_returns_original);

	printf("\n=== Alt+H (enable_extra_hashes) ===\n");
	RUN(toggle_extra_hashes_basic);
	RUN(toggle_extra_hashes_double);

	printf("\n=== Alt+I (enable_iso) ===\n");
	RUN(toggle_iso_off);
	RUN(toggle_iso_on);
	RUN(toggle_iso_double);

	printf("\n=== Alt+L (force_large_fat32) ===\n");
	RUN(toggle_large_fat32_requests_refresh);
	RUN(toggle_large_fat32_double);

	printf("\n=== Alt+M (ignore_boot_marker) ===\n");
	RUN(toggle_boot_marker_basic);
	RUN(toggle_boot_marker_double);

	printf("\n=== Alt+N (enable_ntfs_compression) ===\n");
	RUN(toggle_ntfs_compression_basic);
	RUN(toggle_ntfs_compression_double);

	printf("\n=== Alt+S (size_check toggle) ===\n");
	RUN(toggle_size_check_default_on);
	RUN(toggle_size_check_re_enable);
	RUN(toggle_size_check_double);

	printf("\n=== Alt+T (preserve_timestamps) ===\n");
	RUN(toggle_preserve_ts_on);
	RUN(toggle_preserve_ts_double);

	printf("\n=== Alt+U (use_fake_units) ===\n");
	RUN(toggle_proper_units_requests_refresh);
	RUN(toggle_proper_units_double);

	printf("\n=== Alt+W (enable_vmdk) ===\n");
	RUN(toggle_vmdk_requests_refresh);
	RUN(toggle_vmdk_double);

	printf("\n=== Alt+Y (force_update) ===\n");
	RUN(toggle_force_update_zero_to_one);
	RUN(toggle_force_update_one_to_zero);
	RUN(toggle_force_update_large_to_zero);
	RUN(toggle_force_update_double_returns_one);

	printf("\n=== Ctrl+Alt+Y (force_update strict) ===\n");
	RUN(toggle_force_update_strict_zero_to_two);
	RUN(toggle_force_update_strict_nonzero_to_zero);
	RUN(toggle_force_update_strict_differs_from_normal);

	printf("\n=== Alt+. (usb_debug) ===\n");
	RUN(toggle_usb_debug_off_to_on);
	RUN(toggle_usb_debug_on_to_off);
	RUN(toggle_usb_debug_no_partition_refresh);

	printf("\n=== Alt+, (lock_drive) ===\n");
	RUN(toggle_lock_drive_on_to_off);
	RUN(toggle_lock_drive_off_to_on);
	RUN(toggle_lock_drive_no_refresh);
	RUN(toggle_lock_drive_double);

	printf("\n=== Alt+Q (file_indexing) ===\n");
	RUN(toggle_file_indexing_off_to_on);
	RUN(toggle_file_indexing_on_to_off);
	RUN(toggle_file_indexing_no_refresh);

	printf("\n=== Ctrl+Alt+F (non_usb_removable) ===\n");
	RUN(toggle_non_usb_removable_enable_saves_hdds);
	RUN(toggle_non_usb_removable_enable_hdds_true);
	RUN(toggle_non_usb_removable_disable_restores_hdds);
	RUN(toggle_non_usb_removable_disable_restores_true);
	RUN(toggle_non_usb_removable_requests_refresh);
	RUN(toggle_non_usb_removable_result_value_matches);

	printf("\n=== Alt+Z (zero_drive) ===\n");
	RUN(zero_drive_sets_flags);
	RUN(zero_drive_does_not_enable_fast);

	printf("\n=== Ctrl+Alt+Z (fast zero_drive) ===\n");
	RUN(fast_zero_drive_sets_flags);
	RUN(fast_zero_drive_overrides_false);

	printf("\n=== size_check_fails logic ===\n");
	RUN(size_check_fails_when_image_larger_and_check_enabled);
	RUN(size_check_passes_when_image_fits);
	RUN(size_check_bypassed_when_disabled);
	RUN(size_check_exact_size_passes);
	RUN(size_check_zero_image_passes);
	RUN(size_check_zero_disk_fails_with_any_image);

	printf("\n=== Ctrl+P (persistent_log) ===\n");
	RUN(toggle_persistent_log_off_to_on);
	RUN(toggle_persistent_log_on_to_off);
	RUN(toggle_persistent_log_double_returns_original);
	RUN(toggle_persistent_log_no_refresh_devs);
	RUN(toggle_persistent_log_no_refresh_part);

	printf("\n=== Alt+J (enable_joliet) ===\n");
	RUN(toggle_joliet_off_to_on);
	RUN(toggle_joliet_on_to_off);
	RUN(toggle_joliet_double_returns_original);
	RUN(toggle_joliet_no_refresh_devs);
	RUN(toggle_joliet_no_refresh_part);

	printf("\n=== Alt+K (enable_rockridge) ===\n");
	RUN(toggle_rockridge_off_to_on);
	RUN(toggle_rockridge_on_to_off);
	RUN(toggle_rockridge_double_returns_original);
	RUN(toggle_rockridge_no_refresh_devs);
	RUN(toggle_rockridge_no_refresh_part);

	printf("\n=== Alt+/-  (thread_priority) ===\n");
	RUN(thread_priority_increment_from_normal);
	RUN(thread_priority_decrement_from_above_normal);
	RUN(thread_priority_clamped_at_highest);
	RUN(thread_priority_clamped_at_lowest);
	RUN(thread_priority_no_refresh_devs);
	RUN(thread_priority_no_refresh_part);
	RUN(thread_priority_increment_stores_new_value);
	RUN(thread_priority_decrement_stores_new_value);

	TEST_RESULTS();
	return (_fail > 0) ? 1 : 0;
}
