/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * src/linux/kbd_shortcuts.c — keyboard shortcut toggle functions
 *
 * Copyright © 2025 Rufus contributors
 *
 * Implements the Alt+key "cheat mode" toggles that mirror the Windows
 * rufus.c keyboard handler.  Each function takes a pointer to the relevant
 * global so that it can be unit-tested without linking the full application.
 *
 * The GTK callbacks in ui_gtk.c call these helpers and then perform any
 * required UI refresh (GetDevices, SetPartitionScheme, etc.).
 */

#include "kbd_shortcuts.h"

/* --------------------------------------------------------------------- *
 * Individual toggle helpers                                              *
 * --------------------------------------------------------------------- */

/* Alt+A — toggle Rufus MBR vs standard MBR */
kbdshortcut_result_t kbdshortcut_toggle_rufus_mbr(int *use_rufus_mbr)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*use_rufus_mbr = !*use_rufus_mbr;
	r.new_value = *use_rufus_mbr;
	return r;
}

/* Alt+B — toggle fake USB drive detection */
kbdshortcut_result_t kbdshortcut_toggle_detect_fakes(int *detect_fakes)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*detect_fakes = !*detect_fakes;
	r.new_value = *detect_fakes;
	return r;
}

/* Alt+E — toggle dual UEFI/BIOS mode (affects partition scheme) */
kbdshortcut_result_t kbdshortcut_toggle_dual_uefi_bios(int *allow_dual_uefi_bios)
{
	kbdshortcut_result_t r = { 0, 0, 1 };
	*allow_dual_uefi_bios = !*allow_dual_uefi_bios;
	r.new_value    = *allow_dual_uefi_bios;
	r.refresh_part = 1;
	return r;
}

/* Alt+G — toggle Virtual Disk (VHD/VMDK) detection */
kbdshortcut_result_t kbdshortcut_toggle_vhds(int *enable_VHDs)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*enable_VHDs  = !*enable_VHDs;
	r.new_value   = *enable_VHDs;
	r.refresh_devs = 1;
	return r;
}

/* Alt+H — toggle SHA-512 hash computation */
kbdshortcut_result_t kbdshortcut_toggle_extra_hashes(int *enable_extra_hashes)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*enable_extra_hashes = !*enable_extra_hashes;
	r.new_value = *enable_extra_hashes;
	return r;
}

/* Alt+I — toggle ISO extraction support (force DD mode when disabled) */
kbdshortcut_result_t kbdshortcut_toggle_iso(int *enable_iso)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*enable_iso = !*enable_iso;
	r.new_value = *enable_iso;
	return r;
}

/* Alt+L — force large-FAT32 format on drives < 32 GB */
kbdshortcut_result_t kbdshortcut_toggle_large_fat32(int *force_large_fat32)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*force_large_fat32 = !*force_large_fat32;
	r.new_value    = *force_large_fat32;
	r.refresh_devs = 1;
	return r;
}

/* Alt+M — ignore 0x55AA boot marker (treat any image as DD-writable) */
kbdshortcut_result_t kbdshortcut_toggle_boot_marker(int *ignore_boot_marker)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*ignore_boot_marker = !*ignore_boot_marker;
	r.new_value = *ignore_boot_marker;
	return r;
}

/* Alt+N — toggle NTFS compression */
kbdshortcut_result_t kbdshortcut_toggle_ntfs_compression(int *enable_ntfs_compression)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*enable_ntfs_compression = !*enable_ntfs_compression;
	r.new_value = *enable_ntfs_compression;
	return r;
}

/* Alt+S — toggle ISO-vs-drive size check */
kbdshortcut_result_t kbdshortcut_toggle_size_check(int *size_check)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*size_check = !*size_check;
	r.new_value = *size_check;
	return r;
}

/* Alt+T — preserve file timestamps when extracting ISO files */
kbdshortcut_result_t kbdshortcut_toggle_preserve_ts(int *preserve_timestamps)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*preserve_timestamps = !*preserve_timestamps;
	r.new_value = *preserve_timestamps;
	return r;
}

/* Alt+U — use "proper" (binary) size units (GiB/MiB) vs SI (GB/MB) */
kbdshortcut_result_t kbdshortcut_toggle_proper_units(int *use_fake_units)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	/* use_fake_units == TRUE means SI units; toggle means switching to GiB */
	*use_fake_units = !*use_fake_units;
	r.new_value    = *use_fake_units;
	r.refresh_devs = 1;
	return r;
}

/* Alt+W — toggle VMware (VMDK) disk detection */
kbdshortcut_result_t kbdshortcut_toggle_vmdk(int *enable_vmdk)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*enable_vmdk   = !*enable_vmdk;
	r.new_value    = *enable_vmdk;
	r.refresh_devs = 1;
	return r;
}

/* Alt+Y — force update check to succeed (sets version to 0.0.0 for check) */
kbdshortcut_result_t kbdshortcut_toggle_force_update(int *force_update)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*force_update = (*force_update > 0) ? 0 : 1;
	r.new_value   = *force_update;
	return r;
}

/* Ctrl+Alt+Y — force update (strict: force_update = 2 ignores timestamp errors) */
kbdshortcut_result_t kbdshortcut_toggle_force_update_strict(int *force_update)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*force_update = (*force_update > 0) ? 0 : 2;
	r.new_value   = *force_update;
	return r;
}

/* Alt+. (period) — toggle USB enumeration debug */
kbdshortcut_result_t kbdshortcut_toggle_usb_debug(int *usb_debug)
{
	kbdshortcut_result_t r = { 0, 1, 0 };  /* refresh_devs=1 */
	*usb_debug  = !*usb_debug;
	r.new_value = *usb_debug;
	return r;
}

/* Alt+, (comma) — toggle physical drive locking */
kbdshortcut_result_t kbdshortcut_toggle_lock_drive(int *lock_drive)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*lock_drive = !*lock_drive;
	r.new_value = *lock_drive;
	return r;
}

/* Alt+Q — toggle file indexing (for file systems that support it) */
kbdshortcut_result_t kbdshortcut_toggle_file_indexing(int *enable_file_indexing)
{
	kbdshortcut_result_t r = { 0, 0, 0 };
	*enable_file_indexing = !*enable_file_indexing;
	r.new_value           = *enable_file_indexing;
	return r;
}

/*
 * Ctrl+Alt+F — toggle listing of non-USB removable drives.
 * When enabling:  saves current enable_hdds value, then forces enable_hdds=1.
 * When disabling: restores the previously saved enable_hdds value.
 * Returns refresh_devs=1 always.
 */
kbdshortcut_result_t kbdshortcut_toggle_non_usb_removable(int *list_non_usb_removable,
                                                            int *enable_hdds,
                                                            int *prev_enable_hdds)
{
	kbdshortcut_result_t r = { 0, 1, 0 };
	*list_non_usb_removable = !*list_non_usb_removable;
	if (*list_non_usb_removable) {
		*prev_enable_hdds = *enable_hdds;
		*enable_hdds      = 1;
	} else {
		*enable_hdds = *prev_enable_hdds;
	}
	r.new_value = *list_non_usb_removable;
	return r;
}

/* --------------------------------------------------------------------- *
 * Zero-drive helpers                                                     *
 * --------------------------------------------------------------------- */

/* Alt+Z — zero the entire drive */
void kbdshortcut_zero_drive(int *zero_drive, int *fast_zeroing)
{
	*zero_drive   = 1;
	*fast_zeroing = 0;
}

/* Ctrl+Alt+Z — zero the drive while skipping empty blocks */
void kbdshortcut_fast_zero_drive(int *zero_drive, int *fast_zeroing)
{
	*zero_drive   = 1;
	*fast_zeroing = 1;
}

/* --------------------------------------------------------------------- *
 * Size-check enforcement                                                 *
 * --------------------------------------------------------------------- */

/*
 * Returns non-zero when the image is larger than the disk AND the size check
 * is currently enabled (size_check == 1).
 * Returns 0 when the image fits, or when size enforcement is bypassed.
 */
int kbdshortcut_size_check_fails(int size_check,
                                 unsigned long long projected_size,
                                 unsigned long long disk_size)
{
	if (!size_check)
		return 0;
	return (projected_size > disk_size) ? 1 : 0;
}
