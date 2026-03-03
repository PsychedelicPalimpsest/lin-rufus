/*
 * test_ui_enable_opts_linux.c — Tests for ui_enable_opts.c condition predicates
 *
 * Copyright © 2025 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "framework.h"

#define RUFUS_TEST
#include "../src/linux/ui_enable_opts.c"

/* Helper: blank image report */
static RUFUS_IMG_REPORT blank_report(void) {
RUFUS_IMG_REPORT r;
memset(&r, 0, sizeof(r));
return r;
}

/* Helper: EFI-bootable ISO */
static RUFUS_IMG_REPORT efi_iso(void) {
RUFUS_IMG_REPORT r = blank_report();
r.has_efi = 1;           /* IS_EFI_BOOTABLE */
r.is_iso = 1;
return r;
}

/* Helper: BIOS-bootable ISO (syslinux) */
static RUFUS_IMG_REPORT bios_iso(void) {
RUFUS_IMG_REPORT r = blank_report();
r.sl_version = 1;      /* IS_BIOS_BOOTABLE via HAS_SYSLINUX */
r.is_iso = 1;
return r;
}

/* Helper: DD-only image */
static RUFUS_IMG_REPORT dd_only_img(void) {
RUFUS_IMG_REPORT r = blank_report();
r.is_bootable_img = 1;
r.is_iso = 0;            /* IS_DD_ONLY requires is_bootable_img && (!is_iso || disable_iso) */
return r;
}

/* Helper: Windows image (has bootmgr → HAS_WINDOWS) */
static RUFUS_IMG_REPORT windows_iso(void) {
RUFUS_IMG_REPORT r = blank_report();
r.has_bootmgr = 1;       /* HAS_BOOTMGR → HAS_WINDOWS */
r.has_efi = 1;
r.is_iso = 1;
return r;
}

/* ==================== should_enable_old_bios ==================== */

TEST(old_bios_null_report) {
CHECK(!should_enable_old_bios(PARTITION_STYLE_MBR, TT_BIOS, BT_IMAGE, NULL));
}

TEST(old_bios_enabled_for_mbr_bios_bios_iso) {
RUFUS_IMG_REPORT r = bios_iso();
CHECK(should_enable_old_bios(PARTITION_STYLE_MBR, TT_BIOS, BT_IMAGE, &r));
}

TEST(old_bios_disabled_for_gpt) {
RUFUS_IMG_REPORT r = bios_iso();
CHECK(!should_enable_old_bios(PARTITION_STYLE_GPT, TT_BIOS, BT_IMAGE, &r));
}

TEST(old_bios_disabled_for_uefi_target) {
RUFUS_IMG_REPORT r = bios_iso();
CHECK(!should_enable_old_bios(PARTITION_STYLE_MBR, TT_UEFI, BT_IMAGE, &r));
}

TEST(old_bios_disabled_for_non_bootable_boot_type) {
RUFUS_IMG_REPORT r = bios_iso();
CHECK(!should_enable_old_bios(PARTITION_STYLE_MBR, TT_BIOS, BT_NON_BOOTABLE, &r));
}

TEST(old_bios_disabled_for_dd_only_image) {
RUFUS_IMG_REPORT r = dd_only_img();
CHECK(!should_enable_old_bios(PARTITION_STYLE_MBR, TT_BIOS, BT_IMAGE, &r));
}

TEST(old_bios_disabled_for_non_bios_bootable_image) {
/* EFI-only image (no syslinux/bootmgr/grub) with MBR+BIOS */
RUFUS_IMG_REPORT r = efi_iso();
CHECK(!should_enable_old_bios(PARTITION_STYLE_MBR, TT_BIOS, BT_IMAGE, &r));
}

TEST(old_bios_enabled_for_freedos) {
/* FreeDOS is BT_FREEDOS, not BT_IMAGE */
RUFUS_IMG_REPORT r = blank_report();
CHECK(should_enable_old_bios(PARTITION_STYLE_MBR, TT_BIOS, BT_FREEDOS, &r));
}

TEST(old_bios_enabled_for_syslinux_boot_type) {
RUFUS_IMG_REPORT r = blank_report();
CHECK(should_enable_old_bios(PARTITION_STYLE_MBR, TT_BIOS, BT_SYSLINUX_V6, &r));
}

/* ==================== should_enable_uefi_validation ==================== */

TEST(uefi_val_null_report) {
CHECK(!should_enable_uefi_validation(BT_IMAGE, TT_UEFI, 0, 0, FALSE, NULL));
}

TEST(uefi_val_enabled_for_efi_iso) {
RUFUS_IMG_REPORT r = efi_iso();
CHECK(should_enable_uefi_validation(BT_IMAGE, TT_UEFI, 0, 0, FALSE, &r));
}

TEST(uefi_val_disabled_for_non_image_boot_type) {
RUFUS_IMG_REPORT r = efi_iso();
CHECK(!should_enable_uefi_validation(BT_FREEDOS, TT_UEFI, 0, 0, FALSE, &r));
}

TEST(uefi_val_disabled_for_non_efi_image) {
RUFUS_IMG_REPORT r = bios_iso();  /* no has_efi */
CHECK(!should_enable_uefi_validation(BT_IMAGE, TT_UEFI, 0, 0, FALSE, &r));
}

TEST(uefi_val_disabled_for_dd_only) {
RUFUS_IMG_REPORT r = dd_only_img();
r.has_efi = 1;
CHECK(!should_enable_uefi_validation(BT_IMAGE, TT_UEFI, 0, 0, FALSE, &r));
}

TEST(uefi_val_disabled_for_wintogo_selected) {
RUFUS_IMG_REPORT r = windows_iso();
CHECK(!should_enable_uefi_validation(BT_IMAGE, TT_UEFI,
                                     IMOP_WINTOGO, IMOP_WIN_TO_GO, FALSE, &r));
}

TEST(uefi_val_enabled_for_wintogo_flag_but_not_selected) {
/* IMOP_WINTOGO set but imop_sel != IMOP_WIN_TO_GO */
RUFUS_IMG_REPORT r = windows_iso();
CHECK(should_enable_uefi_validation(BT_IMAGE, TT_UEFI,
                                    IMOP_WINTOGO, IMOP_WIN_STANDARD, FALSE, &r));
}

TEST(uefi_val_disabled_for_bios_target_windows_no_dual) {
RUFUS_IMG_REPORT r = windows_iso();
CHECK(!should_enable_uefi_validation(BT_IMAGE, TT_BIOS, 0, 0, FALSE, &r));
}

TEST(uefi_val_enabled_for_bios_target_windows_with_dual) {
RUFUS_IMG_REPORT r = windows_iso();
CHECK(should_enable_uefi_validation(BT_IMAGE, TT_BIOS, 0, 0, TRUE, &r));
}

TEST(uefi_val_enabled_for_bios_target_non_windows) {
/* Non-Windows EFI ISO with BIOS target */
RUFUS_IMG_REPORT r = efi_iso();
CHECK(should_enable_uefi_validation(BT_IMAGE, TT_BIOS, 0, 0, FALSE, &r));
}

/* ==================== should_enable_extended_label ==================== */

TEST(ext_label_null_report) {
CHECK(!should_enable_extended_label(FS_FAT32, BT_IMAGE, NULL));
}

TEST(ext_label_enabled_for_fat32_non_dd) {
RUFUS_IMG_REPORT r = efi_iso();
CHECK(should_enable_extended_label(FS_FAT32, BT_IMAGE, &r));
}

TEST(ext_label_disabled_for_ext2) {
RUFUS_IMG_REPORT r = blank_report();
CHECK(!should_enable_extended_label(FS_EXT2, BT_NON_BOOTABLE, &r));
}

TEST(ext_label_disabled_for_ext3) {
RUFUS_IMG_REPORT r = blank_report();
CHECK(!should_enable_extended_label(FS_EXT3, BT_NON_BOOTABLE, &r));
}

TEST(ext_label_disabled_for_ext4) {
RUFUS_IMG_REPORT r = blank_report();
CHECK(!should_enable_extended_label(FS_EXT4, BT_NON_BOOTABLE, &r));
}

TEST(ext_label_disabled_for_dd_only_image) {
RUFUS_IMG_REPORT r = dd_only_img();
CHECK(!should_enable_extended_label(FS_FAT32, BT_IMAGE, &r));
}

TEST(ext_label_enabled_for_ntfs) {
RUFUS_IMG_REPORT r = blank_report();
CHECK(should_enable_extended_label(FS_NTFS, BT_NON_BOOTABLE, &r));
}

TEST(ext_label_enabled_for_non_bootable) {
RUFUS_IMG_REPORT r = blank_report();
CHECK(should_enable_extended_label(FS_FAT32, BT_NON_BOOTABLE, &r));
}

/* ==================== should_enable_quick_format ==================== */

TEST(quick_format_null_report) {
CHECK(!should_enable_quick_format(FS_FAT32, BT_IMAGE, FALSE, 16 * 1024 * 1024ULL, NULL));
}

TEST(quick_format_enabled_normally) {
RUFUS_IMG_REPORT r = efi_iso();
CHECK(should_enable_quick_format(FS_FAT32, BT_IMAGE, FALSE, 16 * 1024 * 1024ULL, &r));
}

TEST(quick_format_disabled_for_dd_only) {
RUFUS_IMG_REPORT r = dd_only_img();
CHECK(!should_enable_quick_format(FS_FAT32, BT_IMAGE, FALSE, 16 * 1024 * 1024ULL, &r));
}

TEST(quick_format_disabled_for_large_fat32) {
RUFUS_IMG_REPORT r = blank_report();
/* 64 GB > LARGE_FAT32_SIZE (32 GB) */
CHECK(!should_enable_quick_format(FS_FAT32, BT_NON_BOOTABLE, FALSE,
                                   64ULL * 1024 * 1024 * 1024, &r));
}

TEST(quick_format_disabled_when_force_large_fat32) {
RUFUS_IMG_REPORT r = blank_report();
/* Even on a 16 MB FAT32, force_large_fat32 disables user choice */
CHECK(!should_enable_quick_format(FS_FAT32, BT_NON_BOOTABLE, TRUE,
                                   16 * 1024 * 1024ULL, &r));
}

TEST(quick_format_enabled_for_ntfs_normal_size) {
RUFUS_IMG_REPORT r = blank_report();
CHECK(should_enable_quick_format(FS_NTFS, BT_NON_BOOTABLE, FALSE,
                                  8ULL * 1024 * 1024 * 1024, &r));
}

/* ==================== should_force_quick_format ==================== */

TEST(force_quick_format_false_for_small_fat32) {
CHECK(!should_force_quick_format(FS_FAT32, FALSE, 16 * 1024 * 1024ULL));
}

TEST(force_quick_format_true_for_large_fat32) {
CHECK(should_force_quick_format(FS_FAT32, FALSE, 64ULL * 1024 * 1024 * 1024));
}

TEST(force_quick_format_true_when_flag_set) {
CHECK(should_force_quick_format(FS_FAT32, TRUE, 16 * 1024 * 1024ULL));
}

TEST(force_quick_format_false_for_ntfs) {
CHECK(!should_force_quick_format(FS_NTFS, FALSE, 64ULL * 1024 * 1024 * 1024));
}

TEST(force_quick_format_true_for_refs) {
CHECK(should_force_quick_format(FS_REFS, FALSE, 16 * 1024 * 1024ULL));
}

int main(void) {
/* should_enable_old_bios */
RUN(old_bios_null_report);
RUN(old_bios_enabled_for_mbr_bios_bios_iso);
RUN(old_bios_disabled_for_gpt);
RUN(old_bios_disabled_for_uefi_target);
RUN(old_bios_disabled_for_non_bootable_boot_type);
RUN(old_bios_disabled_for_dd_only_image);
RUN(old_bios_disabled_for_non_bios_bootable_image);
RUN(old_bios_enabled_for_freedos);
RUN(old_bios_enabled_for_syslinux_boot_type);

/* should_enable_uefi_validation */
RUN(uefi_val_null_report);
RUN(uefi_val_enabled_for_efi_iso);
RUN(uefi_val_disabled_for_non_image_boot_type);
RUN(uefi_val_disabled_for_non_efi_image);
RUN(uefi_val_disabled_for_dd_only);
RUN(uefi_val_disabled_for_wintogo_selected);
RUN(uefi_val_enabled_for_wintogo_flag_but_not_selected);
RUN(uefi_val_disabled_for_bios_target_windows_no_dual);
RUN(uefi_val_enabled_for_bios_target_windows_with_dual);
RUN(uefi_val_enabled_for_bios_target_non_windows);

/* should_enable_extended_label */
RUN(ext_label_null_report);
RUN(ext_label_enabled_for_fat32_non_dd);
RUN(ext_label_disabled_for_ext2);
RUN(ext_label_disabled_for_ext3);
RUN(ext_label_disabled_for_ext4);
RUN(ext_label_disabled_for_dd_only_image);
RUN(ext_label_enabled_for_ntfs);
RUN(ext_label_enabled_for_non_bootable);

/* should_enable_quick_format */
RUN(quick_format_null_report);
RUN(quick_format_enabled_normally);
RUN(quick_format_disabled_for_dd_only);
RUN(quick_format_disabled_for_large_fat32);
RUN(quick_format_disabled_when_force_large_fat32);
RUN(quick_format_enabled_for_ntfs_normal_size);

/* should_force_quick_format */
RUN(force_quick_format_false_for_small_fat32);
RUN(force_quick_format_true_for_large_fat32);
RUN(force_quick_format_true_when_flag_set);
RUN(force_quick_format_false_for_ntfs);
RUN(force_quick_format_true_for_refs);

TEST_RESULTS();
}
