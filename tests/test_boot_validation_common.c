/*
 * tests/test_boot_validation_common.c
 * Cross-platform unit tests for the boot-time validation predicates
 * from src/common/boot_validation.c.
 *
 * Runs on Linux (native) and Windows (Wine / MinGW cross-compile).
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2025 PsychedelicPalimpsest
 */

#include "framework.h"

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include "../src/windows/rufus.h"
#else
#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/winioctl.h"
#include "../src/windows/rufus.h"
#endif

#include "../src/common/boot_validation.h"

/* =========================================================
 * boot_check_is_pure_dd
 * ========================================================= */

TEST(pure_dd_true_when_bootable_and_not_iso)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    r.is_iso          = FALSE;
    CHECK(boot_check_is_pure_dd(r) == TRUE);
}

TEST(pure_dd_false_when_iso)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    r.is_iso          = TRUE;
    CHECK(boot_check_is_pure_dd(r) == FALSE);
}

TEST(pure_dd_false_when_not_bootable)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 0;
    r.is_iso          = FALSE;
    CHECK(boot_check_is_pure_dd(r) == FALSE);
}

TEST(pure_dd_true_when_disable_iso_and_not_iso)
{
    /*
     * IS_DD_BOOTABLE = is_bootable_img > 0 — does NOT inspect disable_iso.
     * disable_iso=TRUE + is_iso=FALSE still means pure DD.
     */
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    r.disable_iso     = TRUE;
    r.is_iso          = FALSE;
    CHECK(boot_check_is_pure_dd(r) == TRUE);
}

TEST(pure_dd_false_when_zero_bootable)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 0;
    r.is_iso          = FALSE;
    CHECK(boot_check_is_pure_dd(r) == FALSE);
}

/* =========================================================
 * boot_check_can_write_as_esp
 * ========================================================= */

TEST(can_write_esp_true_small_efi_gpt_fat32)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = 512 * 1024 * 1024ULL; /* 512 MB < 1 GB limit */
    r.has_efi = 0x02;                        /* HAS_REGULAR_EFI */
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_GPT, FS_FAT32) == TRUE);
}

TEST(can_write_esp_false_too_large)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = 2ULL * 1024 * 1024 * 1024; /* 2 GB > 1 GB limit */
    r.has_efi = 0x02;
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_GPT, FS_FAT32) == FALSE);
}

TEST(can_write_esp_false_not_gpt)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = 512 * 1024 * 1024ULL;
    r.has_efi = 0x02;
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_MBR, FS_FAT32) == FALSE);
}

TEST(can_write_esp_false_not_fat)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = 512 * 1024 * 1024ULL;
    r.has_efi = 0x02;
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_GPT, FS_NTFS) == FALSE);
}

TEST(can_write_esp_false_no_efi)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = 512 * 1024 * 1024ULL;
    r.has_efi = 0; /* no EFI bootloader */
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_GPT, FS_FAT32) == FALSE);
}

TEST(can_write_esp_true_fat16)
{
    /* FAT16 is still IS_FAT() */
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = 64 * 1024 * 1024ULL;
    r.has_efi = 0x02;
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_GPT, FS_FAT16) == TRUE);
}

TEST(can_write_esp_false_exactly_at_limit)
{
    /* MAX_ISO_TO_ESP_SIZE is 1 GiB (1<<30); exactly at limit → fail (< not <=) */
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = MAX_ISO_TO_ESP_SIZE;
    r.has_efi = 0x02;
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_GPT, FS_FAT32) == FALSE);
}

/* =========================================================
 * boot_check_uefi_compat_fails
 * ========================================================= */

TEST(uefi_compat_fails_when_uefi_and_no_efi)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_efi = 0;
    CHECK(boot_check_uefi_compat_fails(r, TT_UEFI) == TRUE);
}

TEST(uefi_compat_ok_when_uefi_and_has_efi)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_efi = 0x02;
    CHECK(boot_check_uefi_compat_fails(r, TT_UEFI) == FALSE);
}

TEST(uefi_compat_ok_when_bios_target)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_efi = 0;
    CHECK(boot_check_uefi_compat_fails(r, TT_BIOS) == FALSE);
}

TEST(uefi_compat_ok_when_non_uefi_target)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_efi = 0;
    /* Any target that is not TT_UEFI: use TT_MAX as a sentinel */
    CHECK(boot_check_uefi_compat_fails(r, TT_MAX) == FALSE);
}

/* =========================================================
 * boot_check_fat_4gb_fails
 * ========================================================= */

TEST(fat_4gb_fails_when_fat32_and_4gb_file)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_4GB_file = 1;
    CHECK(boot_check_fat_4gb_fails(r, FS_FAT32) == TRUE);
}

TEST(fat_4gb_fails_when_fat16_and_4gb_file)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_4GB_file = 2;
    CHECK(boot_check_fat_4gb_fails(r, FS_FAT16) == TRUE);
}

TEST(fat_4gb_ok_when_ntfs_and_4gb_file)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_4GB_file = 1;
    CHECK(boot_check_fat_4gb_fails(r, FS_NTFS) == FALSE);
}

TEST(fat_4gb_ok_when_fat_but_no_4gb_file)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_4GB_file = 0;
    CHECK(boot_check_fat_4gb_fails(r, FS_FAT32) == FALSE);
}

TEST(fat_4gb_ok_special_0x11_split_wim)
{
    /* has_4GB_file == 0x11: split WIM pair — exempt on both Windows and Linux */
    RUFUS_IMG_REPORT r = { 0 };
    r.has_4GB_file = 0x11;
    CHECK(boot_check_fat_4gb_fails(r, FS_FAT32) == FALSE);
}

TEST(fat_4gb_ok_exfat_with_4gb_file)
{
    /* exFAT supports files > 4 GB */
    RUFUS_IMG_REPORT r = { 0 };
    r.has_4GB_file = 1;
    CHECK(boot_check_fat_4gb_fails(r, FS_EXFAT) == FALSE);
}

/* =========================================================
 * boot_check_fat_compat_fails
 * ========================================================= */

TEST(fat_compat_fails_ntfs_non_windows_non_grub_syslinux_v5)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.sl_version = 0x0500; /* SL_MAJOR == 5 */
    CHECK(boot_check_fat_compat_fails(r, FS_NTFS, TT_BIOS, FALSE) == TRUE);
}

TEST(fat_compat_ok_ntfs_with_grub)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_grub2 = 1;
    CHECK(boot_check_fat_compat_fails(r, FS_NTFS, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_ok_ntfs_with_windows)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_bootmgr = 1; /* HAS_BOOTMGR → HAS_WINDOWS */
    CHECK(boot_check_fat_compat_fails(r, FS_NTFS, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_ok_ntfs_syslinux_v6_or_above)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.sl_version = 0x0600; /* SL_MAJOR == 6 > 5 */
    CHECK(boot_check_fat_compat_fails(r, FS_NTFS, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_fails_fat_no_syslinux_no_efi_no_grub)
{
    RUFUS_IMG_REPORT r = { 0 }; /* all zero */
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == TRUE);
}

TEST(fat_compat_ok_fat_with_syslinux)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.sl_version = 0x0600; /* Syslinux 6 */
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_ok_fat_with_grub)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_grub2 = 1;
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_ok_fat_with_efi)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_efi = 0x02;
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_ok_fat_with_reactos)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.reactos_path[0] = 'x'; /* HAS_REACTOS: reactos_path[0] != 0 */
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_ok_fat_with_kolibrios)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_kolibrios = 1;
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_fails_fat_windows_no_dual)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_bootmgr = 1;
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == TRUE);
}

TEST(fat_compat_ok_fat_windows_with_dual)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_bootmgr = 1;
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, TRUE) == FALSE);
}

TEST(fat_compat_fails_fat_wininst_no_dual)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.wininst_index = 1; /* HAS_WININST: wininst_index != 0 */
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == TRUE);
}

TEST(fat_compat_ok_fat_wininst_with_dual)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.wininst_index = 1; /* HAS_WININST: wininst_index != 0 */
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, TRUE) == FALSE);
}

/* =========================================================
 * boot_check_fat16_kolibrios_fails
 * ========================================================= */

TEST(fat16_kolibrios_fails_when_fat16_and_kolibrios)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_kolibrios = 1;
    CHECK(boot_check_fat16_kolibrios_fails(r, FS_FAT16) == TRUE);
}

TEST(fat16_kolibrios_ok_fat32_kolibrios)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_kolibrios = 1;
    CHECK(boot_check_fat16_kolibrios_fails(r, FS_FAT32) == FALSE);
}

TEST(fat16_kolibrios_ok_fat16_no_kolibrios)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_kolibrios = 0;
    CHECK(boot_check_fat16_kolibrios_fails(r, FS_FAT16) == FALSE);
}

TEST(fat16_kolibrios_ok_ntfs_kolibrios)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_kolibrios = 1;
    CHECK(boot_check_fat16_kolibrios_fails(r, FS_NTFS) == FALSE);
}

int main(void)
{
    printf("=== boot_check_is_pure_dd ===\n");
    RUN(pure_dd_true_when_bootable_and_not_iso);
    RUN(pure_dd_false_when_iso);
    RUN(pure_dd_false_when_not_bootable);
    RUN(pure_dd_true_when_disable_iso_and_not_iso);
    RUN(pure_dd_false_when_zero_bootable);

    printf("\n=== boot_check_can_write_as_esp ===\n");
    RUN(can_write_esp_true_small_efi_gpt_fat32);
    RUN(can_write_esp_false_too_large);
    RUN(can_write_esp_false_not_gpt);
    RUN(can_write_esp_false_not_fat);
    RUN(can_write_esp_false_no_efi);
    RUN(can_write_esp_true_fat16);
    RUN(can_write_esp_false_exactly_at_limit);

    printf("\n=== boot_check_uefi_compat_fails ===\n");
    RUN(uefi_compat_fails_when_uefi_and_no_efi);
    RUN(uefi_compat_ok_when_uefi_and_has_efi);
    RUN(uefi_compat_ok_when_bios_target);
    RUN(uefi_compat_ok_when_non_uefi_target);

    printf("\n=== boot_check_fat_4gb_fails ===\n");
    RUN(fat_4gb_fails_when_fat32_and_4gb_file);
    RUN(fat_4gb_fails_when_fat16_and_4gb_file);
    RUN(fat_4gb_ok_when_ntfs_and_4gb_file);
    RUN(fat_4gb_ok_when_fat_but_no_4gb_file);
    RUN(fat_4gb_ok_special_0x11_split_wim);
    RUN(fat_4gb_ok_exfat_with_4gb_file);

    printf("\n=== boot_check_fat_compat_fails ===\n");
    RUN(fat_compat_fails_ntfs_non_windows_non_grub_syslinux_v5);
    RUN(fat_compat_ok_ntfs_with_grub);
    RUN(fat_compat_ok_ntfs_with_windows);
    RUN(fat_compat_ok_ntfs_syslinux_v6_or_above);
    RUN(fat_compat_fails_fat_no_syslinux_no_efi_no_grub);
    RUN(fat_compat_ok_fat_with_syslinux);
    RUN(fat_compat_ok_fat_with_grub);
    RUN(fat_compat_ok_fat_with_efi);
    RUN(fat_compat_ok_fat_with_reactos);
    RUN(fat_compat_ok_fat_with_kolibrios);
    RUN(fat_compat_fails_fat_windows_no_dual);
    RUN(fat_compat_ok_fat_windows_with_dual);
    RUN(fat_compat_fails_fat_wininst_no_dual);
    RUN(fat_compat_ok_fat_wininst_with_dual);

    printf("\n=== boot_check_fat16_kolibrios_fails ===\n");
    RUN(fat16_kolibrios_fails_when_fat16_and_kolibrios);
    RUN(fat16_kolibrios_ok_fat32_kolibrios);
    RUN(fat16_kolibrios_ok_fat16_no_kolibrios);
    RUN(fat16_kolibrios_ok_ntfs_kolibrios);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
