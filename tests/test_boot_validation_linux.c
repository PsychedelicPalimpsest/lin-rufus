/*
 * tests/test_boot_validation_linux.c
 * Unit tests for boot_validation.c predicates (pure C, no GTK)
 */
#include "../src/linux/boot_validation.h"
#include "../src/linux/compat/winioctl.h"   /* PARTITION_STYLE_GPT/MBR */
#include "framework.h"
#include <string.h>

/* =========================================================
 * boot_check_is_pure_dd
 * ========================================================= */

TEST(pure_dd_true_when_bootable_and_not_iso)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;   /* IS_DD_BOOTABLE(r) == TRUE */
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
    /* IS_DD_BOOTABLE = is_bootable_img > 0 (does NOT check disable_iso).
     * With disable_iso=TRUE and is_iso=FALSE the image is still a pure DD
     * image and must be written as DD. */
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    r.disable_iso     = TRUE;
    r.is_iso          = FALSE;
    CHECK(boot_check_is_pure_dd(r) == TRUE);
}

/* =========================================================
 * boot_check_can_write_as_esp
 * ========================================================= */

TEST(can_write_esp_true_small_efi_gpt_fat)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = 512 * 1024 * 1024ULL;  /* 512 MB < 1 GB limit */
    r.has_efi = 0x02;  /* HAS_REGULAR_EFI: (r.has_efi & 0x7FFE) != 0 */
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_GPT, FS_FAT32) == TRUE);
}

TEST(can_write_esp_false_too_large)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = 2ULL * 1024 * 1024 * 1024;  /* 2 GB > 1 GB limit */
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
    r.has_efi = 0;  /* no EFI bootloader */
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_GPT, FS_FAT32) == FALSE);
}

TEST(can_write_esp_true_fat16)
{
    /* FAT16 is still FAT */
    RUFUS_IMG_REPORT r = { 0 };
    r.projected_size = 64 * 1024 * 1024ULL;
    r.has_efi = 0x02;
    CHECK(boot_check_can_write_as_esp(r, PARTITION_STYLE_GPT, FS_FAT16) == TRUE);
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

/* =========================================================
 * boot_check_fat_4gb_fails
 * ========================================================= */

TEST(fat_4gb_fails_when_fat32_and_4gb_file)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_4GB_file = 1;  /* non-zero, not the special 0x11 value */
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
    /* has_4GB_file == 0x11: split WIM pair — Windows exempts it, we do too */
    RUFUS_IMG_REPORT r = { 0 };
    r.has_4GB_file = 0x11;
    CHECK(boot_check_fat_4gb_fails(r, FS_FAT32) == FALSE);
}

/* =========================================================
 * boot_check_fat_compat_fails
 * ========================================================= */

TEST(fat_compat_fails_ntfs_non_windows_non_grub_syslinux_v5_or_less)
{
    /* NTFS selected but no Windows/Grub, and Syslinux ≤ 5 → fail */
    RUFUS_IMG_REPORT r = { 0 };
    r.sl_version = 0x0500;   /* SL_MAJOR == 5 */
    /* no HAS_WINDOWS, no HAS_GRUB */
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
    r.has_bootmgr = 1;   /* HAS_BOOTMGR → HAS_WINDOWS */
    CHECK(boot_check_fat_compat_fails(r, FS_NTFS, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_fails_fat_no_syslinux_no_efi_no_grub_no_reactos)
{
    /* FAT + no Syslinux + no dual + not EFI + no ReactOS + no KolibriOS + no Grub → fail */
    RUFUS_IMG_REPORT r = { 0 };
    /* all fields zero */
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == TRUE);
}

TEST(fat_compat_ok_fat_with_syslinux)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.sl_version = 0x0600;   /* Syslinux 6 */
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_ok_fat_with_grub)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_grub2 = 1;
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == FALSE);
}

TEST(fat_compat_fails_fat_windows_no_dual)
{
    /* FAT + Windows image + no allow_dual → fail */
    RUFUS_IMG_REPORT r = { 0 };
    r.has_bootmgr = 1;
    CHECK(boot_check_fat_compat_fails(r, FS_FAT32, TT_BIOS, FALSE) == TRUE);
}

TEST(fat_compat_ok_fat_windows_with_dual)
{
    /* FAT + Windows image + allow_dual_uefi_bios → OK */
    RUFUS_IMG_REPORT r = { 0 };
    r.has_bootmgr = 1;
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

int main(void)
{
    printf("=== boot_check_is_pure_dd tests ===\n");
    RUN(pure_dd_true_when_bootable_and_not_iso);
    RUN(pure_dd_false_when_iso);
    RUN(pure_dd_false_when_not_bootable);
    RUN(pure_dd_true_when_disable_iso_and_not_iso);

    printf("\n=== boot_check_can_write_as_esp tests ===\n");
    RUN(can_write_esp_true_small_efi_gpt_fat);
    RUN(can_write_esp_false_too_large);
    RUN(can_write_esp_false_not_gpt);
    RUN(can_write_esp_false_not_fat);
    RUN(can_write_esp_false_no_efi);
    RUN(can_write_esp_true_fat16);

    printf("\n=== boot_check_uefi_compat_fails tests ===\n");
    RUN(uefi_compat_fails_when_uefi_and_no_efi);
    RUN(uefi_compat_ok_when_uefi_and_has_efi);
    RUN(uefi_compat_ok_when_bios_target);

    printf("\n=== boot_check_fat_4gb_fails tests ===\n");
    RUN(fat_4gb_fails_when_fat32_and_4gb_file);
    RUN(fat_4gb_fails_when_fat16_and_4gb_file);
    RUN(fat_4gb_ok_when_ntfs_and_4gb_file);
    RUN(fat_4gb_ok_when_fat_but_no_4gb_file);
    RUN(fat_4gb_ok_special_0x11_split_wim);

    printf("\n=== boot_check_fat_compat_fails tests ===\n");
    RUN(fat_compat_fails_ntfs_non_windows_non_grub_syslinux_v5_or_less);
    RUN(fat_compat_ok_ntfs_with_grub);
    RUN(fat_compat_ok_ntfs_with_windows);
    RUN(fat_compat_fails_fat_no_syslinux_no_efi_no_grub_no_reactos);
    RUN(fat_compat_ok_fat_with_syslinux);
    RUN(fat_compat_ok_fat_with_grub);
    RUN(fat_compat_fails_fat_windows_no_dual);
    RUN(fat_compat_ok_fat_windows_with_dual);

    printf("\n=== boot_check_fat16_kolibrios_fails tests ===\n");
    RUN(fat16_kolibrios_fails_when_fat16_and_kolibrios);
    RUN(fat16_kolibrios_ok_fat32_kolibrios);
    RUN(fat16_kolibrios_ok_fat16_no_kolibrios);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
