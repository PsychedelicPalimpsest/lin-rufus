/*
 * Rufus: The Reliable USB Formatting Utility
 * Tests for GetMBRPartitionType() and GetGPTPartitionType()
 * from src/common/drive.c — cross-platform (Linux native + Wine/MinGW).
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Run:
 *   make -C tests test_partition_types_common_linux    (Linux native)
 *   make -C tests test_partition_types_common.exe      (MinGW / Wine)
 */

#include "framework.h"

/* Use the common drive header for function declarations */
#include "../src/common/drive.h"

/* For GUID construction in tests */
#include "../src/windows/rufus.h"

/* ---- helpers ------------------------------------------------------------ */

/* Construct a GUID from raw components (host byte order for Data1/2/3, raw
 * bytes for Data4) — matches the in-memory layout of DEFINE_GUID on both
 * little-endian Linux and Windows. */
static GUID make_guid(uint32_t d1, uint16_t d2, uint16_t d3,
                      uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3,
                      uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7)
{
    GUID g;
    g.Data1    = d1;
    g.Data2    = d2;
    g.Data3    = d3;
    g.Data4[0] = b0; g.Data4[1] = b1;
    g.Data4[2] = b2; g.Data4[3] = b3;
    g.Data4[4] = b4; g.Data4[5] = b5;
    g.Data4[6] = b6; g.Data4[7] = b7;
    return g;
}

/* ===================================================================== */
/* GetMBRPartitionType tests                                              */
/* ===================================================================== */

TEST(mbr_type_empty_partition)
{
    /* 0x00 = "Empty" */
    const char *name = GetMBRPartitionType(0x00);
    CHECK(name != NULL);
    CHECK_STR_EQ(name, "Empty");
}

TEST(mbr_type_fat16)
{
    const char *name = GetMBRPartitionType(0x06);
    CHECK(name != NULL);
    /* "FAT16" is in the name */
    CHECK(strstr(name, "FAT16") != NULL || strstr(name, "FAT") != NULL);
}

TEST(mbr_type_ntfs_exfat_udf)
{
    /* 0x07 covers NTFS / exFAT / UDF */
    const char *name = GetMBRPartitionType(0x07);
    CHECK(name != NULL);
    CHECK(strstr(name, "NTFS") != NULL || strstr(name, "exFAT") != NULL ||
          strstr(name, "UDF")  != NULL);
}

TEST(mbr_type_fat32)
{
    /* 0x0B = "FAT32" */
    const char *name = GetMBRPartitionType(0x0B);
    CHECK(name != NULL);
    CHECK_STR_EQ(name, "FAT32");
}

TEST(mbr_type_fat32_lba)
{
    /* 0x0C = "FAT32 LBA" */
    const char *name = GetMBRPartitionType(0x0C);
    CHECK(name != NULL);
    CHECK(strstr(name, "FAT32") != NULL);
    CHECK(strstr(name, "LBA")   != NULL || strstr(name, "lba") != NULL);
}

TEST(mbr_type_extended)
{
    /* 0x05 = "Extended" */
    const char *name = GetMBRPartitionType(0x05);
    CHECK(name != NULL);
    CHECK(strstr(name, "Extended") != NULL || strstr(name, "extended") != NULL);
}

TEST(mbr_type_linux_swap)
{
    /* 0x82 = "GNU/Linux Swap" */
    const char *name = GetMBRPartitionType(0x82);
    CHECK(name != NULL);
    CHECK(strstr(name, "Swap") != NULL || strstr(name, "swap") != NULL);
}

TEST(mbr_type_linux_data)
{
    /* 0x83 = "GNU/Linux" */
    const char *name = GetMBRPartitionType(0x83);
    CHECK(name != NULL);
    CHECK(strstr(name, "Linux") != NULL || strstr(name, "linux") != NULL);
}

TEST(mbr_type_linux_lvm)
{
    /* 0x8E = "GNU/Linux LVM" */
    const char *name = GetMBRPartitionType(0x8E);
    CHECK(name != NULL);
    CHECK(strstr(name, "LVM") != NULL || strstr(name, "Linux") != NULL);
}

TEST(mbr_type_freebsd)
{
    /* 0xA5 = FreeBSD */
    const char *name = GetMBRPartitionType(0xA5);
    CHECK(name != NULL);
    CHECK(strstr(name, "BSD") != NULL || strstr(name, "FreeBSD") != NULL);
}

TEST(mbr_type_efi_system_partition)
{
    /* 0xEF = "EFI System Partition" */
    const char *name = GetMBRPartitionType(0xEF);
    CHECK(name != NULL);
    CHECK(strstr(name, "EFI") != NULL);
}

TEST(mbr_type_linux_raid_auto)
{
    /* 0xFD = "GNU/Linux RAID Auto" */
    const char *name = GetMBRPartitionType(0xFD);
    CHECK(name != NULL);
    CHECK(strstr(name, "RAID") != NULL || strstr(name, "Linux") != NULL);
}

TEST(mbr_type_returns_non_null_for_any_byte)
{
    /* Every byte value must return a non-NULL string */
    int i;
    for (i = 0; i <= 255; i++) {
        const char *name = GetMBRPartitionType((uint8_t)i);
        CHECK(name != NULL);
    }
}

TEST(mbr_type_unknown_value_returns_unknown)
{
    /* 0xAA is not in the table → "Unknown" */
    const char *name = GetMBRPartitionType(0xAA);
    CHECK(name != NULL);
    CHECK_STR_EQ(name, "Unknown");
}

TEST(mbr_type_0xff_returns_unknown_or_known)
{
    /* 0xFF — may or may not be in the table; must not crash */
    const char *name = GetMBRPartitionType(0xFF);
    CHECK(name != NULL);
}

TEST(mbr_type_hidden_ntfs)
{
    /* 0x17 = "Hidden NTFS" */
    const char *name = GetMBRPartitionType(0x17);
    CHECK(name != NULL);
    CHECK(strstr(name, "NTFS") != NULL || strstr(name, "Hidden") != NULL);
}

TEST(mbr_type_hidden_fat32)
{
    /* 0x1B = "Hidden FAT32" */
    const char *name = GetMBRPartitionType(0x1B);
    CHECK(name != NULL);
    CHECK(strstr(name, "FAT32") != NULL || strstr(name, "Hidden") != NULL);
}

TEST(mbr_type_winre_hidden_ntfs)
{
    /* 0x27 = "Hidden NTFS WinRE" */
    const char *name = GetMBRPartitionType(0x27);
    CHECK(name != NULL);
    CHECK(strstr(name, "NTFS") != NULL || strstr(name, "Hidden") != NULL ||
          strstr(name, "WinRE") != NULL);
}

TEST(mbr_type_freedos_fat32)
{
    /* 0x97 or 0x98 = FreeDOS hidden FAT32 */
    const char *name97 = GetMBRPartitionType(0x97);
    const char *name98 = GetMBRPartitionType(0x98);
    CHECK(name97 != NULL);
    CHECK(name98 != NULL);
}

TEST(mbr_type_consistent_repeated_call)
{
    /* Calling the same type twice must return identical results */
    const char *a = GetMBRPartitionType(0x83);
    const char *b = GetMBRPartitionType(0x83);
    CHECK_STR_EQ(a, b);
}

/* ===================================================================== */
/* GetGPTPartitionType tests                                              */
/* ===================================================================== */

TEST(gpt_type_efi_system_partition)
{
    /* PARTITION_GENERIC_ESP: {C12A7328-F81F-11D2-BA4B-00A0C93EC93B} */
    GUID esp = make_guid(0xC12A7328, 0xF81F, 0x11D2,
                         0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B);
    const char *name = GetGPTPartitionType(&esp);
    CHECK(name != NULL);
    CHECK(strstr(name, "EFI") != NULL);
}

TEST(gpt_type_linux_data)
{
    /* PARTITION_LINUX_DATA: {0FC63DAF-8483-4772-8E79-3D69D8477DE4} */
    GUID ld = make_guid(0x0FC63DAF, 0x8483, 0x4772,
                        0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4);
    const char *name = GetGPTPartitionType(&ld);
    CHECK(name != NULL);
    CHECK(strstr(name, "Linux") != NULL || strstr(name, "Data") != NULL);
}

TEST(gpt_type_linux_swap)
{
    /* PARTITION_LINUX_SWAP: {0657FD6D-A4AB-43C4-84E5-0933C84B4F4F} */
    GUID ls = make_guid(0x0657FD6D, 0xA4AB, 0x43C4,
                        0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F);
    const char *name = GetGPTPartitionType(&ls);
    CHECK(name != NULL);
    CHECK(strstr(name, "Swap") != NULL || strstr(name, "swap") != NULL);
}

TEST(gpt_type_microsoft_basic_data)
{
    /* PARTITION_MICROSOFT_DATA: {EBD0A0A2-B9E5-4433-87C0-68B6B72699C7} */
    GUID md = make_guid(0xEBD0A0A2, 0xB9E5, 0x4433,
                        0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7);
    const char *name = GetGPTPartitionType(&md);
    CHECK(name != NULL);
    CHECK(strstr(name, "Basic") != NULL || strstr(name, "Data") != NULL ||
          strstr(name, "Microsoft") != NULL);
}

TEST(gpt_type_linux_lvm)
{
    /* PARTITION_LINUX_LVM: {E6D6D379-F507-44C2-A23C-238F2A3DF928} */
    GUID lv = make_guid(0xE6D6D379, 0xF507, 0x44C2,
                        0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28);
    const char *name = GetGPTPartitionType(&lv);
    CHECK(name != NULL);
    CHECK(strstr(name, "LVM") != NULL || strstr(name, "Linux") != NULL);
}

TEST(gpt_type_unknown_returns_guid_string)
{
    /* A completely unknown GUID must return a non-empty GUID string */
    GUID unk = make_guid(0x12345678, 0xABCD, 0xEF01,
                         0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01);
    const char *name = GetGPTPartitionType(&unk);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
    /* Should look like a GUID string (contains '-') */
    CHECK(strchr(name, '-') != NULL);
}

TEST(gpt_type_null_guid_returns_non_null)
{
    /* All-zero GUID — may or may not be in the table; must not crash */
    GUID zero;
    memset(&zero, 0, sizeof(zero));
    const char *name = GetGPTPartitionType(&zero);
    CHECK(name != NULL);
}

TEST(gpt_type_consistent_repeated_call)
{
    /* Same GUID twice returns identical string */
    GUID esp = make_guid(0xC12A7328, 0xF81F, 0x11D2,
                         0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B);
    const char *a = GetGPTPartitionType(&esp);
    const char *b = GetGPTPartitionType(&esp);
    CHECK_STR_EQ(a, b);
}

TEST(gpt_type_linux_boot)
{
    /* PARTITION_LINUX_BOOT: {BC13C2FF-59E6-4262-A352-B275FD6F7172} */
    GUID lb = make_guid(0xBC13C2FF, 0x59E6, 0x4262,
                        0xA3, 0x52, 0xB2, 0x75, 0xFD, 0x6F, 0x71, 0x72);
    const char *name = GetGPTPartitionType(&lb);
    CHECK(name != NULL);
    CHECK(strstr(name, "Linux") != NULL || strstr(name, "Boot") != NULL);
}

TEST(gpt_type_android_boot)
{
    /* PARTITION_ANDROID_BOOT: {49A4D17F-93A3-45C1-A0DE-F50B2EBE2599} */
    GUID ab = make_guid(0x49A4D17F, 0x93A3, 0x45C1,
                        0xA0, 0xDE, 0xF5, 0x0B, 0x2E, 0xBE, 0x25, 0x99);
    const char *name = GetGPTPartitionType(&ab);
    CHECK(name != NULL);
    CHECK(strstr(name, "Android") != NULL || strstr(name, "Boot") != NULL);
}

/* ===================================================================== */
/* main                                                                   */
/* ===================================================================== */

int main(void)
{
    /* MBR tests */
    RUN(mbr_type_empty_partition);
    RUN(mbr_type_fat16);
    RUN(mbr_type_ntfs_exfat_udf);
    RUN(mbr_type_fat32);
    RUN(mbr_type_fat32_lba);
    RUN(mbr_type_extended);
    RUN(mbr_type_linux_swap);
    RUN(mbr_type_linux_data);
    RUN(mbr_type_linux_lvm);
    RUN(mbr_type_freebsd);
    RUN(mbr_type_efi_system_partition);
    RUN(mbr_type_linux_raid_auto);
    RUN(mbr_type_returns_non_null_for_any_byte);
    RUN(mbr_type_unknown_value_returns_unknown);
    RUN(mbr_type_0xff_returns_unknown_or_known);
    RUN(mbr_type_hidden_ntfs);
    RUN(mbr_type_hidden_fat32);
    RUN(mbr_type_winre_hidden_ntfs);
    RUN(mbr_type_freedos_fat32);
    RUN(mbr_type_consistent_repeated_call);
    /* GPT tests */
    RUN(gpt_type_efi_system_partition);
    RUN(gpt_type_linux_data);
    RUN(gpt_type_linux_swap);
    RUN(gpt_type_microsoft_basic_data);
    RUN(gpt_type_linux_lvm);
    RUN(gpt_type_unknown_returns_guid_string);
    RUN(gpt_type_null_guid_returns_non_null);
    RUN(gpt_type_consistent_repeated_call);
    RUN(gpt_type_linux_boot);
    RUN(gpt_type_android_boot);
    TEST_RESULTS();
}
