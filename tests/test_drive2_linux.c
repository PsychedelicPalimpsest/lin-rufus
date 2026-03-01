/*
 * test_drive2_linux.c — Tests for additional linux/drive.c functions
 *
 * Covers:
 *  1. CompareGUID         — GUID equality comparison (linux/stdfn.c)
 *  2. GuidToString        — GUID → string conversion (linux/stdio.c)
 *  3. StringToGuid        — string → GUID conversion (linux/stdio.c)
 *  4. GetMBRPartitionType — MBR partition type lookup
 *  5. GetGPTPartitionType — GPT partition type lookup
 *  6. AnalyzeMBR          — boot-sector MBR analysis (uses ms-sys)
 *  7. AnalyzePBR          — partition boot record analysis (uses ms-sys)
 *  8. RefreshLayout       — kernel partition-table refresh by DriveIndex
 *  9. GetDriveTypeFromIndex — drive type (fixed/removable/USB) from sysfs
 * 10. GetDriveLabel       — filesystem label via libblkid
 */

#include "framework.h"

/*
 * Pull in the Linux drive.c internal API (drive_linux_reset_drives, etc.)
 * and the stdfn + stdio headers for CompareGUID / GuidToString.
 */
#include "../src/linux/drive_linux.h"
#include "../src/windows/rufus.h"   /* MAX_GUID_STRING_LENGTH, BOOL, etc.  */
#include "../src/windows/drive.h"   /* GetMBRPartitionType, GetGPTPartitionType */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* -------------------------------------------------------------------------
 * Helper: create a temporary file with the given size, returns fd.
 * --------------------------------------------------------------------- */
static int make_temp(char path[64], size_t size)
{
    strcpy(path, "/tmp/rufus_d2_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    if (size > 0 && ftruncate(fd, (off_t)size) != 0) {
        close(fd); unlink(path); return -1;
    }
    return fd;
}

/* -------------------------------------------------------------------------
 * External declarations (functions declared in rufus.h / drive.h)
 * --------------------------------------------------------------------- */
extern BOOL CompareGUID(const GUID *guid1, const GUID *guid2);
extern char *GuidToString(const GUID *guid, BOOL bDecorated);
extern GUID *StringToGuid(const char *str);
extern UINT GetDriveTypeFromIndex(DWORD DriveIndex);
extern BOOL GetDriveLabel(DWORD DriveIndex, char *letters,
                          char **label, BOOL bSilent);

/* =========================================================================
 * 1. CompareGUID
 * ======================================================================= */

TEST(compare_guid_equal)
{
    GUID a = { 0x12345678, 0x1234, 0x1234, { 1,2,3,4,5,6,7,8 } };
    GUID b = { 0x12345678, 0x1234, 0x1234, { 1,2,3,4,5,6,7,8 } };
    CHECK(CompareGUID(&a, &b) == TRUE);
}

TEST(compare_guid_different_data1)
{
    GUID a = { 0xAAAAAAAA, 0x1234, 0x1234, { 1,2,3,4,5,6,7,8 } };
    GUID b = { 0xBBBBBBBB, 0x1234, 0x1234, { 1,2,3,4,5,6,7,8 } };
    CHECK(CompareGUID(&a, &b) == FALSE);
}

TEST(compare_guid_different_data4)
{
    GUID a = { 0x12345678, 0x1234, 0x1234, { 1,2,3,4,5,6,7,8 } };
    GUID b = { 0x12345678, 0x1234, 0x1234, { 1,2,3,4,5,6,7,9 } };
    CHECK(CompareGUID(&a, &b) == FALSE);
}

TEST(compare_guid_null_first)
{
    GUID a = { 0, 0, 0, {0} };
    CHECK(CompareGUID(NULL, &a) == FALSE);
}

TEST(compare_guid_null_second)
{
    GUID a = { 0, 0, 0, {0} };
    CHECK(CompareGUID(&a, NULL) == FALSE);
}

TEST(compare_guid_both_null)
{
    CHECK(CompareGUID(NULL, NULL) == FALSE);
}

TEST(compare_guid_self)
{
    GUID a = { 0xDEADBEEF, 0xABCD, 0xEF01, { 0,1,2,3,4,5,6,7 } };
    CHECK(CompareGUID(&a, &a) == TRUE);
}

/* =========================================================================
 * 2. GuidToString
 * ======================================================================= */

TEST(guid_to_string_decorated)
{
    /* EFI System Partition GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B */
    GUID efi = { 0xC12A7328, 0xF81F, 0x11D2,
                 { 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };
    char *s = GuidToString(&efi, TRUE);
    CHECK(s != NULL);
    /* Must start with '{' and end with '}' */
    CHECK(s[0] == '{');
    CHECK(s[strlen(s)-1] == '}');
    /* Total length: 38 chars including braces */
    CHECK(strlen(s) == 38);
}

TEST(guid_to_string_undecorated)
{
    GUID g = { 0x00112233, 0x4455, 0x6677,
               { 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } };
    char *s = GuidToString(&g, FALSE);
    CHECK(s != NULL);
    /* No braces, but contains hex digits and dashes */
    CHECK(s[0] != '{');
    /* Undecorated: 32 hex digits (no dashes) or with dashes? */
    /* Looking at the Windows impl: undecorated has no dashes */
    /* "00112233445566778899AABBCCDDEEFF" = 32 chars */
    CHECK(strlen(s) >= 32);
}

TEST(guid_to_string_null)
{
    CHECK(GuidToString(NULL, TRUE) == NULL);
}

TEST(guid_to_string_zero_guid)
{
    GUID g = { 0, 0, 0, {0,0,0,0,0,0,0,0} };
    char *s = GuidToString(&g, TRUE);
    CHECK(s != NULL);
    CHECK_STR_EQ(s, "{00000000-0000-0000-0000-000000000000}");
}

/* =========================================================================
 * 3. StringToGuid
 * ======================================================================= */

TEST(string_to_guid_valid)
{
    /* Round-trip: GUID → string → GUID */
    GUID original = { 0xC12A7328, 0xF81F, 0x11D2,
                      { 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };
    char *s = GuidToString(&original, TRUE);
    GUID *parsed = StringToGuid(s);
    CHECK(parsed != NULL);
    CHECK(CompareGUID(&original, parsed) == TRUE);
}

TEST(string_to_guid_null)
{
    CHECK(StringToGuid(NULL) == NULL);
}

TEST(string_to_guid_bad_format)
{
    CHECK(StringToGuid("not-a-guid") == NULL);
}

/* =========================================================================
 * 4. GetMBRPartitionType
 * ======================================================================= */

TEST(get_mbr_type_fat32)
{
    /* 0x0B = FAT32 (CHS) */
    const char *name = GetMBRPartitionType(0x0B);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
    /* Should not be "Unknown" or empty */
    CHECK(strcmp(name, "Unknown") != 0);
}

TEST(get_mbr_type_fat32_lba)
{
    /* 0x0C = FAT32 (LBA) */
    const char *name = GetMBRPartitionType(0x0C);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
}

TEST(get_mbr_type_efi_system)
{
    /* 0xEF = EFI System Partition */
    const char *name = GetMBRPartitionType(0xEF);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
    CHECK(strcmp(name, "Unknown") != 0);
}

TEST(get_mbr_type_empty)
{
    /* 0x00 = Empty */
    const char *name = GetMBRPartitionType(0x00);
    CHECK(name != NULL);
    /* Should be "Empty" */
    CHECK(strcmp(name, "Empty") == 0);
}

TEST(get_mbr_type_ntfs)
{
    /* 0x07 = NTFS/HPFS */
    const char *name = GetMBRPartitionType(0x07);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
    CHECK(strcmp(name, "Unknown") != 0);
}

TEST(get_mbr_type_linux_swap)
{
    /* 0x82 = Linux swap */
    const char *name = GetMBRPartitionType(0x82);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
}

TEST(get_mbr_type_linux_data)
{
    /* 0x83 = Linux */
    const char *name = GetMBRPartitionType(0x83);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
}

TEST(get_mbr_type_unknown)
{
    /* 0xD0 is typically not a known type */
    const char *name = GetMBRPartitionType(0xD0);
    CHECK(name != NULL);
    /* If not in table, returns "Unknown" */
    CHECK(strlen(name) > 0);
}

/* =========================================================================
 * 5. GetGPTPartitionType
 * ======================================================================= */

TEST(get_gpt_type_efi_system)
{
    /* EFI System Partition: C12A7328-F81F-11D2-BA4B-00A0C93EC93B */
    GUID efi_sp = { 0xC12A7328, 0xF81F, 0x11D2,
                    { 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };
    const char *name = GetGPTPartitionType(&efi_sp);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
    /* Should not be a raw GUID string - it's a known type */
    CHECK(name[0] != '{');
}

TEST(get_gpt_type_microsoft_basic)
{
    /* Microsoft Basic Data: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7 */
    GUID ms_data = { 0xEBD0A0A2, 0xB9E5, 0x4433,
                     { 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 } };
    const char *name = GetGPTPartitionType(&ms_data);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
    CHECK(name[0] != '{');
}

TEST(get_gpt_type_unknown_returns_guid_string)
{
    /* A random GUID that should not be in the table */
    GUID unknown = { 0x00010203, 0x0405, 0x0607,
                     { 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F } };
    const char *name = GetGPTPartitionType(&unknown);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
    /* Unknown GUID should return a formatted GUID string (starts with '{') */
    CHECK(name[0] == '{');
}

TEST(get_gpt_type_linux_data)
{
    /* Linux filesystem data: 0FC63DAF-8483-4772-8E79-3D69D8477DE4 */
    GUID linux_data = { 0x0FC63DAF, 0x8483, 0x4772,
                        { 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4 } };
    const char *name = GetGPTPartitionType(&linux_data);
    CHECK(name != NULL);
    CHECK(strlen(name) > 0);
}

/* =========================================================================
 * 6. AnalyzeMBR
 * ======================================================================= */

TEST(analyze_mbr_null_handle)
{
    /* NULL handle must return FALSE gracefully */
    BOOL r = AnalyzeMBR(NULL, "Null", TRUE);
    CHECK(r == FALSE);
}

TEST(analyze_mbr_invalid_handle)
{
    BOOL r = AnalyzeMBR(INVALID_HANDLE_VALUE, "Invalid", TRUE);
    CHECK(r == FALSE);
}

TEST(analyze_mbr_no_boot_marker)
{
    /* File of zeros — no 0x55AA at offset 0x1FE → AnalyzeMBR returns FALSE */
    char path[64];
    int fd = make_temp(path, 512);
    CHECK(fd >= 0);
    close(fd);

    /* Register as a drive so GetPhysicalHandle works */
    drive_linux_reset_drives();
    drive_linux_add_drive(path, "T", "NoMBR", 512);

    HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzeMBR(h, "TestDrive", TRUE);
    CHECK(r == FALSE);

    CloseHandle(h);
    unlink(path);
}

TEST(analyze_mbr_with_boot_marker)
{
    /* File with 0x55AA at offset 0x1FE → AnalyzeMBR returns TRUE */
    char path[64];
    int fd = make_temp(path, 512);
    CHECK(fd >= 0);

    /* Write 0x55AA at offset 0x1FE */
    uint8_t sig[2] = { 0x55, 0xAA };
    pwrite(fd, sig, 2, 0x1FE);
    close(fd);

    drive_linux_reset_drives();
    drive_linux_add_drive(path, "T", "HasMBR", 512);

    HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
    CHECK(h != INVALID_HANDLE_VALUE);

    /* Should return TRUE (has boot marker, even if unknown MBR type) */
    BOOL r = AnalyzeMBR(h, "TestDrive", TRUE);
    CHECK(r == TRUE);

    CloseHandle(h);
    unlink(path);
}

/* =========================================================================
 * 7. AnalyzePBR
 * ======================================================================= */

TEST(analyze_pbr_null_handle)
{
    BOOL r = AnalyzePBR(NULL);
    CHECK(r == FALSE);
}

TEST(analyze_pbr_invalid_handle)
{
    BOOL r = AnalyzePBR(INVALID_HANDLE_VALUE);
    CHECK(r == FALSE);
}

TEST(analyze_pbr_no_boot_marker)
{
    /* Zero-filled file — no x86 PBR → return FALSE */
    char path[64];
    int fd = make_temp(path, 512);
    CHECK(fd >= 0);
    close(fd);

    drive_linux_reset_drives();
    drive_linux_add_drive(path, "T", "NoPBR", 512);

    HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzePBR(h);
    CHECK(r == FALSE);

    CloseHandle(h);
    unlink(path);
}

TEST(analyze_pbr_with_boot_marker_non_fat)
{
    /* Sector with 0x55AA but not a known FAT PBR → returns TRUE with
     * "unknown PBR" message but does not crash */
    char path[64];
    int fd = make_temp(path, 512);
    CHECK(fd >= 0);
    uint8_t sig[2] = { 0x55, 0xAA };
    pwrite(fd, sig, 2, 0x1FE);
    close(fd);

    drive_linux_reset_drives();
    drive_linux_add_drive(path, "T", "UnknownPBR", 512);

    HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzePBR(h);
    /* With 0x55AA but no recognizable PBR signature: should return TRUE */
    CHECK(r == TRUE);

    CloseHandle(h);
    unlink(path);
}

/* =========================================================================
 * 8. RefreshLayout(DWORD DriveIndex)
 * ======================================================================= */

TEST(refresh_layout_invalid_index)
{
    /* Out-of-range index should return FALSE without crashing */
    BOOL r = RefreshLayout(DRIVE_INDEX_MIN - 1);
    CHECK(r == FALSE);
}

TEST(refresh_layout_no_drives)
{
    drive_linux_reset_drives();
    /* No drives registered → should return FALSE */
    BOOL r = RefreshLayout(DRIVE_INDEX_MIN);
    CHECK(r == FALSE);
}

TEST(refresh_layout_regular_file)
{
    /* Regular file (not a block device): BLKRRPART is a no-op
     * but the function should not crash and should return a sensible value */
    char path[64];
    int fd = make_temp(path, 4096);
    CHECK(fd >= 0);
    close(fd);

    drive_linux_reset_drives();
    drive_linux_add_drive(path, "T", "RefreshTest", 4096);

    /* Should not crash; result value is non-fatal */
    RefreshLayout(DRIVE_INDEX_MIN);

    unlink(path);
}

/* =========================================================================
 * 9. GetDriveTypeFromIndex
 * ======================================================================= */

TEST(get_drive_type_invalid_index)
{
    drive_linux_reset_drives();
    UINT t = GetDriveTypeFromIndex(DRIVE_INDEX_MIN - 1);
    /* Out of range → DRIVE_UNKNOWN (0) */
    CHECK(t == DRIVE_UNKNOWN);
}

TEST(get_drive_type_no_drives)
{
    drive_linux_reset_drives();
    UINT t = GetDriveTypeFromIndex(DRIVE_INDEX_MIN);
    /* No drives registered → DRIVE_UNKNOWN (0) */
    CHECK(t == DRIVE_UNKNOWN);
}

TEST(get_drive_type_temp_file)
{
    /* Temp files are not block devices, so the sysfs lookup will fail.
     * The function must return a valid UINT without crashing. */
    char path[64];
    int fd = make_temp(path, 4096);
    CHECK(fd >= 0);
    close(fd);

    drive_linux_reset_drives();
    drive_linux_add_drive(path, "T", "TypeTest", 4096);

    UINT t = GetDriveTypeFromIndex(DRIVE_INDEX_MIN);
    /* No sysfs entry for temp file → should return DRIVE_UNKNOWN or DRIVE_FIXED */
    CHECK(t == DRIVE_UNKNOWN || t == DRIVE_FIXED || t == DRIVE_REMOVABLE);

    unlink(path);
}

/* =========================================================================
 * 10. GetDriveLabel
 * ======================================================================= */

TEST(get_drive_label_invalid_index)
{
    drive_linux_reset_drives();
    char *label = NULL;
    BOOL r = GetDriveLabel(DRIVE_INDEX_MIN - 1, NULL, &label, TRUE);
    CHECK(r == FALSE);
}

TEST(get_drive_label_no_drives)
{
    drive_linux_reset_drives();
    char *label = NULL;
    BOOL r = GetDriveLabel(DRIVE_INDEX_MIN, NULL, &label, TRUE);
    CHECK(r == FALSE);
}

TEST(get_drive_label_null_label_ptr)
{
    /* Null label output pointer should not crash */
    char path[64];
    int fd = make_temp(path, 4096);
    CHECK(fd >= 0);
    close(fd);

    drive_linux_reset_drives();
    drive_linux_add_drive(path, "T", "LabelTest", 4096);

    /* Should not crash with NULL label */
    BOOL r = GetDriveLabel(DRIVE_INDEX_MIN, NULL, NULL, TRUE);
    (void)r;

    unlink(path);
}

TEST(get_drive_label_temp_file_no_fs)
{
    /* A zero-filled temp file has no filesystem; blkid returns no label.
     * GetDriveLabel should return FALSE (no label found). */
    char path[64];
    int fd = make_temp(path, 512 * 1024);
    CHECK(fd >= 0);
    close(fd);

    drive_linux_reset_drives();
    drive_linux_add_drive(path, "T", "NoLabel", 512 * 1024);

    char *label = NULL;
    BOOL r = GetDriveLabel(DRIVE_INDEX_MIN, NULL, &label, TRUE);
    CHECK(r == FALSE);

    unlink(path);
}

/* =========================================================================
 * Main
 * ======================================================================= */

int main(void)
{
    printf("=== drive2 Linux tests ===\n");

    printf("--- CompareGUID ---\n");
    RUN_TEST(compare_guid_equal);
    RUN_TEST(compare_guid_different_data1);
    RUN_TEST(compare_guid_different_data4);
    RUN_TEST(compare_guid_null_first);
    RUN_TEST(compare_guid_null_second);
    RUN_TEST(compare_guid_both_null);
    RUN_TEST(compare_guid_self);

    printf("--- GuidToString ---\n");
    RUN_TEST(guid_to_string_decorated);
    RUN_TEST(guid_to_string_undecorated);
    RUN_TEST(guid_to_string_null);
    RUN_TEST(guid_to_string_zero_guid);

    printf("--- StringToGuid ---\n");
    RUN_TEST(string_to_guid_valid);
    RUN_TEST(string_to_guid_null);
    RUN_TEST(string_to_guid_bad_format);

    printf("--- GetMBRPartitionType ---\n");
    RUN_TEST(get_mbr_type_fat32);
    RUN_TEST(get_mbr_type_fat32_lba);
    RUN_TEST(get_mbr_type_efi_system);
    RUN_TEST(get_mbr_type_empty);
    RUN_TEST(get_mbr_type_ntfs);
    RUN_TEST(get_mbr_type_linux_swap);
    RUN_TEST(get_mbr_type_linux_data);
    RUN_TEST(get_mbr_type_unknown);

    printf("--- GetGPTPartitionType ---\n");
    RUN_TEST(get_gpt_type_efi_system);
    RUN_TEST(get_gpt_type_microsoft_basic);
    RUN_TEST(get_gpt_type_unknown_returns_guid_string);
    RUN_TEST(get_gpt_type_linux_data);

    printf("--- AnalyzeMBR ---\n");
    RUN_TEST(analyze_mbr_null_handle);
    RUN_TEST(analyze_mbr_invalid_handle);
    RUN_TEST(analyze_mbr_no_boot_marker);
    RUN_TEST(analyze_mbr_with_boot_marker);

    printf("--- AnalyzePBR ---\n");
    RUN_TEST(analyze_pbr_null_handle);
    RUN_TEST(analyze_pbr_invalid_handle);
    RUN_TEST(analyze_pbr_no_boot_marker);
    RUN_TEST(analyze_pbr_with_boot_marker_non_fat);

    printf("--- RefreshLayout ---\n");
    RUN_TEST(refresh_layout_invalid_index);
    RUN_TEST(refresh_layout_no_drives);
    RUN_TEST(refresh_layout_regular_file);

    printf("--- GetDriveTypeFromIndex ---\n");
    RUN_TEST(get_drive_type_invalid_index);
    RUN_TEST(get_drive_type_no_drives);
    RUN_TEST(get_drive_type_temp_file);

    printf("--- GetDriveLabel ---\n");
    RUN_TEST(get_drive_label_invalid_index);
    RUN_TEST(get_drive_label_no_drives);
    RUN_TEST(get_drive_label_null_label_ptr);
    RUN_TEST(get_drive_label_temp_file_no_fs);

    PRINT_RESULTS();
    return (g_failed == 0) ? 0 : 1;
}
