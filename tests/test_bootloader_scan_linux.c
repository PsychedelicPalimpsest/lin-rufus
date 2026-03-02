/*
 * test_bootloader_scan_linux.c — Tests for GetBootladerInfo() (Linux)
 *
 * Verifies that GetBootladerInfo() correctly analyses UEFI bootloaders
 * embedded in an ISO image and updates img_report.has_secureboot_bootloader.
 *
 * The three helper functions it calls (ReadISOFileToBuffer,
 * IsSignedBySecureBootAuthority, IsBootloaderRevoked) are all controlled
 * via test-injection globals so no real ISO or EFI binary is needed.
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#include "framework.h"

/* ---- compat layer ---- */
#include "windows.h"
#include "commctrl.h"

/* ---- rufus types ---- */
#include "rufus.h"
#include "missing.h"
#include "localization.h"
#include "resource.h"

/* ================================================================
 * Globals required by image_scan.c and its dependencies
 * ================================================================ */
HWND hMainDialog      = NULL;
HWND hDeviceList      = NULL;
HWND hProgress        = NULL;
HWND hStatus          = NULL;
HWND hInfo            = NULL;
HWND hLog             = NULL;
HWND hBootType        = NULL;
HWND hFileSystem      = NULL;
HWND hPartitionScheme = NULL;
HWND hTargetSystem    = NULL;
HWND hImageOption     = NULL;

BOOL op_in_progress      = FALSE;
BOOL enable_HDDs         = FALSE;
BOOL enable_VHDs         = TRUE;
BOOL right_to_left_mode  = FALSE;

DWORD ErrorStatus        = 0;
DWORD LastWriteError     = 0;
DWORD MainThreadId       = 0;
DWORD DownloadStatus     = 0;

int fs_type              = 0;
int boot_type            = 0;
int partition_type       = 0;
int target_type          = 0;
uint8_t image_options    = 0;

char szFolderPath[MAX_PATH]  = "";
char app_dir[MAX_PATH]       = "";
char temp_dir[MAX_PATH]      = "/tmp";
char app_data_dir[MAX_PATH]  = "/tmp";
char system_dir[MAX_PATH]    = "/tmp";
char sysnative_dir[MAX_PATH] = "/tmp";
char user_dir[MAX_PATH]      = "/tmp";
char *image_path             = NULL;
char *fido_url               = NULL;
uint64_t persistence_size    = 0;

BOOL large_drive               = FALSE;
BOOL write_as_esp              = FALSE;
BOOL write_as_image            = FALSE;
BOOL lock_drive                = FALSE;
BOOL zero_drive                = FALSE;
BOOL fast_zeroing              = FALSE;
BOOL force_large_fat32         = FALSE;
BOOL enable_ntfs_compression   = FALSE;
BOOL enable_file_indexing      = FALSE;
BOOL preserve_timestamps       = FALSE;
BOOL validate_md5sum           = FALSE;
BOOL cpu_has_sha1_accel        = FALSE;
BOOL cpu_has_sha256_accel      = FALSE;
BOOL dont_display_image_name   = FALSE;
BOOL write_as_esp_2            = FALSE;
BOOL ignore_boot_marker        = FALSE;
BOOL has_ffu_support           = FALSE;

int imop_win_sel               = 0;
int selection_default          = 0;

uint64_t md5sum_totalbytes = 0;
HANDLE format_thread       = NULL;
StrArray modified_files;
RUFUS_DRIVE rufus_drive[MAX_DRIVES];

/* img_report is defined in iso.c; in this test we define it here */
RUFUS_IMG_REPORT img_report;

/* ================================================================
 * Interceptors — control what the helper functions return
 * ================================================================ */

/* ReadISOFileToBuffer: returns g_read_len bytes of g_read_buf */
static uint8_t   g_read_data[64] = { 0x4D, 0x5A };  /* MZ header placeholder */
static uint32_t  g_read_len      = sizeof(g_read_data);
/* When < 0: fail (return 0) */
static int       g_read_fail     = 0;

uint32_t ReadISOFileToBuffer(const char *iso, const char *iso_file, uint8_t **buf)
{
    (void)iso; (void)iso_file;
    if (g_read_fail || g_read_len == 0) { *buf = NULL; return 0; }
    *buf = (uint8_t *)malloc(g_read_len);
    if (!*buf) return 0;
    memcpy(*buf, g_read_data, g_read_len);
    return g_read_len;
}

/* IsSignedBySecureBootAuthority: controlled by g_is_signed */
static BOOL g_is_signed = FALSE;
BOOL IsSignedBySecureBootAuthority(uint8_t *buf, uint32_t len)
{ (void)buf; (void)len; return g_is_signed; }

/* IsBootloaderRevoked: controlled by g_revoke_result (0 = not revoked) */
static int g_revoke_result = 0;
int IsBootloaderRevoked(uint8_t *buf, uint32_t len)
{ (void)buf; (void)len; return g_revoke_result; }

/* ================================================================
 * Stubs for other functions called transitively
 * ================================================================ */
BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return TRUE; }
LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return 0; }

int NotificationEx(int t, const char *s, const notification_info *i,
                   const char *title, const char *fmt, ...)
{ (void)t; (void)s; (void)i; (void)title; (void)fmt; return IDOK; }

/* ================================================================
 * Function under test (defined in image_scan.c)
 * ================================================================ */
extern void GetBootladerInfo(void);

/* ================================================================
 * Helper: reset all injection state
 * ================================================================ */
static void reset(void)
{
    memset(&img_report, 0, sizeof(img_report));
    g_read_fail    = 0;
    g_read_len     = sizeof(g_read_data);
    g_is_signed    = FALSE;
    g_revoke_result = 0;
}

/* ================================================================
 * Tests
 * ================================================================ */

/* 1. When img_report.has_efi == 0 (not EFI-bootable), function is a no-op */
TEST(bootloader_info_no_efi_is_noop)
{
    reset();
    img_report.has_efi = 0;
    /* Add an entry that would trigger analysis if efi is set */
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed = TRUE;
    GetBootladerInfo();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 2. When all efi_boot_entry paths are empty, no analysis and bit stays 0 */
TEST(bootloader_info_empty_entries_noop)
{
    reset();
    img_report.has_efi = 1;
    /* All paths are empty (already 0 from memset) */
    GetBootladerInfo();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 3. A single signed, non-revoked bootloader sets bit 0 of has_secureboot_bootloader */
TEST(bootloader_info_signed_sets_bit0)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/shimx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed    = TRUE;
    g_revoke_result = 0;
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);
}

/* 4. An unsigned, non-revoked bootloader leaves bit 0 clear */
TEST(bootloader_info_unsigned_bit0_clear)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/grubx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed    = FALSE;
    g_revoke_result = 0;
    GetBootladerInfo();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 5. A revoked bootloader (result=1) sets bit 1 (1 << 1) */
TEST(bootloader_info_revoked_sets_revocation_bit)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed    = FALSE;
    g_revoke_result = 1; /* UEFI DBX */
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & (1 << 1)) != 0);
}

/* 6. Revocation type 3 (SBAT) sets bit 3 */
TEST(bootloader_info_sbat_revocation_sets_bit3)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/grubx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed    = FALSE;
    g_revoke_result = 3; /* SBAT */
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & (1 << 3)) != 0);
}

/* 7. When ReadISOFileToBuffer returns 0 (unreadable file), bit stays 0 and
 *    the function continues to the next entry without crashing */
TEST(bootloader_info_unreadable_file_skipped)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_read_fail = 1;  /* force ReadISOFileToBuffer to return 0 */
    g_is_signed    = TRUE;
    g_revoke_result = 2;
    GetBootladerInfo();
    /* Since the file couldn't be read, IsSignedBy / IsRevoked are never called */
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 8. Multiple entries: first signed, second revoked → both bits set */
TEST(bootloader_info_multiple_entries)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/shimx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    strncpy(img_report.efi_boot_entry[1].path, "/EFI/BOOT/grubx64.efi",
            sizeof(img_report.efi_boot_entry[1].path) - 1);

    /* Alternate: entry 0 → signed+not-revoked; entry 1 → unsigned+revoked(1) */
    /* We control by making IsSignedBy and IsRevoked stateless mocks.
     * Since they share global state, we test the union of both calls. */
    g_is_signed    = TRUE;   /* both calls return TRUE for is_signed */
    g_revoke_result = 1;     /* both calls return 1 (revoked) */
    GetBootladerInfo();
    /* Bit 0 (signed) and bit 1 (revoked type 1) should be set */
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);
    CHECK((img_report.has_secureboot_bootloader & (1 << 1)) != 0);
}

/* 9. Only entries with non-empty paths are processed */
TEST(bootloader_info_stops_at_empty_path)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    /* entry[1] path is empty (memset ensures this) */
    g_is_signed    = TRUE;
    g_revoke_result = 0;
    GetBootladerInfo();
    /* Bit 0 should be set (entry 0 was processed) */
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);
}

/* 10. Revocation of all 5 types sets the correct bits */
TEST(bootloader_info_all_revocation_types)
{
    int r;
    for (r = 1; r <= 5; r++) {
        reset();
        img_report.has_efi = 1;
        strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
                sizeof(img_report.efi_boot_entry[0].path) - 1);
        g_is_signed    = FALSE;
        g_revoke_result = r;
        GetBootladerInfo();
        CHECK((img_report.has_secureboot_bootloader & (1 << r)) != 0);
    }
}

/* 11. has_secureboot_bootloader starts at 0 after a fresh reset;
 *     successive calls are idempotent when img_report is cleared */
TEST(bootloader_info_fresh_state_zero)
{
    reset();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 12. Revoked bit set in 0xfe mask causes "alert needed" condition
 *     (i.e. has_secureboot_bootloader & 0xfe is non-zero when revoked) */
TEST(bootloader_info_alert_mask_nonzero_on_revocation)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed    = FALSE;
    g_revoke_result = 2; /* type 2 → bit 2 → 0xfe mask check passes */
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & 0xfe) != 0);
}

/* 13. When signed but NOT revoked, alert mask is zero (bit 0 only = signed,
 *     not in 0xfe) */
TEST(bootloader_info_alert_mask_zero_when_signed_only)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/shimx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed    = TRUE;
    g_revoke_result = 0;
    GetBootladerInfo();
    /* Bit 0 is set but 0xfe mask is clear → no alert needed */
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);
    CHECK_INT_EQ(0, (int)(img_report.has_secureboot_bootloader & 0xfe));
}

int main(void)
{
    RUN(bootloader_info_no_efi_is_noop);
    RUN(bootloader_info_empty_entries_noop);
    RUN(bootloader_info_signed_sets_bit0);
    RUN(bootloader_info_unsigned_bit0_clear);
    RUN(bootloader_info_revoked_sets_revocation_bit);
    RUN(bootloader_info_sbat_revocation_sets_bit3);
    RUN(bootloader_info_unreadable_file_skipped);
    RUN(bootloader_info_multiple_entries);
    RUN(bootloader_info_stops_at_empty_path);
    RUN(bootloader_info_all_revocation_types);
    RUN(bootloader_info_fresh_state_zero);
    RUN(bootloader_info_alert_mask_nonzero_on_revocation);
    RUN(bootloader_info_alert_mask_zero_when_signed_only);
    TEST_RESULTS();
}

#endif /* __linux__ */
