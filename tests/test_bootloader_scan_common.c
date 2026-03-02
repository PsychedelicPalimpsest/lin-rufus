/*
 * test_bootloader_scan_common.c — Cross-platform tests for GetBootladerInfo()
 *
 * Tests the common implementation of GetBootladerInfo() that lives in
 * src/common/bootloader_scan.c.  All external dependencies are provided as
 * injectable stubs so no real ISO or EFI binary is needed.
 *
 * Compiles and runs on both Linux (native) and Windows (MinGW/Wine).
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

/* ---- Platform-specific headers ---- */
#ifdef _WIN32
#  include <windows.h>
#  include "rufus.h"
#  include "missing.h"
#  include "resource.h"
#else
#  include "windows.h"     /* compat layer */
#  include "commctrl.h"
#  include "rufus.h"
#  include "missing.h"
#  include "resource.h"
#endif

/* ================================================================
 * Globals required by rufus.h externs
 * ================================================================ */
RUFUS_IMG_REPORT img_report;
char *image_path = NULL;

/* Other globals referenced transitively */
HWND hMainDialog      = NULL;
BOOL right_to_left_mode = FALSE;

/* ================================================================
 * Interceptors — control what the helper functions return
 * ================================================================ */

static uint8_t   g_read_data[64] = { 0x4D, 0x5A };  /* MZ header placeholder */
static uint32_t  g_read_len      = sizeof(g_read_data);
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

static BOOL g_is_signed = FALSE;
BOOL IsSignedBySecureBootAuthority(uint8_t *buf, uint32_t len)
{ (void)buf; (void)len; return g_is_signed; }

static int g_revoke_result = 0;
int IsBootloaderRevoked(uint8_t *buf, uint32_t len)
{ (void)buf; (void)len; return g_revoke_result; }

/* ================================================================
 * Stubs for stdio / localization functions
 * ================================================================ */
void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration, int msg_id, ...)
{ (void)info; (void)debug; (void)duration; (void)msg_id; }

void uprintf(const char *fmt, ...)
{ (void)fmt; }

int lmprintf(int msg_id, ...)
{ (void)msg_id; return 0; }

#ifndef _WIN32
/* On Linux, SendMessage/PostMessage need stubs */
BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return TRUE; }
LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return 0; }
#endif

/* ================================================================
 * The function under test (from common/bootloader_scan.c)
 * ================================================================ */
extern void GetBootladerInfo(void);

/* ================================================================
 * Helper: reset all injection state
 * ================================================================ */
static void reset(void)
{
    memset(&img_report, 0, sizeof(img_report));
    g_read_fail     = 0;
    g_read_len      = sizeof(g_read_data);
    g_is_signed     = FALSE;
    g_revoke_result = 0;
}

/* ================================================================
 * Tests
 * ================================================================ */

/* 1. When img_report.has_efi == 0, function is a no-op */
TEST(common_bootloader_info_no_efi_is_noop)
{
    reset();
    img_report.has_efi = 0;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed = TRUE;
    GetBootladerInfo();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 2. When all efi_boot_entry paths are empty, bit stays 0 */
TEST(common_bootloader_info_empty_entries_noop)
{
    reset();
    img_report.has_efi = 1;
    GetBootladerInfo();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 3. A single signed, non-revoked bootloader sets bit 0 */
TEST(common_bootloader_info_signed_sets_bit0)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/shimx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed     = TRUE;
    g_revoke_result = 0;
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);
}

/* 4. An unsigned, non-revoked bootloader leaves bit 0 clear */
TEST(common_bootloader_info_unsigned_bit0_clear)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/grubx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed     = FALSE;
    g_revoke_result = 0;
    GetBootladerInfo();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 5. Revocation result 1 (UEFI DBX) sets bit 1 */
TEST(common_bootloader_info_uefi_dbx_revocation)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed     = FALSE;
    g_revoke_result = 1; /* UEFI DBX */
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & (1 << 1)) != 0);
}

/* 6. Revocation result 3 (Linux SBAT) sets bit 3 */
TEST(common_bootloader_info_sbat_revocation)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/grubx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed     = FALSE;
    g_revoke_result = 3; /* Linux SBAT */
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & (1 << 3)) != 0);
}

/* 7. Unreadable file (ReadISOFileToBuffer returns 0) is skipped gracefully */
TEST(common_bootloader_info_unreadable_file_skipped)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_read_fail     = 1;
    g_is_signed     = TRUE;
    g_revoke_result = 2;
    GetBootladerInfo();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 8. Multiple entries processed: bits accumulate across entries */
TEST(common_bootloader_info_multiple_entries_accumulate)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/shimx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    strncpy(img_report.efi_boot_entry[1].path, "/EFI/BOOT/grubx64.efi",
            sizeof(img_report.efi_boot_entry[1].path) - 1);
    g_is_signed     = TRUE;
    g_revoke_result = 1; /* both entries return same mock values */
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);       /* signed */
    CHECK((img_report.has_secureboot_bootloader & (1 << 1)) != 0); /* revoked bit 1 */
}

/* 9. Processing stops at first empty path */
TEST(common_bootloader_info_stops_at_empty_path)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    /* entry[1] path is zero (empty) — processing should stop after entry[0] */
    g_is_signed     = TRUE;
    g_revoke_result = 0;
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);
}

/* 10. All 5 revocation types (1–5) each set their respective bit */
TEST(common_bootloader_info_all_five_revocation_types)
{
    int r;
    for (r = 1; r <= 5; r++) {
        reset();
        img_report.has_efi = 1;
        strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
                sizeof(img_report.efi_boot_entry[0].path) - 1);
        g_is_signed     = FALSE;
        g_revoke_result = r;
        GetBootladerInfo();
        CHECK((img_report.has_secureboot_bootloader & (1 << r)) != 0);
    }
}

/* 11. Fresh state: has_secureboot_bootloader starts at 0 */
TEST(common_bootloader_info_fresh_state_is_zero)
{
    reset();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 12. Revoked bootloader sets bit in 0xfe mask (used by UI alert logic) */
TEST(common_bootloader_info_alert_mask_nonzero_on_revocation)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed     = FALSE;
    g_revoke_result = 2;
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & 0xfe) != 0);
}

/* 13. Signed + not-revoked: alert mask 0xfe is zero, only bit 0 set */
TEST(common_bootloader_info_signed_only_no_alert)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/shimx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed     = TRUE;
    g_revoke_result = 0;
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);
    CHECK_INT_EQ(0, (int)(img_report.has_secureboot_bootloader & 0xfe));
}

/* 14. Revocation type 4 (Windows SVN) sets bit 4 */
TEST(common_bootloader_info_windows_svn_revocation)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/Microsoft/Boot/bootmgfw.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed     = FALSE;
    g_revoke_result = 4; /* Windows SVN */
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & (1 << 4)) != 0);
}

/* 15. Revocation type 5 (Cert DBX) sets bit 5 */
TEST(common_bootloader_info_cert_dbx_revocation)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootia32.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed     = FALSE;
    g_revoke_result = 5; /* Cert DBX */
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & (1 << 5)) != 0);
}

/* 16. Signed AND revoked: both bit 0 (signed) and the revocation bit are set */
TEST(common_bootloader_info_signed_and_revoked)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/shimx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_is_signed     = TRUE;
    g_revoke_result = 3; /* SBAT revoked */
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);       /* signed */
    CHECK((img_report.has_secureboot_bootloader & (1 << 3)) != 0); /* SBAT */
}

/* 17. Zero-length read (g_read_len == 0) is treated as unreadable */
TEST(common_bootloader_info_zero_len_read_skipped)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    g_read_len  = 0;
    g_is_signed = TRUE;
    GetBootladerInfo();
    CHECK_INT_EQ(0, (int)img_report.has_secureboot_bootloader);
}

/* 18. Three consecutive entries all signed → bit 0 set, 0xfe stays 0 */
TEST(common_bootloader_info_three_signed_entries)
{
    reset();
    img_report.has_efi = 1;
    strncpy(img_report.efi_boot_entry[0].path, "/EFI/BOOT/bootx64.efi",
            sizeof(img_report.efi_boot_entry[0].path) - 1);
    strncpy(img_report.efi_boot_entry[1].path, "/EFI/BOOT/shimx64.efi",
            sizeof(img_report.efi_boot_entry[1].path) - 1);
    strncpy(img_report.efi_boot_entry[2].path, "/EFI/BOOT/grubx64.efi",
            sizeof(img_report.efi_boot_entry[2].path) - 1);
    g_is_signed     = TRUE;
    g_revoke_result = 0;
    GetBootladerInfo();
    CHECK((img_report.has_secureboot_bootloader & 1) != 0);
    CHECK_INT_EQ(0, (int)(img_report.has_secureboot_bootloader & 0xfe));
}

int main(void)
{
    RUN(common_bootloader_info_no_efi_is_noop);
    RUN(common_bootloader_info_empty_entries_noop);
    RUN(common_bootloader_info_signed_sets_bit0);
    RUN(common_bootloader_info_unsigned_bit0_clear);
    RUN(common_bootloader_info_uefi_dbx_revocation);
    RUN(common_bootloader_info_sbat_revocation);
    RUN(common_bootloader_info_unreadable_file_skipped);
    RUN(common_bootloader_info_multiple_entries_accumulate);
    RUN(common_bootloader_info_stops_at_empty_path);
    RUN(common_bootloader_info_all_five_revocation_types);
    RUN(common_bootloader_info_fresh_state_is_zero);
    RUN(common_bootloader_info_alert_mask_nonzero_on_revocation);
    RUN(common_bootloader_info_signed_only_no_alert);
    RUN(common_bootloader_info_windows_svn_revocation);
    RUN(common_bootloader_info_cert_dbx_revocation);
    RUN(common_bootloader_info_signed_and_revoked);
    RUN(common_bootloader_info_zero_len_read_skipped);
    RUN(common_bootloader_info_three_signed_entries);
    TEST_RESULTS();
}
