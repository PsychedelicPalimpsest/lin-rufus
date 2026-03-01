/*
 * test_pki_linux.c — Tests for Linux PKI/certificate functions (pki.c)
 *
 * Tests the OpenSSL-based implementation of:
 *   WinPKIErrorString, ValidateOpensslSignature, GetSignatureName,
 *   GetSignatureTimeStamp, GetIssuerCertificateInfo, ValidateSignature,
 *   ParseSKUSiPolicy
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* ---- test framework ---- */
#include "framework.h"

/* ---- compat layer ---- */
#include "windows.h"
#include "commctrl.h"

/* ---- rufus headers ---- */
#include "rufus.h"
#include "resource.h"
#include "missing.h"

/* ================================================================
 * Minimal globals required by linux/pki.c
 * ================================================================ */

HWND hMainDialog   = NULL;
HWND hDeviceList   = NULL;
HWND hProgress     = NULL;
HWND hStatus       = NULL;
HWND hInfo         = NULL;
HWND hLog          = NULL;
HWND hCapacity     = NULL;

BOOL op_in_progress        = FALSE;
BOOL enable_HDDs           = FALSE;
BOOL enable_VHDs           = TRUE;
BOOL right_to_left_mode    = FALSE;
BOOL large_drive           = FALSE;
BOOL write_as_esp          = FALSE;
BOOL write_as_image        = FALSE;
BOOL lock_drive            = FALSE;
BOOL zero_drive            = FALSE;
BOOL fast_zeroing          = FALSE;
BOOL force_large_fat32     = FALSE;
BOOL enable_ntfs_compression = FALSE;
BOOL enable_file_indexing  = FALSE;

DWORD ErrorStatus          = 0;
DWORD LastWriteError       = 0;
DWORD MainThreadId         = 0;
DWORD DownloadStatus       = 0;

int fs_type                = 0;
int boot_type              = 0;
int partition_type         = 0;
int target_type            = 0;
int dialog_showing         = 0;
int force_update           = 0;

RUFUS_UPDATE update        = {{0}, {0}, NULL, NULL};
windows_version_t WindowsVersion = {0};
BOOL en_msg_mode           = FALSE;

/* Minimal stubs */
void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s) { (void)s; }
char* lmprintf(uint32_t msg_id, ...) { (void)msg_id; return ""; }
int NotificationEx(int type, const char* dont_display_setting,
                   const notification_info* more_info,
                   const char* title, const char* format, ...)
    { (void)type; (void)dont_display_setting; (void)more_info; (void)title; (void)format; return 0; }

/* ================================================================
 * Function declarations (from linux/pki.c)
 * ================================================================ */
extern const char* WinPKIErrorString(void);
extern char* GetSignatureName(const char* path, const char* country_code,
                              uint8_t* thumbprint, BOOL bSilent);
extern int   GetIssuerCertificateInfo(uint8_t* cert, cert_info_t* info);
extern uint64_t GetSignatureTimeStamp(const char* path);
extern LONG  ValidateSignature(HWND hDlg, const char* path);
extern BOOL  ValidateOpensslSignature(BYTE* buf, DWORD buflen, BYTE* sig, DWORD siglen);
extern BOOL  ParseSKUSiPolicy(void);

/* ================================================================
 * Tests: WinPKIErrorString
 * ================================================================ */

TEST(win_pki_error_string_not_null)
{
    const char* s = WinPKIErrorString();
    CHECK_MSG(s != NULL, "WinPKIErrorString() returned NULL");
}

TEST(win_pki_error_string_no_error)
{
    const char* s = WinPKIErrorString();
    CHECK_MSG(s != NULL && s[0] != '\0', "WinPKIErrorString() returned empty string");
}

/* ================================================================
 * Tests: ValidateOpensslSignature — parameter validation
 * ================================================================ */

TEST(validate_openssl_sig_null_buf)
{
    uint8_t sig[RSA_SIGNATURE_SIZE] = {0};
    BOOL r = ValidateOpensslSignature(NULL, 8, sig, RSA_SIGNATURE_SIZE);
    CHECK_MSG(r == FALSE, "NULL buf should return FALSE");
}

TEST(validate_openssl_sig_null_sig)
{
    uint8_t buf[8] = {0};
    BOOL r = ValidateOpensslSignature(buf, 8, NULL, RSA_SIGNATURE_SIZE);
    CHECK_MSG(r == FALSE, "NULL sig should return FALSE");
}

TEST(validate_openssl_sig_zero_len)
{
    uint8_t buf[8] = {0};
    uint8_t sig[RSA_SIGNATURE_SIZE] = {0};
    BOOL r = ValidateOpensslSignature(buf, 0, sig, RSA_SIGNATURE_SIZE);
    CHECK_MSG(r == FALSE, "zero buflen should return FALSE");
}

TEST(validate_openssl_sig_wrong_sig_size)
{
    uint8_t buf[8] = {0};
    uint8_t sig[RSA_SIGNATURE_SIZE - 1] = {0};
    BOOL r = ValidateOpensslSignature(buf, 8, sig, RSA_SIGNATURE_SIZE - 1);
    CHECK_MSG(r == FALSE, "wrong siglen should return FALSE");
}

TEST(validate_openssl_sig_bad_signature)
{
    /* Random bytes for both buffer and signature — should fail RSA verification */
    uint8_t buf[32];
    uint8_t sig[RSA_SIGNATURE_SIZE];
    size_t i;
    for (i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i ^ 0xA5);
    for (i = 0; i < sizeof(sig); i++) sig[i] = (uint8_t)(i * 3 + 7);
    BOOL r = ValidateOpensslSignature(buf, sizeof(buf), sig, RSA_SIGNATURE_SIZE);
    CHECK_MSG(r == FALSE, "random signature should not verify");
}

/* ================================================================
 * Tests: GetSignatureName
 * ================================================================ */

TEST(get_signature_name_null_path_ok)
{
    /* NULL path → try current binary (unsigned on Linux dev build) → NULL or string */
    char* name = GetSignatureName(NULL, NULL, NULL, TRUE);
    /* Just verify it doesn't crash; result may be NULL for unsigned binaries */
    (void)name;
    CHECK(1);
}

TEST(get_signature_name_nonexistent)
{
    char* name = GetSignatureName("/nonexistent_file_for_rufus_test.exe",
                                  NULL, NULL, TRUE);
    CHECK_MSG(name == NULL, "nonexistent file should return NULL");
}

TEST(get_signature_name_not_pe)
{
    /* Create a temp text file that is definitely not a PE */
    char tmppath[] = "/tmp/rufus_pki_test_XXXXXX";
    int fd = mkstemp(tmppath);
    CHECK_MSG(fd >= 0, "failed to create temp file");
    const char* txt = "This is not a PE file.\n";
    write(fd, txt, strlen(txt));
    close(fd);

    char* name = GetSignatureName(tmppath, NULL, NULL, TRUE);
    unlink(tmppath);
    CHECK_MSG(name == NULL, "non-PE file should return NULL");
}

/* ================================================================
 * Tests: GetSignatureTimeStamp
 * ================================================================ */

TEST(get_signature_timestamp_null)
{
    /* NULL path → try current binary → 0 on unsigned binary */
    uint64_t ts = GetSignatureTimeStamp(NULL);
    /* Unsigned dev binary → 0; we just verify no crash */
    (void)ts;
    CHECK(1);
}

TEST(get_signature_timestamp_nonexistent)
{
    uint64_t ts = GetSignatureTimeStamp("/nonexistent_file_for_rufus_test.exe");
    CHECK_MSG(ts == 0, "nonexistent file should return 0");
}

TEST(get_signature_timestamp_not_pe)
{
    char tmppath[] = "/tmp/rufus_pki_ts_test_XXXXXX";
    int fd = mkstemp(tmppath);
    CHECK_MSG(fd >= 0, "failed to create temp file");
    const char* txt = "not a PE\n";
    write(fd, txt, strlen(txt));
    close(fd);

    uint64_t ts = GetSignatureTimeStamp(tmppath);
    unlink(tmppath);
    CHECK_MSG(ts == 0, "non-PE file should return 0 timestamp");
}

/* ================================================================
 * Tests: GetIssuerCertificateInfo
 * ================================================================ */

TEST(get_issuer_cert_info_null_cert)
{
    cert_info_t info;
    memset(&info, 0, sizeof(info));
    int r = GetIssuerCertificateInfo(NULL, &info);
    /* NULL cert with valid info → 0 (unsigned/empty) */
    CHECK_MSG(r == 0 || r == -1, "NULL cert should return 0 or -1");
}

TEST(get_issuer_cert_info_null_info)
{
    /* Non-NULL cert pointer with garbage data, but info is NULL → -1 (error) */
    uint8_t fake_cert[16] = {0};
    int r = GetIssuerCertificateInfo(fake_cert, NULL);
    CHECK_MSG(r == -1, "NULL info should return -1");
}

TEST(get_issuer_cert_info_zero_length)
{
    /* WIN_CERTIFICATE with dwLength == 0 → 0 (no cert) */
    uint8_t fake_cert[16] = {0};  /* dwLength = 0 */
    cert_info_t info;
    memset(&info, 0, sizeof(info));
    int r = GetIssuerCertificateInfo(fake_cert, &info);
    CHECK_MSG(r == 0 || r == -1, "zero-length cert should return 0 or -1");
}

/* ================================================================
 * Tests: ValidateSignature
 * ================================================================ */

TEST(validate_signature_nonexistent)
{
    /* On Linux, a nonexistent file should return non-zero (file not found) */
    LONG r = ValidateSignature(NULL, "/nonexistent_file_for_rufus_test.exe");
    CHECK_MSG(r != 0, "nonexistent file should return error (non-zero)");
}

TEST(validate_signature_null_path)
{
    /* NULL path is a no-op stub on Linux — should not crash */
    LONG r = ValidateSignature(NULL, NULL);
    (void)r;
    CHECK(1);
}

/* ================================================================
 * Tests: ParseSKUSiPolicy
 * ================================================================ */

TEST(parse_sku_si_policy_no_crash)
{
    /* Windows-only feature — must return FALSE on Linux */
    BOOL r = ParseSKUSiPolicy();
    CHECK_MSG(r == FALSE, "ParseSKUSiPolicy should return FALSE on Linux");
}

/* ================================================================
 * Main
 * ================================================================ */
int main(void)
{
    printf("=== PKI Linux Tests ===\n");

    RUN_TEST(win_pki_error_string_not_null);
    RUN_TEST(win_pki_error_string_no_error);

    RUN_TEST(validate_openssl_sig_null_buf);
    RUN_TEST(validate_openssl_sig_null_sig);
    RUN_TEST(validate_openssl_sig_zero_len);
    RUN_TEST(validate_openssl_sig_wrong_sig_size);
    RUN_TEST(validate_openssl_sig_bad_signature);

    RUN_TEST(get_signature_name_null_path_ok);
    RUN_TEST(get_signature_name_nonexistent);
    RUN_TEST(get_signature_name_not_pe);

    RUN_TEST(get_signature_timestamp_null);
    RUN_TEST(get_signature_timestamp_nonexistent);
    RUN_TEST(get_signature_timestamp_not_pe);

    RUN_TEST(get_issuer_cert_info_null_cert);
    RUN_TEST(get_issuer_cert_info_null_info);
    RUN_TEST(get_issuer_cert_info_zero_length);

    RUN_TEST(validate_signature_nonexistent);
    RUN_TEST(validate_signature_null_path);

    RUN_TEST(parse_sku_si_policy_no_crash);

    PRINT_RESULTS();
    return g_failed > 0 ? 1 : 0;
}

#endif /* __linux__ */
