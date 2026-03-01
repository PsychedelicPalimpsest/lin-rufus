/* tests/test_dbx_linux.c
 * Tests for DBX caching and timestamp logic in src/linux/net.c.
 *
 * Covers:
 *   - dbx_build_timestamp_url()       — pure URL transformer (no network)
 *   - dbx_parse_github_timestamp()    — pure JSON timestamp parser (no network)
 *   - UseLocalDbx()                   — settings-based cache freshness check
 *   - CheckForDBXUpdates()            — smoke test (no real network required)
 *
 * Function stubs: dbx_linux_glue.c
 * Settings:       real common/parser.c + linux/parser.c via DBX_LINUX_SRC
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
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include "framework.h"

#include "windows.h"
#include "commctrl.h"
#include "rufus.h"
#include "resource.h"
#include "missing.h"
#include "localization.h"
#include "../src/linux/settings.h"

/* ================================================================
 * Globals required by net.c and its transitive dependencies.
 * Function stubs live in dbx_linux_glue.c.
 * ================================================================ */

HWND hMainDialog    = NULL;
HWND hDeviceList    = NULL;
HWND hProgress      = NULL;
HWND hStatus        = NULL;
HWND hInfo          = NULL;
HWND hLog           = NULL;
HWND hCapacity      = NULL;

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
int selection_default      = 0;
int persistence_unit_selection = -1;
int update_progress_type   = 0;
uint8_t image_options      = 0;
float fScale               = 1.0f;
uint64_t persistence_size  = 0;
int64_t iso_blocking_status = -1;
uint32_t pe256ssp_size     = 0;
uint8_t *pe256ssp          = NULL;
uint16_t rufus_version[3]  = {0,0,0};
uint16_t embedded_sl_version[2] = {0,0};
uint32_t dur_mins = 0, dur_secs = 0;

char szFolderPath[MAX_PATH]   = "";
char app_dir[MAX_PATH]        = "";
char temp_dir[MAX_PATH]       = "/tmp";
char app_data_dir[MAX_PATH]   = "/tmp";
char system_dir[MAX_PATH]     = "/tmp";
char sysnative_dir[MAX_PATH]  = "/tmp";
char user_dir[MAX_PATH]       = "";
char cur_dir[MAX_PATH]        = "";
char embedded_sl_version_str[2][12] = {"", ""};
char embedded_sl_version_ext[2][32] = {"", ""};
char ClusterSizeLabel[MAX_CLUSTER_SIZES][64];
char msgbox[1024]             = "";
char msgbox_title[32]         = "";
char image_option_txt[128]    = "";
char ubuffer[UBUFFER_SIZE]    = "";

char *ini_file            = NULL;
char *image_path          = NULL;
char *archive_path        = NULL;
char *fido_url            = NULL;
char *save_image_type     = NULL;
char *sbat_level_txt      = NULL;
char *sb_active_txt       = NULL;
char *sb_revoked_txt      = NULL;

HINSTANCE hMainInstance   = NULL;
HWND hMultiToolbar = NULL, hSaveToolbar = NULL, hHashToolbar = NULL;
HWND hAdvancedDeviceToolbar = NULL, hAdvancedFormatToolbar = NULL;
HWND hUpdatesDlg = NULL;
HWND hPartitionScheme = NULL, hTargetSystem = NULL, hFileSystem = NULL;
HWND hClusterSize = NULL, hLabel = NULL, hBootType = NULL, hNBPasses = NULL;
HWND hImageOption = NULL, hLogDialog = NULL;
WORD selected_langid      = 0;
BOOL allow_dual_uefi_bios = FALSE, usb_debug = FALSE;
BOOL detect_fakes         = FALSE;
BOOL use_own_c32[NB_OLD_C32];
BOOL expert_mode          = FALSE;
BOOL force_update_check   = FALSE;

int nb_passes             = 0;
int rufus_drive_number    = 0;

RUFUS_IMG_REPORT img_report   = {0};
loc_cmd *selected_locale  = NULL;

/* ================================================================
 * Functions under test (declared extern — defined in net.c)
 * ================================================================ */
extern BOOL dbx_build_timestamp_url(const char *content_url, char *out, size_t out_len);
extern BOOL dbx_parse_github_timestamp(const char *json, uint64_t *ts);
extern BOOL UseLocalDbx(int arch);
extern void CheckForDBXUpdates(void);

/* ================================================================
 * INI helper for UseLocalDbx / settings tests
 * ================================================================ */
static char s_tmp_ini[64];

static void setup_ini(void)
{
    snprintf(s_tmp_ini, sizeof(s_tmp_ini), "/tmp/test_dbx_XXXXXX");
    int fd = mkstemp(s_tmp_ini);
    if (fd >= 0) close(fd);
    ini_file = s_tmp_ini;
}

static void teardown_ini(void)
{
    unlink(s_tmp_ini);
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s~", s_tmp_ini);
    unlink(tmp);
    ini_file = NULL;
}

/* ================================================================
 * dbx_build_timestamp_url() — pure URL transformer tests
 * ================================================================ */

/* 1. NULL content_url returns FALSE */
TEST(build_url_null_content_url_returns_false)
{
    char out[512];
    BOOL r = dbx_build_timestamp_url(NULL, out, sizeof(out));
    CHECK(r == FALSE);
}

/* 2. NULL output buffer returns FALSE */
TEST(build_url_null_out_returns_false)
{
    const char *url = "https://api.github.com/repos/x/y/contents/foo/bar.bin";
    BOOL r = dbx_build_timestamp_url(url, NULL, 512);
    CHECK(r == FALSE);
}

/* 3. Zero output length returns FALSE */
TEST(build_url_zero_len_returns_false)
{
    char out[512];
    const char *url = "https://api.github.com/repos/x/y/contents/foo/bar.bin";
    BOOL r = dbx_build_timestamp_url(url, out, 0);
    CHECK(r == FALSE);
}

/* 4. URL without "contents/" returns FALSE */
TEST(build_url_missing_contents_segment_returns_false)
{
    char out[512];
    const char *url = "https://api.github.com/repos/x/y/foo/bar.bin";
    BOOL r = dbx_build_timestamp_url(url, out, sizeof(out));
    CHECK(r == FALSE);
}

/* 5. Valid URL: output starts with original base (up to "contents/") */
TEST(build_url_valid_url_has_correct_base)
{
    char out[512];
    const char *url = "https://api.github.com/repos/microsoft/secureboot_objects/contents/PostSignedObjects/DBX/amd64/DBXUpdate.bin";
    BOOL r = dbx_build_timestamp_url(url, out, sizeof(out));
    CHECK(r == TRUE);
    CHECK(strncmp(out, "https://api.github.com/repos/microsoft/secureboot_objects/", 58) == 0);
}

/* 6. Valid URL: output contains "commits?path=" */
TEST(build_url_valid_url_contains_commits_path_param)
{
    char out[512];
    const char *url = "https://api.github.com/repos/microsoft/secureboot_objects/contents/PostSignedObjects/DBX/amd64/DBXUpdate.bin";
    BOOL r = dbx_build_timestamp_url(url, out, sizeof(out));
    CHECK(r == TRUE);
    CHECK(strstr(out, "commits?path=") != NULL);
}

/* 7. Forward slashes in path are URL-encoded as %2F */
TEST(build_url_path_slashes_encoded_as_percent2F)
{
    char out[512];
    const char *url = "https://api.github.com/repos/x/y/contents/a/b/c.bin";
    BOOL r = dbx_build_timestamp_url(url, out, sizeof(out));
    CHECK(r == TRUE);
    /* The path "a/b/c.bin" should appear as "a%2Fb%2Fc.bin" */
    CHECK(strstr(out, "a%2Fb%2Fc.bin") != NULL);
    /* No raw '/' after the path= parameter */
    char *path_start = strstr(out, "commits?path=");
    CHECK(path_start != NULL);
    CHECK(strchr(path_start + 13, '/') == NULL);
}

/* 8. Output ends with "&page=1&per_page=1" */
TEST(build_url_output_ends_with_pagination)
{
    char out[512];
    const char *url = "https://api.github.com/repos/x/y/contents/a/b.bin";
    BOOL r = dbx_build_timestamp_url(url, out, sizeof(out));
    CHECK(r == TRUE);
    size_t n = strlen(out);
    const char *suffix = "&page=1&per_page=1";
    CHECK(n >= strlen(suffix));
    CHECK(strcmp(out + n - strlen(suffix), suffix) == 0);
}

/* 9. Buffer too small → returns FALSE */
TEST(build_url_truncated_buffer_returns_false)
{
    char out[10];
    const char *url = "https://api.github.com/repos/x/y/contents/path/file.bin";
    BOOL r = dbx_build_timestamp_url(url, out, sizeof(out));
    CHECK(r == FALSE);
}

/* 10. Exact round-trip for the real amd64 DBX URL */
TEST(build_url_exact_amd64_output)
{
    char out[512];
    const char *url = "https://api.github.com/repos/microsoft/secureboot_objects/contents/PostSignedObjects/DBX/amd64/DBXUpdate.bin";
    const char *expected =
        "https://api.github.com/repos/microsoft/secureboot_objects/"
        "commits?path=PostSignedObjects%2FDBX%2Famd64%2FDBXUpdate.bin"
        "&page=1&per_page=1";
    BOOL r = dbx_build_timestamp_url(url, out, sizeof(out));
    CHECK(r == TRUE);
    CHECK_MSG(strcmp(out, expected) == 0,
        "Expected exact URL output for amd64 DBX");
}

/* 11. Simple single-component path (no sub-slashes) */
TEST(build_url_single_component_path)
{
    char out[512];
    const char *url = "https://example.com/repos/contents/file.bin";
    BOOL r = dbx_build_timestamp_url(url, out, sizeof(out));
    CHECK(r == TRUE);
    CHECK(strstr(out, "file.bin") != NULL);
    /* No %2F since there are no slashes to encode in the path */
    CHECK(strstr(out, "%2F") == NULL);
}

/* ================================================================
 * dbx_parse_github_timestamp() — JSON parser tests
 * ================================================================ */

/* 12. NULL json returns FALSE */
TEST(parse_ts_null_json_returns_false)
{
    uint64_t ts = 0;
    BOOL r = dbx_parse_github_timestamp(NULL, &ts);
    CHECK(r == FALSE);
}

/* 13. NULL output pointer returns FALSE */
TEST(parse_ts_null_ts_returns_false)
{
    const char *json = "[{\"commit\":{\"author\":{\"date\":\"2025-01-01T00:00:00Z\"}}}]";
    BOOL r = dbx_parse_github_timestamp(json, NULL);
    CHECK(r == FALSE);
}

/* 14. JSON with no "date" field returns FALSE */
TEST(parse_ts_missing_date_field_returns_false)
{
    uint64_t ts = 0;
    const char *json = "[{\"commit\":{\"author\":{\"message\":\"no date here\"}}}]";
    BOOL r = dbx_parse_github_timestamp(json, &ts);
    CHECK(r == FALSE);
}

/* 15. Malformed date string returns FALSE */
TEST(parse_ts_malformed_date_returns_false)
{
    uint64_t ts = 0;
    const char *json = "{\"date\":\"not-a-date\"}";
    BOOL r = dbx_parse_github_timestamp(json, &ts);
    CHECK(r == FALSE);
}

/* 16. Partial date (only YYYY-MM-DD, no time) returns FALSE */
TEST(parse_ts_partial_date_missing_time_returns_false)
{
    uint64_t ts = 0;
    const char *json = "{\"date\":\"2025-01-15\"}";
    BOOL r = dbx_parse_github_timestamp(json, &ts);
    CHECK(r == FALSE);
}

/* 17. Valid minimal JSON returns TRUE and non-zero ts */
TEST(parse_ts_valid_json_returns_true_nonzero_ts)
{
    uint64_t ts = 0;
    const char *json = "{\"date\":\"2025-02-24T20:20:22Z\"}";
    BOOL r = dbx_parse_github_timestamp(json, &ts);
    CHECK(r == TRUE);
    CHECK(ts > 0);
}

/* 18. Known date → known epoch: 2025-02-24T20:20:22Z = 1740428422 */
TEST(parse_ts_known_date_matches_expected_epoch)
{
    uint64_t ts = 0;
    const char *json = "{\"date\":\"2025-02-24T20:20:22Z\"}";
    BOOL r = dbx_parse_github_timestamp(json, &ts);
    CHECK(r == TRUE);
    CHECK_INT_EQ((int)1740428422U, (int)ts);
}

/* 19. Second known date: 2025-04-15T16:18:40Z = 1744733920 */
TEST(parse_ts_second_known_date_matches_expected_epoch)
{
    uint64_t ts = 0;
    const char *json = "{\"date\":\"2025-04-15T16:18:40Z\"}";
    BOOL r = dbx_parse_github_timestamp(json, &ts);
    CHECK(r == TRUE);
    CHECK_INT_EQ((int)1744733920U, (int)ts);
}

/* 20. Date embedded inside realistic GitHub API JSON response */
TEST(parse_ts_real_github_json_fragment)
{
    uint64_t ts = 0;
    const char *json =
        "[{\"sha\":\"abc123\","
        "\"commit\":{\"author\":{"
        "\"name\":\"GitHub\","
        "\"email\":\"noreply@github.com\","
        "\"date\":\"2025-03-01T12:00:00Z\""
        "}}}]";
    BOOL r = dbx_parse_github_timestamp(json, &ts);
    CHECK(r == TRUE);
    CHECK(ts > 0);
}

/* 21. Spaces before the date string value are tolerated */
TEST(parse_ts_spaces_before_date_value_tolerated)
{
    uint64_t ts = 0;
    const char *json = "{\"date\":   \"2025-02-24T20:20:22Z\"}";
    BOOL r = dbx_parse_github_timestamp(json, &ts);
    CHECK(r == TRUE);
    CHECK_INT_EQ((int)1740428422U, (int)ts);
}

/* 22. First "date" occurrence in JSON is used */
TEST(parse_ts_first_date_field_used)
{
    uint64_t ts = 0;
    /* Two "date" fields: first one should win */
    const char *json =
        "{\"date\":\"2025-02-24T20:20:22Z\","
        "\"date\":\"2030-01-01T00:00:00Z\"}";
    BOOL r = dbx_parse_github_timestamp(json, &ts);
    CHECK(r == TRUE);
    CHECK_INT_EQ((int)1740428422U, (int)ts);
}

/* 23. Empty string returns FALSE */
TEST(parse_ts_empty_string_returns_false)
{
    uint64_t ts = 0;
    BOOL r = dbx_parse_github_timestamp("", &ts);
    CHECK(r == FALSE);
}

/* ================================================================
 * UseLocalDbx() — settings-based freshness tests
 * ================================================================ */

/* 24. ARCH_UNKNOWN (0) → always FALSE */
TEST(use_local_dbx_arch_unknown_returns_false)
{
    setup_ini();
    BOOL r = UseLocalDbx(ARCH_UNKNOWN);
    teardown_ini();
    CHECK(r == FALSE);
}

/* 25. Negative arch → FALSE */
TEST(use_local_dbx_negative_arch_returns_false)
{
    setup_ini();
    BOOL r = UseLocalDbx(-1);
    teardown_ini();
    CHECK(r == FALSE);
}

/* 26. ARCH_MAX → FALSE (out of range) */
TEST(use_local_dbx_arch_max_returns_false)
{
    setup_ini();
    BOOL r = UseLocalDbx(ARCH_MAX);
    teardown_ini();
    CHECK(r == FALSE);
}

/* 27. ARCH_EBC (8) → FALSE: dbx_info has only 7 entries (arch 1..7) */
TEST(use_local_dbx_arch_ebc_returns_false)
{
    setup_ini();
    BOOL r = UseLocalDbx(ARCH_EBC);
    teardown_ini();
    CHECK(r == FALSE);
}

/* 28. No saved timestamp → FALSE (0 is not > any positive embedded timestamp) */
TEST(use_local_dbx_no_saved_timestamp_returns_false)
{
    setup_ini();
    WriteSetting64("DBXTimestamp_x64", 0);
    BOOL r = UseLocalDbx(ARCH_X86_64);
    teardown_ini();
    CHECK(r == FALSE);
}

/* 29. Saved timestamp well below embedded → FALSE */
TEST(use_local_dbx_saved_less_than_embedded_returns_false)
{
    setup_ini();
    WriteSetting64("DBXTimestamp_x64", (int64_t)1000);
    BOOL r = UseLocalDbx(ARCH_X86_64);
    teardown_ini();
    CHECK(r == FALSE);
}

/* 30. Saved timestamp == embedded → FALSE (must be strictly greater) */
TEST(use_local_dbx_saved_equal_to_embedded_returns_false)
{
    setup_ini();
    /* The embedded x64 timestamp in dbx_info is 1760555920; equal → not > → FALSE */
    WriteSetting64("DBXTimestamp_x64", (int64_t)1760555920);
    BOOL r = UseLocalDbx(ARCH_X86_64);
    teardown_ini();
    CHECK(r == FALSE);
}

/* 31. Saved timestamp > embedded → TRUE */
TEST(use_local_dbx_saved_greater_than_embedded_returns_true)
{
    setup_ini();
    /* INT64_MAX will always exceed any real timestamp */
    WriteSetting64("DBXTimestamp_x64", (int64_t)INT64_MAX);
    BOOL r = UseLocalDbx(ARCH_X86_64);
    teardown_ini();
    CHECK(r == TRUE);
}

/* 32. ARCH_IA_64 has embedded timestamp = 0; any positive saved value → TRUE */
TEST(use_local_dbx_zero_embedded_ts_with_positive_saved_returns_true)
{
    setup_ini();
    WriteSetting64("DBXTimestamp_ia64", (int64_t)1);
    BOOL r = UseLocalDbx(ARCH_IA_64);
    teardown_ini();
    CHECK(r == TRUE);
}

/* 33. ARCH_IA_64 embedded = 0, saved = 0 → FALSE (0 > 0 is false) */
TEST(use_local_dbx_zero_embedded_ts_with_zero_saved_returns_false)
{
    setup_ini();
    WriteSetting64("DBXTimestamp_ia64", (int64_t)0);
    BOOL r = UseLocalDbx(ARCH_IA_64);
    teardown_ini();
    CHECK(r == FALSE);
}

/* 34. ARCH_ARM_64 with large saved timestamp → TRUE */
TEST(use_local_dbx_arm64_with_large_saved_ts_returns_true)
{
    setup_ini();
    WriteSetting64("DBXTimestamp_aa64", (int64_t)INT64_MAX);
    BOOL r = UseLocalDbx(ARCH_ARM_64);
    teardown_ini();
    CHECK(r == TRUE);
}

/* 35. ARCH_RISCV_64 embedded = 0, saved = 12345 → TRUE */
TEST(use_local_dbx_riscv64_positive_saved_returns_true)
{
    setup_ini();
    WriteSetting64("DBXTimestamp_riscv64", (int64_t)12345);
    BOOL r = UseLocalDbx(ARCH_RISCV_64);
    teardown_ini();
    CHECK(r == TRUE);
}

/* 36. ARCH_LOONGARCH_64 embedded = 0, saved = 0 → FALSE */
TEST(use_local_dbx_loongarch64_zero_saved_returns_false)
{
    setup_ini();
    WriteSetting64("DBXTimestamp_loongarch64", (int64_t)0);
    BOOL r = UseLocalDbx(ARCH_LOONGARCH_64);
    teardown_ini();
    CHECK(r == FALSE);
}

/* ================================================================
 * Arch name consistency tests
 * ================================================================ */

/* 37. efi_archname[ARCH_X86_64] == "x64" (matches DBXTimestamp_x64 key) */
TEST(efi_archname_x64_is_x64)
{
    extern const char *efi_archname[];
    CHECK(strcmp(efi_archname[ARCH_X86_64], "x64") == 0);
}

/* 38. efi_archname[ARCH_ARM_64] == "aa64" (matches DBXTimestamp_aa64 key) */
TEST(efi_archname_arm64_is_aa64)
{
    extern const char *efi_archname[];
    CHECK(strcmp(efi_archname[ARCH_ARM_64], "aa64") == 0);
}

/* 39. efi_archname[ARCH_IA_64] == "ia64" */
TEST(efi_archname_ia64_is_ia64)
{
    extern const char *efi_archname[];
    CHECK(strcmp(efi_archname[ARCH_IA_64], "ia64") == 0);
}

/* ================================================================
 * CheckForDBXUpdates() smoke test — must not crash without network
 * ================================================================ */

/* 40. CheckForDBXUpdates() completes without crashing (no-network path) */
TEST(check_for_dbx_updates_no_crash)
{
    setup_ini();
    CheckForDBXUpdates();   /* all downloads fail gracefully; NotificationEx returns IDNO */
    teardown_ini();
    CHECK(TRUE);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
    printf("DBX caching and timestamp tests\n");
    printf("================================\n");

    printf("\n  dbx_build_timestamp_url()\n");
    RUN(build_url_null_content_url_returns_false);
    RUN(build_url_null_out_returns_false);
    RUN(build_url_zero_len_returns_false);
    RUN(build_url_missing_contents_segment_returns_false);
    RUN(build_url_valid_url_has_correct_base);
    RUN(build_url_valid_url_contains_commits_path_param);
    RUN(build_url_path_slashes_encoded_as_percent2F);
    RUN(build_url_output_ends_with_pagination);
    RUN(build_url_truncated_buffer_returns_false);
    RUN(build_url_exact_amd64_output);
    RUN(build_url_single_component_path);

    printf("\n  dbx_parse_github_timestamp()\n");
    RUN(parse_ts_null_json_returns_false);
    RUN(parse_ts_null_ts_returns_false);
    RUN(parse_ts_missing_date_field_returns_false);
    RUN(parse_ts_malformed_date_returns_false);
    RUN(parse_ts_partial_date_missing_time_returns_false);
    RUN(parse_ts_valid_json_returns_true_nonzero_ts);
    RUN(parse_ts_known_date_matches_expected_epoch);
    RUN(parse_ts_second_known_date_matches_expected_epoch);
    RUN(parse_ts_real_github_json_fragment);
    RUN(parse_ts_spaces_before_date_value_tolerated);
    RUN(parse_ts_first_date_field_used);
    RUN(parse_ts_empty_string_returns_false);

    printf("\n  UseLocalDbx()\n");
    RUN(use_local_dbx_arch_unknown_returns_false);
    RUN(use_local_dbx_negative_arch_returns_false);
    RUN(use_local_dbx_arch_max_returns_false);
    RUN(use_local_dbx_arch_ebc_returns_false);
    RUN(use_local_dbx_no_saved_timestamp_returns_false);
    RUN(use_local_dbx_saved_less_than_embedded_returns_false);
    RUN(use_local_dbx_saved_equal_to_embedded_returns_false);
    RUN(use_local_dbx_saved_greater_than_embedded_returns_true);
    RUN(use_local_dbx_zero_embedded_ts_with_positive_saved_returns_true);
    RUN(use_local_dbx_zero_embedded_ts_with_zero_saved_returns_false);
    RUN(use_local_dbx_arm64_with_large_saved_ts_returns_true);
    RUN(use_local_dbx_riscv64_positive_saved_returns_true);
    RUN(use_local_dbx_loongarch64_zero_saved_returns_false);

    printf("\n  Arch name consistency\n");
    RUN(efi_archname_x64_is_x64);
    RUN(efi_archname_arm64_is_aa64);
    RUN(efi_archname_ia64_is_ia64);

    printf("\n  CheckForDBXUpdates() smoke test\n");
    RUN(check_for_dbx_updates_no_crash);

    TEST_RESULTS();
}

#endif /* __linux__ */
