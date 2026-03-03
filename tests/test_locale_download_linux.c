/* tests/test_locale_download_linux.c
 *
 * Tests for locale auto-download (Item 115).
 *
 * This covers:
 *   - parse_update() populating update.loc_url and update.loc_version
 *   - is_locale_update_needed() deciding when a refresh is required
 *   - download_locale_update() writing the .loc file to app_data_dir
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
#include <time.h>
#include <sys/stat.h>

#include "framework.h"

/* Compat layer */
#include "windows.h"
#include "rufus.h"
#include "missing.h"

/* Settings */
#include "../src/linux/settings.h"

/* Tested functions */
extern void parse_update(char *buf, size_t len);
extern RUFUS_UPDATE update;

extern BOOL is_locale_update_needed(void);
extern BOOL download_locale_update(void);

/* app_data_dir exposed by globals.c */
extern char app_data_dir[];

/* ini_file from settings.h */
extern char *ini_file;

/* -----------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------- */

static char s_ini[64];

static void setup_ini(void)
{
    snprintf(s_ini, sizeof(s_ini), "/tmp/test_loc_XXXXXX");
    int fd = mkstemp(s_ini);
    if (fd >= 0) close(fd);
    ini_file = s_ini;
}

static void teardown_ini(void)
{
    unlink(s_ini);
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s~", s_ini);
    unlink(tmp);
    ini_file = NULL;
}

/* Reset update struct to a clean state */
static void reset_update(void)
{
    safe_free(update.loc_url);
    update.loc_version = 0;
}

/* -----------------------------------------------------------------------
 * Part 1 – parse_update() locale fields
 * -------------------------------------------------------------------- */

/* 1. A buffer with loc_url should populate update.loc_url */
TEST(parse_update_sets_loc_url)
{
    reset_update();
    char buf[] = "version = 4.0.0\nloc_url = https://example.com/embedded.loc\nloc_version = 42\n";
    parse_update(buf, strlen(buf) + 1);
    CHECK(update.loc_url != NULL);
    CHECK(strstr(update.loc_url, "embedded.loc") != NULL);
    reset_update();
}

/* 2. A buffer with loc_version should populate update.loc_version */
TEST(parse_update_sets_loc_version)
{
    reset_update();
    char buf[] = "version = 4.0.0\nloc_url = https://example.com/embedded.loc\nloc_version = 77\n";
    parse_update(buf, strlen(buf) + 1);
    CHECK_INT_EQ(77, (int)update.loc_version);
    reset_update();
}

/* 3. Buffer without loc_url leaves update.loc_url NULL */
TEST(parse_update_no_loc_url_leaves_null)
{
    reset_update();
    char buf[] = "version = 4.0.0\ndownload_url = https://example.com/rufus.tar.gz\n";
    parse_update(buf, strlen(buf) + 1);
    CHECK(update.loc_url == NULL);
}

/* 4. Buffer without loc_version leaves update.loc_version == 0 */
TEST(parse_update_no_loc_version_leaves_zero)
{
    reset_update();
    char buf[] = "version = 4.0.0\ndownload_url = https://example.com/rufus.tar.gz\n";
    parse_update(buf, strlen(buf) + 1);
    CHECK_INT_EQ(0, (int)update.loc_version);
}

/* 5. Re-parsing with a different loc_url frees the old one and sets the new one */
TEST(parse_update_replaces_old_loc_url)
{
    reset_update();
    char buf1[] = "version = 4.0.0\nloc_url = https://example.com/old.loc\nloc_version = 1\n";
    parse_update(buf1, strlen(buf1) + 1);
    char *first = update.loc_url ? strdup(update.loc_url) : NULL;

    char buf2[] = "version = 4.0.0\nloc_url = https://example.com/new.loc\nloc_version = 2\n";
    parse_update(buf2, strlen(buf2) + 1);

    CHECK(update.loc_url != NULL);
    CHECK(first == NULL || strcmp(first, update.loc_url) != 0);
    free(first);
    reset_update();
}

/* 6. Re-parsing with no loc_url frees the old and sets NULL */
TEST(parse_update_clears_loc_url_on_reparse_without_it)
{
    reset_update();
    char buf1[] = "version = 4.0.0\nloc_url = https://example.com/embedded.loc\nloc_version = 3\n";
    parse_update(buf1, strlen(buf1) + 1);
    CHECK(update.loc_url != NULL);

    char buf2[] = "version = 4.0.0\ndownload_url = https://example.com/rufus.tar.gz\n";
    parse_update(buf2, strlen(buf2) + 1);
    CHECK(update.loc_url == NULL);
    CHECK_INT_EQ(0, (int)update.loc_version);
}

/* -----------------------------------------------------------------------
 * Part 2 – is_locale_update_needed()
 * -------------------------------------------------------------------- */

/* 7. No loc_url → not needed */
TEST(no_loc_url_not_needed)
{
    setup_ini();
    reset_update();
    BOOL r = is_locale_update_needed();
    teardown_ini();
    CHECK(r == FALSE);
}

/* 8. loc_url set, stored version == 0, file absent → needed */
TEST(version_zero_with_url_is_needed)
{
    setup_ini();
    reset_update();
    update.loc_url = strdup("https://example.com/embedded.loc");
    update.loc_version = 5;
    /* stored version starts at 0 (fresh ini) */
    BOOL r = is_locale_update_needed();
    teardown_ini();
    reset_update();
    CHECK(r == TRUE);
}

/* 9. loc_url set, stored version matches → not needed (even if stale time) */
TEST(version_matches_not_needed)
{
    setup_ini();
    reset_update();
    update.loc_url = strdup("https://example.com/embedded.loc");
    update.loc_version = 10;
    /* Write matching stored version and recent timestamp */
    WriteSetting32(SETTING_LOCALE_VERSION, 10);
    WriteSetting64(SETTING_LAST_LOCALE_UPDATE, (int64_t)time(NULL));
    BOOL r = is_locale_update_needed();
    teardown_ini();
    reset_update();
    CHECK(r == FALSE);
}

/* 10. loc_url set, stored version differs → needed */
TEST(version_mismatch_is_needed)
{
    setup_ini();
    reset_update();
    update.loc_url = strdup("https://example.com/embedded.loc");
    update.loc_version = 20;
    WriteSetting32(SETTING_LOCALE_VERSION, 15);
    WriteSetting64(SETTING_LAST_LOCALE_UPDATE, (int64_t)time(NULL));
    BOOL r = is_locale_update_needed();
    teardown_ini();
    reset_update();
    CHECK(r == TRUE);
}

/* 11. loc_url set, last check was > 30 days ago → needed even if versions match */
TEST(stale_timestamp_triggers_recheck)
{
    setup_ini();
    reset_update();
    update.loc_url = strdup("https://example.com/embedded.loc");
    update.loc_version = 5;
    WriteSetting32(SETTING_LOCALE_VERSION, 5);
    /* 31 days ago */
    WriteSetting64(SETTING_LAST_LOCALE_UPDATE, (int64_t)(time(NULL) - 31 * 86400));
    BOOL r = is_locale_update_needed();
    teardown_ini();
    reset_update();
    CHECK(r == TRUE);
}

/* 12. loc_url set, last check was just now → not needed (version matches) */
TEST(recent_timestamp_not_needed_if_version_matches)
{
    setup_ini();
    reset_update();
    update.loc_url = strdup("https://example.com/embedded.loc");
    update.loc_version = 7;
    WriteSetting32(SETTING_LOCALE_VERSION, 7);
    WriteSetting64(SETTING_LAST_LOCALE_UPDATE, (int64_t)time(NULL));
    BOOL r = is_locale_update_needed();
    teardown_ini();
    reset_update();
    CHECK(r == FALSE);
}

/* -----------------------------------------------------------------------
 * Part 3 – download_locale_update() output path
 * -------------------------------------------------------------------- */

/* 13. download_locale_update with no loc_url returns FALSE immediately */
TEST(download_no_loc_url_returns_false)
{
    setup_ini();
    reset_update();
    /* No URL set */
    BOOL r = download_locale_update();
    teardown_ini();
    CHECK(r == FALSE);
}

/* 14. download_locale_update target path is under app_data_dir */
TEST(download_target_path_under_app_data_dir)
{
    /* Verify the destination path contains app_data_dir as prefix.
     * We test the path-building logic via get_locale_download_path(). */
    extern const char *get_locale_download_path(void);
    const char *p = get_locale_download_path();
    CHECK(p != NULL);
    if (app_data_dir[0] != '\0')
        CHECK(strncmp(p, app_data_dir, strlen(app_data_dir)) == 0);
    /* Path must end with "embedded.loc" */
    CHECK(strstr(p, "embedded.loc") != NULL);
}

/* 15. After a successful download_locale_update(), SETTING_LAST_LOCALE_UPDATE
 *     should be updated to a recent timestamp.
 *     We use a file:// URL pointing at a local temp file to avoid network. */
TEST(download_updates_last_locale_timestamp)
{
    /* Create a temp dir as fake app_data_dir */
    char fake_data_dir[] = "/tmp/test_loc_data_XXXXXX";
    char *dd = mkdtemp(fake_data_dir);
    if (!dd) { printf("SKIP: mkdtemp failed\n"); return; }

    /* Write a dummy embedded.loc to serve as source */
    char src_loc[] = "/tmp/test_loc_src_XXXXXX";
    int fd = mkstemp(src_loc);
    if (fd < 0) { rmdir(fake_data_dir); printf("SKIP: mkstemp failed\n"); return; }
    write(fd, "[loc]\nversion = 42\n", 20);
    close(fd);

    setup_ini();
    reset_update();

    /* Point app_data_dir at our temp dir */
    char saved_data_dir[MAX_PATH];
    strncpy(saved_data_dir, app_data_dir, sizeof(saved_data_dir));
    snprintf(app_data_dir, MAX_PATH, "%s", fake_data_dir);

    /* Use file:// URL so no real network needed */
    char url[256];
    snprintf(url, sizeof(url), "file://%s", src_loc);
    update.loc_url = strdup(url);
    update.loc_version = 42;

    BOOL r = download_locale_update();
    int64_t ts = ReadSetting64(SETTING_LAST_LOCALE_UPDATE);

    /* Restore */
    snprintf(app_data_dir, MAX_PATH, "%s", saved_data_dir);
    teardown_ini();
    reset_update();
    unlink(src_loc);
    /* Remove downloaded file */
    char dl_path[MAX_PATH];
    snprintf(dl_path, sizeof(dl_path), "%s/embedded.loc", fake_data_dir);
    unlink(dl_path);
    rmdir(fake_data_dir);

    CHECK(r == TRUE);
    CHECK(ts > 0);
    /* Timestamp should be within the last minute */
    CHECK((time_t)ts > time(NULL) - 60);
}

/* 16. After a successful download, SETTING_LOCALE_VERSION is set to update.loc_version */
TEST(download_stores_loc_version)
{
    char fake_data_dir[] = "/tmp/test_loc_ver_XXXXXX";
    char *dd = mkdtemp(fake_data_dir);
    if (!dd) { printf("SKIP: mkdtemp failed\n"); return; }

    char src_loc[] = "/tmp/test_loc_ver_src_XXXXXX";
    int fd = mkstemp(src_loc);
    if (fd < 0) { rmdir(fake_data_dir); printf("SKIP: mkstemp failed\n"); return; }
    write(fd, "[loc]\nversion = 99\n", 19);
    close(fd);

    setup_ini();
    reset_update();

    char saved_data_dir[MAX_PATH];
    strncpy(saved_data_dir, app_data_dir, sizeof(saved_data_dir));
    snprintf(app_data_dir, MAX_PATH, "%s", fake_data_dir);

    char url[256];
    snprintf(url, sizeof(url), "file://%s", src_loc);
    update.loc_url = strdup(url);
    update.loc_version = 99;

    BOOL r = download_locale_update();
    int32_t stored_ver = ReadSetting32(SETTING_LOCALE_VERSION);

    snprintf(app_data_dir, MAX_PATH, "%s", saved_data_dir);
    teardown_ini();
    reset_update();
    unlink(src_loc);
    char dl_path[MAX_PATH];
    snprintf(dl_path, sizeof(dl_path), "%s/embedded.loc", fake_data_dir);
    unlink(dl_path);
    rmdir(fake_data_dir);

    CHECK(r == TRUE);
    CHECK_INT_EQ(99, (int)stored_ver);
}

/* 17. SETTING_LOCALE_VERSION and SETTING_LAST_LOCALE_UPDATE are readable
 *     as 32-bit and 64-bit respectively */
TEST(locale_settings_read_write_roundtrip)
{
    setup_ini();
    WriteSetting32(SETTING_LOCALE_VERSION, 123);
    WriteSetting64(SETTING_LAST_LOCALE_UPDATE, (int64_t)9876543210LL);
    int32_t v = ReadSetting32(SETTING_LOCALE_VERSION);
    int64_t t = ReadSetting64(SETTING_LAST_LOCALE_UPDATE);
    teardown_ini();
    CHECK_INT_EQ(123, (int)v);
    CHECK(t == (int64_t)9876543210LL);
}

/* 18. loc_version in parse_update buffer can be a multi-digit number */
TEST(parse_update_loc_version_multi_digit)
{
    reset_update();
    char buf[] = "version = 4.0.0\nloc_url = https://example.com/embedded.loc\nloc_version = 12345\n";
    parse_update(buf, strlen(buf) + 1);
    CHECK_INT_EQ(12345, (int)update.loc_version);
    reset_update();
}

int main(void)
{
    printf("=== test_locale_download_linux ===\n");
    RUN(parse_update_sets_loc_url);
    RUN(parse_update_sets_loc_version);
    RUN(parse_update_no_loc_url_leaves_null);
    RUN(parse_update_no_loc_version_leaves_zero);
    RUN(parse_update_replaces_old_loc_url);
    RUN(parse_update_clears_loc_url_on_reparse_without_it);
    RUN(no_loc_url_not_needed);
    RUN(version_zero_with_url_is_needed);
    RUN(version_matches_not_needed);
    RUN(version_mismatch_is_needed);
    RUN(stale_timestamp_triggers_recheck);
    RUN(recent_timestamp_not_needed_if_version_matches);
    RUN(download_no_loc_url_returns_false);
    RUN(download_target_path_under_app_data_dir);
    RUN(download_updates_last_locale_timestamp);
    RUN(download_stores_loc_version);
    RUN(locale_settings_read_write_roundtrip);
    RUN(parse_update_loc_version_multi_digit);
    TEST_RESULTS();
}
#endif /* __linux__ */
