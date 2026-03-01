/* tests/test_update_check_linux.c
 * Tests for the first-run update-check consent dialog in SetUpdateCheck().
 *
 * SetUpdateCheck() should:
 *   - On first run (SETTING_UPDATE_INTERVAL == 0): show a Yes/No GTK dialog
 *     asking the user whether they want automatic update checks.
 *     • Yes → write SETTING_UPDATE_INTERVAL = 86400 (daily), return TRUE
 *     • No  → write SETTING_UPDATE_INTERVAL = -1 (disabled), return FALSE
 *   - On subsequent runs (interval != 0): skip dialog entirely.
 *   - When interval == -1 (user explicitly disabled): return FALSE without dialog.
 *   - Return FALSE immediately when settings storage is unavailable (ini_file == NULL).
 *
 * All dialog interactions go through stdlg_set_test_response() which makes
 * NotificationEx() return the injected value without showing any GTK widget.
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

#include "framework.h"

/* Compat + rufus headers */
#include "windows.h"
#include "rufus.h"
#include "missing.h"
#include "localization.h"

/* Settings API */
#include "../src/linux/settings.h"

/* stdlg test injection */
extern void stdlg_set_test_response(int response, const char *file_path);
extern void stdlg_clear_test_mode(void);

/* SetUpdateCheck lives in stdlg.c */
extern BOOL SetUpdateCheck(void);

/* ini_file global (provided by glue) */
extern char *ini_file;

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static char s_tmp_ini[64];

static void setup_ini(void)
{
    snprintf(s_tmp_ini, sizeof(s_tmp_ini), "/tmp/test_upd_XXXXXX");
    int fd = mkstemp(s_tmp_ini);
    if (fd >= 0) close(fd);
    ini_file = s_tmp_ini;
    /* Ensure interval starts as "not set" (0 == first run) */
    WriteSetting32(SETTING_UPDATE_INTERVAL, 0);
}

static void teardown_ini(void)
{
    unlink(s_tmp_ini);
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s~", s_tmp_ini);
    unlink(tmp);
    ini_file = NULL;
    stdlg_clear_test_mode();
}

/* -------------------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------------- */

/* 1. First run + user says YES → daily interval enabled, returns TRUE */
TEST(first_run_user_accepts_enables_daily_updates)
{
    setup_ini();
    stdlg_set_test_response(IDYES, NULL);
    BOOL r = SetUpdateCheck();
    int32_t interval = ReadSetting32(SETTING_UPDATE_INTERVAL);
    teardown_ini();
    CHECK(r == TRUE);
    CHECK(interval > 0);
}

/* 2. First run + user says NO → interval set to -1, returns FALSE */
TEST(first_run_user_declines_disables_updates)
{
    setup_ini();
    stdlg_set_test_response(IDNO, NULL);
    BOOL r = SetUpdateCheck();
    int32_t interval = ReadSetting32(SETTING_UPDATE_INTERVAL);
    teardown_ini();
    CHECK(r == FALSE);
    CHECK_INT_EQ(-1, (int)interval);
}

/* 3. Returning user (interval already set to daily) → no dialog, returns TRUE */
TEST(returning_user_daily_interval_no_dialog_returns_true)
{
    setup_ini();
    WriteSetting32(SETTING_UPDATE_INTERVAL, 86400);
    /* No test response set — if dialog were shown, it would return default IDNO
     * (safe default) and the function would return FALSE.  We expect TRUE. */
    BOOL r = SetUpdateCheck();
    teardown_ini();
    CHECK(r == TRUE);
}

/* 4. User previously disabled updates (interval == -1) → returns FALSE without dialog */
TEST(previously_disabled_returns_false_no_dialog)
{
    setup_ini();
    WriteSetting32(SETTING_UPDATE_INTERVAL, -1);
    BOOL r = SetUpdateCheck();
    teardown_ini();
    CHECK(r == FALSE);
}

/* 5. Settings unavailable (ini_file == NULL) → returns FALSE */
TEST(no_settings_returns_false)
{
    stdlg_clear_test_mode();
    char *saved = ini_file;
    ini_file = NULL;
    BOOL r = SetUpdateCheck();
    ini_file = saved;
    CHECK(r == FALSE);
}

/* 6. First run + YES → interval is exactly DEFAULT_UPDATE_INTERVAL (86400 s) */
TEST(first_run_yes_sets_daily_interval_value)
{
    setup_ini();
    stdlg_set_test_response(IDYES, NULL);
    SetUpdateCheck();
    int32_t interval = ReadSetting32(SETTING_UPDATE_INTERVAL);
    teardown_ini();
    CHECK_INT_EQ(86400, (int)interval);
}

/* 7. CommCheck64 is written and readable as part of SetUpdateCheck */
TEST(comm_check_written_and_readable)
{
    setup_ini();
    stdlg_set_test_response(IDYES, NULL);
    SetUpdateCheck();
    int64_t commcheck = ReadSetting64(SETTING_COMM_CHECK);
    teardown_ini();
    CHECK(commcheck != 0);
}

/* 8. Calling SetUpdateCheck twice (returning user second time) does not
 *    reset a previously accepted interval */
TEST(second_call_does_not_reset_interval)
{
    setup_ini();
    /* First call — user accepts */
    stdlg_set_test_response(IDYES, NULL);
    SetUpdateCheck();
    int32_t after_first = ReadSetting32(SETTING_UPDATE_INTERVAL);
    /* Second call — no response preset (should not show dialog again) */
    BOOL r2 = SetUpdateCheck();
    int32_t after_second = ReadSetting32(SETTING_UPDATE_INTERVAL);
    teardown_ini();
    CHECK(after_first > 0);
    CHECK(r2 == TRUE);
    CHECK_INT_EQ((int)after_first, (int)after_second);
}

/* 9. First run + YES then NO on subsequent calls: interval stays positive */
TEST(subsequent_call_after_yes_stays_positive)
{
    setup_ini();
    stdlg_set_test_response(IDYES, NULL);
    SetUpdateCheck();
    /* Interval is now 86400; second call should not show dialog */
    stdlg_set_test_response(IDNO, NULL); /* if dialog shown, would disable */
    BOOL r = SetUpdateCheck();
    int32_t interval = ReadSetting32(SETTING_UPDATE_INTERVAL);
    teardown_ini();
    CHECK(r == TRUE);
    CHECK(interval > 0);
}

/* 10. Returns FALSE when interval is a large negative (disabled) */
TEST(large_negative_interval_returns_false)
{
    setup_ini();
    WriteSetting32(SETTING_UPDATE_INTERVAL, -99999);
    BOOL r = SetUpdateCheck();
    teardown_ini();
    CHECK(r == FALSE);
}

int main(void)
{
    printf("=== test_update_check_linux ===\n");
    RUN(first_run_user_accepts_enables_daily_updates);
    RUN(first_run_user_declines_disables_updates);
    RUN(returning_user_daily_interval_no_dialog_returns_true);
    RUN(previously_disabled_returns_false_no_dialog);
    RUN(no_settings_returns_false);
    RUN(first_run_yes_sets_daily_interval_value);
    RUN(comm_check_written_and_readable);
    RUN(second_call_does_not_reset_interval);
    RUN(subsequent_call_after_yes_stays_positive);
    RUN(large_negative_interval_returns_false);
    TEST_RESULTS();
}
#endif /* __linux__ */
