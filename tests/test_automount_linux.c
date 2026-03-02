/*
 * test_automount_linux.c — Tests for SetAutoMount() / GetAutoMount()
 *
 * Verifies that the udev-rule-based automount inhibit works correctly
 * without touching the real /run/udev/rules.d/ directory.
 *
 * The rule file path is redirected to a temporary file via
 * automount_set_rule_file() (RUFUS_TEST build-time injection).
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "framework.h"

/* compat layer */
#include "windows.h"

/* rufus types */
#include "rufus.h"
#include "missing.h"
#include "drive.h"

/* Linux-internal API — gives automount_set_rule_file() */
#include "../src/linux/drive_linux.h"

/* =========================================================================
 * Helpers
 * ========================================================================= */

/* Path of the rule file injected for each test */
static char g_rule_path[256];

/* Create a unique temp path (file is NOT created, only the name is reserved) */
static void make_tmp_rule_path(void)
{
    snprintf(g_rule_path, sizeof(g_rule_path), "/tmp/test_automount_XXXXXX");
    /* mkstemp creates the file; we close + remove it immediately so the path
       is available as a clean "not-yet-created" target for the test. */
    int fd = mkstemp(g_rule_path);
    if (fd >= 0) {
        close(fd);
        unlink(g_rule_path);
    }
    automount_set_rule_file(g_rule_path);
}

static void cleanup_rule_file(void)
{
    unlink(g_rule_path);
    automount_set_rule_file(NULL);
}

/* =========================================================================
 * Tests
 * ========================================================================= */

/* SetAutoMount(FALSE) creates the rule file */
TEST(set_automount_disable_creates_rule_file)
{
    make_tmp_rule_path();

    BOOL ok = SetAutoMount(FALSE);
    CHECK(ok);

    struct stat st;
    CHECK(stat(g_rule_path, &st) == 0);

    cleanup_rule_file();
}

/* SetAutoMount(TRUE) removes the rule file */
TEST(set_automount_enable_removes_rule_file)
{
    make_tmp_rule_path();

    /* First disable … */
    CHECK(SetAutoMount(FALSE));
    struct stat st;
    CHECK(stat(g_rule_path, &st) == 0);  /* file exists */

    /* … then re-enable */
    CHECK(SetAutoMount(TRUE));
    CHECK(stat(g_rule_path, &st) != 0);  /* file gone */
    CHECK(errno == ENOENT);

    cleanup_rule_file();
}

/* SetAutoMount(TRUE) when no rule file exists returns TRUE (idempotent) */
TEST(set_automount_enable_idempotent)
{
    make_tmp_rule_path();
    /* File doesn't exist yet — enabling should still succeed */
    CHECK(SetAutoMount(TRUE));
    cleanup_rule_file();
}

/* GetAutoMount returns TRUE (enabled) when no rule file exists */
TEST(get_automount_returns_true_when_no_rule)
{
    make_tmp_rule_path();
    /* No rule file present */
    BOOL enabled = FALSE;
    BOOL ok = GetAutoMount(&enabled);
    CHECK(ok);
    CHECK(enabled == TRUE);
    cleanup_rule_file();
}

/* GetAutoMount returns FALSE (disabled) when rule file exists */
TEST(get_automount_returns_false_when_rule_present)
{
    make_tmp_rule_path();

    CHECK(SetAutoMount(FALSE));

    BOOL enabled = TRUE;
    BOOL ok = GetAutoMount(&enabled);
    CHECK(ok);
    CHECK(enabled == FALSE);

    cleanup_rule_file();
}

/* GetAutoMount NULL pointer guard */
TEST(get_automount_null_guard)
{
    CHECK(GetAutoMount(NULL) == FALSE);
}

/* Repeated disable is idempotent */
TEST(set_automount_disable_idempotent)
{
    make_tmp_rule_path();

    CHECK(SetAutoMount(FALSE));
    CHECK(SetAutoMount(FALSE));  /* overwrite — should succeed */

    BOOL enabled;
    CHECK(GetAutoMount(&enabled));
    CHECK(enabled == FALSE);

    cleanup_rule_file();
}

/* SetAutoMount FALSE then TRUE then FALSE → round trip */
TEST(automount_round_trip)
{
    make_tmp_rule_path();

    BOOL enabled;

    /* Start: enabled */
    CHECK(GetAutoMount(&enabled));
    CHECK(enabled == TRUE);

    /* Disable */
    CHECK(SetAutoMount(FALSE));
    CHECK(GetAutoMount(&enabled));
    CHECK(enabled == FALSE);

    /* Re-enable */
    CHECK(SetAutoMount(TRUE));
    CHECK(GetAutoMount(&enabled));
    CHECK(enabled == TRUE);

    /* Disable again */
    CHECK(SetAutoMount(FALSE));
    CHECK(GetAutoMount(&enabled));
    CHECK(enabled == FALSE);

    cleanup_rule_file();
}

/* Rule file contains expected udev directives */
TEST(rule_file_content)
{
    make_tmp_rule_path();

    CHECK(SetAutoMount(FALSE));

    FILE *fp = fopen(g_rule_path, "r");
    CHECK(fp != NULL);

    char buf[1024] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    CHECK(n > 0);

    /* Must contain the UDISKS_AUTO suppressor */
    CHECK(strstr(buf, "UDISKS_AUTO") != NULL);
    CHECK(strstr(buf, "UDISKS_IGNORE") != NULL);
    CHECK(strstr(buf, "block") != NULL);

    cleanup_rule_file();
}

/* =========================================================================
 * Main
 * ========================================================================= */
int main(void)
{
    RUN(set_automount_disable_creates_rule_file);
    RUN(set_automount_enable_removes_rule_file);
    RUN(set_automount_enable_idempotent);
    RUN(get_automount_returns_true_when_no_rule);
    RUN(get_automount_returns_false_when_rule_present);
    RUN(get_automount_null_guard);
    RUN(set_automount_disable_idempotent);
    RUN(automount_round_trip);
    RUN(rule_file_content);
    TEST_RESULTS();
}

#endif /* __linux__ */
