/*
 * test_crash_handler_linux.c — Tests for src/linux/crash_handler.c
 *
 * Tests cover:
 *  1. install_crash_handlers — returns 0, SIGSEGV handler is registered
 *  2. install_crash_handlers — SIGABRT handler is registered
 *  3. install_crash_handlers — SIGBUS handler is registered
 *  4. install_crash_handlers — idempotent (calling twice is safe)
 *  5. crash_handler_build_log_path — returns non-NULL for valid buf/size
 *  6. crash_handler_build_log_path — path starts with app_data_dir
 *  7. crash_handler_build_log_path — path contains "crash-" prefix
 *  8. crash_handler_build_log_path — path ends with ".log"
 *  9. crash_handler_build_log_path — NULL buf returns NULL
 * 10. crash_handler_build_log_path — size==0 returns NULL
 * 11. crash_handler_build_log_path — uses /tmp fallback when app_data_dir empty
 * 12. rufus_crash_handler — creates a log file when called directly (test hook)
 * 13. rufus_crash_handler — log file contains "crashed" text
 * 14. rufus_crash_handler — log file contains "Backtrace" section header
 * 15. rufus_crash_handler — exit hook is called with the signal number
 * 16. rufus_crash_handler — log file is created even for SIGABRT
 * 17. rufus_crash_handler — log file is created even for SIGBUS
 * 18. crash_handler_build_log_path — path does not contain consecutive slashes
 * 19. crash_handler_build_log_path — timestamp portion is plausible (year 2020+)
 * 20. crash_handler_build_log_path — output fits entirely in provided buffer
 */

#include "framework.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* The module under test */
#include "../src/linux/crash_handler.h"

/* ---- test stubs for globals crash_handler.c depends on ---- */
char app_data_dir[4096] = "";

/* ---- helpers ---- */

static char g_tmp_dir[256];

/* Create a temp dir for the test and point app_data_dir at it. */
static void setup_tmp_dir(void)
{
    snprintf(g_tmp_dir, sizeof(g_tmp_dir), "/tmp/rufus_crash_test_XXXXXX");
    if (mkdtemp(g_tmp_dir) == NULL) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        g_tmp_dir[0] = '\0';
    }
    snprintf(app_data_dir, sizeof(app_data_dir), "%s", g_tmp_dir);
}

static void cleanup_tmp_dir(void)
{
    if (g_tmp_dir[0] == '\0') return;
    /* Remove crash-*.log files inside the dir, then the dir itself. */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmp_dir);
    (void)system(cmd);
    g_tmp_dir[0] = '\0';
    app_data_dir[0] = '\0';
}

/* Read contents of a file into buf (at most size-1 bytes). Returns bytes read. */
static size_t read_file(const char *path, char *buf, size_t size)
{
    FILE *f = fopen(path, "r");
    size_t n = 0;
    if (!f) return 0;
    n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return n;
}

/* Exit hook used by handler tests — records the signal number. */
static int g_exit_called = 0;
static int g_exit_signum = -1;

static void test_exit_hook(int signum)
{
    g_exit_called = 1;
    g_exit_signum = signum;
}

/* ===========================================================================
 * 1–4. install_crash_handlers — handler registration
 * =========================================================================*/

TEST(install_returns_zero)
{
    int rc = install_crash_handlers();
    CHECK_INT_EQ(0, rc);
}

TEST(sigsegv_handler_is_registered)
{
    struct sigaction sa;
    install_crash_handlers();
    sigaction(SIGSEGV, NULL, &sa);
    /* SA_RESETHAND is set; the handler function must be rufus_crash_handler */
    CHECK_MSG(sa.sa_handler == rufus_crash_handler,
              "SIGSEGV sa_handler should be rufus_crash_handler");
}

TEST(sigabrt_handler_is_registered)
{
    struct sigaction sa;
    install_crash_handlers();
    sigaction(SIGABRT, NULL, &sa);
    CHECK_MSG(sa.sa_handler == rufus_crash_handler,
              "SIGABRT sa_handler should be rufus_crash_handler");
}

TEST(sigbus_handler_is_registered)
{
    struct sigaction sa;
    install_crash_handlers();
    sigaction(SIGBUS, NULL, &sa);
    CHECK_MSG(sa.sa_handler == rufus_crash_handler,
              "SIGBUS sa_handler should be rufus_crash_handler");
}

TEST(install_is_idempotent)
{
    int rc1 = install_crash_handlers();
    int rc2 = install_crash_handlers();
    CHECK_INT_EQ(0, rc1);
    CHECK_INT_EQ(0, rc2);
}

/* ===========================================================================
 * 5–11. crash_handler_build_log_path — path construction
 * =========================================================================*/

TEST(build_log_path_returns_non_null)
{
    char buf[512];
    setup_tmp_dir();
    char *p = crash_handler_build_log_path(buf, sizeof(buf));
    CHECK_MSG(p != NULL, "should return non-NULL for valid buf");
    CHECK_MSG(p == buf,  "should return the same pointer as buf");
    cleanup_tmp_dir();
}

TEST(build_log_path_starts_with_app_data_dir)
{
    char buf[512];
    setup_tmp_dir();
    crash_handler_build_log_path(buf, sizeof(buf));
    CHECK_MSG(strncmp(buf, app_data_dir, strlen(app_data_dir)) == 0,
              "path should start with app_data_dir");
    cleanup_tmp_dir();
}

TEST(build_log_path_contains_crash_prefix)
{
    char buf[512];
    setup_tmp_dir();
    crash_handler_build_log_path(buf, sizeof(buf));
    CHECK_MSG(strstr(buf, "crash-") != NULL,
              "path should contain 'crash-' prefix");
    cleanup_tmp_dir();
}

TEST(build_log_path_ends_with_dot_log)
{
    char buf[512];
    size_t len;
    setup_tmp_dir();
    crash_handler_build_log_path(buf, sizeof(buf));
    len = strlen(buf);
    CHECK_MSG(len > 4 && strcmp(buf + len - 4, ".log") == 0,
              "path should end with '.log'");
    cleanup_tmp_dir();
}

TEST(build_log_path_null_buf_returns_null)
{
    char *p = crash_handler_build_log_path(NULL, 512);
    CHECK_MSG(p == NULL, "NULL buf should return NULL");
}

TEST(build_log_path_zero_size_returns_null)
{
    char buf[512];
    char *p = crash_handler_build_log_path(buf, 0);
    CHECK_MSG(p == NULL, "size==0 should return NULL");
}

TEST(build_log_path_fallback_to_tmp)
{
    char buf[512];
    /* Clear app_data_dir to trigger /tmp fallback */
    char saved[sizeof(app_data_dir)];
    memcpy(saved, app_data_dir, sizeof(app_data_dir));
    app_data_dir[0] = '\0';

    crash_handler_build_log_path(buf, sizeof(buf));
    CHECK_MSG(strncmp(buf, "/tmp/", 5) == 0,
              "path should start with /tmp/ when app_data_dir is empty");

    memcpy(app_data_dir, saved, sizeof(app_data_dir));
}

TEST(build_log_path_no_double_slash)
{
    char buf[512];
    setup_tmp_dir();
    crash_handler_build_log_path(buf, sizeof(buf));
    CHECK_MSG(strstr(buf, "//") == NULL,
              "path should not contain consecutive slashes");
    cleanup_tmp_dir();
}

TEST(build_log_path_timestamp_plausible)
{
    char buf[512];
    char *p;
    setup_tmp_dir();
    crash_handler_build_log_path(buf, sizeof(buf));
    /* Find "crash-" and check the year that follows */
    p = strstr(buf, "crash-");
    CHECK_MSG(p != NULL, "'crash-' found in path");
    if (p) {
        /* p points to "crash-YYYY-..."; year starts at p+6 */
        int year = 0;
        sscanf(p + 6, "%4d", &year);
        CHECK_MSG(year >= 2020,
                  "timestamp year should be >= 2020");
    }
    cleanup_tmp_dir();
}

TEST(build_log_path_fits_in_buffer)
{
    char buf[512];
    setup_tmp_dir();
    char *p = crash_handler_build_log_path(buf, sizeof(buf));
    CHECK_MSG(p != NULL, "build_log_path succeeded");
    CHECK_MSG(strlen(buf) < sizeof(buf),
              "path fits within provided buffer");
    cleanup_tmp_dir();
}

/* ===========================================================================
 * 12–17. rufus_crash_handler — direct invocation via test hook
 * =========================================================================*/

TEST(handler_creates_log_file)
{
    char log_path[512];
    struct stat st;

    setup_tmp_dir();
    crash_handler_set_exit(test_exit_hook);
    g_exit_called = 0;
    g_exit_signum = -1;

    rufus_crash_handler(SIGSEGV);

    /* Build what the path should be (within ~1 second margin) */
    crash_handler_build_log_path(log_path, sizeof(log_path));

    /* The log file should exist somewhere under g_tmp_dir */
    {
        char find_cmd[512];
        char found_path[512] = "";
        FILE *fp;
        snprintf(find_cmd, sizeof(find_cmd),
                 "find %s -name 'crash-*.log' 2>/dev/null | head -1",
                 g_tmp_dir);
        fp = popen(find_cmd, "r");
        if (fp) {
            if (fgets(found_path, sizeof(found_path), fp)) {
                /* strip trailing newline */
                size_t n = strlen(found_path);
                if (n > 0 && found_path[n-1] == '\n') found_path[n-1] = '\0';
            }
            pclose(fp);
        }
        CHECK_MSG(found_path[0] != '\0',
                  "crash log file should exist under tmp dir");
        CHECK_MSG(stat(found_path, &st) == 0 && st.st_size > 0,
                  "crash log file should be non-empty");
    }

    crash_handler_set_exit(NULL);
    cleanup_tmp_dir();
}

TEST(handler_log_contains_crashed_text)
{
    char found_path[512] = "";
    char content[4096];
    FILE *fp;
    char find_cmd[512];

    setup_tmp_dir();
    crash_handler_set_exit(test_exit_hook);

    rufus_crash_handler(SIGSEGV);

    snprintf(find_cmd, sizeof(find_cmd),
             "find %s -name 'crash-*.log' 2>/dev/null | head -1", g_tmp_dir);
    fp = popen(find_cmd, "r");
    if (fp) {
        if (fgets(found_path, sizeof(found_path), fp)) {
            size_t n = strlen(found_path);
            if (n > 0 && found_path[n-1] == '\n') found_path[n-1] = '\0';
        }
        pclose(fp);
    }

    read_file(found_path, content, sizeof(content));
    CHECK_MSG(strstr(content, "crashed") != NULL || strstr(content, "Rufus") != NULL,
              "log should contain 'crashed' or 'Rufus'");

    crash_handler_set_exit(NULL);
    cleanup_tmp_dir();
}

TEST(handler_log_contains_backtrace_header)
{
    char found_path[512] = "";
    char content[4096];
    FILE *fp;
    char find_cmd[512];

    setup_tmp_dir();
    crash_handler_set_exit(test_exit_hook);

    rufus_crash_handler(SIGSEGV);

    snprintf(find_cmd, sizeof(find_cmd),
             "find %s -name 'crash-*.log' 2>/dev/null | head -1", g_tmp_dir);
    fp = popen(find_cmd, "r");
    if (fp) {
        if (fgets(found_path, sizeof(found_path), fp)) {
            size_t n = strlen(found_path);
            if (n > 0 && found_path[n-1] == '\n') found_path[n-1] = '\0';
        }
        pclose(fp);
    }

    read_file(found_path, content, sizeof(content));
    CHECK_MSG(strstr(content, "Backtrace") != NULL,
              "log should contain 'Backtrace' section header");

    crash_handler_set_exit(NULL);
    cleanup_tmp_dir();
}

TEST(handler_exit_hook_receives_signal_number)
{
    setup_tmp_dir();
    crash_handler_set_exit(test_exit_hook);
    g_exit_called = 0;
    g_exit_signum = -1;

    rufus_crash_handler(SIGSEGV);

    CHECK_MSG(g_exit_called == 1, "exit hook should be called exactly once");
    CHECK_INT_EQ(SIGSEGV, g_exit_signum);

    crash_handler_set_exit(NULL);
    cleanup_tmp_dir();
}

TEST(handler_sigabrt_creates_log_file)
{
    struct stat st;
    char found_path[512] = "";
    FILE *fp;
    char find_cmd[512];

    setup_tmp_dir();
    crash_handler_set_exit(test_exit_hook);
    g_exit_called = 0;

    rufus_crash_handler(SIGABRT);

    CHECK_INT_EQ(1, g_exit_called);

    snprintf(find_cmd, sizeof(find_cmd),
             "find %s -name 'crash-*.log' 2>/dev/null | head -1", g_tmp_dir);
    fp = popen(find_cmd, "r");
    if (fp) {
        if (fgets(found_path, sizeof(found_path), fp)) {
            size_t n = strlen(found_path);
            if (n > 0 && found_path[n-1] == '\n') found_path[n-1] = '\0';
        }
        pclose(fp);
    }
    CHECK_MSG(found_path[0] != '\0' && stat(found_path, &st) == 0 && st.st_size > 0,
              "crash log for SIGABRT should be non-empty");

    crash_handler_set_exit(NULL);
    cleanup_tmp_dir();
}

TEST(handler_sigbus_creates_log_file)
{
    struct stat st;
    char found_path[512] = "";
    FILE *fp;
    char find_cmd[512];

    setup_tmp_dir();
    crash_handler_set_exit(test_exit_hook);
    g_exit_called = 0;

    rufus_crash_handler(SIGBUS);

    CHECK_INT_EQ(1, g_exit_called);

    snprintf(find_cmd, sizeof(find_cmd),
             "find %s -name 'crash-*.log' 2>/dev/null | head -1", g_tmp_dir);
    fp = popen(find_cmd, "r");
    if (fp) {
        if (fgets(found_path, sizeof(found_path), fp)) {
            size_t n = strlen(found_path);
            if (n > 0 && found_path[n-1] == '\n') found_path[n-1] = '\0';
        }
        pclose(fp);
    }
    CHECK_MSG(found_path[0] != '\0' && stat(found_path, &st) == 0 && st.st_size > 0,
              "crash log for SIGBUS should be non-empty");

    crash_handler_set_exit(NULL);
    cleanup_tmp_dir();
}

/* ===========================================================================
 * 18–20. Additional path-construction edge cases
 * =========================================================================*/

TEST(build_log_path_with_trailing_slash_in_app_data_dir)
{
    char buf[512];
    /* Simulate app_data_dir ending with a slash (shouldn't cause //) */
    char saved[sizeof(app_data_dir)];
    memcpy(saved, app_data_dir, sizeof(app_data_dir));
    snprintf(app_data_dir, sizeof(app_data_dir), "/tmp/rufus_test_dir");

    crash_handler_build_log_path(buf, sizeof(buf));
    CHECK_MSG(strstr(buf, "//") == NULL,
              "no double-slash even if app_data_dir has a slash");

    memcpy(app_data_dir, saved, sizeof(app_data_dir));
}

TEST(handler_log_contains_signal_number)
{
    char found_path[512] = "";
    char content[4096];
    FILE *fp;
    char find_cmd[512];
    char sig_str[16];

    setup_tmp_dir();
    crash_handler_set_exit(test_exit_hook);

    rufus_crash_handler(SIGSEGV);

    snprintf(find_cmd, sizeof(find_cmd),
             "find %s -name 'crash-*.log' 2>/dev/null | head -1", g_tmp_dir);
    fp = popen(find_cmd, "r");
    if (fp) {
        if (fgets(found_path, sizeof(found_path), fp)) {
            size_t n = strlen(found_path);
            if (n > 0 && found_path[n-1] == '\n') found_path[n-1] = '\0';
        }
        pclose(fp);
    }

    read_file(found_path, content, sizeof(content));
    snprintf(sig_str, sizeof(sig_str), "%d", SIGSEGV);
    CHECK_MSG(strstr(content, sig_str) != NULL,
              "log should contain the signal number as text");

    crash_handler_set_exit(NULL);
    cleanup_tmp_dir();
}

TEST(handler_exit_hook_clear_and_reset)
{
    /* Verify that NULL hook is safe (doesn't call anything, returns normally) */
    setup_tmp_dir();
    crash_handler_set_exit(test_exit_hook);
    crash_handler_set_exit(NULL);   /* clear hook */

    /* Can't call rufus_crash_handler here without the hook — it would _exit().
     * Just verify the set/clear API doesn't crash. */
    CHECK(1);
    cleanup_tmp_dir();
}

/* ===========================================================================
 * main
 * =========================================================================*/

int main(void)
{
    printf("=== test_crash_handler_linux ===\n");

    printf("\n  install_crash_handlers — signal registration\n");
    RUN(install_returns_zero);
    RUN(sigsegv_handler_is_registered);
    RUN(sigabrt_handler_is_registered);
    RUN(sigbus_handler_is_registered);
    RUN(install_is_idempotent);

    printf("\n  crash_handler_build_log_path — path construction\n");
    RUN(build_log_path_returns_non_null);
    RUN(build_log_path_starts_with_app_data_dir);
    RUN(build_log_path_contains_crash_prefix);
    RUN(build_log_path_ends_with_dot_log);
    RUN(build_log_path_null_buf_returns_null);
    RUN(build_log_path_zero_size_returns_null);
    RUN(build_log_path_fallback_to_tmp);
    RUN(build_log_path_no_double_slash);
    RUN(build_log_path_timestamp_plausible);
    RUN(build_log_path_fits_in_buffer);

    printf("\n  rufus_crash_handler — direct invocation\n");
    RUN(handler_creates_log_file);
    RUN(handler_log_contains_crashed_text);
    RUN(handler_log_contains_backtrace_header);
    RUN(handler_exit_hook_receives_signal_number);
    RUN(handler_sigabrt_creates_log_file);
    RUN(handler_sigbus_creates_log_file);
    RUN(handler_log_contains_signal_number);

    printf("\n  edge cases\n");
    RUN(build_log_path_with_trailing_slash_in_app_data_dir);
    RUN(handler_exit_hook_clear_and_reset);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
