/*
 * test_stdio_linux.c — TDD tests for RunCommandWithProgress (src/linux/stdio.c)
 *
 * Tests cover:
 *  1. Basic command execution — exit code 0 returned for success
 *  2. Non-zero exit code returned for failing commands
 *  3. Command not found returns non-zero
 *  4. Logging mode — stdout/stderr captured (no crash, correct exit code)
 *  5. NULL dir — uses current working directory
 *  6. Progress pattern — regex parsed, UpdateProgressWithInfo called
 *  7. Pattern with no match — runs cleanly, no crash
 *  8. msg=0 pattern=NULL — silent mode, just waits for exit
 *  9. Pipe read: multi-line output is processed
 * 10. Cancelled via ErrorStatus — child is terminated early
 * 11. SizeToHumanReadable — basic unit formatting
 * 12. WindowsErrorString — returns non-NULL
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/* Pull in the public API */
#include "../src/windows/rufus.h"

/* Log handler API from stdio.c */
extern void rufus_set_log_handler(void (*fn)(const char *msg));

/* ---- test stubs for symbols that stdio.c needs from ui / globals ---- */

/* These are normally in globals.c; we define minimal versions here */
DWORD ErrorStatus = 0;
DWORD DownloadStatus = 0;
DWORD MainThreadId = 0;
DWORD LastWriteError = 0;

/* Capture UpdateProgressWithInfo calls */
static int progress_calls = 0;
static uint64_t last_progress_cur = 0;
static uint64_t last_progress_tot = 0;

void UpdateProgress(int op, float percent) { (void)op; (void)percent; }
void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL force)
{
    (void)op; (void)msg; (void)force;
    progress_calls++;
    last_progress_cur = cur;
    last_progress_tot = tot;
}

/* ---- helper to reset state ---- */
static void reset(void)
{
    ErrorStatus = 0;
    progress_calls = 0;
    last_progress_cur = 0;
    last_progress_tot = 0;
}

/* ===========================================================================
 * 1. Basic command — exit code 0
 * =========================================================================*/
TEST(run_command_exit_zero)
{
    reset();
    DWORD r = RunCommand("true", NULL, FALSE);
    CHECK_MSG(r == 0, "RunCommand('true') should return 0");
}

/* ===========================================================================
 * 2. Non-zero exit code
 * =========================================================================*/
TEST(run_command_exit_nonzero)
{
    reset();
    DWORD r = RunCommand("false", NULL, FALSE);
    CHECK_MSG(r != 0, "RunCommand('false') should return non-zero");
}

/* ===========================================================================
 * 3. Command not found
 * =========================================================================*/
TEST(run_command_not_found)
{
    reset();
    DWORD r = RunCommand("__this_command_does_not_exist__", NULL, FALSE);
    CHECK_MSG(r != 0, "Non-existent command should return non-zero exit code");
}

/* ===========================================================================
 * 4. Logging mode — captures output without crash
 * =========================================================================*/
TEST(run_command_with_log)
{
    reset();
    DWORD r = RunCommand("echo hello_world_test", NULL, TRUE);
    CHECK_MSG(r == 0, "echo with log should return 0");
}

/* ===========================================================================
 * 5. NULL dir — uses cwd
 * =========================================================================*/
TEST(run_command_null_dir)
{
    reset();
    DWORD r = RunCommand("pwd", NULL, FALSE);
    CHECK_MSG(r == 0, "pwd with NULL dir should succeed");
}

/* ===========================================================================
 * 6. dir argument — changes working directory for child
 * =========================================================================*/
TEST(run_command_with_dir)
{
    reset();
    DWORD r = RunCommand("pwd", "/tmp", FALSE);
    CHECK_MSG(r == 0, "pwd /tmp should succeed");
}

/* ===========================================================================
 * 7. Progress pattern — UpdateProgressWithInfo called
 *    Use a script that emits a progress line matching the pattern
 *    Pattern: "([0-9]+)%" → matches "50%"
 * =========================================================================*/
TEST(run_command_progress_pattern)
{
    reset();
    /* echo a line that the pattern will match */
    DWORD r = RunCommandWithProgress(
        "printf '50%%\\n'", NULL, FALSE,
        1 /* msg != 0 → enable progress */,
        "([0-9]+)%%"
    );
    CHECK_MSG(r == 0, "printf should succeed");
    CHECK_MSG(progress_calls > 0, "UpdateProgressWithInfo should have been called");
}

/* ===========================================================================
 * 8. Pattern with no match — runs cleanly
 * =========================================================================*/
TEST(run_command_progress_no_match)
{
    reset();
    DWORD r = RunCommandWithProgress(
        "echo nothing_matches_here", NULL, FALSE,
        1,
        "ZZZNOMATCH([0-9]+)"
    );
    CHECK_MSG(r == 0, "Command with non-matching pattern should still succeed");
    /* progress may or may not have been called; we just need no crash */
}

/* ===========================================================================
 * 9. msg=0 pattern=NULL — silent (just wait for exit)
 * =========================================================================*/
TEST(run_command_silent_mode)
{
    reset();
    DWORD r = RunCommandWithProgress("true", NULL, FALSE, 0, NULL);
    CHECK_MSG(r == 0, "Silent mode should still return correct exit code");
}

/* ===========================================================================
 * 10. Multi-line output processed
 * =========================================================================*/
TEST(run_command_multiline_output)
{
    reset();
    DWORD r = RunCommand("printf 'line1\\nline2\\nline3\\n'", NULL, TRUE);
    CHECK_MSG(r == 0, "Multi-line output should be processed without crash");
}

/* ===========================================================================
 * 11. Cancellation via ErrorStatus — child terminates, returns ERROR_CANCELLED
 * =========================================================================*/
TEST(run_command_cancellation)
{
    reset();
    /* Set cancellation flag before launching a long-running command */
    ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED);
    DWORD r = RunCommandWithProgress("sleep 30", NULL, FALSE, 0, NULL);
    /* Command should have been terminated */
    CHECK_MSG(r == ERROR_CANCELLED, "Cancelled command should return ERROR_CANCELLED");
}

/* ===========================================================================
 * 12. SizeToHumanReadable — basic sanity checks
 * =========================================================================*/
TEST(size_to_human_readable_bytes)
{
    char* s = SizeToHumanReadable(512, FALSE, FALSE);
    CHECK_MSG(s != NULL, "SizeToHumanReadable should not return NULL");
    CHECK_MSG(strstr(s, "512") != NULL || strstr(s, "B") != NULL,
              "512 bytes result should contain '512' or 'B'");
}

TEST(size_to_human_readable_kb)
{
    char* s = SizeToHumanReadable(1024, FALSE, FALSE);
    CHECK_MSG(s != NULL, "SizeToHumanReadable 1K should not return NULL");
    /* 1024 bytes = 1.00 KB */
    CHECK_MSG(strstr(s, "1") != NULL, "1024 bytes should produce '1...'");
}

TEST(size_to_human_readable_gb)
{
    char* s = SizeToHumanReadable(2ULL * 1024 * 1024 * 1024, FALSE, FALSE);
    CHECK_MSG(s != NULL, "SizeToHumanReadable 2GB should not return NULL");
    CHECK_MSG(strstr(s, "2") != NULL, "2GB should produce '2...'");
}

/* ===========================================================================
 * 13. WindowsErrorString — non-NULL, non-empty
 * =========================================================================*/
TEST(windows_error_string_non_null)
{
    const char* s = WindowsErrorString();
    CHECK_MSG(s != NULL, "WindowsErrorString should not return NULL");
}

/* ===========================================================================
 * 14–18. Log handler routing
 * uprintf() should call a registered handler instead of writing to stderr.
 * =========================================================================*/

static char captured_log[512];
static int  log_call_count = 0;

static void test_log_handler(const char *msg)
{
    strncpy(captured_log, msg, sizeof(captured_log) - 1);
    captured_log[sizeof(captured_log) - 1] = '\0';
    log_call_count++;
}

TEST(uprintf_calls_registered_handler)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    log_call_count = 0;
    uprintf("hello %d", 42);
    rufus_set_log_handler(NULL);
    CHECK_MSG(log_call_count == 1, "handler should be called exactly once");
    CHECK_MSG(strstr(captured_log, "hello 42") != NULL,
              "handler should receive formatted message");
}

TEST(uprintf_formats_multiple_args)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    uprintf("x=%s y=%d", "foo", 7);
    rufus_set_log_handler(NULL);
    CHECK_MSG(strstr(captured_log, "x=foo") != NULL, "string arg formatted");
    CHECK_MSG(strstr(captured_log, "y=7") != NULL, "integer arg formatted");
}

TEST(uprintf_no_crash_without_handler)
{
    rufus_set_log_handler(NULL);
    /* Should fall back to stderr — just verify no crash */
    uprintf("fallback test %d", 123);
    CHECK(1); /* reached without crash */
}

TEST(uprintf_handler_receives_no_newline)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    uprintf("no newline");
    rufus_set_log_handler(NULL);
    /* The handler should receive the message without a trailing newline,
     * since the handler itself decides how to display it. */
    CHECK_MSG(captured_log[0] != '\0', "handler received a message");
    size_t len = strlen(captured_log);
    CHECK_MSG(len > 0 && captured_log[len - 1] != '\n',
              "handler message should not end with newline");
}

TEST(uprintf_set_and_clear_handler)
{
    int calls_before = 0;
    rufus_set_log_handler(test_log_handler);
    log_call_count = 0;
    uprintf("one");
    calls_before = log_call_count;

    rufus_set_log_handler(NULL);  /* clear handler */
    uprintf("two");  /* should go to stderr only, not handler */
    CHECK_MSG(log_call_count == calls_before, "handler not called after clear");
}

/* ===========================================================================
 * main
 * =========================================================================*/
int main(void)
{
    printf("=== stdio_linux tests ===\n");

    RUN(run_command_exit_zero);
    RUN(run_command_exit_nonzero);
    RUN(run_command_not_found);
    RUN(run_command_with_log);
    RUN(run_command_null_dir);
    RUN(run_command_with_dir);
    RUN(run_command_progress_pattern);
    RUN(run_command_progress_no_match);
    RUN(run_command_silent_mode);
    RUN(run_command_multiline_output);
    RUN(run_command_cancellation);
    RUN(size_to_human_readable_bytes);
    RUN(size_to_human_readable_kb);
    RUN(size_to_human_readable_gb);
    RUN(windows_error_string_non_null);
    RUN(uprintf_calls_registered_handler);
    RUN(uprintf_formats_multiple_args);
    RUN(uprintf_no_crash_without_handler);
    RUN(uprintf_handler_receives_no_newline);
    RUN(uprintf_set_and_clear_handler);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
