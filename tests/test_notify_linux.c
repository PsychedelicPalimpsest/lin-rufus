/* tests/test_notify_linux.c
 * Tests for the libnotify / notify-send desktop notification bridge.
 * These tests cover the pure-C command-building logic in notify.c and the
 * exported API surface, exercising all behaviour that doesn't require a
 * running DBus / notification daemon.
 */
#include "framework.h"
#include "../src/linux/notify.h"

#include <string.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * notify_build_cmd() tests
 * ------------------------------------------------------------------------- */

TEST(build_cmd_null_title_returns_zero)
{
    char buf[256];
    size_t n = notify_build_cmd(NULL, "body", TRUE, buf, sizeof(buf));
    CHECK_INT_EQ(0, (int)n);
}

TEST(build_cmd_null_body_uses_empty)
{
    char buf[256];
    size_t n = notify_build_cmd("Title", NULL, TRUE, buf, sizeof(buf));
    CHECK(n > 0);
    CHECK(strstr(buf, "Title") != NULL);
}

TEST(build_cmd_null_buf_returns_zero)
{
    size_t n = notify_build_cmd("Title", "Body", TRUE, NULL, 256);
    CHECK_INT_EQ(0, (int)n);
}

TEST(build_cmd_zero_bufsz_returns_zero)
{
    char buf[256];
    size_t n = notify_build_cmd("Title", "Body", TRUE, buf, 0);
    CHECK_INT_EQ(0, (int)n);
}

TEST(build_cmd_contains_notify_send)
{
    char buf[512];
    size_t n = notify_build_cmd("Rufus", "Done", TRUE, buf, sizeof(buf));
    CHECK(n > 0);
    CHECK(strstr(buf, "notify-send") != NULL);
}

TEST(build_cmd_contains_title)
{
    char buf[512];
    notify_build_cmd("MyTitle", "SomeBody", TRUE, buf, sizeof(buf));
    CHECK(strstr(buf, "MyTitle") != NULL);
}

TEST(build_cmd_contains_body)
{
    char buf[512];
    notify_build_cmd("T", "TheBody", TRUE, buf, sizeof(buf));
    CHECK(strstr(buf, "TheBody") != NULL);
}

TEST(build_cmd_success_uses_dialog_information_icon)
{
    char buf[512];
    notify_build_cmd("Done", "Format completed", TRUE, buf, sizeof(buf));
    /* Success should use a positive / info icon hint */
    CHECK(strstr(buf, "dialog-information") != NULL ||
          strstr(buf, "normal") != NULL);
}

TEST(build_cmd_failure_uses_dialog_error_icon)
{
    char buf[512];
    notify_build_cmd("Failed", "Format failed", FALSE, buf, sizeof(buf));
    /* Failure should use an error / critical urgency hint */
    CHECK(strstr(buf, "dialog-error") != NULL ||
          strstr(buf, "critical") != NULL);
}

TEST(build_cmd_result_is_null_terminated)
{
    char buf[512];
    size_t n = notify_build_cmd("A", "B", TRUE, buf, sizeof(buf));
    CHECK(n < sizeof(buf));
    CHECK_INT_EQ('\0', (int)buf[n]);
}

TEST(build_cmd_small_buf_truncates_safely)
{
    char buf[16];
    size_t n = notify_build_cmd("Title", "A long body string", TRUE, buf, sizeof(buf));
    /* Should return 0 (didn't fit) or truncate safely — either way no overflow */
    CHECK(n < sizeof(buf) || buf[sizeof(buf) - 1] == '\0');
    (void)n;
}

TEST(build_cmd_special_chars_in_title_are_handled)
{
    char buf[512];
    /* Single quotes in the message should not break the shell command */
    size_t n = notify_build_cmd("It's done", "Body text", TRUE, buf, sizeof(buf));
    CHECK(n > 0);
    /* Result must still be null-terminated and reasonably sized */
    CHECK(buf[n] == '\0');
}

TEST(build_cmd_special_chars_in_body_are_handled)
{
    char buf[512];
    size_t n = notify_build_cmd("Title", "Body with \"quotes\"", TRUE, buf, sizeof(buf));
    CHECK(n > 0);
    CHECK(buf[n] == '\0');
}

/* -------------------------------------------------------------------------
 * rufus_notify() API tests
 * rufus_notify() tries libnotify first; these tests verify the API
 * is callable and returns a sensible BOOL without requiring a DBus session.
 * ------------------------------------------------------------------------- */

TEST(rufus_notify_null_title_returns_false)
{
    BOOL r = rufus_notify(NULL, "body", TRUE);
    CHECK(r == FALSE);
}

TEST(rufus_notify_null_body_no_crash)
{
    /* NULL body should degrade gracefully (use empty string internally) */
    BOOL r = rufus_notify("Rufus", NULL, TRUE);
    /* We don't assert TRUE — a real DBus may or may not be present in CI */
    (void)r;
    CHECK(1); /* test passes if we reach here without crash */
}

TEST(rufus_notify_empty_title_returns_false)
{
    BOOL r = rufus_notify("", "body", TRUE);
    CHECK(r == FALSE);
}

TEST(rufus_notify_success_call_no_crash)
{
    /* Just verify no crash / undefined behaviour */
    rufus_notify("Rufus", "Format completed successfully.", TRUE);
    CHECK(1);
}

TEST(rufus_notify_failure_call_no_crash)
{
    rufus_notify("Rufus", "Format failed.", FALSE);
    CHECK(1);
}

/* -------------------------------------------------------------------------
 * notify_format_message() helper tests
 * The helper builds human-readable title/body strings from operation code.
 * ------------------------------------------------------------------------- */

TEST(format_message_format_success_title_not_empty)
{
    char title[128], body[256];
    notify_format_message(NOTIFY_OP_FORMAT, TRUE, title, sizeof(title),
                          body, sizeof(body));
    CHECK(title[0] != '\0');
}

TEST(format_message_format_success_body_not_empty)
{
    char title[128], body[256];
    notify_format_message(NOTIFY_OP_FORMAT, TRUE, title, sizeof(title),
                          body, sizeof(body));
    CHECK(body[0] != '\0');
}

TEST(format_message_format_failure_title_not_empty)
{
    char title[128], body[256];
    notify_format_message(NOTIFY_OP_FORMAT, FALSE, title, sizeof(title),
                          body, sizeof(body));
    CHECK(title[0] != '\0');
}

TEST(format_message_hash_success_title_not_empty)
{
    char title[128], body[256];
    notify_format_message(NOTIFY_OP_HASH, TRUE, title, sizeof(title),
                          body, sizeof(body));
    CHECK(title[0] != '\0');
}

TEST(format_message_download_success_title_not_empty)
{
    char title[128], body[256];
    notify_format_message(NOTIFY_OP_DOWNLOAD, TRUE, title, sizeof(title),
                          body, sizeof(body));
    CHECK(title[0] != '\0');
}

TEST(format_message_null_title_buf_no_crash)
{
    char body[256];
    notify_format_message(NOTIFY_OP_FORMAT, TRUE, NULL, 0, body, sizeof(body));
    CHECK(1);
}

TEST(format_message_null_body_buf_no_crash)
{
    char title[128];
    notify_format_message(NOTIFY_OP_FORMAT, TRUE, title, sizeof(title), NULL, 0);
    CHECK(1);
}

TEST(format_message_success_body_mentions_success)
{
    char title[128], body[256];
    notify_format_message(NOTIFY_OP_FORMAT, TRUE, title, sizeof(title),
                          body, sizeof(body));
    /* Body should contain something positive */
    int has_success = (strstr(body, "success") != NULL ||
                       strstr(body, "Success") != NULL ||
                       strstr(body, "complete") != NULL ||
                       strstr(body, "Complete") != NULL ||
                       strstr(body, "done") != NULL ||
                       strstr(body, "Done") != NULL);
    CHECK(has_success);
}

TEST(format_message_failure_body_mentions_failure)
{
    char title[128], body[256];
    notify_format_message(NOTIFY_OP_FORMAT, FALSE, title, sizeof(title),
                          body, sizeof(body));
    int has_fail = (strstr(body, "fail") != NULL ||
                    strstr(body, "Fail") != NULL ||
                    strstr(body, "error") != NULL ||
                    strstr(body, "Error") != NULL);
    CHECK(has_fail);
}

int main(void)
{
    printf("=== test_notify_linux ===\n");

    /* notify_build_cmd tests */
    RUN(build_cmd_null_title_returns_zero);
    RUN(build_cmd_null_body_uses_empty);
    RUN(build_cmd_null_buf_returns_zero);
    RUN(build_cmd_zero_bufsz_returns_zero);
    RUN(build_cmd_contains_notify_send);
    RUN(build_cmd_contains_title);
    RUN(build_cmd_contains_body);
    RUN(build_cmd_success_uses_dialog_information_icon);
    RUN(build_cmd_failure_uses_dialog_error_icon);
    RUN(build_cmd_result_is_null_terminated);
    RUN(build_cmd_small_buf_truncates_safely);
    RUN(build_cmd_special_chars_in_title_are_handled);
    RUN(build_cmd_special_chars_in_body_are_handled);

    /* rufus_notify API tests */
    RUN(rufus_notify_null_title_returns_false);
    RUN(rufus_notify_null_body_no_crash);
    RUN(rufus_notify_empty_title_returns_false);
    RUN(rufus_notify_success_call_no_crash);
    RUN(rufus_notify_failure_call_no_crash);

    /* notify_format_message tests */
    RUN(format_message_format_success_title_not_empty);
    RUN(format_message_format_success_body_not_empty);
    RUN(format_message_format_failure_title_not_empty);
    RUN(format_message_hash_success_title_not_empty);
    RUN(format_message_download_success_title_not_empty);
    RUN(format_message_null_title_buf_no_crash);
    RUN(format_message_null_body_buf_no_crash);
    RUN(format_message_success_body_mentions_success);
    RUN(format_message_failure_body_mentions_failure);

    TEST_RESULTS();
}
