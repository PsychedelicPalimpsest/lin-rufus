/*
 * test_status_history_linux.c — TDD tests for src/linux/status_history.c
 *
 * Tests cover:
 *  1.  Fresh history: tooltip is empty
 *  2.  Push one message: tooltip is empty (current is in label, not tooltip)
 *  3.  Push two messages: tooltip contains first message only
 *  4.  Push N+1 messages: oldest wraps out of tooltip
 *  5.  Push N messages: tooltip contains first N-1 entries
 *  6.  Tooltip entries are newline-separated, newest first
 *  7.  NULL message is handled safely (treated as empty string)
 *  8.  After clear(), history is empty again
 *  9.  Very long message is stored truncated, not overflowing
 * 10.  Push then clear then push: clean state
 * 11.  Tooltip buffer-too-small: output still null-terminated
 * 12.  Multiple wraps: ring wraps correctly after 2*N entries
 * 13.  get_current: returns most recently pushed message
 * 14.  get_current on fresh history returns ""
 * 15.  Messages are independent across pushes
 */

#include "framework.h"

#include <string.h>
#include <stdlib.h>

/* Under test */
#include "../src/linux/status_history.h"

/* ===========================================================================
 * 1. Fresh history: tooltip is empty
 * =========================================================================*/
TEST(fresh_history_tooltip_is_empty)
{
    status_history_clear();
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    CHECK_MSG(buf[0] == '\0', "fresh history tooltip must be empty string");
}

/* ===========================================================================
 * 2. Push one message: tooltip is empty (current shown in label)
 * =========================================================================*/
TEST(push_one_tooltip_is_empty)
{
    status_history_clear();
    status_history_push("First message");
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    CHECK_MSG(buf[0] == '\0', "after 1 push, tooltip must be empty (current in label)");
}

/* ===========================================================================
 * 3. Push two messages: tooltip contains first message
 * =========================================================================*/
TEST(push_two_tooltip_has_first)
{
    status_history_clear();
    status_history_push("Message A");
    status_history_push("Message B");
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    CHECK_MSG(strstr(buf, "Message A") != NULL, "tooltip must contain first message after 2 pushes");
    CHECK_MSG(strstr(buf, "Message B") == NULL, "tooltip must not contain current message");
}

/* ===========================================================================
 * 4. Push N+1 messages: oldest falls off tooltip
 * =========================================================================*/
TEST(push_n_plus_one_oldest_drops)
{
    status_history_clear();
    /* Push STATUS_HISTORY_SIZE+1 messages */
    for (int i = 0; i <= STATUS_HISTORY_SIZE; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Msg%d", i);
        status_history_push(msg);
    }
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    /* "Msg0" is oldest: must have wrapped out */
    CHECK_MSG(strstr(buf, "Msg0") == NULL, "oldest message must have been evicted");
    /* "Msg1" should still be in tooltip history */
    CHECK_MSG(strstr(buf, "Msg1") != NULL, "next-oldest must still be in tooltip");
}

/* ===========================================================================
 * 5. Push N messages: tooltip contains N-1 entries (current excluded)
 * =========================================================================*/
TEST(push_n_tooltip_has_n_minus_1)
{
    status_history_clear();
    for (int i = 1; i <= STATUS_HISTORY_SIZE; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Entry%d", i);
        status_history_push(msg);
    }
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    /* All except the current (Entry N) must be in tooltip */
    for (int i = 1; i < STATUS_HISTORY_SIZE; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Entry%d", i);
        CHECK_MSG(strstr(buf, msg) != NULL, "all non-current entries must be in tooltip");
    }
    /* Current (EntryN) must NOT be in tooltip */
    char cur[32];
    snprintf(cur, sizeof(cur), "Entry%d", STATUS_HISTORY_SIZE);
    CHECK_MSG(strstr(buf, cur) == NULL, "current entry must not appear in tooltip");
}

/* ===========================================================================
 * 6. Tooltip entries are newline-separated
 * =========================================================================*/
TEST(tooltip_entries_newline_separated)
{
    status_history_clear();
    status_history_push("Alpha");
    status_history_push("Beta");
    status_history_push("Gamma");
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    /* There should be at least one '\n' separating the 2 non-current entries */
    CHECK_MSG(strchr(buf, '\n') != NULL, "tooltip entries must be newline-separated");
}

/* ===========================================================================
 * 7. NULL message handled safely
 * =========================================================================*/
TEST(null_message_handled_safely)
{
    status_history_clear();
    status_history_push(NULL);  /* must not crash */
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    /* After pushing NULL (treated as ""), tooltip is empty (1 entry = current) */
    (void)buf; /* No crash is the main check */
    CHECK_MSG(1, "pushing NULL must not crash");
}

/* ===========================================================================
 * 8. After clear(), history is empty
 * =========================================================================*/
TEST(clear_resets_history)
{
    status_history_clear();
    status_history_push("X");
    status_history_push("Y");
    status_history_push("Z");
    status_history_clear();
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    CHECK_MSG(buf[0] == '\0', "after clear, tooltip must be empty");
}

/* ===========================================================================
 * 9. Very long message is truncated safely
 * =========================================================================*/
TEST(very_long_message_truncated_safely)
{
    status_history_clear();
    char long_msg[4096];
    memset(long_msg, 'A', sizeof(long_msg) - 1);
    long_msg[sizeof(long_msg) - 1] = '\0';
    status_history_push(long_msg);     /* store this */
    status_history_push("Short");      /* make it non-current */
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    /* buf must be null-terminated and not overflowed */
    CHECK_MSG(buf[sizeof(buf) - 1] == '\0' || strlen(buf) < sizeof(buf),
              "tooltip buf must be null-terminated after long message");
}

/* ===========================================================================
 * 10. Push then clear then push: clean state
 * =========================================================================*/
TEST(push_clear_push_clean_state)
{
    status_history_clear();
    status_history_push("Old1");
    status_history_push("Old2");
    status_history_clear();
    status_history_push("New1");
    status_history_push("New2");
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    CHECK_MSG(strstr(buf, "Old1") == NULL, "cleared messages must not reappear");
    CHECK_MSG(strstr(buf, "Old2") == NULL, "cleared messages must not reappear");
    CHECK_MSG(strstr(buf, "New1") != NULL, "new messages must appear in tooltip");
}

/* ===========================================================================
 * 11. Tooltip with tiny output buffer: still null-terminated
 * =========================================================================*/
TEST(tooltip_tiny_buf_null_terminated)
{
    status_history_clear();
    status_history_push("Hello");
    status_history_push("World");
    char tiny[4];
    status_history_tooltip(tiny, sizeof(tiny));
    CHECK_MSG(tiny[sizeof(tiny) - 1] == '\0', "tiny buf must be null-terminated");
}

/* ===========================================================================
 * 12. Multiple wraps: ring works after 2*N entries
 * =========================================================================*/
TEST(multiple_wraps_ring_correct)
{
    status_history_clear();
    for (int i = 0; i < 2 * STATUS_HISTORY_SIZE + 1; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "W%d", i);
        status_history_push(msg);
    }
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    /* Very old messages must be gone; recent ones present */
    CHECK_MSG(strstr(buf, "W0") == NULL, "very old message must be evicted after 2*N wraps");
    /* The last pushed is current (not in tooltip).
     * The N-1 before it should be in the tooltip. */
    int last = 2 * STATUS_HISTORY_SIZE;
    char expected[32];
    snprintf(expected, sizeof(expected), "W%d", last - 1);
    CHECK_MSG(strstr(buf, expected) != NULL, "recent non-current message must be in tooltip");
}

/* ===========================================================================
 * 13. get_current returns most recently pushed
 * =========================================================================*/
TEST(get_current_returns_latest)
{
    status_history_clear();
    status_history_push("First");
    status_history_push("Second");
    status_history_push("Third");
    char buf[256];
    status_history_get_current(buf, sizeof(buf));
    CHECK_MSG(strcmp(buf, "Third") == 0, "get_current must return most recently pushed message");
}

/* ===========================================================================
 * 14. get_current on fresh history returns empty string
 * =========================================================================*/
TEST(get_current_fresh_returns_empty)
{
    status_history_clear();
    char buf[256];
    status_history_get_current(buf, sizeof(buf));
    CHECK_MSG(buf[0] == '\0', "get_current on fresh history must return empty string");
}

/* ===========================================================================
 * 15. Messages are independent across pushes
 * =========================================================================*/
TEST(messages_independent_across_pushes)
{
    status_history_clear();
    char m1[] = "Alpha";
    char m2[] = "Beta";
    status_history_push(m1);
    status_history_push(m2);
    /* Mutate original buffers — stored copy must be unchanged */
    m1[0] = 'X';
    m2[0] = 'X';
    char buf[512];
    status_history_tooltip(buf, sizeof(buf));
    CHECK_MSG(strstr(buf, "Alpha") != NULL, "stored message must be independent copy");
}

/* ===========================================================================
 * main
 * =========================================================================*/
int main(void)
{
    printf("=== status_history tests ===\n");

    RUN(fresh_history_tooltip_is_empty);
    RUN(push_one_tooltip_is_empty);
    RUN(push_two_tooltip_has_first);
    RUN(push_n_plus_one_oldest_drops);
    RUN(push_n_tooltip_has_n_minus_1);
    RUN(tooltip_entries_newline_separated);
    RUN(null_message_handled_safely);
    RUN(clear_resets_history);
    RUN(very_long_message_truncated_safely);
    RUN(push_clear_push_clean_state);
    RUN(tooltip_tiny_buf_null_terminated);
    RUN(multiple_wraps_ring_correct);
    RUN(get_current_returns_latest);
    RUN(get_current_fresh_returns_empty);
    RUN(messages_independent_across_pushes);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
