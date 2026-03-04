/*
 * test_status_timeout_linux.c — TDD tests for src/linux/status_timeout.c
 *
 * Tests cover:
 *  1.  No backends set: show() does not crash
 *  2.  show() calls update_fn immediately with the message
 *  3.  show() makes is_pending() return 1
 *  4.  fire() calls update_fn with the restore-to message
 *  5.  fire() clears is_pending()
 *  6.  cancel() clears is_pending()
 *  7.  cancel() does NOT call update_fn
 *  8.  Second show() while pending: cancel_fn called, new timer armed
 *  9.  NULL msg: update_fn not called, timer still armed
 * 10.  NULL restore_to: saves empty string, restores to ""
 * 11.  ms=0 uses STATUS_TIMEOUT_DEFAULT_MS
 * 12.  get_saved() returns the restore_to message
 * 13.  reset() clears all state and removes backends
 * 14.  Multiple shows update saved message to latest restore_to
 * 15.  fire() when not pending: no crash, display unchanged
 */

#include "framework.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "../src/linux/status_timeout.h"

/* -------------------------------------------------------------------------
 * Mock backend state
 * ---------------------------------------------------------------------- */

static char    mock_display[512];   /* what the "status label" currently shows */
static unsigned mock_timer_ms = 0;  /* ms passed to last add_fn call */
static int      mock_add_calls = 0;
static int      mock_cancel_calls = 0;
static int      mock_update_calls = 0;
static char     mock_update_last[512]; /* last msg sent to update_fn */

/* Pending callback state (simulates GLib timer) */
static void  (*mock_pending_cb)(void *) = NULL;
static void   *mock_pending_arg = NULL;
static unsigned mock_next_id = 1;
static unsigned mock_active_id = 0;

static unsigned mock_add_fn(unsigned ms, void (*cb)(void *), void *arg)
{
	mock_timer_ms    = ms;
	mock_pending_cb  = cb;
	mock_pending_arg = arg;
	mock_add_calls++;
	mock_active_id = mock_next_id++;
	return mock_active_id;
}

static void mock_cancel_fn(unsigned id)
{
	(void)id;
	mock_cancel_calls++;
	mock_pending_cb  = NULL;
	mock_pending_arg = NULL;
	mock_active_id   = 0;
}

static void mock_update_fn(const char *msg)
{
	mock_update_calls++;
	strncpy(mock_update_last, msg ? msg : "", sizeof(mock_update_last) - 1);
	mock_update_last[sizeof(mock_update_last) - 1] = '\0';
	strncpy(mock_display,     msg ? msg : "", sizeof(mock_display) - 1);
	mock_display[sizeof(mock_display) - 1] = '\0';
}

/* Fire the pending mock timer callback */
static void mock_fire(void)
{
	if (mock_pending_cb) {
		void (*cb)(void *) = mock_pending_cb;
		void *arg = mock_pending_arg;
		mock_pending_cb  = NULL;
		mock_pending_arg = NULL;
		mock_active_id   = 0;
		cb(arg);
	}
}

/* Reset all mock state */
static void mock_reset(void)
{
	mock_display[0]      = '\0';
	mock_timer_ms        = 0;
	mock_add_calls       = 0;
	mock_cancel_calls    = 0;
	mock_update_calls    = 0;
	mock_update_last[0]  = '\0';
	mock_pending_cb      = NULL;
	mock_pending_arg     = NULL;
	mock_next_id         = 1;
	mock_active_id       = 0;
}

/* Helper: set backends and reset mock */
static void setup(void)
{
	mock_reset();
	status_timeout_reset();
	status_timeout_set_backends(mock_add_fn, mock_cancel_fn, mock_update_fn);
}

/* ===========================================================================
 * 1. No backends set: show() does not crash
 * =========================================================================*/
TEST(no_backends_no_crash)
{
	status_timeout_reset(); /* clears all backends */
	status_timeout_show("Hello", "World", 100);
	/* If we get here, no crash */
	CHECK_MSG(1, "show() with no backends must not crash");
}

/* ===========================================================================
 * 2. show() calls update_fn immediately with the message
 * =========================================================================*/
TEST(show_calls_update_fn_immediately)
{
	setup();
	status_timeout_show("Toggle: enabled", "Ready", 500);
	CHECK_MSG(mock_update_calls == 1,
	          "update_fn must be called exactly once immediately");
	CHECK_MSG(strcmp(mock_update_last, "Toggle: enabled") == 0,
	          "update_fn must receive the transient message");
}

/* ===========================================================================
 * 3. show() makes is_pending() return 1
 * =========================================================================*/
TEST(show_sets_pending)
{
	setup();
	CHECK_MSG(status_timeout_is_pending() == 0, "initially not pending");
	status_timeout_show("Msg", "Restore", 500);
	CHECK_MSG(status_timeout_is_pending() == 1,
	          "is_pending must be 1 after show()");
}

/* ===========================================================================
 * 4. fire() calls update_fn with the restore-to message
 * =========================================================================*/
TEST(fire_restores_saved_message)
{
	setup();
	strncpy(mock_display, "Ready", sizeof(mock_display) - 1);
	status_timeout_show("Toggle: on", "Ready", 500);
	mock_update_calls = 0; /* reset counter after show() */
	status_timeout_fire();
	CHECK_MSG(mock_update_calls == 1,
	          "update_fn must be called once on fire()");
	CHECK_MSG(strcmp(mock_update_last, "Ready") == 0,
	          "fire() must restore the saved message");
}

/* ===========================================================================
 * 5. fire() clears is_pending()
 * =========================================================================*/
TEST(fire_clears_pending)
{
	setup();
	status_timeout_show("Msg", "Restore", 500);
	CHECK_MSG(status_timeout_is_pending() == 1, "must be pending before fire");
	status_timeout_fire();
	CHECK_MSG(status_timeout_is_pending() == 0,
	          "is_pending must be 0 after fire()");
}

/* ===========================================================================
 * 6. cancel() clears is_pending()
 * =========================================================================*/
TEST(cancel_clears_pending)
{
	setup();
	status_timeout_show("Msg", "Restore", 500);
	CHECK_MSG(status_timeout_is_pending() == 1, "must be pending before cancel");
	status_timeout_cancel();
	CHECK_MSG(status_timeout_is_pending() == 0,
	          "is_pending must be 0 after cancel()");
}

/* ===========================================================================
 * 7. cancel() does NOT call update_fn
 * =========================================================================*/
TEST(cancel_does_not_call_update_fn)
{
	setup();
	status_timeout_show("Msg", "Restore", 500);
	mock_update_calls = 0; /* reset after show() */
	status_timeout_cancel();
	CHECK_MSG(mock_update_calls == 0,
	          "cancel() must not call update_fn");
}

/* ===========================================================================
 * 8. Second show() while pending: cancel_fn called, new timer armed
 * =========================================================================*/
TEST(second_show_cancels_first_timer)
{
	setup();
	status_timeout_show("First", "Restore1", 500);
	int add_after_first    = mock_add_calls;
	int cancel_after_first = mock_cancel_calls;

	status_timeout_show("Second", "Restore2", 500);

	CHECK_MSG(mock_cancel_calls == cancel_after_first + 1,
	          "cancel_fn must be called when a new show() supersedes an old one");
	CHECK_MSG(mock_add_calls == add_after_first + 1,
	          "a new timer must be armed for the second show()");
	CHECK_MSG(status_timeout_is_pending() == 1,
	          "must still be pending after second show()");
}

/* ===========================================================================
 * 9. NULL msg: update_fn not called, timer still armed
 * =========================================================================*/
TEST(null_msg_no_update_but_timer_armed)
{
	setup();
	status_timeout_show(NULL, "Restore", 500);
	CHECK_MSG(mock_update_calls == 0,
	          "update_fn must NOT be called when msg is NULL");
	CHECK_MSG(mock_add_calls == 1,
	          "timer must still be armed even when msg is NULL");
	CHECK_MSG(status_timeout_is_pending() == 1,
	          "must be pending even when msg is NULL");
}

/* ===========================================================================
 * 10. NULL restore_to: saves empty string
 * =========================================================================*/
TEST(null_restore_to_saves_empty)
{
	setup();
	status_timeout_show("Msg", NULL, 500);
	CHECK_MSG(strcmp(status_timeout_get_saved(), "") == 0,
	          "NULL restore_to must be saved as empty string");
	/* Fire and verify empty string is shown */
	mock_update_calls = 0;
	status_timeout_fire();
	CHECK_MSG(mock_update_calls == 1, "update_fn called on fire");
	CHECK_MSG(strcmp(mock_update_last, "") == 0,
	          "fire() must restore to empty string when restore_to was NULL");
}

/* ===========================================================================
 * 11. ms=0 uses STATUS_TIMEOUT_DEFAULT_MS
 * =========================================================================*/
TEST(zero_ms_uses_default)
{
	setup();
	status_timeout_show("Msg", "R", 0);
	CHECK_MSG(mock_timer_ms == STATUS_TIMEOUT_DEFAULT_MS,
	          "ms=0 must schedule timer with STATUS_TIMEOUT_DEFAULT_MS");
}

/* ===========================================================================
 * 12. get_saved() returns the restore_to message
 * =========================================================================*/
TEST(get_saved_returns_restore_to)
{
	setup();
	status_timeout_show("Transient", "PersistentStatus", 500);
	CHECK_MSG(strcmp(status_timeout_get_saved(), "PersistentStatus") == 0,
	          "get_saved() must return the restore_to value");
}

/* ===========================================================================
 * 13. reset() clears all state and removes backends
 * =========================================================================*/
TEST(reset_clears_state)
{
	setup();
	status_timeout_show("Msg", "R", 500);
	status_timeout_reset();
	CHECK_MSG(status_timeout_is_pending() == 0,
	          "is_pending must be 0 after reset()");
	CHECK_MSG(strcmp(status_timeout_get_saved(), "") == 0,
	          "saved msg must be empty after reset()");
	/* Backends are cleared — no crash when calling show() */
	status_timeout_show("Another", "X", 100);
	CHECK_MSG(1, "show() after reset() must not crash");
}

/* ===========================================================================
 * 14. Multiple shows update saved message to latest restore_to
 * =========================================================================*/
TEST(multiple_shows_update_saved)
{
	setup();
	status_timeout_show("First",  "RestoreA", 500);
	CHECK_MSG(strcmp(status_timeout_get_saved(), "RestoreA") == 0,
	          "saved after first show must be RestoreA");
	status_timeout_show("Second", "RestoreB", 500);
	CHECK_MSG(strcmp(status_timeout_get_saved(), "RestoreB") == 0,
	          "saved after second show must be RestoreB");
}

/* ===========================================================================
 * 15. fire() when not pending: no crash, display unchanged
 * =========================================================================*/
TEST(fire_when_not_pending_no_crash)
{
	setup();
	strncpy(mock_display, "Steady", sizeof(mock_display) - 1);
	CHECK_MSG(status_timeout_is_pending() == 0, "not pending initially");
	status_timeout_fire(); /* no-op */
	CHECK_MSG(mock_update_calls == 0,
	          "update_fn must not be called by fire() when not pending");
	CHECK_MSG(strcmp(mock_display, "Steady") == 0,
	          "display must be unchanged after fire() when not pending");
}

/* ===========================================================================
 * main
 * =========================================================================*/
int main(void)
{
	printf("=== status_timeout tests ===\n");

	RUN(no_backends_no_crash);
	RUN(show_calls_update_fn_immediately);
	RUN(show_sets_pending);
	RUN(fire_restores_saved_message);
	RUN(fire_clears_pending);
	RUN(cancel_clears_pending);
	RUN(cancel_does_not_call_update_fn);
	RUN(second_show_cancels_first_timer);
	RUN(null_msg_no_update_but_timer_armed);
	RUN(null_restore_to_saves_empty);
	RUN(zero_ms_uses_default);
	RUN(get_saved_returns_restore_to);
	RUN(reset_clears_state);
	RUN(multiple_shows_update_saved);
	RUN(fire_when_not_pending_no_crash);

	TEST_RESULTS();
	return (_fail > 0) ? 1 : 0;
}
