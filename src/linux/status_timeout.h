/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux port — timed status-bar message module
 * Copyright © 2013-2026 Pete Batard <pete@akeo.ie>
 * Linux port Copyright © 2024-2026 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * status_timeout — platform-agnostic timed status message
 *
 * Mirrors the Windows PrintStatusTimeout / TID_MESSAGE_STATUS mechanism:
 * show a transient message in the status bar for a fixed duration, then
 * revert to the previous persistent message.
 *
 * All platform-specific concerns (GTK timer, GTK label) are injected via
 * function pointers so the logic can be unit-tested without a display.
 */

#ifndef STATUS_TIMEOUT_H
#define STATUS_TIMEOUT_H

/* Default timeout in milliseconds — matches STATUS_MSG_TIMEOUT on Windows */
#define STATUS_TIMEOUT_DEFAULT_MS 3500u

/* -------------------------------------------------------------------------
 * Injectable backend types
 * ---------------------------------------------------------------------- */

/*
 * Schedule a one-shot timer that fires after |ms| milliseconds.
 * The implementation must call cb(arg) once, then not call it again.
 * Returns an opaque non-zero ID on success, 0 on failure.
 */
typedef unsigned (*status_timeout_add_fn_t)(unsigned ms,
                                            void (*cb)(void *),
                                            void *arg);

/*
 * Cancel a previously scheduled timer (identified by the ID returned by
 * status_timeout_add_fn_t).  Must be a no-op when called with id == 0.
 */
typedef void (*status_timeout_cancel_fn_t)(unsigned id);

/*
 * Update the status display with |msg|.
 */
typedef void (*status_timeout_update_fn_t)(const char *msg);

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/*
 * Inject the three backend functions.
 * Pass NULL to clear a backend (all three are optional; missing ones are
 * silently skipped).
 */
void status_timeout_set_backends(status_timeout_add_fn_t    add_fn,
                                 status_timeout_cancel_fn_t cancel_fn,
                                 status_timeout_update_fn_t update_fn);

/*
 * Show |msg| in the status display for |ms| milliseconds, then restore to
 * |restore_to|.
 *
 *  - If |msg| is NULL the display is not updated but the timer is still set.
 *  - If |restore_to| is NULL the restore target is an empty string.
 *  - If |ms| is 0, STATUS_TIMEOUT_DEFAULT_MS is used.
 *  - If a previous timeout is already pending, it is cancelled (without
 *    restoring) before the new one is armed.
 */
void status_timeout_show(const char *msg,
                         const char *restore_to,
                         unsigned    ms);

/*
 * Cancel any pending restore timer.  The display is NOT updated.
 */
void status_timeout_cancel(void);

/* -------------------------------------------------------------------------
 * Test helpers (also useful for the GTK integration layer)
 * ---------------------------------------------------------------------- */

/* Non-zero when a restore timer is currently pending */
int status_timeout_is_pending(void);

/* The message that will be restored when the timer fires */
const char *status_timeout_get_saved(void);

/* Manually fire the pending callback (for unit tests, no real timer needed) */
void status_timeout_fire(void);

/* Reset all state and backends (call between tests) */
void status_timeout_reset(void);

#endif /* STATUS_TIMEOUT_H */
