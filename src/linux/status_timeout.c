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

#include <string.h>
#include "status_timeout.h"

/* -------------------------------------------------------------------------
 * Module state
 * ---------------------------------------------------------------------- */

#define SAVED_MSG_LEN 512

static status_timeout_add_fn_t    s_add_fn    = NULL;
static status_timeout_cancel_fn_t s_cancel_fn = NULL;
static status_timeout_update_fn_t s_update_fn = NULL;

static char     s_saved_msg[SAVED_MSG_LEN];
static unsigned s_timer_id = 0;
static int      s_pending  = 0;

/* -------------------------------------------------------------------------
 * Internal restore callback — called when the timer fires
 * ---------------------------------------------------------------------- */

static void restore_cb(void *arg)
{
	(void)arg;
	s_pending  = 0;
	s_timer_id = 0;
	if (s_update_fn)
		s_update_fn(s_saved_msg);
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void status_timeout_set_backends(status_timeout_add_fn_t    add_fn,
                                 status_timeout_cancel_fn_t cancel_fn,
                                 status_timeout_update_fn_t update_fn)
{
	s_add_fn    = add_fn;
	s_cancel_fn = cancel_fn;
	s_update_fn = update_fn;
}

void status_timeout_show(const char *msg, const char *restore_to, unsigned ms)
{
	if (ms == 0)
		ms = STATUS_TIMEOUT_DEFAULT_MS;

	/* Cancel any already-pending restore */
	if (s_pending) {
		if (s_cancel_fn && s_timer_id != 0)
			s_cancel_fn(s_timer_id);
		s_timer_id = 0;
		s_pending  = 0;
	}

	/* Save the restore-to message */
	const char *r = restore_to ? restore_to : "";
	strncpy(s_saved_msg, r, SAVED_MSG_LEN - 1);
	s_saved_msg[SAVED_MSG_LEN - 1] = '\0';

	/* Show the transient message */
	if (s_update_fn && msg)
		s_update_fn(msg);

	/* Schedule the restore */
	if (s_add_fn) {
		s_timer_id = s_add_fn(ms, restore_cb, NULL);
		s_pending  = (s_timer_id != 0) ? 1 : 0;
	}
}

void status_timeout_cancel(void)
{
	if (s_pending) {
		if (s_cancel_fn && s_timer_id != 0)
			s_cancel_fn(s_timer_id);
	}
	s_timer_id = 0;
	s_pending  = 0;
}

int status_timeout_is_pending(void)
{
	return s_pending;
}

const char *status_timeout_get_saved(void)
{
	return s_saved_msg;
}

void status_timeout_fire(void)
{
	if (s_pending)
		restore_cb(NULL);
}

void status_timeout_reset(void)
{
	status_timeout_cancel();
	s_add_fn    = NULL;
	s_cancel_fn = NULL;
	s_update_fn = NULL;
	s_saved_msg[0] = '\0';
}
