/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: status_history.h — status message history API
 * Copyright © 2025 Rufus contributors
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
 * status_history.h — Status label history ring buffer
 *
 * Keeps the last STATUS_HISTORY_SIZE messages in a ring buffer.
 * The most recently pushed message is the "current" status (shown in the label).
 * All previous messages are returned as a newline-separated tooltip string.
 */

#pragma once

#include <stddef.h>

#define STATUS_HISTORY_SIZE 5   /* number of messages to retain (including current) */

/* Push a new status message.  The oldest message wraps out when the ring is full. */
void status_history_push(const char *msg);

/* Write a newline-separated string of all non-current history entries into
 * buf (newest first).  buf is always null-terminated.  Returns buf. */
char *status_history_tooltip(char *buf, size_t buf_sz);

/* Write the most recently pushed message into buf.  Returns buf.
 * Returns empty string if history is empty. */
char *status_history_get_current(char *buf, size_t buf_sz);

/* Reset all history (useful for tests and on-app-start). */
void status_history_clear(void);
