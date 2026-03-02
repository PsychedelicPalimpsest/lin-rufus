/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: notify.h — desktop notification API
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

/* src/linux/notify.h
 * Desktop notification bridge for the Linux port of Rufus.
 *
 * Provides a thin abstraction over libnotify (when available at compile time)
 * with a notify-send subprocess fallback for environments that have the CLI
 * tool but not the shared library.
 *
 * Public API
 * ----------
 *   rufus_notify()         – send a desktop notification
 *   notify_format_message()– build human-readable title/body for an operation
 *   notify_build_cmd()     – build the notify-send shell command (testable)
 *
 * Operation codes (notify_op_t)
 * ------------------------------
 *   NOTIFY_OP_FORMAT    – USB formatting / image write
 *   NOTIFY_OP_HASH      – file hash computation
 *   NOTIFY_OP_DOWNLOAD  – ISO / update download
 */
#pragma once

#include <stddef.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  ifndef BOOL
#    define BOOL int
#  endif
#  ifndef TRUE
#    define TRUE 1
#  endif
#  ifndef FALSE
#    define FALSE 0
#  endif
#endif

/* -------------------------------------------------------------------------
 * Operation codes
 * ---------------------------------------------------------------------- */
typedef enum {
    NOTIFY_OP_FORMAT   = 0,
    NOTIFY_OP_HASH     = 1,
    NOTIFY_OP_DOWNLOAD = 2,
} notify_op_t;

/* -------------------------------------------------------------------------
 * API
 * ---------------------------------------------------------------------- */

/**
 * rufus_notify – dispatch a desktop notification.
 *
 * Tries libnotify first (when compiled with USE_LIBNOTIFY).  Falls back to
 * forking notify-send.  Returns FALSE immediately if title is NULL/empty or
 * no notification backend is available.
 *
 * @param title   Short summary line shown in the notification bubble.
 * @param body    Optional longer description (may be NULL).
 * @param success TRUE → use "information" urgency; FALSE → "critical".
 * @return        TRUE if the notification was dispatched successfully.
 */
BOOL rufus_notify(const char *title, const char *body, BOOL success);

/**
 * notify_format_message – build standard title/body strings for an op.
 *
 * Fills @p title_buf and @p body_buf with human-readable strings describing
 * the completion of @p op.  Safe to call with NULL buffers / zero sizes.
 *
 * @param op         Which operation completed.
 * @param success    Whether it succeeded.
 * @param title_buf  Buffer for the notification title (may be NULL).
 * @param title_sz   Size of title_buf.
 * @param body_buf   Buffer for the notification body (may be NULL).
 * @param body_sz    Size of body_buf.
 */
void notify_format_message(notify_op_t op, BOOL success,
                            char *title_buf, size_t title_sz,
                            char *body_buf,  size_t body_sz);

/**
 * notify_build_cmd – build the notify-send(1) shell command string.
 *
 * This function is kept pure (no side effects, no exec) so it can be tested
 * without a running DBus session.
 *
 * @param title   Notification title (must not be NULL).
 * @param body    Notification body (NULL → empty string used).
 * @param success TRUE → dialog-information icon; FALSE → dialog-error icon
 *                and critical urgency.
 * @param buf     Output buffer for the shell command string.
 * @param bufsz   Size of @p buf.
 * @return        Number of bytes written (excluding NUL), or 0 on error.
 */
size_t notify_build_cmd(const char *title, const char *body, BOOL success,
                        char *buf, size_t bufsz);
