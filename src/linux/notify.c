/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: notify.c — desktop notification support
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

/* src/linux/notify.c
 * Desktop notification bridge for the Linux port of Rufus.
 *
 * Three-tier dispatch:
 *   1. libnotify (compile-time, requires USE_LIBNOTIFY + pkg libnotify)
 *   2. notify-send subprocess (runtime, no library needed)
 *   3. Silent no-op (logs a message via uprintf)
 */

#include "notify.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_LIBNOTIFY
#  include <libnotify/notify.h>
#endif

/* uprintf is the Rufus logger.  Provide a weak no-op for unit tests that
 * don't link the full stdio.c. */
#ifdef RUFUS_TEST
static void _notify_log(const char *fmt, ...) { (void)fmt; }
#  define uprintf _notify_log
#else
extern int uprintf(const char *fmt, ...);
#endif

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

/* Escape a string for safe use inside double-quoted shell arguments.
 * Replaces " → \", ` → \`, \ → \\, $ → \$ in-place into @p dst. */
static size_t shell_escape(const char *src, char *dst, size_t dstsz)
{
    size_t di = 0;
    if (!src || !dst || dstsz == 0)
        return 0;

    while (*src && di + 2 < dstsz) { /* +2: escaped char + NUL */
        char c = *src++;
        if (c == '"' || c == '`' || c == '\\' || c == '$') {
            if (di + 3 >= dstsz)
                break; /* not enough space */
            dst[di++] = '\\';
        }
        dst[di++] = c;
    }
    dst[di] = '\0';
    return di;
}

/* -------------------------------------------------------------------------
 * notify_build_cmd
 * ---------------------------------------------------------------------- */

size_t notify_build_cmd(const char *title, const char *body, BOOL success,
                        char *buf, size_t bufsz)
{
    if (!title || !buf || bufsz == 0)
        return 0;

    if (!body)
        body = "";

    /* Escape title and body for embedding in double-quoted shell args */
    char etitle[256];
    char ebody[512];
    shell_escape(title, etitle, sizeof(etitle));
    shell_escape(body,  ebody,  sizeof(ebody));

    const char *icon    = success ? "dialog-information" : "dialog-error";
    const char *urgency = success ? "normal"             : "critical";

    int n = snprintf(buf, bufsz,
                     "notify-send"
                     " --icon=\"%s\""
                     " --urgency=%s"
                     " \"%s\""
                     " \"%s\"",
                     icon, urgency, etitle, ebody);

    if (n < 0 || (size_t)n >= bufsz) {
        buf[0] = '\0';
        return 0;
    }
    return (size_t)n;
}

/* -------------------------------------------------------------------------
 * notify_format_message
 * ---------------------------------------------------------------------- */

void notify_format_message(notify_op_t op, BOOL success,
                            char *title_buf, size_t title_sz,
                            char *body_buf,  size_t body_sz)
{
    const char *title = NULL;
    const char *body  = NULL;

    switch (op) {
    case NOTIFY_OP_FORMAT:
        title = success ? "Rufus — Format Complete"
                        : "Rufus — Format Failed";
        body  = success ? "Format complete. The drive is ready to use."
                        : "The format operation encountered an error.";
        break;
    case NOTIFY_OP_HASH:
        title = success ? "Rufus — Hash Complete"
                        : "Rufus — Hash Failed";
        body  = success ? "File hash computation completed successfully."
                        : "File hash computation failed.";
        break;
    case NOTIFY_OP_DOWNLOAD:
        title = success ? "Rufus — Download Complete"
                        : "Rufus — Download Failed";
        body  = success ? "The download completed successfully."
                        : "The download encountered an error.";
        break;
    default:
        title = success ? "Rufus — Operation Complete"
                        : "Rufus — Operation Failed";
        body  = success ? "The operation completed successfully."
                        : "The operation failed.";
        break;
    }

    if (title_buf && title_sz > 0)
        snprintf(title_buf, title_sz, "%s", title);
    if (body_buf && body_sz > 0)
        snprintf(body_buf, body_sz, "%s", body);
}

/* -------------------------------------------------------------------------
 * rufus_notify
 * ---------------------------------------------------------------------- */

BOOL rufus_notify(const char *title, const char *body, BOOL success)
{
    if (!title || title[0] == '\0')
        return FALSE;

    if (!body)
        body = "";

#ifdef USE_LIBNOTIFY
    /* ------------------------------------------------------------------ *
     * Tier 1: libnotify                                                    *
     * ------------------------------------------------------------------ */
    if (!notify_is_initted()) {
        if (!notify_init("Rufus")) {
            uprintf("notify: notify_init() failed, falling back to notify-send");
            goto fallback;
        }
    }

    NotifyNotification *n = notify_notification_new(title, body, NULL);
    if (!n) {
        uprintf("notify: failed to create notification");
        goto fallback;
    }

    notify_notification_set_urgency(n,
        success ? NOTIFY_URGENCY_NORMAL : NOTIFY_URGENCY_CRITICAL);
    notify_notification_set_icon_from_pixbuf(n, NULL); /* use app icon */

    const char *icon = success ? "dialog-information" : "dialog-error";
    notify_notification_set_hint_string(n, "image-path", icon);

    GError *err = NULL;
    BOOL ok = notify_notification_show(n, &err) ? TRUE : FALSE;
    if (err) {
        uprintf("notify: %s", err->message);
        g_error_free(err);
        ok = FALSE;
    }
    g_object_unref(G_OBJECT(n));
    return ok;

fallback:
#endif /* USE_LIBNOTIFY */

    /* ------------------------------------------------------------------ *
     * Tier 2: notify-send subprocess                                       *
     * ------------------------------------------------------------------ */
    {
        char cmd[768];
        size_t n = notify_build_cmd(title, body, success, cmd, sizeof(cmd));
        if (n == 0) {
            uprintf("notify: command too long, dropping notification");
            return FALSE;
        }

        /* Redirect stdout/stderr so the subprocess stays silent */
        char full_cmd[800];
        snprintf(full_cmd, sizeof(full_cmd), "%s >/dev/null 2>&1", cmd);

        int rc = system(full_cmd);
        if (rc != 0)
            uprintf("notify: notify-send exited with %d", rc);
        return (rc == 0) ? TRUE : FALSE;
    }
}
