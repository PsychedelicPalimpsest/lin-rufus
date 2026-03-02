/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: status_history.c — status message history
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
 * status_history.c — Status label history ring buffer
 *
 * Stores the last STATUS_HISTORY_SIZE messages in a circular array.
 * Designed to be called from the GTK main thread only (no locking needed).
 */

#include "status_history.h"

#include <string.h>
#include <stdio.h>

#define MSG_MAX 256   /* max chars per stored message (truncated if longer) */

static char  ring[STATUS_HISTORY_SIZE][MSG_MAX];
static int   head  = 0;   /* index of most recently pushed entry */
static int   count = 0;   /* number of valid entries (0 … STATUS_HISTORY_SIZE) */

void status_history_clear(void)
{
    head  = 0;
    count = 0;
    for (int i = 0; i < STATUS_HISTORY_SIZE; i++)
        ring[i][0] = '\0';
}

void status_history_push(const char *msg)
{
    if (!msg) msg = "";

    /* Advance head to next slot */
    if (count > 0)
        head = (head + 1) % STATUS_HISTORY_SIZE;
    /* else head stays at 0 for the very first push */

    strncpy(ring[head], msg, MSG_MAX - 1);
    ring[head][MSG_MAX - 1] = '\0';

    if (count < STATUS_HISTORY_SIZE)
        count++;
}

/*
 * Build tooltip: all entries except the current one, newest first.
 * Returns buf.
 */
char *status_history_tooltip(char *buf, size_t buf_sz)
{
    if (!buf || buf_sz == 0)
        return buf;

    buf[0] = '\0';

    if (count <= 1) {
        /* Only the current entry (or nothing): no history to show */
        return buf;
    }

    /* Walk backwards from the entry just before head, up to count-1 entries */
    size_t pos = 0;
    int    first = 1;
    for (int i = 1; i < count; i++) {
        int idx = (head - i + STATUS_HISTORY_SIZE) % STATUS_HISTORY_SIZE;
        const char *entry = ring[idx];

        if (!first) {
            /* Append newline separator */
            if (pos + 1 < buf_sz) {
                buf[pos++] = '\n';
                buf[pos]   = '\0';
            } else {
                break;
            }
        }
        first = 0;

        size_t len = strlen(entry);
        size_t avail = buf_sz - pos - 1; /* -1 for null terminator */
        if (len > avail) len = avail;
        if (len > 0) {
            memcpy(buf + pos, entry, len);
            pos += len;
            buf[pos] = '\0';
        }

        if (pos + 1 >= buf_sz)
            break;
    }

    buf[buf_sz - 1] = '\0';
    return buf;
}

char *status_history_get_current(char *buf, size_t buf_sz)
{
    if (!buf || buf_sz == 0)
        return buf;

    if (count == 0) {
        buf[0] = '\0';
        return buf;
    }

    strncpy(buf, ring[head], buf_sz - 1);
    buf[buf_sz - 1] = '\0';
    return buf;
}
