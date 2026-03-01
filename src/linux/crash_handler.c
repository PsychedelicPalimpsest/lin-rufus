/*
 * Rufus: The Reliable USB Formatting Utility
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
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
 * crash_handler.c — SIGSEGV/SIGABRT/SIGBUS handler with backtrace logging.
 *
 * When a fatal signal arrives the handler:
 *  1. Writes a human-readable header + full backtrace to stderr.
 *  2. Opens (or creates) the crash log file under app_data_dir and writes
 *     the same information there.
 *  3. Prints the log path to stderr so the user can attach it to a bug report.
 *  4. Calls _exit(1) (or the test hook if installed).
 *
 * Only async-signal-safe libc functions are used inside the handler
 * (write, open, close, backtrace_symbols_fd, _exit, strsignal).
 */

#include "crash_handler.h"

#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* app_data_dir is declared in globals.c */
extern char app_data_dir[];

/* Maximum depth of the captured backtrace */
#define MAX_FRAMES 64

/* -------------------------------------------------------------------------
 * Internal helpers (async-signal-safe where it matters)
 * -----------------------------------------------------------------------*/

/* Write a NUL-terminated string to fd using write() (signal-safe). */
static void _write_str(int fd, const char *s)
{
    if (s && *s)
        (void)write(fd, s, strlen(s));
}

/* Write a decimal integer to fd (signal-safe — avoids printf). */
static void _write_int(int fd, int v)
{
    char buf[32];
    int pos = sizeof(buf) - 1;
    int neg = (v < 0);
    unsigned int u = (unsigned int)(neg ? -(long)v : (long)v);

    buf[pos] = '\0';
    if (u == 0) {
        buf[--pos] = '0';
    } else {
        while (u > 0) {
            buf[--pos] = (char)('0' + u % 10);
            u /= 10;
        }
    }
    if (neg) buf[--pos] = '-';
    _write_str(fd, buf + pos);
}

/* -------------------------------------------------------------------------
 * Test hook (RUFUS_TEST builds only)
 * -----------------------------------------------------------------------*/
#ifdef RUFUS_TEST
static void (*_exit_hook)(int) = NULL;
void crash_handler_set_exit(void (*fn)(int)) { _exit_hook = fn; }
#endif

/* -------------------------------------------------------------------------
 * Public API
 * -----------------------------------------------------------------------*/

/*
 * crash_handler_build_log_path() — build path for the crash log file.
 *
 * Format: <app_data_dir>/crash-<YYYY-MM-DDTHH:MM:SS>.log
 * Falls back to /tmp if app_data_dir is empty.
 */
char *crash_handler_build_log_path(char *buf, size_t size)
{
    time_t now;
    struct tm *tm_info;
    char ts[32];
    const char *dir;

    if (!buf || size == 0)
        return NULL;

    now = time(NULL);
    tm_info = localtime(&now);
    if (tm_info)
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);
    else
        snprintf(ts, sizeof(ts), "unknown");

    dir = (app_data_dir[0] != '\0') ? app_data_dir : "/tmp";
    snprintf(buf, size, "%s/crash-%s.log", dir, ts);
    return buf;
}

/*
 * rufus_crash_handler() — the actual signal handler.
 *
 * Must remain async-signal-safe; avoid printf/malloc.
 */
void rufus_crash_handler(int signum)
{
    void *frames[MAX_FRAMES];
    int  nframes;
    char log_path[512];
    int  log_fd = -1;
    const char *sig_name;
    int  fds[2];

    /* Resolve signal name */
    sig_name = strsignal(signum);

    /* ---- Build header text ---- */
    /* Write to stderr first */
    _write_str(STDERR_FILENO, "\n*** Rufus crashed: signal ");
    _write_int(STDERR_FILENO, signum);
    if (sig_name) {
        _write_str(STDERR_FILENO, " (");
        _write_str(STDERR_FILENO, sig_name);
        _write_str(STDERR_FILENO, ")");
    }
    _write_str(STDERR_FILENO, "\n");

    /* ---- Capture backtrace ---- */
    nframes = backtrace(frames, MAX_FRAMES);

    /* Build crash log path */
    crash_handler_build_log_path(log_path, sizeof(log_path));

    /* ---- Open log file ---- */
    log_fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    /* Write backtrace to both stderr and log file */
    fds[0] = STDERR_FILENO;
    fds[1] = log_fd;

    for (int i = 0; i < 2; i++) {
        int fd = fds[i];
        if (fd < 0) continue;

        _write_str(fd, "*** Rufus crashed: signal ");
        _write_int(fd, signum);
        if (sig_name) {
            _write_str(fd, " (");
            _write_str(fd, sig_name);
            _write_str(fd, ")");
        }
        _write_str(fd, "\n\nBacktrace:\n");
        backtrace_symbols_fd(frames, nframes, fd);
        _write_str(fd, "\n");
    }

    if (log_fd >= 0) {
        close(log_fd);
        _write_str(STDERR_FILENO, "Crash log written to: ");
        _write_str(STDERR_FILENO, log_path);
        _write_str(STDERR_FILENO, "\n");
        _write_str(STDERR_FILENO,
            "Please attach this file when reporting the bug.\n");
    }

#ifdef RUFUS_TEST
    if (_exit_hook) {
        _exit_hook(signum);
        return;
    }
#endif
    _exit(1);
}

/*
 * install_crash_handlers() — register the handler for SIGSEGV/SIGABRT/SIGBUS.
 */
int install_crash_handlers(void)
{
    struct sigaction sa;
    int signals[] = { SIGSEGV, SIGABRT, SIGBUS };
    int ok = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = rufus_crash_handler;
    sigemptyset(&sa.sa_mask);
    /* SA_RESETHAND: restore default after first call so the process
     * terminates cleanly if the handler itself faults.
     * SA_NODEFER:   don't block the signal inside the handler. */
    sa.sa_flags = SA_RESETHAND | SA_NODEFER;

    for (int i = 0; i < (int)(sizeof(signals) / sizeof(signals[0])); i++) {
        if (sigaction(signals[i], &sa, NULL) != 0)
            ok = -1;
    }
    return ok;
}
