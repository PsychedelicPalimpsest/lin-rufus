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
#pragma once

#include <stddef.h>

/*
 * install_crash_handlers() — Install SIGSEGV / SIGABRT / SIGBUS signal
 * handlers.  On a crash, the handler writes a full backtrace to stderr and
 * to a timestamped log file under the Rufus data directory:
 *
 *   ~/.local/share/rufus/crash-<YYYY-MM-DDTHH:MM:SS>.log
 *
 * The log path is also printed to stderr so users can attach it to bug
 * reports.
 *
 * Returns 0 on success, -1 if sigaction() failed for any signal.
 */
int install_crash_handlers(void);

/*
 * crash_handler_build_log_path() — Build the crash log file path from
 * app_data_dir and the current wall-clock time.
 *
 * Writes the full path into buf (at most size bytes including NUL).
 * Returns buf on success, NULL on error (buf==NULL or size==0).
 */
char *crash_handler_build_log_path(char *buf, size_t size);

/*
 * rufus_crash_handler() — The actual SA_SIGACTION-compatible handler.
 *
 * In production it writes the backtrace and calls _exit(1).
 * In RUFUS_TEST builds a pluggable exit hook can be set so tests can
 * invoke the handler without killing the test process:
 *
 *   crash_handler_set_exit(my_hook);
 *   rufus_crash_handler(SIGSEGV);   // does NOT call _exit
 */
void rufus_crash_handler(int signum);

#ifdef RUFUS_TEST
/*
 * crash_handler_set_exit() — Override the _exit() call inside the handler
 * (test builds only).  Pass NULL to restore the real _exit() behaviour.
 */
void crash_handler_set_exit(void (*fn)(int));
#endif
