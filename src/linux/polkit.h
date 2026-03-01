/*
 * Rufus: The Reliable USB Formatting Utility
 * polkit privilege elevation helper — Linux port
 * Copyright © 2025 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#pragma once

#ifdef __linux__

/*
 * rufus_needs_elevation() — returns TRUE if the current process is not
 * running as root (euid != 0).
 */
int rufus_needs_elevation(void);

/*
 * rufus_build_pkexec_argv() — allocate and return a NULL-terminated argv
 * array suitable for execv() that re-launches `exe_path` under pkexec with
 * the given arguments.
 *
 * The returned array has the following layout:
 *   [0] pkexec_path   (e.g. "/usr/bin/pkexec")
 *   [1] exe_path      (absolute path to this executable)
 *   [2..n] extra_argv (forwarded command-line arguments, may be empty)
 *   [n+1] NULL
 *
 * Returns a heap-allocated array (free with rufus_free_pkexec_argv()) or
 * NULL on allocation failure.
 *
 * Neither pkexec_path nor exe_path is validated — callers are responsible
 * for passing non-NULL strings.
 */
char **rufus_build_pkexec_argv(const char *pkexec_path,
                               const char *exe_path,
                               char * const extra_argv[],
                               int extra_argc);

/*
 * rufus_free_pkexec_argv() — release the array allocated by
 * rufus_build_pkexec_argv().
 */
void rufus_free_pkexec_argv(char **argv);

/*
 * rufus_try_pkexec() — attempt to re-launch the current process under
 * pkexec.  Does not return on success (execv replaces the process image).
 * Returns non-zero if pkexec could not be launched (e.g. not in PATH or
 * execv failed), so the caller can fall back to warning the user.
 *
 * argc/argv should be the values from main().
 */
int rufus_try_pkexec(int argc, char *argv[]);

#endif /* __linux__ */
