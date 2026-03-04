/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: paths.c — SUDO_USER-aware settings path resolution
 * Copyright © 2025 PsychedelicPalimpsest
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

/* src/linux/paths.c
 * Home-directory resolution for the Linux port of Rufus.
 *
 * Feature 222: SUDO_USER-aware settings paths
 *
 * When the user runs 'sudo rufus', the process executes as root but
 * SUDO_USER is set to the original user's login name.  Without this
 * logic Rufus would store its settings in /root/.config/rufus/rufus.ini,
 * which is not what the user expects — they want their own config to be
 * used.  This mirrors the Windows UAC behaviour where elevated processes
 * still see the original user's profile.
 *
 * Two exported functions:
 *
 *   rufus_effective_home_impl()  — pure, testable, takes injected params
 *   rufus_effective_home()       — production wrapper, uses live env/uid
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#include "paths.h"

/*
 * rufus_effective_home_impl() — injectable implementation for testing.
 *
 * @euid       effective user ID (0 = root)
 * @sudo_user  value of $SUDO_USER (may be NULL or empty)
 * @home_env   value of $HOME (may be NULL or empty)
 * @buf        output buffer for the resolved home directory path
 * @sz         size of @buf
 *
 * Returns @buf (always, even on error — falls back to "/tmp").
 *
 * Resolution logic:
 *   1. If running as root (euid==0) AND SUDO_USER is non-empty:
 *      look up the original user's home via getpwnam(SUDO_USER).
 *      If the lookup succeeds, use pw_dir.
 *      If the lookup fails, fall through to step 2.
 *   2. Otherwise: use home_env if non-empty, else "/tmp".
 */
const char *rufus_effective_home_impl(uid_t euid,
                                      const char *sudo_user,
                                      const char *home_env,
                                      char *buf, size_t sz)
{
    if (euid == 0 && sudo_user != NULL && sudo_user[0] != '\0') {
        struct passwd *pw = getpwnam(sudo_user);
        if (pw != NULL && pw->pw_dir != NULL && pw->pw_dir[0] != '\0') {
            snprintf(buf, sz, "%s", pw->pw_dir);
            return buf;
        }
    }
    if (home_env != NULL && home_env[0] != '\0') {
        snprintf(buf, sz, "%s", home_env);
    } else {
        snprintf(buf, sz, "/tmp");
    }
    return buf;
}

/*
 * rufus_effective_home() — resolve the effective home directory.
 *
 * Wraps rufus_effective_home_impl() with live environment/uid values.
 * When running as root via 'sudo rufus', uses the original user's home
 * (from SUDO_USER → getpwnam) so that settings are stored in the
 * user's profile rather than /root.
 */
const char *rufus_effective_home(char *buf, size_t sz)
{
    return rufus_effective_home_impl(geteuid(),
                                     getenv("SUDO_USER"),
                                     getenv("HOME"),
                                     buf, sz);
}
