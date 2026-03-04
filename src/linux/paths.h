/*
 * Rufus: The Reliable USB Formatting Utility
 * paths.h — SUDO_USER-aware home directory resolution
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <sys/types.h>
#include <stddef.h>

/*
 * rufus_effective_home_impl() — pure/testable implementation.
 *
 * Resolves the "real" home directory considering SUDO_USER:
 *   - euid==0 + non-empty sudo_user → getpwnam(sudo_user)->pw_dir
 *   - otherwise                     → home_env (or "/tmp" if NULL/empty)
 *
 * Returns @buf.  Never returns NULL.
 */
const char *rufus_effective_home_impl(uid_t euid,
                                      const char *sudo_user,
                                      const char *home_env,
                                      char *buf, size_t sz);

/*
 * rufus_effective_home() — production wrapper (live env + geteuid()).
 * Returns @buf.  Never returns NULL.
 */
const char *rufus_effective_home(char *buf, size_t sz);
