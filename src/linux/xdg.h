/*
 * Rufus: The Reliable USB Formatting Utility
 * XDG user directory lookup — Linux
 * Copyright © 2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GetXdgUserDir() — look up an XDG user directory by name.
 *
 * Reads $XDG_CONFIG_HOME/user-dirs.dirs (or ~/.config/user-dirs.dirs),
 * finds the line  XDG_<name>_DIR="..."  and returns the resolved path.
 * $HOME substitution is performed.
 *
 * name        One of: DOWNLOAD, DESKTOP, DOCUMENTS, PICTURES, MUSIC, VIDEOS,
 *             TEMPLATES, PUBLICSHARE.
 * buf         Output buffer.
 * bufsz       Size of buf.
 *
 * Returns TRUE and fills buf on success.
 * Returns FALSE and leaves buf unchanged on failure; caller may use a default.
 */
BOOL GetXdgUserDir(const char* name, char* buf, size_t bufsz);

#ifdef RUFUS_TEST
/* Redirect the config home directory (NULL = use default / env var). */
void xdg_set_config_home(const char* path);
/* Redirect the home directory (NULL = use getenv("HOME")).           */
void xdg_set_home_dir(const char* path);
#endif

#ifdef __cplusplus
}
#endif
