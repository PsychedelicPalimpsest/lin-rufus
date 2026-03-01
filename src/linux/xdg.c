/*
 * Rufus: The Reliable USB Formatting Utility
 * XDG user directory lookup — Linux implementation
 * Copyright © 2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * xdg.h references BOOL which is defined in windows.h (compat).
 * We need to define it before including xdg.h when compiled standalone.
 */
#ifndef BOOL
typedef int BOOL;
#define TRUE  1
#define FALSE 0
#endif

#include "xdg.h"

/* ── Test injection state ─────────────────────────────────────────────────── */
static const char* s_config_home = NULL;
static const char* s_home_dir    = NULL;

#ifdef RUFUS_TEST
void xdg_set_config_home(const char* path) { s_config_home = path; }
void xdg_set_home_dir(const char* path)    { s_home_dir    = path; }
#endif

/* ── Internal helpers ────────────────────────────────────────────────────── */

/* Returns the effective $HOME directory. */
static const char* get_home_dir(void)
{
    if (s_home_dir)
        return s_home_dir;
    const char* h = getenv("HOME");
    return (h && h[0]) ? h : "/tmp";
}

/* Returns the effective XDG_CONFIG_HOME path.
 * buf must be at least PATH_MAX bytes. */
static const char* get_config_home(char* buf, size_t bufsz)
{
    if (s_config_home)
        return s_config_home;
    const char* xch = getenv("XDG_CONFIG_HOME");
    if (xch && xch[0])
        return xch;
    snprintf(buf, bufsz, "%s/.config", get_home_dir());
    return buf;
}

/* ── Public API ──────────────────────────────────────────────────────────── */
BOOL GetXdgUserDir(const char* name, char* buf, size_t bufsz)
{
    char config_buf[4096];
    char dirs_path[4096];
    const char* config_home = get_config_home(config_buf, sizeof(config_buf));

    snprintf(dirs_path, sizeof(dirs_path), "%s/user-dirs.dirs", config_home);
    FILE* f = fopen(dirs_path, "r");
    if (!f)
        return FALSE;

    /* Build the key we're looking for: XDG_<name>_DIR= */
    char key[64];
    snprintf(key, sizeof(key), "XDG_%s_DIR=", name);
    size_t keylen = strlen(key);

    char line[4096];
    BOOL found = FALSE;
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and blank lines */
        const char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0')
            continue;

        if (strncmp(p, key, keylen) != 0)
            continue;

        /* Found the key — parse the value */
        p += keylen;

        /* Strip leading/trailing whitespace before the quote */
        while (*p == ' ' || *p == '\t') p++;

        /* Value must be a quoted string: "..."  or  $HOME/...  */
        if (*p == '"') {
            p++; /* skip opening quote */
            char val[4096];
            size_t vi = 0;
            while (*p && *p != '"' && vi < sizeof(val) - 1)
                val[vi++] = *p++;
            val[vi] = '\0';

            /* Perform $HOME substitution */
            if (strncmp(val, "$HOME", 5) == 0) {
                const char* home = get_home_dir();
                snprintf(buf, bufsz, "%s%s", home, val + 5);
            } else {
                snprintf(buf, bufsz, "%s", val);
            }
            found = TRUE;
            break;
        }
    }
    fclose(f);
    return found;
}
