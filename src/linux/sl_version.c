/*
 * Rufus: The Reliable USB Formatting Utility
 * Syslinux / Isolinux version string detection — Linux port
 * Copyright © 2003 Lars Munch Christensen
 * Copyright © 1998-2008 H. Peter Anvin
 * Copyright © 2012-2024 Pete Batard
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

/*
 * This file contains GetSyslinuxVersion() in isolation so that it can be
 * linked into both the main syslinux module AND the ISO scan tests without
 * dragging in all of syslinux.c's heavy dependencies (libfat, libinstaller,
 * block-device code, etc.).
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "rufus.h"

/* ------------------------------------------------------------------
 * GetSyslinuxVersion — scan a buffer for a syslinux/isolinux version
 * string of the form "SYSLINUX x.yy" or "ISOLINUX x.yy".
 *
 * Ported verbatim from src/windows/syslinux.c.
 * ------------------------------------------------------------------ */
uint16_t GetSyslinuxVersion(char *buf, size_t buf_size, char **ext)
{
    size_t i, j, k;
    char *p = NULL;
    unsigned long version_ul[2];
    uint16_t version = 0;
    const char LINUX[] = { 'L', 'I', 'N', 'U', 'X', ' ' };
    static char *nullstr = "";
    char unauthorized[] = { '<', '>', ':', '|', '*', '?', '\\', '/' };

    *ext = nullstr;
    if (buf_size < 256)
        return 0;

    /* Start at 64 to skip the short incomplete version at the top of ldlinux.sys */
    for (i = 64; i < buf_size - 64; i++) {
        if (memcmp(&buf[i], LINUX, sizeof(LINUX)) == 0) {
            /* Require "SYS" or "ISO" prefix immediately before "LINUX " */
            if (!( ((buf[i - 3] == 'I') && (buf[i - 2] == 'S') && (buf[i - 1] == 'O'))
                || ((buf[i - 3] == 'S') && (buf[i - 2] == 'Y') && (buf[i - 1] == 'S')) ))
                continue;
            i += sizeof(LINUX);
            version_ul[0] = strtoul(&buf[i], &p, 10);
            if (version_ul[0] >= 256) continue;
            version_ul[1] = strtoul(&p[1], &p, 10);
            if (version_ul[1] >= 256) continue;
            version = (uint16_t)((version_ul[0] << 8) + version_ul[1]);
            if (version == 0) continue;

            /* Force a '/' separator before any extra version suffix */
            *p = '/';
            /* Remove the x.yz- duplicate if present */
            for (j = 0; (buf[i + j] == p[1 + j]) && (buf[i + j] != ' '); j++);
            if (p[j + 1] == '-') j++;
            if (j > 0) {
                for (k = 1; p[k + j] != ' ' && p[k + j] != '\0'; k++)
                    p[k] = p[k + j];
                p[k] = '\0';
            }

            /* Drop characters that are invalid in directory names */
            for (j = 1; p[j] != '\0'; j++) {
                for (k = 0; k < sizeof(unauthorized); k++) {
                    if (p[j] == unauthorized[k]) {
                        p[j] = '_';
                        break;
                    }
                }
            }
            *ext = p;
            return version;
        }
    }
    return 0;
}
