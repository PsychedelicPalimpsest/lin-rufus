/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: dos_locale.c — DOS locale data
 * Copyright © 2011-2024 Pete Batard <pete@akeo.ie>
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
 * Linux implementation: dos_locale.c
 * SetDOSLocale — create minimal AUTOEXEC.BAT and FDCONFIG.SYS for FreeDOS
 *
 * On Linux we can't easily detect the system OEM codepage or keyboard
 * layout, so we default to US English / CP437.  A future enhancement
 * could parse /etc/locale.conf or $LANG to pick a better default.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "rufus.h"
#include "dos.h"

BOOL SetDOSLocale(const char* path, BOOL bFreeDOS)
{
    (void)bFreeDOS;  /* always treat as FreeDOS on Linux */

    if (path == NULL) {
        uprintf("SetDOSLocale: NULL path");
        return FALSE;
    }

    /* Create AUTOEXEC.BAT */
    char filename[MAX_PATH];
    snprintf(filename, sizeof(filename), "%sAUTOEXEC.BAT", path);
    FILE* fd = fopen(filename, "w");
    if (fd == NULL) {
        uprintf_errno("SetDOSLocale: cannot create AUTOEXEC.BAT");
        return FALSE;
    }
    fprintf(fd, "@echo off\r\n");
    fprintf(fd, "set PATH=.;\\;\\LOCALE\r\n");
    fprintf(fd, "echo Using US keyboard with CP437 codepage\r\n");
    fclose(fd);

    /* Create FDCONFIG.SYS (FreeDOS config) */
    snprintf(filename, sizeof(filename), "%sFDCONFIG.SYS", path);
    fd = fopen(filename, "w");
    if (fd == NULL) {
        /* Non-fatal — AUTOEXEC.BAT is sufficient for basic boot */
        uprintf_errno("SetDOSLocale: cannot create FDCONFIG.SYS");
        return TRUE;
    }
    fprintf(fd, "!DEVICE=\\LOCALE\\DISPLAY.EXE CON=(EGA,,1)\r\n");
    fprintf(fd, "!DEVICE=\\LOCALE\\KEYB.EXE US,437,\\LOCALE\\KEYBOARD.SYS\r\n");
    fclose(fd);

    uprintf("SetDOSLocale: created AUTOEXEC.BAT and FDCONFIG.SYS");
    return TRUE;
}
