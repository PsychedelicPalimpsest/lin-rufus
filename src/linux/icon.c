/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: icon.c — icon/image utilities
 * Copyright © 2012-2026 Pete Batard <pete@akeo.ie>
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

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "rufus.h"

BOOL ExtractAppIcon(const char* path, BOOL bSilent) { (void)path;(void)bSilent; return FALSE; }

/*
 * Create autorun.inf in path (if one does not already exist).
 * Mirrors Windows icon.c SetAutorun() — creates the [autorun] label entry.
 * Icon extraction is skipped on Linux (no embedded .exe resources).
 */
BOOL SetAutorun(const char* path)
{
	FILE *fd;
	char filename[PATH_MAX];
	char label_buf[64] = "";

	if (!path)
		return FALSE;

	/* Build full path to autorun.inf */
	snprintf(filename, sizeof(filename), "%s/autorun.inf", path);

	fd = fopen(filename, "r");
	if (fd != NULL) {
		uprintf("%s already exists - keeping it", filename);
		fclose(fd);
		return FALSE;
	}

	/* Read the current volume label from hLabel (GTK window text bridge) */
	if (hLabel)
		GetWindowTextA(hLabel, label_buf, (int)sizeof(label_buf));

	fd = fopen(filename, "w");
	if (fd == NULL) {
		uprintf("Unable to create %s", filename);
		return FALSE;
	}

	fprintf(fd, "; Created by Rufus\n; " RUFUS_URL "\n");
	fprintf(fd, "[autorun]\nicon  = autorun.ico\nlabel = %s\n", label_buf);
	fclose(fd);
	uprintf("Created: %s", filename);
	return TRUE;
}
