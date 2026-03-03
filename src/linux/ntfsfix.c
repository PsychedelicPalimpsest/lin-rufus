/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux NTFS fixup — run ntfsfix to repair NTFS boot integrity.
 *
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../linux/compat/windows.h"
#include "../windows/rufus.h"

/*
 * RunNtfsFix - run ntfsfix on a partition to ensure NTFS boot integrity.
 *
 * WinPE/AIK images need the NTFS volume to be marked "clean" after writing;
 * without this, some BIOSes and early boot-loaders refuse to start.
 * Mirrors Windows format.c CheckDisk().
 */
BOOL RunNtfsFix(const char *partition_path)
{
	if (!partition_path || partition_path[0] == '\0') return FALSE;
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "ntfsfix \"%s\"", partition_path);
	uprintf("Running NTFS fixup: %s", cmd);
	int r = system(cmd);
	if (r != 0)
		uprintf("WARNING: ntfsfix returned %d", r);
	return TRUE;
}
