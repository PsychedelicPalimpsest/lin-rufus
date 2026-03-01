/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: download_resume.c — .partial file helpers
 * Copyright © 2015-2025 Pete Batard <pete@akeo.ie>
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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include "download_resume.h"

/*
 * get_partial_path — append ".partial" suffix to target_path.
 */
char *get_partial_path(const char *target_path, char *buf, size_t bufsz)
{
	size_t tlen;

	if (target_path == NULL || buf == NULL)
		return NULL;

	tlen = strlen(target_path);
	/* Need room for target_path + ".partial" + NUL */
	if (tlen + 8 + 1 > bufsz)
		return NULL;

	memcpy(buf, target_path, tlen);
	memcpy(buf + tlen, ".partial", 9); /* includes NUL */
	return buf;
}

/*
 * has_partial_download — return TRUE if target_path.partial exists.
 */
BOOL has_partial_download(const char *target_path)
{
	char partial[4096];
	struct stat st;

	if (!get_partial_path(target_path, partial, sizeof(partial)))
		return FALSE;
	return (stat(partial, &st) == 0);
}

/*
 * get_partial_size — return the byte size of target_path.partial.
 */
uint64_t get_partial_size(const char *target_path)
{
	char partial[4096];
	struct stat st;

	if (!get_partial_path(target_path, partial, sizeof(partial)))
		return 0;
	if (stat(partial, &st) != 0)
		return 0;
	return (uint64_t)st.st_size;
}

/*
 * finalize_partial_download — rename target_path.partial → target_path.
 */
BOOL finalize_partial_download(const char *target_path)
{
	char partial[4096];

	if (!get_partial_path(target_path, partial, sizeof(partial)))
		return FALSE;
	return (rename(partial, target_path) == 0);
}

/*
 * abandon_partial_download — delete target_path.partial.
 */
BOOL abandon_partial_download(const char *target_path)
{
	char partial[4096];

	if (!get_partial_path(target_path, partial, sizeof(partial)))
		return FALSE;
	return (unlink(partial) == 0);
}
