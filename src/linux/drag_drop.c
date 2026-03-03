/*
 * Rufus: The Reliable USB Formatting Utility
 * Drag-and-drop URI helpers — Linux implementation
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "drag_drop.h"

/*
 * path_from_file_uri  —  convert a "file://" URI to a local filesystem path.
 *
 * Handles:
 *  - "file:///path"   → "/path"   (three-slash form, most common)
 *  - "file://host/path" host part is stripped
 *  - Percent-encoded characters (%XX) are decoded
 *
 * Returns a malloc'd string on success, NULL on failure or invalid input.
 * Caller must free() the result.
 */
char *path_from_file_uri(const char *uri)
{
	if (!uri)
		return NULL;

	/* Must start with "file://" */
	if (strncmp(uri, "file://", 7) != 0)
		return NULL;

	const char *p = uri + 7;

	/* Skip optional host component: "file://hostname/path" → skip to '/' */
	if (*p != '/') {
		p = strchr(p, '/');
		if (!p)
			return NULL;
	}

	/* Allocate output buffer (decoded path is always <= encoded length) */
	char *out = malloc(strlen(p) + 1);
	if (!out)
		return NULL;

	char *q = out;
	while (*p) {
		if (*p == '%' && isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2])) {
			char hex[3] = { p[1], p[2], '\0' };
			*q++ = (char)strtol(hex, NULL, 16);
			p += 3;
		} else {
			*q++ = *p++;
		}
	}
	*q = '\0';

	/* Strip trailing newline/carriage return (some GTK versions append \r\n) */
	while (q > out && (q[-1] == '\r' || q[-1] == '\n'))
		*--q = '\0';

	return out;
}
