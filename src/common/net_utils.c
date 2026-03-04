/*
 * Rufus: The Reliable USB Formatting Utility
 * Portable networking utility functions — shared between Linux and Windows builds.
 *
 * Provides pure-logic helpers that have no OS-specific dependencies:
 *   rufus_is_newer_version()      — version tuple comparison
 *   dbx_build_timestamp_url()     — GitHub "contents" → "commits" URL rewrite
 *   dbx_parse_github_timestamp()  — extract UTC epoch from GitHub commits JSON
 *
 * Copyright © 2025 PsychedelicPalimpsest
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "net_utils.h"

/*
 * On Windows, timegm (POSIX) is not available; _mkgmtime is the equivalent.
 * We define a compatibility shim here, local to this translation unit.
 */
#ifdef _WIN32
#  define timegm _mkgmtime
#endif

/* ---- internal helper -------------------------------------------- */

static uint64_t ver_to_u64(uint16_t v[3])
{
	return ((uint64_t)v[0] << 32) | ((uint64_t)v[1] << 16) | (uint64_t)v[2];
}

/* ------------------------------------------------------------------ */

BOOL rufus_is_newer_version(uint16_t server[3], uint16_t current[3])
{
	return (ver_to_u64(server) > ver_to_u64(current)) ? TRUE : FALSE;
}

BOOL dbx_build_timestamp_url(const char *content_url, char *out, size_t out_len)
{
	const char *marker = "contents/";
	const char *p, *path_part;
	char encoded[512];
	size_t base_len, ei;
	int n;

	if (content_url == NULL || out == NULL || out_len == 0)
		return FALSE;

	p = strstr(content_url, marker);
	if (p == NULL)
		return FALSE;

	base_len  = (size_t)(p - content_url);
	path_part = p + strlen(marker);

	/* URL-encode '/' as '%2F' within the file path */
	ei = 0;
	for (const char *s = path_part; *s && ei < sizeof(encoded) - 3; s++) {
		if (*s == '/') {
			encoded[ei++] = '%';
			encoded[ei++] = '2';
			encoded[ei++] = 'F';
		} else {
			encoded[ei++] = *s;
		}
	}
	encoded[ei] = '\0';

	n = snprintf(out, out_len, "%.*scommits?path=%s&page=1&per_page=1",
	             (int)base_len, content_url, encoded);
	return (n > 0 && (size_t)n < out_len);
}

BOOL dbx_parse_github_timestamp(const char *json, uint64_t *ts)
{
	const char *p, *c;
	struct tm t = { 0 };
	int r;
	time_t epoch;

	if (json == NULL || ts == NULL)
		return FALSE;

	p = strstr(json, "\"date\":");
	if (p == NULL)
		return FALSE;

	c = p + 7; /* skip past "date": */
	while (*c == ' ' || *c == '"')
		c++;

	r = sscanf(c, "%d-%d-%dT%d:%d:%dZ",
	           &t.tm_year, &t.tm_mon, &t.tm_mday,
	           &t.tm_hour, &t.tm_min, &t.tm_sec);
	if (r != 6)
		return FALSE;

	t.tm_year -= 1900;
	t.tm_mon  -= 1;

	epoch = timegm(&t);
	if (epoch == (time_t)-1)
		return FALSE;

	*ts = (uint64_t)epoch;
	return TRUE;
}
