/*
 * Rufus: The Reliable USB Formatting Utility
 * Portable networking utility functions — shared between Linux and Windows builds.
 *
 * Copyright © 2025 PsychedelicPalimpsest
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include "windows.h"
#endif

/*
 * rufus_is_newer_version — returns TRUE if server[] is strictly newer than current[].
 * Both arrays have 3 elements: major, minor, patch.
 */
BOOL rufus_is_newer_version(uint16_t server[3], uint16_t current[3]);

/*
 * dbx_build_timestamp_url — converts a GitHub "contents" API URL to the
 * corresponding "commits" API URL used to obtain the last-modified timestamp.
 *
 * Example:
 *   in:  "https://api.github.com/repos/o/r/contents/path/to/file.efi"
 *   out: "https://api.github.com/repos/o/r/commits?path=path%2Fto%2Ffile.efi&page=1&per_page=1"
 *
 * Returns TRUE on success, FALSE if input is NULL, output buffer is too small,
 * or the "contents/" marker is absent.
 */
BOOL dbx_build_timestamp_url(const char *content_url, char *out, size_t out_len);

/*
 * dbx_parse_github_timestamp — extracts the UTC epoch timestamp from a GitHub
 * commits API JSON response body.
 *
 * Scans the JSON for the first occurrence of  "date":"YYYY-MM-DDTHH:MM:SSZ"
 * and converts it to a Unix epoch stored in *ts.
 *
 * Returns TRUE on success, FALSE on any parse error or NULL argument.
 */
BOOL dbx_parse_github_timestamp(const char *json, uint64_t *ts);
