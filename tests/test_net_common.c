/*
 * test_net_common.c — Cross-platform tests for portable net-utility functions
 *
 * Tests the three pure-logic helpers in src/common/net_utils.c:
 *   rufus_is_newer_version()      — version tuple comparison
 *   dbx_build_timestamp_url()     — GitHub contents → commits URL rewrite
 *   dbx_parse_github_timestamp()  — UTC epoch extraction from GitHub commits JSON
 *
 * These tests run on Linux (native) and on Windows via Wine (MinGW cross-build).
 * There are no OS-specific dependencies.
 *
 * Copyright © 2025 PsychedelicPalimpsest
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "framework.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include "windows.h"
#endif

#include "../src/common/net_utils.h"

/* ================================================================== */
/* rufus_is_newer_version                                              */
/* ================================================================== */

TEST(newer_version_major_bump)
{
	uint16_t server[3]  = {4, 0, 0};
	uint16_t current[3] = {3, 9, 9};
	CHECK(rufus_is_newer_version(server, current) == TRUE);
}

TEST(newer_version_minor_bump)
{
	uint16_t server[3]  = {3, 2, 0};
	uint16_t current[3] = {3, 1, 0};
	CHECK(rufus_is_newer_version(server, current) == TRUE);
}

TEST(newer_version_patch_bump)
{
	uint16_t server[3]  = {3, 1, 2};
	uint16_t current[3] = {3, 1, 1};
	CHECK(rufus_is_newer_version(server, current) == TRUE);
}

TEST(newer_version_same_returns_false)
{
	uint16_t server[3]  = {3, 1, 1};
	uint16_t current[3] = {3, 1, 1};
	CHECK(rufus_is_newer_version(server, current) == FALSE);
}

TEST(newer_version_older_major_returns_false)
{
	uint16_t server[3]  = {2, 9, 9};
	uint16_t current[3] = {3, 0, 0};
	CHECK(rufus_is_newer_version(server, current) == FALSE);
}

TEST(newer_version_older_minor_returns_false)
{
	uint16_t server[3]  = {3, 0, 5};
	uint16_t current[3] = {3, 1, 0};
	CHECK(rufus_is_newer_version(server, current) == FALSE);
}

TEST(newer_version_zeros)
{
	uint16_t server[3]  = {0, 0, 0};
	uint16_t current[3] = {0, 0, 0};
	CHECK(rufus_is_newer_version(server, current) == FALSE);
}

TEST(newer_version_server_zero_current_nonzero)
{
	uint16_t server[3]  = {0, 0, 0};
	uint16_t current[3] = {1, 0, 0};
	CHECK(rufus_is_newer_version(server, current) == FALSE);
}

TEST(newer_version_max_values)
{
	uint16_t server[3]  = {0xFFFF, 0xFFFF, 0xFFFF};
	uint16_t current[3] = {0xFFFF, 0xFFFF, 0xFFFE};
	CHECK(rufus_is_newer_version(server, current) == TRUE);
}

/* ================================================================== */
/* dbx_build_timestamp_url                                             */
/* ================================================================== */

static const char *SAMPLE_CONTENTS_URL =
	"https://api.github.com/repos/microsoft/secureboot_objects"
	"/contents/PostSignedObjects/DBX/amd64/DBXUpdate.bin";

static const char *EXPECTED_COMMITS_URL =
	"https://api.github.com/repos/microsoft/secureboot_objects"
	"/commits?path=PostSignedObjects%2FDBX%2Famd64%2FDBXUpdate.bin"
	"&page=1&per_page=1";

TEST(dbx_url_basic)
{
	char out[512];
	CHECK(dbx_build_timestamp_url(SAMPLE_CONTENTS_URL, out, sizeof(out)) == TRUE);
	CHECK_STR_EQ(out, EXPECTED_COMMITS_URL);
}

TEST(dbx_url_no_slash_in_path)
{
	/* File directly under "contents/" — no slashes to encode */
	const char *url = "https://api.github.com/repos/o/r/contents/file.bin";
	const char *expected = "https://api.github.com/repos/o/r/commits?path=file.bin&page=1&per_page=1";
	char out[256];
	CHECK(dbx_build_timestamp_url(url, out, sizeof(out)) == TRUE);
	CHECK_STR_EQ(out, expected);
}

TEST(dbx_url_null_input_returns_false)
{
	char out[256];
	CHECK(dbx_build_timestamp_url(NULL, out, sizeof(out)) == FALSE);
}

TEST(dbx_url_null_out_returns_false)
{
	CHECK(dbx_build_timestamp_url(SAMPLE_CONTENTS_URL, NULL, 256) == FALSE);
}

TEST(dbx_url_zero_out_len_returns_false)
{
	char out[4];
	CHECK(dbx_build_timestamp_url(SAMPLE_CONTENTS_URL, out, 0) == FALSE);
}

TEST(dbx_url_buffer_too_small_returns_false)
{
	char out[10];
	CHECK(dbx_build_timestamp_url(SAMPLE_CONTENTS_URL, out, sizeof(out)) == FALSE);
}

TEST(dbx_url_missing_contents_marker_returns_false)
{
	const char *url = "https://api.github.com/repos/o/r/releases/file.bin";
	char out[256];
	CHECK(dbx_build_timestamp_url(url, out, sizeof(out)) == FALSE);
}

TEST(dbx_url_multiple_slashes_all_encoded)
{
	const char *url = "https://api.github.com/repos/o/r/contents/a/b/c/d.bin";
	const char *expected =
		"https://api.github.com/repos/o/r/commits?path=a%2Fb%2Fc%2Fd.bin"
		"&page=1&per_page=1";
	char out[256];
	CHECK(dbx_build_timestamp_url(url, out, sizeof(out)) == TRUE);
	CHECK_STR_EQ(out, expected);
}

TEST(dbx_url_exact_buffer_size_returns_false)
{
	/* Buffer exactly equal to the required strlen — snprintf will truncate */
	char out[256];
	int expected_len = (int)strlen(EXPECTED_COMMITS_URL);
	CHECK(dbx_build_timestamp_url(SAMPLE_CONTENTS_URL, out, (size_t)expected_len) == FALSE);
}

/* ================================================================== */
/* dbx_parse_github_timestamp                                          */
/* ================================================================== */

/* A minimal GitHub commits-API JSON snippet with a known date */
static const char *SAMPLE_JSON =
	"[{\"sha\":\"abc\",\"commit\":"
	"{\"author\":{\"name\":\"Bot\",\"date\":\"2024-01-15T12:30:00Z\"}}}]";

/* 2024-01-15 12:30:00 UTC */
#define EXPECTED_TS ((uint64_t)1705321800ULL)

TEST(dbx_parse_basic)
{
	uint64_t ts = 0;
	CHECK(dbx_parse_github_timestamp(SAMPLE_JSON, &ts) == TRUE);
	CHECK_INT_EQ((int64_t)ts, (int64_t)EXPECTED_TS);
}

TEST(dbx_parse_null_json_returns_false)
{
	uint64_t ts = 0;
	CHECK(dbx_parse_github_timestamp(NULL, &ts) == FALSE);
}

TEST(dbx_parse_null_ts_returns_false)
{
	CHECK(dbx_parse_github_timestamp(SAMPLE_JSON, NULL) == FALSE);
}

TEST(dbx_parse_no_date_field_returns_false)
{
	const char *json = "[{\"sha\":\"abc\",\"commit\":{\"author\":{\"name\":\"Bot\"}}}]";
	uint64_t ts = 0;
	CHECK(dbx_parse_github_timestamp(json, &ts) == FALSE);
}

TEST(dbx_parse_malformed_date_returns_false)
{
	const char *json = "[{\"date\":\"not-a-date\"}]";
	uint64_t ts = 0;
	CHECK(dbx_parse_github_timestamp(json, &ts) == FALSE);
}

TEST(dbx_parse_epoch_2000)
{
	/* 2000-01-01 00:00:00 UTC == 946684800 */
	const char *json = "[{\"date\":\"2000-01-01T00:00:00Z\"}]";
	uint64_t ts = 0;
	CHECK(dbx_parse_github_timestamp(json, &ts) == TRUE);
	CHECK_INT_EQ((int64_t)ts, (int64_t)946684800LL);
}

TEST(dbx_parse_epoch_unix_start)
{
	/* 1970-01-01 00:00:00 UTC == 0 */
	const char *json = "[{\"date\":\"1970-01-01T00:00:00Z\"}]";
	uint64_t ts = 0;
	CHECK(dbx_parse_github_timestamp(json, &ts) == TRUE);
	CHECK_INT_EQ((int64_t)ts, 0);
}

TEST(dbx_parse_spaces_around_date_value)
{
	/* The parser skips leading spaces and quotes after "date": */
	const char *json = "[{\"date\":  \"2024-01-15T12:30:00Z\"}]";
	uint64_t ts = 0;
	CHECK(dbx_parse_github_timestamp(json, &ts) == TRUE);
	CHECK_INT_EQ((int64_t)ts, (int64_t)EXPECTED_TS);
}

int main(void)
{
	/* rufus_is_newer_version */
	RUN(newer_version_major_bump);
	RUN(newer_version_minor_bump);
	RUN(newer_version_patch_bump);
	RUN(newer_version_same_returns_false);
	RUN(newer_version_older_major_returns_false);
	RUN(newer_version_older_minor_returns_false);
	RUN(newer_version_zeros);
	RUN(newer_version_server_zero_current_nonzero);
	RUN(newer_version_max_values);

	/* dbx_build_timestamp_url */
	RUN(dbx_url_basic);
	RUN(dbx_url_no_slash_in_path);
	RUN(dbx_url_null_input_returns_false);
	RUN(dbx_url_null_out_returns_false);
	RUN(dbx_url_zero_out_len_returns_false);
	RUN(dbx_url_buffer_too_small_returns_false);
	RUN(dbx_url_missing_contents_marker_returns_false);
	RUN(dbx_url_multiple_slashes_all_encoded);
	RUN(dbx_url_exact_buffer_size_returns_false);

	/* dbx_parse_github_timestamp */
	RUN(dbx_parse_basic);
	RUN(dbx_parse_null_json_returns_false);
	RUN(dbx_parse_null_ts_returns_false);
	RUN(dbx_parse_no_date_field_returns_false);
	RUN(dbx_parse_malformed_date_returns_false);
	RUN(dbx_parse_epoch_2000);
	RUN(dbx_parse_epoch_unix_start);
	RUN(dbx_parse_spaces_around_date_value);

	TEST_RESULTS();
}
