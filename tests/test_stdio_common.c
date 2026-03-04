/*
 * test_stdio_common.c — Cross-platform tests for common/stdio.c
 *
 * Tests the portable GUID and timestamp utility functions.
 * The suite runs identically on Linux and Windows (via Wine).
 *
 * Functions under test:
 *   GuidToString()            — GUID → "{XXXXXXXX-XXXX-…}" or plain hex
 *   StringToGuid()            — "{XXXXXXXX-XXXX-…}" → GUID
 *   TimestampToHumanReadable()— YYYYMMDDHHMMSS → "YYYY.MM.DD HH:MM:SS (UTC)"
 *
 * Copyright © 2025 PsychedelicPalimpsest
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "framework.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "rufus.h"

/* ================================================================== */
/* GuidToString tests                                                  */
/* ================================================================== */

TEST(guid_to_string_null_returns_null)
{
	CHECK(GuidToString(NULL, TRUE)  == NULL);
	CHECK(GuidToString(NULL, FALSE) == NULL);
}

TEST(guid_to_string_zero_guid_decorated)
{
	GUID g = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };
	char *s = GuidToString(&g, TRUE);
	CHECK(s != NULL);
	CHECK_STR_EQ("{00000000-0000-0000-0000-000000000000}", s);
}

TEST(guid_to_string_known_guid)
{
	/* EFI System Partition GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B */
	GUID efi = { 0xC12A7328, 0xF81F, 0x11D2,
	             { 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };
	char *s = GuidToString(&efi, TRUE);
	CHECK(s != NULL);
	CHECK_STR_EQ("{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}", s);
}

TEST(guid_to_string_undecorated_format)
{
	GUID g = { 0xAABBCCDD, 0x1122, 0x3344,
	           { 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC } };
	/* Copy decorated result — GuidToString uses a static buffer */
	char decorated[40];
	char *tmp = GuidToString(&g, TRUE);
	CHECK(tmp != NULL);
	strncpy(decorated, tmp, sizeof(decorated) - 1);
	decorated[sizeof(decorated) - 1] = '\0';

	char *plain = GuidToString(&g, FALSE);
	CHECK(plain != NULL);
	/* Decorated has braces; undecorated does not */
	CHECK(decorated[0] == '{');
	CHECK(plain[0] != '{');
	/* Decorated: 38 chars; undecorated: 32 hex digits */
	CHECK_INT_EQ(38, (int)strlen(decorated));
	CHECK_INT_EQ(32, (int)strlen(plain));
}

TEST(guid_to_string_upper_case)
{
	GUID g = { 0xabcdef12, 0xabcd, 0xef01,
	           { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } };
	char *s = GuidToString(&g, TRUE);
	CHECK(s != NULL);
	/* All hex digits must be uppercase */
	for (int i = 0; s[i]; i++) {
		char c = s[i];
		if (c >= 'a' && c <= 'f') {
			CHECK_MSG(0, "GuidToString must use uppercase hex");
		}
	}
}

/* ================================================================== */
/* StringToGuid tests                                                  */
/* ================================================================== */

TEST(string_to_guid_null_returns_null)
{
	CHECK(StringToGuid(NULL) == NULL);
}

TEST(string_to_guid_bad_format_returns_null)
{
	CHECK(StringToGuid("not-a-guid") == NULL);
	CHECK(StringToGuid("{ZZZZZZZZ-0000-0000-0000-000000000000}") == NULL);
	CHECK(StringToGuid("C12A7328-F81F-11D2-BA4B-00A0C93EC93B") == NULL); /* no braces */
}

TEST(string_to_guid_parses_known_guid)
{
	GUID *g = StringToGuid("{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}");
	CHECK(g != NULL);
	CHECK_INT_EQ((int)0xC12A7328, (int)g->Data1);
	CHECK_INT_EQ((int)0xF81F,     (int)g->Data2);
	CHECK_INT_EQ((int)0x11D2,     (int)g->Data3);
	CHECK_INT_EQ((int)0xBA,       (int)g->Data4[0]);
	CHECK_INT_EQ((int)0x4B,       (int)g->Data4[1]);
}

TEST(string_to_guid_round_trip)
{
	GUID original = { 0xDEADBEEF, 0xCAFE, 0xBABE,
	                  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF } };
	char encoded[40];
	char *tmp = GuidToString(&original, TRUE);
	CHECK(tmp != NULL);
	strncpy(encoded, tmp, sizeof(encoded) - 1);
	encoded[sizeof(encoded) - 1] = '\0';

	GUID *decoded = StringToGuid(encoded);
	CHECK(decoded != NULL);
	CHECK_INT_EQ((int)original.Data1,    (int)decoded->Data1);
	CHECK_INT_EQ((int)original.Data2,    (int)decoded->Data2);
	CHECK_INT_EQ((int)original.Data3,    (int)decoded->Data3);
	CHECK_INT_EQ((int)original.Data4[0], (int)decoded->Data4[0]);
	CHECK_INT_EQ((int)original.Data4[7], (int)decoded->Data4[7]);
}

/* ================================================================== */
/* TimestampToHumanReadable tests                                      */
/* ================================================================== */

TEST(timestamp_returns_non_null)
{
	char *s = TimestampToHumanReadable(20250115120000ULL);
	CHECK(s != NULL);
}

TEST(timestamp_zero_gives_zero_date)
{
	char *s = TimestampToHumanReadable(0ULL);
	CHECK(s != NULL);
	CHECK_STR_EQ("0000.00.00 00:00:00 (UTC)", s);
}

TEST(timestamp_basic_date)
{
	char *s = TimestampToHumanReadable(20250115120000ULL);
	CHECK(s != NULL);
	CHECK_STR_EQ("2025.01.15 12:00:00 (UTC)", s);
}

TEST(timestamp_result_contains_utc)
{
	char *s = TimestampToHumanReadable(20230630235959ULL);
	CHECK(s != NULL);
	CHECK(strstr(s, "(UTC)") != NULL);
}

TEST(timestamp_format_separators)
{
	char *s = TimestampToHumanReadable(20240630235959ULL);
	CHECK(s != NULL);
	/* Date uses dots; time uses colons */
	CHECK(s[4] == '.' && s[7] == '.');
	CHECK(s[13] == ':' && s[16] == ':');
}

TEST(timestamp_length_correct)
{
	/* "YYYY.MM.DD HH:MM:SS (UTC)" = 25 characters */
	char *s = TimestampToHumanReadable(20250101000000ULL);
	CHECK(s != NULL);
	CHECK_INT_EQ(25, (int)strlen(s));
}

TEST(timestamp_max_values)
{
	char *s = TimestampToHumanReadable(99991231235959ULL);
	CHECK(s != NULL);
	CHECK_STR_EQ("9999.12.31 23:59:59 (UTC)", s);
}

TEST(timestamp_different_calls_give_different_results)
{
	char buf1[32];
	char *s1 = TimestampToHumanReadable(20230101000000ULL);
	CHECK(s1 != NULL);
	strncpy(buf1, s1, sizeof(buf1) - 1);
	buf1[sizeof(buf1) - 1] = '\0';

	char *s2 = TimestampToHumanReadable(20241225180000ULL);
	CHECK(s2 != NULL);
	CHECK(strcmp(buf1, s2) != 0);
}

/* ================================================================== */
/* main                                                                */
/* ================================================================== */

int main(void)
{
	printf("=== stdio common (GuidToString / StringToGuid / TimestampToHumanReadable) ===\n");

	printf("\n  GuidToString\n");
	RUN(guid_to_string_null_returns_null);
	RUN(guid_to_string_zero_guid_decorated);
	RUN(guid_to_string_known_guid);
	RUN(guid_to_string_undecorated_format);
	RUN(guid_to_string_upper_case);

	printf("\n  StringToGuid\n");
	RUN(string_to_guid_null_returns_null);
	RUN(string_to_guid_bad_format_returns_null);
	RUN(string_to_guid_parses_known_guid);
	RUN(string_to_guid_round_trip);

	printf("\n  TimestampToHumanReadable\n");
	RUN(timestamp_returns_non_null);
	RUN(timestamp_zero_gives_zero_date);
	RUN(timestamp_basic_date);
	RUN(timestamp_result_contains_utc);
	RUN(timestamp_format_separators);
	RUN(timestamp_length_correct);
	RUN(timestamp_max_values);
	RUN(timestamp_different_calls_give_different_results);

	TEST_RESULTS();
}
