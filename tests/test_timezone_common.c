/*
 * Rufus: The Reliable USB Formatting Utility
 * Tests for GetLocalTimezone() — cross-platform (Linux native + Windows/Wine).
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include "framework.h"

#ifdef _WIN32
#include "../common/timezone_name.h"
#else
#include "timezone.h"
#include "../src/common/timezone_name.h"
#endif

/* ================================================================
 * GetLocalTimezone() tests (cross-platform)
 * ================================================================ */

/* Must return a non-NULL, non-empty string. */
TEST(local_timezone_not_empty)
{
	const char *tz = GetLocalTimezone();
	CHECK(tz != NULL);
	CHECK(tz[0] != '\0');
}

/* Result must fit within 128 chars (standard Windows tz name max). */
TEST(local_timezone_reasonable_length)
{
	const char *tz = GetLocalTimezone();
	CHECK(tz != NULL);
	CHECK(strlen(tz) < 128);
}

/* Must be deterministic across two calls. */
TEST(local_timezone_deterministic)
{
	const char *a = GetLocalTimezone();
	const char *b = GetLocalTimezone();
	CHECK(a != NULL && b != NULL);
	CHECK_STR_EQ(a, b);
}

int main(void)
{
	printf("=== GetLocalTimezone() cross-platform tests ===\n");
	RUN(local_timezone_not_empty);
	RUN(local_timezone_reasonable_length);
	RUN(local_timezone_deterministic);
	TEST_RESULTS();
}
