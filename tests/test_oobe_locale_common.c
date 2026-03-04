/*
 * Rufus: The Reliable USB Formatting Utility
 * Tests for GetOobeLocale() — cross-platform (Linux native + Windows/Wine).
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
#include "registry.h"
#include "../common/oobe_locale.h"
#else
#include "locale_oobe.h"  /* includes ../common/oobe_locale.h */
#endif

/* ================================================================
 * GetOobeLocale() tests (cross-platform)
 * ================================================================ */

/* All fields must be null-terminated and within their declared sizes. */
TEST(oobe_locale_fields_fit_in_struct)
{
	OobeLocale loc = { 0 };
	GetOobeLocale(&loc);

	CHECK(strnlen(loc.ui_locale,     sizeof(loc.ui_locale))     < sizeof(loc.ui_locale));
	CHECK(strnlen(loc.system_locale, sizeof(loc.system_locale)) < sizeof(loc.system_locale));
	CHECK(strnlen(loc.user_locale,   sizeof(loc.user_locale))   < sizeof(loc.user_locale));
	CHECK(strnlen(loc.input_locale,  sizeof(loc.input_locale))  < sizeof(loc.input_locale));
	CHECK(strnlen(loc.ui_fallback,   sizeof(loc.ui_fallback))   < sizeof(loc.ui_fallback));
}

/* ui_locale must be a valid BCP47 tag — non-empty and contains '-'. */
TEST(oobe_locale_ui_locale_looks_like_bcp47)
{
	OobeLocale loc = { 0 };
	GetOobeLocale(&loc);
	CHECK(loc.ui_locale[0] != '\0');
	CHECK(strchr(loc.ui_locale, '-') != NULL);
}

/* system_locale must be a valid BCP47 tag. */
TEST(oobe_locale_system_locale_looks_like_bcp47)
{
	OobeLocale loc = { 0 };
	GetOobeLocale(&loc);
	CHECK(loc.system_locale[0] != '\0');
	CHECK(strchr(loc.system_locale, '-') != NULL);
}

/* user_locale must be a valid BCP47 tag. */
TEST(oobe_locale_user_locale_looks_like_bcp47)
{
	OobeLocale loc = { 0 };
	GetOobeLocale(&loc);
	CHECK(loc.user_locale[0] != '\0');
	CHECK(strchr(loc.user_locale, '-') != NULL);
}

/* Calling GetOobeLocale() twice must return identical results. */
TEST(oobe_locale_deterministic)
{
	OobeLocale a = { 0 }, b = { 0 };
	GetOobeLocale(&a);
	GetOobeLocale(&b);
	CHECK_STR_EQ(a.ui_locale,     b.ui_locale);
	CHECK_STR_EQ(a.system_locale, b.system_locale);
	CHECK_STR_EQ(a.user_locale,   b.user_locale);
	CHECK_STR_EQ(a.input_locale,  b.input_locale);
	CHECK_STR_EQ(a.ui_fallback,   b.ui_fallback);
}

int main(void)
{
	printf("=== GetOobeLocale() cross-platform tests ===\n");
	RUN(oobe_locale_fields_fit_in_struct);
	RUN(oobe_locale_ui_locale_looks_like_bcp47);
	RUN(oobe_locale_system_locale_looks_like_bcp47);
	RUN(oobe_locale_user_locale_looks_like_bcp47);
	RUN(oobe_locale_deterministic);
	TEST_RESULTS();
}
