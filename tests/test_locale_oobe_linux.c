/*
 * Rufus: The Reliable USB Formatting Utility
 * Unit tests for Linux OOBE locale detection (locale_oobe.c)
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "framework.h"
#include "locale_oobe.h"

/* ================================================================
 * lang_to_bcp47 tests
 * ================================================================ */

TEST(lang_to_bcp47_null_returns_en_US)
{
	const char *r = lang_to_bcp47(NULL);
	CHECK(r != NULL);
	CHECK_STR_EQ(r, "en-US");
}

TEST(lang_to_bcp47_empty_returns_en_US)
{
	const char *r = lang_to_bcp47("");
	CHECK(r != NULL);
	CHECK_STR_EQ(r, "en-US");
}

TEST(lang_to_bcp47_C_returns_en_US)
{
	const char *r = lang_to_bcp47("C");
	CHECK_STR_EQ(r, "en-US");
}

TEST(lang_to_bcp47_POSIX_returns_en_US)
{
	const char *r = lang_to_bcp47("POSIX");
	CHECK_STR_EQ(r, "en-US");
}

TEST(lang_to_bcp47_en_US_UTF8)
{
	const char *r = lang_to_bcp47("en_US.UTF-8");
	CHECK_STR_EQ(r, "en-US");
}

TEST(lang_to_bcp47_fr_FR_UTF8)
{
	const char *r = lang_to_bcp47("fr_FR.UTF-8");
	CHECK_STR_EQ(r, "fr-FR");
}

TEST(lang_to_bcp47_de_DE_euro)
{
	const char *r = lang_to_bcp47("de_DE@euro");
	CHECK_STR_EQ(r, "de-DE");
}

TEST(lang_to_bcp47_zh_CN_UTF8)
{
	const char *r = lang_to_bcp47("zh_CN.UTF-8");
	CHECK_STR_EQ(r, "zh-CN");
}

TEST(lang_to_bcp47_pt_BR_UTF8)
{
	const char *r = lang_to_bcp47("pt_BR.UTF-8");
	CHECK_STR_EQ(r, "pt-BR");
}

TEST(lang_to_bcp47_en_GB)
{
	const char *r = lang_to_bcp47("en_GB");
	CHECK_STR_EQ(r, "en-GB");
}

TEST(lang_to_bcp47_bare_en_defaults_en_US)
{
	const char *r = lang_to_bcp47("en");
	CHECK_STR_EQ(r, "en-US");
}

TEST(lang_to_bcp47_bare_fr_defaults_fr_FR)
{
	const char *r = lang_to_bcp47("fr");
	CHECK_STR_EQ(r, "fr-FR");
}

TEST(lang_to_bcp47_bare_de_defaults_de_DE)
{
	const char *r = lang_to_bcp47("de");
	CHECK_STR_EQ(r, "de-DE");
}

TEST(lang_to_bcp47_bare_ja_defaults_ja_JP)
{
	const char *r = lang_to_bcp47("ja");
	CHECK_STR_EQ(r, "ja-JP");
}

TEST(lang_to_bcp47_strips_encoding_with_at_modifier)
{
	/* "de_CH@euro" should strip "@euro" and give "de-CH" */
	const char *r = lang_to_bcp47("de_CH@euro");
	CHECK_STR_EQ(r, "de-CH");
}

/* ================================================================
 * GetLinuxOobeLocale tests
 * ================================================================ */

TEST(get_linux_oobe_locale_not_null_fields)
{
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("en_US.UTF-8");
	locale_oobe_set_keyboard_injection("us");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_keyboard_injection(NULL);

	CHECK(loc.ui_locale[0]     != '\0');
	CHECK(loc.system_locale[0] != '\0');
	CHECK(loc.user_locale[0]   != '\0');
	CHECK(loc.input_locale[0]  != '\0');
	CHECK(loc.ui_fallback[0]   != '\0');
}

TEST(get_linux_oobe_locale_en_US_keyboard_us)
{
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("en_US.UTF-8");
	locale_oobe_set_keyboard_injection("us");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_keyboard_injection(NULL);

	CHECK_STR_EQ(loc.ui_locale,     "en-US");
	CHECK_STR_EQ(loc.system_locale, "en-US");
	CHECK_STR_EQ(loc.user_locale,   "en-US");
	CHECK_STR_EQ(loc.input_locale,  "0409:00000409");
	CHECK_STR_EQ(loc.ui_fallback,   "en-US");
}

TEST(get_linux_oobe_locale_fr_FR_keyboard_fr)
{
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("fr_FR.UTF-8");
	locale_oobe_set_keyboard_injection("fr");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_keyboard_injection(NULL);

	CHECK_STR_EQ(loc.ui_locale,    "fr-FR");
	CHECK_STR_EQ(loc.input_locale, "040c:0000040c");
}

TEST(get_linux_oobe_locale_de_DE_keyboard_de)
{
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("de_DE.UTF-8");
	locale_oobe_set_keyboard_injection("de");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_keyboard_injection(NULL);

	CHECK_STR_EQ(loc.ui_locale,    "de-DE");
	CHECK_STR_EQ(loc.input_locale, "0407:00000407");
}

TEST(get_linux_oobe_locale_fallback_ui_always_en_US)
{
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("fr_FR.UTF-8");
	locale_oobe_set_keyboard_injection("fr");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_keyboard_injection(NULL);

	CHECK_STR_EQ(loc.ui_fallback, "en-US");
}

TEST(get_linux_oobe_locale_unknown_kb_falls_back)
{
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("en_US.UTF-8");
	locale_oobe_set_keyboard_injection("xyzzy_unknown");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_keyboard_injection(NULL);

	/* Unknown keyboard → should fall back (to US or locale-derived) */
	CHECK(loc.input_locale[0] != '\0');
}

TEST(get_linux_oobe_locale_comma_separated_keyboard_uses_first)
{
	/* "us,de" → should detect "us" layout → "0409:00000409" */
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("en_US.UTF-8");
	locale_oobe_set_keyboard_injection("us,de");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_keyboard_injection(NULL);

	CHECK_STR_EQ(loc.input_locale, "0409:00000409");
}

TEST(get_linux_oobe_locale_null_safe)
{
	/* Should not crash */
	GetLinuxOobeLocale(NULL);
	CHECK(1); /* just verify no crash */
}

TEST(get_linux_oobe_locale_C_lang_defaults_to_en_US)
{
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("C");
	locale_oobe_set_keyboard_injection("us");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_keyboard_injection(NULL);

	CHECK_STR_EQ(loc.ui_locale, "en-US");
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
	printf("=== lang_to_bcp47 tests ===\n");
	RUN(lang_to_bcp47_null_returns_en_US);
	RUN(lang_to_bcp47_empty_returns_en_US);
	RUN(lang_to_bcp47_C_returns_en_US);
	RUN(lang_to_bcp47_POSIX_returns_en_US);
	RUN(lang_to_bcp47_en_US_UTF8);
	RUN(lang_to_bcp47_fr_FR_UTF8);
	RUN(lang_to_bcp47_de_DE_euro);
	RUN(lang_to_bcp47_zh_CN_UTF8);
	RUN(lang_to_bcp47_pt_BR_UTF8);
	RUN(lang_to_bcp47_en_GB);
	RUN(lang_to_bcp47_bare_en_defaults_en_US);
	RUN(lang_to_bcp47_bare_fr_defaults_fr_FR);
	RUN(lang_to_bcp47_bare_de_defaults_de_DE);
	RUN(lang_to_bcp47_bare_ja_defaults_ja_JP);
	RUN(lang_to_bcp47_strips_encoding_with_at_modifier);

	printf("\n=== GetLinuxOobeLocale tests ===\n");
	RUN(get_linux_oobe_locale_not_null_fields);
	RUN(get_linux_oobe_locale_en_US_keyboard_us);
	RUN(get_linux_oobe_locale_fr_FR_keyboard_fr);
	RUN(get_linux_oobe_locale_de_DE_keyboard_de);
	RUN(get_linux_oobe_locale_fallback_ui_always_en_US);
	RUN(get_linux_oobe_locale_unknown_kb_falls_back);
	RUN(get_linux_oobe_locale_comma_separated_keyboard_uses_first);
	RUN(get_linux_oobe_locale_null_safe);
	RUN(get_linux_oobe_locale_C_lang_defaults_to_en_US);

	TEST_RESULTS();
}

#endif /* __linux__ */
