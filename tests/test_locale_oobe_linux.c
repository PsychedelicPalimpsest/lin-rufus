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
#include <unistd.h>

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
 * /etc/default/keyboard file-based detection tests
 * ================================================================ */

/* Helper: write a temp /etc/default/keyboard-style file */
static char *write_keyboard_file(const char *content)
{
	static char path[128];
	snprintf(path, sizeof(path), "/tmp/test_locale_oobe_keyboard.XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) return NULL;
	write(fd, content, strlen(content));
	close(fd);
	return path;
}

TEST(etc_default_keyboard_plain_layout)
{
	char *p = write_keyboard_file("XKBLAYOUT=fr\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("fr_FR.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(p);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	unlink(p);
	CHECK_MSG(strstr(loc.input_locale, "040c") != NULL || strstr(loc.input_locale, "040C") != NULL,
	          "etc/default/keyboard fr → French input locale (040c)");
}

TEST(etc_default_keyboard_quoted_layout)
{
	char *p = write_keyboard_file("XKBLAYOUT=\"de\"\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("de_DE.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(p);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	unlink(p);
	CHECK_MSG(strstr(loc.input_locale, "0407") != NULL,
	          "etc/default/keyboard \"de\" → German input locale (0407)");
}

TEST(etc_default_keyboard_comma_layout_uses_first)
{
	char *p = write_keyboard_file("XKBLAYOUT=us,de\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("en_US.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(p);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	unlink(p);
	CHECK_MSG(strstr(loc.input_locale, "0409") != NULL,
	          "etc/default/keyboard us,de → US input locale (0409) first");
}

TEST(etc_default_keyboard_missing_file_fallback)
{
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("en_US.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path("/tmp/nonexistent_keyboard_file_XXXXXX");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	CHECK_MSG(loc.input_locale[0] != '\0',
	          "missing /etc/default/keyboard must still produce a fallback locale");
}

TEST(etc_default_keyboard_with_comment_lines)
{
	char *p = write_keyboard_file(
		"# Generated by debconf\n"
		"XKBMODEL=\"pc105\"\n"
		"XKBLAYOUT=es\n"
		"XKBVARIANT=\"\"\n"
		"XKBOPTIONS=\"\"\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("es_ES.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(p);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	unlink(p);
	CHECK_MSG(strstr(loc.input_locale, "0c0a") != NULL || strstr(loc.input_locale, "0C0A") != NULL,
	          "etc/default/keyboard with comment lines: es → Spanish locale (0c0a)");
}

TEST(etc_default_keyboard_no_xkblayout_falls_back_to_lang)
{
	/* File exists but has no XKBLAYOUT line → fall through to lang-based detection */
	char *p = write_keyboard_file(
		"# No XKBLAYOUT here\n"
		"XKBMODEL=\"pc105\"\n"
		"XKBOPTIONS=\"\"\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("de_DE.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(p);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	unlink(p);
	/* Should still produce a non-empty locale (fallback via LANG) */
	CHECK_MSG(loc.input_locale[0] != '\0',
	          "no XKBLAYOUT in file → fallback to LANG-based detection");
	CHECK_MSG(strstr(loc.system_locale, "de-DE") != NULL,
	          "no XKBLAYOUT in file → system_locale from LANG");
}

/* ================================================================
 * /etc/vconsole.conf file-based detection tests (Fedora/RHEL/Arch parity)
 * ================================================================ */

/* Helper: write a temp /etc/vconsole.conf-style file */
static char *write_vconsole_file(const char *content)
{
	static char path[128];
	snprintf(path, sizeof(path), "/tmp/test_locale_oobe_vconsole.XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) return NULL;
	write(fd, content, strlen(content));
	close(fd);
	return path;
}

TEST(vconsole_keymap_sets_input_locale_de)
{
	/* Fedora/RHEL: KEYMAP=de in /etc/vconsole.conf → German input locale */
	char *p = write_vconsole_file("KEYMAP=\"de\"\nFONT=eurlatgr\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("de_DE.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path("/nonexistent/keyboard");
	locale_oobe_set_vconsole_path(p);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	locale_oobe_set_vconsole_path(NULL);
	unlink(p);
	/* German input locale = 0407:00000407 */
	CHECK_MSG(strstr(loc.input_locale, "0407") != NULL,
	          "vconsole KEYMAP=de -> German input locale (0407)");
}

TEST(vconsole_xkblayout_sets_input_locale_fr)
{
	/* Arch Linux: XKBLAYOUT=fr in /etc/vconsole.conf */
	char *p = write_vconsole_file("XKBLAYOUT=fr\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("fr_FR.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path("/nonexistent/keyboard");
	locale_oobe_set_vconsole_path(p);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	locale_oobe_set_vconsole_path(NULL);
	unlink(p);
	/* French input locale = 040c:0000040c */
	CHECK_MSG(strstr(loc.input_locale, "040c") != NULL || strstr(loc.input_locale, "040C") != NULL,
	          "vconsole XKBLAYOUT=fr -> French input locale (040c)");
}

TEST(etc_default_keyboard_takes_priority_over_vconsole_oobe)
{
	/* /etc/default/keyboard (fr) should win over /etc/vconsole.conf (de) */
	char *kb = write_keyboard_file("XKBLAYOUT=fr\n");
	char *vc = write_vconsole_file("KEYMAP=de\n");
	if (!kb || !vc) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("fr_FR.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(kb);
	locale_oobe_set_vconsole_path(vc);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	locale_oobe_set_vconsole_path(NULL);
	unlink(kb);
	unlink(vc);
	/* Should use French (040c), not German (0407) */
	CHECK_MSG(strstr(loc.input_locale, "040c") != NULL || strstr(loc.input_locale, "040C") != NULL,
	          "etc/default/keyboard (fr) takes priority over vconsole (de)");
}

TEST(vconsole_keymap_with_variant_suffix_stripped_oobe)
{
	/* KEYMAP=de-latin1 -> base layout "de" -> German input locale */
	char *p = write_vconsole_file("KEYMAP=de-latin1\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("de_DE.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path("/nonexistent/keyboard");
	locale_oobe_set_vconsole_path(p);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	locale_oobe_set_vconsole_path(NULL);
	unlink(p);
	CHECK_MSG(strstr(loc.input_locale, "0407") != NULL,
	          "vconsole KEYMAP=de-latin1 -> German input locale (0407) after stripping suffix");
}

/* ================================================================
 * Extended kb_map coverage tests — common layouts missing from
 * the original table (parity with xkb_dos_table in dos_locale.c)
 * ================================================================ */

/* Helper: get input_locale for a given XKB layout injection */
static void get_input_locale_for_xkb(const char *xkb, char *out, size_t outsz)
{
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_keyboard_injection(xkb);
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_keyboard_injection(NULL);
	strncpy(out, loc.input_locale, outsz - 1);
	out[outsz - 1] = '\0';
}

TEST(kb_map_estonian_ee_maps_to_0425)
{
	char il[64];
	get_input_locale_for_xkb("ee", il, sizeof(il));
	CHECK_MSG(strstr(il, "0425") != NULL,
	          "Estonian (ee) should map to input locale 0425");
}

TEST(kb_map_lithuanian_lt_maps_to_0427)
{
	char il[64];
	get_input_locale_for_xkb("lt", il, sizeof(il));
	CHECK_MSG(strstr(il, "0427") != NULL,
	          "Lithuanian (lt) should map to input locale 0427");
}

TEST(kb_map_latvian_lv_maps_to_0426)
{
	char il[64];
	get_input_locale_for_xkb("lv", il, sizeof(il));
	CHECK_MSG(strstr(il, "0426") != NULL,
	          "Latvian (lv) should map to input locale 0426");
}

TEST(kb_map_slovenian_si_maps_to_0424)
{
	char il[64];
	get_input_locale_for_xkb("si", il, sizeof(il));
	CHECK_MSG(strstr(il, "0424") != NULL,
	          "Slovenian (si) should map to input locale 0424");
}

TEST(kb_map_albanian_al_maps_to_041c)
{
	char il[64];
	get_input_locale_for_xkb("al", il, sizeof(il));
	CHECK_MSG(strstr(il, "041c") != NULL || strstr(il, "041C") != NULL,
	          "Albanian (al) should map to input locale 041c");
}

TEST(kb_map_icelandic_is_maps_to_040f)
{
	char il[64];
	get_input_locale_for_xkb("is", il, sizeof(il));
	CHECK_MSG(strstr(il, "040f") != NULL || strstr(il, "040F") != NULL,
	          "Icelandic (is) should map to input locale 040f");
}

TEST(kb_map_latin_american_la_maps_to_080a)
{
	char il[64];
	get_input_locale_for_xkb("la", il, sizeof(il));
	CHECK_MSG(strstr(il, "080a") != NULL,
	          "Latin American (la) should map to input locale 080a");
}

TEST(kb_map_macedonian_mk_maps_to_042f)
{
	char il[64];
	get_input_locale_for_xkb("mk", il, sizeof(il));
	CHECK_MSG(strstr(il, "042f") != NULL || strstr(il, "042F") != NULL,
	          "Macedonian (mk) should map to input locale 042f");
}

TEST(kb_map_serbian_cyrillic_sr_maps_to_0c1a)
{
	char il[64];
	get_input_locale_for_xkb("sr", il, sizeof(il));
	CHECK_MSG(strstr(il, "0c1a") != NULL || strstr(il, "0C1A") != NULL,
	          "Serbian Cyrillic (sr) should map to input locale 0c1a");
}

TEST(kb_map_vietnamese_vn_maps_to_042a)
{
	char il[64];
	get_input_locale_for_xkb("vn", il, sizeof(il));
	CHECK_MSG(strstr(il, "042a") != NULL || strstr(il, "042A") != NULL,
	          "Vietnamese (vn) should map to input locale 042a");
}

/* ================================================================
 * XKB variant support tests — XKBVARIANT= in /etc/default/keyboard
 * ================================================================ */

TEST(swiss_french_variant_gives_fr_ch_locale)
{
	/* Swiss layout with French variant -> fr-CH / 100c input locale */
	char *p = write_keyboard_file("XKBLAYOUT=\"ch\"\nXKBVARIANT=\"fr\"\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("fr_CH.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(p);
	locale_oobe_set_vconsole_path("/nonexistent/vconsole.conf");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	locale_oobe_set_vconsole_path(NULL);
	unlink(p);
	CHECK_MSG(strstr(loc.input_locale, "100c") != NULL || strstr(loc.input_locale, "100C") != NULL,
	          "Swiss French (ch + fr variant) should give fr-CH input locale (100c)");
}

TEST(swiss_german_no_variant_gives_de_ch_locale)
{
	/* Swiss layout with no variant -> de-CH / 0807 input locale */
	char *p = write_keyboard_file("XKBLAYOUT=\"ch\"\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("de_CH.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(p);
	locale_oobe_set_vconsole_path("/nonexistent/vconsole.conf");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	locale_oobe_set_vconsole_path(NULL);
	unlink(p);
	CHECK_MSG(strstr(loc.input_locale, "0807") != NULL,
	          "Swiss German (ch, no variant) should give de-CH input locale (0807)");
}

TEST(serbian_latin_variant_gives_0x081a_locale)
{
	/* Serbian layout with Latin variant -> Serbian Latin / 081a input locale */
	char *p = write_keyboard_file("XKBLAYOUT=\"rs\"\nXKBVARIANT=\"latin\"\n");
	if (!p) { CHECK(0); return; }
	LinuxOobeLocale loc = { 0 };
	locale_oobe_set_lang_injection("sr_RS.UTF-8");
	locale_oobe_set_keyboard_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(p);
	locale_oobe_set_vconsole_path("/nonexistent/vconsole.conf");
	GetLinuxOobeLocale(&loc);
	locale_oobe_set_lang_injection(NULL);
	locale_oobe_set_etc_default_keyboard_path(NULL);
	locale_oobe_set_vconsole_path(NULL);
	unlink(p);
	CHECK_MSG(strstr(loc.input_locale, "081a") != NULL || strstr(loc.input_locale, "081A") != NULL,
	          "Serbian Latin (rs + latin variant) should give Serbian Latin locale (081a)");
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

	printf("\n=== /etc/default/keyboard file detection tests ===\n");
	RUN(etc_default_keyboard_plain_layout);
	RUN(etc_default_keyboard_quoted_layout);
	RUN(etc_default_keyboard_comma_layout_uses_first);
	RUN(etc_default_keyboard_missing_file_fallback);
	RUN(etc_default_keyboard_with_comment_lines);
	RUN(etc_default_keyboard_no_xkblayout_falls_back_to_lang);

	printf("\n=== /etc/vconsole.conf detection tests ===\n");
	RUN(vconsole_keymap_sets_input_locale_de);
	RUN(vconsole_xkblayout_sets_input_locale_fr);
	RUN(etc_default_keyboard_takes_priority_over_vconsole_oobe);
	RUN(vconsole_keymap_with_variant_suffix_stripped_oobe);

	printf("\n=== Extended kb_map coverage tests ===\n");
	RUN(kb_map_estonian_ee_maps_to_0425);
	RUN(kb_map_lithuanian_lt_maps_to_0427);
	RUN(kb_map_latvian_lv_maps_to_0426);
	RUN(kb_map_slovenian_si_maps_to_0424);
	RUN(kb_map_albanian_al_maps_to_041c);
	RUN(kb_map_icelandic_is_maps_to_040f);
	RUN(kb_map_latin_american_la_maps_to_080a);
	RUN(kb_map_macedonian_mk_maps_to_042f);
	RUN(kb_map_serbian_cyrillic_sr_maps_to_0c1a);
	RUN(kb_map_vietnamese_vn_maps_to_042a);

	printf("\n=== XKB variant support tests ===\n");
	RUN(swiss_french_variant_gives_fr_ch_locale);
	RUN(swiss_german_no_variant_gives_de_ch_locale);
	RUN(serbian_latin_variant_gives_0x081a_locale);

	TEST_RESULTS();
}

#endif /* __linux__ */
