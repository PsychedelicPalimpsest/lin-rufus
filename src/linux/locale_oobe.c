/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux OOBE locale detection — maps LANG / keyboard layout to
 * Windows locale strings for autounattend.xml generation.
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "locale_oobe.h"

/* ── injection state (test-only) ─────────────────────────────────────────── */
#ifdef RUFUS_TEST
static const char *s_lang_injection             = NULL;
static const char *s_keyboard_injection         = NULL;
static const char *s_etc_default_keyboard_path  = NULL;
static const char *s_vconsole_path              = NULL;

void locale_oobe_set_lang_injection(const char *lang)
{
	s_lang_injection = lang;
}

void locale_oobe_set_keyboard_injection(const char *xkb_layout)
{
	s_keyboard_injection = xkb_layout;
}

void locale_oobe_set_etc_default_keyboard_path(const char *path)
{
	s_etc_default_keyboard_path = path;
}

void locale_oobe_set_vconsole_path(const char *path)
{
	s_vconsole_path = path;
}
#endif /* RUFUS_TEST */

/* ── POSIX locale → BCP47 ─────────────────────────────────────────────────
 *
 * Handles:
 *   "en_US.UTF-8"  →  "en-US"
 *   "fr_FR@euro"   →  "fr-FR"
 *   "de_DE"        →  "de-DE"
 *   "zh_CN"        →  "zh-CN"
 *   "C" / "POSIX"  →  "en-US"
 *   NULL or ""     →  "en-US"
 *   bare "en"      →  "en-US"  (common language code → canonical BCP47)
 * ───────────────────────────────────────────────────────────────────────── */

/* Mapping from bare ISO-639-1 language code to canonical BCP47 country tag.
 * Only the most common languages are listed; unlisted codes are passed through
 * unchanged (i.e. "xx" → "xx"). */
typedef struct { const char *lang; const char *bcp47; } LangDefaultEntry;
static const LangDefaultEntry lang_defaults[] = {
	{ "af", "af-ZA" }, { "ar", "ar-SA" }, { "bg", "bg-BG" },
	{ "ca", "ca-ES" }, { "cs", "cs-CZ" }, { "cy", "cy-GB" },
	{ "da", "da-DK" }, { "de", "de-DE" }, { "el", "el-GR" },
	{ "en", "en-US" }, { "es", "es-ES" }, { "et", "et-EE" },
	{ "eu", "eu-ES" }, { "fi", "fi-FI" }, { "fr", "fr-FR" },
	{ "gl", "gl-ES" }, { "he", "he-IL" }, { "hi", "hi-IN" },
	{ "hr", "hr-HR" }, { "hu", "hu-HU" }, { "hy", "hy-AM" },
	{ "id", "id-ID" }, { "is", "is-IS" }, { "it", "it-IT" },
	{ "ja", "ja-JP" }, { "ka", "ka-GE" }, { "kk", "kk-KZ" },
	{ "ko", "ko-KR" }, { "lt", "lt-LT" }, { "lv", "lv-LV" },
	{ "mk", "mk-MK" }, { "ms", "ms-MY" }, { "nb", "nb-NO" },
	{ "nl", "nl-NL" }, { "nn", "nn-NO" }, { "no", "nb-NO" },
	{ "pl", "pl-PL" }, { "pt", "pt-PT" }, { "ro", "ro-RO" },
	{ "ru", "ru-RU" }, { "sk", "sk-SK" }, { "sl", "sl-SI" },
	{ "sq", "sq-AL" }, { "sr", "sr-RS" }, { "sv", "sv-SE" },
	{ "th", "th-TH" }, { "tr", "tr-TR" }, { "uk", "uk-UA" },
	{ "uz", "uz-UZ" }, { "vi", "vi-VN" }, { "zh", "zh-CN" },
};

const char *lang_to_bcp47(const char *posix_locale)
{
	static char buf[32];
	char tmp[64];
	size_t i;

	if (posix_locale == NULL || posix_locale[0] == '\0' ||
	    strcmp(posix_locale, "C") == 0 ||
	    strcmp(posix_locale, "POSIX") == 0)
		return "en-US";

	/* Copy up to the first '.' or '@' (strip encoding and modifier) */
	strncpy(tmp, posix_locale, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';
	for (i = 0; tmp[i]; i++) {
		if (tmp[i] == '.' || tmp[i] == '@') {
			tmp[i] = '\0';
			break;
		}
	}

	/* Replace '_' with '-' to form a BCP47 tag */
	for (i = 0; tmp[i]; i++) {
		if (tmp[i] == '_')
			tmp[i] = '-';
	}

	/* If we have a country code already ("en-US", "fr-FR", etc.), return it */
	if (strchr(tmp, '-') != NULL) {
		strncpy(buf, tmp, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		return buf;
	}

	/* Bare language code — try the defaults table */
	for (i = 0; i < sizeof(lang_defaults) / sizeof(lang_defaults[0]); i++) {
		if (strcmp(tmp, lang_defaults[i].lang) == 0)
			return lang_defaults[i].bcp47;
	}

	/* Unknown bare code — return as-is */
	strncpy(buf, tmp, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
	return buf;
}

/* ── xkb layout → Windows input locale ───────────────────────────────────
 *
 * Windows InputLocale format: "LCID_hex:KLID_hex"
 *   e.g. "0409:00000409"  (en-US keyboard)
 *
 * Only the most common keyboard layouts are mapped.  If the xkb layout is
 * not found in the table, we fall back to deriving it from the locale tag.
 * ───────────────────────────────────────────────────────────────────────── */
typedef struct { const char *xkb; const char *win; } KbEntry;
static const KbEntry kb_map[] = {
	{ "us",   "0409:00000409" },
	{ "gb",   "0809:00000809" },
	{ "de",   "0407:00000407" },
	{ "fr",   "040c:0000040c" },
	{ "es",   "0c0a:0000040a" },
	{ "it",   "0410:00000410" },
	{ "pt",   "0416:00000416" },
	{ "br",   "0416:00000416" },
	{ "ru",   "0419:00000419" },
	{ "pl",   "0415:00000415" },
	{ "nl",   "0413:00000413" },
	{ "be",   "080c:0000080c" },
	{ "ch",   "0807:00000807" },
	{ "at",   "0c07:00000c07" },
	{ "dk",   "0406:00000406" },
	{ "fi",   "040b:0000040b" },
	{ "se",   "041d:0000041d" },
	{ "no",   "0414:00000414" },
	{ "cz",   "0405:00000405" },
	{ "sk",   "041b:0000041b" },
	{ "hu",   "040e:0000040e" },
	{ "ro",   "0418:00000418" },
	{ "hr",   "041a:0000041a" },
	{ "tr",   "041f:0000041f" },
	{ "gr",   "0408:00000408" },
	{ "jp",   "0411:00000411" },
	{ "cn",   "0804:00000804" },
	{ "tw",   "0404:00000404" },
	{ "kr",   "0412:00000412" },
	{ "ua",   "0422:00000422" },
	{ "bg",   "0402:00000402" },
	{ "rs",   "0c1a:00000c1a" },
	{ "il",   "040d:0000040d" },
	{ "ara",  "0401:00000401" },
	{ "in",   "4009:00004009" },
	{ "latam","080a:0000080a" },
	/* Extended entries — parity with xkb_dos_table in dos_locale.c */
	{ "al",   "041c:0000041c" },  /* Albanian */
	{ "am",   "042b:0002042b" },  /* Armenian (Eastern) */
	{ "az",   "042c:0000042c" },  /* Azerbaijani (Latin) */
	{ "ba",   "141a:0000141a" },  /* Bosnian (Latin) */
	{ "by",   "0423:00000423" },  /* Belarusian */
	{ "ee",   "0425:00000425" },  /* Estonian */
	{ "fo",   "0438:00000406" },  /* Faroese (uses Danish keyboard) */
	{ "ge",   "0437:00000437" },  /* Georgian */
	{ "ir",   "0429:00000429" },  /* Persian */
	{ "is",   "040f:0000040f" },  /* Icelandic */
	{ "kk",   "043f:0000043f" },  /* Kazakh */
	{ "ko",   "0412:00000412" },  /* Korean (alternate) */
	{ "ky",   "0440:00000440" },  /* Kyrgyz */
	{ "lt",   "0427:00000427" },  /* Lithuanian */
	{ "lv",   "0426:00000426" },  /* Latvian */
	{ "mk",   "042f:0000042f" },  /* Macedonian */
	{ "mn",   "0450:00000450" },  /* Mongolian */
	{ "mt",   "043a:0000043a" },  /* Maltese */
	{ "ph",   "3409:00000409" },  /* Filipino (uses US keyboard) */
	{ "si",   "0424:00000424" },  /* Slovenian */
	{ "sq",   "041c:0000041c" },  /* Albanian (sq = sq-AL alternate code) */
	{ "sr",   "0c1a:00000c1a" },  /* Serbian (Cyrillic) */
	{ "th",   "041e:0000041e" },  /* Thai */
	{ "tj",   "0428:00000428" },  /* Tajik */
	{ "tm",   "0442:00000442" },  /* Turkmen */
	{ "uz",   "0443:00000443" },  /* Uzbek (Latin) */
	{ "vn",   "042a:0000042a" },  /* Vietnamese */
	{ "yu",   "081a:0000081a" },  /* Yugoslav / Serbian Latin */
	/* XKB variant overrides — "layout:variant" combined keys */
	{ "ch:fr",       "100c:0000100c" },  /* Swiss French (ch + fr variant) */
	{ "ch:fr_mac",   "100c:0000100c" },  /* Swiss French Mac layout */
	{ "rs:latin",    "081a:0000081a" },  /* Serbian Latin (not Cyrillic) */
	{ "rs:latinyz",  "081a:0000081a" },  /* Serbian Latin YZ */
};

/* xkb layouts can be comma-separated (e.g. "us,de"); extract the first one */
static void first_xkb_layout(const char *src, char *out, size_t outsz)
{
	size_t i;
	for (i = 0; i < outsz - 1 && src[i] && src[i] != ','; i++)
		out[i] = src[i];
	out[i] = '\0';
}

/* Try to read the first XKBLAYOUT from /etc/default/keyboard.
 * Also reads XKBVARIANT= from the same file; if non-empty, the result is
 * returned as "layout:variant" (e.g. "ch:fr" for Swiss French). */
static int try_etc_default_keyboard(char *out, size_t outsz)
{
	const char *path = "/etc/default/keyboard";
#ifdef RUFUS_TEST
	if (s_etc_default_keyboard_path)
		path = s_etc_default_keyboard_path;
#endif
	FILE *f = fopen(path, "r");
	if (!f) return 0;

	char layout[32] = {0};
	char variant[32] = {0};
	char line[256];
	while (fgets(line, sizeof(line), f)) {
		if (layout[0] == '\0' && strncmp(line, "XKBLAYOUT=", 10) == 0) {
			char *val = line + 10;
			if (*val == '"') val++;
			size_t n = strcspn(val, "\"\n\r");
			if (n > 0 && n < sizeof(layout)) {
				strncpy(layout, val, n);
				layout[n] = '\0';
			}
			continue;
		}
		if (variant[0] == '\0' && strncmp(line, "XKBVARIANT=", 11) == 0) {
			char *val = line + 11;
			if (*val == '"') val++;
			size_t n = strcspn(val, "\"\n\r");
			if (n > 0 && n < sizeof(variant)) {
				strncpy(variant, val, n);
				variant[n] = '\0';
			}
		}
	}
	fclose(f);

	if (layout[0] == '\0')
		return 0;

	if (variant[0] != '\0')
		snprintf(out, outsz, "%s:%s", layout, variant);
	else {
		strncpy(out, layout, outsz - 1);
		out[outsz - 1] = '\0';
	}
	return 1;
}

/*
 * Try to read a keyboard layout from /etc/vconsole.conf.
 * Checks XKBLAYOUT= first (with XKBVARIANT= for variant), then KEYMAP=.
 * For XKBLAYOUT=, variant is combined as "layout:variant" if present.
 * For KEYMAP=, variant suffixes like "de-latin1" are stripped to "de".
 */
static int try_vconsole(char *out, size_t outsz)
{
	const char *path = "/etc/vconsole.conf";
#ifdef RUFUS_TEST
	if (s_vconsole_path)
		path = s_vconsole_path;
#endif
	FILE *f = fopen(path, "r");
	if (!f) return 0;

	char xkblayout[32] = {0};
	char xkbvariant[32] = {0};
	char keymap[32] = {0};
	char line[256];

	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		while (*p == ' ' || *p == '\t') p++;

		if (xkblayout[0] == '\0' && strncmp(p, "XKBLAYOUT=", 10) == 0) {
			p += 10;
			if (*p == '"' || *p == '\'') p++;
			size_t i = 0;
			/* Don't strip suffix here — we read XKBVARIANT= separately */
			while (*p && *p != '"' && *p != '\'' && *p != '\n' && *p != '\r'
			       && *p != ',' && i < sizeof(xkblayout) - 1) {
				xkblayout[i++] = (char)tolower((unsigned char)*p);
				p++;
			}
			xkblayout[i] = '\0';
			continue;
		}

		if (xkbvariant[0] == '\0' && strncmp(p, "XKBVARIANT=", 11) == 0) {
			p += 11;
			if (*p == '"' || *p == '\'') p++;
			size_t i = 0;
			while (*p && *p != '"' && *p != '\'' && *p != '\n' && *p != '\r'
			       && i < sizeof(xkbvariant) - 1) {
				xkbvariant[i++] = (char)tolower((unsigned char)*p);
				p++;
			}
			xkbvariant[i] = '\0';
			continue;
		}

		if (keymap[0] == '\0' && strncmp(p, "KEYMAP=", 7) == 0) {
			p += 7;
			if (*p == '"' || *p == '\'') p++;
			/* Strip variant suffix ("-" or "_") for KEYMAP= entries */
			size_t i = 0;
			while (*p && *p != '"' && *p != '\'' && *p != '\n' && *p != '\r'
			       && *p != '-' && *p != '_' && *p != ','
			       && i < sizeof(keymap) - 1) {
				keymap[i++] = (char)tolower((unsigned char)*p);
				p++;
			}
			keymap[i] = '\0';
		}
	}
	fclose(f);

	/* Prefer XKBLAYOUT= (+ optional XKBVARIANT=) over KEYMAP= */
	if (xkblayout[0] != '\0') {
		if (xkbvariant[0] != '\0')
			snprintf(out, outsz, "%s:%s", xkblayout, xkbvariant);
		else {
			strncpy(out, xkblayout, outsz - 1);
			out[outsz - 1] = '\0';
		}
		return 1;
	}
	if (keymap[0] != '\0') {
		strncpy(out, keymap, outsz - 1);
		out[outsz - 1] = '\0';
		return 1;
	}
	return 0;
}

/* Map an xkb layout string to a Windows input locale string.
 * Returns a pointer to a static string; never NULL.
 * Accepts "layout:variant" format; first tries the combined key, then falls
 * back to layout-only if no variant match is found. */
static const char *xkb_to_win_input_locale(const char *xkb, const char *bcp47_fallback)
{
	size_t i;
	char layout[64] = { 0 };  /* may hold "layout:variant" */

	if (xkb && xkb[0]) {
		first_xkb_layout(xkb, layout, sizeof(layout));
		/* Try exact match (handles both "xx" and "xx:variant" combined keys) */
		for (i = 0; i < sizeof(kb_map) / sizeof(kb_map[0]); i++) {
			if (strcmp(layout, kb_map[i].xkb) == 0)
				return kb_map[i].win;
		}
		/* If combined "layout:variant" had no match, fall back to layout only */
		if (strchr(layout, ':')) {
			char base[32] = { 0 };
			const char *colon = strchr(layout, ':');
			size_t n = (size_t)(colon - layout);
			if (n >= sizeof(base)) n = sizeof(base) - 1;
			strncpy(base, layout, n);
			base[n] = '\0';
			for (i = 0; i < sizeof(kb_map) / sizeof(kb_map[0]); i++) {
				if (strcmp(base, kb_map[i].xkb) == 0)
					return kb_map[i].win;
			}
		}
	}

	/* Fall back: derive xkb from the locale's country code */
	if (bcp47_fallback && strchr(bcp47_fallback, '-')) {
		const char *country = strchr(bcp47_fallback, '-') + 1;
		/* Lowercase country code as xkb layout guess */
		char cc[8] = { 0 };
		size_t j;
		for (j = 0; j < sizeof(cc) - 1 && country[j]; j++)
			cc[j] = (char)tolower((unsigned char)country[j]);
		for (i = 0; i < sizeof(kb_map) / sizeof(kb_map[0]); i++) {
			if (strcmp(cc, kb_map[i].xkb) == 0)
				return kb_map[i].win;
		}
	}

	/* Last resort: US keyboard */
	return "0409:00000409";
}

/* ── GetLinuxOobeLocale ────────────────────────────────────────────────── */

void GetLinuxOobeLocale(LinuxOobeLocale *out)
{
	if (!out) return;

	/* ── locale ── */
	const char *lang = NULL;
#ifdef RUFUS_TEST
	if (s_lang_injection)
		lang = s_lang_injection;
#endif
	if (!lang)
		lang = getenv("LANG");
	if (!lang)
		lang = getenv("LANGUAGE");

	const char *bcp47 = lang_to_bcp47(lang);
	strncpy(out->ui_locale,     bcp47, sizeof(out->ui_locale)     - 1);
	strncpy(out->system_locale, bcp47, sizeof(out->system_locale) - 1);
	strncpy(out->user_locale,   bcp47, sizeof(out->user_locale)   - 1);

	/* UI fallback — always English for safety */
	strncpy(out->ui_fallback, "en-US", sizeof(out->ui_fallback) - 1);

	/* ── keyboard / input locale ── */
	const char *xkb = NULL;
#ifdef RUFUS_TEST
	if (s_keyboard_injection)
		xkb = s_keyboard_injection;
#endif
	if (!xkb)
		xkb = getenv("XKBLAYOUT");

	char detected_xkb[32] = { 0 };
	if (!xkb || !xkb[0]) {
		/* Try /etc/default/keyboard (Debian/Ubuntu), then /etc/vconsole.conf (Fedora/Arch) */
		if (try_etc_default_keyboard(detected_xkb, sizeof(detected_xkb)))
			xkb = detected_xkb;
		else if (try_vconsole(detected_xkb, sizeof(detected_xkb)))
			xkb = detected_xkb;
	}

	const char *input = xkb_to_win_input_locale(xkb, bcp47);
	strncpy(out->input_locale, input, sizeof(out->input_locale) - 1);

	/* Null-terminate all fields */
	out->ui_locale[sizeof(out->ui_locale)         - 1] = '\0';
	out->system_locale[sizeof(out->system_locale) - 1] = '\0';
	out->user_locale[sizeof(out->user_locale)     - 1] = '\0';
	out->input_locale[sizeof(out->input_locale)   - 1] = '\0';
	out->ui_fallback[sizeof(out->ui_fallback)     - 1] = '\0';
}
