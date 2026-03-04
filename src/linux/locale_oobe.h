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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * LinuxOobeLocale — locale strings for the Microsoft-Windows-International-Core
 * component in an autounattend.xml OOBE section.
 */
typedef struct {
	char ui_locale[32];     /* e.g. "en-US"          */
	char system_locale[32]; /* e.g. "en-US"          */
	char user_locale[32];   /* e.g. "en-US"          */
	char input_locale[64];  /* e.g. "0409:00000409"  */
	char ui_fallback[32];   /* e.g. "en-US"          */
} LinuxOobeLocale;

/*
 * lang_to_bcp47() — convert a POSIX locale string (e.g. "en_US.UTF-8",
 * "fr_FR@euro", "de_DE") to a BCP47 tag (e.g. "en-US", "fr-FR", "de-DE").
 * "C" and "POSIX" map to "en-US".  Returns a pointer to a static buffer.
 * Never returns NULL.
 */
const char *lang_to_bcp47(const char *posix_locale);

/*
 * GetLinuxOobeLocale() — fill @out with locale information derived from the
 * running Linux system.  Uses $LANG (or injection override) for locale tags
 * and keyboard-layout detection for InputLocale.
 */
void GetLinuxOobeLocale(LinuxOobeLocale *out);

/*
 * Test-injection helpers — only compiled when RUFUS_TEST is defined.
 */
#ifdef RUFUS_TEST
/* Override the LANG value used by lang_to_bcp47 / GetLinuxOobeLocale.
 * Pass NULL to revert to the real $LANG environment variable. */
void locale_oobe_set_lang_injection(const char *lang);

/* Override the xkb layout string used for InputLocale detection.
 * Pass NULL to revert to real detection. */
void locale_oobe_set_keyboard_injection(const char *xkb_layout);
#endif

#ifdef __cplusplus
}
#endif
