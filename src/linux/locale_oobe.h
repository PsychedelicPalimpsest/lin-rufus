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

/* Pull in the cross-platform struct and GetOobeLocale() declaration. */
#include "../common/oobe_locale.h"

/* LinuxOobeLocale is an alias for OobeLocale for backward compatibility. */
typedef OobeLocale LinuxOobeLocale;

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

/* Override the path to /etc/default/keyboard (for testing file-based
 * keyboard layout detection). Pass NULL to revert to default. */
void locale_oobe_set_etc_default_keyboard_path(const char *path);

/* Override the path to /etc/vconsole.conf (for testing Fedora/RHEL/Arch
 * keyboard layout detection via KEYMAP= or XKBLAYOUT=). Pass NULL to revert. */
void locale_oobe_set_vconsole_path(const char *path);
#endif

#ifdef __cplusplus
}
#endif
