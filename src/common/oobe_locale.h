/*
 * Rufus: The Reliable USB Formatting Utility
 * Cross-platform OOBE locale — common interface for
 * Microsoft-Windows-International-Core locale strings used in
 * autounattend.xml OOBE sections.
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
 * OobeLocale — locale strings for the Microsoft-Windows-International-Core
 * component in an autounattend.xml OOBE section.
 *
 * On Linux  : filled by reading $LANG and the XKB keyboard layout.
 * On Windows: filled by reading Windows locale APIs and the registry.
 */
typedef struct {
	char ui_locale[32];     /* e.g. "en-US"          */
	char system_locale[32]; /* e.g. "en-US"          */
	char user_locale[32];   /* e.g. "en-US"          */
	char input_locale[64];  /* e.g. "0409:00000409"  */
	char ui_fallback[32];   /* e.g. "en-US"          */
} OobeLocale;

/*
 * GetOobeLocale() — fill @out with OOBE locale information derived from
 * the running system.
 *
 * Linux  : reads $LANG / XKB keyboard layout (via locale_oobe.c).
 * Windows: reads GetUserDefaultUILanguage / GetSystemDefaultLCID /
 *          GetUserDefaultLCID and the registry "Keyboard Layout\Preload\1".
 *
 * Never returns NULL; fields that cannot be determined are set to "".
 */
void GetOobeLocale(OobeLocale *out);

#ifdef __cplusplus
}
#endif
