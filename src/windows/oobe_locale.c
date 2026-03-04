/*
 * Rufus: The Reliable USB Formatting Utility
 * Windows OOBE locale detection — fills OobeLocale from Windows APIs
 * and the registry.
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <windows.h>
#include <string.h>

#include "registry.h"
#include "../common/oobe_locale.h"

/* Convert a Windows LCID to a BCP47 locale name (e.g. "en-US").
 * Returns a pointer to a static buffer; falls back to "en-US" on error. */
static const char *_lcid_to_bcp47(DWORD lang_id)
{
	static char buf[LOCALE_NAME_MAX_LENGTH];
	wchar_t wbuf[LOCALE_NAME_MAX_LENGTH];
	if (LCIDToLocaleName(lang_id, wbuf, LOCALE_NAME_MAX_LENGTH, 0) > 0)
		WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, sizeof(buf), NULL, NULL);
	else
		strcpy(buf, "en-US");
	return buf;
}

/*
 * GetOobeLocale() — fill @out with OOBE locale information from the
 * running Windows system.
 *
 * - ui_locale      : LCID → BCP47 of GetUserDefaultUILanguage()
 * - system_locale  : LCID → BCP47 of GetSystemDefaultLCID()
 * - user_locale    : LCID → BCP47 of GetUserDefaultLCID()
 * - input_locale   : HKCU\Keyboard Layout\Preload\1
 * - ui_fallback    : HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language\InstallLanguageFallback
 */
void GetOobeLocale(OobeLocale *out)
{
	const char *s;

	memset(out, 0, sizeof(*out));

	strncpy(out->ui_locale, _lcid_to_bcp47(GetUserDefaultUILanguage()),
	        sizeof(out->ui_locale) - 1);
	strncpy(out->system_locale, _lcid_to_bcp47(GetSystemDefaultLCID()),
	        sizeof(out->system_locale) - 1);
	strncpy(out->user_locale, _lcid_to_bcp47(GetUserDefaultLCID()),
	        sizeof(out->user_locale) - 1);

	s = ReadRegistryKeyStr(REGKEY_HKCU, "Keyboard Layout\\Preload\\1");
	strncpy(out->input_locale, s ? s : "", sizeof(out->input_locale) - 1);

	s = ReadRegistryKeyStr(REGKEY_HKLM,
		"SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\InstallLanguageFallback");
	strncpy(out->ui_fallback, s ? s : "", sizeof(out->ui_fallback) - 1);
}
