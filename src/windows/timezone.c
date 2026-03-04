/*
 * Rufus: The Reliable USB Formatting Utility
 * Windows local timezone detection — returns the current system
 * timezone as a Windows timezone name string.
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <windows.h>
#include <string.h>

#include "../common/timezone_name.h"

/*
 * GetLocalTimezone() — return the current Windows timezone StandardName
 * (e.g. "Eastern Standard Time") as a UTF-8 string.
 * Falls back to "UTC" if GetTimeZoneInformation() fails.
 */
const char *GetLocalTimezone(void)
{
	static char tzname_buf[128];
	TIME_ZONE_INFORMATION tz_info;

	if (GetTimeZoneInformation(&tz_info) == TIME_ZONE_ID_INVALID) {
		return "UTC";
	}

	if (WideCharToMultiByte(CP_UTF8, 0, tz_info.StandardName, -1,
	                        tzname_buf, sizeof(tzname_buf), NULL, NULL) == 0) {
		return "UTC";
	}

	return tzname_buf;
}
