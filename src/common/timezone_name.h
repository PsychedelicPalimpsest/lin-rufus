/*
 * Rufus: The Reliable USB Formatting Utility
 * Cross-platform local timezone name — common interface for obtaining
 * the current system timezone as a Windows timezone name string, as
 * used in autounattend.xml.
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
 * GetLocalTimezone() — return the current system timezone as a Windows
 * timezone name string (e.g. "Eastern Standard Time", "UTC").
 *
 * On Linux  : resolves IANA → Windows name via the IANA_to_TZ mapping
 *             (reads $TZ, /etc/timezone, or /etc/localtime symlink).
 * On Windows: reads the StandardName from GetTimeZoneInformation().
 *
 * Returns a pointer to a static or caller-owned string; never NULL.
 * Falls back to "UTC" if the timezone cannot be determined.
 */
const char *GetLocalTimezone(void);

#ifdef __cplusplus
}
#endif
