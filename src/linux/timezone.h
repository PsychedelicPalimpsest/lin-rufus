/*
 * Rufus: The Reliable USB Formatting Utility
 * IANA → Windows timezone name mapping — Linux
 * Copyright © 2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * IanaToWindowsTimezone() — resolve the running system's timezone to its
 * canonical Windows timezone name (as used in autounattend.xml).
 *
 * Resolution order:
 *   1. $TZ environment variable (IANA name, e.g. "America/New_York")
 *   2. /etc/timezone  (Debian/Ubuntu style — contains just the IANA name)
 *   3. /etc/localtime symlink stripped against the zoneinfo root
 *      (e.g. /usr/share/zoneinfo/Europe/Paris → "Europe/Paris")
 *
 * Returns a pointer to a static string with the Windows timezone name.
 * Never returns NULL.  Falls back to "UTC" if the zone cannot be mapped.
 */
const char* IanaToWindowsTimezone(void);

/*
 * Test-injection helpers — only compiled when RUFUS_TEST is defined.
 * Allow tests to supply a fixed IANA name without touching the filesystem.
 */
#ifdef RUFUS_TEST
void timezone_set_tz_injection(const char* iana_name);   /* NULL = disable */
void timezone_set_etc_timezone_path(const char* path);   /* NULL = default  */
void timezone_set_localtime_path(const char* path);      /* NULL = default  */
void timezone_set_zoneinfo_root(const char* path);       /* NULL = default  */
#endif

#ifdef __cplusplus
}
#endif
