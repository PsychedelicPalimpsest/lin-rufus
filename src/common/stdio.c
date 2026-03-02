/*
 * Rufus: The Reliable USB Formatting Utility
 * Portable stdio utility implementations (shared between Windows and Linux)
 * Copyright © 2011-2026 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This file contains platform-independent utility functions extracted from
 * windows/stdio.c and linux/stdio.c.  It must not contain any OS-specific
 * API calls.
 *
 * Portable functions provided here:
 *   GuidToString()            — GUID → "{XXXXXXXX-XXXX-…}" string
 *   StringToGuid()            — "{XXXXXXXX-XXXX-…}" string → GUID
 *   TimestampToHumanReadable()— YYYYMMDDHHMMSS uint64 → "YYYY.MM.DD …"
 *
 * Both linux/stdio.c and windows/stdio.c #include this file directly.
 * Do not compile this file independently.
 */

#ifndef _WIN32
#include <stdint.h>
#include <stdio.h>
#endif

/* -------------------------------------------------------------------------
 * GUID string conversion helpers
 * --------------------------------------------------------------------- */

char *GuidToString(const GUID *guid, BOOL bDecorated)
{
	static char guid_string[MAX_GUID_STRING_LENGTH];
	if (guid == NULL) return NULL;
	snprintf(guid_string, sizeof(guid_string),
	         bDecorated
	         ? "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
	         : "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
	         (uint32_t)guid->Data1, guid->Data2, guid->Data3,
	         guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
	         guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
	return guid_string;
}

GUID *StringToGuid(const char *str)
{
	static GUID guid;
	unsigned int d[11];
	if (str == NULL) return NULL;
	if (sscanf(str, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
	           &d[0], &d[1], &d[2],
	           &d[3], &d[4], &d[5], &d[6],
	           &d[7], &d[8], &d[9], &d[10]) != 11)
		return NULL;
	guid.Data1    = (uint32_t)d[0];
	guid.Data2    = (uint16_t)d[1];
	guid.Data3    = (uint16_t)d[2];
	guid.Data4[0] = (uint8_t)d[3];
	guid.Data4[1] = (uint8_t)d[4];
	guid.Data4[2] = (uint8_t)d[5];
	guid.Data4[3] = (uint8_t)d[6];
	guid.Data4[4] = (uint8_t)d[7];
	guid.Data4[5] = (uint8_t)d[8];
	guid.Data4[6] = (uint8_t)d[9];
	guid.Data4[7] = (uint8_t)d[10];
	return &guid;
}

/* -------------------------------------------------------------------------
 * TimestampToHumanReadable
 * Convert a YYYYMMDDHHMMSS UTC timestamp (stored as uint64_t) to a
 * human-readable string: "YYYY.MM.DD HH:MM:SS (UTC)".
 * --------------------------------------------------------------------- */
char *TimestampToHumanReadable(uint64_t ts)
{
	static char str[64];
	uint64_t rem = ts, divisor = 10000000000ULL;
	uint16_t data[6];
	int i;

	for (i = 0; i < 6; i++) {
		data[i] = (uint16_t)((divisor == 0) ? rem : (rem / divisor));
		rem %= divisor;
		divisor /= 100ULL;
	}
	snprintf(str, sizeof(str), "%04d.%02d.%02d %02d:%02d:%02d (UTC)",
	         data[0], data[1], data[2], data[3], data[4], data[5]);
	return str;
}
