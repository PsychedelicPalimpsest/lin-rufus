/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux: usb_speed.c — USB speed Mbps → version string conversion
 * Copyright © 2024-2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "usb_speed.h"
#include <stdlib.h>

/*
 * Convert a sysfs USB speed string (Mbps, e.g. "480") to a human-readable
 * USB version label.  Mirrors the usb_speed_name[] table in Windows dev.c.
 * Returns a static string; never NULL.
 */
const char *usb_speed_string(const char *speed_mbps)
{
	if (!speed_mbps || speed_mbps[0] == '\0')
		return "USB";
	long mbps = strtol(speed_mbps, NULL, 10);
	if (mbps >= 40000)       return "USB 4";
	else if (mbps >= 20000)  return "USB 3.2";
	else if (mbps >= 10000)  return "USB 3.1";
	else if (mbps >= 5000)   return "USB 3.0";
	else if (mbps >= 480)    return "USB 2.0";
	else if (mbps >= 12)     return "USB 1.1";
	else if (mbps >= 1)      return "USB 1.0";
	return "USB";
}
