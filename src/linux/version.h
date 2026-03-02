/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: version.h — version definitions
 * Copyright © 2025 Rufus contributors
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

/* src/linux/version.h - Rufus Linux port version constants */
#pragma once
#define RUFUS_LINUX_VERSION_MAJOR 4
#define RUFUS_LINUX_VERSION_MINOR 13
#define RUFUS_LINUX_VERSION_PATCH 0

/* Stringify helpers for RUFUS_VERSION_STR */
#define _RUFUS_STR(x)  #x
#define _RUFUS_XSTR(x) _RUFUS_STR(x)

/*
 * RUFUS_VERSION_STR — compile-time version string "MAJOR.MINOR.PATCH",
 * e.g. "4.13.0".  Used to embed the version marker in the binary.
 */
#define RUFUS_VERSION_STR \
    _RUFUS_XSTR(RUFUS_LINUX_VERSION_MAJOR) "." \
    _RUFUS_XSTR(RUFUS_LINUX_VERSION_MINOR) "." \
    _RUFUS_XSTR(RUFUS_LINUX_VERSION_PATCH)
