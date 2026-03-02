/*
 * format_fat32.c — Portable FAT32 helper functions
 *
 * Contains pure-C helpers shared by both the Linux and Windows FAT32
 * formatter.  No OS-specific I/O is performed here.
 *
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
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

#include <stdint.h>
#include "format_fat32.h"

/* Size constants (same values as rufus.h KB/MB/GB/TB, duplicated here
 * so this file can be compiled stand-alone without pulling all of rufus.h) */
#define FAT32_KB  1024ULL
#define FAT32_MB  (1024ULL * FAT32_KB)
#define FAT32_GB  (1024ULL * FAT32_MB)
#define FAT32_TB  (1024ULL * FAT32_GB)

/*
 * fat32_default_cluster_size — See format_fat32.h for full description.
 *
 * Derived from the Microsoft recommendation table:
 *   https://support.microsoft.com/en-us/help/140365/
 */
uint32_t fat32_default_cluster_size(uint64_t partition_bytes)
{
	if (partition_bytes < 64 * FAT32_MB)   return 512;
	if (partition_bytes < 128 * FAT32_MB)  return 1024;
	if (partition_bytes < 256 * FAT32_MB)  return 2048;
	if (partition_bytes < 8 * FAT32_GB)    return 4096;
	if (partition_bytes < 16 * FAT32_GB)   return 8192;
	if (partition_bytes < 32 * FAT32_GB)   return 16384;
	if (partition_bytes < 2 * FAT32_TB)    return 32768;
	return 65536;
}
