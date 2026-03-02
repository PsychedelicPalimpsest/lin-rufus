/*
 * format_fat32.h — Portable FAT32 helper functions
 *
 * Pure-C functions that contain no OS-specific I/O and may be called
 * from both the Linux and Windows FAT32 formatter code paths.
 *
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <stdint.h>

/*
 * fat32_default_cluster_size — Return the default FAT32 cluster size in
 * bytes for a partition of the given size, following the Microsoft
 * recommendation table:
 *   https://support.microsoft.com/en-us/help/140365/
 *
 *   < 64 MB  →  512 bytes
 *   < 128 MB →    1 KiB
 *   < 256 MB →    2 KiB
 *   <   8 GB →    4 KiB
 *   <  16 GB →    8 KiB
 *   <  32 GB →   16 KiB
 *   <   2 TB →   32 KiB
 *   >= 2 TB  →   64 KiB
 *
 * The returned value is always a power of two in the range [512, 65536].
 * A partition_bytes of 0 returns 512 (degenerate case).
 */
uint32_t fat32_default_cluster_size(uint64_t partition_bytes);
