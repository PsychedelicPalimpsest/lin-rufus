/*
 * ventoy_detect.h — Detect existing Ventoy installation on a block device.
 *
 * Detection strategy (in order of reliability):
 *  1. Read the first sector; if bytes 0x1B4–0x1B7 spell "VTOY", it is a
 *     Ventoy MBR disk.
 *  2. Scan partition filesystem labels via libblkid; presence of a
 *     partition with label "Ventoy" (data) or "VTOYEFI" (EFI) confirms
 *     a Ventoy GPT disk.
 *  3. For GPT disks, check the GPT partition name field (UTF-16LE,
 *     72 bytes at offset 0x38 in each partition entry) for "VTOYEFI".
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once
#ifndef RUFUS_VENTOY_DETECT_H
#define RUFUS_VENTOY_DETECT_H

#ifndef _WIN32
#  include "compat/windows.h"
#else
#  include "../windows/rufus.h"
#endif

/*
 * Ventoy MBR signature is "VTOY" at disk byte offset 0x1B4.
 * (Different from the Windows disk-signature at 0x1B8.)
 */
#define VENTOY_MBR_OFFSET  0x1B4
#define VENTOY_MBR_MAGIC   "VTOY"
#define VENTOY_MBR_MAGIC_LEN 4

/* Partition filesystem labels used by Ventoy */
#define VENTOY_LABEL_DATA  "Ventoy"
#define VENTOY_LABEL_EFI   "VTOYEFI"

/*
 * ventoy_detect() — probe |dev_path| (e.g. "/dev/sdb") for a Ventoy
 * installation.  Returns TRUE if a Ventoy layout is found.
 */
BOOL ventoy_detect(const char *dev_path);

/*
 * ventoy_detect_by_label() — scan partitions partXp1..partXp16 for a
 * filesystem label matching "Ventoy" or "VTOYEFI" using libblkid.
 * Returns TRUE if found.  Used as fallback when direct MBR read fails.
 */
BOOL ventoy_detect_by_label(const char *dev_path);

/*
 * ventoy_check_mbr() — read 4 bytes from |dev_path| at offset
 * VENTOY_MBR_OFFSET and compare to VENTOY_MBR_MAGIC.
 * Returns TRUE if the magic matches.
 */
BOOL ventoy_check_mbr(const char *dev_path);

#endif /* RUFUS_VENTOY_DETECT_H */
