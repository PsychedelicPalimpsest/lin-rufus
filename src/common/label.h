/*
 * format.h — Portable format helper functions
 *
 * Pure-C functions shared by both the Linux and Windows format code paths.
 * No OS-specific I/O is performed here.
 *
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include "rufus.h"

/*
 * ToValidLabel — Sanitize a UTF-8 drive label in-place so it conforms to
 * the filesystem naming rules for FAT (bFAT=TRUE) or NTFS/exFAT (bFAT=FALSE).
 *
 * FAT rules (max 11 chars, ASCII-only, uppercase):
 *   - Non-ASCII UTF-8 sequences → single '_'
 *   - Unauthorized chars (* ? , ; : / \ | + = < > [ ] ") → removed
 *   - Period '.' and tab '\t' → '_'
 *   - Lowercase letters → uppercase
 *   - Truncated to 11 characters
 *   - If the result is mostly underscores, substituted with a size string
 *     derived from SelectedDrive.DiskSize (e.g. "7_9 GB").
 *
 * NTFS/exFAT rules (max 32 chars, Unicode allowed):
 *   - Unauthorized chars (* ? , ; : / \ | + = < > [ ] ") → removed
 *   - Period '.' and tab '\t' → '_'
 *   - Non-ASCII UTF-8 passes through unchanged
 *   - Truncated to 32 characters (UTF-8 codepoint-aware)
 *
 * Both forms also update img_report.usb_label with the sanitized value.
 */
void ToValidLabel(char *Label, BOOL bFAT);
