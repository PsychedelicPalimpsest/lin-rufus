/*
 * iso_scan.h — Portable ISO buffer-scanning helpers
 *
 * These functions scan in-memory binary buffers to identify GRUB versions,
 * GRUB filesystem modules, and EFI bootloader identities.  They contain no
 * OS-specific I/O and may be called from both Linux and Windows code.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <stddef.h>
#include "rufus.h"

/*
 * GetGrubVersion — Scan a binary buffer for a GRUB version string and
 * update img_report.grub2_version if not already set.
 *
 * @buf      Buffer to scan (must be NUL-terminated where the version ends).
 * @buf_size Number of bytes in buf.
 * @source   Filename/path label used in diagnostic uprintf calls.
 */
void GetGrubVersion(char* buf, size_t buf_size, const char* source);

/*
 * GetGrubFs — Scan a binary buffer for GRUB filesystem module entries and
 * add any unique filesystem names found to @filesystems.
 *
 * @buf         Buffer to scan.
 * @buf_size    Number of bytes in buf.
 * @filesystems StrArray to receive unique filesystem names; may be NULL
 *              (call is a no-op).
 */
void GetGrubFs(char* buf, size_t buf_size, StrArray* filesystems);

/*
 * GetEfiBootInfo — Scan a binary buffer for known EFI bootloader signature
 * strings and log version info via uprintf.
 *
 * @buf      Buffer to scan.
 * @buf_size Number of bytes in buf.
 * @source   Filename/path label used in diagnostic uprintf calls.
 */
void GetEfiBootInfo(char* buf, size_t buf_size, const char* source);
