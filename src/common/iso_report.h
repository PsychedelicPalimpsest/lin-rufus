/*
 * common/iso_report.h — log_iso_report() declaration
 *
 * Portable function that logs all ISO scan results from img_report.
 * Extracted from DisplayISOProps() in windows/rufus.c.
 *
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

/*
 * log_iso_report — log all ISO scan properties from the global img_report.
 *
 * Calls uprintf() for each detected property:
 *  - ISO label and projected size
 *  - Windows version (if detected)
 *  - Size mismatch (truncation or over-size)
 *  - Boot flags: Syslinux, KolibriOS, ReactOS, Grub4DOS, GRUB2, EFI,
 *    Bootmgr, WinPE, Windows install images
 *  - Filesystem notes: NTFS requirement, symbolic links
 *
 * On Windows, also displays a dialog if a truncation mismatch is detected.
 */
void log_iso_report(void);
