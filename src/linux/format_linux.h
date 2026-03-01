/*
 * format_linux.h — Linux-specific format helpers exposed for testing
 *
 * These functions are implemented in linux/format.c as non-static
 * helpers so that tests can call them directly.
 */
#pragma once

#include <stdint.h>
#include "windows.h"

/*
 * format_linux_clear_mbr_gpt - zero the MBR/GPT areas of a drive.
 *
 * Zeroes MAX_SECTORS_TO_CLEAR sectors at the beginning of the drive and
 * MAX_SECTORS_TO_CLEAR/8 sectors at the end.
 */
BOOL format_linux_clear_mbr_gpt(HANDLE hDrive, LONGLONG DiskSize, DWORD SectorSize);

/*
 * format_linux_write_mbr - write the appropriate MBR boot code.
 *
 * Selects the MBR type based on the global boot_type, target_type, and
 * img_report, then writes only the boot code bytes (0–445) plus the
 * 0x55AA signature — partition table entries (bytes 446–509) are untouched.
 */
BOOL format_linux_write_mbr(HANDLE hDrive);

/*
 * format_linux_write_drive - raw image write or zero-drive.
 *
 * If bZeroDrive is TRUE, writes zeros across the entire drive (SelectedDrive.DiskSize).
 * If bZeroDrive is FALSE, copies from global image_path to hDrive.
 */
BOOL format_linux_write_drive(HANDLE hDrive, BOOL bZeroDrive);
