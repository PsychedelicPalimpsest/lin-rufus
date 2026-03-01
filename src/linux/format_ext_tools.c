/*
 * Rufus: The Reliable USB Formatting Utility — Linux NTFS/exFAT formatter
 *
 * Wraps mkntfs (ntfs-3g) and mkfs.exfat (exfatprogs / exfat-utils) via
 * RunCommandWithProgress() to provide NTFS and exFAT formatting on Linux.
 *
 * Copyright © 2019-2025 Pete Batard <pete@akeo.ie>
 * Linux port © 2024 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "resource.h"
#include "format_linux.h"

/* =========================================================================
 * Internal helpers
 * ======================================================================= */

/*
 * Locate an external tool binary.  Searches the common system tool directories
 * and returns the first executable found, or NULL.
 */
static const char *find_format_tool(const char *name)
{
	static char buf[256];
	static const char * const dirs[] = {
		"/sbin", "/usr/sbin", "/bin", "/usr/bin",
		"/usr/local/sbin", "/usr/local/bin", NULL
	};
	for (int i = 0; dirs[i]; i++) {
		snprintf(buf, sizeof(buf), "%s/%s", dirs[i], name);
		if (access(buf, X_OK) == 0) return buf;
	}
	return NULL;
}

/* =========================================================================
 * format_ntfs_build_cmd
 *
 * Build the mkntfs command string into cmd_buf.
 *
 * Parameters:
 *   tool         - absolute path to mkntfs binary (must not be NULL)
 *   part_path    - partition device/file path (must not be NULL)
 *   cluster_size - bytes per cluster; 0 means let mkntfs choose
 *   label        - volume label or NULL/empty to omit -L
 *   quick        - if TRUE, add -Q (quick format — skip zeroing)
 *   cmd_buf      - output buffer (must not be NULL)
 *   cmd_buf_len  - size of cmd_buf; must be large enough for the full command
 *
 * Returns TRUE on success, FALSE if any argument is NULL or the buffer is
 * too small to hold the resulting command.
 * ======================================================================= */
BOOL format_ntfs_build_cmd(const char *tool, const char *part_path,
                            DWORD cluster_size, const char *label, BOOL quick,
                            BOOL force,
                            char *cmd_buf, size_t cmd_buf_len)
{
	if (!tool || !part_path || !cmd_buf || cmd_buf_len < 16)
		return FALSE;

	char tmp[1024];
	int n;

	if (quick)
		n = snprintf(tmp, sizeof(tmp), "%s -Q", tool);
	else
		n = snprintf(tmp, sizeof(tmp), "%s", tool);

	if (n < 0 || (size_t)n >= sizeof(tmp)) return FALSE;

	if (force) {
		int m = snprintf(tmp + n, sizeof(tmp) - (size_t)n, " -F");
		if (m < 0 || (size_t)(n + m) >= sizeof(tmp)) return FALSE;
		n += m;
	}

	if (cluster_size > 0) {
		int m = snprintf(tmp + n, sizeof(tmp) - (size_t)n,
		                 " -c %u", (unsigned)cluster_size);
		if (m < 0 || (size_t)(n + m) >= sizeof(tmp)) return FALSE;
		n += m;
	}

	if (label && label[0] != '\0') {
		int m = snprintf(tmp + n, sizeof(tmp) - (size_t)n,
		                 " -L \"%s\"", label);
		if (m < 0 || (size_t)(n + m) >= sizeof(tmp)) return FALSE;
		n += m;
	}

	int m = snprintf(tmp + n, sizeof(tmp) - (size_t)n, " \"%s\"", part_path);
	if (m < 0 || (size_t)(n + m) >= sizeof(tmp)) return FALSE;
	n += m;

	if ((size_t)n >= cmd_buf_len) return FALSE;

	memcpy(cmd_buf, tmp, (size_t)n + 1);
	return TRUE;
}

/* =========================================================================
 * format_exfat_build_cmd
 *
 * Build the mkfs.exfat command string into cmd_buf.
 *
 * Parameters:
 *   tool         - absolute path to mkfs.exfat (or mkexfatfs) binary
 *   part_path    - partition device/file path
 *   cluster_size - bytes per cluster; 0 means let the tool choose
 *   label        - volume label or NULL/empty to omit -n
 *   cmd_buf      - output buffer
 *   cmd_buf_len  - size of cmd_buf
 *
 * Returns TRUE on success, FALSE on any invalid argument or buffer overflow.
 * ======================================================================= */
BOOL format_exfat_build_cmd(const char *tool, const char *part_path,
                             DWORD cluster_size, const char *label,
                             char *cmd_buf, size_t cmd_buf_len)
{
	if (!tool || !part_path || !cmd_buf || cmd_buf_len < 16)
		return FALSE;

	char tmp[1024];
	int n = snprintf(tmp, sizeof(tmp), "%s", tool);
	if (n < 0 || (size_t)n >= sizeof(tmp)) return FALSE;

	if (cluster_size > 0) {
		int m = snprintf(tmp + n, sizeof(tmp) - (size_t)n,
		                 " -c %u", (unsigned)cluster_size);
		if (m < 0 || (size_t)(n + m) >= sizeof(tmp)) return FALSE;
		n += m;
	}

	if (label && label[0] != '\0') {
		int m = snprintf(tmp + n, sizeof(tmp) - (size_t)n,
		                 " -n \"%s\"", label);
		if (m < 0 || (size_t)(n + m) >= sizeof(tmp)) return FALSE;
		n += m;
	}

	int m = snprintf(tmp + n, sizeof(tmp) - (size_t)n, " \"%s\"", part_path);
	if (m < 0 || (size_t)(n + m) >= sizeof(tmp)) return FALSE;
	n += m;

	if ((size_t)n >= cmd_buf_len) return FALSE;

	memcpy(cmd_buf, tmp, (size_t)n + 1);
	return TRUE;
}

/* =========================================================================
 * FormatNTFS
 *
 * Format a partition as NTFS using mkntfs.
 *
 * Locates mkntfs at runtime, resolves the partition device path, builds
 * the command, and runs it via RunCommandWithProgress().
 *
 * Returns TRUE on success, FALSE if mkntfs is not installed or fails.
 * ======================================================================= */
BOOL FormatNTFS(DWORD DriveIndex, uint64_t PartitionOffset,
                DWORD UnitAllocationSize, LPCSTR Label, DWORD Flags)
{
	if ((DriveIndex < DRIVE_INDEX_MIN) || (DriveIndex > DRIVE_INDEX_MAX)) {
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	/* Prefer mkntfs (ntfs-3g); also accept mkfs.ntfs */
	const char *tool = find_format_tool("mkntfs");
	if (!tool) tool = find_format_tool("mkfs.ntfs");
	if (!tool) {
		uprintf("FormatNTFS: mkntfs not found; please install ntfs-3g");
		ErrorStatus = RUFUS_ERROR(ERROR_NOT_SUPPORTED);
		return FALSE;
	}

	/* Get the partition device path.  Use GetLogicalName first (real device),
	 * then fall back to the physical path (image file in tests). */
	char *part_path = GetLogicalName(DriveIndex, PartitionOffset, FALSE, TRUE);
	if (!part_path)
		part_path = GetPhysicalName(DriveIndex);
	if (!part_path) {
		ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
		return FALSE;
	}

	BOOL quick = (Flags & FP_QUICK) ? TRUE : FALSE;

	/* When formatting a non-block device (e.g. test image file) mkntfs refuses
	 * to proceed without -F (force).  Detect this and set the flag. */
	struct stat st_p;
	BOOL force = (stat(part_path, &st_p) == 0 && !S_ISBLK(st_p.st_mode));

	char cmd[1024];
	if (!format_ntfs_build_cmd(tool, part_path, UnitAllocationSize,
	                            Label, quick, force, cmd, sizeof(cmd))) {
		free(part_path);
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	free(part_path);

	uprintf("Formatting as NTFS: %s", cmd);
	PrintStatusInfo(FALSE, FALSE, 0, MSG_222, "NTFS");
	UpdateProgressWithInfoInit(NULL, TRUE);

	DWORD rc = RunCommandWithProgress(cmd, NULL, TRUE, MSG_217, NULL);
	if (rc != 0) {
		if (rc != ERROR_CANCELLED)
			uprintf("mkntfs failed with exit code %lu", (unsigned long)rc);
		if (!IS_ERROR(ErrorStatus))
			ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
		return FALSE;
	}

	UpdateProgressWithInfo(OP_FORMAT, MSG_217, 100, 100);
	return TRUE;
}

/* =========================================================================
 * FormatExFAT
 *
 * Format a partition as exFAT using mkfs.exfat (exfatprogs) or mkexfatfs
 * (exfat-utils).
 *
 * Returns TRUE on success, FALSE if no exFAT tool is installed or fails.
 * ======================================================================= */
BOOL FormatExFAT(DWORD DriveIndex, uint64_t PartitionOffset,
                 DWORD UnitAllocationSize, LPCSTR Label, DWORD Flags)
{
	(void)Flags; /* exFAT has no quick-format equivalent */

	if ((DriveIndex < DRIVE_INDEX_MIN) || (DriveIndex > DRIVE_INDEX_MAX)) {
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	/* Try both exfatprogs and legacy exfat-utils tool names */
	const char *tool = find_format_tool("mkfs.exfat");
	if (!tool) tool = find_format_tool("mkexfatfs");
	if (!tool) {
		uprintf("FormatExFAT: mkfs.exfat not found; please install exfatprogs or exfat-utils");
		ErrorStatus = RUFUS_ERROR(ERROR_NOT_SUPPORTED);
		return FALSE;
	}

	char *part_path = GetLogicalName(DriveIndex, PartitionOffset, FALSE, TRUE);
	if (!part_path)
		part_path = GetPhysicalName(DriveIndex);
	if (!part_path) {
		ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
		return FALSE;
	}

	char cmd[1024];
	if (!format_exfat_build_cmd(tool, part_path, UnitAllocationSize,
	                             Label, cmd, sizeof(cmd))) {
		free(part_path);
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	free(part_path);

	uprintf("Formatting as exFAT: %s", cmd);
	PrintStatusInfo(FALSE, FALSE, 0, MSG_222, "exFAT");
	UpdateProgressWithInfoInit(NULL, TRUE);

	DWORD rc = RunCommandWithProgress(cmd, NULL, TRUE, MSG_217, NULL);
	if (rc != 0) {
		if (rc != ERROR_CANCELLED)
			uprintf("mkfs.exfat failed with exit code %lu", (unsigned long)rc);
		if (!IS_ERROR(ErrorStatus))
			ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
		return FALSE;
	}

	UpdateProgressWithInfo(OP_FORMAT, MSG_217, 100, 100);
	return TRUE;
}

#endif /* __linux__ */
