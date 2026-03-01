/*
 * Rufus: The Reliable USB Formatting Utility
 * Process management — Linux implementation
 * Copyright © 2013-2026 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "rufus.h"
#include "drive.h"

/* NT / Windows stubs — N/A on Linux */
NTSTATUS PhEnumHandlesEx(void *Handles)                              { (void)Handles; return 0; }
NTSTATUS PhOpenProcess(HANDLE *h, DWORD access, HANDLE pid)          { (void)h; (void)access; (void)pid; return 0; }
char    *NtStatusError(NTSTATUS s)                                   { (void)s; return ""; }

/* Always return TRUE — on Linux we simply require root */
BOOL EnablePrivileges(void) { return TRUE; }

/* -----------------------------------------------------------------------
 * GetPPID — read parent PID from /proc/<pid>/status
 * --------------------------------------------------------------------- */
DWORD GetPPID(DWORD pid)
{
	if (pid == 0)
		return 0;

	char path[64];
	char line[256];
	FILE *f;
	DWORD ppid = 0;

	snprintf(path, sizeof(path), "/proc/%u/status", (unsigned)pid);
	f = fopen(path, "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "PPid:", 5) == 0) {
			ppid = (DWORD)strtoul(line + 5, NULL, 10);
			break;
		}
	}
	fclose(f);
	return ppid;
}

/* -----------------------------------------------------------------------
 * Process search state
 * We use a synchronous /proc scan rather than Windows' background thread.
 * --------------------------------------------------------------------- */
static BOOL  search_active        = FALSE;
static DWORD search_device_number = (DWORD)-1;

/* -----------------------------------------------------------------------
 * StartProcessSearch — mark search as active (always succeeds on Linux)
 * --------------------------------------------------------------------- */
BOOL StartProcessSearch(void)
{
	search_active = TRUE;
	return TRUE;
}

/* -----------------------------------------------------------------------
 * StopProcessSearch — reset search state
 * --------------------------------------------------------------------- */
void StopProcessSearch(void)
{
	search_active        = FALSE;
	search_device_number = (DWORD)-1;
}

/* -----------------------------------------------------------------------
 * SetProcessSearch — register the drive index to scan for open handles
 * --------------------------------------------------------------------- */
BOOL SetProcessSearch(DWORD DeviceNum)
{
	if (!search_active) {
		uprintf("SetProcessSearch: process search not started");
		return FALSE;
	}
	search_device_number = DeviceNum;
	return TRUE;
}

/* -----------------------------------------------------------------------
 * Internal: scan /proc for any process holding the given device open.
 * Returns a bitmask: bit 0 = read, bit 1 = write, bit 2 = execute.
 * --------------------------------------------------------------------- */
static BYTE scan_proc_for_device(dev_t target_dev)
{
	BYTE mask = 0;
	struct dirent *entry, *fd_entry;
	char fd_path[64], link_path[128];
	struct stat st;
	DIR *proc_dir, *fd_dir;

	proc_dir = opendir("/proc");
	if (!proc_dir)
		return 0;

	while ((entry = readdir(proc_dir)) != NULL && !mask) {
		/* Only numeric directories (PIDs) */
		if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
			continue;

		snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", entry->d_name);
		fd_dir = opendir(fd_path);
		if (!fd_dir)
			continue;

		while ((fd_entry = readdir(fd_dir)) != NULL) {
			if (fd_entry->d_name[0] == '.')
				continue;

			snprintf(link_path, sizeof(link_path),
			         "/proc/%s/fd/%s", entry->d_name, fd_entry->d_name);

			if (stat(link_path, &st) == 0 &&
			    (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) &&
			    st.st_rdev == target_dev) {
				/* Report both read and write access conservatively */
				mask |= 0x03;
				break;
			}
		}
		closedir(fd_dir);
	}
	closedir(proc_dir);
	return mask;
}

/* -----------------------------------------------------------------------
 * GetProcessSearch — synchronously scan /proc for open handles to the
 * registered drive.  Returns a bitmask of access types found.
 * --------------------------------------------------------------------- */
BYTE GetProcessSearch(uint32_t timeout, uint8_t access_mask, BOOL bIgnoreStaleProcesses)
{
	(void)timeout;
	(void)access_mask;
	(void)bIgnoreStaleProcesses;

	if (!search_active || search_device_number == (DWORD)-1)
		return 0;

	char *dev_path = GetPhysicalName(search_device_number);
	if (!dev_path)
		return 0;

	struct stat st;
	BYTE result = 0;
	if (stat(dev_path, &st) == 0 && S_ISBLK(st.st_mode))
		result = scan_proc_for_device(st.st_rdev);

	free(dev_path);
	return result;
}

/* -----------------------------------------------------------------------
 * SearchProcessAlt — scan /proc/<pid>/comm for a process with the given
 * name.  Returns TRUE if any matching process is found.
 * --------------------------------------------------------------------- */
BOOL SearchProcessAlt(char *name)
{
	if (!name || name[0] == '\0')
		return FALSE;

	DIR *proc_dir = opendir("/proc");
	if (!proc_dir)
		return FALSE;

	struct dirent *entry;
	BOOL found = FALSE;

	while ((entry = readdir(proc_dir)) != NULL && !found) {
		if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
			continue;

		char comm_path[64];
		snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);

		FILE *f = fopen(comm_path, "r");
		if (!f)
			continue;

		char comm[256];
		if (fgets(comm, sizeof(comm), f)) {
			size_t len = strlen(comm);
			if (len > 0 && comm[len - 1] == '\n')
				comm[len - 1] = '\0';
			if (strcmp(comm, name) == 0)
				found = TRUE;
		}
		fclose(f);
	}
	closedir(proc_dir);
	return found;
}
