/* Linux compat stub for psapi.h — real /proc implementations */
#pragma once
#ifndef _WIN32
#include "windows.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * PROCESS_MEMORY_COUNTERS — subset of the Windows struct.
 * Only WorkingSetSize (VmRSS) and PagefileUsage (VmSwap+VmRSS proxy) are
 * populated; the others are zeroed.
 */
typedef struct _PROCESS_MEMORY_COUNTERS {
	DWORD  cb;
	DWORD  PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} PROCESS_MEMORY_COUNTERS, *PPROCESS_MEMORY_COUNTERS;

/*
 * MODULEINFO — base address, size and entry point of a mapped module.
 * Populated by EnumProcessModules from /proc/self/maps.
 */
typedef struct _MODULEINFO {
	LPVOID lpBaseOfDll;
	DWORD  SizeOfImage;
	LPVOID EntryPoint;
} MODULEINFO, *LPMODULEINFO;

/*
 * GetProcessMemoryInfo — reads VmRSS and VmPeak from /proc/PID/status.
 * The handle is ignored (only the calling process is supported).
 */
static inline BOOL GetProcessMemoryInfo(HANDLE hProcess,
                                        PPROCESS_MEMORY_COUNTERS ppsmemCounters,
                                        DWORD cb)
{
	FILE *f;
	char line[256];
	unsigned long vmrss_kb = 0, vmpeak_kb = 0;

	(void)hProcess;
	if (!ppsmemCounters || cb < sizeof(PROCESS_MEMORY_COUNTERS))
		return FALSE;

	memset(ppsmemCounters, 0, sizeof(PROCESS_MEMORY_COUNTERS));
	ppsmemCounters->cb = sizeof(PROCESS_MEMORY_COUNTERS);

	f = fopen("/proc/self/status", "r");
	if (!f)
		return FALSE;

	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "VmRSS:", 6) == 0)
			sscanf(line + 6, " %lu", &vmrss_kb);
		else if (strncmp(line, "VmPeak:", 7) == 0)
			sscanf(line + 7, " %lu", &vmpeak_kb);
	}
	fclose(f);

	ppsmemCounters->WorkingSetSize     = (SIZE_T)vmrss_kb  * 1024;
	ppsmemCounters->PeakWorkingSetSize = (SIZE_T)vmpeak_kb * 1024;
	ppsmemCounters->PagefileUsage      = ppsmemCounters->WorkingSetSize;
	ppsmemCounters->PeakPagefileUsage  = ppsmemCounters->PeakWorkingSetSize;
	return TRUE;
}

/*
 * EnumProcessModules — populates hModules[0..cb/sizeof(HMODULE)] from
 * /proc/self/maps by collecting unique base addresses of mapped files.
 * lpcbNeeded receives the total bytes needed for the full list.
 * The handle is ignored.
 */
static inline BOOL EnumProcessModules(HANDLE hProcess,
                                      HMODULE *lphModule,
                                      DWORD   cb,
                                      LPDWORD lpcbNeeded)
{
	FILE *f;
	char line[512];
	/* collect up to 256 unique base addresses */
	unsigned long bases[256];
	int n = 0;

	(void)hProcess;
	if (!lpcbNeeded)
		return FALSE;

	f = fopen("/proc/self/maps", "r");
	if (!f) {
		*lpcbNeeded = 0;
		return FALSE;
	}

	while (fgets(line, sizeof(line), f) && n < 256) {
		unsigned long start, end;
		char perms[8], path[512];
		int fields;
		path[0] = '\0';
		fields = sscanf(line, "%lx-%lx %7s %*s %*s %*s %511s",
		                &start, &end, perms, path);
		/* only executable anonymous mappings or mapped files */
		if (fields < 3)
			continue;
		if (perms[2] != 'x')
			continue;
		/* skip duplicates (e.g. multiple exec sections of the same DSO) */
		int dup = 0;
		for (int i = 0; i < n; i++) {
			if (bases[i] == start) { dup = 1; break; }
		}
		if (!dup)
			bases[n++] = start;
	}
	fclose(f);

	*lpcbNeeded = (DWORD)(n * sizeof(HMODULE));

	if (!lphModule || cb == 0)
		return TRUE;   /* caller is asking for the needed size only */

	int maxmods = (int)(cb / sizeof(HMODULE));
	int fill = n < maxmods ? n : maxmods;
	for (int i = 0; i < fill; i++)
		lphModule[i] = (HMODULE)(uintptr_t)bases[i];

	return TRUE;
}

/*
 * GetModuleInformation — fills MODULEINFO for a module handle obtained via
 * EnumProcessModules.  Walks /proc/self/maps to find the contiguous range.
 */
static inline BOOL GetModuleInformation(HANDLE hProcess,
                                        HMODULE hModule,
                                        LPMODULEINFO lpmodinfo,
                                        DWORD cb)
{
	FILE *f;
	char line[512];
	unsigned long base = (unsigned long)(uintptr_t)hModule;
	unsigned long seg_start, seg_end;
	unsigned long map_start = 0, map_end = 0;
	int found = 0;

	(void)hProcess;
	if (!lpmodinfo || cb < sizeof(MODULEINFO))
		return FALSE;

	memset(lpmodinfo, 0, sizeof(MODULEINFO));

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return FALSE;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &seg_start, &seg_end) != 2)
			continue;
		if (seg_start == base) {
			map_start = seg_start;
			map_end   = seg_end;
			found = 1;
		} else if (found && seg_start == map_end) {
			/* extend contiguous range */
			map_end = seg_end;
		} else if (found) {
			break;
		}
	}
	fclose(f);

	if (!found)
		return FALSE;

	lpmodinfo->lpBaseOfDll = (LPVOID)(uintptr_t)map_start;
	lpmodinfo->SizeOfImage = (DWORD)(map_end - map_start);
	lpmodinfo->EntryPoint  = lpmodinfo->lpBaseOfDll;  /* approximate */
	return TRUE;
}

/* GetModuleFileNameExA — returns the exe path for the main module */
static inline DWORD GetModuleFileNameExA(HANDLE hProcess,
                                         HMODULE hModule,
                                         char *lpFilename,
                                         DWORD nSize)
{
	ssize_t r;
	(void)hProcess;
	(void)hModule;
	if (!lpFilename || nSize == 0)
		return 0;
	r = readlink("/proc/self/exe", lpFilename, (size_t)(nSize - 1));
	if (r < 0) {
		lpFilename[0] = '\0';
		return 0;
	}
	lpFilename[r] = '\0';
	return (DWORD)r;
}

/* Convenience: GetCurrentProcess returns a pseudo-handle (ignored anyway) */
#ifndef GetCurrentProcess
#define GetCurrentProcess() ((HANDLE)(intptr_t)-1)
#endif

#endif /* !_WIN32 */
