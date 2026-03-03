/*
 * test_psapi_linux.c — Tests for the Linux psapi.h compat implementation.
 *
 * Tests cover:
 *   1. GetProcessMemoryInfo — reads VmRSS / VmPeak from /proc/self/status
 *   2. EnumProcessModules   — enumerates executable mappings from /proc/self/maps
 *   3. GetModuleInformation — maps a module handle back to base/size
 *   4. GetModuleFileNameExA — resolves exe path via /proc/self/exe
 *   5. NULL / bad-arg guards
 *
 * Linux-only (uses /proc filesystem).
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "framework.h"

/* Pull in the implementation */
#include "../src/linux/compat/psapi.h"

/* ------------------------------------------------------------------ */
/* GetProcessMemoryInfo                                                  */
/* ------------------------------------------------------------------ */

TEST(get_process_memory_info_returns_true)
{
	PROCESS_MEMORY_COUNTERS pmc = {0};
	BOOL ret = GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
	CHECK(ret == TRUE);
}

TEST(get_process_memory_info_working_set_nonzero)
{
	PROCESS_MEMORY_COUNTERS pmc = {0};
	GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
	/* any running process must have some resident memory */
	CHECK(pmc.WorkingSetSize > 0);
}

TEST(get_process_memory_info_cb_set)
{
	PROCESS_MEMORY_COUNTERS pmc = {0};
	GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
	CHECK(pmc.cb == sizeof(PROCESS_MEMORY_COUNTERS));
}

TEST(get_process_memory_info_peak_ge_current)
{
	PROCESS_MEMORY_COUNTERS pmc = {0};
	GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
	CHECK(pmc.PeakWorkingSetSize >= pmc.WorkingSetSize);
}

TEST(get_process_memory_info_null_struct_returns_false)
{
	BOOL ret = GetProcessMemoryInfo(GetCurrentProcess(), NULL, sizeof(PROCESS_MEMORY_COUNTERS));
	CHECK(ret == FALSE);
}

TEST(get_process_memory_info_small_cb_returns_false)
{
	PROCESS_MEMORY_COUNTERS pmc = {0};
	BOOL ret = GetProcessMemoryInfo(GetCurrentProcess(), &pmc, 4);
	CHECK(ret == FALSE);
}

TEST(get_process_memory_info_pagefile_usage_nonzero)
{
	PROCESS_MEMORY_COUNTERS pmc = {0};
	GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
	/* PagefileUsage should mirror WorkingSetSize at minimum */
	CHECK(pmc.PagefileUsage > 0);
}

/* ------------------------------------------------------------------ */
/* EnumProcessModules                                                   */
/* ------------------------------------------------------------------ */

TEST(enum_process_modules_returns_true)
{
	DWORD needed = 0;
	BOOL ret = EnumProcessModules(GetCurrentProcess(), NULL, 0, &needed);
	CHECK(ret == TRUE);
}

TEST(enum_process_modules_needed_nonzero)
{
	DWORD needed = 0;
	EnumProcessModules(GetCurrentProcess(), NULL, 0, &needed);
	CHECK(needed > 0);
}

TEST(enum_process_modules_fills_handles)
{
	DWORD needed = 0;
	HMODULE mods[64];
	int n;

	EnumProcessModules(GetCurrentProcess(), NULL, 0, &needed);
	n = (int)(needed / sizeof(HMODULE));
	CHECK(n > 0);

	memset(mods, 0, sizeof(mods));
	BOOL ret = EnumProcessModules(GetCurrentProcess(), mods,
	                               n * sizeof(HMODULE), &needed);
	CHECK(ret == TRUE);
	/* at least one handle must be non-NULL (the main exe) */
	CHECK(mods[0] != NULL);
}

TEST(enum_process_modules_null_lpcb_needed_returns_false)
{
	BOOL ret = EnumProcessModules(GetCurrentProcess(), NULL, 0, NULL);
	CHECK(ret == FALSE);
}

TEST(enum_process_modules_consistent_count)
{
	DWORD needed1 = 0, needed2 = 0;
	EnumProcessModules(GetCurrentProcess(), NULL, 0, &needed1);
	EnumProcessModules(GetCurrentProcess(), NULL, 0, &needed2);
	CHECK(needed1 == needed2);
}

/* ------------------------------------------------------------------ */
/* GetModuleInformation                                                  */
/* ------------------------------------------------------------------ */

TEST(get_module_information_returns_true_for_valid_handle)
{
	DWORD needed = 0;
	HMODULE mods[1];
	MODULEINFO mi = {0};

	EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed);
	/* mods[0] is the first executable mapping */
	BOOL ret = GetModuleInformation(GetCurrentProcess(), mods[0], &mi, sizeof(mi));
	CHECK(ret == TRUE);
}

TEST(get_module_information_base_matches_handle)
{
	DWORD needed = 0;
	HMODULE mods[1];
	MODULEINFO mi = {0};

	EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed);
	GetModuleInformation(GetCurrentProcess(), mods[0], &mi, sizeof(mi));
	CHECK(mi.lpBaseOfDll == (LPVOID)mods[0]);
}

TEST(get_module_information_size_nonzero)
{
	DWORD needed = 0;
	HMODULE mods[1];
	MODULEINFO mi = {0};

	EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed);
	GetModuleInformation(GetCurrentProcess(), mods[0], &mi, sizeof(mi));
	CHECK(mi.SizeOfImage > 0);
}

TEST(get_module_information_null_info_returns_false)
{
	BOOL ret = GetModuleInformation(GetCurrentProcess(), NULL, NULL, sizeof(MODULEINFO));
	CHECK(ret == FALSE);
}

TEST(get_module_information_small_cb_returns_false)
{
	DWORD needed = 0;
	HMODULE mods[1];
	MODULEINFO mi = {0};
	EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed);
	BOOL ret = GetModuleInformation(GetCurrentProcess(), mods[0], &mi, 4);
	CHECK(ret == FALSE);
}

TEST(get_module_information_invalid_handle_returns_false)
{
	MODULEINFO mi = {0};
	/* Use an address that is very unlikely to be a mapped region base */
	HMODULE bad = (HMODULE)(uintptr_t)0x1UL;
	BOOL ret = GetModuleInformation(GetCurrentProcess(), bad, &mi, sizeof(mi));
	CHECK(ret == FALSE);
}

/* ------------------------------------------------------------------ */
/* GetModuleFileNameExA                                                  */
/* ------------------------------------------------------------------ */

TEST(get_module_filename_exA_returns_nonzero_len)
{
	char buf[512] = {0};
	DWORD n = GetModuleFileNameExA(GetCurrentProcess(), NULL, buf, sizeof(buf));
	CHECK(n > 0);
}

TEST(get_module_filename_exA_contains_slash)
{
	char buf[512] = {0};
	GetModuleFileNameExA(GetCurrentProcess(), NULL, buf, sizeof(buf));
	/* an absolute path must contain a '/' */
	CHECK(strchr(buf, '/') != NULL);
}

TEST(get_module_filename_exA_null_buf_returns_zero)
{
	DWORD n = GetModuleFileNameExA(GetCurrentProcess(), NULL, NULL, 64);
	CHECK(n == 0);
}

TEST(get_module_filename_exA_zero_size_returns_zero)
{
	char buf[4] = {0};
	DWORD n = GetModuleFileNameExA(GetCurrentProcess(), NULL, buf, 0);
	CHECK(n == 0);
}

TEST(get_module_filename_exA_result_is_nul_terminated)
{
	char buf[512];
	memset(buf, 0xFF, sizeof(buf));
	DWORD n = GetModuleFileNameExA(GetCurrentProcess(), NULL, buf, sizeof(buf));
	CHECK(n > 0);
	CHECK(buf[n] == '\0');
}

/* ------------------------------------------------------------------ */
/* GetCurrentProcess pseudo-handle                                       */
/* ------------------------------------------------------------------ */

TEST(get_current_process_is_not_null)
{
	CHECK(GetCurrentProcess() != NULL);
}

int main(void)
{
	RUN(get_process_memory_info_returns_true);
	RUN(get_process_memory_info_working_set_nonzero);
	RUN(get_process_memory_info_cb_set);
	RUN(get_process_memory_info_peak_ge_current);
	RUN(get_process_memory_info_null_struct_returns_false);
	RUN(get_process_memory_info_small_cb_returns_false);
	RUN(get_process_memory_info_pagefile_usage_nonzero);

	RUN(enum_process_modules_returns_true);
	RUN(enum_process_modules_needed_nonzero);
	RUN(enum_process_modules_fills_handles);
	RUN(enum_process_modules_null_lpcb_needed_returns_false);
	RUN(enum_process_modules_consistent_count);

	RUN(get_module_information_returns_true_for_valid_handle);
	RUN(get_module_information_base_matches_handle);
	RUN(get_module_information_size_nonzero);
	RUN(get_module_information_null_info_returns_false);
	RUN(get_module_information_small_cb_returns_false);
	RUN(get_module_information_invalid_handle_returns_false);

	RUN(get_module_filename_exA_returns_nonzero_len);
	RUN(get_module_filename_exA_contains_slash);
	RUN(get_module_filename_exA_null_buf_returns_zero);
	RUN(get_module_filename_exA_zero_size_returns_zero);
	RUN(get_module_filename_exA_result_is_nul_terminated);

	RUN(get_current_process_is_not_null);

	TEST_RESULTS();
}

#endif /* __linux__ */
