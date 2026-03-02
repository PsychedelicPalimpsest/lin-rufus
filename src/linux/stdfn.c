/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: stdfn.c — standard utility functions
 * Copyright © 2013-2026 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Linux stub: stdfn.c - standard functions (stub for porting) */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "rufus.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <fontconfig/fontconfig.h>
#include "freedos_data.h"

/* Emulates Windows SetLastError / GetLastError */
DWORD _win_last_error = 0;

/*
 * Weak fallback for fd_resources: used when freedos_data.c is not linked
 * (e.g. in unit tests that don't need FreeDOS resources).  The strong
 * definition in freedos_data.c takes priority when that file is linked.
 */
__attribute__((weak)) const fd_resource_t fd_resources[FD_RESOURCES_COUNT] =
    {{0, NULL, NULL, 0}};

/* Portable hash table, string array, and GUID comparison — from common/stdfn.c */
#include "../../common/stdfn.c"

/* Misc stubs */
BOOL    isSMode(void)                                             { return FALSE; }
void    GetWindowsVersion(windows_version_t* wv)                  { if(wv) memset(wv,0,sizeof(*wv)); }
version_t* GetExecutableVersion(const char* path)                 { (void)path; return NULL; }

/*
 * FileIO — read, write, or append a whole file using standard POSIX I/O.
 *
 * FILE_IO_READ:   open path, allocate *buf (caller must free), fill *size.
 * FILE_IO_WRITE:  create/overwrite path with *size bytes from *buf.
 * FILE_IO_APPEND: append *size bytes from *buf to path (create if needed).
 *
 * Returns TRUE on success, FALSE on any error.
 */
BOOL FileIO(enum file_io_type io_type, char* path, char** buf, DWORD* size)
{
	FILE* f = NULL;
	BOOL ret = FALSE;

	if (path == NULL || buf == NULL || size == NULL)
		return FALSE;

	switch (io_type) {
	case FILE_IO_READ: {
		f = fopen(path, "rb");
		if (f == NULL) {
			*buf = NULL;
			goto out;
		}
		/* Determine file size */
		if (fseek(f, 0, SEEK_END) != 0)
			goto out;
		long fsz = ftell(f);
		if (fsz < 0)
			goto out;
		rewind(f);
		*size = (DWORD)fsz;
		*buf = (char*)malloc((size_t)fsz + 1);   /* +1 for safety NUL */
		if (*buf == NULL)
			goto out;
		(*buf)[fsz] = '\0';
		if (fsz > 0 && fread(*buf, 1, (size_t)fsz, f) != (size_t)fsz) {
			free(*buf);
			*buf = NULL;
			goto out;
		}
		ret = TRUE;
		break;
	}

	case FILE_IO_WRITE: {
		f = fopen(path, "wb");
		if (f == NULL)
			goto out;
		if (*size > 0 && fwrite(*buf, 1, (size_t)*size, f) != (size_t)*size)
			goto out;
		ret = TRUE;
		break;
	}

	case FILE_IO_APPEND: {
		f = fopen(path, "ab");
		if (f == NULL)
			goto out;
		if (*size > 0 && fwrite(*buf, 1, (size_t)*size, f) != (size_t)*size)
			goto out;
		ret = TRUE;
		break;
	}

	default:
		goto out;
	}

out:
	if (f != NULL)
		fclose(f);
	return ret;
}
uint8_t* GetResource(HMODULE m, char* n, char* t, const char* d, DWORD* l, BOOL dup)
{
    (void)m; (void)t; (void)d;
    uintptr_t id = (uintptr_t)(void*)n;
    if (id < 0x10000) {
        for (int i = 0; i < FD_RESOURCES_COUNT; i++) {
            if (fd_resources[i].id == (int)id) {
                if (l) *l = fd_resources[i].size;
                if (dup) {
                    uint8_t *copy = malloc(fd_resources[i].size);
                    if (copy) memcpy(copy, fd_resources[i].data, fd_resources[i].size);
                    return copy;
                }
                return (uint8_t*)fd_resources[i].data;
            }
        }
    }
    if (l) *l = 0;
    return NULL;
}
DWORD GetResourceSize(HMODULE m, char* n, char* t, const char* d)
{
    (void)m; (void)t; (void)d;
    uintptr_t id = (uintptr_t)(void*)n;
    if (id < 0x10000) {
        for (int i = 0; i < FD_RESOURCES_COUNT; i++) {
            if (fd_resources[i].id == (int)id)
                return fd_resources[i].size;
        }
    }
    return 0;
}
BOOL    IsFontAvailable(const char* fn)
{
    if (!fn) return FALSE;
    FcConfig *cfg = FcInitLoadConfigAndFonts();
    if (!cfg) return FALSE;
    FcPattern *pat = FcNameParse((const FcChar8 *)fn);
    FcConfigSubstitute(cfg, pat, FcMatchPattern);
    FcDefaultSubstitute(pat);
    FcResult res;
    FcPattern *match = FcFontMatch(cfg, pat, &res);
    BOOL found = FALSE;
    if (match) {
        FcChar8 *family = NULL;
        if (FcPatternGetString(match, FC_FAMILY, 0, &family) == FcResultMatch
            && family != NULL) {
            found = (strcasestr((const char *)family, fn) != NULL) ||
                    (strcasestr(fn, (const char *)family) != NULL);
        }
        FcPatternDestroy(match);
    }
    FcPatternDestroy(pat);
    FcConfigDestroy(cfg);
    return found;
}
DWORD WINAPI SetLGPThread(LPVOID param)                           { (void)param; return 0; }
BOOL    SetLGP(BOOL r, BOOL* ek, const char* p, const char* pol, DWORD v) { (void)r;(void)ek;(void)p;(void)pol;(void)v; return FALSE; }
BOOL    SetThreadAffinity(DWORD_PTR* ta, size_t n)
{
    if (!ta || n == 0) return FALSE;
    memset(ta, 0, n * sizeof(DWORD_PTR));

    /* Get the set of CPUs available to this process */
    cpu_set_t cs;
    CPU_ZERO(&cs);
    if (sched_getaffinity(0, sizeof(cs), &cs) != 0)
        return FALSE;

    /* Collect the available CPU indices into a local array */
    int cpus[CPU_SETSIZE];
    int ncpu = 0;
    for (int i = 0; i < CPU_SETSIZE && ncpu < (int)(sizeof(DWORD_PTR) * 8); i++) {
        if (CPU_ISSET(i, &cs))
            cpus[ncpu++] = i;
    }

    /* Need at least n CPUs to spread across n threads */
    if ((size_t)ncpu < n)
        return FALSE;

    /* Spread CPUs across threads, last slot gets the remainder */
    int per = ncpu / (int)n;
    int ci = 0;
    ta[n - 1] = 0;
    for (size_t i = 0; i < n - 1; i++) {
        for (int j = 0; j < per; j++)
            ta[i] |= (DWORD_PTR)1 << cpus[ci++];
        ta[n - 1] |= ta[i]; /* accumulate for complement below */
    }
    /* Remaining CPUs assigned to last thread */
    for (int i = ci; i < ncpu; i++)
        ta[n - 1] |= (DWORD_PTR)1 << cpus[i];
    /* Remove earlier threads' bits from last slot */
    for (size_t i = 0; i < n - 1; i++)
        ta[n - 1] ^= ta[i];

    return TRUE;
}
BOOL    IsCurrentProcessElevated(void)                            { return (geteuid() == 0); }

/* ToLocaleName: on Linux, LCID is ignored. Instead we return the BCP-47
 * locale name from the LANG/LANGUAGE environment (e.g. "en_US.UTF-8"
 * → "en-US"), falling back to "en-US" if the locale is unset or "C". */
char* ToLocaleName(DWORD lang_id)
{
    (void)lang_id;
    static char locale_name[64];

    const char* lang = getenv("LANG");
    if (lang == NULL || lang[0] == '\0' || strcmp(lang, "C") == 0 ||
        strcmp(lang, "POSIX") == 0) {
        return "en-US";
    }

    /* Copy the lang code (up to '.', '@', or NUL) and convert '_' → '-' */
    size_t i = 0;
    while (lang[i] && lang[i] != '.' && lang[i] != '@' &&
           i < sizeof(locale_name) - 1) {
        locale_name[i] = (lang[i] == '_') ? '-' : lang[i];
        i++;
    }
    locale_name[i] = '\0';
    return (i > 0) ? locale_name : "en-US";
}
BOOL    SetPrivilege(HANDLE hToken, LPCWSTR priv, BOOL enable)   { (void)hToken;(void)priv;(void)enable; return FALSE; }
BOOL    MountRegistryHive(const HKEY k, const char* n, const char* p) { (void)k;(void)n;(void)p; return FALSE; }
BOOL    UnmountRegistryHive(const HKEY k, const char* n)         { (void)k;(void)n; return FALSE; }
BOOL    TakeOwnership(LPCSTR lpszOwnFile)                        { (void)lpszOwnFile; return FALSE; }

/* Hash function arrays */

/* -------------------------------------------------------------------------
 * Weak fallbacks for parser / settings functions.
 *
 * These are used when linux/parser.c is not linked (most unit-test builds).
 * The strong definitions in linux/parser.c take priority when that file is
 * compiled in.  Without these stubs, any test that includes drive.c (which
 * includes settings.h, which calls get_token_data_file) fails to link.
 * The weak stubs return NULL / FALSE which is the correct "not found" value.
 * --------------------------------------------------------------------- */
__attribute__((weak)) char* get_token_data_file_indexed(
    const char* token, const char* filename, int index)
{ (void)token; (void)filename; (void)index; return NULL; }

__attribute__((weak)) char* set_token_data_file(
    const char* token, const char* data, const char* filename)
{ (void)token; (void)data; (void)filename; return NULL; }

__attribute__((weak)) char* get_token_data_buffer(
    const char* token, unsigned int n,
    const char* buffer, size_t buffer_size)
{ (void)token; (void)n; (void)buffer; (void)buffer_size; return NULL; }
