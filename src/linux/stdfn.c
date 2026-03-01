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

/*
 * Hash table functions - from glibc 2.3.2 via Windows stdfn.c:
 * [Aho,Sethi,Ullman] Compilers: Principles, Techniques and Tools, 1986
 * [Knuth]            The Art of Computer Programming, part 3 (6.4)
 */

/*
 * Test primality.  Only odd numbers are ever passed (nel |= 1 in htab_create).
 */
static uint32_t isprime(uint32_t number)
{
	uint32_t divider = 3;
	while ((divider * divider < number) && (number % divider != 0))
		divider += 2;
	return (number % divider != 0);
}

/*
 * Allocate the hash table.  We round nel up to the next prime so that
 * the double-hash step visits every slot before repeating.
 */
BOOL htab_create(uint32_t nel, htab_table* htab)
{
	if (htab == NULL)
		return FALSE;
	if_assert_fails(htab->table == NULL) {
		uprintf("WARNING: htab_create() was called with a non empty table");
		return FALSE;
	}

	/* Round up to next odd prime */
	nel |= 1;
	while (!isprime(nel))
		nel += 2;

	htab->size = nel;
	htab->filled = 0;

	htab->table = (htab_entry*)calloc(htab->size + 1, sizeof(htab_entry));
	if (htab->table == NULL) {
		uprintf("Could not allocate space for hash table");
		return FALSE;
	}

	return TRUE;
}

/* Free all resources owned by htab. */
void htab_destroy(htab_table* htab)
{
	size_t i;

	if ((htab == NULL) || (htab->table == NULL))
		return;

	for (i = 0; i < htab->size + 1; i++) {
		if (htab->table[i].used)
			safe_free(htab->table[i].str);
	}
	htab->filled = 0;
	htab->size = 0;
	safe_free(htab->table);
	htab->table = NULL;
}

/*
 * Double-hashing open-address lookup / insert.
 *
 * Returns the slot index for str (inserting a new entry if not present),
 * or 0 on error.  Index 0 is never used as a valid slot; it signals failure.
 *
 * The caller may attach arbitrary data to the returned slot:
 *   htab.table[idx].data = my_pointer;
 */
uint32_t htab_hash(char* str, htab_table* htab)
{
	uint32_t hval, hval2;
	uint32_t idx;
	uint32_t r = 0;
	int c;
	char* sz = str;

	if ((htab == NULL) || (htab->table == NULL) || (str == NULL))
		return 0;

	/* sdbm hash — empirically better than djb2 for this workload */
	while ((c = *sz++) != 0)
		r = c + (r << 6) + (r << 16) - r;
	if (r == 0)
		++r;

	hval = r % htab->size;
	if (hval == 0)
		++hval;

	idx = hval;

	if (htab->table[idx].used) {
		if ((htab->table[idx].used == hval) &&
		    (safe_strcmp(str, htab->table[idx].str) == 0))
			return idx;   /* Found existing entry */

		/* Second hash for double-hashing probe sequence */
		hval2 = 1 + hval % (htab->size - 2);

		do {
			if (idx <= hval2)
				idx = ((uint32_t)htab->size) + idx - hval2;
			else
				idx -= hval2;

			if (idx == hval)
				break;  /* Wrapped all the way round — full */

			if ((htab->table[idx].used == hval) &&
			    (safe_strcmp(str, htab->table[idx].str) == 0))
				return idx;
		} while (htab->table[idx].used);
	}

	/* Not found — insert at idx */
	if_assert_fails(htab->filled < htab->size) {
		uprintf("Hash table is full (%d entries)", htab->size);
		return 0;
	}

	safe_free(htab->table[idx].str);
	htab->table[idx].used = hval;
	htab->table[idx].str = (char*)malloc(safe_strlen(str) + 1);
	if (htab->table[idx].str == NULL) {
		uprintf("Could not duplicate string for hash table");
		return 0;
	}
	memcpy(htab->table[idx].str, str, safe_strlen(str) + 1);
	++htab->filled;

	return idx;
}

/* String arrays */
void StrArrayCreate(StrArray* arr, uint32_t initial_size) {
    if (!arr) return;
    arr->Max = initial_size;
    arr->Index = 0;
    arr->String = (char**)calloc(initial_size, sizeof(char*));
}
int32_t StrArrayAdd(StrArray* arr, const char* str, BOOL dup) {
    (void)dup;
    if (!arr || !str || arr->Index >= arr->Max) return -1;
    arr->String[arr->Index] = strdup(str);
    return (int32_t)arr->Index++;
}
int32_t StrArrayAddUnique(StrArray* arr, const char* str, BOOL dup) {
    int32_t i = StrArrayFind(arr, str);
    return (i >= 0) ? i : StrArrayAdd(arr, str, dup);
}
int32_t StrArrayFind(StrArray* arr, const char* str) {
    if (!arr || !str) return -1;
    for (uint32_t i = 0; i < arr->Index; i++)
        if (arr->String[i] && strcmp(arr->String[i], str) == 0) return (int32_t)i;
    return -1;
}
void StrArrayClear(StrArray* arr) {
    if (!arr) return;
    for (uint32_t i = 0; i < arr->Index; i++) { free(arr->String[i]); arr->String[i] = NULL; }
    arr->Index = 0;
}
void StrArrayDestroy(StrArray* arr) {
    StrArrayClear(arr);
    free(arr->String);
    arr->String = NULL;
    arr->Max = 0;
}

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

/* -------------------------------------------------------------------------
 * GUID helpers
 * --------------------------------------------------------------------- */

BOOL CompareGUID(const GUID *guid1, const GUID *guid2)
{
    if (guid1 == NULL || guid2 == NULL)
        return FALSE;
    return (memcmp(guid1, guid2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}

/* Hash function arrays */
