/*
 * Rufus: The Reliable USB Formatting Utility
 * Portable standard function implementations (shared between Windows and Linux)
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

/*
 * This file contains the platform-independent utility functions extracted from
 * windows/stdfn.c.  It must not contain any OS-specific API calls.
 *
 * Portable functions provided here:
 *   isprime()         — internal primality helper for htab
 *   htab_create()     — allocate the hash table
 *   htab_destroy()    — free all resources owned by htab
 *   htab_hash()       — double-hashing open-address lookup / insert
 *   StrArrayCreate()  — allocate a growable string array
 *   StrArrayAdd()     — append a string (with optional duplication and growth)
 *   StrArrayAddUnique() — append only if not already present
 *   StrArrayFind()    — linear search
 *   StrArrayClear()   — free all entries; keep the backing array
 *   StrArrayDestroy() — free entries and backing array
 *   CompareGUID()     — memcmp-based GUID comparison
 *
 * OS-specific implementations (FileIO, GetResource, IsFontAvailable, etc.)
 * remain in src/windows/stdfn.c and src/linux/stdfn.c respectively.
 */

#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "rufus.h"

/* ---------------------------------------------------------------------------
 * Hash table functions
 * Based on glibc 2.3.2 implementation via windows/stdfn.c.
 * References:
 *   [Aho, Sethi, Ullman] Compilers: Principles, Techniques and Tools, 1986
 *   [Knuth] The Art of Computer Programming, part 3 (6.4)
 * --------------------------------------------------------------------------- */

/* Test primality.  Only odd numbers are ever passed (nel |= 1 in htab_create). */
static uint32_t isprime(uint32_t number)
{
	uint32_t divider = 3;
	while ((divider * divider < number) && (number % divider != 0))
		divider += 2;
	return (number % divider != 0);
}

/*
 * Allocate the hash table.  nel is rounded up to the next prime so that the
 * double-hash step visits every slot before repeating.
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

/* ---------------------------------------------------------------------------
 * String array — a dynamically growing array of char* strings
 * --------------------------------------------------------------------------- */

void StrArrayCreate(StrArray* arr, uint32_t initial_size)
{
	if (arr == NULL) return;
	arr->Max = initial_size;
	arr->Index = 0;
	arr->String = (char**)calloc(arr->Max, sizeof(char*));
	if (arr->String == NULL)
		uprintf("Could not allocate string array");
}

int32_t StrArrayAdd(StrArray* arr, const char* str, BOOL duplicate)
{
	char** old_table;
	if ((arr == NULL) || (arr->String == NULL) || (str == NULL))
		return -1;
	if (arr->Index == arr->Max) {
		arr->Max *= 2;
		old_table = arr->String;
		arr->String = (char**)realloc(arr->String, arr->Max * sizeof(char*));
		if (arr->String == NULL) {
			free(old_table);
			uprintf("Could not reallocate string array");
			return -1;
		}
	}
	arr->String[arr->Index] = duplicate ? safe_strdup(str) : (char*)str;
	if (arr->String[arr->Index] == NULL) {
		uprintf("Could not store string in array");
		return -1;
	}
	return arr->Index++;
}

int32_t StrArrayFind(StrArray* arr, const char* str)
{
	uint32_t i;
	if ((str == NULL) || (arr == NULL) || (arr->String == NULL))
		return -1;
	for (i = 0; i < arr->Index; i++) {
		if (arr->String[i] != NULL && strcmp(arr->String[i], str) == 0)
			return (int32_t)i;
	}
	return -1;
}

int32_t StrArrayAddUnique(StrArray* arr, const char* str, BOOL duplicate)
{
	int32_t i = StrArrayFind(arr, str);
	return (i < 0) ? StrArrayAdd(arr, str, duplicate) : i;
}

void StrArrayClear(StrArray* arr)
{
	uint32_t i;
	if ((arr == NULL) || (arr->String == NULL))
		return;
	for (i = 0; i < arr->Index; i++)
		safe_free(arr->String[i]);
	arr->Index = 0;
}

void StrArrayDestroy(StrArray* arr)
{
	StrArrayClear(arr);
	if (arr != NULL) {
		safe_free(arr->String);
		arr->Max = 0;
	}
}

/* ---------------------------------------------------------------------------
 * GUID comparison
 * --------------------------------------------------------------------------- */

BOOL CompareGUID(const GUID *guid1, const GUID *guid2)
{
	if (guid1 == NULL || guid2 == NULL)
		return FALSE;
	return (memcmp(guid1, guid2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}
