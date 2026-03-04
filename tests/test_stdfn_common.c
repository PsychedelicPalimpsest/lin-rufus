/*
 * test_stdfn_common.c — Cross-platform tests for htab, StrArray, CompareGUID
 *
 * Tests the portable data-structure functions in src/common/stdfn.c.
 * These functions must behave identically on Linux and Windows (via Wine).
 *
 * Functions under test:
 *   htab_create()       — allocate hash table
 *   htab_destroy()      — free hash table
 *   htab_hash()         — lookup / insert string in hash table
 *   StrArrayCreate()    — allocate growable string array
 *   StrArrayAdd()       — append string (with or without duplication)
 *   StrArrayFind()      — linear search
 *   StrArrayAddUnique() — append only if absent
 *   StrArrayClear()     — free entries, keep backing array
 *   StrArrayDestroy()   — free everything
 *   CompareGUID()       — GUID equality comparison
 *
 * Copyright © 2025 PsychedelicPalimpsest
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "framework.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "rufus.h"

/* ------------------------------------------------------------------ */
/* Stubs                                                               */
/* ------------------------------------------------------------------ */

void uprintf(const char *fmt, ...) { (void)fmt; }

/* ================================================================== */
/* htab tests                                                          */
/* ================================================================== */

TEST(htab_create_null_table)
{
	CHECK(htab_create(128, NULL) == FALSE);
}

TEST(htab_create_valid)
{
	htab_table htab = HTAB_EMPTY;
	CHECK(htab_create(64, &htab) == TRUE);
	CHECK(htab.table != NULL);
	CHECK(htab.size > 0);
	CHECK(htab.filled == 0);
	htab_destroy(&htab);
}

TEST(htab_create_small_size)
{
	htab_table htab = HTAB_EMPTY;
	/* Small sizes get rounded up to the next prime */
	CHECK(htab_create(1, &htab) == TRUE);
	CHECK(htab.size > 0);
	htab_destroy(&htab);
}

TEST(htab_create_zero_size)
{
	htab_table htab = HTAB_EMPTY;
	/* Zero is treated like a very small size */
	CHECK(htab_create(0, &htab) == TRUE);
	htab_destroy(&htab);
}

TEST(htab_destroy_clears_fields)
{
	htab_table htab = HTAB_EMPTY;
	htab_create(64, &htab);
	htab_destroy(&htab);
	CHECK(htab.table == NULL);
	CHECK(htab.size == 0);
	CHECK(htab.filled == 0);
}

TEST(htab_destroy_null_safe)
{
	htab_destroy(NULL);   /* must not crash */
	CHECK(1);
}

TEST(htab_destroy_empty_table)
{
	htab_table htab = HTAB_EMPTY;
	htab_destroy(&htab);  /* must not crash on zero-init table */
	CHECK(1);
}

TEST(htab_hash_null_str)
{
	htab_table htab = HTAB_EMPTY;
	htab_create(64, &htab);
	/* NULL string should return 0 (not crash) */
	CHECK(htab_hash(NULL, &htab) == 0);
	htab_destroy(&htab);
}

TEST(htab_hash_null_table)
{
	CHECK(htab_hash("hello", NULL) == 0);
}

TEST(htab_hash_nonzero_for_string)
{
	htab_table htab = HTAB_EMPTY;
	htab_create(64, &htab);
	uint32_t idx = htab_hash("hello", &htab);
	CHECK(idx != 0);
	htab_destroy(&htab);
}

TEST(htab_hash_insert_then_lookup)
{
	htab_table htab = HTAB_EMPTY;
	htab_create(64, &htab);
	/* Insert "world" */
	uint32_t insert_idx = htab_hash("world", &htab);
	CHECK(insert_idx != 0);
	/* Second call with same key should return the same slot */
	uint32_t lookup_idx = htab_hash("world", &htab);
	CHECK(lookup_idx == insert_idx);
	htab_destroy(&htab);
}

TEST(htab_hash_different_keys_different_slots)
{
	htab_table htab = HTAB_EMPTY;
	htab_create(64, &htab);
	uint32_t a = htab_hash("alpha", &htab);
	uint32_t b = htab_hash("beta",  &htab);
	CHECK(a != b);
	htab_destroy(&htab);
}

TEST(htab_hash_data_pointer_stored)
{
	htab_table htab = HTAB_EMPTY;
	htab_create(64, &htab);
	uint32_t idx = htab_hash("key", &htab);
	CHECK(htab.table[idx].str != NULL);
	CHECK(strcmp(htab.table[idx].str, "key") == 0);
	htab_destroy(&htab);
}

TEST(htab_hash_many_entries)
{
	htab_table htab = HTAB_EMPTY;
	htab_create(64, &htab);
	char key[32];
	for (int i = 0; i < 20; i++) {
		snprintf(key, sizeof(key), "key_%d", i);
		CHECK(htab_hash(key, &htab) != 0);
	}
	CHECK(htab.filled == 20);
	htab_destroy(&htab);
}

/* ================================================================== */
/* StrArray tests                                                      */
/* ================================================================== */

TEST(strarray_create_initializes)
{
	StrArray arr;
	StrArrayCreate(&arr, 8);
	CHECK(arr.String != NULL);
	CHECK(arr.Index == 0);
	StrArrayDestroy(&arr);
}

TEST(strarray_add_with_dup)
{
	StrArray arr;
	StrArrayCreate(&arr, 4);
	int32_t idx = StrArrayAdd(&arr, "hello", TRUE);
	CHECK(idx == 0);
	CHECK(arr.Index == 1);
	CHECK(arr.String[0] != NULL);
	CHECK(strcmp(arr.String[0], "hello") == 0);
	StrArrayDestroy(&arr);
}

TEST(strarray_add_without_dup)
{
	StrArray arr;
	const char *literal = "world";
	StrArrayCreate(&arr, 4);
	int32_t idx = StrArrayAdd(&arr, literal, FALSE);
	CHECK(idx == 0);
	CHECK(arr.String[0] == literal);  /* same pointer */
	/* Prevent StrArrayDestroy from freeing a string literal */
	arr.String[0] = NULL;
	arr.Index = 0;
	StrArrayDestroy(&arr);
}

TEST(strarray_find_present)
{
	StrArray arr;
	StrArrayCreate(&arr, 4);
	StrArrayAdd(&arr, "alpha", TRUE);
	StrArrayAdd(&arr, "beta",  TRUE);
	int32_t pos = StrArrayFind(&arr, "beta");
	CHECK(pos == 1);
	StrArrayDestroy(&arr);
}

TEST(strarray_find_absent)
{
	StrArray arr;
	StrArrayCreate(&arr, 4);
	StrArrayAdd(&arr, "one", TRUE);
	int32_t pos = StrArrayFind(&arr, "two");
	CHECK(pos < 0);
	StrArrayDestroy(&arr);
}

TEST(strarray_find_null_str)
{
	StrArray arr;
	StrArrayCreate(&arr, 4);
	int32_t pos = StrArrayFind(&arr, NULL);
	CHECK(pos < 0);
	StrArrayDestroy(&arr);
}

TEST(strarray_add_unique_adds_new)
{
	StrArray arr;
	StrArrayCreate(&arr, 4);
	int32_t idx = StrArrayAddUnique(&arr, "new_item", TRUE);
	CHECK(idx == 0);
	CHECK(arr.Index == 1);
	StrArrayDestroy(&arr);
}

TEST(strarray_add_unique_skips_duplicate)
{
	StrArray arr;
	StrArrayCreate(&arr, 4);
	StrArrayAdd(&arr, "dup", TRUE);
	int32_t idx = StrArrayAddUnique(&arr, "dup", TRUE);
	/* Returns existing index when item already present */
	CHECK(idx == 0);
	CHECK(arr.Index == 1);     /* count unchanged */
	StrArrayDestroy(&arr);
}

TEST(strarray_clear_resets_index)
{
	StrArray arr;
	StrArrayCreate(&arr, 4);
	StrArrayAdd(&arr, "a", TRUE);
	StrArrayAdd(&arr, "b", TRUE);
	CHECK(arr.Index == 2);
	StrArrayClear(&arr);
	CHECK(arr.Index == 0);
	CHECK(arr.String != NULL);  /* backing array kept */
	StrArrayDestroy(&arr);
}

TEST(strarray_grows_beyond_initial)
{
	StrArray arr;
	StrArrayCreate(&arr, 2);
	for (int i = 0; i < 10; i++) {
		char buf[16];
		snprintf(buf, sizeof(buf), "item_%d", i);
		StrArrayAdd(&arr, buf, TRUE);
	}
	CHECK(arr.Index == 10);
	StrArrayDestroy(&arr);
}

TEST(strarray_empty_string_entry)
{
	StrArray arr;
	StrArrayCreate(&arr, 4);
	int32_t idx = StrArrayAdd(&arr, "", TRUE);
	CHECK(idx == 0);
	CHECK(arr.String[0] != NULL);
	CHECK(arr.String[0][0] == '\0');
	StrArrayDestroy(&arr);
}

TEST(strarray_destroy_null_safe)
{
	StrArrayDestroy(NULL);   /* must not crash */
	CHECK(1);
}

/* ================================================================== */
/* CompareGUID tests                                                   */
/* ================================================================== */

static const GUID GUID_A = {
	0x12345678, 0x1234, 0x1234,
	{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 }
};

static const GUID GUID_B = {
	0xdeadbeef, 0xcafe, 0xbabe,
	{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe }
};

TEST(compare_guid_equal)
{
	GUID copy = GUID_A;
	CHECK(CompareGUID(&GUID_A, &copy) == TRUE);
}

TEST(compare_guid_different)
{
	CHECK(CompareGUID(&GUID_A, &GUID_B) == FALSE);
}

TEST(compare_guid_null_first)
{
	CHECK(CompareGUID(NULL, &GUID_A) == FALSE);
}

TEST(compare_guid_null_second)
{
	CHECK(CompareGUID(&GUID_A, NULL) == FALSE);
}

TEST(compare_guid_both_null)
{
	CHECK(CompareGUID(NULL, NULL) == FALSE);
}

TEST(compare_guid_differ_in_data4)
{
	GUID a = GUID_A, b = GUID_A;
	b.Data4[7] ^= 0xFF;   /* flip last byte */
	CHECK(CompareGUID(&a, &b) == FALSE);
}

/* ================================================================== */
/* main                                                                */
/* ================================================================== */

int main(void)
{
	printf("=== stdfn common (htab / StrArray / CompareGUID) ===\n");

	printf("\n  htab_create / htab_destroy\n");
	RUN(htab_create_null_table);
	RUN(htab_create_valid);
	RUN(htab_create_small_size);
	RUN(htab_create_zero_size);
	RUN(htab_destroy_clears_fields);
	RUN(htab_destroy_null_safe);
	RUN(htab_destroy_empty_table);

	printf("\n  htab_hash\n");
	RUN(htab_hash_null_str);
	RUN(htab_hash_null_table);
	RUN(htab_hash_nonzero_for_string);
	RUN(htab_hash_insert_then_lookup);
	RUN(htab_hash_different_keys_different_slots);
	RUN(htab_hash_data_pointer_stored);
	RUN(htab_hash_many_entries);

	printf("\n  StrArray\n");
	RUN(strarray_create_initializes);
	RUN(strarray_add_with_dup);
	RUN(strarray_add_without_dup);
	RUN(strarray_find_present);
	RUN(strarray_find_absent);
	RUN(strarray_find_null_str);
	RUN(strarray_add_unique_adds_new);
	RUN(strarray_add_unique_skips_duplicate);
	RUN(strarray_clear_resets_index);
	RUN(strarray_grows_beyond_initial);
	RUN(strarray_empty_string_entry);
	RUN(strarray_destroy_null_safe);

	printf("\n  CompareGUID\n");
	RUN(compare_guid_equal);
	RUN(compare_guid_different);
	RUN(compare_guid_null_first);
	RUN(compare_guid_null_second);
	RUN(compare_guid_both_null);
	RUN(compare_guid_differ_in_data4);

	TEST_RESULTS();
}
