/*
 * test_stdfn.c — Unit tests for htab_* and StrArray_* functions
 *               defined in src/linux/stdfn.c (Linux) and
 *               src/windows/stdfn.c (Windows).
 *
 * Both builds share the same abstract interface declared in rufus.h.
 * These tests are Linux-only because htab is a Linux porting target
 * (the Windows implementation already works as part of the product).
 */

#ifndef __linux__
int main(void) { return 0; } /* Skip on non-Linux */
#else

#include "windows.h"
#include "rufus.h"
#include "framework.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sched.h>

/* --------------------------------------------------------------------------
 * Minimal stubs required by stdfn.c
 * -------------------------------------------------------------------------- */
void uprintf(const char *fmt, ...) { (void)fmt; }

/* ===========================================================================
 * htab_create tests
 * ========================================================================= */

TEST(htab_create_null_table)
{
    /* Passing NULL table pointer must return FALSE */
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

TEST(htab_create_small)
{
    /* Creating with a small size should still work (rounds up to prime) */
    htab_table htab = HTAB_EMPTY;
    CHECK(htab_create(1, &htab) == TRUE);
    CHECK(htab.table != NULL);
    htab_destroy(&htab);
}

TEST(htab_create_zero)
{
    /*
     * Size 0 is unusual but the implementation ORs with 1 first, so it
     * should still allocate a minimal prime-sized table.
     */
    htab_table htab = HTAB_EMPTY;
    BOOL ok = htab_create(0, &htab);
    if (ok)
        htab_destroy(&htab);
    /* Either TRUE or FALSE is acceptable — just must not crash */
    CHECK(1);
}

/* ===========================================================================
 * htab_hash NULL-input edge cases
 * ========================================================================= */

TEST(htab_hash_null_str)
{
    htab_table htab = HTAB_EMPTY;
    CHECK(htab_create(64, &htab) == TRUE);
    /* NULL string must return 0 (not crash) */
    CHECK(htab_hash(NULL, &htab) == 0);
    htab_destroy(&htab);
}

TEST(htab_hash_null_table)
{
    CHECK(htab_hash("hello", NULL) == 0);
}

TEST(htab_hash_both_null)
{
    CHECK(htab_hash(NULL, NULL) == 0);
}

/* ===========================================================================
 * htab_hash insert and lookup
 * ========================================================================= */

TEST(htab_hash_nonzero_return)
{
    htab_table htab = HTAB_EMPTY;
    CHECK(htab_create(64, &htab) == TRUE);
    uint32_t idx = htab_hash("hello", &htab);
    CHECK(idx != 0);
    CHECK(htab.filled == 1);
    htab_destroy(&htab);
}

TEST(htab_hash_lookup_same_index)
{
    htab_table htab = HTAB_EMPTY;
    CHECK(htab_create(64, &htab) == TRUE);
    uint32_t idx1 = htab_hash("hello", &htab);
    uint32_t idx2 = htab_hash("hello", &htab);
    CHECK(idx1 != 0);
    /* Second call on same string must return the SAME slot (no double insert) */
    CHECK(idx1 == idx2);
    CHECK(htab.filled == 1);     /* Only one entry inserted */
    htab_destroy(&htab);
}

TEST(htab_hash_different_strings_different_slots)
{
    htab_table htab = HTAB_EMPTY;
    CHECK(htab_create(64, &htab) == TRUE);
    uint32_t a = htab_hash("hello", &htab);
    uint32_t b = htab_hash("world", &htab);
    CHECK(a != 0);
    CHECK(b != 0);
    CHECK(a != b);
    CHECK(htab.filled == 2);
    htab_destroy(&htab);
}

TEST(htab_hash_data_pointer)
{
    htab_table htab = HTAB_EMPTY;
    CHECK(htab_create(64, &htab) == TRUE);
    uint32_t idx = htab_hash("mykey", &htab);
    CHECK(idx != 0);
    if (idx == 0 || htab.table == NULL) goto cleanup_dp;
    /* Store and retrieve user data pointer */
    htab.table[idx].data = (void*)(uintptr_t)42;
    {
        uint32_t idx2 = htab_hash("mykey", &htab);
        CHECK(idx2 == idx);
        CHECK((uintptr_t)htab.table[idx2].data == 42);
    }
cleanup_dp:
    htab_destroy(&htab);
}

TEST(htab_hash_str_content)
{
    /* Verify the stored string is a copy of what was passed */
    htab_table htab = HTAB_EMPTY;
    CHECK(htab_create(64, &htab) == TRUE);
    char buf[] = "dynamic_key";
    uint32_t idx = htab_hash(buf, &htab);
    CHECK(idx != 0);
    if (idx == 0 || htab.table == NULL) goto cleanup_sc;
    CHECK(htab.table[idx].str != NULL);
    CHECK(strcmp(htab.table[idx].str, "dynamic_key") == 0);
    /* The stored string must be a copy, not the same pointer */
    CHECK(htab.table[idx].str != buf);
cleanup_sc:
    htab_destroy(&htab);
}

TEST(htab_hash_many_entries)
{
    /*
     * Insert a known set of strings and verify each can be looked up and
     * returns a consistent index.
     */
    static const char *keys[] = {
        "alpha", "beta", "gamma", "delta", "epsilon",
        "zeta", "eta", "theta", "iota", "kappa",
        "lambda", "mu", "nu", "xi", "omicron",
        "pi", "rho", "sigma", "tau", "upsilon"
    };
    const int N = (int)(sizeof(keys) / sizeof(keys[0]));
    uint32_t saved[20];

    htab_table htab = HTAB_EMPTY;
    /* 257 is a reasonable prime larger than the number of keys */
    CHECK(htab_create(257, &htab) == TRUE);

    for (int i = 0; i < N; i++) {
        saved[i] = htab_hash((char*)keys[i], &htab);
        CHECK(saved[i] != 0);
    }
    CHECK((int)htab.filled == N);

    /* Re-lookup every key: must return the same slot */
    for (int i = 0; i < N; i++) {
        uint32_t idx = htab_hash((char*)keys[i], &htab);
        CHECK(idx == saved[i]);
    }

    /* All slots still distinct */
    for (int i = 0; i < N; i++)
        for (int j = i + 1; j < N; j++)
            CHECK(saved[i] != saved[j]);

    htab_destroy(&htab);
}

TEST(htab_hash_uppercase)
{
    /* Two strings that differ only in case must hash to different slots */
    htab_table htab = HTAB_EMPTY;
    CHECK(htab_create(64, &htab) == TRUE);
    uint32_t lower = htab_hash("usbstor", &htab);
    uint32_t upper = htab_hash("USBSTOR", &htab);
    CHECK(lower != 0);
    CHECK(upper != 0);
    CHECK(lower != upper);
    htab_destroy(&htab);
}

/* ===========================================================================
 * htab_destroy
 * ========================================================================= */

TEST(htab_destroy_clears_fields)
{
    htab_table htab = HTAB_EMPTY;
    CHECK(htab_create(64, &htab) == TRUE);
    htab_hash("a", &htab);
    htab_hash("b", &htab);
    htab_destroy(&htab);
    CHECK(htab.table == NULL);
    CHECK(htab.size == 0);
    CHECK(htab.filled == 0);
}

TEST(htab_destroy_null)
{
    /* Destroy of NULL pointer must not crash */
    htab_destroy(NULL);
    CHECK(1);
}

TEST(htab_destroy_empty)
{
    /* Destroy of an empty (never created) table must not crash */
    htab_table htab = HTAB_EMPTY;
    htab_destroy(&htab);
    CHECK(1);
}

/* ===========================================================================
 * StrArray tests
 * ========================================================================= */

TEST(strarray_create)
{
    StrArray arr;
    StrArrayCreate(&arr, 16);
    CHECK(arr.String != NULL);
    CHECK(arr.Max == 16);
    CHECK(arr.Index == 0);
    StrArrayDestroy(&arr);
}

TEST(strarray_add_and_find)
{
    StrArray arr;
    StrArrayCreate(&arr, 16);
    int32_t i = StrArrayAdd(&arr, "hello", TRUE);
    CHECK(i == 0);
    CHECK(arr.Index == 1);
    i = StrArrayAdd(&arr, "world", TRUE);
    CHECK(i == 1);
    CHECK(arr.Index == 2);
    CHECK(StrArrayFind(&arr, "hello") == 0);
    CHECK(StrArrayFind(&arr, "world") == 1);
    CHECK(StrArrayFind(&arr, "missing") == -1);
    StrArrayDestroy(&arr);
}

TEST(strarray_add_unique)
{
    StrArray arr;
    StrArrayCreate(&arr, 16);
    StrArrayAdd(&arr, "foo", TRUE);
    /* Adding a duplicate via AddUnique must NOT grow the array */
    int32_t idx = StrArrayAddUnique(&arr, "foo", TRUE);
    CHECK(idx == 0);
    CHECK(arr.Index == 1);
    /* Adding a new entry must grow it */
    idx = StrArrayAddUnique(&arr, "bar", TRUE);
    CHECK(idx == 1);
    CHECK(arr.Index == 2);
    StrArrayDestroy(&arr);
}

TEST(strarray_clear)
{
    StrArray arr;
    StrArrayCreate(&arr, 8);
    StrArrayAdd(&arr, "a", TRUE);
    StrArrayAdd(&arr, "b", TRUE);
    StrArrayClear(&arr);
    CHECK(arr.Index == 0);
    /* String pointers should be NULL after clear */
    CHECK(arr.String[0] == NULL);
    CHECK(arr.String[1] == NULL);
    /* Can re-add after clear */
    int32_t i = StrArrayAdd(&arr, "c", TRUE);
    CHECK(i == 0);
    StrArrayDestroy(&arr);
}

TEST(strarray_destroy)
{
    StrArray arr;
    StrArrayCreate(&arr, 4);
    StrArrayAdd(&arr, "x", TRUE);
    StrArrayDestroy(&arr);
    CHECK(arr.String == NULL);
    CHECK(arr.Max == 0);
}

TEST(strarray_find_null)
{
    StrArray arr;
    StrArrayCreate(&arr, 4);
    CHECK(StrArrayFind(NULL, "x") == -1);
    CHECK(StrArrayFind(&arr, NULL) == -1);
    StrArrayDestroy(&arr);
}

TEST(strarray_empty_string)
{
    StrArray arr;
    StrArrayCreate(&arr, 4);
    int32_t i = StrArrayAdd(&arr, "", TRUE);
    CHECK(i == 0);
    CHECK(StrArrayFind(&arr, "") == 0);
    StrArrayDestroy(&arr);
}

/* ===========================================================================
 * SetThreadAffinity tests
 * =========================================================================*/

extern BOOL SetThreadAffinity(DWORD_PTR* ta, size_t n);

/* NULL array returns FALSE */
TEST(set_thread_affinity_null_array)
{
    BOOL r = SetThreadAffinity(NULL, 4);
    CHECK(r == FALSE);
}

/* n=0 returns FALSE */
TEST(set_thread_affinity_zero_n)
{
    DWORD_PTR ta[1] = { 0xDEAD };
    BOOL r = SetThreadAffinity(ta, 0);
    CHECK(r == FALSE);
}

/* n=1 succeeds when at least 1 CPU is available */
TEST(set_thread_affinity_single_thread)
{
    cpu_set_t cs;
    CPU_ZERO(&cs);
    sched_getaffinity(0, sizeof(cs), &cs);
    int ncpu = CPU_COUNT(&cs);
    if (ncpu < 1) { return; }

    DWORD_PTR ta[1] = { 0 };
    BOOL r = SetThreadAffinity(ta, 1);
    CHECK(r == TRUE);
    CHECK(ta[0] != 0);
}

/* n=2 fills two distinct non-zero masks, masks are disjoint */
TEST(set_thread_affinity_two_threads)
{
    cpu_set_t cs;
    CPU_ZERO(&cs);
    sched_getaffinity(0, sizeof(cs), &cs);
    int ncpu = CPU_COUNT(&cs);
    if (ncpu < 2) { return; }

    DWORD_PTR ta[2] = { 0, 0 };
    BOOL r = SetThreadAffinity(ta, 2);
    CHECK(r == TRUE);
    CHECK(ta[0] != 0);
    CHECK(ta[1] != 0);
    /* Each CPU assigned to at most one thread */
    CHECK((ta[0] & ta[1]) == 0);
}

/* Masks cover all available CPUs (union = full CPU set) */
TEST(set_thread_affinity_covers_all_cpus)
{
    cpu_set_t cs;
    CPU_ZERO(&cs);
    sched_getaffinity(0, sizeof(cs), &cs);
    int ncpu = CPU_COUNT(&cs);
    if (ncpu < 2) { return; }

    DWORD_PTR ta[2] = { 0, 0 };
    BOOL r = SetThreadAffinity(ta, 2);
    CHECK(r == TRUE);

    DWORD_PTR expected = 0;
    for (int i = 0; i < CPU_SETSIZE && i < (int)(sizeof(DWORD_PTR) * 8); i++) {
        if (CPU_ISSET(i, &cs))
            expected |= (DWORD_PTR)1 << i;
    }
    CHECK((ta[0] | ta[1]) == expected);
}

/* ===========================================================================
 * ToLocaleName tests
 * =========================================================================*/

extern char* ToLocaleName(DWORD lang_id);

/* Returns non-NULL string */
TEST(to_locale_name_non_null)
{
    char* r = ToLocaleName(0);
    CHECK(r != NULL);
}

/* "en-US" locale returns "en-US" */
TEST(to_locale_name_en_us)
{
    setenv("LANG", "en_US.UTF-8", 1);
    char* r = ToLocaleName(0);
    CHECK(strcmp(r, "en-US") == 0);
}

/* underscore converted to hyphen */
TEST(to_locale_name_underscore_to_hyphen)
{
    setenv("LANG", "fr_FR.UTF-8", 1);
    char* r = ToLocaleName(0);
    CHECK(strcmp(r, "fr-FR") == 0);
}

/* LANG=C falls back to en-US */
TEST(to_locale_name_c_locale)
{
    setenv("LANG", "C", 1);
    char* r = ToLocaleName(0);
    CHECK(strcmp(r, "en-US") == 0);
}

/* Suffix after '@' is stripped */
TEST(to_locale_name_strips_modifier)
{
    setenv("LANG", "de_DE@euro", 1);
    char* r = ToLocaleName(0);
    CHECK(strcmp(r, "de-DE") == 0);
}

/* ===========================================================================
 * main
 * ========================================================================= */

int main(void)
{
    printf("=== htab_create ===\n");
    RUN(htab_create_null_table);
    RUN(htab_create_valid);
    RUN(htab_create_small);
    RUN(htab_create_zero);

    printf("\n=== htab_hash edge cases ===\n");
    RUN(htab_hash_null_str);
    RUN(htab_hash_null_table);
    RUN(htab_hash_both_null);

    printf("\n=== htab_hash insert/lookup ===\n");
    RUN(htab_hash_nonzero_return);
    RUN(htab_hash_lookup_same_index);
    RUN(htab_hash_different_strings_different_slots);
    RUN(htab_hash_data_pointer);
    RUN(htab_hash_str_content);
    RUN(htab_hash_many_entries);
    RUN(htab_hash_uppercase);

    printf("\n=== htab_destroy ===\n");
    RUN(htab_destroy_clears_fields);
    RUN(htab_destroy_null);
    RUN(htab_destroy_empty);

    printf("\n=== StrArray ===\n");
    RUN(strarray_create);
    RUN(strarray_add_and_find);
    RUN(strarray_add_unique);
    RUN(strarray_clear);
    RUN(strarray_destroy);
    RUN(strarray_find_null);
    RUN(strarray_empty_string);

    printf("\n=== SetThreadAffinity ===\n");
    RUN(set_thread_affinity_null_array);
    RUN(set_thread_affinity_zero_n);
    RUN(set_thread_affinity_single_thread);
    RUN(set_thread_affinity_two_threads);
    RUN(set_thread_affinity_covers_all_cpus);

    printf("\n=== ToLocaleName ===\n");
    RUN(to_locale_name_non_null);
    RUN(to_locale_name_en_us);
    RUN(to_locale_name_underscore_to_hyphen);
    RUN(to_locale_name_c_locale);
    RUN(to_locale_name_strips_modifier);

    TEST_RESULTS();
}

#endif /* __linux__ */
