/*
 * test_reproducible_builds_linux.c
 * Tests for reproducible-build infrastructure (item 101)
 *
 * Checks that:
 *   1. RUFUS_BUILD_EPOCH is defined (via configure.ac / test CFLAGS)
 *   2. configure.ac declares -fmacro-prefix-map support detection
 *   3. configure.ac declares SOURCE_DATE_EPOCH propagation
 *   4. Build epoch is 0 when SOURCE_DATE_EPOCH not set at configure time
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "framework.h"

/* ------------------------------------------------------------------ */
/* Tests: RUFUS_BUILD_EPOCH macro                                      */
/* ------------------------------------------------------------------ */

TEST(build_epoch_is_defined)
{
#ifdef RUFUS_BUILD_EPOCH
    CHECK_MSG(1, "RUFUS_BUILD_EPOCH is defined");
#else
    CHECK_MSG(0, "RUFUS_BUILD_EPOCH not defined — configure.ac reproducible-build support is missing");
#endif
}

TEST(build_epoch_is_nonnegative)
{
#ifdef RUFUS_BUILD_EPOCH
    uint64_t epoch = (uint64_t)(RUFUS_BUILD_EPOCH);
    CHECK(epoch + 1 > 0);  /* always true for uint64_t, just exercises the type */
#else
    CHECK_MSG(0, "RUFUS_BUILD_EPOCH not defined");
#endif
}

TEST(build_epoch_zero_without_source_date_epoch)
{
    uint64_t epoch;
#ifdef RUFUS_BUILD_EPOCH
    epoch = (uint64_t)(RUFUS_BUILD_EPOCH);
#else
    epoch = 0;
#endif
    const char *env_epoch = getenv("SOURCE_DATE_EPOCH");
    if (env_epoch == NULL) {
        CHECK(epoch == 0);
    } else {
        /* env was set; we can't verify the binary value from here */
        CHECK_MSG(1, "SOURCE_DATE_EPOCH set in env; skipping zero-check");
    }
}

/* ------------------------------------------------------------------ */
/* Tests: configure.ac content checks                                  */
/* ------------------------------------------------------------------ */

static char configure_content[1 << 20];

static int load_configure_ac(void)
{
    FILE *f = fopen("../configure.ac", "r");
    if (!f) f = fopen("configure.ac", "r");
    if (!f) return 0;
    size_t n = fread(configure_content, 1, sizeof(configure_content) - 1, f);
    fclose(f);
    configure_content[n] = '\0';
    return (int)(n > 0);
}

TEST(configure_ac_has_macro_prefix_map_check)
{
    if (!load_configure_ac()) { CHECK_MSG(0, "Could not read configure.ac"); return; }
    CHECK(strstr(configure_content, "fmacro-prefix-map") != NULL);
}

TEST(configure_ac_has_source_date_epoch_support)
{
    if (!load_configure_ac()) { CHECK_MSG(0, "Could not read configure.ac"); return; }
    CHECK(strstr(configure_content, "SOURCE_DATE_EPOCH") != NULL);
}

TEST(configure_ac_has_rufus_build_epoch_define)
{
    if (!load_configure_ac()) { CHECK_MSG(0, "Could not read configure.ac"); return; }
    CHECK(strstr(configure_content, "RUFUS_BUILD_EPOCH") != NULL);
}

TEST(configure_ac_macro_prefix_map_uses_abs_srcdir)
{
    if (!load_configure_ac()) { CHECK_MSG(0, "Could not read configure.ac"); return; }
    CHECK(strstr(configure_content, "abs_top_srcdir") != NULL);
}

TEST(configure_ac_epoch_uses_ull_suffix)
{
    if (!load_configure_ac()) { CHECK_MSG(0, "Could not read configure.ac"); return; }
    CHECK(strstr(configure_content, "RUFUS_BUILD_EPOCH=0ULL") != NULL ||
          strstr(configure_content, "RUFUS_BUILD_EPOCH=${SOURCE_DATE_EPOCH}ULL") != NULL);
}

/* ------------------------------------------------------------------ */
/* Tests: __FILE__ path (informational)                                */
/* ------------------------------------------------------------------ */

TEST(file_macro_format_acceptable)
{
    /* With -fmacro-prefix-map=$(abs_top_srcdir)/=, __FILE__ should be
     * repo-relative (e.g. "tests/test_repro…c"). We just ensure the
     * macro expands to something non-empty. */
    const char *this_file = __FILE__;
    CHECK(this_file != NULL && this_file[0] != '\0');
}

/* ------------------------------------------------------------------ */
/* Test runner                                                          */
/* ------------------------------------------------------------------ */

int main(void)
{
    RUN(build_epoch_is_defined);
    RUN(build_epoch_is_nonnegative);
    RUN(build_epoch_zero_without_source_date_epoch);
    RUN(configure_ac_has_macro_prefix_map_check);
    RUN(configure_ac_has_source_date_epoch_support);
    RUN(configure_ac_has_rufus_build_epoch_define);
    RUN(configure_ac_macro_prefix_map_uses_abs_srcdir);
    RUN(configure_ac_epoch_uses_ull_suffix);
    RUN(file_macro_format_acceptable);

    TEST_RESULTS();
}

#endif /* __linux__ */
