/*
 * test_fat32_common.c — Tests for common FAT32 helper functions
 *
 * Tests fat32_default_cluster_size() from src/common/format_fat32.c.
 * This function is portable (no OS I/O) and must behave identically
 * on Linux and Windows.
 *
 * Boundary conditions tested (from the MS specification):
 *   https://support.microsoft.com/en-us/help/140365/
 *     <  64 MB  →  512 bytes
 *     < 128 MB  →    1 KB
 *     < 256 MB  →    2 KB
 *     <   8 GB  →    4 KB
 *     <  16 GB  →    8 KB
 *     <  32 GB  → 16 KB
 *     <   2 TB  → 32 KB
 *     >= 2 TB   → 64 KB
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "framework.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "../src/common/format_fat32.h"

/* ------------------------------------------------------------------ */
/* Stubs for anything pulled in by rufus.h / format_fat32.h            */
/* ------------------------------------------------------------------ */

/* None needed — fat32_default_cluster_size() takes only a uint64_t    */
/* and returns a uint32_t.  It uses no globals and calls nothing else.  */

/* ------------------------------------------------------------------ */
/* Convenience: expected values matching the MS/Linux spec              */
/* ------------------------------------------------------------------ */
#define BYTES_512     512u
#define BYTES_1K      1024u
#define BYTES_2K      2048u
#define BYTES_4K      4096u
#define BYTES_8K      8192u
#define BYTES_16K     16384u
#define BYTES_32K     32768u
#define BYTES_64K     65536u

#define KB  1024ULL
#define MB  (1024ULL * KB)
#define GB  (1024ULL * MB)
#define TB  (1024ULL * GB)

/* ------------------------------------------------------------------ */
/* Test: partition sizes well inside each bucket                        */
/* ------------------------------------------------------------------ */

TEST(cluster_size_32mb_gives_512)
{
    CHECK_INT_EQ((int)BYTES_512, (int)fat32_default_cluster_size(32 * MB));
}

TEST(cluster_size_64mb_gives_1k)
{
    /* 64 MB is the first byte of the "< 128 MB" bucket */
    CHECK_INT_EQ((int)BYTES_1K, (int)fat32_default_cluster_size(64 * MB));
}

TEST(cluster_size_96mb_gives_1k)
{
    CHECK_INT_EQ((int)BYTES_1K, (int)fat32_default_cluster_size(96 * MB));
}

TEST(cluster_size_128mb_gives_2k)
{
    CHECK_INT_EQ((int)BYTES_2K, (int)fat32_default_cluster_size(128 * MB));
}

TEST(cluster_size_200mb_gives_2k)
{
    CHECK_INT_EQ((int)BYTES_2K, (int)fat32_default_cluster_size(200 * MB));
}

TEST(cluster_size_256mb_gives_4k)
{
    CHECK_INT_EQ((int)BYTES_4K, (int)fat32_default_cluster_size(256 * MB));
}

TEST(cluster_size_1gb_gives_4k)
{
    CHECK_INT_EQ((int)BYTES_4K, (int)fat32_default_cluster_size(1 * GB));
}

TEST(cluster_size_8gb_gives_8k)
{
    CHECK_INT_EQ((int)BYTES_8K, (int)fat32_default_cluster_size(8 * GB));
}

TEST(cluster_size_12gb_gives_8k)
{
    CHECK_INT_EQ((int)BYTES_8K, (int)fat32_default_cluster_size(12 * GB));
}

TEST(cluster_size_16gb_gives_16k)
{
    CHECK_INT_EQ((int)BYTES_16K, (int)fat32_default_cluster_size(16 * GB));
}

TEST(cluster_size_24gb_gives_16k)
{
    CHECK_INT_EQ((int)BYTES_16K, (int)fat32_default_cluster_size(24 * GB));
}

TEST(cluster_size_32gb_gives_32k)
{
    CHECK_INT_EQ((int)BYTES_32K, (int)fat32_default_cluster_size(32 * GB));
}

TEST(cluster_size_1tb_gives_32k)
{
    CHECK_INT_EQ((int)BYTES_32K, (int)fat32_default_cluster_size(1 * TB));
}

/* 2 TB is the boundary between 32 KB and 64 KB */
TEST(cluster_size_2tb_gives_64k)
{
    CHECK_INT_EQ((int)BYTES_64K, (int)fat32_default_cluster_size(2 * TB));
}

TEST(cluster_size_4tb_gives_64k)
{
    CHECK_INT_EQ((int)BYTES_64K, (int)fat32_default_cluster_size(4 * TB));
}

/* ------------------------------------------------------------------ */
/* Boundary: one byte before the transition point                       */
/* ------------------------------------------------------------------ */

TEST(cluster_size_below_64mb_boundary)
{
    /* 64MB - 1 byte should still be in the 512-byte bucket */
    CHECK_INT_EQ((int)BYTES_512, (int)fat32_default_cluster_size(64 * MB - 1));
}

TEST(cluster_size_below_128mb_boundary)
{
    CHECK_INT_EQ((int)BYTES_1K, (int)fat32_default_cluster_size(128 * MB - 1));
}

TEST(cluster_size_below_256mb_boundary)
{
    CHECK_INT_EQ((int)BYTES_2K, (int)fat32_default_cluster_size(256 * MB - 1));
}

TEST(cluster_size_below_8gb_boundary)
{
    CHECK_INT_EQ((int)BYTES_4K, (int)fat32_default_cluster_size(8 * GB - 1));
}

TEST(cluster_size_below_16gb_boundary)
{
    CHECK_INT_EQ((int)BYTES_8K, (int)fat32_default_cluster_size(16 * GB - 1));
}

TEST(cluster_size_below_32gb_boundary)
{
    CHECK_INT_EQ((int)BYTES_16K, (int)fat32_default_cluster_size(32 * GB - 1));
}

TEST(cluster_size_below_2tb_boundary)
{
    CHECK_INT_EQ((int)BYTES_32K, (int)fat32_default_cluster_size(2 * TB - 1));
}

/* ------------------------------------------------------------------ */
/* Edge cases                                                           */
/* ------------------------------------------------------------------ */

TEST(cluster_size_zero_partition)
{
    /* Zero bytes: smallest bucket (512) — degenerate but must not crash */
    CHECK_INT_EQ((int)BYTES_512, (int)fat32_default_cluster_size(0));
}

TEST(cluster_size_one_byte)
{
    CHECK_INT_EQ((int)BYTES_512, (int)fat32_default_cluster_size(1));
}

TEST(cluster_size_result_is_power_of_two)
{
    /* Every returned cluster size must be a power of two */
    uint64_t test_sizes[] = {
        1, 32 * MB, 64 * MB, 128 * MB, 256 * MB,
        1 * GB, 8 * GB, 16 * GB, 32 * GB, 1 * TB, 2 * TB, 4 * TB
    };
    for (int i = 0; i < (int)(sizeof(test_sizes) / sizeof(test_sizes[0])); i++) {
        uint32_t cs = fat32_default_cluster_size(test_sizes[i]);
        CHECK((cs & (cs - 1)) == 0);   /* power-of-two check */
    }
}

TEST(cluster_size_result_in_valid_range)
{
    /* The result must always be between 512 bytes and 64 KB */
    uint64_t test_sizes[] = {
        0, 1, 32 * MB, 64 * MB, 4 * GB, 2 * TB, 4 * TB
    };
    for (int i = 0; i < (int)(sizeof(test_sizes) / sizeof(test_sizes[0])); i++) {
        uint32_t cs = fat32_default_cluster_size(test_sizes[i]);
        CHECK(cs >= 512);
        CHECK(cs <= 65536);
    }
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    /* --- boundary / mid-bucket tests --- */
    RUN(cluster_size_32mb_gives_512);
    RUN(cluster_size_64mb_gives_1k);
    RUN(cluster_size_96mb_gives_1k);
    RUN(cluster_size_128mb_gives_2k);
    RUN(cluster_size_200mb_gives_2k);
    RUN(cluster_size_256mb_gives_4k);
    RUN(cluster_size_1gb_gives_4k);
    RUN(cluster_size_8gb_gives_8k);
    RUN(cluster_size_12gb_gives_8k);
    RUN(cluster_size_16gb_gives_16k);
    RUN(cluster_size_24gb_gives_16k);
    RUN(cluster_size_32gb_gives_32k);
    RUN(cluster_size_1tb_gives_32k);
    RUN(cluster_size_2tb_gives_64k);
    RUN(cluster_size_4tb_gives_64k);

    /* --- off-by-one boundary --- */
    RUN(cluster_size_below_64mb_boundary);
    RUN(cluster_size_below_128mb_boundary);
    RUN(cluster_size_below_256mb_boundary);
    RUN(cluster_size_below_8gb_boundary);
    RUN(cluster_size_below_16gb_boundary);
    RUN(cluster_size_below_32gb_boundary);
    RUN(cluster_size_below_2tb_boundary);

    /* --- edge cases --- */
    RUN(cluster_size_zero_partition);
    RUN(cluster_size_one_byte);
    RUN(cluster_size_result_is_power_of_two);
    RUN(cluster_size_result_in_valid_range);

    TEST_RESULTS();
}
