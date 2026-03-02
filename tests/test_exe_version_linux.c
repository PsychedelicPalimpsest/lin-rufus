/*
 * test_exe_version_linux.c — Tests for GetExecutableVersion() on Linux
 *
 * Strategy: TDD — tests written before the implementation.
 *
 * GetExecutableVersion(path) opens an ELF binary, scans for the embedded
 * "RUFUS:VER:MAJOR.MINOR.PATCH\n" marker, and returns a populated version_t.
 *
 *   path == NULL  → read /proc/self/exe (the running binary itself)
 *   path != NULL  → read the specified file
 *
 * The test binary itself embeds the marker (via stdfn.c → version.h),
 * so the NULL-path tests can verify a round-trip: compile-time constants
 * → marker in binary → parsed back by GetExecutableVersion.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __linux__
int main(void) { return 0; }
#else

#include "windows.h"
#include "rufus.h"
#include "framework.h"
#include "version.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* -----------------------------------------------------------------------
 * Minimal stubs required by stdfn.c
 * ----------------------------------------------------------------------- */
void uprintf(const char *fmt, ...) { (void)fmt; }

/* Helper: write a temp file containing the given bytes, return path (caller free()s) */
static char* write_temp_file(const void *data, size_t len)
{
    char *path = strdup("/tmp/test_exe_ver_XXXXXX");
    if (!path) return NULL;
    int fd = mkstemp(path);
    if (fd < 0) { free(path); return NULL; }
    if (write(fd, data, len) != (ssize_t)len) {
        close(fd); unlink(path); free(path); return NULL;
    }
    close(fd);
    return path;
}

/* -----------------------------------------------------------------------
 * NULL path: reads /proc/self/exe which contains the marker via stdfn.c
 * ----------------------------------------------------------------------- */

TEST(null_path_returns_non_null)
{
    /* The test binary links stdfn.c which embeds the version marker */
    version_t *v = GetExecutableVersion(NULL);
    CHECK(v != NULL);
}

TEST(null_path_major_matches_build)
{
    version_t *v = GetExecutableVersion(NULL);
    CHECK(v != NULL);
    CHECK_INT_EQ(RUFUS_LINUX_VERSION_MAJOR, (int)v->Major);
}

TEST(null_path_minor_matches_build)
{
    version_t *v = GetExecutableVersion(NULL);
    CHECK(v != NULL);
    CHECK_INT_EQ(RUFUS_LINUX_VERSION_MINOR, (int)v->Minor);
}

TEST(null_path_micro_matches_build)
{
    version_t *v = GetExecutableVersion(NULL);
    CHECK(v != NULL);
    CHECK_INT_EQ(RUFUS_LINUX_VERSION_PATCH, (int)v->Micro);
}

TEST(null_path_nano_is_zero)
{
    version_t *v = GetExecutableVersion(NULL);
    CHECK(v != NULL);
    CHECK_INT_EQ(0, (int)v->Nano);
}

/* -----------------------------------------------------------------------
 * Explicit path: temp file with a known marker embedded
 * ----------------------------------------------------------------------- */

TEST(file_with_marker_returns_non_null)
{
    const char marker[] = "RUFUS:VER:3.5.2\n";
    char *path = write_temp_file(marker, sizeof(marker) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v != NULL);
}

TEST(file_with_marker_major_correct)
{
    const char marker[] = "RUFUS:VER:3.5.2\n";
    char *path = write_temp_file(marker, sizeof(marker) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v != NULL);
    CHECK_INT_EQ(3, (int)v->Major);
}

TEST(file_with_marker_minor_correct)
{
    const char marker[] = "RUFUS:VER:3.5.2\n";
    char *path = write_temp_file(marker, sizeof(marker) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v != NULL);
    CHECK_INT_EQ(5, (int)v->Minor);
}

TEST(file_with_marker_micro_correct)
{
    const char marker[] = "RUFUS:VER:3.5.2\n";
    char *path = write_temp_file(marker, sizeof(marker) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v != NULL);
    CHECK_INT_EQ(2, (int)v->Micro);
}

TEST(file_with_marker_nano_is_zero)
{
    const char marker[] = "RUFUS:VER:3.5.2\n";
    char *path = write_temp_file(marker, sizeof(marker) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v != NULL);
    CHECK_INT_EQ(0, (int)v->Nano);
}

TEST(file_with_large_version_numbers)
{
    const char marker[] = "RUFUS:VER:100.200.300\n";
    char *path = write_temp_file(marker, sizeof(marker) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v != NULL);
    CHECK_INT_EQ(100, (int)v->Major);
    CHECK_INT_EQ(200, (int)v->Minor);
    CHECK_INT_EQ(300, (int)v->Micro);
}

TEST(file_with_marker_preceded_by_garbage)
{
    /* Marker is preceded by 512 bytes of zeros — simulates real binary */
    const size_t prefix_len = 512;
    const char marker[] = "RUFUS:VER:7.2.1\n";
    size_t total = prefix_len + sizeof(marker) - 1;
    char *buf = calloc(1, total);
    CHECK(buf != NULL);
    memcpy(buf + prefix_len, marker, sizeof(marker) - 1);
    char *path = write_temp_file(buf, total);
    free(buf);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v != NULL);
    CHECK_INT_EQ(7, (int)v->Major);
    CHECK_INT_EQ(2, (int)v->Minor);
    CHECK_INT_EQ(1, (int)v->Micro);
}

TEST(file_with_marker_at_chunk_boundary)
{
    /*
     * Put the marker exactly at a chunk boundary (4096 bytes in).
     * This tests that multi-chunk scanning works correctly.
     */
    const size_t prefix_len = 4096;
    const char marker[] = "RUFUS:VER:9.0.1\n";
    size_t total = prefix_len + sizeof(marker) - 1;
    char *buf = calloc(1, total);
    CHECK(buf != NULL);
    memcpy(buf + prefix_len, marker, sizeof(marker) - 1);
    char *path = write_temp_file(buf, total);
    free(buf);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v != NULL);
    CHECK_INT_EQ(9, (int)v->Major);
    CHECK_INT_EQ(0, (int)v->Minor);
    CHECK_INT_EQ(1, (int)v->Micro);
}

/* -----------------------------------------------------------------------
 * Error conditions
 * ----------------------------------------------------------------------- */

TEST(file_without_marker_returns_null)
{
    const char data[] = "This file has no version marker in it whatsoever.";
    char *path = write_temp_file(data, sizeof(data) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v == NULL);
}

TEST(empty_file_returns_null)
{
    const char data[] = "";
    char *path = write_temp_file(data, 0);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v == NULL);
}

TEST(nonexistent_file_returns_null)
{
    version_t *v = GetExecutableVersion("/nonexistent/path/to/binary");
    CHECK(v == NULL);
}

TEST(malformed_version_not_numeric_returns_null)
{
    const char marker[] = "RUFUS:VER:bad.version.string\n";
    char *path = write_temp_file(marker, sizeof(marker) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v == NULL);
}

TEST(partial_version_two_parts_returns_null)
{
    /* Only "MAJOR.MINOR" without patch component → must not return a version */
    const char marker[] = "RUFUS:VER:4.13\n";
    char *path = write_temp_file(marker, sizeof(marker) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v == NULL);
}

TEST(prefix_only_no_version_returns_null)
{
    const char marker[] = "RUFUS:VER:";
    char *path = write_temp_file(marker, sizeof(marker) - 1);
    CHECK(path != NULL);
    version_t *v = GetExecutableVersion(path);
    unlink(path); free(path);
    CHECK(v == NULL);
}

/* -----------------------------------------------------------------------
 * Consistency checks
 * ----------------------------------------------------------------------- */

TEST(null_path_equals_self_path)
{
    /*
     * GetExecutableVersion(NULL) and GetExecutableVersion("/proc/self/exe")
     * must agree on the version fields.
     */
    version_t *vn = GetExecutableVersion(NULL);
    version_t *vp = GetExecutableVersion("/proc/self/exe");
    CHECK(vn != NULL);
    CHECK(vp != NULL);
    CHECK_INT_EQ((int)vn->Major, (int)vp->Major);
    CHECK_INT_EQ((int)vn->Minor, (int)vp->Minor);
    CHECK_INT_EQ((int)vn->Micro, (int)vp->Micro);
    CHECK_INT_EQ((int)vn->Nano,  (int)vp->Nano);
}

int main(void)
{
    /* NULL-path tests: require marker in this binary (provided by stdfn.c) */
    RUN(null_path_returns_non_null);
    RUN(null_path_major_matches_build);
    RUN(null_path_minor_matches_build);
    RUN(null_path_micro_matches_build);
    RUN(null_path_nano_is_zero);

    /* Temp-file tests: explicitly controlled content */
    RUN(file_with_marker_returns_non_null);
    RUN(file_with_marker_major_correct);
    RUN(file_with_marker_minor_correct);
    RUN(file_with_marker_micro_correct);
    RUN(file_with_marker_nano_is_zero);
    RUN(file_with_large_version_numbers);
    RUN(file_with_marker_preceded_by_garbage);
    RUN(file_with_marker_at_chunk_boundary);

    /* Error conditions */
    RUN(file_without_marker_returns_null);
    RUN(empty_file_returns_null);
    RUN(nonexistent_file_returns_null);
    RUN(malformed_version_not_numeric_returns_null);
    RUN(partial_version_two_parts_returns_null);
    RUN(prefix_only_no_version_returns_null);

    /* Consistency */
    RUN(null_path_equals_self_path);

    TEST_RESULTS();
}

#endif /* __linux__ */
