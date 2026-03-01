/*
 * test_download_resume_linux.c — TDD tests for the download resume helpers.
 *
 * Tests get_partial_path(), has_partial_download(), get_partial_size(),
 * finalize_partial_download(), and abandon_partial_download() using
 * temporary files so no real network is needed.
 *
 * Build: see tests/Makefile entry for test_download_resume_linux.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "framework.h"
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/linux/download_resume.h"

/* ---- helpers ---- */

/* Create a temporary file with given content; returns its path (static buf). */
static char *make_named_tmpfile(const void *content, size_t len)
{
    static char path[256];
    int fd;
    snprintf(path, sizeof(path), "/tmp/rufus_dr_XXXXXX");
    fd = mkstemp(path);
    if (fd < 0) return NULL;
    if (len > 0 && write(fd, content, len) != (ssize_t)len) {
        close(fd);
        unlink(path);
        return NULL;
    }
    close(fd);
    return path;
}

/* Create a partial file for the given target path, with given content. */
static BOOL make_partial_file(const char *target, const void *content, size_t len)
{
    char partial[512];
    int fd;
    if (!get_partial_path(target, partial, sizeof(partial)))
        return FALSE;
    fd = open(partial, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return FALSE;
    if (len > 0 && write(fd, content, len) != (ssize_t)len) {
        close(fd);
        unlink(partial);
        return FALSE;
    }
    close(fd);
    return TRUE;
}

/* ---- get_partial_path tests ---- */

static void test_partial_path_appends_suffix(void)
{
    char buf[256];
    const char *result = get_partial_path("/tmp/foo.iso", buf, sizeof(buf));
    CHECK(result != NULL);
    CHECK(strcmp(result, "/tmp/foo.iso.partial") == 0);
}

static void test_partial_path_bare_filename(void)
{
    char buf[256];
    const char *result = get_partial_path("rufus.loc", buf, sizeof(buf));
    CHECK(result != NULL);
    CHECK(strcmp(result, "rufus.loc.partial") == 0);
}

static void test_partial_path_null_target_returns_null(void)
{
    char buf[256];
    const char *result = get_partial_path(NULL, buf, sizeof(buf));
    CHECK(result == NULL);
}

static void test_partial_path_null_buf_returns_null(void)
{
    const char *result = get_partial_path("/tmp/foo.iso", NULL, 256);
    CHECK(result == NULL);
}

static void test_partial_path_buffer_too_small_returns_null(void)
{
    char buf[5]; /* too small for "/tmp/foo.iso.partial" */
    const char *result = get_partial_path("/tmp/foo.iso", buf, sizeof(buf));
    CHECK(result == NULL);
}

/* ---- has_partial_download tests ---- */

static void test_has_partial_false_when_no_partial(void)
{
    /* Use a target path whose .partial does not exist */
    CHECK(!has_partial_download("/tmp/rufus_no_such_target_xyz"));
}

static void test_has_partial_true_when_partial_exists(void)
{
    const char *target = make_named_tmpfile(NULL, 0);
    CHECK(target != NULL);
    /* Remove the target itself — we only need the name for the partial path */
    unlink(target);
    /* Create a .partial file */
    CHECK(make_partial_file(target, "hello", 5));
    CHECK(has_partial_download(target));
    /* cleanup */
    char partial[512];
    get_partial_path(target, partial, sizeof(partial));
    unlink(partial);
}

/* ---- get_partial_size tests ---- */

static void test_get_partial_size_zero_when_no_partial(void)
{
    CHECK(get_partial_size("/tmp/rufus_no_such_size_xyz") == 0);
}

static void test_get_partial_size_correct_when_partial_exists(void)
{
    const char *target = make_named_tmpfile(NULL, 0);
    CHECK(target != NULL);
    unlink(target);
    const char data[] = "RUFUS_TEST_DATA_42BYTES_PADDED_1234567890";
    size_t dlen = strlen(data);
    CHECK(make_partial_file(target, data, dlen));
    CHECK(get_partial_size(target) == (uint64_t)dlen);
    /* cleanup */
    char partial[512];
    get_partial_path(target, partial, sizeof(partial));
    unlink(partial);
}

static void test_get_partial_size_zero_for_empty_partial(void)
{
    const char *target = make_named_tmpfile(NULL, 0);
    CHECK(target != NULL);
    unlink(target);
    CHECK(make_partial_file(target, NULL, 0));
    CHECK(get_partial_size(target) == 0);
    /* cleanup */
    char partial[512];
    get_partial_path(target, partial, sizeof(partial));
    unlink(partial);
}

/* ---- finalize_partial_download tests ---- */

static void test_finalize_renames_partial_to_target(void)
{
    const char *target = make_named_tmpfile(NULL, 0);
    CHECK(target != NULL);
    unlink(target); /* ensure target does not exist before finalize */

    const char data[] = "FINAL_CONTENT";
    CHECK(make_partial_file(target, data, strlen(data)));
    CHECK(finalize_partial_download(target));

    /* target must now exist */
    struct stat st;
    CHECK(stat(target, &st) == 0);
    CHECK((size_t)st.st_size == strlen(data));

    /* .partial must be gone */
    char partial[512];
    get_partial_path(target, partial, sizeof(partial));
    CHECK(stat(partial, &st) != 0); /* ENOENT */

    unlink(target);
}

static void test_finalize_returns_false_when_no_partial(void)
{
    CHECK(!finalize_partial_download("/tmp/rufus_no_such_finalize_xyz"));
}

static void test_finalize_overwrites_existing_target(void)
{
    /* Create an existing "stale" target */
    const char *target = make_named_tmpfile("stale", 5);
    CHECK(target != NULL);

    /* Create a .partial with new content */
    const char fresh[] = "fresh_download_data";
    CHECK(make_partial_file(target, fresh, strlen(fresh)));
    CHECK(finalize_partial_download(target));

    /* target now has fresh content */
    struct stat st;
    CHECK(stat(target, &st) == 0);
    CHECK((size_t)st.st_size == strlen(fresh));

    unlink(target);
}

/* ---- abandon_partial_download tests ---- */

static void test_abandon_removes_partial(void)
{
    const char *target = make_named_tmpfile(NULL, 0);
    CHECK(target != NULL);
    unlink(target);
    CHECK(make_partial_file(target, "data", 4));
    CHECK(abandon_partial_download(target));

    char partial[512];
    get_partial_path(target, partial, sizeof(partial));
    struct stat st;
    CHECK(stat(partial, &st) != 0); /* gone */
}

static void test_abandon_returns_false_when_no_partial(void)
{
    CHECK(!abandon_partial_download("/tmp/rufus_no_such_abandon_xyz"));
}

/* ---- net.c integration test: resume offset is set correctly ---- */

/*
 * This test verifies the contract that get_partial_size() returns the
 * byte offset that should be passed to CURLOPT_RESUME_FROM_LARGE.
 * The test does NOT perform a real download; it just confirms that
 * after writing N bytes to a .partial file the resume offset == N.
 */
static void test_resume_offset_matches_partial_size(void)
{
    const char *target = make_named_tmpfile(NULL, 0);
    CHECK(target != NULL);
    unlink(target);

    /* Simulate a partially-downloaded file of 1024 bytes */
    char buf[1024];
    memset(buf, 0xAB, sizeof(buf));
    CHECK(make_partial_file(target, buf, sizeof(buf)));

    uint64_t offset = get_partial_size(target);
    CHECK(offset == 1024);

    char partial[512];
    get_partial_path(target, partial, sizeof(partial));
    unlink(partial);
}

/* ---- test suite registration ---- */

int main(void)
{
    printf("=== download_resume tests ===\n");

    RUN_TEST(test_partial_path_appends_suffix);
    RUN_TEST(test_partial_path_bare_filename);
    RUN_TEST(test_partial_path_null_target_returns_null);
    RUN_TEST(test_partial_path_null_buf_returns_null);
    RUN_TEST(test_partial_path_buffer_too_small_returns_null);

    RUN_TEST(test_has_partial_false_when_no_partial);
    RUN_TEST(test_has_partial_true_when_partial_exists);

    RUN_TEST(test_get_partial_size_zero_when_no_partial);
    RUN_TEST(test_get_partial_size_correct_when_partial_exists);
    RUN_TEST(test_get_partial_size_zero_for_empty_partial);

    RUN_TEST(test_finalize_renames_partial_to_target);
    RUN_TEST(test_finalize_returns_false_when_no_partial);
    RUN_TEST(test_finalize_overwrites_existing_target);

    RUN_TEST(test_abandon_removes_partial);
    RUN_TEST(test_abandon_returns_false_when_no_partial);

    RUN_TEST(test_resume_offset_matches_partial_size);

    TEST_RESULTS();
}
