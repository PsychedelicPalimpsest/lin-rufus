/*
 * test_verify_linux.c — TDD tests for the write-and-verify pass.
 *
 * Tests verify_write_pass() using ordinary temporary files as both the
 * source image and the "device" file descriptor so no real block device
 * is needed.
 *
 * Build: see tests/Makefile entry for test_verify_linux.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include "framework.h"
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/linux/verify.h"

/* ---- test-visible stubs / globals ---- */
DWORD   ErrorStatus      = 0;
DWORD   LastWriteError   = 0;
int     progress_call_count = 0;
int     last_op          = -1;
uint64_t last_progress_cur = 0;
uint64_t last_progress_tot = 0;

void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL force)
{
    (void)msg; (void)force;
    last_op           = op;
    last_progress_cur = cur;
    last_progress_tot = tot;
    progress_call_count++;
}

void UpdateProgress(int op, float pct)
{
    (void)op; (void)pct;
}

/* uprintf is a macro/function used inside verify.c for error logging */
int test_uprintf(const char *fmt, ...)
{
    (void)fmt; return 0;
}

/* ---- helpers ---- */

/* Write content of len bytes to a temp file; returns open fd or -1. */
static int make_tmpfile(const uint8_t *content, size_t len)
{
    char tmpl[] = "/tmp/rufus_verify_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    unlink(tmpl); /* file stays open but is deleted from directory */
    if (len > 0 && write(fd, content, len) != (ssize_t)len) {
        close(fd);
        return -1;
    }
    /* rewind so pread from offset 0 works */
    lseek(fd, 0, SEEK_SET);
    return fd;
}

/* Write content to a real on-disk temp file (needed for source_path). */
static char *make_named_tmpfile(const uint8_t *content, size_t len)
{
    static char path[64];
    snprintf(path, sizeof(path), "/tmp/rufus_verify_src_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) return NULL;
    if (len > 0 && write(fd, content, len) != (ssize_t)len) {
        close(fd);
        unlink(path);
        return NULL;
    }
    close(fd);
    return path;
}

/* ---- tests ---- */

TEST(verify_null_source_returns_false)
{
    int dev_fd = make_tmpfile((uint8_t*)"hello", 5);
    CHECK(dev_fd >= 0);
    BOOL result = verify_write_pass(NULL, dev_fd, 5);
    CHECK(result == FALSE);
    close(dev_fd);
}

TEST(verify_invalid_fd_returns_false)
{
    uint8_t data[] = "hello";
    char *src = make_named_tmpfile(data, sizeof(data) - 1);
    CHECK(src != NULL);
    BOOL result = verify_write_pass(src, -1, sizeof(data) - 1);
    CHECK(result == FALSE);
    unlink(src);
}

TEST(verify_zero_size_returns_true)
{
    int dev_fd = make_tmpfile(NULL, 0);
    CHECK(dev_fd >= 0);
    uint8_t data[] = "anything";
    char *src = make_named_tmpfile(data, sizeof(data) - 1);
    CHECK(src != NULL);
    BOOL result = verify_write_pass(src, dev_fd, 0);
    CHECK(result == TRUE);
    close(dev_fd);
    unlink(src);
}

TEST(verify_match_small)
{
    uint8_t data[4096];
    for (int i = 0; i < (int)sizeof(data); i++) data[i] = (uint8_t)(i & 0xFF);

    char *src = make_named_tmpfile(data, sizeof(data));
    CHECK(src != NULL);

    int dev_fd = make_tmpfile(data, sizeof(data));
    CHECK(dev_fd >= 0);

    LastWriteError = 0;
    BOOL result = verify_write_pass(src, dev_fd, sizeof(data));
    CHECK(result == TRUE);
    CHECK_INT_EQ(0, (int)LastWriteError);

    close(dev_fd);
    unlink(src);
}

TEST(verify_mismatch_small)
{
    uint8_t src_data[4096];
    uint8_t dev_data[4096];
    for (int i = 0; i < (int)sizeof(src_data); i++) src_data[i] = (uint8_t)(i & 0xFF);
    memcpy(dev_data, src_data, sizeof(dev_data));
    dev_data[512] ^= 0xFF; /* flip byte at offset 512 */

    char *src = make_named_tmpfile(src_data, sizeof(src_data));
    CHECK(src != NULL);

    int dev_fd = make_tmpfile(dev_data, sizeof(dev_data));
    CHECK(dev_fd >= 0);

    LastWriteError = 0;
    BOOL result = verify_write_pass(src, dev_fd, sizeof(src_data));
    CHECK(result == FALSE);
    CHECK(LastWriteError != 0);

    close(dev_fd);
    unlink(src);
}

TEST(verify_match_large)
{
    /* 9 MB — crosses the 4 MB chunk boundary */
    size_t sz = 9 * 1024 * 1024;
    uint8_t *buf = malloc(sz);
    CHECK(buf != NULL);
    for (size_t i = 0; i < sz; i++) buf[i] = (uint8_t)(i & 0xFF);

    char *src = make_named_tmpfile(buf, sz);
    CHECK(src != NULL);

    int dev_fd = make_tmpfile(buf, sz);
    CHECK(dev_fd >= 0);

    LastWriteError = 0;
    BOOL result = verify_write_pass(src, dev_fd, (uint64_t)sz);
    CHECK(result == TRUE);
    CHECK_INT_EQ(0, (int)LastWriteError);

    free(buf);
    close(dev_fd);
    unlink(src);
}

TEST(verify_mismatch_second_chunk)
{
    /* 9 MB — mismatch at offset 5 MB (in the second 4 MB chunk) */
    size_t sz = 9 * 1024 * 1024;
    uint8_t *src_buf = malloc(sz);
    uint8_t *dev_buf = malloc(sz);
    CHECK(src_buf != NULL);
    CHECK(dev_buf != NULL);
    for (size_t i = 0; i < sz; i++) src_buf[i] = (uint8_t)(i & 0xFF);
    memcpy(dev_buf, src_buf, sz);
    dev_buf[5 * 1024 * 1024 + 7] ^= 0xFF; /* flip byte at 5 MB + 7 */

    char *src = make_named_tmpfile(src_buf, sz);
    CHECK(src != NULL);

    int dev_fd = make_tmpfile(dev_buf, sz);
    CHECK(dev_fd >= 0);

    LastWriteError = 0;
    BOOL result = verify_write_pass(src, dev_fd, (uint64_t)sz);
    CHECK(result == FALSE);
    CHECK(LastWriteError != 0);

    free(src_buf);
    free(dev_buf);
    close(dev_fd);
    unlink(src);
}

TEST(verify_cancelled_returns_false)
{
    uint8_t data[4096];
    memset(data, 0xAA, sizeof(data));

    char *src = make_named_tmpfile(data, sizeof(data));
    CHECK(src != NULL);

    int dev_fd = make_tmpfile(data, sizeof(data));
    CHECK(dev_fd >= 0);

    /* Simulate user cancel */
    ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED);

    BOOL result = verify_write_pass(src, dev_fd, sizeof(data));
    CHECK(result == FALSE);

    ErrorStatus = 0;
    close(dev_fd);
    unlink(src);
}

TEST(verify_reports_progress)
{
    size_t sz = 5 * 1024 * 1024; /* 5 MB — two chunks */
    uint8_t *buf = malloc(sz);
    CHECK(buf != NULL);
    memset(buf, 0x55, sz);

    char *src = make_named_tmpfile(buf, sz);
    CHECK(src != NULL);

    int dev_fd = make_tmpfile(buf, sz);
    CHECK(dev_fd >= 0);

    progress_call_count = 0;
    BOOL result = verify_write_pass(src, dev_fd, (uint64_t)sz);
    CHECK(result == TRUE);
    CHECK(progress_call_count > 0);

    free(buf);
    close(dev_fd);
    unlink(src);
}

TEST(verify_source_shorter_than_written_fails)
{
    /* source file is smaller than written_size — verify should fail gracefully */
    uint8_t src_data[1024];
    uint8_t dev_data[4096];
    memset(src_data, 0xCC, sizeof(src_data));
    memset(dev_data, 0xCC, sizeof(dev_data));

    char *src = make_named_tmpfile(src_data, sizeof(src_data));
    CHECK(src != NULL);

    int dev_fd = make_tmpfile(dev_data, sizeof(dev_data));
    CHECK(dev_fd >= 0);

    /* Ask to verify 4096 bytes but source only has 1024 */
    BOOL result = verify_write_pass(src, dev_fd, sizeof(dev_data));
    CHECK(result == FALSE);

    close(dev_fd);
    unlink(src);
}

int main(void)
{
    RUN(verify_null_source_returns_false);
    RUN(verify_invalid_fd_returns_false);
    RUN(verify_zero_size_returns_true);
    RUN(verify_match_small);
    RUN(verify_mismatch_small);
    RUN(verify_match_large);
    RUN(verify_mismatch_second_chunk);
    RUN(verify_cancelled_returns_false);
    RUN(verify_reports_progress);
    RUN(verify_source_shorter_than_written_fails);
    TEST_RESULTS();
}
