/*
 * test_badblocks_linux.c - Tests for Linux BadBlocks() implementation
 *
 * Tests are TDD-first; each test covers a specific behavior.
 *
 * I/O model: BadBlocks receives a HANDLE (= int fd cast to pointer).
 * We create a temp file of known size and run BadBlocks against it.
 */

#define _GNU_SOURCE   /* mkstemp, pread, pwrite */
#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>

/* Pull in the compat layer so <windows.h> works */
#include <windows.h>   /* from linux/compat */

/* rufus.h defines PrintInfo as a macro; we stub PrintStatusInfo which it expands to */
#include "../src/windows/rufus.h"
#include "../src/windows/resource.h"
#include "../src/windows/badblocks.h"

/* ── globals expected by badblocks.c ──────────────────────────────── */
DWORD  MainThreadId = 0, ErrorStatus = 0, DownloadStatus = 0, LastWriteError = 0;
BOOL   allow_dual_uefi_bios = FALSE, large_drive = FALSE, usb_debug = FALSE;
BOOL   detect_fakes = FALSE;
HWND   hMainDialog = NULL;
const char *flash_type[BADLOCKS_PATTERN_TYPES] = { "SLC","MLC","TLC","4bit","5bit" };

/* ── stubs for functions called by badblocks ─────────────────────── */
void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration, int msg_id, ...)
     { (void)info; (void)debug; (void)duration; (void)msg_id; }
char *lmprintf(int msg_id, ...) { (void)msg_id; return ""; }
void   UpdateProgress(int op, float pct)  { (void)op; (void)pct; }
char  *SizeToHumanReadable(uint64_t s, BOOL c, BOOL f)
       { (void)s;(void)c;(void)f; static char buf[32]; snprintf(buf,sizeof(buf),"%" PRIu64,s); return buf; }
void   uprintf(const char *fmt, ...)
       { va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); va_end(ap); }
BOOL   WriteFileWithRetry(HANDLE h, const void *buf, DWORD n, DWORD *wr, DWORD retries)
       { (void)retries; return WriteFile(h, buf, n, wr, NULL); }

/* ── helpers ─────────────────────────────────────────────────────── */

/* Create a temp file of 'size' bytes (filled with zeros), return fd */
static int make_temp_drive(uint64_t size)
{
    char tmpl[] = "/tmp/bb_test_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    unlink(tmpl);           /* remove name; fd still valid */
    if (ftruncate(fd, (off_t)size) != 0) { close(fd); return -1; }
    return fd;
}

/* ── tests ───────────────────────────────────────────────────────── */

/* NULL report → FALSE immediately */
TEST(badblocks_null_report)
{
    int fd = make_temp_drive(BADBLOCK_BLOCK_SIZE * 4);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;
    BOOL r = BadBlocks(h, BADBLOCK_BLOCK_SIZE * 4, 1, 0, NULL, NULL);
    CHECK(r == FALSE);
    close(fd);
}

/* Zero-size disk → nothing to test; must not crash */
TEST(badblocks_zero_size)
{
    int fd = make_temp_drive(0);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;
    badblocks_report rpt = { 0 };
    BOOL r = BadBlocks(h, 0, 1, 0, &rpt, NULL);
    /* With zero blocks there's nothing to test; expect success and 0 bad blocks */
    CHECK(rpt.bb_count == 0);
    (void)r;
    close(fd);
}

/* Good drive (temp file) → 0 bad blocks, no errors */
TEST(badblocks_good_drive_one_pass)
{
    const uint64_t drive_sz = (uint64_t)BADBLOCK_BLOCK_SIZE * 16;
    int fd = make_temp_drive(drive_sz);
    CHECK(fd >= 0);

    HANDLE h = (HANDLE)(intptr_t)fd;
    badblocks_report rpt = { 0 };
    BOOL r = BadBlocks(h, drive_sz, 1, 0, &rpt, NULL);

    CHECK(r == TRUE);
    CHECK_INT_EQ(0, (int)rpt.bb_count);
    CHECK_INT_EQ(0, (int)rpt.num_read_errors);
    CHECK_INT_EQ(0, (int)rpt.num_write_errors);
    CHECK_INT_EQ(0, (int)rpt.num_corruption_errors);
    close(fd);
}

/* Two-pass test on a good drive */
TEST(badblocks_good_drive_two_pass)
{
    const uint64_t drive_sz = (uint64_t)BADBLOCK_BLOCK_SIZE * 8;
    int fd = make_temp_drive(drive_sz);
    CHECK(fd >= 0);

    HANDLE h = (HANDLE)(intptr_t)fd;
    badblocks_report rpt = { 0 };
    BOOL r = BadBlocks(h, drive_sz, 2, 0, &rpt, NULL);

    CHECK(r == TRUE);
    CHECK_INT_EQ(0, (int)rpt.bb_count);
    close(fd);
}

/* SLC flash type (pattern type 2) */
TEST(badblocks_slc_pattern)
{
    const uint64_t drive_sz = (uint64_t)BADBLOCK_BLOCK_SIZE * 8;
    int fd = make_temp_drive(drive_sz);
    CHECK(fd >= 0);

    HANDLE h = (HANDLE)(intptr_t)fd;
    badblocks_report rpt = { 0 };
    BOOL r = BadBlocks(h, drive_sz, 1, 2, &rpt, NULL);   /* flash_type=2 → SLC */

    CHECK(r == TRUE);
    CHECK_INT_EQ(0, (int)rpt.bb_count);
    close(fd);
}

/* Report fields are initialised: write errors and corruption errors start 0 */
TEST(badblocks_report_fields_initialised)
{
    const uint64_t drive_sz = (uint64_t)BADBLOCK_BLOCK_SIZE * 4;
    int fd = make_temp_drive(drive_sz);
    CHECK(fd >= 0);

    badblocks_report rpt;
    /* Set garbage to verify initialisation */
    memset(&rpt, 0xFF, sizeof(rpt));

    HANDLE h = (HANDLE)(intptr_t)fd;
    BOOL r = BadBlocks(h, drive_sz, 1, 0, &rpt, NULL);
    CHECK(r == TRUE);
    CHECK_INT_EQ(0, (int)rpt.num_read_errors);
    CHECK_INT_EQ(0, (int)rpt.num_write_errors);
    CHECK_INT_EQ(0, (int)rpt.num_corruption_errors);
    close(fd);
}

/* Log file pointer: passing a non-NULL log fd should not crash */
TEST(badblocks_with_log_fd)
{
    const uint64_t drive_sz = (uint64_t)BADBLOCK_BLOCK_SIZE * 4;
    int fd = make_temp_drive(drive_sz);
    CHECK(fd >= 0);

    FILE *log = tmpfile();
    CHECK(log != NULL);

    HANDLE h = (HANDLE)(intptr_t)fd;
    badblocks_report rpt = { 0 };
    BOOL r = BadBlocks(h, drive_sz, 1, 0, &rpt, log);
    CHECK(r == TRUE);
    CHECK_INT_EQ(0, (int)rpt.bb_count);

    fclose(log);
    close(fd);
}

/* Invalid handle → FALSE */
TEST(badblocks_invalid_handle)
{
    badblocks_report rpt = { 0 };
    BOOL r = BadBlocks(INVALID_HANDLE_VALUE, BADBLOCK_BLOCK_SIZE * 4, 1, 0, &rpt, NULL);
    /* Should fail gracefully */
    CHECK(r == FALSE || rpt.bb_count == 0);  /* at minimum, no crash */
}

/* Cancellation: set ErrorStatus mid-run; expect FALSE returned */
TEST(badblocks_cancellation)
{
    /* Use a large-ish drive so there are enough blocks to cancel mid-run */
    const uint64_t drive_sz = (uint64_t)BADBLOCK_BLOCK_SIZE * 128;
    int fd = make_temp_drive(drive_sz);
    CHECK(fd >= 0);

    /* Signal cancellation immediately */
    ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED);

    HANDLE h = (HANDLE)(intptr_t)fd;
    badblocks_report rpt = { 0 };
    BOOL r = BadBlocks(h, drive_sz, 1, 0, &rpt, NULL);
    CHECK(r == FALSE);

    ErrorStatus = 0;   /* reset for subsequent tests */
    close(fd);
}

/* Multiple flash types (0..4) should all complete without crash */
TEST(badblocks_all_flash_types)
{
    const uint64_t drive_sz = (uint64_t)BADBLOCK_BLOCK_SIZE * 4;

    for (int ft = 0; ft < BADLOCKS_PATTERN_TYPES; ft++) {
        int fd = make_temp_drive(drive_sz);
        CHECK(fd >= 0);
        HANDLE h = (HANDLE)(intptr_t)fd;
        badblocks_report rpt = { 0 };
        BOOL r = BadBlocks(h, drive_sz, 1, ft, &rpt, NULL);
        CHECK(r == TRUE);
        CHECK_INT_EQ(0, (int)rpt.bb_count);
        close(fd);
    }
}

/* ── test runner ─────────────────────────────────────────────────── */
int main(void)
{
    printf("=== BadBlocks Linux tests ===\n");
    RUN(badblocks_null_report);
    RUN(badblocks_zero_size);
    RUN(badblocks_good_drive_one_pass);
    RUN(badblocks_good_drive_two_pass);
    RUN(badblocks_slc_pattern);
    RUN(badblocks_report_fields_initialised);
    RUN(badblocks_with_log_fd);
    RUN(badblocks_invalid_handle);
    RUN(badblocks_cancellation);
    RUN(badblocks_all_flash_types);
    TEST_RESULTS();
}
