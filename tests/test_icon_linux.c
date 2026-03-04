/*
 * test_icon_linux.c — Unit tests for src/linux/icon.c
 *
 * Tests cover:
 *   1.  extract_app_icon_returns_false        — stub always returns FALSE
 *   2.  null_path_returns_false               — SetAutorun(NULL) → FALSE
 *   3.  creates_autorun_inf                   — file is created on disk
 *   4.  content_has_autorun_header            — [autorun] section present
 *   5.  content_has_icon_entry                — icon = autorun.ico line present
 *   6.  content_has_rufus_comment             — "; Created by Rufus" comment
 *   7.  existing_file_not_overwritten         — pre-existing file is preserved
 *   8.  existing_file_returns_false           — returns FALSE when file exists
 *   9.  label_in_content_when_hlabel_set      — volume label written to file
 *  10.  empty_label_in_content_when_no_hlabel — empty label= line when hLabel=NULL
 *  11.  returns_true_on_success               — successful create returns TRUE
 *  12.  invalid_dir_returns_false             — nonexistent dir → FALSE
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>

/* ---- compat layer ---- */
#include "../src/linux/compat/windows.h"

/* ---- window text bridge (so GetWindowTextA / SetWindowTextA work) ---- */
#include "../src/linux/window_text_bridge.h"

/* ---- function under test ---- */
extern BOOL ExtractAppIcon(const char *path, BOOL bSilent);
extern BOOL SetAutorun(const char *path);

/* ================================================================
 * Minimal globals required by icon.c (rufus.h / uprintf)
 * ================================================================ */
HWND hMainDialog   = NULL;
HWND hDeviceList   = NULL;
HWND hProgress     = NULL;
HWND hStatus       = NULL;
HWND hInfo         = NULL;
HWND hLog          = NULL;
HWND hLabel        = NULL;

DWORD ErrorStatus      = 0;
DWORD DownloadStatus   = 0;
DWORD MainThreadId     = 0;
DWORD LastWriteError   = 0;
BOOL  right_to_left_mode = FALSE;

/* uprintf stub — swallow all log messages */
void uprintf(const char *fmt, ...) { (void)fmt; }
void ruprintf(const char *fmt, ...) { (void)fmt; }

/* ================================================================
 * Helpers
 * ================================================================ */

/* Create a unique temp directory for each test and return its path. */
static char tmp_dir[PATH_MAX];

static void make_tmp_dir(void)
{
    snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/test_icon_XXXXXX");
    if (mkdtemp(tmp_dir) == NULL) {
        perror("mkdtemp");
        tmp_dir[0] = '\0';
    }
}

static void cleanup_tmp_dir(void)
{
    if (tmp_dir[0] == '\0') return;
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
    (void)system(cmd);
    tmp_dir[0] = '\0';
}

/* Read the autorun.inf from tmp_dir into a static buffer.
 * Returns NULL if the file does not exist. */
static char file_buf[4096];
static const char *read_autorun_inf(void)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/autorun.inf", tmp_dir);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    size_t n = fread(file_buf, 1, sizeof(file_buf) - 1, f);
    file_buf[n] = '\0';
    fclose(f);
    return file_buf;
}

/* ================================================================
 * Test 1: ExtractAppIcon is a no-op stub returning FALSE
 * ================================================================ */
TEST(extract_app_icon_returns_false)
{
    BOOL r = ExtractAppIcon("/some/path", FALSE);
    CHECK_INT_EQ(FALSE, r);
    r = ExtractAppIcon(NULL, TRUE);
    CHECK_INT_EQ(FALSE, r);
}

/* ================================================================
 * Test 2: NULL path returns FALSE without crashing
 * ================================================================ */
TEST(null_path_returns_false)
{
    BOOL r = SetAutorun(NULL);
    CHECK_INT_EQ(FALSE, r);
}

/* ================================================================
 * Test 3: SetAutorun creates autorun.inf in the given directory
 * ================================================================ */
TEST(creates_autorun_inf)
{
    make_tmp_dir();
    BOOL r = SetAutorun(tmp_dir);
    CHECK_INT_EQ(TRUE, r);

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/autorun.inf", tmp_dir);
    struct stat st;
    CHECK_INT_EQ(0, stat(path, &st));

    cleanup_tmp_dir();
}

/* ================================================================
 * Test 4: Content contains the [autorun] section header
 * ================================================================ */
TEST(content_has_autorun_header)
{
    make_tmp_dir();
    SetAutorun(tmp_dir);
    const char *c = read_autorun_inf();
    CHECK(c != NULL);
    CHECK(strstr(c, "[autorun]") != NULL);
    cleanup_tmp_dir();
}

/* ================================================================
 * Test 5: Content contains "icon  = autorun.ico" line
 * ================================================================ */
TEST(content_has_icon_entry)
{
    make_tmp_dir();
    SetAutorun(tmp_dir);
    const char *c = read_autorun_inf();
    CHECK(c != NULL);
    CHECK(strstr(c, "autorun.ico") != NULL);
    cleanup_tmp_dir();
}

/* ================================================================
 * Test 6: Content contains the Rufus comment header
 * ================================================================ */
TEST(content_has_rufus_comment)
{
    make_tmp_dir();
    SetAutorun(tmp_dir);
    const char *c = read_autorun_inf();
    CHECK(c != NULL);
    CHECK(strstr(c, "Created by Rufus") != NULL);
    cleanup_tmp_dir();
}

/* ================================================================
 * Test 7: Pre-existing autorun.inf is not overwritten
 * ================================================================ */
TEST(existing_file_not_overwritten)
{
    make_tmp_dir();

    /* Create a sentinel file first */
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/autorun.inf", tmp_dir);
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    fputs("SENTINEL_CONTENT\n", f);
    fclose(f);

    SetAutorun(tmp_dir);

    const char *c = read_autorun_inf();
    CHECK(c != NULL);
    CHECK(strstr(c, "SENTINEL_CONTENT") != NULL);

    cleanup_tmp_dir();
}

/* ================================================================
 * Test 8: Returns FALSE when autorun.inf already exists
 * ================================================================ */
TEST(existing_file_returns_false)
{
    make_tmp_dir();

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/autorun.inf", tmp_dir);
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    fclose(f);

    BOOL r = SetAutorun(tmp_dir);
    CHECK_INT_EQ(FALSE, r);

    cleanup_tmp_dir();
}

/* ================================================================
 * Test 9: Volume label from hLabel is written to the file
 * ================================================================ */
TEST(label_in_content_when_hlabel_set)
{
    make_tmp_dir();

    /* Register a fake hLabel and set its text */
    HWND fake_label = (HWND)(uintptr_t)0xAB01;
    window_text_register(fake_label);
    SetWindowTextA(fake_label, "MY_USB_LABEL");
    hLabel = fake_label;

    SetAutorun(tmp_dir);

    const char *c = read_autorun_inf();
    CHECK(c != NULL);
    CHECK(strstr(c, "MY_USB_LABEL") != NULL);

    hLabel = NULL;
    window_text_unregister(fake_label);
    cleanup_tmp_dir();
}

/* ================================================================
 * Test 10: Empty label= line when hLabel is NULL
 * ================================================================ */
TEST(empty_label_in_content_when_no_hlabel)
{
    make_tmp_dir();
    hLabel = NULL;

    SetAutorun(tmp_dir);

    const char *c = read_autorun_inf();
    CHECK(c != NULL);
    /* "label = " must appear with an empty or whitespace value */
    CHECK(strstr(c, "label = ") != NULL);

    cleanup_tmp_dir();
}

/* ================================================================
 * Test 11: SetAutorun returns TRUE on successful creation
 * ================================================================ */
TEST(returns_true_on_success)
{
    make_tmp_dir();
    BOOL r = SetAutorun(tmp_dir);
    CHECK_INT_EQ(TRUE, r);
    cleanup_tmp_dir();
}

/* ================================================================
 * Test 12: Non-existent directory returns FALSE
 * ================================================================ */
TEST(invalid_dir_returns_false)
{
    BOOL r = SetAutorun("/nonexistent/path/that/cannot/exist");
    CHECK_INT_EQ(FALSE, r);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
    printf("=== test_icon_linux ===\n");
    RUN(extract_app_icon_returns_false);
    RUN(null_path_returns_false);
    RUN(creates_autorun_inf);
    RUN(content_has_autorun_header);
    RUN(content_has_icon_entry);
    RUN(content_has_rufus_comment);
    RUN(existing_file_not_overwritten);
    RUN(existing_file_returns_false);
    RUN(label_in_content_when_hlabel_set);
    RUN(empty_label_in_content_when_no_hlabel);
    RUN(returns_true_on_success);
    RUN(invalid_dir_returns_false);
    TEST_RESULTS();
}

#endif /* __linux__ */
