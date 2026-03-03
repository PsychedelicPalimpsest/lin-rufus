/*
 * test_log_save_linux.c — TDD tests for Feature 208: log auto-save to file.
 *
 * Tests the rufus_log_write() helper that saves or appends log text to
 * <dir>/rufus.log.  Runs without GTK (no UI dependency).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "framework.h"
#include "../src/linux/compat/windows.h"

/* Stub for uprintf — used by stdfn.c; we don't need log output during tests */
void uprintf(const char *fmt, ...) { (void)fmt; }

/* Function under test — implemented in src/linux/stdfn.c */
extern BOOL rufus_log_write(const char *text, BOOL append, const char *dir);

/* ---- helpers ----------------------------------------------------------- */

static char tmp_dir[256];

static void setup_tmpdir(void)
{
    snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/rufus_log_test_XXXXXX");
    if (mkdtemp(tmp_dir) == NULL) {
        perror("mkdtemp");
        tmp_dir[0] = '\0';
    }
}

static void rm_tmpdir(void)
{
    if (tmp_dir[0]) {
        /* remove rufus.log if present */
        char path[280];
        snprintf(path, sizeof(path), "%s/rufus.log", tmp_dir);
        unlink(path);
        rmdir(tmp_dir);
        tmp_dir[0] = '\0';
    }
}

/* Read entire file into a caller-owned malloc buffer; returns NULL on error. */
static char *read_file(const char *dir, const char *name)
{
    char path[280];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    buf[sz] = '\0';
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    return buf;
}

/* ---- tests ------------------------------------------------------------- */

TEST(log_write_null_text_returns_false)
{
    setup_tmpdir();
    BOOL r = rufus_log_write(NULL, FALSE, tmp_dir);
    CHECK(r == FALSE);
    rm_tmpdir();
}

TEST(log_write_null_dir_returns_false)
{
    BOOL r = rufus_log_write("hello", FALSE, NULL);
    CHECK(r == FALSE);
}

TEST(log_write_creates_file)
{
    setup_tmpdir();
    CHECK(tmp_dir[0] != '\0');

    BOOL r = rufus_log_write("test log line\n", FALSE, tmp_dir);
    CHECK(r == TRUE);

    char path[280];
    snprintf(path, sizeof(path), "%s/rufus.log", tmp_dir);
    struct stat st;
    CHECK(stat(path, &st) == 0);

    rm_tmpdir();
}

TEST(log_write_contents_correct)
{
    setup_tmpdir();
    CHECK(tmp_dir[0] != '\0');

    const char *msg = "hello from test\n";
    BOOL r = rufus_log_write(msg, FALSE, tmp_dir);
    CHECK(r == TRUE);

    char *content = read_file(tmp_dir, "rufus.log");
    CHECK(content != NULL);
    if (content) {
        CHECK(strcmp(content, msg) == 0);
        free(content);
    }
    rm_tmpdir();
}

TEST(log_write_overwrite_replaces_content)
{
    setup_tmpdir();
    CHECK(tmp_dir[0] != '\0');

    rufus_log_write("first write\n", FALSE, tmp_dir);
    rufus_log_write("second write\n", FALSE, tmp_dir);

    char *content = read_file(tmp_dir, "rufus.log");
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, "second write") != NULL);
        /* "first write" must NOT be in the file (was overwritten) */
        CHECK(strstr(content, "first write") == NULL);
        free(content);
    }
    rm_tmpdir();
}

TEST(log_write_append_accumulates)
{
    setup_tmpdir();
    CHECK(tmp_dir[0] != '\0');

    rufus_log_write("session 1\n", FALSE, tmp_dir);  /* overwrite/create */
    rufus_log_write("session 2\n", TRUE,  tmp_dir);  /* append */

    char *content = read_file(tmp_dir, "rufus.log");
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, "session 1") != NULL);
        CHECK(strstr(content, "session 2") != NULL);
        free(content);
    }
    rm_tmpdir();
}

TEST(log_write_creates_dir_if_missing)
{
    /* Use a subdir that doesn't exist yet */
    char subdir[280];
    snprintf(subdir, sizeof(subdir), "/tmp/rufus_log_newdir_%d", (int)getpid());
    rmdir(subdir);  /* make sure it doesn't exist */

    BOOL r = rufus_log_write("content\n", FALSE, subdir);
    CHECK(r == TRUE);

    struct stat st;
    CHECK(stat(subdir, &st) == 0);
    CHECK(S_ISDIR(st.st_mode));

    /* cleanup */
    char path[320];
    snprintf(path, sizeof(path), "%s/rufus.log", subdir);
    unlink(path);
    rmdir(subdir);
}

TEST(log_write_empty_string_creates_empty_file)
{
    setup_tmpdir();
    CHECK(tmp_dir[0] != '\0');

    BOOL r = rufus_log_write("", FALSE, tmp_dir);
    CHECK(r == TRUE);

    char path[280];
    snprintf(path, sizeof(path), "%s/rufus.log", tmp_dir);
    struct stat st;
    CHECK(stat(path, &st) == 0);
    CHECK(st.st_size == 0);

    rm_tmpdir();
}

TEST(log_write_multi_line_text)
{
    setup_tmpdir();
    CHECK(tmp_dir[0] != '\0');

    const char *text = "line one\nline two\nline three\n";
    BOOL r = rufus_log_write(text, FALSE, tmp_dir);
    CHECK(r == TRUE);

    char *content = read_file(tmp_dir, "rufus.log");
    CHECK(content != NULL);
    if (content) {
        CHECK(strcmp(content, text) == 0);
        free(content);
    }
    rm_tmpdir();
}

int main(void)
{
    RUN(log_write_null_text_returns_false);
    RUN(log_write_null_dir_returns_false);
    RUN(log_write_creates_file);
    RUN(log_write_contents_correct);
    RUN(log_write_overwrite_replaces_content);
    RUN(log_write_append_accumulates);
    RUN(log_write_creates_dir_if_missing);
    RUN(log_write_empty_string_creates_empty_file);
    RUN(log_write_multi_line_text);
    TEST_RESULTS();
}
