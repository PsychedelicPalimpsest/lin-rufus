/*
 * Rufus: The Reliable USB Formatting Utility
 * Unit tests for XDG user directory lookup (Linux)
 * Copyright © 2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

/* BOOL is used by xdg.h — define a minimal stub before including it */
typedef int BOOL;
#define TRUE  1
#define FALSE 0

#include "xdg.h"

/* ── Minimal test harness ──────────────────────────────────────────────── */
static int tests_run    = 0;
static int tests_failed = 0;

#define CHECK(cond, msg) do { \
    ++tests_run; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
        ++tests_failed; \
    } else { \
        printf("  ok: %s\n", msg); \
    } \
} while (0)

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/* Write a user-dirs.dirs file to tmpdir and return the config dir. */
static char* write_dirs_file(const char* tmpdir, const char* content)
{
    static char cfg[512];
    snprintf(cfg, sizeof(cfg), "%s/.config", tmpdir);
    mkdir(cfg, 0755);

    char path[512];
    snprintf(path, sizeof(path), "%s/user-dirs.dirs", cfg);
    FILE* f = fopen(path, "w");
    assert(f);
    fputs(content, f);
    fclose(f);
    return cfg;
}

static char* make_tmpdir(void)
{
    static char dir[256];
    snprintf(dir, sizeof(dir), "/tmp/test_xdg_XXXXXX");
    assert(mkdtemp(dir) != NULL);
    return dir;
}

/* ── Test cases ─────────────────────────────────────────────────────────── */

static void test_download_home_relative(void)
{
    printf("\ndownload_home_relative:\n");
    char* tmp = make_tmpdir();
    const char* content =
        "# This file is written by xdg-user-dirs-update\n"
        "XDG_DESKTOP_DIR=\"$HOME/Desktop\"\n"
        "XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n"
        "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n";
    char* cfg = write_dirs_file(tmp, content);
    xdg_set_config_home(cfg);
    xdg_set_home_dir(tmp);

    char buf[512] = {0};
    BOOL ok = GetXdgUserDir("DOWNLOAD", buf, sizeof(buf));
    CHECK(ok == TRUE, "download dir found");

    char expected[512];
    snprintf(expected, sizeof(expected), "%s/Downloads", tmp);
    CHECK(strcmp(buf, expected) == 0, "download dir matches $HOME/Downloads");
}

static void test_desktop_home_relative(void)
{
    printf("\ndesktop_home_relative:\n");
    char* tmp = make_tmpdir();
    const char* content =
        "XDG_DESKTOP_DIR=\"$HOME/Desktop\"\n"
        "XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n";
    char* cfg = write_dirs_file(tmp, content);
    xdg_set_config_home(cfg);
    xdg_set_home_dir(tmp);

    char buf[512] = {0};
    BOOL ok = GetXdgUserDir("DESKTOP", buf, sizeof(buf));
    CHECK(ok == TRUE, "desktop dir found");

    char expected[512];
    snprintf(expected, sizeof(expected), "%s/Desktop", tmp);
    CHECK(strcmp(buf, expected) == 0, "desktop dir matches $HOME/Desktop");
}

static void test_absolute_path(void)
{
    printf("\nabsolute_path:\n");
    char* tmp = make_tmpdir();
    const char* content =
        "XDG_DOWNLOAD_DIR=\"/media/downloads\"\n";
    char* cfg = write_dirs_file(tmp, content);
    xdg_set_config_home(cfg);
    xdg_set_home_dir(tmp);

    char buf[512] = {0};
    BOOL ok = GetXdgUserDir("DOWNLOAD", buf, sizeof(buf));
    CHECK(ok == TRUE, "absolute path found");
    CHECK(strcmp(buf, "/media/downloads") == 0, "absolute path returned verbatim");
}

static void test_missing_key_returns_false(void)
{
    printf("\nmissing_key_returns_false:\n");
    char* tmp = make_tmpdir();
    const char* content =
        "XDG_DESKTOP_DIR=\"$HOME/Desktop\"\n";
    char* cfg = write_dirs_file(tmp, content);
    xdg_set_config_home(cfg);
    xdg_set_home_dir(tmp);

    char buf[512] = {0};
    BOOL ok = GetXdgUserDir("DOWNLOAD", buf, sizeof(buf));
    CHECK(ok == FALSE, "missing key returns FALSE");
}

static void test_missing_file_returns_false(void)
{
    printf("\nmissing_file_returns_false:\n");
    /* Point at a non-existent config dir */
    xdg_set_config_home("/tmp/nonexistent_xdg_config_dir_RUFUSTEST");
    xdg_set_home_dir("/tmp");

    char buf[512] = {0};
    BOOL ok = GetXdgUserDir("DOWNLOAD", buf, sizeof(buf));
    CHECK(ok == FALSE, "missing file returns FALSE");
}

static void test_comment_lines_ignored(void)
{
    printf("\ncomment_lines_ignored:\n");
    char* tmp = make_tmpdir();
    const char* content =
        "# XDG_DOWNLOAD_DIR=\"$HOME/Fake\"\n"
        "  # XDG_DOWNLOAD_DIR=\"$HOME/AlsoFake\"\n"
        "XDG_DOWNLOAD_DIR=\"$HOME/RealDownloads\"\n";
    char* cfg = write_dirs_file(tmp, content);
    xdg_set_config_home(cfg);
    xdg_set_home_dir(tmp);

    char buf[512] = {0};
    BOOL ok = GetXdgUserDir("DOWNLOAD", buf, sizeof(buf));
    CHECK(ok == TRUE, "comment-skipping finds real entry");

    char expected[512];
    snprintf(expected, sizeof(expected), "%s/RealDownloads", tmp);
    CHECK(strcmp(buf, expected) == 0, "comment not mistaken for entry");
}

static void test_whitespace_before_key(void)
{
    printf("\nwhitespace_before_key:\n");
    char* tmp = make_tmpdir();
    const char* content =
        "  XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n";
    char* cfg = write_dirs_file(tmp, content);
    xdg_set_config_home(cfg);
    xdg_set_home_dir(tmp);

    char buf[512] = {0};
    BOOL ok = GetXdgUserDir("DOWNLOAD", buf, sizeof(buf));
    CHECK(ok == TRUE, "leading whitespace before key handled");
}

static void test_multiple_dirs_coexist(void)
{
    printf("\nmultiple_dirs_coexist:\n");
    char* tmp = make_tmpdir();
    const char* content =
        "XDG_DESKTOP_DIR=\"$HOME/Desktop\"\n"
        "XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n"
        "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n"
        "XDG_MUSIC_DIR=\"$HOME/Music\"\n"
        "XDG_PICTURES_DIR=\"$HOME/Pictures\"\n"
        "XDG_VIDEOS_DIR=\"$HOME/Videos\"\n";
    char* cfg = write_dirs_file(tmp, content);
    xdg_set_config_home(cfg);
    xdg_set_home_dir(tmp);

    char buf[512] = {0};
    char expected[512];

    BOOL ok = GetXdgUserDir("DOCUMENTS", buf, sizeof(buf));
    CHECK(ok == TRUE, "DOCUMENTS found");
    snprintf(expected, sizeof(expected), "%s/Documents", tmp);
    CHECK(strcmp(buf, expected) == 0, "DOCUMENTS correct");

    ok = GetXdgUserDir("MUSIC", buf, sizeof(buf));
    CHECK(ok == TRUE, "MUSIC found");
    snprintf(expected, sizeof(expected), "%s/Music", tmp);
    CHECK(strcmp(buf, expected) == 0, "MUSIC correct");

    ok = GetXdgUserDir("PICTURES", buf, sizeof(buf));
    CHECK(ok == TRUE, "PICTURES found");
    snprintf(expected, sizeof(expected), "%s/Pictures", tmp);
    CHECK(strcmp(buf, expected) == 0, "PICTURES correct");
}

/* ── main ─────────────────────────────────────────────────────────────────── */
int main(void)
{
    printf("xdg_dirs_linux tests\n");
    printf("====================\n");

    test_download_home_relative();
    test_desktop_home_relative();
    test_absolute_path();
    test_missing_key_returns_false();
    test_missing_file_returns_false();
    test_comment_lines_ignored();
    test_whitespace_before_key();
    test_multiple_dirs_coexist();

    printf("\n%d passed, %d failed\n", tests_run - tests_failed, tests_failed);
    return tests_failed ? 1 : 0;
}
