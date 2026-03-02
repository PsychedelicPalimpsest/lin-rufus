/*
 * test_analyze_br_common.c — Tests for AnalyzeMBR() and AnalyzePBR()
 * from src/common/drive.c — shared code between Linux and Windows.
 *
 * These functions analyze boot-sector MBR/PBR content using the ms-sys
 * FAKE_FD mechanism.  Tests run as Linux native; the implementations live
 * in src/common/drive.c (after extraction from the per-platform files).
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "framework.h"

#include "../src/linux/drive_linux.h"
#include "../src/windows/rufus.h"    /* BOOL, HANDLE, etc. */
#include "../src/common/drive.h"     /* AnalyzeMBR, AnalyzePBR declarations */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* -------------------------------------------------------------------------
 * Helper: create a temporary file of the given size, return fd.
 * ---------------------------------------------------------------------- */
static int make_temp_file(char path[64], size_t size)
{
    strcpy(path, "/tmp/rufus_abr_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    if (size > 0 && ftruncate(fd, (off_t)size) != 0) {
        close(fd); unlink(path); return -1;
    }
    return fd;
}

/* Helper: register a temp file as drive, return an open HANDLE. */
static HANDLE open_drive(const char *path)
{
    drive_linux_reset_drives();
    drive_linux_add_drive(path, "T", "TestDrive", 512);
    return GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
}

/* =========================================================================
 * AnalyzeMBR — null / invalid handle guards
 * ======================================================================= */

TEST(analyze_mbr_null_handle_returns_false)
{
    /* NULL handle must return FALSE gracefully without crashing */
    BOOL r = AnalyzeMBR(NULL, "Null", TRUE);
    CHECK(r == FALSE);
}

TEST(analyze_mbr_invalid_handle_returns_false)
{
    BOOL r = AnalyzeMBR(INVALID_HANDLE_VALUE, "Invalid", TRUE);
    CHECK(r == FALSE);
}

/* =========================================================================
 * AnalyzeMBR — no boot marker (zeroed sector)
 * ======================================================================= */

TEST(analyze_mbr_zeroed_sector_returns_false)
{
    /* A 512-byte file of zeros has no 0x55AA at offset 0x1FE,
     * so AnalyzeMBR should return FALSE. */
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzeMBR(h, "ZeroedDrive", TRUE);
    CHECK(r == FALSE);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

/* =========================================================================
 * AnalyzeMBR — sector with 0x55AA boot marker (unknown MBR type)
 * ======================================================================= */

TEST(analyze_mbr_with_boot_marker_returns_true)
{
    /* Writing 0x55AA at offset 0x1FE satisfies is_br().
     * AnalyzeMBR should return TRUE (unknown MBR, but has a boot marker). */
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);

    uint8_t sig[2] = { 0x55, 0xAA };
    pwrite(fd, sig, 2, 0x1FE);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzeMBR(h, "MarkedDrive", TRUE);
    CHECK(r == TRUE);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

/* =========================================================================
 * AnalyzeMBR — bSilent=FALSE still returns the same values
 * ======================================================================= */

TEST(analyze_mbr_silent_false_no_marker)
{
    /* bSilent=FALSE triggers uprintf output but should not change return value */
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzeMBR(h, "SilentTest", FALSE);
    CHECK(r == FALSE);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

TEST(analyze_mbr_silent_false_with_marker)
{
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    uint8_t sig[2] = { 0x55, 0xAA };
    pwrite(fd, sig, 2, 0x1FE);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzeMBR(h, "SilentTest2", FALSE);
    CHECK(r == TRUE);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

/* =========================================================================
 * AnalyzeMBR — NULL TargetName guard (should use "Drive" fallback)
 * ======================================================================= */

TEST(analyze_mbr_null_target_name_no_marker)
{
    /* NULL TargetName should not crash; should fall back to "Drive" label */
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzeMBR(h, NULL, TRUE);
    CHECK(r == FALSE);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

TEST(analyze_mbr_null_target_name_with_marker)
{
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    uint8_t sig[2] = { 0x55, 0xAA };
    pwrite(fd, sig, 2, 0x1FE);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzeMBR(h, NULL, TRUE);
    CHECK(r == TRUE);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

/* =========================================================================
 * AnalyzePBR — null / invalid handle guards
 * ======================================================================= */

TEST(analyze_pbr_null_handle_returns_false)
{
    BOOL r = AnalyzePBR(NULL);
    CHECK(r == FALSE);
}

TEST(analyze_pbr_invalid_handle_returns_false)
{
    BOOL r = AnalyzePBR(INVALID_HANDLE_VALUE);
    CHECK(r == FALSE);
}

/* =========================================================================
 * AnalyzePBR — zeroed sector (no x86 boot marker)
 * ======================================================================= */

TEST(analyze_pbr_zeroed_sector_returns_false)
{
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzePBR(h);
    CHECK(r == FALSE);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

/* =========================================================================
 * AnalyzePBR — sector with 0x55AA but unknown (non-FAT) PBR
 * ======================================================================= */

TEST(analyze_pbr_unknown_pbr_returns_true)
{
    /* With 0x55AA but no recognizable FAT PBR → should return TRUE
     * with "unknown PBR" message (PBR marker present but type unknown). */
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    uint8_t sig[2] = { 0x55, 0xAA };
    pwrite(fd, sig, 2, 0x1FE);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r = AnalyzePBR(h);
    CHECK(r == TRUE);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

/* =========================================================================
 * AnalyzeMBR — multiple calls with same handle are idempotent
 * ======================================================================= */

TEST(analyze_mbr_repeated_calls_consistent)
{
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    uint8_t sig[2] = { 0x55, 0xAA };
    pwrite(fd, sig, 2, 0x1FE);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r1 = AnalyzeMBR(h, "Drive", TRUE);
    BOOL r2 = AnalyzeMBR(h, "Drive", TRUE);
    BOOL r3 = AnalyzeMBR(h, "Drive", TRUE);
    CHECK(r1 == TRUE);
    CHECK(r1 == r2);
    CHECK(r2 == r3);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

/* =========================================================================
 * AnalyzePBR — multiple calls consistent
 * ======================================================================= */

TEST(analyze_pbr_repeated_calls_consistent)
{
    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    BOOL r1 = AnalyzePBR(h);
    BOOL r2 = AnalyzePBR(h);
    CHECK(r1 == r2);

    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

/* =========================================================================
 * AnalyzeMBR — sector size affects analysis (verify SectorSize guard)
 * ======================================================================= */

TEST(analyze_mbr_uses_selected_drive_sector_size)
{
    /* When SelectedDrive.SectorSize is 0, the implementation falls back to 512.
     * The function should still work without crashing. */
    extern RUFUS_DRIVE_INFO SelectedDrive;
    DWORD saved = SelectedDrive.SectorSize;
    SelectedDrive.SectorSize = 0;  /* Force fallback path */

    char path[64];
    int fd = make_temp_file(path, 512);
    CHECK(fd >= 0);
    uint8_t sig[2] = { 0x55, 0xAA };
    pwrite(fd, sig, 2, 0x1FE);
    close(fd);

    HANDLE h = open_drive(path);
    CHECK(h != INVALID_HANDLE_VALUE);

    /* With SectorSize=0, common code uses 512 as fallback → should still work */
    BOOL r = AnalyzeMBR(h, "Drive", TRUE);
    CHECK(r == TRUE);

    SelectedDrive.SectorSize = saved;
    CloseHandle(h);
    unlink(path);
    drive_linux_reset_drives();
}

/* =========================================================================
 * main
 * ======================================================================= */

int main(void)
{
    RUN(analyze_mbr_null_handle_returns_false);
    RUN(analyze_mbr_invalid_handle_returns_false);
    RUN(analyze_mbr_zeroed_sector_returns_false);
    RUN(analyze_mbr_with_boot_marker_returns_true);
    RUN(analyze_mbr_silent_false_no_marker);
    RUN(analyze_mbr_silent_false_with_marker);
    RUN(analyze_mbr_null_target_name_no_marker);
    RUN(analyze_mbr_null_target_name_with_marker);
    RUN(analyze_pbr_null_handle_returns_false);
    RUN(analyze_pbr_invalid_handle_returns_false);
    RUN(analyze_pbr_zeroed_sector_returns_false);
    RUN(analyze_pbr_unknown_pbr_returns_true);
    RUN(analyze_mbr_repeated_calls_consistent);
    RUN(analyze_pbr_repeated_calls_consistent);
    RUN(analyze_mbr_uses_selected_drive_sector_size);
    TEST_RESULTS();
}
