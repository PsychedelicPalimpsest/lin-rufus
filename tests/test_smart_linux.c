/*
 * test_smart_linux.c - TDD tests for the Linux SMART implementation
 *
 * Tests cover SptStrerr(), ScsiPassthroughDirect(), Identify(),
 * SmartGetVersion(), and IsHDD().
 */

#define _GNU_SOURCE
#include "framework.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <windows.h>        /* from linux/compat */

#include "../src/windows/rufus.h"
#include "../src/windows/drive.h"
#include "../src/windows/smart.h"

/* ── globals expected by smart.c ──────────────────────────────────── */
DWORD  ErrorStatus = 0, DownloadStatus = 0, MainThreadId = 0, LastWriteError = 0;
BOOL   allow_dual_uefi_bios = FALSE, large_drive = FALSE, usb_debug = FALSE;
HWND   hMainDialog = NULL;
RUFUS_DRIVE_INFO SelectedDrive = { .SectorSize = 512 };

/* ── stubs ─────────────────────────────────────────────────────────── */
void uprintf(const char *fmt, ...)
    { va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); }
char *lmprintf(int msg_id, ...) { (void)msg_id; return ""; }
void PrintStatusInfo(BOOL info, BOOL debug, unsigned int dur, int msg_id, ...)
    { (void)info; (void)debug; (void)dur; (void)msg_id; }

/* Controllable stubs for GetDriveTypeFromIndex / GetDriveSize */
static UINT   test_drive_type = DRIVE_REMOVABLE;
static uint64_t test_drive_size = 256ULL * 1024 * 1024 * 1024; /* 256 GB */

UINT GetDriveTypeFromIndex(DWORD DriveIndex) { (void)DriveIndex; return test_drive_type; }
uint64_t GetDriveSize(DWORD DriveIndex)      { (void)DriveIndex; return test_drive_size; }

/* ── forward declarations (non-static under RUFUS_TEST) ───────────── */
int  ScsiPassthroughDirect(HANDLE hPhysical, uint8_t* Cdb, size_t CdbLen,
                           uint8_t Direction, void* DataBuffer,
                           size_t BufLen, uint32_t Timeout);
BOOL Identify(HANDLE hPhysical);
BOOL SmartGetVersion(HANDLE hdevice);
const char* SptStrerr(int errcode);

/* ── helper: 16-byte aligned buffer on heap ──────────────────────── */
static void *make_aligned_buf(size_t size)
{
    void *p = NULL;
    if (posix_memalign(&p, 16, size ? size : 16) != 0)
        return NULL;
    return p;
}

/* ================================================================== */
/* SptStrerr tests                                                      */
/* ================================================================== */

TEST(spt_strerr_success)
{
    CHECK_STR_EQ(SptStrerr(SPT_SUCCESS), "Success");
}

TEST(spt_strerr_cdb_length)
{
    const char *s = SptStrerr(SPT_ERROR_CDB_LENGTH);
    CHECK(s != NULL && strlen(s) > 0);
}

TEST(spt_strerr_buffer)
{
    const char *s = SptStrerr(SPT_ERROR_BUFFER);
    CHECK(s != NULL && strlen(s) > 0);
}

TEST(spt_strerr_direction)
{
    const char *s = SptStrerr(SPT_ERROR_DIRECTION);
    CHECK(s != NULL && strlen(s) > 0);
}

TEST(spt_strerr_extended_cdb)
{
    const char *s = SptStrerr(SPT_ERROR_EXTENDED_CDB);
    CHECK(s != NULL && strlen(s) > 0);
}

TEST(spt_strerr_cdb_opcode)
{
    const char *s = SptStrerr(SPT_ERROR_CDB_OPCODE);
    CHECK(s != NULL && strlen(s) > 0);
}

TEST(spt_strerr_timeout)
{
    CHECK_STR_EQ(SptStrerr(SPT_ERROR_TIMEOUT), "Timeout");
}

TEST(spt_strerr_invalid_param)
{
    const char *s = SptStrerr(SPT_ERROR_INVALID_PARAMETER);
    CHECK(s != NULL && strlen(s) > 0);
}

TEST(spt_strerr_check_status)
{
    const char *s = SptStrerr(SPT_ERROR_CHECK_STATUS);
    CHECK(s != NULL && strlen(s) > 0);
}

TEST(spt_strerr_unknown)
{
    CHECK_STR_EQ(SptStrerr(SPT_ERROR_UNKNOWN_ERROR), "Unknown error");
}

TEST(spt_strerr_scsi_positive)
{
    const char *s = SptStrerr(12);
    CHECK(s != NULL);
    CHECK(strncmp(s, "SCSI status:", 12) == 0);
}

/* ================================================================== */
/* ScsiPassthroughDirect parameter-validation tests                    */
/* ================================================================== */

TEST(scsi_passthrough_zero_cdb)
{
    uint8_t cdb[6] = {0x12, 0, 0, 0, 36, 0}; /* INQUIRY */
    void *buf = make_aligned_buf(36);
    int r = ScsiPassthroughDirect(NULL, cdb, 0,
                                   SCSI_IOCTL_DATA_IN, buf, 36, 2);
    CHECK_INT_EQ(r, SPT_ERROR_CDB_LENGTH);
    free(buf);
}

TEST(scsi_passthrough_long_cdb)
{
    uint8_t cdb[17] = {0};
    cdb[0] = 0x12; /* INQUIRY */
    void *buf = make_aligned_buf(36);
    int r = ScsiPassthroughDirect(NULL, cdb, 17,
                                   SCSI_IOCTL_DATA_IN, buf, 36, 2);
    CHECK_INT_EQ(r, SPT_ERROR_CDB_LENGTH);
    free(buf);
}

TEST(scsi_passthrough_bad_direction)
{
    uint8_t cdb[6] = {0x12, 0, 0, 0, 36, 0};
    void *buf = make_aligned_buf(36);
    /* Direction > SCSI_IOCTL_DATA_UNSPECIFIED(2) */
    int r = ScsiPassthroughDirect(NULL, cdb, 6,
                                   3, buf, 36, 2);
    CHECK_INT_EQ(r, SPT_ERROR_DIRECTION);
    free(buf);
}

TEST(scsi_passthrough_extended_cdb)
{
    uint8_t cdb[6] = {0x7e, 0, 0, 0, 0, 0};
    void *buf = make_aligned_buf(16);
    int r = ScsiPassthroughDirect(NULL, cdb, 6,
                                   SCSI_IOCTL_DATA_UNSPECIFIED, buf, 0, 2);
    CHECK_INT_EQ(r, SPT_ERROR_EXTENDED_CDB);
    free(buf);
}

TEST(scsi_passthrough_high_opcode)
{
    /* 0xc1 is >= 0xc0 and not a USB bridge opcode */
    uint8_t cdb[6] = {0xc1, 0, 0, 0, 0, 0};
    void *buf = make_aligned_buf(16);
    int r = ScsiPassthroughDirect(NULL, cdb, 6,
                                   SCSI_IOCTL_DATA_UNSPECIFIED, buf, 0, 2);
    CHECK_INT_EQ(r, SPT_ERROR_CDB_OPCODE);
    free(buf);
}

TEST(scsi_passthrough_bad_buf_align)
{
    uint8_t cdb[6] = {0x12, 0, 0, 0, 36, 0};
    /* stack buffer: &raw[1] is misaligned by 1 byte */
    char raw[64];
    void *unaligned = (void *)((char *)raw + 1);
    int r = ScsiPassthroughDirect(NULL, cdb, 6,
                                   SCSI_IOCTL_DATA_IN, unaligned, 36, 2);
    CHECK_INT_EQ(r, SPT_ERROR_BUFFER);
}

TEST(scsi_passthrough_invalid_fd)
{
    uint8_t cdb[6] = {0x12, 0, 0, 0, 0, 0}; /* INQUIRY, BufLen=0 */
    HANDLE bad = (HANDLE)(intptr_t)(-1);
    /* NULL is 16-byte aligned; BufLen=0 passes size check */
    int r = ScsiPassthroughDirect(bad, cdb, 6,
                                   SCSI_IOCTL_DATA_UNSPECIFIED, NULL, 0, 2);
    CHECK(r != SPT_SUCCESS);
}

/* ================================================================== */
/* Identify / SmartGetVersion tests                                     */
/* ================================================================== */

TEST(identify_invalid_fd)
{
    SelectedDrive.SectorSize = 512;
    HANDLE bad = (HANDLE)(intptr_t)(-1);
    BOOL r = Identify(bad);
    CHECK(r == FALSE);
}

TEST(smart_get_version_invalid_fd)
{
    HANDLE bad = (HANDLE)(intptr_t)(-1);
    BOOL r = SmartGetVersion(bad);
    CHECK(r == FALSE);
}

/* ================================================================== */
/* IsHDD scoring tests                                                  */
/* ================================================================== */

TEST(is_hdd_null_strid)
{
    test_drive_type = DRIVE_REMOVABLE;
    test_drive_size = 256ULL * 1024 * 1024 * 1024; /* 256 GB – neutral range */
    /* Must not crash; return value is the score (just check it runs) */
    int score = IsHDD(0, 0, 0, NULL);
    (void)score;
    CHECK(1); /* didn't crash */
}

TEST(is_hdd_large_drive_score)
{
    /* DRIVE_FIXED(+3) + >800GB(+15) = +18 → positive */
    test_drive_type = DRIVE_FIXED;
    test_drive_size = 900ULL * 1024 * 1024 * 1024;
    int score = IsHDD(0, 0, 0, NULL);
    CHECK(score > 0);
}

TEST(is_hdd_small_drive_score)
{
    /* size < 128GB → -15 contribution */
    test_drive_type = DRIVE_REMOVABLE;
    test_drive_size = 64ULL * 1024 * 1024 * 1024;
    int score = IsHDD(0, 0, 0, NULL);
    CHECK(score < 0);
}

TEST(is_hdd_seagate_strid)
{
    /* "ST123456" matches str_score entry "ST#" → +10 */
    test_drive_type = DRIVE_REMOVABLE;
    test_drive_size = 256ULL * 1024 * 1024 * 1024; /* neutral size */
    int score = IsHDD(0, 0, 0, "ST123456");
    CHECK(score > 0);
}

TEST(is_hdd_known_vid)
{
    /* VID 0x0bc2 = Seagate, vid_score = +10 */
    test_drive_type = DRIVE_REMOVABLE;
    test_drive_size = 256ULL * 1024 * 1024 * 1024; /* neutral size */
    int score = IsHDD(0, 0x0bc2, 0, NULL);
    CHECK(score > 0);
}

/* ================================================================== */
/* main                                                                 */
/* ================================================================== */

int main(void)
{
    printf("=== test_smart_linux ===\n");

    RUN(spt_strerr_success);
    RUN(spt_strerr_cdb_length);
    RUN(spt_strerr_buffer);
    RUN(spt_strerr_direction);
    RUN(spt_strerr_extended_cdb);
    RUN(spt_strerr_cdb_opcode);
    RUN(spt_strerr_timeout);
    RUN(spt_strerr_invalid_param);
    RUN(spt_strerr_check_status);
    RUN(spt_strerr_unknown);
    RUN(spt_strerr_scsi_positive);

    RUN(scsi_passthrough_zero_cdb);
    RUN(scsi_passthrough_long_cdb);
    RUN(scsi_passthrough_bad_direction);
    RUN(scsi_passthrough_extended_cdb);
    RUN(scsi_passthrough_high_opcode);
    RUN(scsi_passthrough_bad_buf_align);
    RUN(scsi_passthrough_invalid_fd);

    RUN(identify_invalid_fd);
    RUN(smart_get_version_invalid_fd);

    RUN(is_hdd_null_strid);
    RUN(is_hdd_large_drive_score);
    RUN(is_hdd_small_drive_score);
    RUN(is_hdd_seagate_strid);
    RUN(is_hdd_known_vid);

    TEST_RESULTS();
}
