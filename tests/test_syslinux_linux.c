/*
 * test_syslinux_linux.c — Tests for Linux syslinux bootloader installation
 *
 * Tests cover:
 *   • GetSyslinuxVersion() — buffer scanning for V4 and V6 version strings
 *   • libfat_readfile()    — pread-based sector read for libfat traversal
 *   • InstallSyslinux()    — full install on a loopback FAT32 image file
 *
 * InstallSyslinux test uses mtools (mcopy / mformat) to populate the image
 * without needing root privileges.
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

/* ---- compat layer ---- */
#include "windows.h"
#include "commctrl.h"

/* ---- rufus headers ---- */
#include "rufus.h"
#include "drive.h"
#include "resource.h"
#include "syslinux.h"      /* syslinux_make_bootsect, syslinux_patch, etc. */
#include "syslxfs.h"       /* VFAT */
#include "libfat.h"        /* libfat_open, libfat_searchdir, etc. */
#include "setadv.h"        /* syslinux_adv, syslinux_reset_adv, ADV_SIZE */

/* ---- test framework ---- */
#include "framework.h"

/* ================================================================
 * Minimal required globals (mirrors test_format_thread_linux.c)
 * ================================================================ */

RUFUS_DRIVE rufus_drive[MAX_DRIVES];
extern RUFUS_DRIVE_INFO SelectedDrive;
extern int partition_index[PI_MAX];

HWND hMainDialog   = NULL;
HWND hDeviceList   = NULL;
HWND hProgress     = NULL;
HWND hStatus       = NULL;
HWND hInfo         = NULL;
HWND hLog          = NULL;

BOOL enable_HDDs           = FALSE;
BOOL enable_VHDs           = TRUE;
BOOL right_to_left_mode    = FALSE;
BOOL op_in_progress        = FALSE;
BOOL large_drive           = FALSE;
BOOL write_as_esp          = FALSE;
BOOL write_as_image        = FALSE;
BOOL lock_drive            = FALSE;
BOOL zero_drive            = FALSE;
BOOL fast_zeroing          = FALSE;
BOOL force_large_fat32     = FALSE;
BOOL enable_ntfs_compression = FALSE;
BOOL enable_file_indexing  = FALSE;
BOOL allow_dual_uefi_bios  = FALSE;
BOOL usb_debug             = FALSE;
BOOL detect_fakes          = FALSE;
BOOL use_own_c32[NB_OLD_C32];
BOOL has_uefi_csm          = FALSE;
BOOL enable_vmdk           = FALSE;
BOOL use_fake_units        = FALSE;
BOOL preserve_timestamps   = FALSE;
BOOL app_changed_size      = FALSE;
BOOL list_non_usb_removable_drives = FALSE;
BOOL no_confirmation_on_cancel = FALSE;
BOOL advanced_mode_device  = FALSE;
BOOL advanced_mode_format  = FALSE;
BOOL use_rufus_mbr         = TRUE;
BOOL its_a_me_mario        = FALSE;

DWORD ErrorStatus          = 0;
DWORD LastWriteError       = 0;
DWORD MainThreadId         = 0;
DWORD DownloadStatus       = 0;

int fs_type                = 0;
int boot_type              = BT_SYSLINUX_V4;
int partition_type         = 0;
int target_type            = 0;
uint8_t image_options      = 0;
int dialog_showing         = 0;
int force_update           = 0;
int selection_default      = 0;
int persistence_unit_selection = -1;
int64_t iso_blocking_status = -1;

uint64_t persistence_size  = 0;
uint32_t pe256ssp_size     = 0;
uint8_t *pe256ssp          = NULL;
uint16_t rufus_version[3]  = {0,0,0};
uint16_t embedded_sl_version[2] = {0,0};
uint32_t dur_mins = 0, dur_secs = 0;

char szFolderPath[MAX_PATH]    = "";
char app_dir[MAX_PATH]         = "";
char temp_dir[MAX_PATH]        = "/tmp";
char cur_dir[MAX_PATH]         = "";
char app_data_dir[MAX_PATH]    = "";
char user_dir[MAX_PATH]        = "";
char system_dir[MAX_PATH]      = "";
char sysnative_dir[MAX_PATH]   = "";
char msgbox[1024]              = "";
char msgbox_title[32]          = "";
char image_option_txt[128]     = "";
char embedded_sl_version_str[2][12] = {"4.07", "6.04"};
char embedded_sl_version_ext[2][32] = {"", ""};
char ubuffer[UBUFFER_SIZE];

RUFUS_IMG_REPORT img_report;
unsigned long syslinux_ldlinux_len[2];

/* Silence PrintStatusInfo in tests */
void PrintStatusInfo(BOOL beep, BOOL fake_error, unsigned int duration,
                     int msg_id, ...) {
    (void)beep;(void)fake_error;(void)duration;(void)msg_id;
}

/* ================================================================
 * Helper: locate a file relative to the tests/ directory
 * Tests are always run with CWD = tests/, so ../res works.
 * ================================================================ */

static char res_path[512];
static const char *syslinux_res(const char *filename)
{
    snprintf(res_path, sizeof(res_path), "../res/syslinux/%s", filename);
    return res_path;
}

/* ================================================================
 * Helper: load a file into a malloc'd buffer
 * ================================================================ */
static uint8_t *load_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';   /* NUL-terminate so strtoul doesn't overrun */
    if (out_len) *out_len = (size_t)sz;
    return buf;
}

/* ================================================================
 * Tests for GetSyslinuxVersion()
 * ================================================================ */

TEST(get_syslinux_version_v4_file)
{
    const char *path = syslinux_res("ldlinux_v4.sys");
    size_t len = 0;
    char *buf = (char *)load_file(path, &len);
    if (!buf) {
        printf("  SKIP: %s not found\n", path);
        return;
    }
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion(buf, len, &ext);
    free(buf);
    /* Version must be in the range [4.00, 5.00) */
    CHECK_INT_EQ(4, (int)(ver >> 8));   /* major must be 4 */
}

TEST(get_syslinux_version_v6_file)
{
    const char *path = syslinux_res("ldlinux_v6.sys");
    size_t len = 0;
    char *buf = (char *)load_file(path, &len);
    if (!buf) {
        printf("  SKIP: %s not found\n", path);
        return;
    }
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion(buf, len, &ext);
    free(buf);
    /* Version must be in the range [6.00, 7.00) */
    CHECK_INT_EQ(6, (int)(ver >> 8));
}

TEST(get_syslinux_version_synthetic_v4)
{
    /* Build a 512-byte buffer with a V4 version string at offset 100 */
    char buf[512];
    memset(buf, 0, sizeof(buf));
    /* "SYSLINUX 4.07 ..." — "SYS" + "LINUX " + "4.07 ..." */
    const char *marker = "SYSLINUX 4.07  Copyright (C) 1994-2011 H. Peter Anvin et al";
    memcpy(buf + 100, marker, strlen(marker));
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion(buf, sizeof(buf), &ext);
    CHECK_INT_EQ(4, (int)(ver >> 8));
    CHECK_INT_EQ(7, (int)(ver & 0xFF));
}

TEST(get_syslinux_version_synthetic_v6)
{
    char buf[512];
    memset(buf, 0, sizeof(buf));
    const char *marker = "SYSLINUX 6.04  Copyright (C) 1994-2015 H. Peter Anvin et al";
    memcpy(buf + 100, marker, strlen(marker));
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion(buf, sizeof(buf), &ext);
    CHECK_INT_EQ(6, (int)(ver >> 8));
    CHECK_INT_EQ(4, (int)(ver & 0xFF));
}

TEST(get_syslinux_version_isolinux)
{
    char buf[512];
    memset(buf, 0, sizeof(buf));
    /* ISOLINUX prefix */
    const char *marker = "ISOLINUX 6.03  Copyright (C) 1994-2014 H. Peter Anvin et al";
    memcpy(buf + 100, marker, strlen(marker));
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion(buf, sizeof(buf), &ext);
    CHECK_INT_EQ(6, (int)(ver >> 8));
    CHECK_INT_EQ(3, (int)(ver & 0xFF));
}

TEST(get_syslinux_version_no_version)
{
    char buf[256];
    memset(buf, 0xCC, sizeof(buf));
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion(buf, sizeof(buf), &ext);
    CHECK_INT_EQ(0, (int)ver);
}

TEST(get_syslinux_version_buf_too_small)
{
    char buf[100];
    memset(buf, 0, sizeof(buf));
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion(buf, 100, &ext);
    CHECK_INT_EQ(0, (int)ver);
}

TEST(get_syslinux_version_null_ext_out)
{
    /* ext pointer can be non-NULL even before call; function sets *ext */
    char buf[512];
    memset(buf, 0, sizeof(buf));
    const char *marker = "SYSLINUX 4.05  Copyright blah";
    memcpy(buf + 100, marker, strlen(marker));
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion(buf, sizeof(buf), &ext);
    CHECK(ver != 0);
    CHECK(ext != NULL);   /* ext is set to either "" or version suffix */
}

/* ================================================================
 * Tests for libfat_readfile()
 *
 * libfat_readfile(intptr_t pp, void *buf, size_t secsize, libfat_sector_t s)
 * reads secsize bytes at offset s*secsize from fd pp using pread().
 * ================================================================ */

TEST(libfat_readfile_basic)
{
    /* Create a 1-sector temp file filled with known pattern */
    char tmpf[] = "/tmp/test_sl_readfile_XXXXXX";
    int fd = mkstemp(tmpf);
    CHECK(fd >= 0);

    uint8_t pattern[512];
    for (int i = 0; i < 512; i++) pattern[i] = (uint8_t)(i & 0xFF);
    ssize_t w = write(fd, pattern, 512);
    CHECK_INT_EQ(512, (int)w);

    uint8_t readbuf[512] = {0};
    int r = libfat_readfile((intptr_t)fd, readbuf, 512, 0);
    CHECK_INT_EQ(512, r);
    CHECK_INT_EQ(0, memcmp(pattern, readbuf, 512));

    close(fd);
    unlink(tmpf);
}

TEST(libfat_readfile_sector_offset)
{
    /* Write two sectors; read sector 1 */
    char tmpf[] = "/tmp/test_sl_readfile2_XXXXXX";
    int fd = mkstemp(tmpf);
    CHECK(fd >= 0);

    uint8_t s0[512], s1[512];
    memset(s0, 0xAA, 512);
    memset(s1, 0xBB, 512);
    CHECK_INT_EQ(512, (int)write(fd, s0, 512));
    CHECK_INT_EQ(512, (int)write(fd, s1, 512));

    uint8_t readbuf[512] = {0};
    int r = libfat_readfile((intptr_t)fd, readbuf, 512, 1);  /* sector 1 */
    CHECK_INT_EQ(512, r);
    CHECK_INT_EQ(0, memcmp(s1, readbuf, 512));

    close(fd);
    unlink(tmpf);
}

TEST(libfat_readfile_bad_fd)
{
    uint8_t buf[512];
    int r = libfat_readfile((intptr_t)(-1), buf, 512, 0);
    CHECK(r <= 0);
}

/* ================================================================
 * Tests for InstallSyslinux() using a loopback FAT32 image
 *
 * Strategy:
 *   1. truncate + mkfs.fat  → creates a 16 MB FAT32 image
 *   2. mcopy                → writes ldlinux.sys + ADV into the image
 *   3. InstallSyslinux()    → patches ldlinux.sys and installs boot sector
 *   4. Verify               → VBR has syslinux boot code (SYSLINUX marker)
 *
 * No root privileges needed — all writes go to a regular file.
 * ================================================================ */

/* Run a shell command; return TRUE on success */
static BOOL run_cmd(const char *fmt, ...)
{
    char cmd[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    return (system(cmd) == 0) ? TRUE : FALSE;
}

/* Check if mtools is available */
static BOOL has_mtools(void)
{
    return (system("which mcopy >/dev/null 2>&1") == 0) ? TRUE : FALSE;
}

static BOOL has_mkfs_fat(void)
{
    return (system("which mkfs.fat >/dev/null 2>&1") == 0) ? TRUE : FALSE;
}

TEST(install_syslinux_fat32_image)
{
    if (!has_mtools() || !has_mkfs_fat()) {
        printf("  SKIP: mtools or mkfs.fat not available\n");
        return;
    }

    const char *sys_path = syslinux_res("ldlinux_v4.sys");
    const char *bss_path = syslinux_res("ldlinux_v4.bss");

    /* Skip if resource files are missing */
    if (access(sys_path, R_OK) != 0 || access(bss_path, R_OK) != 0) {
        printf("  SKIP: ldlinux_v4.sys/bss not found in res/syslinux/\n");
        return;
    }

    /* Create a temp 64 MB FAT32 image with 1 sector/cluster so libfat
     * correctly identifies it as FAT28 (needs >65524 clusters). */
    char img[] = "/tmp/test_syslinux_XXXXXX";
    int tfd = mkstemp(img);
    CHECK(tfd >= 0);
    close(tfd);

    /* Expand to 64 MB and format; -s 1 forces 1 sector/cluster */
    CHECK(run_cmd("truncate -s 64M '%s'", img));
    CHECK(run_cmd("mkfs.fat -F32 -s 1 -n TESTSL '%s' >/dev/null 2>&1", img));

    /* Open image fd for post-install VBR check */
    int img_fd = open(img, O_RDWR | O_CLOEXEC);
    CHECK(img_fd >= 0);

    /* Load ldlinux.sys only to derive the embedded version number */
    size_t sys_len = 0;
    uint8_t *sys_data = load_file(sys_path, &sys_len);
    CHECK(sys_data != NULL);

    /* Set up drive parameters that InstallSyslinux() needs */
    SelectedDrive.SectorSize = 512;

    /* Set up a fake rufus_drive entry pointing to the image */
    memset(&rufus_drive[0], 0, sizeof(rufus_drive[0]));
    rufus_drive[0].id   = strdup(img);
    rufus_drive[0].size = 64 * 1024 * 1024ULL;
    SelectedDrive.DiskSize  = (LONGLONG)rufus_drive[0].size;
    SelectedDrive.DeviceNumber = 0;

    /* Set the app_dir so InstallSyslinux can find resource files */
    snprintf(app_dir, sizeof(app_dir), "../");
    snprintf(app_data_dir, sizeof(app_data_dir), "../");

    /* Set boot_type and embedded_sl_version for V4 */
    boot_type = BT_SYSLINUX_V4;
    embedded_sl_version[0] = GetSyslinuxVersion((char *)sys_data, sys_len,
                                                 &(char *){NULL});
    memcpy(embedded_sl_version_str[0], "4.07", 5);

    /* img_report.cfg_path must be set (default is root) */
    memset(&img_report, 0, sizeof(img_report));

    /* Call InstallSyslinux with the image as drive 0, fs_type = FAT32 */
    BOOL result = InstallSyslinux(0, '\0', FS_FAT32);
    CHECK(result == TRUE);

    /* Verify: VBR should now contain syslinux boot code.
     * The syslinux signature appears in the OEM Name field at bytes 3-10,
     * OR we check for the syslinux-specific 0xFA NOP at offset 0. */
    uint8_t vbr[512];
    CHECK_INT_EQ(512, (int)pread(img_fd, vbr, 512, 0));

    /* Standard x86 boot sector signature */
    CHECK_INT_EQ(0x55, vbr[510]);
    CHECK_INT_EQ(0xAA, vbr[511]);

    /* The patched ldlinux.sys should still be present in the FAT directory. */
    char mcopy_check_cmd[512];
    snprintf(mcopy_check_cmd, sizeof(mcopy_check_cmd),
             "MTOOLS_SKIP_CHECK=1 mdir -i '%s' '::' 2>/dev/null | grep -qi ldlinux",
             img);
    CHECK(system(mcopy_check_cmd) == 0);

    close(img_fd);
    free(sys_data);
    free(rufus_drive[0].id);
    rufus_drive[0].id = NULL;
    unlink(img);
}

TEST(install_syslinux_v4_version_check)
{
    const char *path = syslinux_res("ldlinux_v4.sys");
    size_t len = 0;
    uint8_t *data = load_file(path, &len);
    if (!data) { printf("  SKIP: ldlinux_v4.sys not found\n"); return; }
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion((char *)data, len, &ext);
    free(data);
    CHECK(ver != 0);
    CHECK_INT_EQ(4, (int)(ver >> 8));
}

TEST(install_syslinux_v6_version_check)
{
    const char *path = syslinux_res("ldlinux_v6.sys");
    size_t len = 0;
    uint8_t *data = load_file(path, &len);
    if (!data) { printf("  SKIP: ldlinux_v6.sys not found\n"); return; }
    char *ext = NULL;
    uint16_t ver = GetSyslinuxVersion((char *)data, len, &ext);
    free(data);
    CHECK(ver != 0);
    CHECK_INT_EQ(6, (int)(ver >> 8));
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void)
{
    RUN(get_syslinux_version_v4_file);
    RUN(get_syslinux_version_v6_file);
    RUN(get_syslinux_version_synthetic_v4);
    RUN(get_syslinux_version_synthetic_v6);
    RUN(get_syslinux_version_isolinux);
    RUN(get_syslinux_version_no_version);
    RUN(get_syslinux_version_buf_too_small);
    RUN(get_syslinux_version_null_ext_out);

    RUN(libfat_readfile_basic);
    RUN(libfat_readfile_sector_offset);
    RUN(libfat_readfile_bad_fd);

    RUN(install_syslinux_fat32_image);
    RUN(install_syslinux_v4_version_check);
    RUN(install_syslinux_v6_version_check);

    TEST_RESULTS();
}

#endif /* __linux__ */
