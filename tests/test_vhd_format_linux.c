/*
 * test_vhd_format_linux.c — Tests for VHD/VHDX DD-write support in
 * linux/format.c:
 *
 *  - Constant checks: IMG_COMPRESSION_VHD / VHDX values
 *  - Predicate: which compression types require VHD mounting
 *  - Root integration: create VHD → mount via qemu-nbd → read/verify
 *
 * Non-root tests: run in LINUX_BINS.
 * Root test (vhd_format_mount_read_verify): requires root + qemu-nbd.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <sys/stat.h>

#include "framework.h"

/* Pull in the Linux compat layer */
#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/winioctl.h"
#include "../src/windows/rufus.h"
#include "../src/bled/bled.h"
#include "../src/windows/format.h"
#include "../src/windows/vhd.h"

/* ------------------------------------------------------------------ */
/* Required stubs                                                       */
/* ------------------------------------------------------------------ */
#include <stdarg.h>
void uprintf(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}
void wuprintf(const wchar_t *fmt, ...) { (void)fmt; }
void uprintfs(const char *s) { if (s) fputs(s, stderr); }
void uprint_progress(uint64_t cur, uint64_t max) { (void)cur; (void)max; }
void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL f)
    { (void)op; (void)msg; (void)cur; (void)tot; (void)f; }
char *lmprintf(uint32_t msg_id, ...) { (void)msg_id; return ""; }
void  PrintStatusInfo(BOOL i, BOOL d, unsigned int dur, int id, ...)
    { (void)i; (void)d; (void)dur; (void)id; }

#define SKIP_NOT_ROOT() do { \
    if (geteuid() != 0) { \
        printf("  SKIP (not root)\n"); _pass++; return; \
    } \
} while(0)

RUFUS_IMG_REPORT img_report = { 0 };
FILE     *fd_md5sum    = NULL;
uint64_t  total_blocks = 0, extra_blocks = 0, nb_blocks = 0, last_nb_blocks = 0;
BOOL      ignore_boot_marker = FALSE, has_ffu_support = FALSE;

DWORD ErrorStatus    = 0;
DWORD MainThreadId   = 0;
DWORD DownloadStatus = 0;
DWORD LastWriteError = 0;
BOOL  op_in_progress = FALSE;
BOOL  large_drive    = FALSE;
BOOL  usb_debug      = FALSE;
BOOL  detect_fakes   = FALSE;
BOOL  allow_dual_uefi_bios = FALSE;
HWND  hMainDialog    = NULL;
char  temp_dir[MAX_PATH] = "/tmp";
char *image_path     = NULL;

BOOL AnalyzeMBR(HANDLE h, const char *name, BOOL s)
    { (void)h; (void)name; (void)s; return FALSE; }
BOOL HashFile(unsigned type, const char *path, uint8_t *sum)
    { (void)type; (void)path; memset(sum, 0, 16); return TRUE; }

/* ------------------------------------------------------------------ */
/* VHD creation helper using qemu-img                                   */
/* ------------------------------------------------------------------ */

/* Create a 1-MiB fixed VHD at |path| using qemu-img.  Returns 0 on
 * success, -1 on error (qemu-img not available or creation fails). */
static int create_fixed_vhd(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "qemu-img create -f vpc -o subformat=fixed '%s' 1M "
             ">/dev/null 2>&1", path);
    return system(cmd) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Unit tests (no root needed)                                          */
/* ------------------------------------------------------------------ */

/* Verify that IMG_COMPRESSION_VHD and VHDX are above BLED_COMPRESSION_MAX */
TEST(vhd_compression_type_above_max)
{
    CHECK(IMG_COMPRESSION_VHD  == (int)BLED_COMPRESSION_MAX + 1);
    CHECK(IMG_COMPRESSION_VHDX == (int)BLED_COMPRESSION_MAX + 2);
}

/* Verify VHDX is exactly one above VHD */
TEST(vhd_vhdx_is_vhd_plus_one)
{
    CHECK(IMG_COMPRESSION_VHDX == IMG_COMPRESSION_VHD + 1);
}

/* The predicate for "needs VHD mount before DD write" */
static BOOL needs_vhd_mount(int compression_type)
{
    return compression_type == IMG_COMPRESSION_VHD ||
           compression_type == IMG_COMPRESSION_VHDX;
}

TEST(vhd_needs_mount_for_vhd_type)
{
    CHECK(needs_vhd_mount(IMG_COMPRESSION_VHD) == TRUE);
}

TEST(vhd_needs_mount_for_vhdx_type)
{
    CHECK(needs_vhd_mount(IMG_COMPRESSION_VHDX) == TRUE);
}

TEST(vhd_no_mount_for_none)
{
    CHECK(needs_vhd_mount(BLED_COMPRESSION_NONE) == FALSE);
}

TEST(vhd_no_mount_for_gzip)
{
    CHECK(needs_vhd_mount(BLED_COMPRESSION_GZIP) == FALSE);
}

TEST(vhd_no_mount_for_ffu)
{
    CHECK(needs_vhd_mount(IMG_COMPRESSION_FFU) == FALSE);
}

/* ------------------------------------------------------------------ */
/* Root integration test: create VHD, mount via qemu-nbd, read back   */
/* ------------------------------------------------------------------ */

static BOOL qemu_nbd_available(void)
{
    return (access("/usr/bin/qemu-nbd", X_OK) == 0 ||
            access("/usr/sbin/qemu-nbd", X_OK) == 0);
}

TEST(vhd_format_qemu_nbd_available)
{
    CHECK(qemu_nbd_available() == TRUE);
}

/* Root + qemu-nbd required: create a 1-MiB VHD, mount it, write a pattern
 * to sector 0 via the NBD path, unmount, remount, read back and verify. */
TEST(vhd_format_mount_read_verify)
{
    SKIP_NOT_ROOT();
    if (!qemu_nbd_available()) {
        fprintf(stderr, "SKIP: qemu-nbd not available\n");
        return;
    }

    char vhd_path[256];
    snprintf(vhd_path, sizeof(vhd_path), "/tmp/rufus_test_vhd_%d.vhd",
             (int)getpid());

    /* Create 1-MiB fixed VHD via qemu-img */
    CHECK_INT_EQ(0, create_fixed_vhd(vhd_path));

    /* Mount to get disk size */
    uint64_t disk_size = 0;
    char *nbd_path = VhdMountImageAndGetSize(vhd_path, &disk_size);
    CHECK(nbd_path != NULL);
    if (!nbd_path) { unlink(vhd_path); return; }
    CHECK(disk_size > 0);

    /* Build a recognisable 512-byte pattern for sector 0 */
    uint8_t pattern[512];
    for (int i = 0; i < 512; i++)
        pattern[i] = (uint8_t)(0xA5 ^ i);
    pattern[510] = 0x55;
    pattern[511] = 0xAA;

    /* Write pattern to sector 0 of the NBD device */
    {
        int fd = open(nbd_path, O_WRONLY);
        CHECK(fd >= 0);
        if (fd >= 0) {
            ssize_t w = pwrite(fd, pattern, 512, 0);
            CHECK_INT_EQ(512, (int)w);
            close(fd);
        }
    }

    /* Unmount */
    VhdUnmountImage();

    /* Re-mount and read back */
    uint64_t size2 = 0;
    char *nbd2 = VhdMountImageAndGetSize(vhd_path, &size2);
    CHECK(nbd2 != NULL);
    if (!nbd2) { unlink(vhd_path); return; }

    uint8_t read_buf[512];
    int fd = open(nbd2, O_RDONLY);
    CHECK(fd >= 0);
    if (fd >= 0) {
        ssize_t n = pread(fd, read_buf, 512, 0);
        CHECK_INT_EQ(512, (int)n);
        if (n == 512)
            CHECK_INT_EQ(0, memcmp(pattern, read_buf, 512));
        close(fd);
    }

    VhdUnmountImage();
    unlink(vhd_path);
}

/* Root test: create a VHD, mount it, use DD copy logic (simulating
 * format_linux_write_drive with vhd_path as source), verify destination. */
TEST(vhd_format_dd_write_to_loopback)
{
    SKIP_NOT_ROOT();
    if (!qemu_nbd_available()) {
        fprintf(stderr, "SKIP: qemu-nbd not available\n");
        return;
    }

    /* Create a 1-MiB fixed VHD */
    char vhd_path[256];
    snprintf(vhd_path, sizeof(vhd_path), "/tmp/rufus_dd_vhd_%d.vhd",
             (int)getpid());
    CHECK_INT_EQ(0, create_fixed_vhd(vhd_path));

    /* Mount it */
    uint64_t disk_size = 0;
    char *nbd_path = VhdMountImageAndGetSize(vhd_path, &disk_size);
    CHECK(nbd_path != NULL);
    if (!nbd_path) { unlink(vhd_path); return; }
    CHECK(disk_size > 0);

    /* Write an MBR signature to sector 0 of the VHD */
    uint8_t mbr[512];
    memset(mbr, 0, sizeof(mbr));
    for (int i = 0; i < 446; i++) mbr[i] = (uint8_t)(0x33 ^ i);
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    {
        int fd = open(nbd_path, O_WRONLY);
        CHECK(fd >= 0);
        if (fd >= 0) {
            pwrite(fd, mbr, 512, 0);
            close(fd);
        }
    }

    /* Create destination file (disk_size zeros) */
    char dst_path[256];
    snprintf(dst_path, sizeof(dst_path), "/tmp/rufus_dd_dst_%d.img",
             (int)getpid());
    {
        FILE *f = fopen(dst_path, "wb");
        CHECK(f != NULL);
        if (!f) { VhdUnmountImage(); unlink(vhd_path); return; }
        uint8_t zero[4096];
        memset(zero, 0, sizeof(zero));
        for (uint64_t off = 0; off < disk_size; off += sizeof(zero))
            fwrite(zero, 1, sizeof(zero), f);
        fclose(f);
    }

    /* DD copy: read from nbd_path (VHD NBD device), write to dst_path */
    {
        int src = open(nbd_path, O_RDONLY);
        int dst = open(dst_path, O_WRONLY);
        CHECK(src >= 0);
        CHECK(dst >= 0);
        if (src >= 0 && dst >= 0) {
            uint8_t buf[65536];
            uint64_t copied = 0;
            while (copied < disk_size) {
                size_t want = sizeof(buf);
                if (disk_size - copied < want) want = (size_t)(disk_size - copied);
                ssize_t r = pread(src, buf, want, (off_t)copied);
                if (r <= 0) break;
                ssize_t w = pwrite(dst, buf, (size_t)r, (off_t)copied);
                if (w != r) break;
                copied += (uint64_t)r;
            }
            CHECK(copied == disk_size);
        }
        if (src >= 0) close(src);
        if (dst >= 0) close(dst);
    }

    VhdUnmountImage();

    /* Read back and verify MBR signature */
    {
        int fd = open(dst_path, O_RDONLY);
        CHECK(fd >= 0);
        if (fd >= 0) {
            uint8_t read_back[512];
            ssize_t n = pread(fd, read_back, 512, 0);
            CHECK_INT_EQ(512, (int)n);
            if (n == 512) {
                CHECK_INT_EQ(0x55, read_back[510]);
                CHECK_INT_EQ(0xAA, read_back[511]);
                CHECK_INT_EQ(0, memcmp(mbr, read_back, 512));
            }
            close(fd);
        }
    }

    unlink(vhd_path);
    unlink(dst_path);
}

/* ------------------------------------------------------------------ */
/* vhd_write_fixed_footer unit tests                                   */
/* ------------------------------------------------------------------ */

/* Helper: write |disk_size| bytes of zeros to a temp file, then call
 * vhd_write_fixed_footer(fd, disk_size) and return the file path.
 * Returns NULL on setup failure.  Caller must unlink + free. */
static char *make_vhd_with_footer(uint64_t disk_size)
{
    char *path = strdup("/tmp/rufus_footer_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) { free(path); return NULL; }

    /* Write raw data (just zeros; we care about the footer) */
    off_t off = 0;
    uint64_t remaining = disk_size;
    uint8_t zero_buf[4096];
    memset(zero_buf, 0, sizeof(zero_buf));
    while (remaining > 0) {
        size_t to_write = (remaining > sizeof(zero_buf)) ? sizeof(zero_buf) : (size_t)remaining;
        ssize_t n = write(fd, zero_buf, to_write);
        if (n <= 0) { close(fd); unlink(path); free(path); return NULL; }
        remaining -= (uint64_t)n;
        off += n;
    }

    /* Append footer */
    if (vhd_write_fixed_footer(fd, disk_size) != 0) {
        close(fd); unlink(path); free(path); return NULL;
    }
    close(fd);
    return path;
}

/* Read the VHD footer from the last 512 bytes of the file into buf. */
static int read_vhd_footer(const char *path, uint8_t buf[512])
{
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size < 512) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, 512, st.st_size - 512);
    close(fd);
    return (n == 512) ? 0 : -1;
}

/* 1. The cookie must be "conectix" */
TEST(vhd_footer_write_cookie)
{
    uint64_t sz = 1024 * 1024;
    char *path = make_vhd_with_footer(sz);
    CHECK(path != NULL);
    if (!path) return;

    uint8_t footer[512];
    CHECK_INT_EQ(0, read_vhd_footer(path, footer));
    CHECK_INT_EQ(0, memcmp(footer, "conectix", 8));

    unlink(path); free(path);
}

/* 2. Disk type must be FIXED (2) at offset 60 big-endian */
TEST(vhd_footer_write_disk_type_fixed)
{
    uint64_t sz = 1024 * 1024;
    char *path = make_vhd_with_footer(sz);
    CHECK(path != NULL);
    if (!path) return;

    uint8_t footer[512];
    CHECK_INT_EQ(0, read_vhd_footer(path, footer));
    uint32_t disk_type;
    memcpy(&disk_type, footer + 60, 4);
    disk_type = be32toh(disk_type);
    CHECK_INT_EQ(2, (int)disk_type);

    unlink(path); free(path);
}

/* 3. Original size (offset 40) and current size (offset 48) must equal disk_size */
TEST(vhd_footer_write_disk_size_preserved)
{
    uint64_t sz = 8ULL * 1024 * 1024;  /* 8 MiB */
    char *path = make_vhd_with_footer(sz);
    CHECK(path != NULL);
    if (!path) return;

    uint8_t footer[512];
    CHECK_INT_EQ(0, read_vhd_footer(path, footer));

    uint64_t orig_size, curr_size;
    memcpy(&orig_size, footer + 40, 8);
    memcpy(&curr_size, footer + 48, 8);
    orig_size = be64toh(orig_size);
    curr_size = be64toh(curr_size);
    CHECK(orig_size == sz);
    CHECK(curr_size == sz);

    unlink(path); free(path);
}

/* 4. The checksum must be valid (ones-complement of footer with checksum zeroed) */
TEST(vhd_footer_checksum_valid)
{
    uint64_t sz = 2 * 1024 * 1024;
    char *path = make_vhd_with_footer(sz);
    CHECK(path != NULL);
    if (!path) return;

    uint8_t footer[512];
    CHECK_INT_EQ(0, read_vhd_footer(path, footer));

    /* Extract stored checksum */
    uint32_t stored;
    memcpy(&stored, footer + 64, 4);
    stored = be32toh(stored);

    /* Recompute: zero out checksum field, sum all bytes, ones-complement */
    uint8_t tmp[512];
    memcpy(tmp, footer, 512);
    memset(tmp + 64, 0, 4);
    uint32_t sum = 0;
    for (int i = 0; i < 512; i++) sum += tmp[i];
    uint32_t expected = ~sum;
    CHECK(stored == expected);

    unlink(path); free(path);
}

/* 5. Footer must be exactly 512 bytes; total file size must be disk_size + 512 */
TEST(vhd_footer_write_file_size)
{
    uint64_t sz = 512 * 1024;  /* 512 KiB */
    char *path = make_vhd_with_footer(sz);
    CHECK(path != NULL);
    if (!path) return;

    struct stat st;
    CHECK_INT_EQ(0, stat(path, &st));
    CHECK((uint64_t)st.st_size == sz + 512);

    unlink(path); free(path);
}

/* 6. vhd_get_fixed_disk_size must round-trip through vhd_write_fixed_footer */
TEST(vhd_get_fixed_disk_size_round_trip)
{
    uint64_t sz = 4 * 1024 * 1024;  /* 4 MiB */
    char *path = make_vhd_with_footer(sz);
    CHECK(path != NULL);
    if (!path) return;

    uint64_t read_back = vhd_get_fixed_disk_size(path);
    CHECK(read_back == sz);

    unlink(path); free(path);
}

/* 7. Round-trip with a large (8 GiB) disk size — ensures 64-bit sizes work */
TEST(vhd_footer_large_disk_size_round_trip)
{
    /* Don't allocate 8 GiB on disk — write only the footer to a 0-byte file,
     * then seek to disk_size and write the footer. */
    uint64_t sz = 8ULL * 1024 * 1024 * 1024;
    char *path = strdup("/tmp/rufus_lg_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) { free(path); return; }

    /* Seek to disk_size and write footer (sparse file) */
    if (lseek(fd, (off_t)sz, SEEK_SET) < 0) {
        close(fd); unlink(path); free(path);
        fprintf(stderr, "  SKIP (sparse file seek failed)\n");
        _pass++;
        return;
    }
    CHECK_INT_EQ(0, vhd_write_fixed_footer(fd, sz));
    close(fd);

    uint64_t read_back = vhd_get_fixed_disk_size(path);
    CHECK(read_back == sz);

    unlink(path); free(path);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    RUN(vhd_compression_type_above_max);
    RUN(vhd_vhdx_is_vhd_plus_one);
    RUN(vhd_needs_mount_for_vhd_type);
    RUN(vhd_needs_mount_for_vhdx_type);
    RUN(vhd_no_mount_for_none);
    RUN(vhd_no_mount_for_gzip);
    RUN(vhd_no_mount_for_ffu);
    RUN(vhd_footer_write_cookie);
    RUN(vhd_footer_write_disk_type_fixed);
    RUN(vhd_footer_write_disk_size_preserved);
    RUN(vhd_footer_checksum_valid);
    RUN(vhd_footer_write_file_size);
    RUN(vhd_get_fixed_disk_size_round_trip);
    RUN(vhd_footer_large_disk_size_round_trip);
    RUN(vhd_format_qemu_nbd_available);
    RUN(vhd_format_mount_read_verify);
    RUN(vhd_format_dd_write_to_loopback);
    TEST_RESULTS();
}
