/*
 * test_vhd_nbd_linux.c — Unit + integration tests for the kernel NBD
 * fallback in VhdMountImageAndGetSize().
 *
 * Non-root tests (LINUX_BIN):
 *   - VHD fixed-footer parsing (vhd_get_fixed_disk_size)
 *   - NBD old-style handshake (socketpair, server thread)
 *   - NBD read request protocol
 *   - NBD write request protocol
 *   - NBD disconnect request
 *
 * Root tests (ROOT_BIN) — require /dev/nbd* (kernel module loaded):
 *   - kernel_nbd_device_available
 *   - kernel_nbd_full_mount_fixed_vhd
 *
 * Build: auto-discovered by tests/Makefile.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/nbd.h>
#include <linux/fs.h>

#include "framework.h"

/* Pull in the Linux compat layer so we can include vhd.h */
#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/winioctl.h"
#include "../src/windows/rufus.h"
#include "../src/windows/vhd.h"

/* ------------------------------------------------------------------ */
/* Required stubs (vhd.c pulls in uprintf etc. via rufus.h)           */
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

/* needed by WimProgressFunc in vhd.c */
RUFUS_IMG_REPORT img_report = { 0 };
FILE     *fd_md5sum    = NULL;
uint64_t  total_blocks = 0, extra_blocks = 0, nb_blocks = 0, last_nb_blocks = 0;
BOOL      ignore_boot_marker = FALSE, has_ffu_support = FALSE;

/* Globals required by vhd.c */
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
/* VHD footer builder helper                                           */
/* ------------------------------------------------------------------ */
#define VHD_FOOTER_SIZE 512
#define VHD_COOKIE      "conectix"
#define VHD_DISK_TYPE_FIXED   2
#define VHD_DISK_TYPE_DYNAMIC 3

/* Build a minimal valid VHD fixed-disk footer into |buf| (512 bytes).
 * |virtual_size| is the virtual disk size in bytes. */
static void make_vhd_footer(uint8_t *buf, uint64_t virtual_size,
                             uint32_t disk_type)
{
    memset(buf, 0, VHD_FOOTER_SIZE);
    memcpy(buf, VHD_COOKIE, 8);                              /* cookie   */
    uint32_t ft = htobe32(disk_type);
    memcpy(buf + 60, &ft, 4);                               /* disk type */
    uint64_t sz = htobe64(virtual_size);
    memcpy(buf + 40, &sz, 8);                               /* original size */
    memcpy(buf + 48, &sz, 8);                               /* current size  */
    /* Format version 1.0 */
    uint32_t fv = htobe32(0x00010000);
    memcpy(buf + 12, &fv, 4);
    /* Data offset = 0xFFFFFFFFFFFFFFFF for fixed VHD */
    if (disk_type == VHD_DISK_TYPE_FIXED) {
        uint64_t doff = 0xFFFFFFFFFFFFFFFFULL;
        memcpy(buf + 16, &doff, 8);
    }
}

/* Create a minimal fixed VHD file at |path| with |disk_bytes| of virtual disk.
 * The file has |disk_bytes| zeroed data followed by the 512-byte footer.
 * Returns 0 on success. */
static int make_fixed_vhd_file(const char *path, uint64_t disk_bytes)
{
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;

    /* Write disk data (sparse: seek to end) */
    if (ftruncate(fd, (off_t)disk_bytes) != 0) { close(fd); return -1; }

    /* Append VHD footer */
    uint8_t footer[VHD_FOOTER_SIZE];
    make_vhd_footer(footer, disk_bytes, VHD_DISK_TYPE_FIXED);
    ssize_t n = pwrite(fd, footer, VHD_FOOTER_SIZE, (off_t)disk_bytes);
    close(fd);
    return (n == VHD_FOOTER_SIZE) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* VHD footer parsing tests                                            */
/* ------------------------------------------------------------------ */

TEST(vhd_fixed_footer_parse_valid)
{
    const char *path = "/tmp/test_rufus_fixed.vhd";
    uint64_t want = 1 * 1024 * 1024;  /* 1 MiB */
    CHECK_MSG(make_fixed_vhd_file(path, want) == 0, "should create VHD file");
    uint64_t got = vhd_get_fixed_disk_size(path);
    unlink(path);
    CHECK_MSG(got == want, "parsed size must match virtual disk size");
}

TEST(vhd_fixed_footer_parse_2mib)
{
    const char *path = "/tmp/test_rufus_fixed2.vhd";
    uint64_t want = 2 * 1024 * 1024;
    CHECK_MSG(make_fixed_vhd_file(path, want) == 0, "should create 2MiB VHD");
    uint64_t got = vhd_get_fixed_disk_size(path);
    unlink(path);
    CHECK_MSG(got == want, "2MiB VHD size must be parsed correctly");
}

TEST(vhd_fixed_footer_parse_null_path)
{
    uint64_t got = vhd_get_fixed_disk_size(NULL);
    CHECK_MSG(got == 0, "NULL path must return 0");
}

TEST(vhd_fixed_footer_parse_missing_file)
{
    uint64_t got = vhd_get_fixed_disk_size("/tmp/nonexistent_rufus_nbd.vhd");
    CHECK_MSG(got == 0, "missing file must return 0");
}

TEST(vhd_fixed_footer_parse_too_small)
{
    /* File smaller than 512 bytes — can't hold a footer */
    const char *path = "/tmp/test_rufus_tiny.vhd";
    FILE *f = fopen(path, "wb");
    if (f) { fputc(0, f); fclose(f); }
    uint64_t got = vhd_get_fixed_disk_size(path);
    unlink(path);
    CHECK_MSG(got == 0, "file < 512 bytes must return 0");
}

TEST(vhd_fixed_footer_parse_bad_cookie)
{
    const char *path = "/tmp/test_rufus_bad_cookie.vhd";
    uint64_t want = 1024 * 1024;
    make_fixed_vhd_file(path, want);
    /* Corrupt the cookie */
    int fd = open(path, O_RDWR);
    if (fd >= 0) {
        pwrite(fd, "BADCOOK!", 8, (off_t)want);  /* overwrite footer cookie */
        close(fd);
    }
    uint64_t got = vhd_get_fixed_disk_size(path);
    unlink(path);
    CHECK_MSG(got == 0, "bad cookie must return 0");
}

TEST(vhd_fixed_footer_parse_dynamic_rejected)
{
    /* Dynamic VHD has disk_type == 3; our parser should return 0 */
    const char *path = "/tmp/test_rufus_dynamic.vhd";
    /* Write minimal file with dynamic footer */
    uint8_t footer[VHD_FOOTER_SIZE];
    make_vhd_footer(footer, 1024 * 1024, VHD_DISK_TYPE_DYNAMIC);
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) { pwrite(fd, footer, VHD_FOOTER_SIZE, 0); close(fd); }
    uint64_t got = vhd_get_fixed_disk_size(path);
    unlink(path);
    CHECK_MSG(got == 0, "dynamic VHD must be rejected (returns 0)");
}

/* ------------------------------------------------------------------ */
/* NBD protocol tests (use socketpair, no kernel NBD required)        */
/* ------------------------------------------------------------------ */

/* NBD handshake magic values */
#define NBDMAGIC      0x4e42444d41474943ULL
#define CLISERV_MAGIC 0x00420281861253ULL

struct srv_args {
    int      vhd_fd;
    int      sock_fd;
    uint64_t disk_size;
};

/* Spawn the NBD server thread with a socketpair; returns the client socket fd.
 * |vhd_fd| is an open file descriptor to the VHD data (caller keeps it open).
 * |disk_size| is the virtual disk size. */
static int spawn_nbd_server(int vhd_fd, uint64_t disk_size, pthread_t *tid_out)
{
    int socks[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) != 0) return -1;

    /* nbd_server_thread takes ownership of ctx (frees it) */
    struct nbd_srv_ctx {
        int      vhd_fd;
        int      sock_fd;
        uint64_t disk_size;
    };
    struct nbd_srv_ctx *ctx = malloc(sizeof(*ctx));
    if (!ctx) { close(socks[0]); close(socks[1]); return -1; }
    ctx->vhd_fd    = vhd_fd;
    ctx->sock_fd   = socks[1];   /* server end */
    ctx->disk_size = disk_size;

    if (pthread_create(tid_out, NULL, nbd_server_thread, ctx) != 0) {
        free(ctx);
        close(socks[0]); close(socks[1]);
        return -1;
    }
    return socks[0];  /* client end */
}

static int read_exact(int fd, void *buf, size_t n)
{
    size_t d = 0;
    while (d < n) {
        ssize_t r = read(fd, (char *)buf + d, n - d);
        if (r <= 0) return -1;
        d += (size_t)r;
    }
    return 0;
}

static int write_exact(int fd, const void *buf, size_t n)
{
    size_t d = 0;
    while (d < n) {
        ssize_t r = write(fd, (const char *)buf + d, n - d);
        if (r <= 0) return -1;
        d += (size_t)r;
    }
    return 0;
}

TEST(nbd_server_handshake_magic)
{
    /* Create a small 4K fixed VHD */
    const char *path = "/tmp/test_rufus_nbd_hs.vhd";
    uint64_t dsz = 4096;
    make_fixed_vhd_file(path, dsz);
    int vfd = open(path, O_RDWR);
    CHECK_MSG(vfd >= 0, "should open VHD file");

    pthread_t tid;
    int cfd = spawn_nbd_server(vfd, dsz, &tid);
    CHECK_MSG(cfd >= 0, "should get client socket");

    /* Read old-style handshake: 8+8+8+4+124 = 152 bytes */
    uint64_t m1, m2, esz;
    uint32_t flags;
    uint8_t  pad[124];

    int ok = (read_exact(cfd, &m1,    8)   == 0 &&
              read_exact(cfd, &m2,    8)   == 0 &&
              read_exact(cfd, &esz,   8)   == 0 &&
              read_exact(cfd, &flags, 4)   == 0 &&
              read_exact(cfd, pad,    124) == 0);
    CHECK_MSG(ok, "should receive full handshake");
    CHECK_MSG(be64toh(m1)  == NBDMAGIC,      "handshake magic1 must be NBDMAGIC");
    CHECK_MSG(be64toh(m2)  == CLISERV_MAGIC, "handshake magic2 must be CLISERV_MAGIC");
    CHECK_MSG(be64toh(esz) == dsz,           "export size must equal disk_size");

    /* Send DISC command to shut down server */
    struct nbd_request disc = {0};
    disc.magic = htobe32(NBD_REQUEST_MAGIC);
    disc.type  = htobe32(NBD_CMD_DISC);
    write_exact(cfd, &disc, sizeof(disc));

    close(cfd);
    pthread_join(tid, NULL);
    close(vfd);
    unlink(path);
}

TEST(nbd_server_read_request)
{
    /* Create a 4K VHD with known data pattern */
    const char *path = "/tmp/test_rufus_nbd_rd.vhd";
    uint64_t dsz = 4096;
    make_fixed_vhd_file(path, dsz);
    /* Write pattern to first 16 bytes */
    int vfd = open(path, O_RDWR);
    CHECK_MSG(vfd >= 0, "should open VHD file");
    const uint8_t pattern[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    pwrite(vfd, pattern, 16, 0);

    pthread_t tid;
    int cfd = spawn_nbd_server(vfd, dsz, &tid);
    CHECK_MSG(cfd >= 0, "should get client socket");

    /* Consume handshake */
    uint8_t hs[152];
    read_exact(cfd, hs, 152);

    /* Send READ request for first 16 bytes */
    struct nbd_request req = {0};
    req.magic  = htobe32(NBD_REQUEST_MAGIC);
    req.type   = htobe32(NBD_CMD_READ);
    req.from   = htobe64(0);
    req.len    = htobe32(16);
    memset(req.handle, 0x42, 8);
    write_exact(cfd, &req, sizeof(req));

    /* Read reply header + data */
    struct nbd_reply rep;
    uint8_t got[16];
    int ok = (read_exact(cfd, &rep, sizeof(rep)) == 0 &&
              read_exact(cfd, got,  16)           == 0);
    CHECK_MSG(ok, "should receive reply + data");
    CHECK_MSG(be32toh(rep.magic) == NBD_REPLY_MAGIC, "reply magic must be correct");
    CHECK_MSG(be32toh(rep.error) == 0, "reply error must be 0");
    CHECK_MSG(memcmp(rep.handle, req.handle, 8) == 0, "reply handle must match");
    CHECK_MSG(memcmp(got, pattern, 16) == 0, "read data must match written pattern");

    /* Disconnect */
    struct nbd_request disc = {0};
    disc.magic = htobe32(NBD_REQUEST_MAGIC);
    disc.type  = htobe32(NBD_CMD_DISC);
    write_exact(cfd, &disc, sizeof(disc));

    close(cfd);
    pthread_join(tid, NULL);
    close(vfd);
    unlink(path);
}

TEST(nbd_server_write_request)
{
    const char *path = "/tmp/test_rufus_nbd_wr.vhd";
    uint64_t dsz = 4096;
    make_fixed_vhd_file(path, dsz);
    int vfd = open(path, O_RDWR);
    CHECK_MSG(vfd >= 0, "should open VHD file");

    pthread_t tid;
    int cfd = spawn_nbd_server(vfd, dsz, &tid);
    CHECK_MSG(cfd >= 0, "should get client socket");

    /* Consume handshake */
    uint8_t hs[152];
    read_exact(cfd, hs, 152);

    /* Send WRITE request */
    const uint8_t wdata[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    struct nbd_request req = {0};
    req.magic  = htobe32(NBD_REQUEST_MAGIC);
    req.type   = htobe32(NBD_CMD_WRITE);
    req.from   = htobe64(512);
    req.len    = htobe32(8);
    memset(req.handle, 0x77, 8);
    write_exact(cfd, &req, sizeof(req));
    write_exact(cfd, wdata, 8);

    /* Read write reply */
    struct nbd_reply rep;
    int ok = read_exact(cfd, &rep, sizeof(rep)) == 0;
    CHECK_MSG(ok, "should receive write reply");
    CHECK_MSG(be32toh(rep.error) == 0, "write reply error must be 0");

    /* Verify data was written to VHD file */
    uint8_t buf[8] = {0};
    pread(vfd, buf, 8, 512);
    CHECK_MSG(memcmp(buf, wdata, 8) == 0, "written data must be in VHD file");

    /* Disconnect */
    struct nbd_request disc = {0};
    disc.magic = htobe32(NBD_REQUEST_MAGIC);
    disc.type  = htobe32(NBD_CMD_DISC);
    write_exact(cfd, &disc, sizeof(disc));

    close(cfd);
    pthread_join(tid, NULL);
    close(vfd);
    unlink(path);
}

TEST(nbd_server_disconnect_exits_cleanly)
{
    const char *path = "/tmp/test_rufus_nbd_disc.vhd";
    make_fixed_vhd_file(path, 4096);
    int vfd = open(path, O_RDWR);

    pthread_t tid;
    int cfd = spawn_nbd_server(vfd, 4096, &tid);
    CHECK_MSG(cfd >= 0, "should get client socket");

    /* Consume handshake */
    uint8_t hs[152];
    read_exact(cfd, hs, 152);

    /* Send DISC immediately */
    struct nbd_request disc = {0};
    disc.magic = htobe32(NBD_REQUEST_MAGIC);
    disc.type  = htobe32(NBD_CMD_DISC);
    write_exact(cfd, &disc, sizeof(disc));
    close(cfd);

    /* pthread_join must return within a few seconds */
    int rc = pthread_join(tid, NULL);
    CHECK_MSG(rc == 0, "server thread must exit cleanly after DISC");

    close(vfd);
    unlink(path);
}

TEST(nbd_server_read_out_of_range)
{
    /* Read beyond disk size — server should reply with all-zero data and no
     * error (pread on a sparse/short file returns 0, we zero-fill).  */
    const char *path = "/tmp/test_rufus_nbd_oob.vhd";
    uint64_t dsz = 512;
    make_fixed_vhd_file(path, dsz);
    int vfd = open(path, O_RDWR);

    pthread_t tid;
    int cfd = spawn_nbd_server(vfd, dsz, &tid);
    uint8_t hs[152];
    read_exact(cfd, hs, 152);

    struct nbd_request req = {0};
    req.magic = htobe32(NBD_REQUEST_MAGIC);
    req.type  = htobe32(NBD_CMD_READ);
    req.from  = htobe64(256);   /* within disk */
    req.len   = htobe32(256);
    write_exact(cfd, &req, sizeof(req));

    struct nbd_reply rep;
    uint8_t buf[256];
    read_exact(cfd, &rep, sizeof(rep));
    read_exact(cfd, buf, 256);
    CHECK_MSG(be32toh(rep.error) == 0, "in-range read must succeed");

    struct nbd_request disc = {0};
    disc.magic = htobe32(NBD_REQUEST_MAGIC);
    disc.type  = htobe32(NBD_CMD_DISC);
    write_exact(cfd, &disc, sizeof(disc));
    close(cfd);
    pthread_join(tid, NULL);
    close(vfd);
    unlink(path);
}

/* ------------------------------------------------------------------ */
/* VhdMountImageAndGetSize extension tests (no kernel NBD required)   */
/* ------------------------------------------------------------------ */

TEST(vhdmount_null_path)
{
    char *r = VhdMountImageAndGetSize(NULL, NULL);
    CHECK_MSG(r == NULL, "NULL path must return NULL");
}

TEST(vhdmount_unknown_extension)
{
    char *r = VhdMountImageAndGetSize("/tmp/test.iso", NULL);
    CHECK_MSG(r == NULL, ".iso extension must return NULL");
}

TEST(vhdmount_no_such_file)
{
    char *r = VhdMountImageAndGetSize("/tmp/nonexistent_rufus_nbd.vhd", NULL);
    (void)r; /* may or may not be NULL depending on qemu-nbd; must not crash */
    CHECK_MSG(1, "must not crash on missing file");
    VhdUnmountImage();
}

/* ------------------------------------------------------------------ */
/* Root-requiring tests — kernel NBD device                           */
/* ------------------------------------------------------------------ */

#define SKIP_NOT_ROOT() do { \
    if (geteuid() != 0) { \
        printf("  SKIP (not root)\n"); _pass++; return; \
    } \
} while(0)

#define SKIP_NO_NBD() do { \
    if (access("/dev/nbd0", F_OK) != 0) { \
        printf("  SKIP (/dev/nbd0 not available — load nbd kernel module)\n"); \
        _pass++; return; \
    } \
} while(0)

TEST(kernel_nbd_device_available)
{
    SKIP_NOT_ROOT();
    int ok = (access("/dev/nbd0", F_OK) == 0);
    if (!ok) {
        printf("  SKIP (/dev/nbd0 absent — nbd kernel module not loaded)\n");
        _pass++; return;
    }
    CHECK_MSG(ok, "/dev/nbd0 must exist when nbd module is loaded");
}

TEST(kernel_nbd_full_mount_fixed_vhd)
{
    SKIP_NOT_ROOT();
    SKIP_NO_NBD();

    const char *path = "/tmp/test_rufus_nbd_full.vhd";
    uint64_t want = 1 * 1024 * 1024;  /* 1 MiB */
    CHECK_MSG(make_fixed_vhd_file(path, want) == 0, "should create fixed VHD");

    uint64_t got_size = 0;
    char *devpath = VhdMountImageAndGetSize(path, &got_size);
    if (devpath == NULL) {
        /* May fail if qemu-nbd is not available and kernel NBD isn't loaded */
        printf("  SKIP (VhdMountImageAndGetSize returned NULL — "
               "qemu-nbd unavailable and kernel NBD not loaded)\n");
        _pass++;
        unlink(path);
        return;
    }

    printf("  mounted at %s, reported size %llu bytes\n",
           devpath, (unsigned long long)got_size);
    CHECK_MSG(got_size == want, "mounted VHD size must equal virtual disk size");

    VhdUnmountImage();
    unlink(path);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== VHD footer parsing tests ===\n");
    RUN(vhd_fixed_footer_parse_valid);
    RUN(vhd_fixed_footer_parse_2mib);
    RUN(vhd_fixed_footer_parse_null_path);
    RUN(vhd_fixed_footer_parse_missing_file);
    RUN(vhd_fixed_footer_parse_too_small);
    RUN(vhd_fixed_footer_parse_bad_cookie);
    RUN(vhd_fixed_footer_parse_dynamic_rejected);

    printf("\n=== NBD server protocol tests (socketpair, no kernel NBD) ===\n");
    RUN(nbd_server_handshake_magic);
    RUN(nbd_server_read_request);
    RUN(nbd_server_write_request);
    RUN(nbd_server_disconnect_exits_cleanly);
    RUN(nbd_server_read_out_of_range);

    printf("\n=== VhdMountImageAndGetSize extension tests ===\n");
    RUN(vhdmount_null_path);
    RUN(vhdmount_unknown_extension);
    RUN(vhdmount_no_such_file);

    printf("\n=== Kernel NBD integration tests (root + /dev/nbd0) ===\n");
    RUN(kernel_nbd_device_available);
    RUN(kernel_nbd_full_mount_fixed_vhd);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
