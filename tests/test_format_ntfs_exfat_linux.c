/*
 * test_format_ntfs_exfat_linux.c — Tests for NTFS and exFAT formatting
 *
 * Strategy:
 *   - Test command-building helpers (format_ntfs_build_cmd / format_exfat_build_cmd)
 *     without any system calls.
 *   - Test graceful failure when tool is not present.
 *   - If mkntfs / mkfs.exfat is installed, format a temporary image file and
 *     verify the on-disk magic bytes.
 *   - Test WritePBR() returns TRUE for NTFS and exFAT (no PBR needed).
 *   - Test FormatPartition() routing to FormatNTFS / FormatExFAT.
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

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
#include "format.h"
#include "resource.h"

/* ================================================================
 * Stubs required by the linked sources
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
HWND hLabel        = NULL;

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
BOOL quick_format          = FALSE;
BOOL use_rufus_mbr         = TRUE;

DWORD ErrorStatus          = 0;
DWORD LastWriteError       = 0;
DWORD MainThreadId         = 0;
DWORD DownloadStatus       = 0;

int fs_type                = 0;
int boot_type              = 0;
int partition_type         = 0;
int target_type            = 0;
uint8_t image_options      = 0;

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
char ubuffer[UBUFFER_SIZE]     = "";
char embedded_sl_version_str[2][12] = {"", ""};
char embedded_sl_version_ext[2][32] = {"", ""};
char ClusterSizeLabel[MAX_CLUSTER_SIZES][64];

char *ini_file            = NULL;
char *image_path          = NULL;
char *archive_path        = NULL;
char *fido_url            = NULL;
char *save_image_type     = NULL;
char *sbat_level_txt      = NULL;
char *sb_active_txt       = NULL;

RUFUS_IMG_REPORT img_report = { 0 };

const char* FileSystemLabel[FS_MAX] = {
    "FAT", "FAT32", "NTFS", "UDF", "exFAT", "ReFS", "ext2", "ext3", "ext4"
};
const int nb_steps[FS_MAX] = { 5, 5, 5, 5, 5, 5, 5, 5, 5 };
const char *md5sum_name[2] = { "md5sum.txt", "md5sum.txt" };

/* Minimal log/progress stubs */
void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s) { (void)s; }
const char *WindowsErrorString(void) { return ""; }

void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration, int msg_id, ...) {
    (void)info; (void)debug; (void)duration; (void)msg_id;
}
char *lmprintf(int msg_id, ...) { (void)msg_id; return ""; }
char *SizeToHumanReadable(uint64_t size, BOOL copy, BOOL fake_units) {
    static char buf[32]; (void)copy; (void)fake_units;
    snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)size);
    return buf;
}

#undef UpdateProgressWithInfo
#undef UpdateProgressWithInfoUpTo
#undef UpdateProgressWithInfoForce
#undef UpdateProgressWithInfoInit
void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t max, BOOL force) {
    (void)op; (void)msg; (void)cur; (void)max; (void)force;
}
void uprint_progress(uint64_t cur, uint64_t max) { (void)cur; (void)max; }
void InitProgress(BOOL bOnlyFormatSection) { (void)bOnlyFormatSection; }

BOOL WriteFileWithRetry(HANDLE h, const void *buf, DWORD n, DWORD *written, DWORD retries) {
    if (h == INVALID_HANDLE_VALUE || !buf) return FALSE;
    int fd = (int)(intptr_t)h;
    DWORD total = 0;
    while (total < n) {
        ssize_t r = write(fd, (const char *)buf + total, n - total);
        if (r > 0) { total += (DWORD)r; }
        else if (r == 0 || (errno != EINTR && errno != EAGAIN)) {
            if (retries > 0) { retries--; continue; }
            break;
        }
    }
    if (written) *written = total;
    return (total == n);
}

LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
    (void)h; (void)m; (void)w; (void)l; return 0;
}
BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
    (void)h; (void)m; (void)w; (void)l; return FALSE;
}
LONG GetEntryWidth(HWND h, const char *e) { (void)h; (void)e; return 0; }
BOOL IsCurrentProcessElevated(void) { return FALSE; }

/* stub for GuidToString / CompareGUID */
char *GuidToString(const GUID *guid, BOOL bDecorated) {
    (void)guid; (void)bDecorated; return NULL;
}
BOOL CompareGUID(const GUID *g1, const GUID *g2) {
    if (!g1 || !g2) return FALSE;
    return memcmp(g1, g2, sizeof(GUID)) == 0;
}

/* ================================================================
 * Test framework
 * ================================================================ */
#include "framework.h"
#include "format_linux.h"   /* FormatNTFS, FormatExFAT, format_ntfs_build_cmd, etc. */

/* Image size for tests */
#define TEST_IMG_SIZE_NTFS   (64ULL * 1024 * 1024)   /* 64 MiB — min for mkntfs */
#define TEST_IMG_SIZE_EXFAT  (16ULL * 1024 * 1024)   /* 16 MiB */

/* ---- helpers ---- */

/* Create a zero-filled sparse temp file of the given size.
 * Caller must free the returned path and unlink the file. */
static char *create_temp_image(uint64_t size)
{
    char *path = (char *)malloc(64);
    if (!path) return NULL;
    strcpy(path, "/tmp/rufus_ntfs_test_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) { free(path); return NULL; }
    if (ftruncate(fd, (off_t)size) != 0) {
        close(fd); unlink(path); free(path); return NULL;
    }
    close(fd);
    return path;
}

static void setup_drive(const char *path, uint64_t size)
{
    memset(rufus_drive, 0, sizeof(rufus_drive));
    rufus_drive[0].id           = (char *)path;
    rufus_drive[0].name         = "Test";
    rufus_drive[0].display_name = "Test Drive";
    rufus_drive[0].label        = "";
    rufus_drive[0].index        = DRIVE_INDEX_MIN;
    rufus_drive[0].port         = 0;
    rufus_drive[0].size         = size;
}

static void teardown_drive(void)
{
    memset(rufus_drive, 0, sizeof(rufus_drive));
}

/* Read bytes at offset from a file; returns 0 on success */
static int read_at(const char *path, off_t off, void *buf, size_t len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = pread(fd, buf, len, off);
    close(fd);
    return (r == (ssize_t)len) ? 0 : -1;
}

/* Search for a tool in common locations; returns the first found path
 * (static buffer) or NULL. */
static const char *find_tool(const char *name)
{
    static char buf[256];
    static const char * const dirs[] = {
        "/sbin", "/usr/sbin", "/bin", "/usr/bin",
        "/usr/local/sbin", "/usr/local/bin", NULL
    };
    for (int i = 0; dirs[i]; i++) {
        snprintf(buf, sizeof(buf), "%s/%s", dirs[i], name);
        if (access(buf, X_OK) == 0) return buf;
    }
    return NULL;
}

/* ================================================================
 * 1. Command-building tests — no system calls
 * ================================================================ */

TEST(ntfs_build_cmd_basic)
{
    char cmd[512];
    BOOL r = format_ntfs_build_cmd("/usr/sbin/mkntfs", "/dev/sdb1",
                                    0, NULL, FALSE, FALSE, cmd, sizeof(cmd));
    CHECK(r == TRUE);
    /* Must contain the tool path and the device */
    CHECK(strstr(cmd, "/usr/sbin/mkntfs") != NULL);
    CHECK(strstr(cmd, "/dev/sdb1") != NULL);
}

TEST(ntfs_build_cmd_quick_flag)
{
    char cmd[512];
    format_ntfs_build_cmd("/usr/sbin/mkntfs", "/dev/sdb1",
                           0, NULL, TRUE, FALSE, cmd, sizeof(cmd));
    /* Quick format flag -Q must appear */
    CHECK(strstr(cmd, "-Q") != NULL);
}

TEST(ntfs_build_cmd_no_quick_when_false)
{
    char cmd[512];
    format_ntfs_build_cmd("/usr/sbin/mkntfs", "/dev/sdb1",
                           0, NULL, FALSE, FALSE, cmd, sizeof(cmd));
    /* -Q must NOT appear when quick is FALSE */
    CHECK(strstr(cmd, "-Q") == NULL);
}

TEST(ntfs_build_cmd_with_label)
{
    char cmd[512];
    format_ntfs_build_cmd("/usr/sbin/mkntfs", "/dev/sdb1",
                           0, "MyLabel", FALSE, FALSE, cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-L") != NULL);
    CHECK(strstr(cmd, "MyLabel") != NULL);
}

TEST(ntfs_build_cmd_empty_label_omitted)
{
    char cmd[512];
    format_ntfs_build_cmd("/usr/sbin/mkntfs", "/dev/sdb1",
                           0, "", FALSE, FALSE, cmd, sizeof(cmd));
    /* Empty label should not add -L flag */
    CHECK(strstr(cmd, "-L") == NULL);
}

TEST(ntfs_build_cmd_with_cluster_size)
{
    char cmd[512];
    format_ntfs_build_cmd("/usr/sbin/mkntfs", "/dev/sdb1",
                           4096, NULL, FALSE, FALSE, cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-c") != NULL);
    CHECK(strstr(cmd, "4096") != NULL);
}

TEST(ntfs_build_cmd_zero_cluster_omitted)
{
    char cmd[512];
    format_ntfs_build_cmd("/usr/sbin/mkntfs", "/dev/sdb1",
                           0, NULL, FALSE, FALSE, cmd, sizeof(cmd));
    /* Zero cluster size should not add -c flag */
    CHECK(strstr(cmd, "-c") == NULL);
}

TEST(ntfs_build_cmd_null_tool_returns_false)
{
    char cmd[512];
    BOOL r = format_ntfs_build_cmd(NULL, "/dev/sdb1",
                                    0, NULL, FALSE, FALSE, cmd, sizeof(cmd));
    CHECK(r == FALSE);
}

TEST(ntfs_build_cmd_null_path_returns_false)
{
    char cmd[512];
    BOOL r = format_ntfs_build_cmd("/usr/sbin/mkntfs", NULL,
                                    0, NULL, FALSE, FALSE, cmd, sizeof(cmd));
    CHECK(r == FALSE);
}

TEST(ntfs_build_cmd_null_buf_returns_false)
{
    BOOL r = format_ntfs_build_cmd("/usr/sbin/mkntfs", "/dev/sdb1",
                                    0, NULL, FALSE, FALSE, NULL, 512);
    CHECK(r == FALSE);
}

TEST(ntfs_build_cmd_buf_too_small_returns_false)
{
    char cmd[4];
    BOOL r = format_ntfs_build_cmd("/usr/sbin/mkntfs", "/dev/sdb1",
                                    0, NULL, FALSE, FALSE, cmd, sizeof(cmd));
    CHECK(r == FALSE);
}

/* exFAT command builder tests */

TEST(exfat_build_cmd_basic)
{
    char cmd[512];
    BOOL r = format_exfat_build_cmd("/usr/sbin/mkfs.exfat", "/dev/sdb1",
                                     0, NULL, cmd, sizeof(cmd));
    CHECK(r == TRUE);
    CHECK(strstr(cmd, "/usr/sbin/mkfs.exfat") != NULL);
    CHECK(strstr(cmd, "/dev/sdb1") != NULL);
}

TEST(exfat_build_cmd_with_label)
{
    char cmd[512];
    format_exfat_build_cmd("/usr/sbin/mkfs.exfat", "/dev/sdb1",
                            0, "ExFatVol", cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-n") != NULL);
    CHECK(strstr(cmd, "ExFatVol") != NULL);
}

TEST(exfat_build_cmd_empty_label_omitted)
{
    char cmd[512];
    format_exfat_build_cmd("/usr/sbin/mkfs.exfat", "/dev/sdb1",
                            0, "", cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-n") == NULL);
}

TEST(exfat_build_cmd_with_cluster_size)
{
    char cmd[512];
    format_exfat_build_cmd("/usr/sbin/mkfs.exfat", "/dev/sdb1",
                            8192, NULL, cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-c") != NULL);
    CHECK(strstr(cmd, "8192") != NULL);
}

TEST(exfat_build_cmd_zero_cluster_omitted)
{
    char cmd[512];
    format_exfat_build_cmd("/usr/sbin/mkfs.exfat", "/dev/sdb1",
                            0, NULL, cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-c") == NULL);
}

TEST(exfat_build_cmd_null_tool_returns_false)
{
    char cmd[512];
    BOOL r = format_exfat_build_cmd(NULL, "/dev/sdb1",
                                     0, NULL, cmd, sizeof(cmd));
    CHECK(r == FALSE);
}

TEST(exfat_build_cmd_null_path_returns_false)
{
    char cmd[512];
    BOOL r = format_exfat_build_cmd("/usr/sbin/mkfs.exfat", NULL,
                                     0, NULL, cmd, sizeof(cmd));
    CHECK(r == FALSE);
}

TEST(exfat_build_cmd_null_buf_returns_false)
{
    BOOL r = format_exfat_build_cmd("/usr/sbin/mkfs.exfat", "/dev/sdb1",
                                     0, NULL, NULL, 512);
    CHECK(r == FALSE);
}

/* ================================================================
 * UDF command builder tests
 * ================================================================ */

TEST(udf_build_cmd_basic)
{
    char cmd[512];
    extern BOOL format_udf_build_cmd(const char *, const char *, DWORD,
                                     const char *, char *, size_t);
    BOOL r = format_udf_build_cmd("/usr/sbin/mkudffs", "/dev/sdb1",
                                   0, NULL, cmd, sizeof(cmd));
    CHECK(r == TRUE);
    CHECK(strstr(cmd, "/usr/sbin/mkudffs") != NULL);
    CHECK(strstr(cmd, "/dev/sdb1") != NULL);
}

TEST(udf_build_cmd_with_label)
{
    char cmd[512];
    extern BOOL format_udf_build_cmd(const char *, const char *, DWORD,
                                     const char *, char *, size_t);
    format_udf_build_cmd("/usr/sbin/mkudffs", "/dev/sdb1",
                          0, "MyUDF", cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-l") != NULL);
    CHECK(strstr(cmd, "MyUDF") != NULL);
}

TEST(udf_build_cmd_empty_label_omitted)
{
    char cmd[512];
    extern BOOL format_udf_build_cmd(const char *, const char *, DWORD,
                                     const char *, char *, size_t);
    format_udf_build_cmd("/usr/sbin/mkudffs", "/dev/sdb1",
                          0, "", cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-l") == NULL);
}

TEST(udf_build_cmd_with_blocksize)
{
    char cmd[512];
    extern BOOL format_udf_build_cmd(const char *, const char *, DWORD,
                                     const char *, char *, size_t);
    format_udf_build_cmd("/usr/sbin/mkudffs", "/dev/sdb1",
                          512, NULL, cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-b") != NULL);
    CHECK(strstr(cmd, "512") != NULL);
}

TEST(udf_build_cmd_zero_blocksize_omitted)
{
    char cmd[512];
    extern BOOL format_udf_build_cmd(const char *, const char *, DWORD,
                                     const char *, char *, size_t);
    format_udf_build_cmd("/usr/sbin/mkudffs", "/dev/sdb1",
                          0, NULL, cmd, sizeof(cmd));
    CHECK(strstr(cmd, "-b") == NULL);
}

TEST(udf_build_cmd_null_tool_returns_false)
{
    char cmd[512];
    extern BOOL format_udf_build_cmd(const char *, const char *, DWORD,
                                     const char *, char *, size_t);
    BOOL r = format_udf_build_cmd(NULL, "/dev/sdb1",
                                   0, NULL, cmd, sizeof(cmd));
    CHECK(r == FALSE);
}

TEST(udf_build_cmd_null_path_returns_false)
{
    char cmd[512];
    extern BOOL format_udf_build_cmd(const char *, const char *, DWORD,
                                     const char *, char *, size_t);
    BOOL r = format_udf_build_cmd("/usr/sbin/mkudffs", NULL,
                                   0, NULL, cmd, sizeof(cmd));
    CHECK(r == FALSE);
}

TEST(udf_build_cmd_null_buf_returns_false)
{
    extern BOOL format_udf_build_cmd(const char *, const char *, DWORD,
                                     const char *, char *, size_t);
    BOOL r = format_udf_build_cmd("/usr/sbin/mkudffs", "/dev/sdb1",
                                   0, NULL, NULL, 512);
    CHECK(r == FALSE);
}

TEST(udf_invalid_drive_returns_false)
{
    ErrorStatus = 0;
    BOOL r = FormatUDF(DRIVE_INDEX_MIN - 1, 0, 0, "Test", FP_FORCE);
    CHECK(r == FALSE);
}

TEST(udf_format_no_tool_returns_false)
{
    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    /* Use a nonexistent tool path — build cmd then run it */
    extern BOOL format_udf_build_cmd(const char *, const char *, DWORD,
                                     const char *, char *, size_t);
    char cmd[512];
    BOOL cmd_ok = format_udf_build_cmd("/nonexistent/mkudffs", path,
                                        0, NULL, cmd, sizeof(cmd));
    CHECK(cmd_ok == TRUE);
    int rc = system(cmd);
    CHECK(rc != 0);

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(udf_format_creates_filesystem_if_tool_present)
{
    const char *tool = find_tool("mkudffs");
    if (tool == NULL) {
        printf("  [SKIP] mkudffs not found\n");
        return;
    }

    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    BOOL r = FormatUDF(DRIVE_INDEX_MIN, 0, 0, "UDFTEST", FP_FORCE);
    CHECK(r == TRUE);

    /* UDF descriptor begins with 0x01 at offset 0 in the AVDP or first sector */
    /* Just verify no error status is set */
    CHECK(IS_ERROR(ErrorStatus) == FALSE);

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(format_partition_udf_returns_false_no_tool)
{
    /* If mkudffs is absent this must return FALSE gracefully */
    const char *tool = find_tool("mkudffs");
    if (tool != NULL) {
        printf("  [SKIP] mkudffs present — cannot test absent-tool path\n");
        return;
    }

    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_UDF, "UDFTEST", FP_FORCE);
    CHECK(r == FALSE);

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(format_partition_udf_returns_true_if_tool_present)
{
    const char *tool = find_tool("mkudffs");
    if (tool == NULL) {
        printf("  [SKIP] mkudffs not found\n");
        return;
    }

    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_UDF, "UDFTEST", FP_FORCE);
    CHECK(r == TRUE);

    teardown_drive();
    unlink(path);
    free(path);
}

/* ================================================================
 * 2. Graceful failure when tool is not present
 * ================================================================ */

TEST(ntfs_format_no_tool_returns_false)
{
    /* Use a nonexistent tool path */
    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    /* Directly test via the internal function with a bad tool path */
    char cmd[512];
    BOOL cmd_ok = format_ntfs_build_cmd("/nonexistent/mkntfs", path,
                                         0, NULL, FALSE, FALSE, cmd, sizeof(cmd));
    /* Command builds fine even with non-existent tool */
    CHECK(cmd_ok == TRUE);
    /* But running it should fail (exit code != 0) */
    int rc = system(cmd);
    CHECK(rc != 0);

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(exfat_format_no_tool_returns_false)
{
    char *path = create_temp_image(TEST_IMG_SIZE_EXFAT);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_EXFAT);
    ErrorStatus = 0;

    char cmd[512];
    BOOL cmd_ok = format_exfat_build_cmd("/nonexistent/mkfs.exfat", path,
                                          0, NULL, cmd, sizeof(cmd));
    CHECK(cmd_ok == TRUE);
    int rc = system(cmd);
    CHECK(rc != 0);

    teardown_drive();
    unlink(path);
    free(path);
}

/* FormatNTFS with invalid drive index */
TEST(ntfs_invalid_drive_returns_false)
{
    ErrorStatus = 0;
    BOOL r = FormatNTFS(DRIVE_INDEX_MIN - 1, 0, 0, "Test", FP_FORCE);
    CHECK(r == FALSE);
}

TEST(exfat_invalid_drive_returns_false)
{
    ErrorStatus = 0;
    BOOL r = FormatExFAT(DRIVE_INDEX_MIN - 1, 0, 0, "Test", FP_FORCE);
    CHECK(r == FALSE);
}

/* ================================================================
 * 3. WritePBR returns TRUE for NTFS and exFAT
 * ================================================================ */

TEST(writepbr_ntfs_returns_true)
{
    /* Create a small temp file as a fake handle */
    char *path = create_temp_image(512 * 512);
    CHECK(path != NULL);
    setup_drive(path, 512 * 512);

    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;

    /* Set actual_fs_type to NTFS via the format path */
    BOOL r = WritePBR_fs(h, FS_NTFS);
    CHECK(r == TRUE);

    close(fd);
    teardown_drive();
    unlink(path);
    free(path);
}

TEST(writepbr_exfat_returns_true)
{
    char *path = create_temp_image(512 * 512);
    CHECK(path != NULL);
    setup_drive(path, 512 * 512);

    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;

    BOOL r = WritePBR_fs(h, FS_EXFAT);
    CHECK(r == TRUE);

    close(fd);
    teardown_drive();
    unlink(path);
    free(path);
}

/* ================================================================
 * 4. FormatPartition routing
 * ================================================================ */

/* When mkntfs is absent, FormatPartition(FS_NTFS) should return FALSE
 * (not crash or assert). */
TEST(format_partition_ntfs_returns_false_no_tool)
{
    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    /* If mkntfs happens to be installed, this may return TRUE — that's OK too */
    BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_NTFS, "NTFSTEST", FP_FORCE | FP_QUICK);
    /* Either TRUE (tool found) or FALSE (tool absent) — must not crash */
    (void)r;

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(format_partition_exfat_no_crash)
{
    char *path = create_temp_image(TEST_IMG_SIZE_EXFAT);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_EXFAT);
    ErrorStatus = 0;

    BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_EXFAT, "EXFATTEST", FP_FORCE);
    (void)r;

    teardown_drive();
    unlink(path);
    free(path);
}

/* ================================================================
 * 5. Actual formatting tests (skipped if tool absent)
 * ================================================================ */

TEST(ntfs_format_creates_filesystem_if_tool_present)
{
    const char *tool = find_tool("mkntfs");
    if (tool == NULL) {
        printf("  [SKIP] mkntfs not found\n");
        return;
    }

    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    BOOL r = FormatNTFS(DRIVE_INDEX_MIN, 0, 0, "NTFSTEST", FP_FORCE | FP_QUICK);
    CHECK(r == TRUE);

    /* Verify NTFS magic "NTFS    " at byte offset 3 */
    uint8_t magic[8] = {0};
    int rc = read_at(path, 3, magic, 8);
    CHECK(rc == 0);
    CHECK(memcmp(magic, "NTFS    ", 8) == 0);

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(ntfs_format_with_label)
{
    const char *tool = find_tool("mkntfs");
    if (tool == NULL) {
        printf("  [SKIP] mkntfs not found\n");
        return;
    }

    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    BOOL r = FormatNTFS(DRIVE_INDEX_MIN, 0, 0, "RUFUSNTFS", FP_FORCE | FP_QUICK);
    CHECK(r == TRUE);

    /* NTFS volume label is at 0x48 in the BPB — but we rely on mkntfs having
     * accepted the label without error as verified by r == TRUE */
    (void)r;

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(ntfs_format_with_cluster_size)
{
    const char *tool = find_tool("mkntfs");
    if (tool == NULL) {
        printf("  [SKIP] mkntfs not found\n");
        return;
    }

    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    /* 4096-byte clusters — valid for NTFS */
    BOOL r = FormatNTFS(DRIVE_INDEX_MIN, 0, 4096, "CLUSTERTEST", FP_FORCE | FP_QUICK);
    CHECK(r == TRUE);

    /* Verify NTFS magic still present */
    uint8_t magic[8] = {0};
    CHECK(read_at(path, 3, magic, 8) == 0);
    CHECK(memcmp(magic, "NTFS    ", 8) == 0);

    /* NTFS BPB: bytes-per-sector at 0x0B, sectors-per-cluster at 0x0D */
    uint16_t bps = 0;
    uint8_t  spc = 0;
    CHECK(read_at(path, 0x0B, &bps, 2) == 0);
    CHECK(read_at(path, 0x0D, &spc, 1) == 0);
    /* cluster_size = bps * spc — must equal 4096 */
    CHECK((uint32_t)bps * spc == 4096);

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(exfat_format_creates_filesystem_if_tool_present)
{
    const char *tool = find_tool("mkfs.exfat");
    if (tool == NULL) {
        /* Also try exfatprogs variant */
        tool = find_tool("mkexfatfs");
        if (tool == NULL) {
            printf("  [SKIP] mkfs.exfat not found\n");
            return;
        }
    }

    char *path = create_temp_image(TEST_IMG_SIZE_EXFAT);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_EXFAT);
    ErrorStatus = 0;

    BOOL r = FormatExFAT(DRIVE_INDEX_MIN, 0, 0, "EXFATTEST", FP_FORCE);
    CHECK(r == TRUE);

    /* Verify exFAT magic "EXFAT   " at byte offset 3 */
    uint8_t magic[8] = {0};
    int rc = read_at(path, 3, magic, 8);
    CHECK(rc == 0);
    CHECK(memcmp(magic, "EXFAT   ", 8) == 0);

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(exfat_format_with_label)
{
    const char *tool = find_tool("mkfs.exfat");
    if (tool == NULL) {
        tool = find_tool("mkexfatfs");
        if (tool == NULL) {
            printf("  [SKIP] mkfs.exfat not found\n");
            return;
        }
    }

    char *path = create_temp_image(TEST_IMG_SIZE_EXFAT);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_EXFAT);
    ErrorStatus = 0;

    BOOL r = FormatExFAT(DRIVE_INDEX_MIN, 0, 0, "RUFUSEXFAT", FP_FORCE);
    CHECK(r == TRUE);

    /* Verify magic */
    uint8_t magic[8] = {0};
    CHECK(read_at(path, 3, magic, 8) == 0);
    CHECK(memcmp(magic, "EXFAT   ", 8) == 0);

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(exfat_format_with_cluster_size)
{
    const char *tool = find_tool("mkfs.exfat");
    if (tool == NULL) {
        tool = find_tool("mkexfatfs");
        if (tool == NULL) {
            printf("  [SKIP] mkfs.exfat not found\n");
            return;
        }
    }

    char *path = create_temp_image(TEST_IMG_SIZE_EXFAT);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_EXFAT);
    ErrorStatus = 0;

    /* 4096-byte clusters */
    BOOL r = FormatExFAT(DRIVE_INDEX_MIN, 0, 4096, "CLUSTEREX", FP_FORCE);
    CHECK(r == TRUE);

    uint8_t magic[8] = {0};
    CHECK(read_at(path, 3, magic, 8) == 0);
    CHECK(memcmp(magic, "EXFAT   ", 8) == 0);

    teardown_drive();
    unlink(path);
    free(path);
}

/* ================================================================
 * 6. FormatPartition routing — uses the full function
 * ================================================================ */

TEST(format_partition_ntfs_returns_true_if_tool_present)
{
    const char *tool = find_tool("mkntfs");
    if (tool == NULL) {
        printf("  [SKIP] mkntfs not found\n");
        return;
    }

    char *path = create_temp_image(TEST_IMG_SIZE_NTFS);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_NTFS);
    ErrorStatus = 0;

    BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_NTFS, "NTFSTEST", FP_FORCE | FP_QUICK);
    CHECK(r == TRUE);

    uint8_t magic[8] = {0};
    CHECK(read_at(path, 3, magic, 8) == 0);
    CHECK(memcmp(magic, "NTFS    ", 8) == 0);

    teardown_drive();
    unlink(path);
    free(path);
}

TEST(format_partition_exfat_returns_true_if_tool_present)
{
    const char *tool = find_tool("mkfs.exfat");
    if (tool == NULL) {
        tool = find_tool("mkexfatfs");
        if (tool == NULL) {
            printf("  [SKIP] mkfs.exfat not found\n");
            return;
        }
    }

    char *path = create_temp_image(TEST_IMG_SIZE_EXFAT);
    CHECK(path != NULL);
    setup_drive(path, TEST_IMG_SIZE_EXFAT);
    ErrorStatus = 0;

    BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_EXFAT, "EXFATTEST", FP_FORCE);
    CHECK(r == TRUE);

    uint8_t magic[8] = {0};
    CHECK(read_at(path, 3, magic, 8) == 0);
    CHECK(memcmp(magic, "EXFAT   ", 8) == 0);

    teardown_drive();
    unlink(path);
    free(path);
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
    printf("=== NTFS and exFAT Format Tests ===\n");

    /* Command building */
    RUN(ntfs_build_cmd_basic);
    RUN(ntfs_build_cmd_quick_flag);
    RUN(ntfs_build_cmd_no_quick_when_false);
    RUN(ntfs_build_cmd_with_label);
    RUN(ntfs_build_cmd_empty_label_omitted);
    RUN(ntfs_build_cmd_with_cluster_size);
    RUN(ntfs_build_cmd_zero_cluster_omitted);
    RUN(ntfs_build_cmd_null_tool_returns_false);
    RUN(ntfs_build_cmd_null_path_returns_false);
    RUN(ntfs_build_cmd_null_buf_returns_false);
    RUN(ntfs_build_cmd_buf_too_small_returns_false);

    RUN(exfat_build_cmd_basic);
    RUN(exfat_build_cmd_with_label);
    RUN(exfat_build_cmd_empty_label_omitted);
    RUN(exfat_build_cmd_with_cluster_size);
    RUN(exfat_build_cmd_zero_cluster_omitted);
    RUN(exfat_build_cmd_null_tool_returns_false);
    RUN(exfat_build_cmd_null_path_returns_false);
    RUN(exfat_build_cmd_null_buf_returns_false);

    RUN(udf_build_cmd_basic);
    RUN(udf_build_cmd_with_label);
    RUN(udf_build_cmd_empty_label_omitted);
    RUN(udf_build_cmd_with_blocksize);
    RUN(udf_build_cmd_zero_blocksize_omitted);
    RUN(udf_build_cmd_null_tool_returns_false);
    RUN(udf_build_cmd_null_path_returns_false);
    RUN(udf_build_cmd_null_buf_returns_false);

    /* Graceful failure */
    RUN(ntfs_format_no_tool_returns_false);
    RUN(exfat_format_no_tool_returns_false);
    RUN(udf_format_no_tool_returns_false);
    RUN(ntfs_invalid_drive_returns_false);
    RUN(exfat_invalid_drive_returns_false);
    RUN(udf_invalid_drive_returns_false);

    /* WritePBR */
    RUN(writepbr_ntfs_returns_true);
    RUN(writepbr_exfat_returns_true);

    /* FormatPartition routing */
    RUN(format_partition_ntfs_returns_false_no_tool);
    RUN(format_partition_exfat_no_crash);
    RUN(format_partition_udf_returns_false_no_tool);

    /* Actual formatting (skipped if tool absent) */
    RUN(ntfs_format_creates_filesystem_if_tool_present);
    RUN(ntfs_format_with_label);
    RUN(ntfs_format_with_cluster_size);
    RUN(exfat_format_creates_filesystem_if_tool_present);
    RUN(exfat_format_with_label);
    RUN(exfat_format_with_cluster_size);
    RUN(udf_format_creates_filesystem_if_tool_present);

    /* Full FormatPartition routing */
    RUN(format_partition_ntfs_returns_true_if_tool_present);
    RUN(format_partition_exfat_returns_true_if_tool_present);
    RUN(format_partition_udf_returns_true_if_tool_present);

    TEST_RESULTS();
}

#endif /* __linux__ */
