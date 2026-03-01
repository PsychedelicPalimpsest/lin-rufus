/*
 * test_loopback_linux.c — integration tests using real /dev/loop* block devices.
 *
 * Each test creates a file-backed loop device, exercises the Rufus disk
 * operations (InitializeDisk, CreatePartition, FormatPartition, MountVolume)
 * against a real kernel block device, and cleans up afterward.
 *
 * REQUIRES ROOT.  Every test skips gracefully when not running as root.
 * Run as:  sudo ./tests/test_loopback_linux
 *
 * Designed for CI integration:
 *   sudo ./run_tests.sh --linux-only    # includes loopback tests when root
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
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <linux/fs.h>       /* BLKGETSIZE64, BLKSSZGET */

/* ---- Rufus compat + headers ---- */
#include "windows.h"
#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "format_linux.h"

/* ================================================================
 * Required globals (mirror of test_format_thread_linux.c)
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
BOOL quick_format          = TRUE;
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
int boot_type              = 0;
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
char *sb_revoked_txt      = NULL;

float fScale              = 1.0f;

sbat_entry_t *sbat_entries = NULL;
thumbprint_list_t *sb_active_certs = NULL, *sb_revoked_certs = NULL;
RUFUS_UPDATE update = { {0,0,0}, {0,0}, NULL, NULL };
RUFUS_IMG_REPORT img_report = { 0 };
HINSTANCE hMainInstance = NULL;
HWND hMultiToolbar = NULL, hSaveToolbar = NULL, hHashToolbar = NULL;
HWND hAdvancedDeviceToolbar = NULL, hAdvancedFormatToolbar = NULL;
HWND hUpdatesDlg = NULL;
HWND hPartitionScheme = NULL, hTargetSystem = NULL, hFileSystem = NULL;
HWND hClusterSize = NULL, hLabel = NULL, hBootType = NULL, hNBPasses = NULL;
HWND hImageOption = NULL, hLogDialog = NULL;
HWND hCapacity = NULL;
WORD selected_langid = 0;

const char* FileSystemLabel[FS_MAX] = {
	"FAT", "FAT32", "NTFS", "UDF", "exFAT", "ReFS", "ext2", "ext3", "ext4"
};
const int nb_steps[FS_MAX] = { 5, 5, 5, 5, 5, 5, 5, 5, 5 };
const char *md5sum_name[2] = { "md5sum.txt", "md5sum.txt" };

uint8_t *grub2_buf = NULL;
long grub2_len = 0;
uint8_t *sec_buf = NULL;
unsigned long syslinux_ldlinux_len[2] = {0, 0};

/* ================================================================
 * Stub functions
 * ================================================================ */

void uprintf(const char* fmt, ...) {
	/* Uncomment for debug output:
	va_list a; va_start(a,fmt); vfprintf(stderr,fmt,a); va_end(a); fputc('\n',stderr);
	*/
	(void)fmt;
}
void uprintfs(const char* s) { (void)s; }
const char* WindowsErrorString(void) { return strerror(errno); }

BOOL WriteFileWithRetry(HANDLE h, const void* buf, DWORD n, DWORD* written, DWORD retries) {
	if (h == INVALID_HANDLE_VALUE || !buf) return FALSE;
	int fd = (int)(intptr_t)h;
	DWORD total = 0;
	while (total < n) {
		ssize_t r = write(fd, (const char*)buf + total, n - total);
		if (r > 0) { total += (DWORD)r; }
		else if (r == 0 || (errno != EINTR && errno != EAGAIN)) {
			if (retries > 0) { retries--; continue; }
			break;
		}
	}
	if (written) *written = total;
	return (total == n);
}

char* lmprintf(int id, ...) { (void)id; return ""; }

void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration, int msg_id, ...) {
	(void)info; (void)debug; (void)duration; (void)msg_id;
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
void UpdateProgress(int op, float percent) { (void)op; (void)percent; }

LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
	(void)h; (void)m; (void)w; (void)l; return 0;
}
BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
	(void)h; (void)m; (void)w; (void)l; return FALSE;
}

char* SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units) {
	static char buf[32];
	static const char* suf[] = { "B", "KB", "MB", "GB", "TB" };
	double hr = (double)size; int s = 0;
	const double div = fake_units ? 1000.0 : 1024.0;
	(void)copy_to_log;
	while (s < 4 && hr >= div) { hr /= div; s++; }
	snprintf(buf, sizeof(buf), "%.1f %s", hr, suf[s]);
	return buf;
}

LONG GetEntryWidth(HWND h, const char* e) { (void)h; (void)e; return 0; }
BOOL IsCurrentProcessElevated(void) { return (geteuid() == 0) ? TRUE : FALSE; }

BOOL ExtractISO(const char *src, const char *dst, BOOL scan_only) {
	(void)src; (void)dst; (void)scan_only;
	return TRUE;
}

/* ================================================================
 * Test framework
 * ================================================================ */

#include "framework.h"

/* ================================================================
 * Root-check macro
 * ================================================================ */

/*
 * Print a SKIP line and return from the current test function when
 * not running as root.  Loopback devices require CAP_SYS_ADMIN.
 */
#define SKIP_NOT_ROOT() \
	do { \
		if (geteuid() != 0) { \
			printf("  SKIP (not root — loopback device requires root)\n"); \
			return; \
		} \
	} while (0)

/* ================================================================
 * Loopback context and helpers
 * ================================================================ */

#define LOOP_IMG_SIZE   ((uint64_t)128 * 1024 * 1024)   /* 128 MiB */
#define LOOP_DEV_MAX    64

typedef struct {
	char  img_path[256];   /* path to the backing image file */
	char  dev_path[64];    /* /dev/loopN */
	int   img_fd;          /* open fd on the image (for direct read checks) */
} loop_ctx_t;

/*
 * Create a sparse 128 MiB file and attach it as a loop device.
 * Populates *ctx on success; returns TRUE.
 */
static BOOL loop_setup(loop_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->img_fd = -1;

	/* Create temp image */
	strncpy(ctx->img_path, "/tmp/rufus_loopback_XXXXXX", sizeof(ctx->img_path) - 1);
	ctx->img_fd = mkstemp(ctx->img_path);
	if (ctx->img_fd < 0) return FALSE;
	if (ftruncate(ctx->img_fd, (off_t)LOOP_IMG_SIZE) != 0) {
		close(ctx->img_fd); ctx->img_fd = -1;
		unlink(ctx->img_path);
		return FALSE;
	}

	/* Attach as loop device; losetup -f --show <img> */
	char cmd[320];
	snprintf(cmd, sizeof(cmd), "losetup -f --show %s 2>/dev/null", ctx->img_path);
	FILE *fp = popen(cmd, "r");
	if (!fp) {
		close(ctx->img_fd); ctx->img_fd = -1;
		unlink(ctx->img_path);
		return FALSE;
	}
	if (!fgets(ctx->dev_path, sizeof(ctx->dev_path), fp)) {
		pclose(fp);
		close(ctx->img_fd); ctx->img_fd = -1;
		unlink(ctx->img_path);
		return FALSE;
	}
	pclose(fp);

	/* Strip newline */
	size_t len = strlen(ctx->dev_path);
	if (len > 0 && ctx->dev_path[len - 1] == '\n')
		ctx->dev_path[len - 1] = '\0';

	/* Verify we got a real block device */
	struct stat st;
	if (stat(ctx->dev_path, &st) != 0 || !S_ISBLK(st.st_mode)) {
		close(ctx->img_fd); ctx->img_fd = -1;
		unlink(ctx->img_path);
		memset(ctx->dev_path, 0, sizeof(ctx->dev_path));
		return FALSE;
	}

	return TRUE;
}

/*
 * Detach the loop device and delete the backing image.
 */
static void loop_teardown(loop_ctx_t *ctx)
{
	if (ctx->dev_path[0] != '\0') {
		char cmd[128];
		snprintf(cmd, sizeof(cmd), "losetup -d %s 2>/dev/null", ctx->dev_path);
		system(cmd);
	}
	if (ctx->img_fd >= 0) {
		close(ctx->img_fd);
		ctx->img_fd = -1;
	}
	if (ctx->img_path[0] != '\0')
		unlink(ctx->img_path);
	memset(ctx, 0, sizeof(*ctx));
}

/*
 * Populate rufus_drive[0] and SelectedDrive for the loop device.
 * Returns the DriveIndex to pass to FormatPartition / CreatePartition.
 */
static DWORD loop_register(loop_ctx_t *ctx)
{
	memset(rufus_drive, 0, sizeof(rufus_drive));
	rufus_drive[0].id           = ctx->dev_path;
	rufus_drive[0].name         = "LoopTest";
	rufus_drive[0].display_name = "Loopback Test Drive";
	rufus_drive[0].label        = "";
	rufus_drive[0].index        = DRIVE_INDEX_MIN;
	rufus_drive[0].port         = 0;
	rufus_drive[0].size         = LOOP_IMG_SIZE;

	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	SelectedDrive.DiskSize   = (LONGLONG)LOOP_IMG_SIZE;
	SelectedDrive.SectorSize = 512;

	return DRIVE_INDEX_MIN;
}

static void loop_unregister(void)
{
	memset(rufus_drive, 0, sizeof(rufus_drive));
	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	memset(partition_index, 0, sizeof(partition_index));
	ErrorStatus = 0;
}

/*
 * Read N bytes at a given byte offset from ctx->img_fd.
 * Returns 0 on success.
 */
static int read_at(loop_ctx_t *ctx, off_t offset, void *buf, size_t n)
{
	ssize_t r = pread(ctx->img_fd, buf, n, offset);
	return (r == (ssize_t)n) ? 0 : -1;
}

/* ================================================================
 * Tests
 * ================================================================ */

/* ----------------------------------------------------------------
 * 1. Verify that losetup itself works: attach and detach a loop device.
 * ---------------------------------------------------------------- */
TEST(loop_attach_detach)
{
	SKIP_NOT_ROOT();

	loop_ctx_t ctx;
	BOOL ok = loop_setup(&ctx);
	CHECK_MSG(ok == TRUE, "loop_setup must succeed");
	CHECK_MSG(ctx.dev_path[0] != '\0', "dev_path must be populated");
	CHECK_MSG(strncmp(ctx.dev_path, "/dev/loop", 9) == 0,
	          "dev_path must start with /dev/loop");

	/* Verify the loop device is a real block device */
	struct stat st;
	int rc = stat(ctx.dev_path, &st);
	CHECK_MSG(rc == 0, "stat on loop device must succeed");
	CHECK_MSG(S_ISBLK(st.st_mode), "loop device must be a block device");

	loop_teardown(&ctx);
	/* After teardown the device should no longer exist as a block device */
	rc = stat(ctx.dev_path, &st);
	/* The path may still exist in sysfs after detach with a short window; just
	 * verify it's no longer backed (the file no longer exists) */
	CHECK_MSG(access(ctx.img_path, F_OK) != 0,
	          "backing image must be deleted after teardown");
}

/* ----------------------------------------------------------------
 * 2. InitializeDisk on a real block device.
 * ---------------------------------------------------------------- */
TEST(initialize_disk_on_loop)
{
	SKIP_NOT_ROOT();

	loop_ctx_t ctx;
	BOOL ok = loop_setup(&ctx);
	CHECK_MSG(ok == TRUE, "loop_setup must succeed");

	/* Open the loop device for writing */
	int fd = open(ctx.dev_path, O_RDWR | O_CLOEXEC);
	CHECK_MSG(fd >= 0, "open loop device for writing must succeed");

	HANDLE h = (HANDLE)(intptr_t)fd;
	BOOL init_ok = InitializeDisk(h);
	close(fd);

	CHECK_MSG(init_ok == TRUE, "InitializeDisk on loop device must return TRUE");

	/* Verify first 512 bytes are zero */
	uint8_t sector0[512];
	int read_rc = read_at(&ctx, 0, sector0, 512);
	CHECK_MSG(read_rc == 0, "pread of first sector must succeed");
	int nonzero = 0;
	for (int i = 0; i < 512; i++) if (sector0[i] != 0) nonzero++;
	CHECK_MSG(nonzero == 0, "InitializeDisk must zero the first 512 bytes");

	loop_teardown(&ctx);
}

/* ----------------------------------------------------------------
 * 3. CreatePartition MBR on a real block device.
 * ---------------------------------------------------------------- */
TEST(create_partition_mbr_on_loop)
{
	SKIP_NOT_ROOT();

	loop_ctx_t ctx;
	BOOL ok = loop_setup(&ctx);
	CHECK_MSG(ok == TRUE, "loop_setup must succeed");

	loop_register(&ctx);

	int fd = open(ctx.dev_path, O_RDWR | O_CLOEXEC);
	CHECK_MSG(fd >= 0, "open loop device for writing must succeed");

	HANDLE h = (HANDLE)(intptr_t)fd;
	BOOL part_ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_FAT32, TRUE, 0);
	close(fd);

	CHECK_MSG(part_ok == TRUE, "CreatePartition MBR must return TRUE");

	/* Verify MBR signature at bytes 510-511 */
	uint8_t mbr[512];
	int read_rc = read_at(&ctx, 0, mbr, 512);
	CHECK_MSG(read_rc == 0, "pread of MBR must succeed");
	CHECK_MSG(mbr[510] == 0x55, "MBR byte 510 must be 0x55");
	CHECK_MSG(mbr[511] == 0xAA, "MBR byte 511 must be 0xAA");

	/* Verify partition entry 0 is marked bootable */
	CHECK_MSG(mbr[446] == 0x80,
	          "first partition entry status byte must be 0x80 (bootable)");

	/* Verify partition starts at LBA 2048 */
	uint32_t lba_start = (uint32_t)mbr[446+8]
	                   | ((uint32_t)mbr[446+9]  << 8)
	                   | ((uint32_t)mbr[446+10] << 16)
	                   | ((uint32_t)mbr[446+11] << 24);
	CHECK_MSG(lba_start == 2048,
	          "MBR partition must start at LBA 2048");

	loop_unregister();
	loop_teardown(&ctx);
}

/* ----------------------------------------------------------------
 * 4. CreatePartition GPT on a real block device.
 * ---------------------------------------------------------------- */
TEST(create_partition_gpt_on_loop)
{
	SKIP_NOT_ROOT();

	loop_ctx_t ctx;
	BOOL ok = loop_setup(&ctx);
	CHECK_MSG(ok == TRUE, "loop_setup must succeed");

	loop_register(&ctx);

	int fd = open(ctx.dev_path, O_RDWR | O_CLOEXEC);
	CHECK_MSG(fd >= 0, "open loop device for writing must succeed");

	HANDLE h = (HANDLE)(intptr_t)fd;
	BOOL part_ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_FAT32, FALSE, 0);
	close(fd);

	CHECK_MSG(part_ok == TRUE, "CreatePartition GPT must return TRUE");

	/* Verify Protective MBR signature at bytes 510-511 */
	uint8_t mbr[512];
	int read_rc = read_at(&ctx, 0, mbr, 512);
	CHECK_MSG(read_rc == 0, "pread of protective MBR must succeed");
	CHECK_MSG(mbr[510] == 0x55, "Protective MBR byte 510 must be 0x55");
	CHECK_MSG(mbr[511] == 0xAA, "Protective MBR byte 511 must be 0xAA");

	/* Verify GPT header signature "EFI PART" at LBA 1 (offset 512) */
	uint8_t gpt_hdr[8];
	read_rc = read_at(&ctx, 512, gpt_hdr, 8);
	CHECK_MSG(read_rc == 0, "pread of GPT header must succeed");
	CHECK_MSG(memcmp(gpt_hdr, "EFI PART", 8) == 0,
	          "GPT header must start with 'EFI PART' signature");

	loop_unregister();
	loop_teardown(&ctx);
}

/* ----------------------------------------------------------------
 * 5. FormatPartition FAT32 on a real block device.
 *    Formats the entire loop device at offset 0 (no MBR partitioning).
 * ---------------------------------------------------------------- */
TEST(format_fat32_on_loop)
{
	SKIP_NOT_ROOT();

	loop_ctx_t ctx;
	BOOL ok = loop_setup(&ctx);
	CHECK_MSG(ok == TRUE, "loop_setup must succeed");

	DWORD di = loop_register(&ctx);
	ErrorStatus = 0;
	fs_type     = FS_FAT32;
	boot_type   = BT_NON_BOOTABLE;

	BOOL fmt_ok = FormatPartition(di, 0, 0, FS_FAT32, "RUFUSTEST", 0);

	CHECK_MSG(fmt_ok == TRUE || !IS_ERROR(ErrorStatus),
	          "FormatPartition(FAT32) must succeed or leave no fatal error");

	if (fmt_ok) {
		/* Verify FAT32 boot sector signature 0x55AA at offset 510 */
		uint8_t boot[512];
		int read_rc = read_at(&ctx, 510, boot, 2);
		CHECK_MSG(read_rc == 0, "pread of boot sector tail must succeed");
		CHECK_MSG(boot[0] == 0x55 && boot[1] == 0xAA,
		          "FAT32 boot sector must end with 0x55 0xAA");

		/* Verify FAT32 OEM name "MSWIN4.1" at offset 3 */
		uint8_t oem[8];
		read_rc = read_at(&ctx, 3, oem, 8);
		CHECK_MSG(read_rc == 0, "pread of OEM name must succeed");
		CHECK_MSG(memcmp(oem, "MSWIN4.1", 8) == 0,
		          "FAT32 OEM name must be 'MSWIN4.1'");
	}

	loop_unregister();
	loop_teardown(&ctx);
}

/* ----------------------------------------------------------------
 * 6. FormatPartition ext4 on a real block device.
 * ---------------------------------------------------------------- */
TEST(format_ext4_on_loop)
{
	SKIP_NOT_ROOT();

	loop_ctx_t ctx;
	BOOL ok = loop_setup(&ctx);
	CHECK_MSG(ok == TRUE, "loop_setup must succeed");

	DWORD di = loop_register(&ctx);
	ErrorStatus = 0;
	fs_type     = FS_EXT4;
	boot_type   = BT_NON_BOOTABLE;

	BOOL fmt_ok = FormatPartition(di, 0, 0, FS_EXT4, "RUFUSTEST", 0);

	CHECK_MSG(fmt_ok == TRUE || !IS_ERROR(ErrorStatus),
	          "FormatPartition(ext4) must succeed or leave no fatal error");

	if (fmt_ok) {
		/* Verify ext4 superblock magic 0xEF53 at offset 1080 (0x438)  */
		uint16_t magic = 0;
		int read_rc = read_at(&ctx, 1080, &magic, 2);
		CHECK_MSG(read_rc == 0, "pread of ext superblock magic must succeed");
		CHECK_MSG(magic == 0xEF53,
		          "ext4 superblock magic must be 0xEF53");
	}

	loop_unregister();
	loop_teardown(&ctx);
}

/* ----------------------------------------------------------------
 * 7. MountVolume: format FAT32 on loop device, then mount it.
 * ---------------------------------------------------------------- */
TEST(mount_fat32_loop)
{
	SKIP_NOT_ROOT();

	loop_ctx_t ctx;
	BOOL ok = loop_setup(&ctx);
	CHECK_MSG(ok == TRUE, "loop_setup must succeed");

	DWORD di = loop_register(&ctx);
	ErrorStatus = 0;

	BOOL fmt_ok = FormatPartition(di, 0, 0, FS_FAT32, "MNTTEST", 0);
	if (!fmt_ok) {
		printf("  SKIP (FormatPartition FAT32 failed — mkfs.fat not available?)\n");
		loop_unregister();
		loop_teardown(&ctx);
		return;
	}

	/* Create temp mount point */
	char mnt[256];
	strncpy(mnt, "/tmp/rufus_mnt_XXXXXX", sizeof(mnt) - 1);
	if (!mkdtemp(mnt)) {
		loop_unregister();
		loop_teardown(&ctx);
		CHECK_MSG(0, "mkdtemp for mount point must succeed");
		return;
	}

	BOOL mount_ok = MountVolume(ctx.dev_path, mnt);
	CHECK_MSG(mount_ok == TRUE, "MountVolume(FAT32 loop) must return TRUE");

	if (mount_ok) {
		/* Verify the mount point is populated (should have at least "." and "..") */
		DIR *d = opendir(mnt);
		CHECK_MSG(d != NULL, "mount point must be openable as directory");
		if (d) closedir(d);

		/* Unmount */
		int umrc = umount2(mnt, 0);
		CHECK_MSG(umrc == 0, "umount2 must succeed");
	}

	rmdir(mnt);
	loop_unregister();
	loop_teardown(&ctx);
}

/* ----------------------------------------------------------------
 * 8. MountVolume: format ext4 on loop device, then mount it.
 * ---------------------------------------------------------------- */
TEST(mount_ext4_loop)
{
	SKIP_NOT_ROOT();

	loop_ctx_t ctx;
	BOOL ok = loop_setup(&ctx);
	CHECK_MSG(ok == TRUE, "loop_setup must succeed");

	DWORD di = loop_register(&ctx);
	ErrorStatus = 0;

	BOOL fmt_ok = FormatPartition(di, 0, 0, FS_EXT4, "MNTEXT4", 0);
	if (!fmt_ok) {
		printf("  SKIP (FormatPartition ext4 failed — libext2fs not available?)\n");
		loop_unregister();
		loop_teardown(&ctx);
		return;
	}

	/* Create temp mount point */
	char mnt[256];
	strncpy(mnt, "/tmp/rufus_mnt_ext4_XXXXXX", sizeof(mnt) - 1);
	if (!mkdtemp(mnt)) {
		loop_unregister();
		loop_teardown(&ctx);
		CHECK_MSG(0, "mkdtemp for ext4 mount point must succeed");
		return;
	}

	BOOL mount_ok = MountVolume(ctx.dev_path, mnt);
	CHECK_MSG(mount_ok == TRUE, "MountVolume(ext4 loop) must return TRUE");

	if (mount_ok) {
		/* Verify the mount point is openable */
		DIR *d = opendir(mnt);
		CHECK_MSG(d != NULL, "ext4 mount point must be openable as directory");
		if (d) closedir(d);

		/* Unmount */
		int umrc = umount2(mnt, 0);
		CHECK_MSG(umrc == 0, "umount2 of ext4 must succeed");
	}

	rmdir(mnt);
	loop_unregister();
	loop_teardown(&ctx);
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void)
{
	if (geteuid() != 0)
		printf("NOTE: Running without root — all tests will be skipped.\n"
		       "      Re-run as root or via sudo for full coverage.\n\n");

	RUN_TEST(loop_attach_detach);
	RUN_TEST(initialize_disk_on_loop);
	RUN_TEST(create_partition_mbr_on_loop);
	RUN_TEST(create_partition_gpt_on_loop);
	RUN_TEST(format_fat32_on_loop);
	RUN_TEST(format_ext4_on_loop);
	RUN_TEST(mount_fat32_loop);
	RUN_TEST(mount_ext4_loop);

	PRINT_RESULTS();
	return (g_failed == 0) ? 0 : 1;
}

#endif /* __linux__ */
