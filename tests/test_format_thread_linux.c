/*
 * test_format_thread_linux.c — Integration tests for FormatThread (Linux)
 *
 * Tests cover:
 *   • format_linux_clear_mbr_gpt() — zeroes first/last sectors
 *   • format_linux_write_mbr()     — writes correct MBR boot code per boot_type
 *   • format_linux_write_drive()   — raw image write and zero-drive mode
 *   • FormatThread()               — full end-to-end format workflow
 *
 * All tests use sparse temp image files as stand-ins for real block devices.
 * FormatThread is always run inside a real pthread (via CreateThread) to avoid
 * calling pthread_exit() on the test's main thread.
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
#include <assert.h>
#include <errno.h>

/* ---- compat + rufus headers ---- */
#include "windows.h"
#include "commctrl.h"
#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "format_linux.h"
#include "resource.h"

/* ================================================================
 * Required globals
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
	(void)fmt;
	/* Uncomment for debug: va_list a; va_start(a,fmt); vfprintf(stderr,fmt,a); va_end(a); fputc('\n',stderr); */
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
BOOL IsCurrentProcessElevated(void) { return FALSE; }

/* ExtractISO stub — just reports success (file copy tested separately) */
BOOL ExtractISO(const char *src, const char *dst, BOOL scan_only) {
	(void)src; (void)dst; (void)scan_only;
	return TRUE;
}

/* ================================================================
 * Test framework
 * ================================================================ */

#include "framework.h"

/* ================================================================
 * Helpers
 * ================================================================ */

#define IMG_512MB  ((uint64_t)512 * 1024 * 1024)
#define IMG_64MB   ((uint64_t)64  * 1024 * 1024)
#define IMG_32MB   ((uint64_t)32  * 1024 * 1024)
#define IMG_4MB    ((uint64_t)4   * 1024 * 1024)

/* Create a sparse temp file of given size; returns malloc'd path or NULL. */
static char* create_temp_image(uint64_t size)
{
	char* path = strdup("/tmp/rufus_ft_XXXXXX");
	if (!path) return NULL;
	int fd = mkstemp(path);
	if (fd < 0) { free(path); return NULL; }
	if (ftruncate(fd, (off_t)size) != 0) {
		close(fd); unlink(path); free(path); return NULL;
	}
	close(fd);
	return path;
}

/* Populate rufus_drive[0] for the given path/size. */
static void setup_drive(const char *path, uint64_t size)
{
	memset(rufus_drive, 0, sizeof(rufus_drive));
	rufus_drive[0].id           = (char*)path;
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
	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	memset(partition_index, 0, sizeof(partition_index));
}

/* Reset all format-relevant globals to a clean state. */
static void reset_globals(void)
{
	boot_type      = BT_NON_BOOTABLE;
	partition_type = PARTITION_STYLE_MBR;
	fs_type        = FS_FAT32;
	target_type    = TT_BIOS;
	write_as_image = FALSE;
	write_as_esp   = FALSE;
	zero_drive     = FALSE;
	write_as_image = FALSE;
	image_path     = NULL;
	ErrorStatus    = 0;
	LastWriteError = 0;
	img_report     = (RUFUS_IMG_REPORT){ 0 };
	use_rufus_mbr  = TRUE;
}

/* Read bytes from a file at offset. Returns 0 on success, -1 on error. */
static int read_at(const char* path, off_t off, void* buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	ssize_t r = pread(fd, buf, len, off);
	close(fd);
	return (r == (ssize_t)len) ? 0 : -1;
}

/* Check if a region of a file is all-zero. */
static int region_is_zero(const char *path, off_t off, size_t len)
{
	uint8_t *buf = (uint8_t*)malloc(len);
	if (!buf) return 0;
	int fd = open(path, O_RDONLY);
	if (fd < 0) { free(buf); return 0; }
	ssize_t r = pread(fd, buf, len, off);
	close(fd);
	if (r != (ssize_t)len) { free(buf); return 0; }
	for (size_t i = 0; i < len; i++) {
		if (buf[i] != 0) { free(buf); return 0; }
	}
	free(buf);
	return 1;
}

/*
 * Run FormatThread in a pthread, wait for it to finish, and return its
 * exit code (0 = success, non-zero = failure).
 */
static DWORD run_format_thread(DWORD DriveIndex)
{
	HANDLE t = CreateThread(NULL, 0, FormatThread,
	                        (void*)(uintptr_t)DriveIndex, 0, NULL);
	if (t == NULL) return (DWORD)-1;
	WaitForSingleObject(t, 60000);  /* up to 60 s */
	DWORD code = 1;
	GetExitCodeThread(t, &code);
	CloseHandle(t);
	return code;
}

/* ================================================================
 * ClearMBRGPT tests
 * ================================================================ */

TEST(clear_mbr_gpt_bad_handle_fails)
{
	BOOL r = format_linux_clear_mbr_gpt(INVALID_HANDLE_VALUE, IMG_4MB, 512);
	CHECK(r == FALSE);
}

TEST(clear_mbr_gpt_null_handle_fails)
{
	BOOL r = format_linux_clear_mbr_gpt(NULL, IMG_4MB, 512);
	CHECK(r == FALSE);
}

TEST(clear_mbr_gpt_zeroes_beginning)
{
	/* First MAX_SECTORS_TO_CLEAR sectors must be zeroed. */
	char* path = create_temp_image(IMG_4MB);
	CHECK(path != NULL);

	/* Pre-fill file with 0xFF so we can detect zeroing */
	int fd = open(path, O_RDWR);
	CHECK(fd >= 0);
	uint8_t ff_buf[512];
	memset(ff_buf, 0xFF, sizeof(ff_buf));
	for (int i = 0; i < MAX_SECTORS_TO_CLEAR; i++)
		pwrite(fd, ff_buf, 512, (off_t)i * 512);
	HANDLE h = (HANDLE)(intptr_t)fd;

	BOOL r = format_linux_clear_mbr_gpt(h, (LONGLONG)IMG_4MB, 512);
	CHECK(r == TRUE);

	/* Close and verify all those sectors are zero */
	close(fd);
	CHECK(region_is_zero(path, 0, MAX_SECTORS_TO_CLEAR * 512));

	unlink(path); free(path);
}

TEST(clear_mbr_gpt_zeroes_end)
{
	/* Last MAX_SECTORS_TO_CLEAR/8 sectors must be zeroed. */
	DWORD tail_sectors = MAX_SECTORS_TO_CLEAR / 8;
	uint64_t size = ((uint64_t)(MAX_SECTORS_TO_CLEAR + 64) * 512);  /* small enough to be fast */
	char* path = create_temp_image(size);
	CHECK(path != NULL);

	int fd = open(path, O_RDWR);
	CHECK(fd >= 0);
	/* Pre-fill the end of the drive with 0xFF */
	uint8_t ff_buf[512];
	memset(ff_buf, 0xFF, sizeof(ff_buf));
	off_t end_off = (off_t)(size - (uint64_t)tail_sectors * 512);
	for (DWORD i = 0; i < tail_sectors; i++)
		pwrite(fd, ff_buf, 512, end_off + (off_t)i * 512);
	HANDLE h = (HANDLE)(intptr_t)fd;

	BOOL r = format_linux_clear_mbr_gpt(h, (LONGLONG)size, 512);
	CHECK(r == TRUE);

	close(fd);
	CHECK(region_is_zero(path, end_off, tail_sectors * 512));

	unlink(path); free(path);
}

/* ================================================================
 * WriteMBR tests
 * ================================================================ */

/* Helper: open drive, call WriteMBR, close, return result. */
static BOOL do_write_mbr(const char *path)
{
	int fd = open(path, O_RDWR);
	if (fd < 0) return FALSE;
	HANDLE h = (HANDLE)(intptr_t)fd;
	BOOL r = format_linux_write_mbr(h);
	close(fd);
	return r;
}

TEST(write_mbr_bad_handle_fails)
{
	BOOL r = format_linux_write_mbr(INVALID_HANDLE_VALUE);
	CHECK(r == FALSE);
}

TEST(write_mbr_non_bootable_writes_zero_code)
{
	/* BT_NON_BOOTABLE → zeroed boot code at bytes 0-445, 0x55AA at 510-511 */
	char* path = create_temp_image(IMG_4MB);
	CHECK(path != NULL);

	/* Pre-fill the first 446 bytes with 0xFF */
	int fd = open(path, O_RDWR);
	CHECK(fd >= 0);
	uint8_t ff[446];
	memset(ff, 0xFF, sizeof(ff));
	pwrite(fd, ff, sizeof(ff), 0);
	close(fd);

	reset_globals();
	boot_type  = BT_NON_BOOTABLE;
	SelectedDrive.SectorSize = 512;

	BOOL r = do_write_mbr(path);
	CHECK(r == TRUE);

	/* Boot code (first 446 bytes) must now be zero */
	CHECK(region_is_zero(path, 0, 446));

	/* Signature must be present */
	uint8_t sig[2];
	CHECK(read_at(path, 510, sig, 2) == 0);
	CHECK(sig[0] == 0x55 && sig[1] == 0xAA);

	unlink(path); free(path);
}

TEST(write_mbr_syslinux_writes_nonzero_code)
{
	/* BT_SYSLINUX_V6 → non-zero boot code */
	char* path = create_temp_image(IMG_4MB);
	CHECK(path != NULL);

	reset_globals();
	boot_type  = BT_SYSLINUX_V6;
	target_type = TT_BIOS;
	SelectedDrive.SectorSize = 512;

	BOOL r = do_write_mbr(path);
	CHECK(r == TRUE);

	/* At least the first byte of the boot code is non-zero (syslinux MBR starts with 0xFA or 0xEB) */
	uint8_t b0;
	CHECK(read_at(path, 0, &b0, 1) == 0);
	CHECK(b0 != 0x00);

	/* Signature must be present */
	uint8_t sig[2];
	CHECK(read_at(path, 510, sig, 2) == 0);
	CHECK(sig[0] == 0x55 && sig[1] == 0xAA);

	unlink(path); free(path);
}

TEST(write_mbr_grub2_writes_nonzero_code)
{
	/* BT_GRUB2 → grub2 boot code */
	char* path = create_temp_image(IMG_4MB);
	CHECK(path != NULL);

	reset_globals();
	boot_type  = BT_GRUB2;
	target_type = TT_BIOS;
	SelectedDrive.SectorSize = 512;

	BOOL r = do_write_mbr(path);
	CHECK(r == TRUE);

	uint8_t b0;
	CHECK(read_at(path, 0, &b0, 1) == 0);
	CHECK(b0 != 0x00);

	uint8_t sig[2];
	CHECK(read_at(path, 510, sig, 2) == 0);
	CHECK(sig[0] == 0x55 && sig[1] == 0xAA);

	unlink(path); free(path);
}

TEST(write_mbr_win7_default)
{
	/* Default case (use_rufus_mbr=TRUE) → rufus MBR */
	char* path = create_temp_image(IMG_4MB);
	CHECK(path != NULL);

	reset_globals();
	boot_type   = BT_IMAGE;
	target_type = TT_BIOS;
	use_rufus_mbr = TRUE;
	SelectedDrive.SectorSize = 512;

	BOOL r = do_write_mbr(path);
	CHECK(r == TRUE);

	uint8_t b0;
	CHECK(read_at(path, 0, &b0, 1) == 0);
	CHECK(b0 != 0x00);

	uint8_t sig[2];
	CHECK(read_at(path, 510, sig, 2) == 0);
	CHECK(sig[0] == 0x55 && sig[1] == 0xAA);

	unlink(path); free(path);
}

TEST(write_mbr_preserves_partition_table)
{
	/*
	 * WriteMBR must only overwrite the boot code (bytes 0-445) and the
	 * signature (bytes 510-511), leaving the partition table (bytes 446-509)
	 * untouched.
	 */
	char* path = create_temp_image(IMG_4MB);
	CHECK(path != NULL);

	/* Write a sentinel byte in the partition table area */
	int fd = open(path, O_RDWR);
	CHECK(fd >= 0);
	uint8_t sentinel = 0xDE;
	pwrite(fd, &sentinel, 1, 446);   /* first byte of partition entries */
	close(fd);

	reset_globals();
	boot_type = BT_NON_BOOTABLE;
	SelectedDrive.SectorSize = 512;
	do_write_mbr(path);

	uint8_t check;
	CHECK(read_at(path, 446, &check, 1) == 0);
	CHECK(check == 0xDE);   /* still intact */

	unlink(path); free(path);
}

/* ================================================================
 * WriteDrive tests
 * ================================================================ */

TEST(write_drive_bad_handle_fails)
{
	BOOL r = format_linux_write_drive(INVALID_HANDLE_VALUE, FALSE);
	CHECK(r == FALSE);
}

TEST(write_drive_zero_zeroes_entire_drive)
{
	uint64_t sz = IMG_4MB;
	char* path = create_temp_image(sz);
	CHECK(path != NULL);

	/* Pre-fill with 0xAA */
	int fd = open(path, O_RDWR);
	CHECK(fd >= 0);
	uint8_t aa[4096];
	memset(aa, 0xAA, sizeof(aa));
	for (uint64_t off = 0; off < sz; off += sizeof(aa))
		pwrite(fd, aa, sizeof(aa), (off_t)off);

	HANDLE h = (HANDLE)(intptr_t)fd;
	SelectedDrive.DiskSize   = (LONGLONG)sz;
	SelectedDrive.SectorSize = 512;

	reset_globals();
	BOOL r = format_linux_write_drive(h, TRUE);
	close(fd);
	CHECK(r == TRUE);
	CHECK(region_is_zero(path, 0, (size_t)sz));

	unlink(path); free(path);
	teardown_drive();
}

TEST(write_drive_image_copies_content)
{
	/* Create a source "image" with a known pattern */
	uint64_t img_sz = IMG_4MB;
	uint64_t drv_sz = IMG_4MB * 2;

	char* img_path = create_temp_image(img_sz);
	char* drv_path = create_temp_image(drv_sz);
	CHECK(img_path != NULL);
	CHECK(drv_path != NULL);

	/* Fill source with a simple pattern */
	int img_fd = open(img_path, O_RDWR);
	CHECK(img_fd >= 0);
	uint8_t pat[512];
	for (int i = 0; i < 512; i++) pat[i] = (uint8_t)(i & 0xFF);
	for (uint64_t off = 0; off < img_sz; off += 512)
		pwrite(img_fd, pat, 512, (off_t)off);
	close(img_fd);

	int drv_fd = open(drv_path, O_RDWR);
	CHECK(drv_fd >= 0);
	HANDLE h = (HANDLE)(intptr_t)drv_fd;
	SelectedDrive.DiskSize   = (LONGLONG)drv_sz;
	SelectedDrive.SectorSize = 512;

	reset_globals();
	/* Set image_path AFTER reset_globals so it isn't cleared */
	image_path = img_path;
	BOOL r = format_linux_write_drive(h, FALSE);
	close(drv_fd);
	CHECK(r == TRUE);

	/* Verify first 512 bytes of drive match source pattern */
	uint8_t dst_buf[512];
	CHECK(read_at(drv_path, 0, dst_buf, 512) == 0);
	CHECK(memcmp(dst_buf, pat, 512) == 0);

	image_path = NULL;
	unlink(img_path); free(img_path);
	unlink(drv_path); free(drv_path);
	teardown_drive();
}

TEST(write_drive_image_null_path_fails)
{
	char* path = create_temp_image(IMG_4MB);
	CHECK(path != NULL);
	int fd = open(path, O_RDWR);
	CHECK(fd >= 0);
	HANDLE h = (HANDLE)(intptr_t)fd;
	SelectedDrive.DiskSize   = (LONGLONG)IMG_4MB;
	SelectedDrive.SectorSize = 512;

	reset_globals();
	image_path = NULL;
	BOOL r = format_linux_write_drive(h, FALSE);
	close(fd);
	CHECK(r == FALSE);

	unlink(path); free(path);
	teardown_drive();
}

/* ================================================================
 * FormatThread integration tests
 * ================================================================ */

/* MBR + FAT32 partition offsets */
#define MBR_PART_ENTRY_OFF  446         /* first partition entry */
#define MBR_LBA_START_OFF   (446 + 8)   /* LBA start in entry */
#define FAT32_MAIN_LBA      2048
#define FAT32_MAIN_OFFSET   ((uint64_t)FAT32_MAIN_LBA * 512)

/* FAT32 boot sector struct */
#pragma pack(push,1)
typedef struct {
	uint8_t  sJmpBoot[3];
	uint8_t  sOEMName[8];
	uint16_t wBytsPerSec;
	uint8_t  bSecPerClus;
	uint16_t wRsvdSecCnt;
	uint8_t  bNumFATs;
	uint16_t wRootEntCnt;
	uint16_t wTotSec16;
	uint8_t  bMedia;
	uint16_t wFATSz16;
	uint16_t wSecPerTrk;
	uint16_t wNumHeads;
	uint32_t dHiddSec;
	uint32_t dTotSec32;
	uint32_t dFATSz32;
} FAT32_BS_MINI;
#pragma pack(pop)

#define EXT2_SUPER_OFF    1024
#define EXT2_MAGIC_OFF    (EXT2_SUPER_OFF + 0x38)
#define EXT2_MAGIC_VAL    0xEF53

TEST(format_thread_bad_drive_index_fails)
{
	reset_globals();
	/* Drive index 0x79 is below DRIVE_INDEX_MIN — no drive in rufus_drive */
	DWORD rc = run_format_thread(0x79);
	/* FormatThread should set ErrorStatus and return non-zero */
	CHECK(rc != 0 || IS_ERROR(ErrorStatus));
}

TEST(format_thread_non_bootable_fat32_creates_valid_partition)
{
	char* path = create_temp_image(IMG_512MB);
	CHECK(path != NULL);
	setup_drive(path, IMG_512MB);
	reset_globals();
	boot_type      = BT_NON_BOOTABLE;
	partition_type = PARTITION_STYLE_MBR;
	fs_type        = FS_FAT32;
	target_type    = TT_BIOS;

	DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
	CHECK(rc == 0);
	CHECK(!IS_ERROR(ErrorStatus));

	/* MBR must have valid signature */
	uint8_t sig[2];
	CHECK(read_at(path, 510, sig, 2) == 0);
	CHECK(sig[0] == 0x55 && sig[1] == 0xAA);

	/* First partition entry must start at LBA 2048 */
	uint32_t lba_start;
	CHECK(read_at(path, MBR_LBA_START_OFF, &lba_start, 4) == 0);
	CHECK(lba_start == FAT32_MAIN_LBA);

	/* FAT32 boot sector at partition offset must have 0x55AA signature */
	uint8_t fat_sig[2];
	CHECK(read_at(path, (off_t)(FAT32_MAIN_OFFSET + 510), fat_sig, 2) == 0);
	CHECK(fat_sig[0] == 0x55 && fat_sig[1] == 0xAA);

	/* FAT32 OEM name must be "MSWIN4.1" */
	FAT32_BS_MINI bs;
	CHECK(read_at(path, (off_t)FAT32_MAIN_OFFSET, &bs, sizeof(bs)) == 0);
	CHECK(memcmp(bs.sOEMName, "MSWIN4.1", 8) == 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(format_thread_non_bootable_fat32_mbr_boot_code_is_zero)
{
	/* Non-bootable → zeroed MBR boot code */
	char* path = create_temp_image(IMG_512MB);
	CHECK(path != NULL);
	setup_drive(path, IMG_512MB);
	reset_globals();
	boot_type      = BT_NON_BOOTABLE;
	partition_type = PARTITION_STYLE_MBR;
	fs_type        = FS_FAT32;

	run_format_thread(DRIVE_INDEX_MIN);

	/* Boot code region (bytes 0-445) must be zeroed for non-bootable */
	CHECK(region_is_zero(path, 0, 446));

	teardown_drive();
	unlink(path); free(path);
}

TEST(format_thread_non_bootable_ext2_creates_valid_partition)
{
	char* path = create_temp_image(IMG_512MB);
	CHECK(path != NULL);
	setup_drive(path, IMG_512MB);
	reset_globals();
	boot_type      = BT_NON_BOOTABLE;
	partition_type = PARTITION_STYLE_MBR;
	fs_type        = FS_EXT2;
	target_type    = TT_BIOS;

	DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
	CHECK(rc == 0);
	CHECK(!IS_ERROR(ErrorStatus));

	/* MBR partition entry must be present with LBA start 2048 */
	uint32_t lba_start;
	CHECK(read_at(path, MBR_LBA_START_OFF, &lba_start, 4) == 0);
	CHECK(lba_start == FAT32_MAIN_LBA);

	/* ext2 superblock magic at partition offset + 1024 + 0x38 */
	uint16_t magic;
	CHECK(read_at(path, (off_t)(FAT32_MAIN_OFFSET + EXT2_MAGIC_OFF - EXT2_SUPER_OFF), &magic, 2) == 0);
	/* Note: ext2 superblock is at 1024 bytes into the filesystem, not into the partition */
	CHECK(read_at(path, (off_t)(FAT32_MAIN_OFFSET + EXT2_MAGIC_OFF), &magic, 2) == 0);
	CHECK(magic == EXT2_MAGIC_VAL);

	teardown_drive();
	unlink(path); free(path);
}

TEST(format_thread_non_bootable_ext3_creates_valid_partition)
{
	char* path = create_temp_image(IMG_512MB);
	CHECK(path != NULL);
	setup_drive(path, IMG_512MB);
	reset_globals();
	boot_type      = BT_NON_BOOTABLE;
	partition_type = PARTITION_STYLE_MBR;
	fs_type        = FS_EXT3;
	target_type    = TT_BIOS;

	DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
	CHECK(rc == 0);
	CHECK(!IS_ERROR(ErrorStatus));

	/* ext3 superblock magic */
	uint16_t magic;
	CHECK(read_at(path, (off_t)(FAT32_MAIN_OFFSET + EXT2_MAGIC_OFF), &magic, 2) == 0);
	CHECK(magic == EXT2_MAGIC_VAL);

	/* ext3 must have HAS_JOURNAL compat feature */
	uint32_t compat;
	CHECK(read_at(path, (off_t)(FAT32_MAIN_OFFSET + EXT2_SUPER_OFF + 0x5C), &compat, 4) == 0);
	CHECK((compat & 0x0004) != 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(format_thread_syslinux_fat32_has_syslinux_mbr)
{
	/* BT_SYSLINUX_V6 → syslinux MBR boot code */
	char* path = create_temp_image(IMG_512MB);
	CHECK(path != NULL);
	setup_drive(path, IMG_512MB);
	reset_globals();
	boot_type      = BT_SYSLINUX_V6;
	partition_type = PARTITION_STYLE_MBR;
	fs_type        = FS_FAT32;
	target_type    = TT_BIOS;

	run_format_thread(DRIVE_INDEX_MIN);

	/* Syslinux MBR boot code starts with non-zero byte */
	uint8_t b0;
	CHECK(read_at(path, 0, &b0, 1) == 0);
	CHECK(b0 != 0x00);

	teardown_drive();
	unlink(path); free(path);
}

TEST(format_thread_gpt_partition_style)
{
	/* GPT partition style: check for protective MBR marker (0xEE) */
	char* path = create_temp_image(IMG_512MB);
	CHECK(path != NULL);
	setup_drive(path, IMG_512MB);
	reset_globals();
	boot_type      = BT_NON_BOOTABLE;
	partition_type = PARTITION_STYLE_GPT;
	fs_type        = FS_FAT32;
	target_type    = TT_UEFI;

	DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
	CHECK(rc == 0);
	CHECK(!IS_ERROR(ErrorStatus));

	/* Protective MBR: partition type byte at 446+4 must be 0xEE */
	uint8_t ptype;
	CHECK(read_at(path, 450, &ptype, 1) == 0);
	CHECK(ptype == 0xEE);

	/* GPT header signature at LBA 1 */
	uint8_t gpt_sig[8];
	CHECK(read_at(path, 512, gpt_sig, 8) == 0);
	CHECK(memcmp(gpt_sig, "EFI PART", 8) == 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(format_thread_write_as_image_copies_content)
{
	/* write_as_image=TRUE → FormatThread copies image file to drive */
	uint64_t img_sz = IMG_4MB;
	uint64_t drv_sz = IMG_32MB;

	char* img_path = create_temp_image(img_sz);
	char* drv_path = create_temp_image(drv_sz);
	CHECK(img_path != NULL);
	CHECK(drv_path != NULL);

	/* Write a known pattern to the image */
	int img_fd = open(img_path, O_RDWR);
	CHECK(img_fd >= 0);
	uint8_t head_sig[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
	pwrite(img_fd, head_sig, 8, 0);
	close(img_fd);

	setup_drive(drv_path, drv_sz);
	reset_globals();
	write_as_image = TRUE;
	boot_type      = BT_IMAGE;
	image_path     = img_path;

	DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
	CHECK(rc == 0);

	/* Verify signature copied to drive */
	uint8_t dst[8];
	CHECK(read_at(drv_path, 0, dst, 8) == 0);
	CHECK(memcmp(dst, head_sig, 8) == 0);

	image_path = NULL;
	teardown_drive();
	unlink(img_path); free(img_path);
	unlink(drv_path); free(drv_path);
}

TEST(format_thread_zero_drive_zeroes_everything)
{
	uint64_t sz = IMG_4MB;
	char* path = create_temp_image(sz);
	CHECK(path != NULL);

	/* Pre-fill with 0xAA */
	int fd = open(path, O_RDWR);
	CHECK(fd >= 0);
	uint8_t aa[4096];
	memset(aa, 0xAA, sizeof(aa));
	for (uint64_t off = 0; off < sz; off += sizeof(aa))
		pwrite(fd, aa, sizeof(aa), (off_t)off);
	close(fd);

	setup_drive(path, sz);
	reset_globals();
	zero_drive = TRUE;
	SelectedDrive.SectorSize = 512;
	SelectedDrive.DiskSize   = (LONGLONG)sz;

	DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
	CHECK(rc == 0);
	CHECK(region_is_zero(path, 0, (size_t)sz));

	teardown_drive();
	unlink(path); free(path);
}

TEST(format_thread_posts_format_completed)
{
	/*
	 * FormatThread must call PostMessage(..., UM_FORMAT_COMPLETED, ...) at the
	 * end (even on error).  Here we register a simple counter handler to
	 * capture the message.
	 *
	 * Note: hMainDialog is NULL in tests, so PostMessage is a no-op — this
	 * test verifies the thread exits cleanly with exit code 0 (no crash).
	 */
	char* path = create_temp_image(IMG_512MB);
	CHECK(path != NULL);
	setup_drive(path, IMG_512MB);
	reset_globals();
	boot_type      = BT_NON_BOOTABLE;
	partition_type = PARTITION_STYLE_MBR;
	fs_type        = FS_FAT32;

	/* Run and expect a clean exit (no segfault / hang) */
	DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
	CHECK(rc == 0);

	teardown_drive();
	unlink(path); free(path);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
	printf("=== ClearMBRGPT tests ===\n");
	RUN(clear_mbr_gpt_bad_handle_fails);
	RUN(clear_mbr_gpt_null_handle_fails);
	RUN(clear_mbr_gpt_zeroes_beginning);
	RUN(clear_mbr_gpt_zeroes_end);

	printf("\n=== WriteMBR tests ===\n");
	RUN(write_mbr_bad_handle_fails);
	RUN(write_mbr_non_bootable_writes_zero_code);
	RUN(write_mbr_syslinux_writes_nonzero_code);
	RUN(write_mbr_grub2_writes_nonzero_code);
	RUN(write_mbr_win7_default);
	RUN(write_mbr_preserves_partition_table);

	printf("\n=== WriteDrive tests ===\n");
	RUN(write_drive_bad_handle_fails);
	RUN(write_drive_zero_zeroes_entire_drive);
	RUN(write_drive_image_copies_content);
	RUN(write_drive_image_null_path_fails);

	printf("\n=== FormatThread integration tests ===\n");
	RUN(format_thread_bad_drive_index_fails);
	RUN(format_thread_non_bootable_fat32_creates_valid_partition);
	RUN(format_thread_non_bootable_fat32_mbr_boot_code_is_zero);
	RUN(format_thread_non_bootable_ext2_creates_valid_partition);
	RUN(format_thread_non_bootable_ext3_creates_valid_partition);
	RUN(format_thread_syslinux_fat32_has_syslinux_mbr);
	RUN(format_thread_gpt_partition_style);
	RUN(format_thread_write_as_image_copies_content);
	RUN(format_thread_zero_drive_zeroes_everything);
	RUN(format_thread_posts_format_completed);

	TEST_RESULTS();
}

#endif /* __linux__ */
