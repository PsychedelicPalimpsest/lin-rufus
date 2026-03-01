/*
 * test_format_linux.c — tests for Linux FAT32 and ext2/ext3 formatting
 *
 * Strategy: create temporary disk image files, format them via
 * FormatLargeFAT32() and FormatExtFs(), then parse the on-disk
 * structures to verify correctness.  No root / block device needed.
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

/* ---- compat layer ---- */
#include "windows.h"
#include "commctrl.h"
/* ---- rufus headers ---- */
#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "resource.h"

/* ================================================================
 * Globals required by rufus.h / drive.h / format.h externs
 * ================================================================ */

RUFUS_DRIVE rufus_drive[MAX_DRIVES];
/* defined in drive.c */
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
char *sb_revoked_txt      = NULL;

float fScale              = 1.0f;
int dialog_showing        = 0;
int force_update          = 0;
int selection_default     = 0;
int persistence_unit_selection = -1;
uint64_t persistence_size = 0;
int64_t iso_blocking_status = -1;
uint32_t pe256ssp_size    = 0;
uint8_t *pe256ssp         = NULL;
uint16_t rufus_version[3] = {0,0,0};
uint16_t embedded_sl_version[2] = {0,0};
uint32_t dur_mins = 0, dur_secs = 0;
sbat_entry_t *sbat_entries = NULL;
thumbprint_list_t *sb_active_certs = NULL, *sb_revoked_certs = NULL;
RUFUS_UPDATE update = { {0,0,0}, {0,0}, NULL, NULL };
HINSTANCE hMainInstance = NULL;
HWND hMultiToolbar = NULL, hSaveToolbar = NULL, hHashToolbar = NULL;
HWND hAdvancedDeviceToolbar = NULL, hAdvancedFormatToolbar = NULL;
HWND hUpdatesDlg = NULL;
HWND hPartitionScheme = NULL, hTargetSystem = NULL, hFileSystem = NULL;
HWND hClusterSize = NULL, hLabel = NULL, hBootType = NULL, hNBPasses = NULL;
HWND hImageOption = NULL, hLogDialog = NULL;
HWND hCapacity = NULL;
WORD selected_langid = 0;
BOOL allow_dual_uefi_bios = FALSE, usb_debug = FALSE;
BOOL detect_fakes = FALSE;
BOOL use_own_c32[NB_OLD_C32];
BOOL has_uefi_csm = FALSE, its_a_me_mario = FALSE;
BOOL enable_vmdk = FALSE;
BOOL use_fake_units = FALSE, preserve_timestamps = FALSE;
BOOL app_changed_size = FALSE;
BOOL list_non_usb_removable_drives = FALSE;
BOOL no_confirmation_on_cancel = FALSE;
BOOL advanced_mode_device = FALSE, advanced_mode_format = FALSE;
unsigned long syslinux_ldlinux_len[2] = {0, 0};

const char* FileSystemLabel[FS_MAX] = {
	"FAT", "FAT32", "NTFS", "UDF", "exFAT", "ReFS", "ext2", "ext3", "ext4"
};
const int nb_steps[FS_MAX] = { 5, 5, 5, 5, 5, 5, 5, 5, 5 };
const char *md5sum_name[2] = { "md5sum.txt", "md5sum.txt" };

uint8_t *grub2_buf = NULL;
long grub2_len = 0;
uint8_t *sec_buf = NULL;

/* ================================================================
 * Stub functions required by format / drive code
 * ================================================================ */

void uprintf(const char* fmt, ...) {
	(void)fmt;
	/* uncomment for debug: va_list a; va_start(a,fmt); vfprintf(stderr,fmt,a); va_end(a); fputc('\n',stderr); */
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

/* ================================================================
 * Test framework
 * ================================================================ */

#include "framework.h"

/* ================================================================
 * Test helpers
 * ================================================================ */

#define TEST_IMG_SIZE_MB    512
#define TEST_IMG_SIZE       ((uint64_t)TEST_IMG_SIZE_MB * 1024 * 1024)
#define TEST_IMG_SIZE_SMALL ((uint64_t)30 * 1024 * 1024)  /* < 32 MB → too small */
#define EXT_IMG_SIZE_MB     64
#define EXT_IMG_SIZE        ((uint64_t)EXT_IMG_SIZE_MB * 1024 * 1024)

/* Create a sparse temp file of the given size. Returns a malloc'd path or
 * NULL on error. Caller must free() the path and unlink() the file. */
static char* create_temp_image(uint64_t size)
{
	char* path = strdup("/tmp/rufus_test_XXXXXX");
	if (!path) return NULL;

	int fd = mkstemp(path);
	if (fd < 0) { free(path); return NULL; }

	/* ftruncate creates a sparse file — no need to write zeros */
	if (ftruncate(fd, (off_t)size) != 0) {
		close(fd); unlink(path); free(path); return NULL;
	}
	close(fd);
	return path;
}

/* Populate rufus_drive[0] and rufus_drive[1] (sentinel) for test use. */
static void setup_drive(const char* path, uint64_t size)
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
	/* id is a pointer we don't own; just clear the array */
	memset(rufus_drive, 0, sizeof(rufus_drive));
}

/* ---- FAT32 boot sector layout (matches format_fat32.c) ---- */
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
	uint16_t wExtFlags;
	uint16_t wFSVer;
	uint32_t dRootClus;
	uint16_t wFSInfo;
	uint16_t wBkBootSec;
	uint8_t  Reserved[12];
	uint8_t  bDrvNum;
	uint8_t  Reserved1;
	uint8_t  bBootSig;
	uint32_t dBS_VolID;
	uint8_t  sVolLab[11];
	uint8_t  sBS_FilSysType[8];
} FAT32_BS;

typedef struct {
	uint32_t dLeadSig;
	uint8_t  sReserved1[480];
	uint32_t dStrucSig;
	uint32_t dFree_Count;
	uint32_t dNxt_Free;
	uint8_t  sReserved2[12];
	uint32_t dTrailSig;
} FAT32_FSINFO;
#pragma pack(pop)

/* Read bytes from a file at a given offset */
static int read_at(const char* path, off_t off, void* buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	ssize_t r = pread(fd, buf, len, off);
	close(fd);
	return (r == (ssize_t)len) ? 0 : -1;
}

/* ================================================================
 * FAT32 tests
 * ================================================================ */

TEST(fat32_format_returns_true)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 4096, "FAT32", "RUFUSTEST", FP_NO_PROGRESS | FP_NO_BOOT);
	CHECK(r == TRUE);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_bootsector_jump_and_oem)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 4096, "FAT32", "RUFUSTEST", FP_NO_PROGRESS | FP_NO_BOOT);
	CHECK(r == TRUE);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);

	/* JMP SHORT + NOP */
	CHECK(bs.sJmpBoot[0] == 0xEB);
	CHECK(bs.sJmpBoot[2] == 0x90);

	/* OEM name */
	CHECK(memcmp(bs.sOEMName, "MSWIN4.1", 8) == 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_bootsector_magic_55aa)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 4096, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	uint8_t sig[2];
	CHECK(read_at(path, 510, sig, 2) == 0);
	CHECK(sig[0] == 0x55);
	CHECK(sig[1] == 0xAA);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_bpb_bytes_per_sector_512)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);

	/* Must be 512 for a file-based image */
	CHECK(bs.wBytsPerSec == 512);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_bpb_num_fats_is_2)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);
	CHECK(bs.bNumFATs == 2);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_bpb_filesystem_type_label)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);
	CHECK(memcmp(bs.sBS_FilSysType, "FAT32   ", 8) == 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_bpb_boot_sig)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);
	CHECK(bs.bBootSig == 0x29);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_volume_id_nonzero)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);
	CHECK(bs.dBS_VolID != 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_root_cluster_is_2)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);
	CHECK(bs.dRootClus == 2);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_fsinfo_signatures)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);

	/* FSInfo is at sector wFSInfo */
	off_t fsinfo_off = (off_t)bs.wFSInfo * bs.wBytsPerSec;
	FAT32_FSINFO fi;
	CHECK(read_at(path, fsinfo_off, &fi, sizeof(fi)) == 0);

	CHECK(fi.dLeadSig  == 0x41615252u);
	CHECK(fi.dStrucSig == 0x61417272u);
	CHECK(fi.dTrailSig == 0xAA550000u);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_first_fat_sector_entries)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);

	/* First FAT starts at sector wRsvdSecCnt */
	off_t fat_off = (off_t)bs.wRsvdSecCnt * bs.wBytsPerSec;
	uint32_t fat[3];
	CHECK(read_at(path, fat_off, fat, sizeof(fat)) == 0);

	CHECK(fat[0] == 0x0FFFFFF8u);  /* media id */
	CHECK(fat[1] == 0x0FFFFFFFu);  /* EOC */
	CHECK(fat[2] == 0x0FFFFFFFu);  /* root dir chain end */

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_backup_bootsector_written)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);

	/* Backup boot sector is at sector wBkBootSec (typically 6) */
	off_t bkup_off = (off_t)bs.wBkBootSec * bs.wBytsPerSec;
	FAT32_BS bkup;
	CHECK(read_at(path, bkup_off, &bkup, sizeof(bkup)) == 0);

	CHECK(bkup.sJmpBoot[0] == 0xEB);
	CHECK(memcmp(bkup.sOEMName, "MSWIN4.1", 8) == 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_reject_wrong_fsname)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "NTFS", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);
	CHECK(r == FALSE);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_reject_too_small_image)
{
	/* 30 MB < 32 MB minimum (65536 sectors * 512 bytes) */
	char* path = create_temp_image(TEST_IMG_SIZE_SMALL);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE_SMALL);

	ErrorStatus = 0;
	BOOL r = FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);
	CHECK(r == FALSE);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_total_sectors_matches_image_size)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);

	uint64_t expected_sectors = TEST_IMG_SIZE / bs.wBytsPerSec;
	/* dTotSec32 should equal total sectors from image size */
	CHECK(bs.dTotSec32 == (uint32_t)expected_sectors);

	teardown_drive();
	unlink(path); free(path);
}

TEST(fat32_two_fats_correctly_placed)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	FormatLargeFAT32(DRIVE_INDEX_MIN, 0, 0, "FAT32", "TEST", FP_NO_PROGRESS | FP_NO_BOOT);

	FAT32_BS bs;
	CHECK(read_at(path, 0, &bs, sizeof(bs)) == 0);

	/* Both FATs should start with the same first 3 entries */
	off_t fat1_off = (off_t)bs.wRsvdSecCnt * bs.wBytsPerSec;
	off_t fat2_off = fat1_off + (off_t)bs.dFATSz32 * bs.wBytsPerSec;

	uint32_t fat1[3], fat2[3];
	CHECK(read_at(path, fat1_off, fat1, sizeof(fat1)) == 0);
	CHECK(read_at(path, fat2_off, fat2, sizeof(fat2)) == 0);

	CHECK(fat1[0] == fat2[0]);
	CHECK(fat1[1] == fat2[1]);
	CHECK(fat1[2] == fat2[2]);

	teardown_drive();
	unlink(path); free(path);
}

/* ================================================================
 * ext2 / ext3 tests
 * ================================================================ */

#include "ext2fs/ext2fs.h"

/* ext2 superblock magic is at byte offset 0x38 within the superblock,
 * and the superblock starts at byte 1024 in the filesystem. */
#define EXT2_SUPER_OFFSET   1024
#define EXT2_MAGIC_OFFSET   (EXT2_SUPER_OFFSET + 0x38)
#define EXT2_MAGIC_VALUE    0xEF53

/* Feature flags in superblock (at specific offsets) */
#define EXT2_SUPER_COMPAT_OFFSET    (EXT2_SUPER_OFFSET + 0x5C)  /* s_feature_compat */
#define EXT2_SUPER_INCOMPAT_OFFSET  (EXT2_SUPER_OFFSET + 0x60)  /* s_feature_incompat */
#define EXT2_FEATURE_COMPAT_HAS_JOURNAL 0x0004

/* Volume label is at offset 0x78 from start of superblock, 16 bytes */
#define EXT2_LABEL_OFFSET   (EXT2_SUPER_OFFSET + 0x78)
#define EXT2_LABEL_LEN      16

TEST(ext2_format_returns_true)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatExtFs(DRIVE_INDEX_MIN, 0, 0, "ext2", "EXT2TEST", FP_NO_PROGRESS);
	CHECK(r == TRUE);

	teardown_drive();
	unlink(path); free(path);
}

TEST(ext2_superblock_magic)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatExtFs(DRIVE_INDEX_MIN, 0, 0, "ext2", "EXT2TEST", FP_NO_PROGRESS);
	CHECK(r == TRUE);

	uint16_t magic;
	CHECK(read_at(path, EXT2_MAGIC_OFFSET, &magic, 2) == 0);
	CHECK(magic == EXT2_MAGIC_VALUE);

	teardown_drive();
	unlink(path); free(path);
}

TEST(ext2_no_journal_feature)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	FormatExtFs(DRIVE_INDEX_MIN, 0, 0, "ext2", "EXT2TEST", FP_NO_PROGRESS);

	uint32_t compat_flags;
	CHECK(read_at(path, EXT2_SUPER_COMPAT_OFFSET, &compat_flags, 4) == 0);
	/* ext2 must NOT have HAS_JOURNAL */
	CHECK((compat_flags & EXT2_FEATURE_COMPAT_HAS_JOURNAL) == 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(ext3_format_returns_true)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatExtFs(DRIVE_INDEX_MIN, 0, 0, "ext3", "EXT3TEST", FP_NO_PROGRESS);
	CHECK(r == TRUE);

	teardown_drive();
	unlink(path); free(path);
}

TEST(ext3_has_journal_feature)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	FormatExtFs(DRIVE_INDEX_MIN, 0, 0, "ext3", "EXT3TEST", FP_NO_PROGRESS);

	uint32_t compat_flags;
	CHECK(read_at(path, EXT2_SUPER_COMPAT_OFFSET, &compat_flags, 4) == 0);
	/* ext3 MUST have HAS_JOURNAL */
	CHECK((compat_flags & EXT2_FEATURE_COMPAT_HAS_JOURNAL) != 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(ext2_superblock_magic_after_ext3_format)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	FormatExtFs(DRIVE_INDEX_MIN, 0, 0, "ext3", "EXT3TEST", FP_NO_PROGRESS);

	uint16_t magic;
	CHECK(read_at(path, EXT2_MAGIC_OFFSET, &magic, 2) == 0);
	CHECK(magic == EXT2_MAGIC_VALUE);

	teardown_drive();
	unlink(path); free(path);
}

TEST(ext2_label_set_correctly)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	FormatExtFs(DRIVE_INDEX_MIN, 0, 0, "ext2", "MYLABEL", FP_NO_PROGRESS);

	char label[EXT2_LABEL_LEN + 1] = {0};
	CHECK(read_at(path, EXT2_LABEL_OFFSET, label, EXT2_LABEL_LEN) == 0);
	CHECK(strcmp(label, "MYLABEL") == 0);

	teardown_drive();
	unlink(path); free(path);
}

TEST(ext2_reject_invalid_fsname)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatExtFs(DRIVE_INDEX_MIN, 0, 0, "ntfs", "TEST", FP_NO_PROGRESS);
	CHECK(r == FALSE);

	teardown_drive();
	unlink(path); free(path);
}

TEST(ext2_get_label_after_format)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatExtFs(DRIVE_INDEX_MIN, 0, 0, "ext2", "GETLABEL", FP_NO_PROGRESS);
	CHECK(r == TRUE);

	const char* lbl = GetExtFsLabel(DRIVE_INDEX_MIN, 0);
	CHECK(lbl != NULL);
	CHECK(strcmp(lbl, "GETLABEL") == 0);

	teardown_drive();
	unlink(path); free(path);
}

/* ================================================================
 * FormatPartition tests
 * ================================================================ */

#include "ms-sys/inc/fat32.h"
#include "ms-sys/inc/br.h"
#include "ms-sys/inc/partition_info.h"
#include "ms-sys/inc/file.h"

/* FormatPartition dispatches to FormatLargeFAT32 for FS_FAT32 */
TEST(format_partition_fat32_succeeds)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 4096, FS_FAT32, "FPTEST", FP_NO_PROGRESS);
	CHECK(r == TRUE);
	CHECK(ErrorStatus == 0);

	/* Boot sector must have 0x55AA signature at offset 510 */
	uint8_t sig[2];
	CHECK(read_at(path, 510, sig, 2) == 0);
	CHECK(sig[0] == 0x55 && sig[1] == 0xAA);

	teardown_drive();
	unlink(path); free(path);
}

/* FormatPartition dispatches to FormatExtFs for FS_EXT2 */
TEST(format_partition_ext2_succeeds)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_EXT2, "FPEXT2", FP_NO_PROGRESS);
	CHECK(r == TRUE);
	CHECK(ErrorStatus == 0);

	uint16_t magic;
	CHECK(read_at(path, EXT2_MAGIC_OFFSET, &magic, 2) == 0);
	CHECK(magic == EXT2_MAGIC_VALUE);

	teardown_drive();
	unlink(path); free(path);
}

/* FormatPartition dispatches to FormatExtFs for FS_EXT3 */
TEST(format_partition_ext3_succeeds)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_EXT3, "FPEXT3", FP_NO_PROGRESS);
	CHECK(r == TRUE);
	CHECK(ErrorStatus == 0);

	/* ext3 must have the journal compat feature */
	uint32_t compat_flags;
	CHECK(read_at(path, EXT2_SUPER_COMPAT_OFFSET, &compat_flags, 4) == 0);
	CHECK((compat_flags & EXT2_FEATURE_COMPAT_HAS_JOURNAL) != 0);

	teardown_drive();
	unlink(path); free(path);
}

/* FSType >= FS_MAX → invalid parameter → FALSE */
TEST(format_partition_bad_fs_type_fails)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_MAX, "TEST", 0);
	CHECK(r == FALSE);

	teardown_drive();
	unlink(path); free(path);
}

/* DriveIndex < DRIVE_INDEX_MIN → invalid parameter → FALSE */
TEST(format_partition_bad_drive_index_fails)
{
	BOOL r = FormatPartition(0x79, 0, 0, FS_FAT32, "TEST", 0);
	CHECK(r == FALSE);
}

/* UnitAllocationSize not a power of 2 → invalid parameter → FALSE */
TEST(format_partition_bad_unit_alloc_fails)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);

	BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 3, FS_FAT32, "TEST", 0);
	CHECK(r == FALSE);

	teardown_drive();
	unlink(path); free(path);
}

/* ================================================================
 * WritePBR tests
 * ================================================================ */

/* After FAT32 format, WritePBR should succeed and leave 0x55AA intact */
TEST(write_pbr_fat32_returns_true)
{
	char* path = create_temp_image(TEST_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, TEST_IMG_SIZE);
	SelectedDrive.SectorSize = 512;

	ErrorStatus = 0;
	BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 4096, FS_FAT32, "PBRTEST", FP_NO_PROGRESS);
	CHECK(r == TRUE);

	/* Open the image to get a writable handle for WritePBR */
	int fd = open(path, O_RDWR);
	CHECK(fd >= 0);
	HANDLE h = (HANDLE)(intptr_t)fd;
	r = WritePBR(h);
	close(fd);
	CHECK(r == TRUE);

	/* Boot sector signature must still be intact */
	uint8_t sig[2];
	CHECK(read_at(path, 510, sig, 2) == 0);
	CHECK(sig[0] == 0x55 && sig[1] == 0xAA);

	teardown_drive();
	unlink(path); free(path);
}

/* For ext2/ext3, WritePBR is a no-op that returns TRUE */
TEST(write_pbr_ext_no_op)
{
	char* path = create_temp_image(EXT_IMG_SIZE);
	CHECK(path != NULL);
	setup_drive(path, EXT_IMG_SIZE);

	ErrorStatus = 0;
	BOOL r = FormatPartition(DRIVE_INDEX_MIN, 0, 0, FS_EXT2, "EXTPBR", FP_NO_PROGRESS);
	CHECK(r == TRUE);

	int fd = open(path, O_RDWR);
	CHECK(fd >= 0);
	HANDLE h = (HANDLE)(intptr_t)fd;
	r = WritePBR(h);
	close(fd);
	CHECK(r == TRUE);

	teardown_drive();
	unlink(path); free(path);
}

/* WritePBR with INVALID_HANDLE_VALUE must fail */
TEST(write_pbr_bad_handle_fails)
{
	BOOL r = WritePBR(INVALID_HANDLE_VALUE);
	CHECK(r == FALSE);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
	printf("=== format_fat32 tests ===\n");
	RUN(fat32_format_returns_true);
	RUN(fat32_bootsector_jump_and_oem);
	RUN(fat32_bootsector_magic_55aa);
	RUN(fat32_bpb_bytes_per_sector_512);
	RUN(fat32_bpb_num_fats_is_2);
	RUN(fat32_bpb_filesystem_type_label);
	RUN(fat32_bpb_boot_sig);
	RUN(fat32_volume_id_nonzero);
	RUN(fat32_root_cluster_is_2);
	RUN(fat32_fsinfo_signatures);
	RUN(fat32_first_fat_sector_entries);
	RUN(fat32_backup_bootsector_written);
	RUN(fat32_reject_wrong_fsname);
	RUN(fat32_reject_too_small_image);
	RUN(fat32_total_sectors_matches_image_size);
	RUN(fat32_two_fats_correctly_placed);

	printf("\n=== format_ext tests ===\n");
	RUN(ext2_format_returns_true);
	RUN(ext2_superblock_magic);
	RUN(ext2_no_journal_feature);
	RUN(ext3_format_returns_true);
	RUN(ext3_has_journal_feature);
	RUN(ext2_superblock_magic_after_ext3_format);
	RUN(ext2_label_set_correctly);
	RUN(ext2_reject_invalid_fsname);
	RUN(ext2_get_label_after_format);

	printf("\n=== FormatPartition tests ===\n");
	RUN(format_partition_fat32_succeeds);
	RUN(format_partition_ext2_succeeds);
	RUN(format_partition_ext3_succeeds);
	RUN(format_partition_bad_fs_type_fails);
	RUN(format_partition_bad_drive_index_fails);
	RUN(format_partition_bad_unit_alloc_fails);

	printf("\n=== WritePBR tests ===\n");
	RUN(write_pbr_fat32_returns_true);
	RUN(write_pbr_ext_no_op);
	RUN(write_pbr_bad_handle_fails);

	TEST_RESULTS();
}

#endif /* __linux__ */
