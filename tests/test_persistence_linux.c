/*
 * test_persistence_linux.c — Tests for casper/persistence partition support
 *
 * Tests cover:
 *   • HAS_PERSISTENCE macro logic
 *   • CreatePartition with XP_PERSISTENCE (MBR + GPT)
 *   • FormatThread persistence partition creation and formatting
 *   • casper-rw label (uses_casper=TRUE) and persistence label (uses_casper=FALSE)
 *   • No extra partition when persistence_size == 0
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

/* ---- compat + rufus headers ---- */
#include "windows.h"
#include "commctrl.h"
#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "format_linux.h"
#include "resource.h"
#include "../res/grub/grub_version.h"

/* ================================================================
 * Required globals — mirror test_format_thread_linux.c exactly
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
 * Stub functions — must match test_format_thread_linux.c
 * ================================================================ */

void uprintf(const char* fmt, ...) { (void)fmt; }
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

BOOL ExtractISO(const char *src, const char *dst, BOOL scan_only) {
    (void)src; (void)dst; (void)scan_only;
    return TRUE;
}

/* Stubs provided by format_thread_linux_glue equivalents */
char *GuidToString(const GUID *guid, BOOL bDecorated)
{ (void)guid; (void)bDecorated; return NULL; }
GUID *StringToGuid(const char *str) { (void)str; return NULL; }
BOOL CompareGUID(const GUID *g1, const GUID *g2) {
    if (!g1 || !g2) return FALSE;
    return (__builtin_memcmp(g1, g2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}
windows_version_t WindowsVersion = { 0 };
char *get_token_data_file_indexed(const char *token, const char *filename, const int index)
{ (void)token; (void)filename; (void)index; return NULL; }
DWORD RunCommandWithProgress(const char *cmd, const char *dir,
                              BOOL log, int msg, const char *pattern)
{ (void)cmd; (void)dir; (void)log; (void)msg; (void)pattern; return 1; }

int install_syslinux_call_count = 0;
BOOL InstallSyslinux(DWORD drive_index, char drive_letter, int file_system)
{
    (void)drive_index; (void)drive_letter; (void)file_system;
    install_syslinux_call_count++;
    return FALSE;
}

DWORD _win_last_error   = 0;
BOOL enable_bad_blocks = FALSE;
BOOL enable_verify_write = FALSE;
int  nb_passes_sel     = 0;
int  bad_blocks_call_count = 0;

/* WUE stubs — format.c calls these after ISO extraction */
char *unattend_xml_path  = NULL;
int   unattend_xml_flags = 0;

void wue_set_mount_path(const char *path) { (void)path; }

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{
    (void)drive_letter; (void)flags; return TRUE;
}

#include "../src/windows/badblocks.h"
BOOL BadBlocks(HANDLE hPhysicalDrive, ULONGLONG disk_size, int nb_passes,
               int flash_type, badblocks_report *report, FILE *fd)
{
    (void)hPhysicalDrive; (void)disk_size; (void)nb_passes;
    (void)flash_type; (void)fd;
    bad_blocks_call_count++;
    if (report) {
        report->bb_count             = 0;
        report->num_read_errors      = 0;
        report->num_write_errors     = 0;
        report->num_corruption_errors = 0;
    }
    return TRUE;
}

int NotificationEx(int type, const char *dont_display_setting,
                   const notification_info *more_info, const char *title,
                   const char *format, ...)
{
    (void)type; (void)dont_display_setting; (void)more_info;
    (void)title; (void)format;
    return IDOK;
}

/* ================================================================
 * Test framework
 * ================================================================ */

#include "framework.h"

/* ================================================================
 * Helpers
 * ================================================================ */

#define IMG_1GB    ((uint64_t)1024 * 1024 * 1024)
#define IMG_512MB  ((uint64_t)512  * 1024 * 1024)
#define IMG_256MB  ((uint64_t)256  * 1024 * 1024)

static char *create_temp_image(uint64_t size)
{
    char *path = strdup("/tmp/rufus_pers_XXXXXX");
    if (!path) return NULL;
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
    memset(&SelectedDrive, 0, sizeof(SelectedDrive));
    memset(partition_index, 0, sizeof(partition_index));
}

static void reset_globals(void)
{
    boot_type        = BT_NON_BOOTABLE;
    partition_type   = PARTITION_STYLE_MBR;
    fs_type          = FS_FAT32;
    target_type      = TT_BIOS;
    write_as_image   = FALSE;
    write_as_esp     = FALSE;
    zero_drive       = FALSE;
    image_path       = NULL;
    ErrorStatus      = 0;
    LastWriteError   = 0;
    img_report       = (RUFUS_IMG_REPORT){ 0 };
    persistence_size = 0;
    use_rufus_mbr    = TRUE;
    install_syslinux_call_count = 0;
    bad_blocks_call_count       = 0;
}

static int read_at(const char *path, off_t off, void *buf, size_t len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = pread(fd, buf, len, off);
    close(fd);
    return (r == (ssize_t)len) ? 0 : -1;
}

static uint32_t read_u32(const char *path, off_t off)
{
    uint32_t v = 0;
    read_at(path, off, &v, 4);
    return v;
}

static uint64_t read_u64(const char *path, off_t off)
{
    uint64_t v = 0;
    read_at(path, off, &v, 8);
    return v;
}

static DWORD run_format_thread(DWORD DriveIndex)
{
    HANDLE t = CreateThread(NULL, 0, FormatThread,
                            (void *)(uintptr_t)DriveIndex, 0, NULL);
    if (t == NULL) return (DWORD)-1;
    WaitForSingleObject(t, 120000); /* up to 120 s */
    DWORD code = 1;
    GetExitCodeThread(t, &code);
    CloseHandle(t);
    return code;
}

/* MBR partition entry offsets */
#define MBR_ENTRY0_OFF   446
#define MBR_ENTRY1_OFF   462
#define MBR_LBA_START(e) ((e) + 8)
#define MBR_LBA_COUNT(e) ((e) + 12)
#define MAIN_LBA_START   2048

/* GPT partition entries start at byte 1024, each entry 128 bytes */
#define GPT_ENTRIES_OFF  1024
#define GPT_ENTRY_SIZE   128
#define GPT_FIRST_LBA(n) (GPT_ENTRIES_OFF + (n) * GPT_ENTRY_SIZE + 32)
#define GPT_LAST_LBA(n)  (GPT_ENTRIES_OFF + (n) * GPT_ENTRY_SIZE + 40)

/* ext2 superblock */
#define EXT2_SUPER_OFF    1024
#define EXT2_MAGIC_OFF    (EXT2_SUPER_OFF + 0x38)
#define EXT2_MAGIC_VAL    0xEF53

/* MBR main partition base offset */
#define FAT32_MAIN_OFFSET   ((uint64_t)MAIN_LBA_START * 512)

/* ================================================================
 * Tests: HAS_PERSISTENCE macro
 * ================================================================ */

TEST(has_persistence_false_when_no_bootloader)
{
    RUFUS_IMG_REPORT r = { 0 };
    CHECK(!HAS_PERSISTENCE(r));
}

TEST(has_persistence_true_for_grub2)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_grub2 = 1;
    CHECK(HAS_PERSISTENCE(r));
}

TEST(has_persistence_true_for_grub4dos)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_grub4dos = TRUE;
    CHECK(HAS_PERSISTENCE(r));
}

TEST(has_persistence_true_for_syslinux)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.sl_version = 0x0600;
    CHECK(HAS_PERSISTENCE(r));
}

TEST(has_persistence_false_for_windows_image)
{
    /* Windows images: has_bootmgr=TRUE means HAS_WINDOWS, so no persistence */
    RUFUS_IMG_REPORT r = { 0 };
    r.has_grub2   = 1;
    r.has_bootmgr = TRUE;
    CHECK(!HAS_PERSISTENCE(r));
}

TEST(has_persistence_false_for_reactos)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_grub2 = 1;
    r.reactos_path[0] = '/'; /* non-empty triggers HAS_REACTOS */
    CHECK(!HAS_PERSISTENCE(r));
}

TEST(has_persistence_false_for_kolibrios)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_grub2     = 1;
    r.has_kolibrios = TRUE;
    CHECK(!HAS_PERSISTENCE(r));
}

TEST(has_persistence_grub_and_syslinux_together)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.has_grub4dos = TRUE;
    r.sl_version   = 0x0400;
    CHECK(HAS_PERSISTENCE(r));
}

/* ================================================================
 * Tests: CreatePartition with XP_PERSISTENCE (MBR)
 * ================================================================ */

TEST(create_partition_mbr_no_persistence_one_partition)
{
    /*
     * Without XP_PERSISTENCE, entry 1 must be completely zeroed.
     */
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;

    SelectedDrive.DiskSize   = (LONGLONG)IMG_512MB;
    SelectedDrive.SectorSize = 512;
    persistence_size = 0;

    BOOL r = CreatePartition(h, PARTITION_STYLE_MBR, FS_FAT32, TRUE, 0);
    close(fd);
    CHECK(r == TRUE);

    /* Entry 0: LBA start == 2048 */
    uint32_t lba0 = read_u32(path, MBR_LBA_START(MBR_ENTRY0_OFF));
    CHECK(lba0 == MAIN_LBA_START);

    /* Entry 1: all zeros */
    uint8_t entry1[16] = { 0 };
    uint8_t zeroes[16] = { 0 };
    CHECK(read_at(path, MBR_ENTRY1_OFF, entry1, 16) == 0);
    CHECK(memcmp(entry1, zeroes, 16) == 0);

    /* MBR signature */
    uint8_t sig[2];
    CHECK(read_at(path, 510, sig, 2) == 0);
    CHECK(sig[0] == 0x55 && sig[1] == 0xAA);

    unlink(path); free(path);
    memset(&SelectedDrive, 0, sizeof(SelectedDrive));
}

TEST(create_partition_mbr_with_persistence_has_two_entries)
{
    /*
     * With XP_PERSISTENCE and persistence_size = 256 MB, CreatePartition
     * must write two non-empty MBR entries.
     */
    const uint64_t pers = 256ULL * 1024 * 1024;
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;

    SelectedDrive.DiskSize   = (LONGLONG)IMG_512MB;
    SelectedDrive.SectorSize = 512;
    persistence_size = pers;

    BOOL r = CreatePartition(h, PARTITION_STYLE_MBR, FS_FAT32, TRUE,
                             XP_PERSISTENCE);
    close(fd);
    CHECK(r == TRUE);

    /* Entry 0 present */
    uint32_t lba0_start = read_u32(path, MBR_LBA_START(MBR_ENTRY0_OFF));
    CHECK(lba0_start == MAIN_LBA_START);

    /* Entry 1 present and follows entry 0 */
    uint32_t lba1_start = read_u32(path, MBR_LBA_START(MBR_ENTRY1_OFF));
    CHECK(lba1_start > MAIN_LBA_START);

    /* Entry 1 size matches persistence_size */
    uint32_t lba1_count = read_u32(path, MBR_LBA_COUNT(MBR_ENTRY1_OFF));
    CHECK(lba1_count == (uint32_t)(pers / 512));

    /* Entry 1 immediately follows entry 0 */
    uint32_t lba0_count = read_u32(path, MBR_LBA_COUNT(MBR_ENTRY0_OFF));
    CHECK(lba1_start == lba0_start + lba0_count);

    unlink(path); free(path);
    memset(&SelectedDrive, 0, sizeof(SelectedDrive));
}

TEST(create_partition_mbr_persistence_main_partition_reduced)
{
    /*
     * With persistence, the main partition must be smaller by exactly
     * persistence_size / sector_size sectors.
     */
    const uint64_t disk   = IMG_512MB;
    const uint64_t pers   = 64ULL * 1024 * 1024;
    const uint32_t sector = 512;
    const uint32_t gap    = 2048;

    char *path = create_temp_image(disk);
    CHECK(path != NULL);
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;

    SelectedDrive.DiskSize   = (LONGLONG)disk;
    SelectedDrive.SectorSize = sector;
    persistence_size = pers;

    BOOL r = CreatePartition(h, PARTITION_STYLE_MBR, FS_FAT32, TRUE,
                             XP_PERSISTENCE);
    close(fd);
    CHECK(r == TRUE);

    uint64_t total_sects  = disk / sector;
    uint32_t pers_sectors = (uint32_t)(pers / sector);
    uint32_t main_sectors = (uint32_t)(total_sects - gap - pers_sectors);

    uint32_t lba0_count = read_u32(path, MBR_LBA_COUNT(MBR_ENTRY0_OFF));
    uint32_t lba1_count = read_u32(path, MBR_LBA_COUNT(MBR_ENTRY1_OFF));

    CHECK(lba0_count == main_sectors);
    CHECK(lba1_count == pers_sectors);

    unlink(path); free(path);
    memset(&SelectedDrive, 0, sizeof(SelectedDrive));
}

TEST(create_partition_mbr_persistence_entry1_type_is_linux)
{
    /*
     * The persistence partition type byte (entry_base + 4) must be 0x83
     * (Linux native filesystem).
     */
    const uint64_t pers = 64ULL * 1024 * 1024;
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;

    SelectedDrive.DiskSize   = (LONGLONG)IMG_512MB;
    SelectedDrive.SectorSize = 512;
    persistence_size = pers;

    BOOL r = CreatePartition(h, PARTITION_STYLE_MBR, FS_FAT32, TRUE,
                             XP_PERSISTENCE);
    close(fd);
    CHECK(r == TRUE);

    uint8_t ptype = 0;
    CHECK(read_at(path, MBR_ENTRY1_OFF + 4, &ptype, 1) == 0);
    CHECK(ptype == 0x83);

    unlink(path); free(path);
    memset(&SelectedDrive, 0, sizeof(SelectedDrive));
}

/* ================================================================
 * Tests: CreatePartition with XP_PERSISTENCE (GPT)
 * ================================================================ */

TEST(create_partition_gpt_no_persistence_one_entry)
{
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;

    SelectedDrive.DiskSize   = (LONGLONG)IMG_512MB;
    SelectedDrive.SectorSize = 512;
    persistence_size = 0;

    BOOL r = CreatePartition(h, PARTITION_STYLE_GPT, FS_FAT32, FALSE, 0);
    close(fd);
    CHECK(r == TRUE);

    /* GPT signature at LBA 1 */
    uint8_t sig[8];
    CHECK(read_at(path, 512, sig, 8) == 0);
    CHECK(memcmp(sig, "EFI PART", 8) == 0);

    /* Entry 0: non-zero first_lba */
    uint64_t first0 = read_u64(path, GPT_FIRST_LBA(0));
    CHECK(first0 >= 34);

    /* Entry 1: first_lba must be zero (unused) */
    uint64_t first1 = read_u64(path, GPT_FIRST_LBA(1));
    CHECK(first1 == 0);

    unlink(path); free(path);
    memset(&SelectedDrive, 0, sizeof(SelectedDrive));
}

TEST(create_partition_gpt_with_persistence_two_entries)
{
    const uint64_t pers = 64ULL * 1024 * 1024;
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;

    SelectedDrive.DiskSize   = (LONGLONG)IMG_512MB;
    SelectedDrive.SectorSize = 512;
    persistence_size = pers;

    BOOL r = CreatePartition(h, PARTITION_STYLE_GPT, FS_FAT32, FALSE,
                             XP_PERSISTENCE);
    close(fd);
    CHECK(r == TRUE);

    /* Entry 0 present */
    uint64_t first0 = read_u64(path, GPT_FIRST_LBA(0));
    uint64_t last0  = read_u64(path, GPT_LAST_LBA(0));
    CHECK(first0 >= 34);
    CHECK(last0 > first0);

    /* Entry 1 present and follows entry 0 */
    uint64_t first1 = read_u64(path, GPT_FIRST_LBA(1));
    uint64_t last1  = read_u64(path, GPT_LAST_LBA(1));
    CHECK(first1 == last0 + 1);
    CHECK(last1 >= first1);

    /* Persistence partition size matches */
    uint64_t pers_sects = pers / 512;
    CHECK((last1 - first1 + 1) == pers_sects);

    unlink(path); free(path);
    memset(&SelectedDrive, 0, sizeof(SelectedDrive));
}

/* ================================================================
 * Tests: FormatThread persistence integration
 * ================================================================ */

TEST(format_thread_persistence_zero_size_single_partition)
{
    /*
     * persistence_size == 0 → FormatThread must create only one partition.
     */
    char *path = create_temp_image(IMG_1GB);
    CHECK(path != NULL);
    setup_drive(path, IMG_1GB);
    reset_globals();
    boot_type          = BT_IMAGE;
    partition_type     = PARTITION_STYLE_MBR;
    fs_type            = FS_FAT32;
    target_type        = TT_BIOS;
    img_report.has_grub2  = 1;
    img_report.is_iso     = 0;
    persistence_size      = 0;
    quick_format          = TRUE;

    DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
    CHECK(rc == 0);
    CHECK(!IS_ERROR(ErrorStatus));

    uint8_t entry1[16] = { 0 };
    uint8_t zeroes[16] = { 0 };
    CHECK(read_at(path, MBR_ENTRY1_OFF, entry1, 16) == 0);
    CHECK(memcmp(entry1, zeroes, 16) == 0);

    teardown_drive();
    unlink(path); free(path);
}

TEST(format_thread_persistence_casper_creates_two_partitions)
{
    /*
     * Ubuntu-like ISO (uses_casper=TRUE) + persistence_size=256MB →
     * two MBR partitions expected.
     */
    const uint64_t pers = 256ULL * 1024 * 1024;
    char *path = create_temp_image(IMG_1GB);
    CHECK(path != NULL);
    setup_drive(path, IMG_1GB);
    reset_globals();
    boot_type              = BT_IMAGE;
    partition_type         = PARTITION_STYLE_MBR;
    fs_type                = FS_FAT32;
    target_type            = TT_BIOS;
    img_report.has_grub2   = 1;
    img_report.uses_casper = TRUE;
    img_report.is_iso      = 0;
    persistence_size       = pers;
    quick_format           = TRUE;

    DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
    CHECK(rc == 0);
    CHECK(!IS_ERROR(ErrorStatus));

    /* Entry 0 present at LBA 2048 */
    uint32_t lba0 = read_u32(path, MBR_LBA_START(MBR_ENTRY0_OFF));
    CHECK(lba0 == MAIN_LBA_START);

    /* Entry 1 present and has correct size */
    uint32_t lba1_start = read_u32(path, MBR_LBA_START(MBR_ENTRY1_OFF));
    CHECK(lba1_start > MAIN_LBA_START);
    uint32_t lba1_count = read_u32(path, MBR_LBA_COUNT(MBR_ENTRY1_OFF));
    CHECK(lba1_count == (uint32_t)(pers / 512));

    teardown_drive();
    unlink(path); free(path);
}

TEST(format_thread_persistence_casper_ext2_magic_present)
{
    /*
     * The persistence partition for a casper image must have a valid ext2/3
     * superblock (magic 0xEF53).
     */
    const uint64_t pers = 256ULL * 1024 * 1024;
    char *path = create_temp_image(IMG_1GB);
    CHECK(path != NULL);
    setup_drive(path, IMG_1GB);
    reset_globals();
    boot_type              = BT_IMAGE;
    partition_type         = PARTITION_STYLE_MBR;
    fs_type                = FS_FAT32;
    target_type            = TT_BIOS;
    img_report.has_grub2   = 1;
    img_report.uses_casper = TRUE;
    img_report.is_iso      = 0;
    persistence_size       = pers;
    quick_format           = TRUE;

    DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
    CHECK(rc == 0);
    CHECK(!IS_ERROR(ErrorStatus));

    uint32_t lba1 = read_u32(path, MBR_LBA_START(MBR_ENTRY1_OFF));
    CHECK(lba1 > 0);
    uint64_t pers_off = (uint64_t)lba1 * 512;
    uint16_t magic = 0;
    CHECK(read_at(path, (off_t)(pers_off + EXT2_MAGIC_OFF), &magic, 2) == 0);
    CHECK(magic == EXT2_MAGIC_VAL);

    teardown_drive();
    unlink(path); free(path);
}

TEST(format_thread_persistence_debian_creates_two_partitions)
{
    /*
     * Debian-like ISO (uses_casper=FALSE) + persistence_size=256MB.
     * Uses grub2 to avoid triggering syslinux stub failure in tests.
     */
    const uint64_t pers = 256ULL * 1024 * 1024;
    char *path = create_temp_image(IMG_1GB);
    CHECK(path != NULL);
    setup_drive(path, IMG_1GB);
    reset_globals();
    boot_type              = BT_IMAGE;
    partition_type         = PARTITION_STYLE_MBR;
    fs_type                = FS_FAT32;
    target_type            = TT_BIOS;
    img_report.has_grub2   = 1;
    img_report.uses_casper = FALSE;
    img_report.is_iso      = 0;
    persistence_size       = pers;
    quick_format           = TRUE;

    DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
    CHECK(rc == 0);
    CHECK(!IS_ERROR(ErrorStatus));

    uint32_t lba1_start = read_u32(path, MBR_LBA_START(MBR_ENTRY1_OFF));
    CHECK(lba1_start > MAIN_LBA_START);
    uint32_t lba1_count = read_u32(path, MBR_LBA_COUNT(MBR_ENTRY1_OFF));
    CHECK(lba1_count == (uint32_t)(pers / 512));

    teardown_drive();
    unlink(path); free(path);
}

TEST(format_thread_persistence_debian_ext2_magic_present)
{
    const uint64_t pers = 256ULL * 1024 * 1024;
    char *path = create_temp_image(IMG_1GB);
    CHECK(path != NULL);
    setup_drive(path, IMG_1GB);
    reset_globals();
    boot_type              = BT_IMAGE;
    partition_type         = PARTITION_STYLE_MBR;
    fs_type                = FS_FAT32;
    target_type            = TT_BIOS;
    img_report.has_grub2   = 1;
    img_report.uses_casper = FALSE;
    img_report.is_iso      = 0;
    persistence_size       = pers;
    quick_format           = TRUE;

    DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
    CHECK(rc == 0);
    CHECK(!IS_ERROR(ErrorStatus));

    uint32_t lba1 = read_u32(path, MBR_LBA_START(MBR_ENTRY1_OFF));
    CHECK(lba1 > 0);
    uint64_t pers_off = (uint64_t)lba1 * 512;
    uint16_t magic = 0;
    CHECK(read_at(path, (off_t)(pers_off + EXT2_MAGIC_OFF), &magic, 2) == 0);
    CHECK(magic == EXT2_MAGIC_VAL);

    teardown_drive();
    unlink(path); free(path);
}

TEST(format_thread_persistence_windows_image_no_extra_partition)
{
    /*
     * Windows image (has_bootmgr=TRUE) is not eligible for persistence
     * even when persistence_size > 0.  Single partition expected.
     */
    const uint64_t pers = 256ULL * 1024 * 1024;
    char *path = create_temp_image(IMG_1GB);
    CHECK(path != NULL);
    setup_drive(path, IMG_1GB);
    reset_globals();
    boot_type              = BT_IMAGE;
    partition_type         = PARTITION_STYLE_MBR;
    fs_type                = FS_FAT32;
    target_type            = TT_BIOS;
    img_report.has_bootmgr = TRUE;
    img_report.is_iso      = 0;
    persistence_size       = pers;
    quick_format           = TRUE;

    DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
    CHECK(rc == 0);
    CHECK(!IS_ERROR(ErrorStatus));

    uint8_t entry1[16] = { 0 };
    uint8_t zeroes[16] = { 0 };
    CHECK(read_at(path, MBR_ENTRY1_OFF, entry1, 16) == 0);
    CHECK(memcmp(entry1, zeroes, 16) == 0);

    teardown_drive();
    unlink(path); free(path);
}

TEST(format_thread_persistence_reduces_main_partition)
{
    /*
     * When persistence is requested the main partition size must decrease
     * by exactly persistence_size / 512 sectors compared to no-persistence.
     */
    const uint64_t pers = 256ULL * 1024 * 1024;

    /* Run 1: no persistence */
    char *path1 = create_temp_image(IMG_1GB);
    CHECK(path1 != NULL);
    setup_drive(path1, IMG_1GB);
    reset_globals();
    boot_type              = BT_IMAGE;
    partition_type         = PARTITION_STYLE_MBR;
    fs_type                = FS_FAT32;
    img_report.has_grub2   = 1;
    img_report.is_iso      = 0;
    persistence_size       = 0;
    quick_format           = TRUE;
    DWORD rc1 = run_format_thread(DRIVE_INDEX_MIN);
    CHECK(rc1 == 0);
    uint32_t full_count = read_u32(path1, MBR_LBA_COUNT(MBR_ENTRY0_OFF));
    teardown_drive();
    unlink(path1); free(path1);

    /* Run 2: with persistence */
    char *path2 = create_temp_image(IMG_1GB);
    CHECK(path2 != NULL);
    setup_drive(path2, IMG_1GB);
    reset_globals();
    boot_type              = BT_IMAGE;
    partition_type         = PARTITION_STYLE_MBR;
    fs_type                = FS_FAT32;
    img_report.has_grub2   = 1;
    img_report.uses_casper = TRUE;
    img_report.is_iso      = 0;
    persistence_size       = pers;
    quick_format           = TRUE;
    DWORD rc2 = run_format_thread(DRIVE_INDEX_MIN);
    CHECK(rc2 == 0);
    uint32_t reduced_count = read_u32(path2, MBR_LBA_COUNT(MBR_ENTRY0_OFF));
    teardown_drive();
    unlink(path2); free(path2);

    CHECK(reduced_count < full_count);
    CHECK((full_count - reduced_count) == (uint32_t)(pers / 512));
}

TEST(format_thread_persistence_gpt_two_entries)
{
    /*
     * GPT + persistence_size → two GPT partition entries.
     */
    const uint64_t pers = 256ULL * 1024 * 1024;
    char *path = create_temp_image(IMG_1GB);
    CHECK(path != NULL);
    setup_drive(path, IMG_1GB);
    reset_globals();
    boot_type              = BT_IMAGE;
    partition_type         = PARTITION_STYLE_GPT;
    fs_type                = FS_FAT32;
    target_type            = TT_BIOS;
    img_report.has_grub2   = 1;
    img_report.uses_casper = TRUE;
    img_report.is_iso      = 0;
    persistence_size       = pers;
    quick_format           = TRUE;

    DWORD rc = run_format_thread(DRIVE_INDEX_MIN);
    CHECK(rc == 0);
    CHECK(!IS_ERROR(ErrorStatus));

    uint64_t first0 = read_u64(path, GPT_FIRST_LBA(0));
    CHECK(first0 >= 34);

    uint64_t first1 = read_u64(path, GPT_FIRST_LBA(1));
    uint64_t last1  = read_u64(path, GPT_LAST_LBA(1));
    CHECK(first1 > first0);
    CHECK((last1 - first1 + 1) == (pers / 512));

    teardown_drive();
    unlink(path); free(path);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
    printf("=== HAS_PERSISTENCE macro tests ===\n");
    RUN(has_persistence_false_when_no_bootloader);
    RUN(has_persistence_true_for_grub2);
    RUN(has_persistence_true_for_grub4dos);
    RUN(has_persistence_true_for_syslinux);
    RUN(has_persistence_false_for_windows_image);
    RUN(has_persistence_false_for_reactos);
    RUN(has_persistence_false_for_kolibrios);
    RUN(has_persistence_grub_and_syslinux_together);

    printf("\n=== CreatePartition MBR persistence tests ===\n");
    RUN(create_partition_mbr_no_persistence_one_partition);
    RUN(create_partition_mbr_with_persistence_has_two_entries);
    RUN(create_partition_mbr_persistence_main_partition_reduced);
    RUN(create_partition_mbr_persistence_entry1_type_is_linux);

    printf("\n=== CreatePartition GPT persistence tests ===\n");
    RUN(create_partition_gpt_no_persistence_one_entry);
    RUN(create_partition_gpt_with_persistence_two_entries);

    printf("\n=== FormatThread persistence integration tests ===\n");
    RUN(format_thread_persistence_zero_size_single_partition);
    RUN(format_thread_persistence_casper_creates_two_partitions);
    RUN(format_thread_persistence_casper_ext2_magic_present);
    RUN(format_thread_persistence_debian_creates_two_partitions);
    RUN(format_thread_persistence_debian_ext2_magic_present);
    RUN(format_thread_persistence_windows_image_no_extra_partition);
    RUN(format_thread_persistence_reduces_main_partition);
    RUN(format_thread_persistence_gpt_two_entries);

    TEST_RESULTS();
}

#endif /* __linux__ */
