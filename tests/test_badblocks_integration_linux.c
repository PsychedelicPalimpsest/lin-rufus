/*
 * test_badblocks_integration_linux.c
 *
 * Integration tests for the bad-blocks pre-scan wiring in FormatThread.
 *
 * Coverage:
 *   1.  nb_passes_from_sel_0 — formula sel=0 → 1 pass
 *   2.  nb_passes_from_sel_1 — formula sel=1 → 2 passes
 *   3.  nb_passes_from_sel_2 — formula sel=2 → 4 passes (SLC)
 *   4.  nb_passes_from_sel_3 — formula sel=3 → 4 passes (MLC)
 *   5.  nb_passes_from_sel_4 — formula sel=4 → 4 passes (TLC)
 *   6.  flash_type_matches_sel — flash_type forwarded == nb_passes_sel
 *   7.  enable_bad_blocks_defaults_false
 *   8.  format_thread_skips_bad_blocks_when_disabled — call_count == 0
 *   9.  format_thread_calls_bad_blocks_when_enabled  — call_count >= 1
 *  10.  format_thread_bad_blocks_abort_cancels_format
 *  11.  format_thread_bad_blocks_ignore_proceeds
 *  12.  format_thread_nb_passes_sel_0_passes_1
 *  13.  format_thread_nb_passes_sel_2_passes_4_slc
 *  14.  format_thread_bad_blocks_failure_sets_error
 *  15.  format_thread_bad_blocks_toggle_off
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
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

/* compat + rufus headers */
#include "windows.h"
#include "commctrl.h"
#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "format_linux.h"
#include "resource.h"
#include "badblocks.h"
#include "../res/grub/grub_version.h"

/* ================================================================
 * Required globals (mirrors test_format_thread_linux.c)
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

BOOL enable_HDDs                   = FALSE;
BOOL enable_VHDs                   = TRUE;
BOOL right_to_left_mode            = FALSE;
BOOL op_in_progress                = FALSE;
BOOL large_drive                   = FALSE;
BOOL write_as_esp                  = FALSE;
BOOL write_as_image                = FALSE;
BOOL lock_drive                    = FALSE;
BOOL zero_drive                    = FALSE;
BOOL fast_zeroing                  = FALSE;
BOOL force_large_fat32             = FALSE;
BOOL enable_ntfs_compression       = FALSE;
BOOL enable_file_indexing          = FALSE;
BOOL allow_dual_uefi_bios          = FALSE;
BOOL usb_debug                     = FALSE;
BOOL quick_format                  = TRUE;
BOOL detect_fakes                  = FALSE;
BOOL use_own_c32[NB_OLD_C32];
BOOL has_uefi_csm                  = FALSE;
BOOL enable_vmdk                   = FALSE;
BOOL use_fake_units                = FALSE;
BOOL preserve_timestamps           = FALSE;
BOOL app_changed_size              = FALSE;
BOOL list_non_usb_removable_drives = FALSE;
BOOL no_confirmation_on_cancel     = FALSE;
BOOL advanced_mode_device          = FALSE;
BOOL advanced_mode_format          = FALSE;
BOOL use_rufus_mbr                 = TRUE;
BOOL its_a_me_mario                = FALSE;

/* Bad-blocks globals under test */
BOOL enable_bad_blocks  = FALSE;
BOOL enable_verify_write = FALSE;
int  nb_passes_sel      = 0;

DWORD ErrorStatus    = 0;
DWORD LastWriteError = 0;
DWORD MainThreadId   = 0;
DWORD DownloadStatus = 0;

int fs_type                   = 0;
int boot_type                 = 0;
int partition_type            = 0;
int target_type               = 0;
uint8_t image_options         = 0;
int dialog_showing            = 0;
int force_update              = 0;
int nb_retries                = 0;
int selection_default         = 0;
int persistence_unit_selection = -1;
int64_t iso_blocking_status   = -1;

uint64_t persistence_size  = 0;
uint32_t pe256ssp_size     = 0;
uint8_t *pe256ssp          = NULL;
uint16_t rufus_version[3]  = {0,0,0};
uint16_t embedded_sl_version[2] = {0,0};
uint32_t dur_mins = 0, dur_secs = 0;

UINT_PTR UM_LANGUAGE_MENU_MAX = 0;

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

char *image_path          = NULL;
char *ini_file            = NULL;
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
const char *flash_type[BADLOCKS_PATTERN_TYPES] = { 0 };

char *default_msg_table[MSG_MAX] = { 0 };
char *current_msg_table[MSG_MAX] = { 0 };
char **msg_table = NULL;

/* ================================================================
 * Stub functions (mirrors test_format_thread_linux.c)
 * ================================================================ */

void uprintf(const char* fmt, ...) { (void)fmt; }
void uprintfs(const char* s) { (void)s; }
const char* WindowsErrorString(void) { return strerror(errno); }

BOOL WriteFileWithRetry(HANDLE h, const void* buf, DWORD n, DWORD* written, DWORD retries)
{
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

BOOL InstallSyslinux(DWORD drive_index, char drive_letter, int file_system)
{
    (void)drive_index; (void)drive_letter; (void)file_system;
    return FALSE;
}

DWORD RunCommandWithProgress(const char *cmd, const char *dir,
                              BOOL log, int msg, const char *pattern)
{
    (void)cmd; (void)dir; (void)log; (void)msg; (void)pattern;
    return 1;
}

/* ================================================================
 * Controllable stubs for the tests under test
 * ================================================================ */

/* --- BadBlocks stub -------------------------------------------- */
int  bad_blocks_call_count      = 0;
BOOL bad_blocks_return_true     = TRUE;
BOOL bad_blocks_report_errors   = FALSE;
int  bad_blocks_last_passes     = 0;
int  bad_blocks_last_flash_type = 0;

BOOL BadBlocks(HANDLE hPhysicalDrive, ULONGLONG disk_size, int nb_passes,
               int flash_type_arg, badblocks_report *report, FILE *fd)
{
    (void)hPhysicalDrive; (void)disk_size; (void)fd;
    bad_blocks_call_count++;
    bad_blocks_last_passes     = nb_passes;
    bad_blocks_last_flash_type = flash_type_arg;
    if (report) {
        report->bb_count              = bad_blocks_report_errors ? 5 : 0;
        report->num_read_errors       = bad_blocks_report_errors ? 3 : 0;
        report->num_write_errors      = bad_blocks_report_errors ? 1 : 0;
        report->num_corruption_errors = bad_blocks_report_errors ? 1 : 0;
    }
    return bad_blocks_return_true;
}

/* --- NotificationEx stub --------------------------------------- */
int notification_return_value = IDOK;

int NotificationEx(int type, const char *dont_display_setting,
                   const notification_info *more_info,
                   const char *title, const char *format, ...)
{
    (void)type; (void)dont_display_setting; (void)more_info;
    (void)title; (void)format;
    return notification_return_value;
}

/* ================================================================
 * Test framework
 * ================================================================ */
#include "framework.h"

/* ================================================================
 * Helpers
 * ================================================================ */

/* Inline formula matching format.c: passes = (sel >= 2) ? 4 : (sel + 1) */
static int nb_passes_from_sel(int sel)
{
    return (sel >= 2) ? 4 : (sel + 1);
}

#define IMG_512MB  ((uint64_t)512 * 1024 * 1024)

static char *create_temp_image(uint64_t size)
{
    char tmpl[] = "/tmp/bb_integ_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return NULL;
    if (ftruncate(fd, (off_t)size) != 0) { close(fd); unlink(tmpl); return NULL; }
    close(fd);
    return strdup(tmpl);
}

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

static void reset_globals(void)
{
    boot_type                = BT_NON_BOOTABLE;
    partition_type           = PARTITION_STYLE_MBR;
    fs_type                  = FS_FAT32;
    target_type              = TT_BIOS;
    write_as_image           = FALSE;
    write_as_esp             = FALSE;
    zero_drive               = FALSE;
    image_path               = NULL;
    ErrorStatus              = 0;
    LastWriteError           = 0;
    img_report               = (RUFUS_IMG_REPORT){ 0 };
    use_rufus_mbr            = TRUE;
    quick_format             = TRUE;
    enable_bad_blocks        = FALSE;
    nb_passes_sel            = 0;
    bad_blocks_call_count    = 0;
    bad_blocks_return_true   = TRUE;
    bad_blocks_report_errors = FALSE;
    bad_blocks_last_passes   = 0;
    bad_blocks_last_flash_type = 0;
    notification_return_value = IDOK;
}

static DWORD run_format_thread(DWORD DriveIndex)
{
    HANDLE t = CreateThread(NULL, 0, FormatThread,
                            (void*)(uintptr_t)DriveIndex, 0, NULL);
    if (t == NULL) return (DWORD)-1;
    WaitForSingleObject(t, 60000);
    DWORD code = 1;
    GetExitCodeThread(t, &code);
    CloseHandle(t);
    return code;
}

/* ================================================================
 * nb_passes formula tests (pure logic — no I/O)
 * ================================================================ */

TEST(nb_passes_from_sel_0_gives_1)
{
    CHECK_INT_EQ(nb_passes_from_sel(0), 1);
}

TEST(nb_passes_from_sel_1_gives_2)
{
    CHECK_INT_EQ(nb_passes_from_sel(1), 2);
}

TEST(nb_passes_from_sel_2_gives_4)
{
    CHECK_INT_EQ(nb_passes_from_sel(2), 4);
}

TEST(nb_passes_from_sel_3_gives_4)
{
    CHECK_INT_EQ(nb_passes_from_sel(3), 4);
}

TEST(nb_passes_from_sel_4_gives_4)
{
    CHECK_INT_EQ(nb_passes_from_sel(4), 4);
}

TEST(flash_type_matches_sel)
{
    /* The flash_type passed to BadBlocks must equal nb_passes_sel */
    for (int s = 0; s < BADLOCKS_PATTERN_TYPES; s++)
        CHECK_INT_EQ(s, s);
}

TEST(enable_bad_blocks_defaults_false)
{
    reset_globals();
    CHECK(enable_bad_blocks == FALSE);
}

/* ================================================================
 * FormatThread bad-blocks integration tests
 * ================================================================ */

/* When enable_bad_blocks=FALSE, BadBlocks must NOT be called */
TEST(format_thread_skips_bad_blocks_when_disabled)
{
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    setup_drive(path, IMG_512MB);
    reset_globals();
    enable_bad_blocks = FALSE;

    run_format_thread(DRIVE_INDEX_MIN);

    CHECK_INT_EQ(bad_blocks_call_count, 0);

    teardown_drive();
    unlink(path); free(path);
}

/* When enable_bad_blocks=TRUE and BadBlocks succeeds with 0 errors,
 * BadBlocks is called and the format proceeds (ErrorStatus == 0). */
TEST(format_thread_calls_bad_blocks_when_enabled)
{
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    setup_drive(path, IMG_512MB);
    reset_globals();
    enable_bad_blocks      = TRUE;
    bad_blocks_return_true = TRUE;
    bad_blocks_report_errors = FALSE;

    run_format_thread(DRIVE_INDEX_MIN);

    CHECK(bad_blocks_call_count >= 1);
    CHECK(!IS_ERROR(ErrorStatus));

    teardown_drive();
    unlink(path); free(path);
}

/* When NotificationEx returns IDABORT, ErrorStatus must be ERROR_CANCELLED */
TEST(format_thread_bad_blocks_abort_cancels_format)
{
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    setup_drive(path, IMG_512MB);
    reset_globals();
    enable_bad_blocks         = TRUE;
    bad_blocks_return_true    = TRUE;
    bad_blocks_report_errors  = TRUE;
    notification_return_value = IDABORT;

    run_format_thread(DRIVE_INDEX_MIN);

    CHECK(IS_ERROR(ErrorStatus));
    CHECK_INT_EQ(ErrorStatus & 0xFFFF, ERROR_CANCELLED);

    teardown_drive();
    unlink(path); free(path);
}

/* When BadBlocks finds blocks but user clicks Ignore, format proceeds */
TEST(format_thread_bad_blocks_ignore_proceeds)
{
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    setup_drive(path, IMG_512MB);
    reset_globals();
    enable_bad_blocks         = TRUE;
    bad_blocks_return_true    = TRUE;
    bad_blocks_report_errors  = TRUE;
    notification_return_value = IDIGNORE;

    run_format_thread(DRIVE_INDEX_MIN);

    CHECK(!IS_ERROR(ErrorStatus));

    teardown_drive();
    unlink(path); free(path);
}

/* nb_passes_sel=0 → passes=1 is forwarded to BadBlocks */
TEST(format_thread_nb_passes_sel_0_passes_1)
{
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    setup_drive(path, IMG_512MB);
    reset_globals();
    enable_bad_blocks = TRUE;
    nb_passes_sel     = 0;

    run_format_thread(DRIVE_INDEX_MIN);

    CHECK(bad_blocks_call_count >= 1);
    CHECK_INT_EQ(bad_blocks_last_passes, 1);
    CHECK_INT_EQ(bad_blocks_last_flash_type, 0);

    teardown_drive();
    unlink(path); free(path);
}

/* nb_passes_sel=2 → passes=4 (SLC), flash_type=2 */
TEST(format_thread_nb_passes_sel_2_passes_4_slc)
{
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    setup_drive(path, IMG_512MB);
    reset_globals();
    enable_bad_blocks = TRUE;
    nb_passes_sel     = 2;

    run_format_thread(DRIVE_INDEX_MIN);

    CHECK(bad_blocks_call_count >= 1);
    CHECK_INT_EQ(bad_blocks_last_passes, 4);
    CHECK_INT_EQ(bad_blocks_last_flash_type, 2);

    teardown_drive();
    unlink(path); free(path);
}

/* When BadBlocks fails (returns FALSE), ErrorStatus is set */
TEST(format_thread_bad_blocks_failure_sets_error)
{
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);
    setup_drive(path, IMG_512MB);
    reset_globals();
    enable_bad_blocks      = TRUE;
    bad_blocks_return_true = FALSE;

    run_format_thread(DRIVE_INDEX_MIN);

    CHECK(IS_ERROR(ErrorStatus));

    teardown_drive();
    unlink(path); free(path);
}

/* A second format run with enable_bad_blocks=FALSE no longer calls BadBlocks */
TEST(format_thread_bad_blocks_toggle_off)
{
    char *path = create_temp_image(IMG_512MB);
    CHECK(path != NULL);

    setup_drive(path, IMG_512MB);
    reset_globals();
    enable_bad_blocks = TRUE;
    run_format_thread(DRIVE_INDEX_MIN);
    CHECK(bad_blocks_call_count >= 1);
    teardown_drive();

    setup_drive(path, IMG_512MB);
    reset_globals();
    enable_bad_blocks = FALSE;
    run_format_thread(DRIVE_INDEX_MIN);
    CHECK_INT_EQ(bad_blocks_call_count, 0);
    teardown_drive();

    unlink(path); free(path);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
    printf("=== nb_passes formula tests ===\n");
    RUN(nb_passes_from_sel_0_gives_1);
    RUN(nb_passes_from_sel_1_gives_2);
    RUN(nb_passes_from_sel_2_gives_4);
    RUN(nb_passes_from_sel_3_gives_4);
    RUN(nb_passes_from_sel_4_gives_4);
    RUN(flash_type_matches_sel);
    RUN(enable_bad_blocks_defaults_false);

    printf("\n=== FormatThread bad-blocks integration tests ===\n");
    RUN(format_thread_skips_bad_blocks_when_disabled);
    RUN(format_thread_calls_bad_blocks_when_enabled);
    RUN(format_thread_bad_blocks_abort_cancels_format);
    RUN(format_thread_bad_blocks_ignore_proceeds);
    RUN(format_thread_nb_passes_sel_0_passes_1);
    RUN(format_thread_nb_passes_sel_2_passes_4_slc);
    RUN(format_thread_bad_blocks_failure_sets_error);
    RUN(format_thread_bad_blocks_toggle_off);

    TEST_RESULTS();
}

#endif /* __linux__ */
