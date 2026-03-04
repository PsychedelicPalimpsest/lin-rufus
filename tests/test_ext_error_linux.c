/*
 * test_ext_error_linux.c — tests for ext2fs error_message() and
 * ext2fs_print_progress() from format_ext.c
 *
 * These functions are candidates for extraction to src/common/format_ext.c
 * (Phase 3 of the Windows+Linux common-merger).  Tests here exercise the
 * pure-C behaviour so that any refactoring to common/ is validated by the
 * same test suite.
 *
 * Copyright © 2025 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
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
#include <errno.h>
#include <sys/stat.h>

/* ---- compat layer ---- */
#include "windows.h"
#include "commctrl.h"
/* ---- rufus headers ---- */
#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "resource.h"
#include "ext2fs/ext2fs.h"

/* ================================================================
 * Globals required by rufus.h / drive.h / format.h externs
 * ================================================================ */
RUFUS_DRIVE rufus_drive[MAX_DRIVES];
extern RUFUS_DRIVE_INFO SelectedDrive;
extern int partition_index[PI_MAX];

HWND hMainDialog      = NULL;
HWND hDeviceList      = NULL;
HWND hProgress        = NULL;
HWND hStatus          = NULL;
HWND hInfo            = NULL;
HWND hLog             = NULL;
HWND hLabel           = NULL;
HWND hBootType        = NULL;
HWND hFileSystem      = NULL;
HWND hClusterSize     = NULL;
HWND hPartitionScheme = NULL;
HWND hTargetSystem    = NULL;
HWND hImageOption     = NULL;

BOOL enable_HDDs             = FALSE;
BOOL enable_VHDs             = TRUE;
BOOL right_to_left_mode      = FALSE;
BOOL op_in_progress          = FALSE;
BOOL large_drive             = FALSE;
BOOL write_as_esp            = FALSE;
BOOL write_as_image          = FALSE;
BOOL lock_drive              = FALSE;
BOOL zero_drive              = FALSE;
BOOL cli_win_to_go         = FALSE;
BOOL fast_zeroing            = FALSE;
BOOL force_large_fat32       = FALSE;
BOOL enable_ntfs_compression = FALSE;
BOOL enable_file_indexing    = FALSE;
BOOL quick_format            = FALSE;
BOOL use_rufus_mbr           = TRUE;
BOOL enable_bad_blocks       = FALSE;
BOOL enable_verify_write     = FALSE;

DWORD ErrorStatus    = 0;
DWORD LastWriteError = 0;
DWORD MainThreadId   = 0;
DWORD DownloadStatus = 0;

int fs_type        = 0;
int boot_type      = 0;
int partition_type = 0;
int target_type    = 0;
int nb_passes_sel  = 0;
uint8_t image_options = 0;

char szFolderPath[MAX_PATH]          = "";
char app_dir[MAX_PATH]               = "";
char temp_dir[MAX_PATH]              = "/tmp";
char cur_dir[MAX_PATH]               = "";
char app_data_dir[MAX_PATH]          = "";
char user_dir[MAX_PATH]              = "";
char system_dir[MAX_PATH]            = "";
char sysnative_dir[MAX_PATH]         = "";
char msgbox[1024]                    = "";
char msgbox_title[32]                = "";
char image_option_txt[128]           = "";
char ubuffer[UBUFFER_SIZE]           = "";
char embedded_sl_version_str[2][12]  = {"", ""};
char embedded_sl_version_ext[2][32]  = {"", ""};
char ClusterSizeLabel[MAX_CLUSTER_SIZES][64];

char *ini_file     = NULL;
char *image_path   = NULL;
char *archive_path = NULL;

RUFUS_IMG_REPORT img_report = { 0 };

uint64_t md5sum_totalbytes   = 0;
BOOL preserve_timestamps     = FALSE;
BOOL validate_md5sum         = FALSE;
HANDLE format_thread         = INVALID_HANDLE_VALUE;

/* stdfn.c */
DWORD _win_last_error = 0;

/* wue.c */
int   unattend_xml_flags = 0;
char *unattend_xml_path  = NULL;

/* FileSystemLabel — must match the FS_* enum order (FS_MAX = 9) */
const char *FileSystemLabel[FS_MAX] = {
"FAT", "FAT32", "NTFS", "UDF", "exFAT", "ReFS", "ext2", "ext3", "ext4"
};
const int nb_steps[FS_MAX]    = { 5, 5, 5, 5, 5, 5, 5, 5, 5 };
const char *md5sum_name[2]    = { "md5sum.txt", "MD5SUMS" };

uint8_t *grub2_buf = NULL;
long     grub2_len = 0;
uint8_t *sec_buf   = NULL;

/* ================================================================
 * Stub functions required by format_ext.c and its includes
 * ================================================================ */
void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s) { (void)s; }
const char *WindowsErrorString(void) { return strerror(errno); }
char *lmprintf(int id, ...) { (void)id; return ""; }

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
void UpdateProgress(int op, float percent) { (void)op; (void)percent; }
void InitProgress(BOOL b) { (void)b; }

LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
(void)h; (void)m; (void)w; (void)l; return 0;
}
BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
(void)h; (void)m; (void)w; (void)l; return FALSE;
}

char *SizeToHumanReadable(uint64_t size, BOOL copy, BOOL fake) {
static char buf[32]; (void)size; (void)copy; (void)fake;
snprintf(buf, sizeof(buf), "?"); return buf;
}

BOOL WriteFileWithRetry(HANDLE h, const void *buf, DWORD n, DWORD *written, DWORD retries) {
(void)h; (void)buf; (void)n; (void)retries;
if (written) *written = 0; return FALSE;
}

char *GuidToString(const GUID *g, BOOL b)      { (void)g;(void)b; return NULL; }
GUID *StringToGuid(const char *s)              { (void)s; return NULL; }
BOOL  CompareGUID(const GUID *g1, const GUID *g2) {
if (!g1 || !g2) return FALSE;
return (__builtin_memcmp(g1, g2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}
char *get_token_data_file_indexed(const char *t, const char *f, int i)
{ (void)t;(void)f;(void)i; return NULL; }

DWORD RunCommandWithProgress(const char *cmd, const char *dir,
                             BOOL log, int msg, const char *pattern)
{ (void)cmd;(void)dir;(void)log;(void)msg;(void)pattern; return ERROR_NOT_SUPPORTED; }

BOOL ExtractISO(const char *s, const char *d, BOOL scan)
{ (void)s;(void)d;(void)scan; return TRUE; }

int NotificationEx(int t, const char *s, const notification_info *ni,
                   const char *title, const char *fmt, ...)
{ (void)t;(void)s;(void)ni;(void)title;(void)fmt; return IDOK; }

BOOL InstallSyslinux(DWORD di, char dl, int fs)
{ (void)di;(void)dl;(void)fs; return TRUE; }

BOOL verify_write_pass(const char *src, int fd, uint64_t sz)
{ (void)src;(void)fd;(void)sz; return TRUE; }

void wue_set_mount_path(const char *p) { (void)p; }
BOOL ApplyWindowsCustomization(char dl, int flags) { (void)dl;(void)flags; return FALSE; }

/* drive.c stub: not linked, provide the one symbol format_ext.c calls */
char *GetExtPartitionName(DWORD di, uint64_t off) { (void)di;(void)off; return NULL; }

/* ================================================================
 * Forward declarations for functions under test
 * ================================================================ */
extern const char *error_message(errcode_t error_code);
extern errcode_t ext2fs_print_progress(int64_t cur_value, int64_t max_value);

/* ================================================================
 * Test framework
 * ================================================================ */
#include "framework.h"

/* ================================================================
 * Tests for error_message()
 * ================================================================ */

TEST(error_message_bad_magic)
{
const char *msg = error_message(EXT2_ET_BAD_MAGIC);
CHECK(msg != NULL);
CHECK_STR_EQ(msg, "Bad magic");
}

TEST(error_message_magic_variants_all_return_bad_magic)
{
errcode_t magic_codes[] = {
EXT2_ET_MAGIC_EXT2FS_FILSYS,
EXT2_ET_MAGIC_BADBLOCKS_LIST,
EXT2_ET_MAGIC_BADBLOCKS_ITERATE,
EXT2_ET_MAGIC_INODE_SCAN,
EXT2_ET_MAGIC_IO_CHANNEL,
EXT2_ET_MAGIC_IO_MANAGER,
EXT2_ET_MAGIC_BLOCK_BITMAP,
EXT2_ET_MAGIC_INODE_BITMAP,
EXT2_ET_MAGIC_GENERIC_BITMAP,
EXT2_ET_BAD_MAGIC,
};
for (size_t i = 0; i < sizeof(magic_codes)/sizeof(magic_codes[0]); i++) {
const char *m = error_message(magic_codes[i]);
CHECK(m != NULL);
CHECK_STR_EQ(m, "Bad magic");
}
}

TEST(error_message_read_only_filesystem)
{
const char *msg = error_message(EXT2_ET_RO_FILSYS);
CHECK(msg != NULL);
CHECK_STR_EQ(msg, "Read-only file system");
}

TEST(error_message_bad_map_or_table)
{
CHECK_STR_EQ(error_message(EXT2_ET_GDESC_BAD_BLOCK_MAP),  "Bad map or table");
CHECK_STR_EQ(error_message(EXT2_ET_GDESC_BAD_INODE_MAP),  "Bad map or table");
CHECK_STR_EQ(error_message(EXT2_ET_GDESC_BAD_INODE_TABLE),"Bad map or table");
}

TEST(error_message_unexpected_block_size)
{
CHECK_STR_EQ(error_message(EXT2_ET_UNEXPECTED_BLOCK_SIZE), "Unexpected block size");
}

TEST(error_message_read_write_errors)
{
errcode_t rw_codes[] = {
EXT2_ET_GDESC_READ,
EXT2_ET_GDESC_WRITE,
EXT2_ET_INODE_BITMAP_WRITE,
EXT2_ET_INODE_BITMAP_READ,
EXT2_ET_BLOCK_BITMAP_WRITE,
EXT2_ET_BLOCK_BITMAP_READ,
EXT2_ET_INODE_TABLE_WRITE,
EXT2_ET_INODE_TABLE_READ,
EXT2_ET_NEXT_INODE_READ,
EXT2_ET_SHORT_READ,
EXT2_ET_SHORT_WRITE,
};
for (size_t i = 0; i < sizeof(rw_codes)/sizeof(rw_codes[0]); i++) {
const char *m = error_message(rw_codes[i]);
CHECK(m != NULL);
CHECK_STR_EQ(m, "read/write error");
}
}

TEST(error_message_no_space_left)
{
CHECK_STR_EQ(error_message(EXT2_ET_DIR_NO_SPACE), "no space left");
}

TEST(error_message_too_small)
{
CHECK_STR_EQ(error_message(EXT2_ET_TOOSMALL), "Too small");
}

TEST(error_message_bad_device_name)
{
CHECK_STR_EQ(error_message(EXT2_ET_BAD_DEVICE_NAME), "Bad device name");
}

TEST(error_message_superblock_corrupted)
{
CHECK_STR_EQ(error_message(EXT2_ET_CORRUPT_SUPERBLOCK), "Superblock is corrupted");
}

TEST(error_message_unimplemented_feature)
{
CHECK_STR_EQ(error_message(EXT2_ET_UNSUPP_FEATURE),   "Unsupported feature");
CHECK_STR_EQ(error_message(EXT2_ET_RO_UNSUPP_FEATURE),"Unsupported feature");
CHECK_STR_EQ(error_message(EXT2_ET_UNIMPLEMENTED),    "Unsupported feature");
}

TEST(error_message_seek_failed)
{
CHECK_STR_EQ(error_message(EXT2_ET_LLSEEK_FAILED), "Seek failed");
}

TEST(error_message_out_of_memory)
{
CHECK_STR_EQ(error_message(EXT2_ET_NO_MEMORY),       "Out of memory");
CHECK_STR_EQ(error_message(EXT2_ET_BLOCK_ALLOC_FAIL),"Out of memory");
CHECK_STR_EQ(error_message(EXT2_ET_INODE_ALLOC_FAIL),"Out of memory");
}

TEST(error_message_invalid_argument)
{
CHECK_STR_EQ(error_message(EXT2_ET_INVALID_ARGUMENT), "Invalid argument");
}

TEST(error_message_file_not_found)
{
CHECK_STR_EQ(error_message(EXT2_ET_FILE_NOT_FOUND), "File not found");
}

TEST(error_message_file_exists)
{
CHECK_STR_EQ(error_message(EXT2_ET_FILE_EXISTS), "File exists");
}

TEST(error_message_cancel_requested)
{
CHECK_STR_EQ(error_message(EXT2_ET_CANCEL_REQUESTED), "Cancel requested");
}

TEST(error_message_journal_errors)
{
CHECK_STR_EQ(error_message(EXT2_ET_NO_JOURNAL_SB),   "No journal superblock");
CHECK_STR_EQ(error_message(EXT2_ET_JOURNAL_NOT_BLOCK),"No journal superblock");
CHECK_STR_EQ(error_message(EXT2_ET_JOURNAL_TOO_SMALL),"Journal too small");
CHECK_STR_EQ(error_message(EXT2_ET_NO_JOURNAL),       "No journal");
}

TEST(error_message_inode_errors)
{
CHECK_STR_EQ(error_message(EXT2_ET_TOO_MANY_INODES),   "Too many inodes");
CHECK_STR_EQ(error_message(EXT2_ET_INODE_IS_GARBAGE),  "Inode is garbage");
CHECK_STR_EQ(error_message(EXT2_ET_INODE_CORRUPTED),   "Inode is corrupted");
CHECK_STR_EQ(error_message(EXT2_ET_EA_INODE_CORRUPTED),"Inode is corrupted");
}

TEST(error_message_checksum_errors)
{
errcode_t csum_codes[] = {
EXT2_ET_INODE_CSUM_INVALID,
EXT2_ET_INODE_BITMAP_CSUM_INVALID,
EXT2_ET_EXTENT_CSUM_INVALID,
EXT2_ET_DIR_CSUM_INVALID,
EXT2_ET_EXT_ATTR_CSUM_INVALID,
EXT2_ET_SB_CSUM_INVALID,
EXT2_ET_BLOCK_BITMAP_CSUM_INVALID,
EXT2_ET_MMP_CSUM_INVALID,
};
for (size_t i = 0; i < sizeof(csum_codes)/sizeof(csum_codes[0]); i++) {
CHECK_STR_EQ(error_message(csum_codes[i]), "Invalid checksum");
}
}

TEST(error_message_filesystem_corrupted)
{
CHECK_STR_EQ(error_message(EXT2_ET_FILESYSTEM_CORRUPTED), "File system is corrupted");
}

TEST(error_message_bad_crc)
{
CHECK_STR_EQ(error_message(EXT2_ET_BAD_CRC), "Bad CRC");
}

TEST(error_message_journal_superblock_corrupted)
{
CHECK_STR_EQ(error_message(EXT2_ET_CORRUPT_JOURNAL_SB),
             "Journal Superblock is corrupted");
}

TEST(error_message_no_gdesc)
{
CHECK_STR_EQ(error_message(EXT2_ET_NO_GDESC),
             "Group descriptors not loaded");
}

TEST(error_message_op_not_supported)
{
CHECK_STR_EQ(error_message(EXT2_ET_OP_NOT_SUPPORTED), "Operation not supported");
}

TEST(error_message_no_current_node)
{
CHECK_STR_EQ(error_message(EXT2_ET_NO_CURRENT_NODE), "No current node");
}

TEST(error_message_io_channel_no_64bit)
{
const char *msg = error_message(EXT2_ET_IO_CHANNEL_NO_SUPPORT_64);
CHECK(msg != NULL);
CHECK(strstr(msg, "64-bit") != NULL || strstr(msg, "64") != NULL);
CHECK(strstr(msg, "I/O") != NULL || strstr(msg, "Channel") != NULL);
}

TEST(error_message_unknown_in_base_range)
{
const char *msg = error_message(EXT2_ET_BASE + 500);
CHECK(msg != NULL);
CHECK(strstr(msg, "Unknown") != NULL || strstr(msg, "ext2") != NULL);
}

TEST(error_message_unknown_base_plus_one)
{
const char *msg = error_message(EXT2_ET_BASE + 1);
CHECK(msg != NULL);
CHECK(strlen(msg) > 0);
}

TEST(error_message_returns_non_null_for_all_known)
{
errcode_t codes[] = {
EXT2_ET_BAD_MAGIC, EXT2_ET_RO_FILSYS, EXT2_ET_TOOSMALL,
EXT2_ET_CANCEL_REQUESTED, EXT2_ET_INVALID_ARGUMENT,
EXT2_ET_FILE_NOT_FOUND, EXT2_ET_NO_JOURNAL, EXT2_ET_BAD_CRC,
EXT2_ET_FILESYSTEM_CORRUPTED, EXT2_ET_NO_GDESC,
};
for (size_t i = 0; i < sizeof(codes)/sizeof(codes[0]); i++)
CHECK(error_message(codes[i]) != NULL);
}

TEST(error_message_repeated_call_same_result)
{
const char *m1 = error_message(EXT2_ET_BAD_MAGIC);
const char *m2 = error_message(EXT2_ET_BAD_MAGIC);
CHECK(m1 != NULL);
CHECK(m2 != NULL);
CHECK_STR_EQ(m1, m2);
}

/* ================================================================
 * Tests for ext2fs_print_progress()
 * ================================================================ */

TEST(ext2fs_print_progress_no_error_returns_zero)
{
ErrorStatus = 0;
errcode_t r = ext2fs_print_progress(0, 100);
CHECK_INT_EQ((int)r, 0);
}

TEST(ext2fs_print_progress_with_values_returns_zero)
{
ErrorStatus = 0;
errcode_t r = ext2fs_print_progress(50, 100);
CHECK_INT_EQ((int)r, 0);
}

TEST(ext2fs_print_progress_at_max_returns_zero)
{
ErrorStatus = 0;
errcode_t r = ext2fs_print_progress(100, 100);
CHECK_INT_EQ((int)r, 0);
}

TEST(ext2fs_print_progress_cancelled_returns_cancel_code)
{
ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED);
errcode_t r = ext2fs_print_progress(50, 100);
CHECK_INT_EQ((int)r, (int)EXT2_ET_CANCEL_REQUESTED);
ErrorStatus = 0;
}

TEST(ext2fs_print_progress_generic_error_returns_cancel_code)
{
ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
errcode_t r = ext2fs_print_progress(1, 100);
CHECK_INT_EQ((int)r, (int)EXT2_ET_CANCEL_REQUESTED);
ErrorStatus = 0;
}

TEST(ext2fs_print_progress_zero_max_does_not_crash)
{
ErrorStatus = 0;
errcode_t r = ext2fs_print_progress(0, 0);
CHECK_INT_EQ((int)r, 0);
}

/* ================================================================
 * ext2_last_winerror() — always maps ext2 errors to ERROR_WRITE_FAULT
 * ================================================================ */

extern DWORD ext2_last_winerror(DWORD default_error);

TEST(ext2_last_winerror_returns_write_fault)
{
	DWORD r = ext2_last_winerror(0);
	/* Must return RUFUS_ERROR(ERROR_WRITE_FAULT) regardless of argument */
	CHECK(r == RUFUS_ERROR(ERROR_WRITE_FAULT));
}

TEST(ext2_last_winerror_ignores_argument)
{
	/* Passing different values must still return the same constant */
	DWORD r1 = ext2_last_winerror(0);
	DWORD r2 = ext2_last_winerror(ERROR_ACCESS_DENIED);
	DWORD r3 = ext2_last_winerror(0xDEADBEEF);
	CHECK(r1 == r2);
	CHECK(r2 == r3);
}

int main(void)
{
printf("=== ext2fs error_message() and progress tests ===\n");

RUN(error_message_bad_magic);
RUN(error_message_magic_variants_all_return_bad_magic);
RUN(error_message_read_only_filesystem);
RUN(error_message_bad_map_or_table);
RUN(error_message_unexpected_block_size);
RUN(error_message_read_write_errors);
RUN(error_message_no_space_left);
RUN(error_message_too_small);
RUN(error_message_bad_device_name);
RUN(error_message_superblock_corrupted);
RUN(error_message_unimplemented_feature);
RUN(error_message_seek_failed);
RUN(error_message_out_of_memory);
RUN(error_message_invalid_argument);
RUN(error_message_file_not_found);
RUN(error_message_file_exists);
RUN(error_message_cancel_requested);
RUN(error_message_journal_errors);
RUN(error_message_inode_errors);
RUN(error_message_checksum_errors);
RUN(error_message_filesystem_corrupted);
RUN(error_message_bad_crc);
RUN(error_message_journal_superblock_corrupted);
RUN(error_message_no_gdesc);
RUN(error_message_op_not_supported);
RUN(error_message_no_current_node);
RUN(error_message_io_channel_no_64bit);
RUN(error_message_unknown_in_base_range);
RUN(error_message_unknown_base_plus_one);
RUN(error_message_returns_non_null_for_all_known);
RUN(error_message_repeated_call_same_result);

RUN(ext2fs_print_progress_no_error_returns_zero);
RUN(ext2fs_print_progress_with_values_returns_zero);
RUN(ext2fs_print_progress_at_max_returns_zero);
RUN(ext2fs_print_progress_cancelled_returns_cancel_code);
RUN(ext2fs_print_progress_generic_error_returns_cancel_code);
RUN(ext2fs_print_progress_zero_max_does_not_crash);

RUN(ext2_last_winerror_returns_write_fault);
RUN(ext2_last_winerror_ignores_argument);

TEST_RESULTS();
}

#endif /* __linux__ */
