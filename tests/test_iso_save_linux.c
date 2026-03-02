/*
 * test_iso_save_linux.c — Tests for OpticalDiscSaveImage / IsoSaveImageThread
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2025 Rufus contributors
 *
 * Tests that the optical-disc-to-ISO save feature:
 *  - Reads a source device/file and writes it to a destination file
 *  - Reports correct byte counts
 *  - Posts UM_FORMAT_COMPLETED on completion
 *  - Handles null / missing inputs gracefully
 *  - Handles multi-chunk reads (data larger than BufSize)
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

/* ---- test framework ---- */
#include "framework.h"

/* ---- compat layer ---- */
#include "windows.h"
#include "commctrl.h"

/* ---- rufus headers ---- */
#include "rufus.h"
#include "resource.h"
#include "localization.h"

/* ================================================================
 * Required globals
 * ================================================================ */
HWND hMainDialog  = NULL;
HWND hDeviceList  = NULL;
HWND hProgress    = NULL;
HWND hStatus      = NULL;
HWND hInfo        = NULL;
HWND hLog         = NULL;

BOOL op_in_progress   = FALSE;
BOOL right_to_left_mode = FALSE;
BOOL preserve_timestamps   = FALSE;
BOOL enable_ntfs_compression = FALSE;
BOOL validate_md5sum       = FALSE;

DWORD ErrorStatus     = 0;
DWORD LastWriteError  = 0;
DWORD MainThreadId    = 0;
DWORD DownloadStatus  = 0;

uint64_t md5sum_totalbytes = 0;
HANDLE   format_thread     = NULL;
StrArray modified_files;

int fs_type       = 0;
int boot_type     = 0;
int partition_type = 0;
int target_type   = 0;
uint8_t image_options = 0;

char szFolderPath[MAX_PATH] = "";
char app_dir[MAX_PATH]      = "";
char temp_dir[MAX_PATH]     = "/tmp";
char app_data_dir[MAX_PATH] = "/tmp";
char user_dir[MAX_PATH]     = "/tmp";
char* image_path            = NULL;

RUFUS_DRIVE SelectedDrive   = { 0 };

/* Track PostMessage calls for UM_FORMAT_COMPLETED */
static UINT last_post_msg   = 0;
static WPARAM last_post_wparam = 0;
static int post_message_call_count = 0;

/* Track progress calls */
static int progress_call_count = 0;
static uint64_t last_progress_cur = 0;
static uint64_t last_progress_max = 0;

/* ================================================================
 * Stub implementations
 * ================================================================ */
/* uprintf, SizeToHumanReadable, uprint_progress are from stdio.c    */
/* lmprintf is from common/localization.c                            */
/* img_report is defined in iso.c                                    */

void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t max, BOOL force) {
	(void)op; (void)msg; (void)force;
	progress_call_count++;
	last_progress_cur = cur;
	last_progress_max = max;
}

LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
	(void)h; (void)m; (void)w; (void)l; return 0;
}
BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
	(void)h; (void)l;
	last_post_msg    = m;
	last_post_wparam = w;
	post_message_call_count++;
	return TRUE;
}

LONG GetEntryWidth(HWND h, const char* e) { (void)h; (void)e; return 0; }

/* ================================================================
 * Access to internal thread functions
 * ================================================================ */
/*
 * The worker thread is declared static in iso.c, so we can't call it
 * directly.  Instead we test through OpticalDiscSaveImage() + the
 * public IsoSaveImageThread wrapper, and also test a helper that runs
 * the save logic synchronously for unit testing purposes.
 */
extern void OpticalDiscSaveImage(void);
extern DWORD WINAPI IsoSaveImageThread(void* param);

/* iso_save_run_thread_sync: exposed only in RUFUS_TEST builds.
 * Runs the optical-disc save operation synchronously (no thread). */
extern DWORD iso_save_run_sync(IMG_SAVE* img_save);

/* ================================================================
 * Helpers
 * ================================================================ */

/* Create a temp file filled with repeated byte 'fill' of given size.
 * Returns malloc'd path, or NULL on failure.  Caller must free + unlink. */
static char* create_temp_file(size_t size, uint8_t fill)
{
	char* path = strdup("/tmp/rufus_isosvt_XXXXXX");
	if (!path) return NULL;
	int fd = mkstemp(path);
	if (fd < 0) { free(path); return NULL; }
	uint8_t buf[4096];
	memset(buf, fill, sizeof(buf));
	size_t written = 0;
	while (written < size) {
		size_t chunk = (size - written < sizeof(buf)) ? (size - written) : sizeof(buf);
		ssize_t n = write(fd, buf, chunk);
		if (n <= 0) { close(fd); free(path); return NULL; }
		written += (size_t)n;
	}
	close(fd);
	return path;
}

/* Return the size of a file, or -1 on error */
static int64_t file_size(const char* path)
{
	struct stat st;
	if (stat(path, &st) != 0) return -1;
	return (int64_t)st.st_size;
}

/* Return TRUE if first n bytes of file all equal 'expected' */
static BOOL file_all_bytes(const char* path, uint8_t expected, size_t n)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return FALSE;
	uint8_t buf[4096];
	size_t checked = 0;
	BOOL ok = TRUE;
	while (checked < n) {
		size_t want = (n - checked < sizeof(buf)) ? (n - checked) : sizeof(buf);
		ssize_t got = read(fd, buf, want);
		if (got <= 0) { ok = FALSE; break; }
		for (ssize_t i = 0; i < got; i++) {
			if (buf[i] != expected) { ok = FALSE; break; }
		}
		if (!ok) break;
		checked += (size_t)got;
	}
	close(fd);
	return ok;
}

/* Reset state before each test */
static void reset_state(void)
{
	ErrorStatus              = 0;
	last_post_msg            = 0;
	last_post_wparam         = 0;
	post_message_call_count  = 0;
	progress_call_count      = 0;
	last_progress_cur        = 0;
	last_progress_max        = 0;
}

/* ================================================================
 * Tests
 * ================================================================ */

/* 1. Null img_save pointer → sets ErrorStatus, posts UM_FORMAT_COMPLETED */
TEST(iso_save_null_param)
{
	reset_state();
	DWORD r = iso_save_run_sync(NULL);
	CHECK(r != 0);  /* non-zero exit = error */
	CHECK(IS_ERROR(ErrorStatus));
	CHECK_INT_EQ(post_message_call_count, 1);
	CHECK_INT_EQ((int)last_post_msg, (int)UM_FORMAT_COMPLETED);
}

/* 2. NULL DevicePath → fails cleanly */
TEST(iso_save_null_device_path)
{
	reset_state();
	IMG_SAVE s = { 0 };
	s.DevicePath = NULL;
	s.ImagePath  = strdup("/tmp/rufus_out_XXXXXX");
	s.DeviceSize = 512;
	s.BufSize    = 512;
	DWORD r = iso_save_run_sync(&s);
	CHECK(r != 0);
	CHECK(IS_ERROR(ErrorStatus));
	CHECK_INT_EQ(post_message_call_count, 1);
	free(s.ImagePath);
}

/* 3. NULL ImagePath → fails cleanly */
TEST(iso_save_null_image_path)
{
	reset_state();
	char* src = create_temp_file(512, 0xAB);
	if (!src) { printf("SKIP: could not create temp file\n"); return; }

	IMG_SAVE s = { 0 };
	s.DevicePath = src;   /* freed by iso_save_run_sync */
	s.ImagePath  = NULL;
	s.DeviceSize = 512;
	s.BufSize    = 512;
	DWORD r = iso_save_run_sync(&s);
	CHECK(r != 0);
	CHECK(IS_ERROR(ErrorStatus));
	CHECK_INT_EQ(post_message_call_count, 1);
	/* src already freed by iso_save_run_sync; just unlink the file */
	unlink(src);
}

/* 4. Device file doesn't exist → open fails */
TEST(iso_save_missing_source)
{
	reset_state();
	IMG_SAVE s = { 0 };
	s.DevicePath = strdup("/tmp/rufus_no_such_file_XXXXXXXX");
	s.ImagePath  = strdup("/tmp/rufus_isosvout_XXXXXX");
	s.DeviceSize = 512;
	s.BufSize    = 512;
	DWORD r = iso_save_run_sync(&s);
	CHECK(r != 0);
	CHECK(IS_ERROR(ErrorStatus));
	free(s.DevicePath);
	free(s.ImagePath);
}

/* 5. Zero-size source → succeeds, writes zero bytes */
TEST(iso_save_zero_size)
{
	reset_state();
	char* src = create_temp_file(0, 0x00);
	if (!src) { printf("SKIP: could not create temp file\n"); return; }
	char* dst = strdup("/tmp/rufus_isosv_out_XXXXXX");
	int fd = mkstemp(dst); if (fd >= 0) close(fd);

	IMG_SAVE s = { 0 };
	s.DevicePath = strdup(src);
	s.ImagePath  = strdup(dst);
	s.DeviceSize = 0;
	s.BufSize    = 4096;
	DWORD r = iso_save_run_sync(&s);
	CHECK_INT_EQ((int)r, 0);
	CHECK(!IS_ERROR(ErrorStatus));
	CHECK_INT_EQ((int)file_size(dst), 0);
	CHECK_INT_EQ(post_message_call_count, 1);
	unlink(src); unlink(dst); free(src); free(dst);
}

/* 6. Correct data copy — small file (512 bytes, all 0xCC) */
TEST(iso_save_copies_data_correctly)
{
	reset_state();
	const size_t DATA_SIZE = 512;
	char* src = create_temp_file(DATA_SIZE, 0xCC);
	if (!src) { printf("SKIP: could not create temp file\n"); return; }
	char* dst = strdup("/tmp/rufus_isosv_out_XXXXXX");
	int fd = mkstemp(dst); if (fd >= 0) close(fd);

	IMG_SAVE s = { 0 };
	s.DevicePath = strdup(src);
	s.ImagePath  = strdup(dst);
	s.DeviceSize = (LONGLONG)DATA_SIZE;
	s.BufSize    = 4096;  /* buffer larger than data */
	DWORD r = iso_save_run_sync(&s);
	CHECK_INT_EQ((int)r, 0);
	CHECK(!IS_ERROR(ErrorStatus));
	CHECK_INT_EQ((int)file_size(dst), (int)DATA_SIZE);
	CHECK(file_all_bytes(dst, 0xCC, DATA_SIZE));
	CHECK_INT_EQ(post_message_call_count, 1);
	unlink(src); unlink(dst); free(src); free(dst);
}

/* 7. Multi-chunk read — data larger than BufSize */
TEST(iso_save_multi_chunk)
{
	reset_state();
	const size_t DATA_SIZE = 64 * 1024;  /* 64 KiB */
	const DWORD  BUF_SIZE  = 8 * 1024;   /* 8 KiB per read */
	char* src = create_temp_file(DATA_SIZE, 0xA5);
	if (!src) { printf("SKIP: could not create temp file\n"); return; }
	char* dst = strdup("/tmp/rufus_isosv_out_XXXXXX");
	int fd = mkstemp(dst); if (fd >= 0) close(fd);

	IMG_SAVE s = { 0 };
	s.DevicePath = strdup(src);
	s.ImagePath  = strdup(dst);
	s.DeviceSize = (LONGLONG)DATA_SIZE;
	s.BufSize    = BUF_SIZE;
	DWORD r = iso_save_run_sync(&s);
	CHECK_INT_EQ((int)r, 0);
	CHECK(!IS_ERROR(ErrorStatus));
	CHECK_INT_EQ((int)file_size(dst), (int)DATA_SIZE);
	CHECK(file_all_bytes(dst, 0xA5, DATA_SIZE));
	/* Should have been called at least ceil(DATA_SIZE / BUF_SIZE) times */
	CHECK(progress_call_count >= (int)(DATA_SIZE / BUF_SIZE));
	unlink(src); unlink(dst); free(src); free(dst);
}

/* 8. Progress is reported with correct max */
TEST(iso_save_progress_max_correct)
{
	reset_state();
	const size_t DATA_SIZE = 1024;
	char* src = create_temp_file(DATA_SIZE, 0x55);
	if (!src) { printf("SKIP: could not create temp file\n"); return; }
	char* dst = strdup("/tmp/rufus_isosv_out_XXXXXX");
	int fd = mkstemp(dst); if (fd >= 0) close(fd);

	IMG_SAVE s = { 0 };
	s.DevicePath = strdup(src);
	s.ImagePath  = strdup(dst);
	s.DeviceSize = (LONGLONG)DATA_SIZE;
	s.BufSize    = 256;
	iso_save_run_sync(&s);
	/* Last progress call should have max == DeviceSize */
	CHECK_INT_EQ((int)last_progress_max, (int)DATA_SIZE);
	unlink(src); unlink(dst); free(src); free(dst);
}

/* 9. UM_FORMAT_COMPLETED always posted even on error */
TEST(iso_save_completion_posted_on_error)
{
	reset_state();
	IMG_SAVE s = { 0 };
	s.DevicePath = strdup("/tmp/rufus_no_such_XXXXXXXXXX");
	s.ImagePath  = strdup("/tmp/rufus_isosv_out_XXXXXX");
	s.DeviceSize = 512;
	s.BufSize    = 512;
	iso_save_run_sync(&s);
	CHECK_INT_EQ(post_message_call_count, 1);
	CHECK_INT_EQ((int)last_post_msg, (int)UM_FORMAT_COMPLETED);
	free(s.DevicePath);
	free(s.ImagePath);
}

/* 10. OpticalDiscSaveImage returns early when op_in_progress is set */
TEST(optical_disc_save_busy)
{
	reset_state();
	op_in_progress = TRUE;
	/* Should return immediately without crashing */
	OpticalDiscSaveImage();
	op_in_progress = FALSE;
	CHECK_INT_EQ(post_message_call_count, 0);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
	/* Initialize localization so lmprintf doesn't crash on uninitialized msg_table */
	msg_table = default_msg_table;

	StrArrayCreate(&modified_files, 8);

	RUN(iso_save_null_param);
	RUN(iso_save_null_device_path);
	RUN(iso_save_null_image_path);
	RUN(iso_save_missing_source);
	RUN(iso_save_zero_size);
	RUN(iso_save_copies_data_correctly);
	RUN(iso_save_multi_chunk);
	RUN(iso_save_progress_max_correct);
	RUN(iso_save_completion_posted_on_error);
	RUN(optical_disc_save_busy);

	StrArrayDestroy(&modified_files);
	TEST_RESULTS();
}

#endif /* __linux__ */
