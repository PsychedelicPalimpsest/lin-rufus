/*
 * test_image_scan_linux.c — Tests for ImageScanThread (Linux)
 *
 * Verifies that ImageScanThread correctly scans an ISO image and populates
 * img_report.  Tests run with both NULL and real ISO paths.
 *
 * A minimal ISO is generated via Python/pycdlib if available; ISO-specific
 * tests are gracefully skipped when pycdlib is not installed.
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
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

/* ---- test framework ---- */
#include "framework.h"

/* ---- compat layer ---- */
#include "windows.h"
#include "commctrl.h"

/* ---- wimlib apply ops stub (needed by libwim.a on Linux) ---- */
#include "../src/wimlib/wimlib/apply.h"
const struct apply_operations unix_apply_ops = {
	.name = "unix-stub",
	.get_supported_features = NULL,
	.extract = NULL,
	.context_size = 0,
};

/* AnalyzeMBR stub — referenced by vhd.c */
BOOL AnalyzeMBR(HANDLE h, const char* name, BOOL s)
{
	(void)h; (void)name; (void)s;
	return FALSE;
}

/* HashFile stub — referenced by vhd.c WimProgressFunc */
BOOL HashFile(unsigned type, const char* path, uint8_t* sum)
{
	(void)type; (void)path; (void)sum;
	return FALSE;
}

/* ---- rufus headers ---- */
#include "rufus.h"
#include "resource.h"

/* ================================================================
 * Globals — model after test_iso_linux.c so iso.c compiles cleanly.
 *
 * img_report is DEFINED by iso.c (line 52).
 * image_path is defined here (iso.c externs it from globals.c, which
 * we are not compiling in this test binary).
 * ================================================================ */

/* Window handles */
HWND hMainDialog      = NULL;
HWND hDeviceList      = NULL;
HWND hProgress        = NULL;
HWND hStatus          = NULL;
HWND hInfo            = NULL;
HWND hLog             = NULL;
HWND hBootType        = NULL;
HWND hFileSystem      = NULL;
HWND hPartitionScheme = NULL;
HWND hTargetSystem    = NULL;
HWND hImageOption     = NULL;

/* State */
BOOL op_in_progress      = FALSE;
BOOL enable_HDDs         = FALSE;
BOOL enable_VHDs         = TRUE;
BOOL right_to_left_mode  = FALSE;

DWORD ErrorStatus        = 0;
DWORD LastWriteError     = 0;
DWORD MainThreadId       = 0;
DWORD DownloadStatus     = 0;

int fs_type              = 0;
int boot_type            = 0;
int partition_type       = 0;
int target_type          = 0;
uint8_t image_options    = 0;

char szFolderPath[MAX_PATH]  = "";
char app_dir[MAX_PATH]       = "";
char temp_dir[MAX_PATH]      = "/tmp";
char app_data_dir[MAX_PATH]  = "/tmp";
char system_dir[MAX_PATH]    = "/tmp";
char sysnative_dir[MAX_PATH] = "/tmp";
char user_dir[MAX_PATH]      = "/tmp";
char *image_path             = NULL;   /* read/written by ImageScanThread */
char *fido_url               = NULL;
uint64_t persistence_size    = 0;

BOOL large_drive               = FALSE;
BOOL write_as_esp              = FALSE;
BOOL write_as_image            = FALSE;
BOOL lock_drive                = FALSE;
BOOL zero_drive                = FALSE;
BOOL fast_zeroing              = FALSE;
BOOL force_large_fat32         = FALSE;
BOOL enable_ntfs_compression   = FALSE;
BOOL enable_file_indexing      = FALSE;
BOOL preserve_timestamps       = FALSE;
BOOL validate_md5sum           = FALSE;
BOOL cpu_has_sha1_accel        = FALSE;
BOOL cpu_has_sha256_accel      = FALSE;
BOOL dont_display_image_name   = FALSE;
BOOL write_as_esp_2            = FALSE;
BOOL ignore_boot_marker        = FALSE;
BOOL has_ffu_support           = FALSE;

int imop_win_sel               = 0;
int selection_default          = 0;

uint64_t md5sum_totalbytes = 0;
HANDLE format_thread       = NULL;
StrArray modified_files;           /* extern'd by iso.c */
RUFUS_DRIVE rufus_drive[MAX_DRIVES];

/* ================================================================
 * PostMessage intercept — count UM_IMAGE_SCANNED notifications
 * ================================================================ */
static int  g_post_count   = 0;
static UINT g_last_msg     = 0;

BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{
	(void)h; (void)w; (void)l;
	g_post_count++;
	g_last_msg = m;
	return TRUE;
}

LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{
	(void)h; (void)m; (void)w; (void)l;
	return 0;
}

/* ================================================================
 * Stubs for UI functions called by ImageScanThread
 * ================================================================ */
void EnableControls(BOOL e, BOOL r)              { (void)e; (void)r; }
void UpdateImage(BOOL b)                         { (void)b; }
void SetFSFromISO(void)                          {}
void SetProposedLabel(int i)                     { (void)i; }
void PopulateProperties(void)                    {}
void SetPartitionSchemeAndTargetSystem(BOOL b)   { (void)b; }
void SetFileSystemAndClusterSize(const char* s)  { (void)s; }
void DisplayISOProps(void)                       {}
BOOL PopulateWindowsVersion(void)                { return FALSE; }
/* GetBootladerInfo is defined in image_scan.c; provide its dependencies */
BOOL IsSignedBySecureBootAuthority(uint8_t* buf, uint32_t len)
{ (void)buf; (void)len; return FALSE; }
int  IsBootloaderRevoked(uint8_t* buf, uint32_t len)
{ (void)buf; (void)len; return 0; }

int NotificationEx(int t, const char* s, const notification_info* i,
                   const char* title, const char* fmt, ...)
{
	(void)t; (void)s; (void)i; (void)title; (void)fmt;
	return IDOK;
}
#define Notification(type, title, fmt, ...) \
	NotificationEx((type), NULL, NULL, (title), (fmt), ##__VA_ARGS__)

/* grub_filesystems / config_path / isolinux_path come from iso.c */
extern StrArray grub_filesystems;

/* ================================================================
 * Test ISO generation
 * ================================================================ */
#define TEST_ISO_PATH   "/tmp/test_rufus_scan.iso"

static int test_iso_available = 0;

static void setup_test_iso(void)
{
	const char *script =
		"python3 -c \""
		"import pycdlib, io\n"
		"iso = pycdlib.PyCdlib()\n"
		"iso.new(interchange_level=1, joliet=3, rock_ridge='1.09', vol_ident='SCANTEST')\n"
		"c1 = b'Hello, scan test!\\n'\n"
		"iso.add_fp(io.BytesIO(c1), len(c1), '/HELLO.TXT;1', joliet_path='/hello.txt', rr_name='hello.txt')\n"
		"iso.write('/tmp/test_rufus_scan.iso')\n"
		"iso.close()\n"
		"\"";
	int rc = system(script);
	struct stat st;
	if (rc == 0 && stat(TEST_ISO_PATH, &st) == 0 && st.st_size > 0)
		test_iso_available = 1;
}

static void cleanup_test_iso(void)
{
	unlink(TEST_ISO_PATH);
}

/* ================================================================
 * Access to globals defined in iso.c (via extern)
 * ================================================================ */
extern RUFUS_IMG_REPORT img_report;   /* defined in iso.c */
extern DWORD WINAPI ImageScanThread(LPVOID param); /* defined in image_scan.c */

/* Helper: run ImageScanThread as a real OS thread and wait for it */
static void run_scan_thread(void)
{
	HANDLE thr = CreateThread(NULL, 0, ImageScanThread, NULL, 0, NULL);
	if (thr == NULL || thr == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "FATAL: CreateThread failed\n");
		return;
	}
	WaitForSingleObject(thr, 15000); /* 15 s */
	CloseHandle(thr);
}

/* ================================================================
 * Tests
 * ================================================================ */

/* ImageScanThread with NULL image_path must return quickly without crash */
TEST(image_scan_null_path_noop)
{
	char *saved = image_path;
	image_path = NULL;
	memset(&img_report, 0, sizeof(img_report));
	g_post_count = 0;

	run_scan_thread();

	/* img_report stays zeroed */
	CHECK_INT_EQ(0, (int)img_report.is_iso);
	CHECK_INT_EQ(0, (int)img_report.image_size);
	/* No UM_IMAGE_SCANNED posted when path is NULL */
	CHECK_INT_EQ(0, g_post_count);

	image_path = saved;
}

/* ImageScanThread with a non-existent path: is_iso stays FALSE */
TEST(image_scan_invalid_path_not_iso)
{
	char *saved = image_path;
	image_path = "/nonexistent/totally/fake/path.iso";
	memset(&img_report, 0, sizeof(img_report));
	g_post_count = 0;

	run_scan_thread();

	CHECK_INT_EQ(0, (int)img_report.is_iso);
	/* UM_IMAGE_SCANNED is still posted so the UI can reset */
	CHECK_INT_EQ(1, g_post_count);
	CHECK_INT_EQ((int)UM_IMAGE_SCANNED, (int)g_last_msg);

	image_path = saved;
}

/* ImageScanThread with a valid ISO sets is_iso to TRUE */
TEST(image_scan_iso_sets_is_iso)
{
	if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }

	char *saved = image_path;
	image_path = TEST_ISO_PATH;
	memset(&img_report, 0, sizeof(img_report));

	run_scan_thread();

	CHECK_INT_EQ(1, (int)img_report.is_iso);

	image_path = saved;
}

/* After scan of valid ISO, img_report.label is non-empty */
TEST(image_scan_iso_label_populated)
{
	if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }

	char *saved = image_path;
	image_path = TEST_ISO_PATH;
	memset(&img_report, 0, sizeof(img_report));

	run_scan_thread();

	CHECK(img_report.label[0] != '\0');

	image_path = saved;
}

/* After scan of valid ISO, image_size > 0 */
TEST(image_scan_iso_size_nonzero)
{
	if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }

	char *saved = image_path;
	image_path = TEST_ISO_PATH;
	memset(&img_report, 0, sizeof(img_report));

	run_scan_thread();

	CHECK(img_report.image_size > 0);

	image_path = saved;
}

/* UM_IMAGE_SCANNED is posted after a successful scan */
TEST(image_scan_posts_um_image_scanned)
{
	if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }

	char *saved = image_path;
	image_path = TEST_ISO_PATH;
	memset(&img_report, 0, sizeof(img_report));
	g_post_count = 0;
	g_last_msg   = 0;

	run_scan_thread();

	CHECK_INT_EQ(1, g_post_count);
	CHECK_INT_EQ((int)UM_IMAGE_SCANNED, (int)g_last_msg);

	image_path = saved;
}

/* ImageScanThread works correctly as a real OS thread (redundant sanity check) */
TEST(image_scan_runs_as_thread)
{
	if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }

	char *saved = image_path;
	image_path = TEST_ISO_PATH;
	memset(&img_report, 0, sizeof(img_report));

	HANDLE thr = CreateThread(NULL, 0, ImageScanThread, NULL, 0, NULL);
	CHECK(thr != NULL && thr != INVALID_HANDLE_VALUE);

	DWORD wait = WaitForSingleObject(thr, 10000); /* 10 s */
	CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)wait);
	CloseHandle(thr);

	/* Thread should have populated img_report */
	CHECK_INT_EQ(1, (int)img_report.is_iso);

	image_path = saved;
}

int main(void)
{
	setup_test_iso();

	RUN(image_scan_null_path_noop);
	RUN(image_scan_invalid_path_not_iso);
	RUN(image_scan_iso_sets_is_iso);
	RUN(image_scan_iso_label_populated);
	RUN(image_scan_iso_size_nonzero);
	RUN(image_scan_posts_um_image_scanned);
	RUN(image_scan_runs_as_thread);

	cleanup_test_iso();
	TEST_RESULTS();
}

#endif /* __linux__ */
