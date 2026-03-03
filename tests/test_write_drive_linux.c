/*
 * test_write_drive_linux.c — TDD tests for compressed image writing
 *
 * Tests for format_linux_write_drive() compressed path: verifies that
 * bled decompression (gz, xz, bz2) writes the correct bytes to the dst fd.
 *
 * All tests use ordinary temp files — no real block device needed.
 *
 * Copyright © 2025 PsychedelicPalimpsest
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
#include "format_linux.h"
#include "bled/bled.h"
#include "framework.h"

/* ================================================================
 * Globals required by format.c / drive.c externs
 * ================================================================ */

RUFUS_DRIVE      rufus_drive[MAX_DRIVES];
RUFUS_IMG_REPORT img_report = {0};

extern RUFUS_DRIVE_INFO SelectedDrive;
extern int              partition_index[PI_MAX];

/* UI handles */
HWND hMainDialog  = NULL;
HWND hDeviceList  = NULL;
HWND hProgress    = NULL;
HWND hStatus      = NULL;
HWND hInfo        = NULL;
HWND hLog         = NULL;
HWND hImageOption = NULL;
HWND hLabel       = NULL;
HWND hMultiToolbar = NULL, hSaveToolbar = NULL, hHashToolbar = NULL;
HWND hAdvancedDeviceToolbar = NULL, hAdvancedFormatToolbar = NULL;

/* Boolean flags */
BOOL zero_drive             = FALSE;
BOOL fast_zeroing           = FALSE;
BOOL force_large_fat32      = FALSE;
BOOL enable_ntfs_compression= FALSE;
BOOL enable_file_indexing   = FALSE;
BOOL write_as_image         = FALSE;
BOOL write_as_esp           = FALSE;
BOOL lock_drive             = FALSE;
BOOL enable_bad_blocks      = FALSE;
BOOL quick_format           = TRUE;
BOOL use_rufus_mbr          = TRUE;
BOOL use_old_bios_fixes     = FALSE;
BOOL use_extended_label     = FALSE;
BOOL enable_verify_write    = FALSE;
BOOL allow_dual_uefi_bios   = FALSE;
BOOL ignore_boot_marker     = FALSE;
BOOL has_ffu_support        = FALSE;

/* Error/status */
DWORD ErrorStatus    = 0;
DWORD LastWriteError = 0;
DWORD MainThreadId   = 0;
DWORD DownloadStatus = 0;
DWORD _win_last_error= 0;

/* FS / boot */
int     fs_type      = 0;
int     boot_type    = 0;
int     partition_type = 0;
int     target_type  = 0;
uint8_t image_options = 0;
int     nb_passes_sel = 0;

/* Path buffers */
char szFolderPath[MAX_PATH]  = "";
char app_dir[MAX_PATH]       = "";
char temp_dir[MAX_PATH]      = "/tmp";
char cur_dir[MAX_PATH]       = "";
char app_data_dir[MAX_PATH]  = "";
char user_dir[MAX_PATH]      = "";
char system_dir[MAX_PATH]    = "";
char sysnative_dir[MAX_PATH] = "";
char msgbox[1024]            = "";
char msgbox_title[32]        = "";
char image_option_txt[128]   = "";
char ubuffer[UBUFFER_SIZE]   = "";
char embedded_sl_version_str[2][12] = {"", ""};
char embedded_sl_version_ext[2][32] = {"", ""};
char ClusterSizeLabel[MAX_CLUSTER_SIZES][64];

/* Heap pointers */
char *ini_file        = NULL;
char *image_path      = NULL;
char *archive_path    = NULL;
char *fido_url        = NULL;
char *save_image_type = NULL;
char *sbat_level_txt  = NULL;
char *sb_active_txt   = NULL;
char *sb_revoked_txt  = NULL;

/* Misc */
float    fScale               = 1.0f;
int      dialog_showing       = 0;
int      force_update         = 0;
int      selection_default    = 0;
int      persistence_unit_selection = -1;
uint64_t persistence_size     = 0;
int64_t  iso_blocking_status  = -1;
uint32_t pe256ssp_size        = 0;
uint8_t *pe256ssp             = NULL;
uint16_t rufus_version[3]     = {0, 0, 0};
uint16_t embedded_sl_version[2] = {0, 0};
uint32_t dur_mins = 0, dur_secs = 0;
BOOL     large_drive          = FALSE;
BOOL     has_uefi_csm = FALSE, its_a_me_mario = FALSE;
BOOL     enable_vmdk = FALSE;
BOOL     use_fake_units = FALSE, preserve_timestamps = FALSE;
BOOL     app_changed_size = FALSE;
BOOL     list_non_usb_removable_drives = FALSE;
BOOL     no_confirmation_on_cancel = FALSE;
BOOL     advanced_mode_device = FALSE, advanced_mode_format = FALSE;
unsigned long syslinux_ldlinux_len[2] = {0, 0};

sbat_entry_t      *sbat_entries     = NULL;
thumbprint_list_t *sb_active_certs  = NULL;
thumbprint_list_t *sb_revoked_certs = NULL;
RUFUS_UPDATE update = {{0, 0, 0}, {0, 0}, NULL, NULL};
HINSTANCE hMainInstance = NULL;

const char *md5sum_name[2]   = {"md5sum.txt", "md5sum.txt~"};
FILE       *fd_md5sum        = NULL;
uint64_t    total_blocks = 0, extra_blocks = 0;
uint64_t    nb_blocks = 0,    last_nb_blocks = 0;
int         unattend_xml_flags = 0;
int         wintogo_index    = -1;
char       *unattend_xml_path = NULL;

const char *FileSystemLabel[FS_MAX] = {
	"FAT", "FAT32", "NTFS", "UDF", "exFAT", "ReFS", "ext2", "ext3", "ext4"
};
const int nb_steps[FS_MAX] = { 5, 5, 5, 5, 5, 5, 5, 5, 5 };

uint8_t *grub2_buf = NULL;
long     grub2_len = 0;
uint8_t *sec_buf   = NULL;

/* ================================================================
 * Stub functions
 * ================================================================ */

void UpdateProgress(int op, float pct) { (void)op; (void)pct; }

#undef UpdateProgressWithInfo
#undef UpdateProgressWithInfoUpTo
#undef UpdateProgressWithInfoForce
#undef UpdateProgressWithInfoInit
void _UpdateProgressWithInfo(int op, int msg, uint64_t c, uint64_t t, BOOL f)
{ (void)op; (void)msg; (void)c; (void)t; (void)f; }
void uprint_progress(uint64_t cur, uint64_t max) { (void)cur; (void)max; }
void InitProgress(BOOL b) { (void)b; }

void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s) { (void)s; }
void PrintStatusInfo(BOOL lo, BOOL de, unsigned int dur, int mid, ...)
{ (void)lo; (void)de; (void)dur; (void)mid; }

const char *WindowsErrorString(void) { return strerror(errno); }
char *lmprintf(int id, ...) { (void)id; return ""; }

LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return 0; }
BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return FALSE; }

char *SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units)
{
	static char buf[32];
	static const char *suf[] = { "B", "KB", "MB", "GB", "TB" };
	double hr = (double)size; int s = 0;
	const double div = fake_units ? 1000.0 : 1024.0;
	(void)copy_to_log;
	while (s < 4 && hr >= div) { hr /= div; s++; }
	snprintf(buf, sizeof(buf), "%.1f %s", hr, suf[s]);
	return buf;
}

BOOL WriteFileWithRetry(HANDLE h, const void *buf, DWORD n, DWORD *written, DWORD retries)
{
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

LONG GetEntryWidth(HWND h, const char *e) { (void)h; (void)e; return 0; }
BOOL IsCurrentProcessElevated(void) { return FALSE; }

char *GuidToString(const GUID *g, BOOL d) { (void)g; (void)d; return NULL; }
GUID *StringToGuid(const char *s) { (void)s; return NULL; }
DWORD RunCommandWithProgress(const char *c, const char *d, BOOL l, int m, const char *p)
{ (void)c; (void)d; (void)l; (void)m; (void)p; return ERROR_NOT_SUPPORTED; }
BOOL CompareGUID(const GUID *a, const GUID *b)
{
	if (!a || !b) return FALSE;
	return (__builtin_memcmp(a, b, sizeof(GUID)) == 0) ? TRUE : FALSE;
}
char *get_token_data_file_indexed(const char *t, const char *f, int i)
{ (void)t; (void)f; (void)i; return NULL; }
BOOL BadBlocks(HANDLE h, ULONGLONG sz, int np, int ft, void *r, FILE *fd)
{ (void)h; (void)sz; (void)np; (void)ft; (void)r; (void)fd; return TRUE; }
int NotificationEx(int t, const char *s, const notification_info *i,
                   const char *title, const char *fmt, ...)
{ (void)t; (void)s; (void)i; (void)title; (void)fmt; return IDOK; }
BOOL InstallSyslinux(DWORD di, char dl, int fs)
{ (void)di; (void)dl; (void)fs; return TRUE; }
BOOL verify_write_pass(const char *p, int f, uint64_t sz)
{ (void)p; (void)f; (void)sz; return TRUE; }
void wue_set_mount_path(const char *p) { (void)p; }
BOOL SetupWinPE(char d) { (void)d; return TRUE; }
BOOL ApplyWindowsCustomization(char d, int f) { (void)d; (void)f; return FALSE; }
BOOL SetupWinToGo(DWORD di, const char *dn, BOOL ue)
{ (void)di; (void)dn; (void)ue; return TRUE; }
BOOL ExtractDOS(const char *p) { (void)p; return TRUE; }
int64_t ExtractISOFile(const char *i, const char *if2, const char *d, uint32_t a)
{ (void)i; (void)if2; (void)d; (void)a; return 0; }
void UpdateMD5Sum(const char *dd, const char *mn) { (void)dd; (void)mn; }
BOOL CopySKUSiPolicy(const char *dn) { (void)dn; return FALSE; }
BOOL ExtractZip(const char *s, const char *d) { (void)s; (void)d; return TRUE; }
BOOL SetAutorun(const char *p) { (void)p; return TRUE; }
BOOL ExtractAppIcon(const char *p, BOOL bs) { (void)p; (void)bs; return FALSE; }
BOOL HashFile(unsigned t, const char *p, uint8_t *s)
{ (void)t; (void)p; (void)s; return FALSE; }
void wuprintf(const wchar_t *fmt, ...) { (void)fmt; }
BOOL ExtractISO(const char *s, const char *d, BOOL so)
{ (void)s; (void)d; (void)so; return TRUE; }

/* ================================================================
 * Helpers
 * ================================================================ */

/* Create a named temp file with data; returns malloc'd path (caller: unlink+free). */
static char *make_named_tmpfile(const uint8_t *data, size_t len)
{
	char *path = (char *)malloc(64);
	if (!path) return NULL;
	snprintf(path, 64, "/tmp/rufus_raw_XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) { free(path); return NULL; }
	if (len > 0 && write(fd, data, len) != (ssize_t)len) {
		close(fd); unlink(path); free(path); return NULL;
	}
	close(fd);
	return path;
}

/* Create an anonymous temp file, optionally pre-filled to size bytes.
 * Returns open fd (unlinked); caller must close(). */
static int make_dst_fd(size_t size)
{
	char tmpl[] = "/tmp/rufus_dst_XXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0) return -1;
	unlink(tmpl);
	if (size > 0)
		ftruncate(fd, (off_t)size);
	return fd;
}

/* Compress raw_path using 'tool -c > out_path'.
 * Returns malloc'd path with appropriate extension, or NULL. */
static char *compress_file(const char *raw_path, const char *tool,
                            const char *ext)
{
	char *out = (char *)malloc(128);
	if (!out) return NULL;
	snprintf(out, 128, "/tmp/rufus_comp_XXXXXX");
	int tmp_fd = mkstemp(out);
	if (tmp_fd < 0) { free(out); return NULL; }
	close(tmp_fd);
	unlink(out);
	strncat(out, ext, 128 - strlen(out) - 1);

	char cmd[512];
	snprintf(cmd, sizeof(cmd), "%s -c '%s' > '%s' 2>/dev/null", tool, raw_path, out);
	if (system(cmd) != 0) { free(out); return NULL; }
	return out;
}

/* ================================================================
 * Tests
 * ================================================================ */

/* NULL handle → FALSE, no crash */
TEST(write_drive_null_handle_returns_false)
{
	uint8_t raw[512] = {0};
	char *p = make_named_tmpfile(raw, sizeof(raw));
	CHECK(p != NULL);
	image_path = p;
	img_report.compression_type = BLED_COMPRESSION_NONE;

	CHECK(format_linux_write_drive(NULL, FALSE) == FALSE);

	unlink(p); free(p);
}

/* INVALID_HANDLE_VALUE → FALSE */
TEST(write_drive_invalid_handle_returns_false)
{
	uint8_t raw[512] = {0};
	char *p = make_named_tmpfile(raw, sizeof(raw));
	CHECK(p != NULL);
	image_path = p;
	img_report.compression_type = BLED_COMPRESSION_NONE;

	CHECK(format_linux_write_drive(INVALID_HANDLE_VALUE, FALSE) == FALSE);

	unlink(p); free(p);
}

/* NULL image_path → FALSE + ErrorStatus set */
TEST(write_drive_null_image_path_returns_false)
{
	int dst = make_dst_fd(512);
	CHECK(dst >= 0);
	image_path = NULL;
	img_report.compression_type = BLED_COMPRESSION_NONE;
	ErrorStatus = 0;

	BOOL ret = format_linux_write_drive((HANDLE)(intptr_t)dst, FALSE);
	CHECK(ret == FALSE);
	CHECK(ErrorStatus != 0);

	close(dst);
}

/* Uncompressed copy: bytes must match exactly */
TEST(write_drive_uncompressed_copies_exact_bytes)
{
	uint8_t raw[1024];
	for (size_t i = 0; i < sizeof(raw); i++)
		raw[i] = (uint8_t)(i & 0xFF);

	char *p = make_named_tmpfile(raw, sizeof(raw));
	CHECK(p != NULL);

	int dst = make_dst_fd(sizeof(raw));
	CHECK(dst >= 0);

	image_path = p;
	img_report.compression_type = BLED_COMPRESSION_NONE;
	img_report.image_size = sizeof(raw);

	BOOL ret = format_linux_write_drive((HANDLE)(intptr_t)dst, FALSE);
	CHECK(ret == TRUE);

	uint8_t out[sizeof(raw)];
	CHECK(pread(dst, out, sizeof(out), 0) == (ssize_t)sizeof(out));
	CHECK(memcmp(raw, out, sizeof(raw)) == 0);

	close(dst);
	unlink(p); free(p);
}

/* Missing source file → FALSE + ErrorStatus set */
TEST(write_drive_missing_source_returns_false)
{
	int dst = make_dst_fd(4096);
	CHECK(dst >= 0);

	image_path = "/tmp/rufus_no_such_file_99999.img";
	img_report.compression_type = BLED_COMPRESSION_NONE;
	ErrorStatus = 0;

	BOOL ret = format_linux_write_drive((HANDLE)(intptr_t)dst, FALSE);
	CHECK(ret == FALSE);
	CHECK(ErrorStatus != 0);

	close(dst);
}

/* gz: decompress must yield the original bytes */
TEST(write_drive_gz_decompresses_correctly)
{
	SKIP_IF(system("gzip --version >/dev/null 2>&1") != 0);

	uint8_t raw[4096];
	for (size_t i = 0; i < sizeof(raw); i++)
		raw[i] = (uint8_t)((i * 7 + 3) & 0xFF);

	char *p = make_named_tmpfile(raw, sizeof(raw));
	CHECK(p != NULL);
	char *gz = compress_file(p, "gzip", ".gz");
	unlink(p); free(p);
	CHECK(gz != NULL);

	int dst = make_dst_fd(sizeof(raw));
	CHECK(dst >= 0);

	image_path = gz;
	img_report.compression_type = BLED_COMPRESSION_GZIP;
	img_report.image_size = sizeof(raw);

	ErrorStatus = 0;
	BOOL ret = format_linux_write_drive((HANDLE)(intptr_t)dst, FALSE);
	CHECK(ret == TRUE);

	uint8_t out[sizeof(raw)];
	CHECK(pread(dst, out, sizeof(out), 0) == (ssize_t)sizeof(out));
	CHECK(memcmp(raw, out, sizeof(raw)) == 0);

	close(dst);
	unlink(gz); free(gz);
}

/* bz2: decompress must yield the original bytes */
TEST(write_drive_bz2_decompresses_correctly)
{
	SKIP_IF(system("bzip2 --version >/dev/null 2>&1") != 0);

	uint8_t raw[4096];
	for (size_t i = 0; i < sizeof(raw); i++)
		raw[i] = (uint8_t)((i * 13 + 5) & 0xFF);

	char *p = make_named_tmpfile(raw, sizeof(raw));
	CHECK(p != NULL);
	char *bz2 = compress_file(p, "bzip2", ".bz2");
	unlink(p); free(p);
	CHECK(bz2 != NULL);

	int dst = make_dst_fd(sizeof(raw));
	CHECK(dst >= 0);

	image_path = bz2;
	img_report.compression_type = BLED_COMPRESSION_BZIP2;
	img_report.image_size = sizeof(raw);
	ErrorStatus = 0;

	BOOL ret = format_linux_write_drive((HANDLE)(intptr_t)dst, FALSE);
	CHECK(ret == TRUE);

	uint8_t out[sizeof(raw)];
	CHECK(pread(dst, out, sizeof(out), 0) == (ssize_t)sizeof(out));
	CHECK(memcmp(raw, out, sizeof(raw)) == 0);

	close(dst);
	unlink(bz2); free(bz2);
}

/* xz: decompress must yield the original bytes */
TEST(write_drive_xz_decompresses_correctly)
{
	SKIP_IF(system("xz --version >/dev/null 2>&1") != 0);

	uint8_t raw[4096];
	for (size_t i = 0; i < sizeof(raw); i++)
		raw[i] = (uint8_t)((i * 17 + 7) & 0xFF);

	char *p = make_named_tmpfile(raw, sizeof(raw));
	CHECK(p != NULL);
	char *xz = compress_file(p, "xz", ".xz");
	unlink(p); free(p);
	CHECK(xz != NULL);

	int dst = make_dst_fd(sizeof(raw));
	CHECK(dst >= 0);

	image_path = xz;
	img_report.compression_type = BLED_COMPRESSION_XZ;
	img_report.image_size = sizeof(raw);
	ErrorStatus = 0;

	BOOL ret = format_linux_write_drive((HANDLE)(intptr_t)dst, FALSE);
	CHECK(ret == TRUE);

	uint8_t out[sizeof(raw)];
	CHECK(pread(dst, out, sizeof(out), 0) == (ssize_t)sizeof(out));
	CHECK(memcmp(raw, out, sizeof(raw)) == 0);

	close(dst);
	unlink(xz); free(xz);
}

/* gz write must start at offset 0 even if dst was previously written */
TEST(write_drive_gz_writes_from_offset_zero)
{
	SKIP_IF(system("gzip --version >/dev/null 2>&1") != 0);

	uint8_t raw[2048];
	memset(raw, 0x5A, sizeof(raw));
	raw[0]             = 0xAA;
	raw[sizeof(raw)-1] = 0xBB;

	char *p = make_named_tmpfile(raw, sizeof(raw));
	CHECK(p != NULL);
	char *gz = compress_file(p, "gzip", ".gz");
	unlink(p); free(p);
	CHECK(gz != NULL);

	/* Pre-fill dst with 0xFF */
	int dst = make_dst_fd(0);
	CHECK(dst >= 0);
	{
		uint8_t fill[sizeof(raw)];
		memset(fill, 0xFF, sizeof(fill));
		write(dst, fill, sizeof(fill));
	}

	image_path = gz;
	img_report.compression_type = BLED_COMPRESSION_GZIP;
	img_report.image_size = sizeof(raw);
	ErrorStatus = 0;

	BOOL ret = format_linux_write_drive((HANDLE)(intptr_t)dst, FALSE);
	CHECK(ret == TRUE);

	uint8_t out[sizeof(raw)];
	CHECK(pread(dst, out, sizeof(out), 0) == (ssize_t)sizeof(out));
	CHECK(out[0]             == 0xAA);
	CHECK(out[sizeof(raw)-1] == 0xBB);
	CHECK(memcmp(raw, out, sizeof(raw)) == 0);

	close(dst);
	unlink(gz); free(gz);
}

/* Corrupt gzip data → FALSE (bled error) */
TEST(write_drive_corrupt_gz_returns_false)
{
	/* Bytes that start with gzip magic but are garbage after */
	static const uint8_t corrupt[] = {
		0x1f, 0x8b, 0x08, 0x00,   /* gzip magic + method */
		0xDE, 0xAD, 0xBE, 0xEF,   /* mtime */
		0x00, 0xFF,                /* xfl + os */
		0xAA, 0xBB, 0xCC           /* truncated, no valid compressed data */
	};
	char *p = make_named_tmpfile(corrupt, sizeof(corrupt));
	CHECK(p != NULL);
	/* bled uses compression_type, not file extension, to pick decoder */

	int dst = make_dst_fd(4096);
	CHECK(dst >= 0);

	image_path = p;
	img_report.compression_type = BLED_COMPRESSION_GZIP;
	ErrorStatus = 0;

	BOOL ret = format_linux_write_drive((HANDLE)(intptr_t)dst, FALSE);
	CHECK(ret == FALSE);

	close(dst);
	unlink(p); free(p);
}

/* Missing gz source file → FALSE */
TEST(write_drive_missing_gz_source_returns_false)
{
	int dst = make_dst_fd(4096);
	CHECK(dst >= 0);

	image_path = "/tmp/rufus_no_such_99999.img.gz";
	img_report.compression_type = BLED_COMPRESSION_GZIP;
	ErrorStatus = 0;

	BOOL ret = format_linux_write_drive((HANDLE)(intptr_t)dst, FALSE);
	CHECK(ret == FALSE);
	CHECK(ErrorStatus != 0);

	close(dst);
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
	printf("Running write_drive tests...\n");

	RUN(write_drive_null_handle_returns_false);
	RUN(write_drive_invalid_handle_returns_false);
	RUN(write_drive_null_image_path_returns_false);
	RUN(write_drive_uncompressed_copies_exact_bytes);
	RUN(write_drive_missing_source_returns_false);
	RUN(write_drive_gz_decompresses_correctly);
	RUN(write_drive_bz2_decompresses_correctly);
	RUN(write_drive_xz_decompresses_correctly);
	RUN(write_drive_gz_writes_from_offset_zero);
	RUN(write_drive_corrupt_gz_returns_false);
	RUN(write_drive_missing_gz_source_returns_false);

	TEST_RESULTS();
}

#endif /* __linux__ */
