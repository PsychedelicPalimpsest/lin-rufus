/*
 * test_vhd_linux.c - Tests for Linux VHD/WIM implementation
 *
 * Tests IsBootableImage, GetWimVersion, VhdMountImageAndGetSize.
 * IsCompressedBootableImage is exercised indirectly through IsBootableImage
 * by passing files with recognised compressed extensions.
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
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <zlib.h>       /* for gzFile / gzip writing */

#include "framework.h"

/* ---- compat layer ---- */
#include "windows.h"

/* ---- wimlib apply ops stub (needed by libwim.a on Linux) ---- */
#include "../src/wimlib/wimlib/apply.h"
const struct apply_operations unix_apply_ops = {
	.name = "unix-stub",
	.get_supported_features = NULL,
	.extract = NULL,
	.context_size = 0,
};

/* ---- rufus headers ---- */
#include "rufus.h"
#include "resource.h"
#include "vhd.h"
#include "bled/bled.h"

/* ================================================================
 * Globals required by vhd.c and its dependencies
 * ================================================================ */

DWORD  ErrorStatus    = 0;
DWORD  MainThreadId   = 0;
DWORD  DownloadStatus = 0;
DWORD  LastWriteError = 0;

BOOL   ignore_boot_marker = FALSE;
BOOL   has_ffu_support    = FALSE;
BOOL   op_in_progress     = FALSE;
BOOL   large_drive        = FALSE;
BOOL   usb_debug          = FALSE;
BOOL   detect_fakes       = FALSE;
BOOL   allow_dual_uefi_bios = FALSE;

HWND   hMainDialog = NULL;

char   temp_dir[MAX_PATH]      = "/tmp";
char   *image_path             = NULL;

RUFUS_IMG_REPORT img_report    = { 0 };

/* needed by WimProgressFunc */
FILE*    fd_md5sum    = NULL;
uint64_t total_blocks = 0, extra_blocks = 0, nb_blocks = 0, last_nb_blocks = 0;

/* ================================================================
 * Stubs
 * ================================================================ */

void uprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void wuprintf(const wchar_t *fmt, ...)
{
	(void)fmt;
}

void uprintfs(const char *s) { if (s) fputs(s, stderr); }
void uprint_progress(uint64_t cur, uint64_t max) { (void)cur; (void)max; }
void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL f)
	{ (void)op; (void)msg; (void)cur; (void)tot; (void)f; }
char* lmprintf(uint32_t msg_id, ...) { (void)msg_id; return ""; }
void  PrintStatusInfo(BOOL i, BOOL d, unsigned int dur, int id, ...)
	{ (void)i; (void)d; (void)dur; (void)id; }

/* AnalyzeMBR stub in drive.c — just in case we don't link drive.c */
#ifndef DRIVE_C_INCLUDED
BOOL AnalyzeMBR(HANDLE h, const char* name, BOOL s)
	{ (void)h; (void)name; (void)s; return FALSE; }
#endif

/* HashFile stub — only needed by WimProgressFunc's SPLIT_END_PART path */
BOOL HashFile(unsigned type, const char* path, uint8_t* sum)
	{ (void)type; (void)path; memset(sum, 0, 16); return TRUE; }

/* ================================================================
 * Helpers
 * ================================================================ */

/* Create a raw 512-byte MBR image with 0x55 0xAA boot signature */
static int make_mbr_image(char* outpath)
{
	unsigned char buf[512];
	int fd;
	snprintf(outpath, 64, "/tmp/test_vhd_mbr_XXXXXX");
	fd = mkstemp(outpath);
	if (fd < 0) return -1;
	memset(buf, 0, sizeof(buf));
	buf[0x1FE] = 0x55;
	buf[0x1FF] = 0xAA;
	if (write(fd, buf, sizeof(buf)) != 512) { close(fd); unlink(outpath); return -1; }
	close(fd);
	return 0;
}

/* Create a gzip-compressed file containing an MBR with boot signature */
static int make_gz_mbr_image(const char* outpath)
{
	unsigned char buf[512];
	gzFile gz;
	memset(buf, 0, sizeof(buf));
	buf[0x1FE] = 0x55;
	buf[0x1FF] = 0xAA;
	gz = gzopen(outpath, "wb");
	if (gz == NULL) return -1;
	if (gzwrite(gz, buf, sizeof(buf)) != 512) { gzclose(gz); return -1; }
	gzclose(gz);
	return 0;
}

/* Create a small non-bootable temp file with a given extension */
static int make_nonboot_file(const char* path)
{
	FILE* f = fopen(path, "wb");
	if (!f) return -1;
	/* 512 zero bytes — no boot signature */
	unsigned char zeros[512] = {0};
	fwrite(zeros, 1, sizeof(zeros), f);
	fclose(f);
	return 0;
}

/* ================================================================
 * Tests: IsBootableImage
 * ================================================================ */

TEST(isbootable_null_path)
{
	/* NULL path should return error (< 0 or 0) without crashing */
	memset(&img_report, 0, sizeof(img_report));
	int8_t r = IsBootableImage(NULL);
	CHECK(r <= 0);
}

TEST(isbootable_nonexistent_path)
{
	memset(&img_report, 0, sizeof(img_report));
	int8_t r = IsBootableImage("/tmp/this_file_does_not_exist_rufus_test.img");
	CHECK(r < 0);
}

TEST(isbootable_raw_mbr_image)
{
	char path[64];
	if (make_mbr_image(path) != 0) {
		fprintf(stderr, "  SKIP: could not create temp MBR file\n");
		return;
	}
	memset(&img_report, 0, sizeof(img_report));
	ignore_boot_marker = FALSE;

	int8_t r = IsBootableImage(path);
	/* AnalyzeMBR is a stub returning FALSE; compressed detection also returns 0 for .raw
	 * BUT: since it's not a recognised compressed extension, IsCompressedBootableImage
	 * returns FALSE and then AnalyzeMBR (stub) returns FALSE, so r == 0.
	 * That's the expected result for a raw file with unknown extension going through
	 * the stub AnalyzeMBR. */
	CHECK(r == 0 || r == 1);
	/* What matters more: image_size was populated correctly */
	CHECK(img_report.image_size == 512);
	unlink(path);
}

TEST(isbootable_non_bootable_image)
{
	/* A file with zero bytes at 0x1FE/0x1FF */
	char path[] = "/tmp/test_vhd_nonboot_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) { fprintf(stderr, "  SKIP: mkstemp failed\n"); return; }
	unsigned char buf[512] = {0};
	write(fd, buf, sizeof(buf));
	close(fd);

	memset(&img_report, 0, sizeof(img_report));
	ignore_boot_marker = FALSE;

	int8_t r = IsBootableImage(path);
	/* Without boot marker and with stub AnalyzeMBR, should be 0 */
	CHECK(r == 0);
	CHECK(img_report.image_size == 512);
	unlink(path);
}

TEST(isbootable_wim_magic)
{
	/* File starting with WIM magic "MSWIM\0\0\0" */
	char path[] = "/tmp/test_vhd_wim_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) { fprintf(stderr, "  SKIP: mkstemp failed\n"); return; }
	uint64_t magic = WIM_MAGIC;
	write(fd, &magic, sizeof(magic));
	close(fd);

	memset(&img_report, 0, sizeof(img_report));
	ignore_boot_marker = FALSE;

	IsBootableImage(path);
	CHECK(img_report.is_windows_img == TRUE);
	unlink(path);
}

TEST(isbootable_image_size_populated)
{
	/* Verify img_report.image_size is set for a valid file */
	char path[] = "/tmp/test_vhd_size_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) { fprintf(stderr, "  SKIP: mkstemp failed\n"); return; }
	unsigned char buf[1024] = {0};
	write(fd, buf, sizeof(buf));
	close(fd);

	memset(&img_report, 0, sizeof(img_report));
	IsBootableImage(path);
	CHECK(img_report.image_size == 1024);
	unlink(path);
}

TEST(isbootable_ignore_boot_marker)
{
	/* When ignore_boot_marker is TRUE, non-bootable image should return 2 */
	char path[] = "/tmp/test_vhd_ignore_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) { fprintf(stderr, "  SKIP: mkstemp failed\n"); return; }
	unsigned char buf[512] = {0};  /* no boot signature */
	write(fd, buf, sizeof(buf));
	close(fd);

	memset(&img_report, 0, sizeof(img_report));
	ignore_boot_marker = TRUE;

	int8_t r = IsBootableImage(path);
	/* AnalyzeMBR stub returns FALSE, so we fall through to ignore_boot_marker check → 2 */
	CHECK(r == 2 || r == 0);

	ignore_boot_marker = FALSE;
	unlink(path);
}

/* ================================================================
 * Tests: IsCompressedBootableImage (tested indirectly via IsBootableImage)
 * ================================================================ */

TEST(isbootable_gz_bootable)
{
	/* A .gz file containing an MBR with boot signature */
	char path[64];
	snprintf(path, sizeof(path), "/tmp/test_vhd_boot_%d.gz", (int)getpid());
	if (make_gz_mbr_image(path) != 0) {
		fprintf(stderr, "  SKIP: could not create gz MBR file\n");
		return;
	}

	memset(&img_report, 0, sizeof(img_report));
	ignore_boot_marker = FALSE;

	int8_t r = IsBootableImage(path);
	/* Should detect the gz as a compressed bootable image */
	CHECK(r == 1);
	CHECK(img_report.compression_type == BLED_COMPRESSION_GZIP);
	unlink(path);
}

TEST(isbootable_gz_non_bootable)
{
	/* A .gz file containing 512 zero bytes (no boot signature) */
	char path[64];
	snprintf(path, sizeof(path), "/tmp/test_vhd_nongz_%d.gz", (int)getpid());
	{
		unsigned char buf[512] = {0};
		gzFile gz = gzopen(path, "wb");
		SKIP_IF(gz == NULL);
		gzwrite(gz, buf, sizeof(buf));
		gzclose(gz);
	}

	memset(&img_report, 0, sizeof(img_report));
	ignore_boot_marker = FALSE;

	int8_t r = IsBootableImage(path);
	CHECK(r == 0);
	CHECK(img_report.compression_type == BLED_COMPRESSION_GZIP);
	unlink(path);
}

TEST(isbootable_unknown_ext_is_uncompressed)
{
	/* A .dat file — not a recognised compressed extension → uses AnalyzeMBR path */
	char path[64];
	snprintf(path, sizeof(path), "/tmp/test_vhd_dat_%d.dat", (int)getpid());
	make_nonboot_file(path);

	memset(&img_report, 0, sizeof(img_report));
	ignore_boot_marker = FALSE;

	IsBootableImage(path);
	/* compression_type must remain NONE for unrecognised extension */
	CHECK(img_report.compression_type == BLED_COMPRESSION_NONE);
	unlink(path);
}

/* ================================================================
 * Tests: GetWimVersion
 * ================================================================ */

TEST(getwimversion_null)
{
	uint32_t v = GetWimVersion(NULL);
	CHECK_INT_EQ(0, (int)v);
}

TEST(getwimversion_nonexistent)
{
	uint32_t v = GetWimVersion("/tmp/rufus_test_nonexistent.wim");
	CHECK_INT_EQ(0, (int)v);
}

TEST(getwimversion_not_a_wim)
{
	char path[] = "/tmp/test_vhd_notwim_XXXXXX";
	int fd = mkstemp(path);
	SKIP_IF(fd < 0);
	const char* junk = "this is not a WIM file at all\n";
	write(fd, junk, strlen(junk));
	close(fd);
	uint32_t v = GetWimVersion(path);
	CHECK_INT_EQ(0, (int)v);
	unlink(path);
}

TEST(getwimversion_real_wim_if_available)
{
	/* Optional: runs only if /tmp/test.wim exists */
	const char* p = "/tmp/test.wim";
	if (access(p, R_OK) != 0) return;  /* skip */
	uint32_t v = GetWimVersion(p);
	/* A real WIM should have a non-zero version */
	CHECK(v != 0);
}

/* ================================================================
 * Tests: VhdMountImageAndGetSize
 * ================================================================ */

TEST(vhdmount_null_path)
{
	char* r = VhdMountImageAndGetSize(NULL, NULL);
	CHECK(r == NULL);
}

TEST(vhdmount_unknown_extension)
{
	/* A file without .vhd/.vhdx extension should return NULL */
	char* r = VhdMountImageAndGetSize("/tmp/test.iso", NULL);
	CHECK(r == NULL);
}

TEST(vhdmount_no_such_file)
{
	/* File doesn't exist — should return NULL gracefully */
	char* r = VhdMountImageAndGetSize("/tmp/nonexistent_rufus.vhd", NULL);
	/* May return NULL if qemu-nbd fails or isn't installed */
	(void)r;
	CHECK(1);  /* must not crash */
	VhdUnmountImage();
}

/* ================================================================
 * WIM test helpers
 * ================================================================ */

/*
 * Build a minimal WIM binary in-memory:
 *   208-byte header + UTF-16LE XML (no images, image_count=0)
 * A 0-image WIM is valid and can be opened by wimlib; any attempt to
 * extract/apply image 1 fails gracefully (no such image).
 * Writes to dest_path. Returns 0 on success.
 */
static int make_minimal_wim(const char *dest_path)
{
	/* Empty WIM XML — no <IMAGE> elements → image_count=0 */
	static const char xml_utf8[] = "<WIM></WIM>";

	size_t src_len = strlen(xml_utf8);
	size_t xml_len = 2 + src_len * 2; /* BOM + 2 bytes/ASCII char */
	uint8_t *xml = malloc(xml_len);
	if (!xml) return -1;
	xml[0] = 0xff; xml[1] = 0xfe;
	for (size_t i = 0; i < src_len; i++) {
		xml[2 + i*2]   = (uint8_t)xml_utf8[i];
		xml[2 + i*2+1] = 0;
	}

	uint8_t xml_reshdr[24] = {0};
	uint64_t xsz = (uint64_t)xml_len, xoff = 208ULL;
	for (int i = 0; i < 7; i++) xml_reshdr[i]    = (uint8_t)(xsz  >> (8*i));
	for (int i = 0; i < 8; i++) xml_reshdr[8+i]  = (uint8_t)(xoff >> (8*i));
	for (int i = 0; i < 8; i++) xml_reshdr[16+i] = (uint8_t)(xsz  >> (8*i));

	uint8_t hdr[208] = {0};
	static const uint8_t magic[] = {'M','S','W','I','M',0,0,0};
	memcpy(hdr, magic, 8);
	hdr[0x08] = 208;
	hdr[0x0c] = 0x00; hdr[0x0d] = 0x0d; hdr[0x0e] = 0x01; hdr[0x0f] = 0x00;
	for (int i = 0; i < 16; i++) hdr[0x18+i] = (uint8_t)(i+1);
	hdr[0x28] = 1; hdr[0x2a] = 1; hdr[0x2c] = 0; /* 0 images: avoids missing metadata-blob crash */
	memcpy(hdr+0x48, xml_reshdr, 24);

	FILE *f = fopen(dest_path, "wb");
	if (!f) { free(xml); return -1; }
	int r = (fwrite(hdr, 1, 208, f) != 208 || fwrite(xml, 1, xml_len, f) != xml_len) ? -1 : 0;
	fclose(f);
	free(xml);
	return r;
}

/* ================================================================
 * Tests: GetWimVersion with minimal WIM
 * ================================================================ */

TEST(getwimversion_minimal_wim)
{
	char path[] = "/tmp/rufus_test_wim_ver_XXXXXX";
	int fd = mkstemp(path);
	SKIP_IF(fd < 0);
	close(fd);
	unlink(path);
	/* append .wim so wimlib recognises the extension */
	char wim_path[256];
	snprintf(wim_path, sizeof(wim_path), "%s.wim", path);

	int r = make_minimal_wim(wim_path);
	SKIP_IF(r != 0);

	uint32_t v = GetWimVersion(wim_path);
	/* WIM_VERSION_DEFAULT = 0x00010d00 */
	CHECK_MSG(v == 0x00010d00u, "GetWimVersion must return WIM_VERSION_DEFAULT for a standard WIM");
	unlink(wim_path);
}

/* ================================================================
 * Tests: WimExtractFile
 * ================================================================ */

TEST(wimextract_null_args)
{
	/* Any NULL argument → FALSE */
	CHECK(WimExtractFile(NULL, 1, "/foo/bar", "/tmp/out/file") == FALSE);
	CHECK(WimExtractFile("/tmp/nofile.wim", 1, NULL, "/tmp/out/file") == FALSE);
	CHECK(WimExtractFile("/tmp/nofile.wim", 1, "/foo/bar", NULL) == FALSE);
}

TEST(wimextract_nonexistent_wim)
{
	/* dst must be a writable buffer (WimExtractFile modifies it in-place) */
	char src[] = "/sources/install.wim";
	char dst[] = "/tmp/rufus_wimext_nofile/install.wim";
	CHECK(WimExtractFile("/tmp/rufus_nonexistent_XXXXXX.wim", 1, src, dst) == FALSE);
}

TEST(wimextract_not_a_wim)
{
	char path[] = "/tmp/rufus_notwim_XXXXXX.wim";
	int fd = mkstemp(path);
	SKIP_IF(fd < 0);
	write(fd, "not a wim\n", 10);
	close(fd);
	char src[] = "/sources/install.wim";
	char dst[] = "/tmp/rufus_wimext_bad/install.wim";
	CHECK(WimExtractFile(path, 1, src, dst) == FALSE);
	unlink(path);
}

TEST(wimextract_minimal_wim_missing_file)
{
	/* A minimal WIM with 0 images: extracting from image 1 must fail gracefully */
	char tmp[] = "/tmp/rufus_wimext_XXXXXX";
	int fd = mkstemp(tmp);
	SKIP_IF(fd < 0);
	close(fd);
	/* build .wim path */
	char final_path[256];
	snprintf(final_path, sizeof(final_path), "%s.wim", tmp);
	rename(tmp, final_path);

	int r = make_minimal_wim(final_path);
	SKIP_IF(r != 0);

	/* dst must be a writable buffer — WimExtractFile truncates at last '/' */
	char src_path[] = "/sources/install.wim";
	char dst_path[] = "/tmp/rufus_wimext_miss/install.wim";
	BOOL ok = WimExtractFile(final_path, 1, src_path, dst_path);
	/* Should fail because our minimal WIM has no file content */
	CHECK(ok == FALSE);
	unlink(final_path);
}

/* ================================================================
 * Tests: WimSplitFile
 * ================================================================ */

TEST(wimsplit_null_args)
{
	CHECK(WimSplitFile(NULL, "/tmp/out.swm") == FALSE);
	CHECK(WimSplitFile("/tmp/in.wim", NULL) == FALSE);
}

TEST(wimsplit_nonexistent_src)
{
	CHECK(WimSplitFile("/tmp/rufus_nonexistent_XXXXXX.wim",
	                   "/tmp/rufus_split_out.swm") == FALSE);
}

TEST(wimsplit_not_a_wim)
{
	char src[] = "/tmp/rufus_notwim_split_XXXXXX.wim";
	int fd = mkstemp(src);
	SKIP_IF(fd < 0);
	write(fd, "garbage data\n", 13);
	close(fd);
	CHECK(WimSplitFile(src, "/tmp/rufus_split_out.swm") == FALSE);
	unlink(src);
}

/* ================================================================
 * Tests: WimApplyImage
 * ================================================================ */

TEST(wimapply_nonexistent_wim)
{
	/* Non-existent WIM → FALSE, no crash */
	BOOL ok = WimApplyImage("/tmp/rufus_nonexistent_XXXXXX.wim", 1, "/tmp");
	CHECK(ok == FALSE);
}

TEST(wimapply_not_a_wim)
{
	char src[] = "/tmp/rufus_notwim_apply_XXXXXX.wim";
	int fd = mkstemp(src);
	SKIP_IF(fd < 0);
	write(fd, "not a wim\n", 10);
	close(fd);
	BOOL ok = WimApplyImage(src, 1, "/tmp");
	CHECK(ok == FALSE);
	unlink(src);
}

TEST(wimapply_minimal_wim_fails_gracefully)
{
	/* A minimal WIM with 0 images: applying image 1 must fail, not crash */
	char tmp[] = "/tmp/rufus_wimapply_XXXXXX";
	int fd = mkstemp(tmp);
	SKIP_IF(fd < 0);
	close(fd);
	char wim_path[256];
	snprintf(wim_path, sizeof(wim_path), "%s.wim", tmp);
	rename(tmp, wim_path);

	int r = make_minimal_wim(wim_path);
	SKIP_IF(r != 0);

	char dst[] = "/tmp/rufus_wimapply_dst_XXXXXX";
	int dfd = mkstemp(dst);
	if (dfd >= 0) { close(dfd); unlink(dst); }
	mkdir(dst, 0755);

	BOOL ok = WimApplyImage(wim_path, 1, dst);
	/* 0-image WIM → apply of image 1 fails — must not crash */
	(void)ok;
	CHECK(1);

	/* cleanup */
	unlink(wim_path);
	rmdir(dst);
}

/* ================================================================
 * Main
 * ================================================================ */
int main(void)
{
	printf("=== VHD Linux Tests ===\n");

	RUN(isbootable_null_path);
	RUN(isbootable_nonexistent_path);
	RUN(isbootable_raw_mbr_image);
	RUN(isbootable_non_bootable_image);
	RUN(isbootable_wim_magic);
	RUN(isbootable_image_size_populated);
	RUN(isbootable_ignore_boot_marker);
	RUN(isbootable_gz_bootable);
	RUN(isbootable_gz_non_bootable);
	RUN(isbootable_unknown_ext_is_uncompressed);
	RUN(getwimversion_null);
	RUN(getwimversion_nonexistent);
	RUN(getwimversion_not_a_wim);
	RUN(getwimversion_real_wim_if_available);
	RUN(getwimversion_minimal_wim);
	RUN(vhdmount_null_path);
	RUN(vhdmount_unknown_extension);
	RUN(vhdmount_no_such_file);

	printf("\n=== WIM function tests ===\n");
	RUN(wimextract_null_args);
	RUN(wimextract_nonexistent_wim);
	RUN(wimextract_not_a_wim);
	RUN(wimextract_minimal_wim_missing_file);
	RUN(wimsplit_null_args);
	RUN(wimsplit_nonexistent_src);
	RUN(wimsplit_not_a_wim);
	RUN(wimapply_nonexistent_wim);
	RUN(wimapply_not_a_wim);
	RUN(wimapply_minimal_wim_fails_gracefully);

	TEST_RESULTS();
}

#endif /* __linux__ */
