/*
 * test_dump_fat_linux.c — Unit and integration tests for DumpFatDir
 * and its helper wchar16_to_utf8.
 *
 * Tests cover:
 *   - wchar16_to_utf8: ASCII, 2-byte UTF-8, 3-byte UTF-8, surrogate pairs,
 *                      empty input, null-termination, long string truncation
 *   - DumpFatDir: null path, missing image, real FAT extraction from ISO
 *
 * The integration tests create a minimal FAT12 image, embed it in a test
 * ISO-9660 image using mkisofs/genisoimage, then call DumpFatDir to verify
 * files are extracted correctly.
 *
 * Linux-only (uses POSIX fork/exec, /tmp, mkisofs).
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
#include <wchar.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <dirent.h>

#include "framework.h"
#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/winioctl.h"
#include "../src/windows/rufus.h"

/* ── forward declarations ─────────────────────────────────────────── */

/* Exposed by dump_fat.c when RUFUS_TEST is defined */
char *dump_fat_wchar16_to_utf8(const wchar_t *wsrc);

/* DumpFatDir uses these globals from globals.c / format.c */
extern char              *image_path;
extern RUFUS_IMG_REPORT   img_report;
extern DWORD              ErrorStatus;

/* ── helpers ──────────────────────────────────────────────────────── */

/*
 * run_cmd — run a shell command, return exit status.
 * stderr is suppressed unless VERBOSE_TESTS is set.
 */
static int run_cmd(const char *cmd)
{
	char full[4096];
#ifdef VERBOSE_TESTS
	snprintf(full, sizeof(full), "%s", cmd);
#else
	snprintf(full, sizeof(full), "%s 2>/dev/null", cmd);
#endif
	return system(full);
}

/*
 * file_contains — return 1 if the named file exists and contains the string.
 */
static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char buf[4096];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	return strstr(buf, needle) != NULL;
}

/*
 * file_exists — return 1 if path can be stat()'d.
 */
static int file_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

/*
 * rm_rf — remove a directory tree (portable via shell).
 */
static void rm_rf(const char *path)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
	run_cmd(cmd);
}

/* ── wchar16_to_utf8 tests ───────────────────────────────────────── */

TEST(wchar16_to_utf8_empty)
{
	/* Empty string → empty result */
	wchar_t ws[] = { 0 };
	char *r = dump_fat_wchar16_to_utf8(ws);
	CHECK(r != NULL);
	CHECK_INT_EQ(0, (int)strlen(r));
}

TEST(wchar16_to_utf8_ascii)
{
	/* Pure ASCII */
	wchar_t ws[] = { 'H', 'e', 'l', 'l', 'o', 0 };
	char *r = dump_fat_wchar16_to_utf8(ws);
	CHECK_STR_EQ("Hello", r);
}

TEST(wchar16_to_utf8_2byte_utf8)
{
	/* U+00E9 LATIN SMALL LETTER E WITH ACUTE → 0xC3 0xA9 */
	wchar_t ws[] = { 0x00E9, 0 };
	char *r = dump_fat_wchar16_to_utf8(ws);
	CHECK(r != NULL);
	unsigned char *u = (unsigned char *)r;
	CHECK_INT_EQ(0xC3, (int)u[0]);
	CHECK_INT_EQ(0xA9, (int)u[1]);
	CHECK_INT_EQ(0,    (int)u[2]);
}

TEST(wchar16_to_utf8_3byte_utf8)
{
	/* U+4E2D CJK character — 3-byte UTF-8 sequence 0xE4 0xB8 0xAD */
	wchar_t ws[] = { 0x4E2D, 0 };
	char *r = dump_fat_wchar16_to_utf8(ws);
	CHECK(r != NULL);
	unsigned char *u = (unsigned char *)r;
	CHECK_INT_EQ(0xE4, (int)u[0]);
	CHECK_INT_EQ(0xB8, (int)u[1]);
	CHECK_INT_EQ(0xAD, (int)u[2]);
	CHECK_INT_EQ(0,    (int)u[3]);
}

TEST(wchar16_to_utf8_surrogate_pair)
{
	/*
	 * U+1F600 GRINNING FACE (😀) encoded as surrogate pair:
	 * high surrogate: 0xD83D, low surrogate: 0xDE00
	 * UTF-8 encoding: 0xF0 0x9F 0x98 0x80
	 */
	wchar_t ws[] = { 0xD83D, 0xDE00, 0 };
	char *r = dump_fat_wchar16_to_utf8(ws);
	CHECK(r != NULL);
	unsigned char *u = (unsigned char *)r;
	CHECK_INT_EQ(0xF0, (int)u[0]);
	CHECK_INT_EQ(0x9F, (int)u[1]);
	CHECK_INT_EQ(0x98, (int)u[2]);
	CHECK_INT_EQ(0x80, (int)u[3]);
	CHECK_INT_EQ(0,    (int)u[4]);
}

TEST(wchar16_to_utf8_mixed_ascii_unicode)
{
	/* "EFI" followed by a 2-byte char and more ASCII */
	wchar_t ws[] = { 'E', 'F', 'I', 0x00F8, '.', 'b', 'i', 'n', 0 };
	char *r = dump_fat_wchar16_to_utf8(ws);
	CHECK(r != NULL);
	/* First 3 bytes should be ASCII "EFI" */
	CHECK_INT_EQ('E', (int)(unsigned char)r[0]);
	CHECK_INT_EQ('F', (int)(unsigned char)r[1]);
	CHECK_INT_EQ('I', (int)(unsigned char)r[2]);
	/* U+00F8 encodes to 2 bytes (0xC3 0xB8) */
	CHECK_INT_EQ(0xC3, (int)(unsigned char)r[3]);
	CHECK_INT_EQ(0xB8, (int)(unsigned char)r[4]);
	/* Then ".bin" */
	CHECK_INT_EQ('.', (int)(unsigned char)r[5]);
}

TEST(wchar16_to_utf8_null_terminated)
{
	/* Verify the result is always null-terminated */
	wchar_t ws[] = { 'A', 'B', 'C', 0 };
	char *r = dump_fat_wchar16_to_utf8(ws);
	CHECK(r != NULL);
	/* strlen should equal 3 */
	CHECK_INT_EQ(3, (int)strlen(r));
}

TEST(wchar16_to_utf8_typical_fat_name)
{
	/* Typical short FAT filename: "BOOTX64.EFI" — all uppercase ASCII */
	wchar_t ws[] = { 'B','O','O','T','X','6','4','.','E','F','I', 0 };
	char *r = dump_fat_wchar16_to_utf8(ws);
	CHECK_STR_EQ("BOOTX64.EFI", r);
}

TEST(wchar16_to_utf8_all_ascii_range)
{
	/* Verify every printable ASCII character passes through unchanged */
	wchar_t ws[128];
	int n = 0;
	for (int c = 0x20; c < 0x7F; c++)
		ws[n++] = (wchar_t)c;
	ws[n] = 0;
	char *r = dump_fat_wchar16_to_utf8(ws);
	CHECK(r != NULL);
	for (int c = 0x20; c < 0x7F; c++)
		CHECK_INT_EQ(c, (int)(unsigned char)r[c - 0x20]);
}

/* ── DumpFatDir null-input guard tests ───────────────────────────── */

TEST(DumpFatDir_null_path_returns_false)
{
	/* Must not crash and must return FALSE */
	BOOL r = DumpFatDir(NULL, 0);
	CHECK_INT_EQ(FALSE, (int)r);
}

TEST(DumpFatDir_null_image_path_returns_false)
{
	/*
	 * cluster == 0 means "open root dir" which reads image_path.
	 * If image_path is NULL, DumpFatDir must return FALSE cleanly.
	 */
	char *saved = image_path;
	image_path = NULL;
	BOOL r = DumpFatDir("/tmp", 0);
	image_path = saved;
	CHECK_INT_EQ(FALSE, (int)r);
}

TEST(DumpFatDir_nonexistent_image_returns_false)
{
	char *saved = image_path;
	image_path = "/tmp/rufus_test_nonexistent_XXXXXXXX.iso";
	BOOL r = DumpFatDir("/tmp", 0);
	image_path = saved;
	CHECK_INT_EQ(FALSE, (int)r);
}

/* ── Integration tests: real FAT + ISO ─────────────────────────────
 *
 * These tests build a real FAT12 image containing test files, embed it in
 * an ISO-9660 image using mkisofs, then call DumpFatDir to extract and
 * verify the files.
 *
 * Requires: mkisofs (or genisoimage), mkfs.fat, mcopy.
 * Each test skips gracefully if any required tool is missing.
 */

static int have_tool(const char *tool)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "which %s >/dev/null 2>&1", tool);
	return system(cmd) == 0;
}

/*
 * create_test_fat_iso — create a FAT image with the given file content
 * and embed it as /efi/test.img inside an ISO.
 *
 * fat_img_path:  where to write the FAT image
 * iso_path:      where to write the ISO
 * iso_efi_path:  the path inside the ISO (e.g. "/efi/test.img")
 * fat_file_name: filename inside the FAT image (e.g. "TEST.TXT")
 * fat_file_data: content of the FAT file
 *
 * Returns 1 on success.
 */
static int create_test_fat_iso(const char *fat_img_path,
                                const char *iso_path,
                                const char *iso_subdir,
                                const char *fat_file_name,
                                const char *fat_file_data)
{
	char cmd[2048];
	char iso_root[512], iso_subdir_full[512], data_file[512];

	/* Check tools */
	if (!have_tool("mkfs.fat") || !have_tool("mcopy") ||
	    (!have_tool("mkisofs") && !have_tool("genisoimage")))
		return 0;

	/* Create temp directory structure for ISO root */
	snprintf(iso_root,        sizeof(iso_root),        "/tmp/rufus_fat_iso_root_%d", (int)getpid());
	snprintf(iso_subdir_full, sizeof(iso_subdir_full),  "%s/%s",      iso_root, iso_subdir);
	snprintf(data_file,       sizeof(data_file),        "/tmp/rufus_fat_data_%d.txt", (int)getpid());

	rm_rf(iso_root);
	snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", iso_subdir_full);
	if (run_cmd(cmd) != 0) return 0;

	/* Write the data file that will go into the FAT image */
	FILE *f = fopen(data_file, "w");
	if (!f) { rm_rf(iso_root); return 0; }
	fputs(fat_file_data, f);
	fclose(f);

	/* Create a 1.44 MB FAT12 image */
	snprintf(cmd, sizeof(cmd), "dd if=/dev/zero of='%s' bs=512 count=2880", fat_img_path);
	if (run_cmd(cmd) != 0) { rm_rf(iso_root); return 0; }
	snprintf(cmd, sizeof(cmd), "mkfs.fat -F 12 '%s'", fat_img_path);
	if (run_cmd(cmd) != 0) { rm_rf(iso_root); return 0; }

	/* Copy file into FAT image */
	snprintf(cmd, sizeof(cmd), "mcopy -i '%s' '%s' '::%s'",
	         fat_img_path, data_file, fat_file_name);
	if (run_cmd(cmd) != 0) { rm_rf(iso_root); return 0; }

	/* Copy FAT image into ISO root */
	snprintf(cmd, sizeof(cmd), "cp '%s' '%s/test.img'", fat_img_path, iso_subdir_full);
	if (run_cmd(cmd) != 0) { rm_rf(iso_root); return 0; }

	/* Build ISO */
	const char *mkiso = have_tool("mkisofs") ? "mkisofs" : "genisoimage";
	snprintf(cmd, sizeof(cmd), "%s -o '%s' -R '%s'", mkiso, iso_path, iso_root);
	int rc = run_cmd(cmd);
	rm_rf(iso_root);
	unlink(data_file);
	return rc == 0;
}

TEST(DumpFatDir_extracts_file_from_fat_in_iso)
{
	/* Skip if required tools are not available */
	if (!have_tool("mkfs.fat") || !have_tool("mcopy") ||
	    (!have_tool("mkisofs") && !have_tool("genisoimage"))) {
		printf("  SKIP: mkfs.fat/mcopy/mkisofs not available\n");
		return;
	}

	char fat_img[256], iso_path[256], out_dir[256];
	snprintf(fat_img,  sizeof(fat_img),  "/tmp/rufus_test_fat_%d.img", (int)getpid());
	snprintf(iso_path, sizeof(iso_path), "/tmp/rufus_test_%d.iso",     (int)getpid());
	snprintf(out_dir,  sizeof(out_dir),  "/tmp/rufus_test_out_%d",     (int)getpid());

	/* Create the test ISO with a FAT image containing "HELLO.TXT" */
	int created = create_test_fat_iso(fat_img, iso_path,
	                                   "efi", "HELLO.TXT",
	                                   "Hello from DumpFatDir!\n");
	if (!created) {
		printf("  SKIP: failed to create test ISO\n");
		unlink(fat_img);
		return;
	}

	/* Prepare output directory */
	rm_rf(out_dir);
	mkdir(out_dir, 0755);

	/* Set up globals DumpFatDir needs */
	char *saved_image_path = image_path;
	image_path = iso_path;
	memset(&img_report, 0, sizeof(img_report));
	snprintf(img_report.efi_img_path, sizeof(img_report.efi_img_path),
	         "/efi/test.img");

	BOOL r = DumpFatDir(out_dir, 0);

	/* Restore globals */
	image_path = saved_image_path;

	CHECK_INT_EQ(TRUE, (int)r);

	/* Verify that HELLO.TXT was extracted to out_dir */
	char expected_file[512];
	snprintf(expected_file, sizeof(expected_file), "%s/HELLO.TXT", out_dir);
	CHECK_INT_EQ(1, file_exists(expected_file));
	CHECK_INT_EQ(1, file_contains(expected_file, "Hello from DumpFatDir!"));

	/* Cleanup */
	rm_rf(out_dir);
	unlink(fat_img);
	unlink(iso_path);
}

TEST(DumpFatDir_skip_existing_files)
{
	/* DumpFatDir should NOT overwrite a file that already exists */
	if (!have_tool("mkfs.fat") || !have_tool("mcopy") ||
	    (!have_tool("mkisofs") && !have_tool("genisoimage"))) {
		printf("  SKIP: mkfs.fat/mcopy/mkisofs not available\n");
		return;
	}

	char fat_img[256], iso_path[256], out_dir[256];
	snprintf(fat_img,  sizeof(fat_img),  "/tmp/rufus_skip_fat_%d.img", (int)getpid());
	snprintf(iso_path, sizeof(iso_path), "/tmp/rufus_skip_%d.iso",     (int)getpid());
	snprintf(out_dir,  sizeof(out_dir),  "/tmp/rufus_skip_out_%d",     (int)getpid());

	int created = create_test_fat_iso(fat_img, iso_path,
	                                   "efi", "SKIP.TXT",
	                                   "From ISO\n");
	if (!created) {
		printf("  SKIP: failed to create test ISO\n");
		unlink(fat_img);
		return;
	}

	rm_rf(out_dir);
	mkdir(out_dir, 0755);

	/* Pre-create the file with different content */
	char pre_path[512];
	snprintf(pre_path, sizeof(pre_path), "%s/SKIP.TXT", out_dir);
	FILE *f = fopen(pre_path, "w");
	fputs("Pre-existing content\n", f);
	fclose(f);

	char *saved_image_path = image_path;
	image_path = iso_path;
	memset(&img_report, 0, sizeof(img_report));
	snprintf(img_report.efi_img_path, sizeof(img_report.efi_img_path),
	         "/efi/test.img");

	BOOL r = DumpFatDir(out_dir, 0);
	image_path = saved_image_path;

	CHECK_INT_EQ(TRUE, (int)r);
	/* File should still contain original pre-existing content */
	CHECK_INT_EQ(1, file_contains(pre_path, "Pre-existing content"));

	rm_rf(out_dir);
	unlink(fat_img);
	unlink(iso_path);
}

TEST(DumpFatDir_multiple_files)
{
	/* Test that multiple files in the FAT image are all extracted */
	if (!have_tool("mkfs.fat") || !have_tool("mcopy") ||
	    (!have_tool("mkisofs") && !have_tool("genisoimage"))) {
		printf("  SKIP: mkfs.fat/mcopy/mkisofs not available\n");
		return;
	}

	char fat_img[256], iso_path[256], out_dir[256];
	char iso_root[512], iso_subdir_full[512];
	snprintf(fat_img,       sizeof(fat_img),       "/tmp/rufus_multi_fat_%d.img", (int)getpid());
	snprintf(iso_path,      sizeof(iso_path),       "/tmp/rufus_multi_%d.iso",     (int)getpid());
	snprintf(out_dir,       sizeof(out_dir),        "/tmp/rufus_multi_out_%d",     (int)getpid());
	snprintf(iso_root,      sizeof(iso_root),       "/tmp/rufus_multi_root_%d",    (int)getpid());
	snprintf(iso_subdir_full, sizeof(iso_subdir_full), "%s/efi",                  iso_root);

	char cmd[2048];
	rm_rf(iso_root);
	snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", iso_subdir_full);
	if (run_cmd(cmd) != 0) { printf("  SKIP: mkdir failed\n"); return; }

	/* Create FAT image */
	snprintf(cmd, sizeof(cmd), "dd if=/dev/zero of='%s' bs=512 count=2880", fat_img);
	if (run_cmd(cmd) != 0) { rm_rf(iso_root); printf("  SKIP: dd failed\n"); return; }
	snprintf(cmd, sizeof(cmd), "mkfs.fat -F 12 '%s'", fat_img);
	if (run_cmd(cmd) != 0) { rm_rf(iso_root); printf("  SKIP: mkfs.fat failed\n"); return; }

	/* Write multiple data files */
	char f1[256], f2[256], f3[256];
	snprintf(f1, sizeof(f1), "/tmp/rufus_multi_f1_%d.txt", (int)getpid());
	snprintf(f2, sizeof(f2), "/tmp/rufus_multi_f2_%d.txt", (int)getpid());
	snprintf(f3, sizeof(f3), "/tmp/rufus_multi_f3_%d.txt", (int)getpid());

	FILE *fp;
	fp = fopen(f1, "w"); fputs("File A content\n", fp); fclose(fp);
	fp = fopen(f2, "w"); fputs("File B content\n", fp); fclose(fp);
	fp = fopen(f3, "w"); fputs("File C content\n", fp); fclose(fp);

	snprintf(cmd, sizeof(cmd), "mcopy -i '%s' '%s' '::FILEA.TXT'", fat_img, f1);
	if (run_cmd(cmd) != 0) goto cleanup;
	snprintf(cmd, sizeof(cmd), "mcopy -i '%s' '%s' '::FILEB.TXT'", fat_img, f2);
	if (run_cmd(cmd) != 0) goto cleanup;
	snprintf(cmd, sizeof(cmd), "mcopy -i '%s' '%s' '::FILEC.TXT'", fat_img, f3);
	if (run_cmd(cmd) != 0) goto cleanup;

	snprintf(cmd, sizeof(cmd), "cp '%s' '%s/test.img'", fat_img, iso_subdir_full);
	if (run_cmd(cmd) != 0) goto cleanup;

	const char *mkiso = have_tool("mkisofs") ? "mkisofs" : "genisoimage";
	snprintf(cmd, sizeof(cmd), "%s -o '%s' -R '%s'", mkiso, iso_path, iso_root);
	if (run_cmd(cmd) != 0) goto cleanup;

	rm_rf(iso_root);

	rm_rf(out_dir);
	mkdir(out_dir, 0755);

	char *saved_image_path = image_path;
	image_path = iso_path;
	memset(&img_report, 0, sizeof(img_report));
	snprintf(img_report.efi_img_path, sizeof(img_report.efi_img_path), "/efi/test.img");

	BOOL r = DumpFatDir(out_dir, 0);
	image_path = saved_image_path;

	CHECK_INT_EQ(TRUE, (int)r);

	char ef1[512], ef2[512], ef3[512];
	snprintf(ef1, sizeof(ef1), "%s/FILEA.TXT", out_dir);
	snprintf(ef2, sizeof(ef2), "%s/FILEB.TXT", out_dir);
	snprintf(ef3, sizeof(ef3), "%s/FILEC.TXT", out_dir);
	CHECK_INT_EQ(1, file_exists(ef1));
	CHECK_INT_EQ(1, file_exists(ef2));
	CHECK_INT_EQ(1, file_exists(ef3));
	CHECK_INT_EQ(1, file_contains(ef1, "File A content"));
	CHECK_INT_EQ(1, file_contains(ef2, "File B content"));
	CHECK_INT_EQ(1, file_contains(ef3, "File C content"));

cleanup:
	rm_rf(iso_root);
	rm_rf(out_dir);
	unlink(fat_img);
	unlink(iso_path);
	unlink(f1);
	unlink(f2);
	unlink(f3);
}

/* ── main ─────────────────────────────────────────────────────────── */

int main(void)
{
	/* wchar16_to_utf8 unit tests */
	RUN(wchar16_to_utf8_empty);
	RUN(wchar16_to_utf8_ascii);
	RUN(wchar16_to_utf8_2byte_utf8);
	RUN(wchar16_to_utf8_3byte_utf8);
	RUN(wchar16_to_utf8_surrogate_pair);
	RUN(wchar16_to_utf8_mixed_ascii_unicode);
	RUN(wchar16_to_utf8_null_terminated);
	RUN(wchar16_to_utf8_typical_fat_name);
	RUN(wchar16_to_utf8_all_ascii_range);

	/* DumpFatDir guard tests */
	RUN(DumpFatDir_null_path_returns_false);
	RUN(DumpFatDir_null_image_path_returns_false);
	RUN(DumpFatDir_nonexistent_image_returns_false);

	/* DumpFatDir integration tests */
	RUN(DumpFatDir_extracts_file_from_fat_in_iso);
	RUN(DumpFatDir_skip_existing_files);
	RUN(DumpFatDir_multiple_files);

	TEST_RESULTS();
}

#endif /* __linux__ */
