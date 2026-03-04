/*
 * test_iso_scan_common.c — Tests for common ISO buffer-scanning helpers
 *
 * Tests GetGrubVersion, GetGrubFs, and GetEfiBootInfo from src/common/iso_scan.c.
 * These functions are portable (no OS I/O) and must behave identically on both
 * Linux and Windows.
 */
#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "rufus.h"
#include "../src/common/iso_scan.h"

/* ---- Stubs for globals referenced by the common code ---- */

/* img_report is declared extern in rufus.h and used by GetGrubVersion */
RUFUS_IMG_REPORT img_report;

/* grub_filesystems is used by GetGrubFs */
StrArray grub_filesystems;

/* uprintf stub */
void uprintf(const char* fmt, ...) { (void)fmt; }

/* sanitize_label stub — just returns 0 */
int sanitize_label(char* label) { (void)label; return 0; }

/* StrArrayCreate/Add/AddUnique/Destroy stubs.
 * We use a simple flat array of up to 16 entries so GetGrubFs can be tested. */
void StrArrayCreate(StrArray* arr, uint32_t initial_size)
{
	(void)initial_size;
	arr->String = calloc(16, sizeof(char*));
	arr->Index  = 0;
	arr->Max    = 16;
}

int32_t StrArrayAdd(StrArray* arr, const char* str, BOOL duplicate)
{
	if (!arr || arr->Index >= arr->Max) return -1;
	arr->String[arr->Index] = duplicate ? strdup(str) : (char*)str;
	return (int32_t)arr->Index++;
}

int32_t StrArrayAddUnique(StrArray* arr, const char* str, BOOL duplicate)
{
	if (!arr || !str) return -1;
	for (uint32_t i = 0; i < arr->Index; i++)
		if (arr->String[i] && strcmp(arr->String[i], str) == 0)
			return -1;
	return StrArrayAdd(arr, str, duplicate);
}

void StrArrayDestroy(StrArray* arr)
{
	if (!arr) return;
	for (uint32_t i = 0; i < arr->Index; i++)
		free(arr->String[i]);
	free(arr->String);
	arr->String = NULL;
	arr->Index = arr->Max = 0;
}

/* =====================================================================
 * GetGrubVersion tests
 * ===================================================================== */

/* Helper: reset img_report and call GetGrubVersion */
static void reset_report(void)
{
	memset(&img_report, 0, sizeof(img_report));
}

/* A buffer containing the double-space GRUB version string */
static void make_grub2_buf(char* buf, size_t bufsz, const char* version)
{
	memset(buf, 0, bufsz);
	/* prefix "GRUB  version " then the version, NUL-terminated */
	snprintf(buf, bufsz, "GRUB  version %s", version);
}

/* A buffer containing the single-space GRUB version string (Fedora/Red Hat) */
static void make_grub2_single_buf(char* buf, size_t bufsz, const char* version)
{
	memset(buf, 0, bufsz);
	snprintf(buf, bufsz, "GRUB version %s", version);
}

TEST(grub_version_double_space)
{
	char buf[256];
	reset_report();
	make_grub2_buf(buf, sizeof(buf), "2.04");
	GetGrubVersion(buf, sizeof(buf), "test.img");
	CHECK_STR_EQ(img_report.grub2_version, "2.04");
}

TEST(grub_version_single_space_fedora)
{
	char buf[256];
	reset_report();
	make_grub2_single_buf(buf, sizeof(buf), "2.12");
	GetGrubVersion(buf, sizeof(buf), "test.img");
	CHECK_STR_EQ(img_report.grub2_version, "2.12");
}

TEST(grub_version_not_set_if_already_populated)
{
	char buf[256];
	reset_report();
	safe_strcpy(img_report.grub2_version, sizeof(img_report.grub2_version), "2.04");
	make_grub2_buf(buf, sizeof(buf), "2.06");
	GetGrubVersion(buf, sizeof(buf), "test.img");
	/* Must NOT overwrite existing value */
	CHECK_STR_EQ(img_report.grub2_version, "2.04");
}

TEST(grub_version_empty_buf)
{
	char buf[256];
	reset_report();
	memset(buf, 0, sizeof(buf));
	/* buf is all-zeros, no GRUB string */
	GetGrubVersion(buf, sizeof(buf), "empty.img");
	CHECK(img_report.grub2_version[0] == '\0');
}

TEST(grub_version_too_small_buf)
{
	char buf[8];
	reset_report();
	memset(buf, 0, sizeof(buf));
	/* buf_size <= max_string_size (32) — function must not crash */
	GetGrubVersion(buf, sizeof(buf), "tiny.img");
	CHECK(img_report.grub2_version[0] == '\0');
}

TEST(grub_version_kaspersky_zero_prefix)
{
	/* A version starting with '0' must be cleared (Kaspersky false-positive) */
	char buf[256];
	reset_report();
	make_grub2_buf(buf, sizeof(buf), "0.97");
	GetGrubVersion(buf, sizeof(buf), "kaspersky.img");
	CHECK(img_report.grub2_version[0] == '\0');
}

TEST(grub_version_nonstandard_suffix)
{
	/* has_grub2 > 1 triggers the "-nonstandard" suffix */
	char buf[256];
	reset_report();
	img_report.has_grub2 = 2; /* > 1 */
	make_grub2_buf(buf, sizeof(buf), "2.04");
	GetGrubVersion(buf, sizeof(buf), "nonstandard.img");
	/* Should contain "-nonstandard" */
	CHECK(strstr(img_report.grub2_version, "-nonstandard") != NULL);
}

TEST(grub_version_gdie_suffix)
{
	/* Buffer containing "grub_debug_is_enabled" triggers "-gdie" suffix */
	char buf[512];
	reset_report();
	memset(buf, 0, sizeof(buf));
	/* Put GRUB version string + debug symbol both in the same buffer */
	const char* version_str = "GRUB  version 2.04";
	const char* debug_str   = "grub_debug_is_enabled";
	memcpy(buf, version_str, strlen(version_str));
	memcpy(buf + 64, debug_str, strlen(debug_str));
	GetGrubVersion(buf, sizeof(buf), "fedora.img");
	CHECK(strstr(img_report.grub2_version, "-gdie") != NULL);
}

TEST(grub_version_null_source_no_crash)
{
	char buf[256];
	reset_report();
	make_grub2_buf(buf, sizeof(buf), "2.02");
	/* source = NULL would be %s in uprintf — our stub ignores it */
	GetGrubVersion(buf, sizeof(buf), NULL);
	/* Must not crash; version should still be set */
	CHECK_STR_EQ(img_report.grub2_version, "2.02");
}

TEST(grub_version_206_appends_label)
{
	/* Version "2.06" gets the sanitized label appended */
	char buf[256];
	reset_report();
	safe_strcpy(img_report.label, sizeof(img_report.label), "Ubuntu-22.04");
	make_grub2_buf(buf, sizeof(buf), "2.06");
	GetGrubVersion(buf, sizeof(buf), "ubuntu.img");
	/* Result must start with "2.06-" */
	CHECK(strncmp(img_report.grub2_version, "2.06-", 5) == 0);
}

/* =====================================================================
 * GetGrubFs tests
 * ===================================================================== */

static void setup_grub_filesystems(void)
{
	StrArrayCreate(&grub_filesystems, 8);
}

static void teardown_grub_filesystems(void)
{
	StrArrayDestroy(&grub_filesystems);
}

TEST(grub_fs_finds_fat)
{
	setup_grub_filesystems();
	char buf[256];
	memset(buf, 0, sizeof(buf));
	/* fshelp NUL "fat" NUL — the bytes immediately after "fshelp\0" are the fs name */
	const char* fshelp = "fshelp";
	const char* fsname = "fat";
	memcpy(buf, fshelp, strlen(fshelp) + 1);
	memcpy(buf + strlen(fshelp) + 1, fsname, strlen(fsname) + 1);
	GetGrubFs(buf, sizeof(buf), &grub_filesystems);
	CHECK(grub_filesystems.Index == 1);
	CHECK_STR_EQ(grub_filesystems.String[0], "fat");
	teardown_grub_filesystems();
}

TEST(grub_fs_finds_ext2)
{
	setup_grub_filesystems();
	char buf[256];
	memset(buf, 0, sizeof(buf));
	const char* fshelp = "fshelp";
	const char* fsname = "ext2";
	memcpy(buf, fshelp, strlen(fshelp) + 1);
	memcpy(buf + strlen(fshelp) + 1, fsname, strlen(fsname) + 1);
	GetGrubFs(buf, sizeof(buf), &grub_filesystems);
	CHECK(grub_filesystems.Index == 1);
	CHECK_STR_EQ(grub_filesystems.String[0], "ext2");
	teardown_grub_filesystems();
}

TEST(grub_fs_deduplicates)
{
	setup_grub_filesystems();
	char buf[512];
	memset(buf, 0, sizeof(buf));
	/* Place the same fshelp+fat twice */
	const char* fshelp = "fshelp";
	const char* fsname = "fat";
	size_t entry_len = strlen(fshelp) + 1 + strlen(fsname) + 1;
	memcpy(buf,            fshelp, strlen(fshelp) + 1);
	memcpy(buf + strlen(fshelp) + 1, fsname, strlen(fsname) + 1);
	memcpy(buf + 64,       fshelp, strlen(fshelp) + 1);
	memcpy(buf + 64 + strlen(fshelp) + 1, fsname, strlen(fsname) + 1);
	(void)entry_len;
	GetGrubFs(buf, sizeof(buf), &grub_filesystems);
	CHECK(grub_filesystems.Index == 1);
	teardown_grub_filesystems();
}

TEST(grub_fs_ignores_too_long_name)
{
	setup_grub_filesystems();
	char buf[256];
	memset(buf, 0, sizeof(buf));
	const char* fshelp = "fshelp";
	/* Name longer than 11 chars should be ignored */
	const char* long_name = "verylongfsname";
	memcpy(buf, fshelp, strlen(fshelp) + 1);
	memcpy(buf + strlen(fshelp) + 1, long_name, strlen(long_name) + 1);
	GetGrubFs(buf, sizeof(buf), &grub_filesystems);
	CHECK(grub_filesystems.Index == 0);
	teardown_grub_filesystems();
}

TEST(grub_fs_empty_buf)
{
	setup_grub_filesystems();
	char buf[256];
	memset(buf, 0, sizeof(buf));
	GetGrubFs(buf, sizeof(buf), &grub_filesystems);
	CHECK(grub_filesystems.Index == 0);
	teardown_grub_filesystems();
}

TEST(grub_fs_too_small_buf)
{
	setup_grub_filesystems();
	char buf[8];
	memset(buf, 0, sizeof(buf));
	/* buf_size < max_string_size — must not crash */
	GetGrubFs(buf, sizeof(buf), &grub_filesystems);
	CHECK(grub_filesystems.Index == 0);
	teardown_grub_filesystems();
}

TEST(grub_fs_null_filesystems_no_crash)
{
	/* passing NULL filesystems must not crash */
	char buf[256];
	memset(buf, 0, sizeof(buf));
	const char* fshelp = "fshelp";
	const char* fsname = "fat";
	memcpy(buf, fshelp, strlen(fshelp) + 1);
	memcpy(buf + strlen(fshelp) + 1, fsname, strlen(fsname) + 1);
	/* NULL filesystems → StrArrayAddUnique stub returns early */
	GetGrubFs(buf, sizeof(buf), NULL);
	/* Just ensuring no crash */
}

TEST(grub_fs_multiple_entries)
{
	setup_grub_filesystems();
	char buf[512];
	memset(buf, 0, sizeof(buf));
	const char* fshelp = "fshelp";
	size_t h = strlen(fshelp) + 1;
	/* Entry 1: fshelp + "fat" */
	memcpy(buf,          fshelp, h); memcpy(buf + h, "fat", 4);
	/* Entry 2: fshelp + "ntfs" at offset 64 */
	memcpy(buf + 64,     fshelp, h); memcpy(buf + 64 + h, "ntfs", 5);
	/* Entry 3: fshelp + "xfs" at offset 128 */
	memcpy(buf + 128,    fshelp, h); memcpy(buf + 128 + h, "xfs", 4);
	GetGrubFs(buf, sizeof(buf), &grub_filesystems);
	CHECK(grub_filesystems.Index == 3);
	teardown_grub_filesystems();
}

/* =====================================================================
 * GetEfiBootInfo tests
 * ===================================================================== */

TEST(efi_boot_info_shim_detected)
{
	char buf[512];
	memset(buf, 0, sizeof(buf));
	const char* shim_sig = "UEFI SHIM\n$Version: 15.7";
	size_t search_len = strlen("UEFI SHIM\n$Version: ");
	memcpy(buf, shim_sig, strlen(shim_sig) + 1);
	GetEfiBootInfo(buf, sizeof(buf), "shimx64.efi");
	/* After detection, buf[search_len] should contain the version string */
	CHECK_MSG(strncmp(buf + search_len, "15.7", 4) == 0,
	          "shim version string must remain at expected offset");
}

TEST(efi_boot_info_systemd_boot_detected)
{
	char buf[512];
	memset(buf, 0, sizeof(buf));
	const char* sd_sig = "#### LoaderInfo: systemd-boot 254.5-1";
	size_t search_len = strlen("#### LoaderInfo: systemd-boot ");
	memcpy(buf, sd_sig, strlen(sd_sig) + 1);
	GetEfiBootInfo(buf, sizeof(buf), "bootx64.efi");
	/* After detection, version string should be at search_len offset */
	CHECK_MSG(strncmp(buf + search_len, "254.5-1", 7) == 0,
	          "systemd-boot version string must remain at expected offset");
}

TEST(efi_boot_info_empty_buf)
{
	char buf[512];
	memset(buf, 0, sizeof(buf));
	GetEfiBootInfo(buf, sizeof(buf), "unknown.efi");
	/* Empty buffer — no match, buf still all-zero */
	CHECK_MSG(buf[0] == '\0', "empty buf must remain unchanged after no-match");
}

TEST(efi_boot_info_too_small)
{
	char buf[8];
	memset(buf, 0, sizeof(buf));
	/* buf_size < max_string_size — must not crash */
	GetEfiBootInfo(buf, sizeof(buf), "small.efi");
	CHECK_MSG(buf[0] == '\0', "too-small buf must remain unchanged");
}

TEST(efi_boot_info_no_match)
{
	char buf[512];
	memset(buf, 0, sizeof(buf));
	const char* data = "This is some random EFI binary data with no recognizable signature";
	size_t dlen = strlen(data);
	memcpy(buf, data, dlen + 1);
	GetEfiBootInfo(buf, sizeof(buf), "random.efi");
	/* No match — buf[dlen] should still be NUL (no in-place modification) */
	CHECK_MSG(buf[dlen] == '\0', "no-match must not modify buf past the data");
}

TEST(efi_boot_info_null_source_no_crash)
{
	char buf[512];
	memset(buf, 0, sizeof(buf));
	const char* shim_sig = "UEFI SHIM\n$Version: 15.4";
	memcpy(buf, shim_sig, strlen(shim_sig) + 1);
	/* source = NULL — must not crash */
	GetEfiBootInfo(buf, sizeof(buf), NULL);
	/* Version string should still be found */
	size_t search_len = strlen("UEFI SHIM\n$Version: ");
	CHECK_MSG(strncmp(buf + search_len, "15.4", 4) == 0,
	          "null source must not prevent detection");
}

TEST(efi_boot_info_version_at_offset)
{
	/* Signature not at offset 0 — function must still find it */
	char buf[512];
	memset(buf, 0, sizeof(buf));
	const char* shim_sig = "UEFI SHIM\n$Version: 15.8";
	size_t offset = 100;
	size_t search_len = strlen("UEFI SHIM\n$Version: ");
	memcpy(buf + offset, shim_sig, strlen(shim_sig) + 1);
	GetEfiBootInfo(buf, sizeof(buf), "shimx64.efi");
	/* Version should be at offset + search_len */
	CHECK_MSG(strncmp(buf + offset + search_len, "15.8", 4) == 0,
	          "signature at non-zero offset must still be detected");
}

/* =====================================================================
 * main
 * ===================================================================== */

int main(void)
{
	printf("=== iso_scan common (GetGrubVersion / GetGrubFs / GetEfiBootInfo) ===\n");

	printf("\n  GetGrubVersion\n");
	RUN(grub_version_double_space);
	RUN(grub_version_single_space_fedora);
	RUN(grub_version_not_set_if_already_populated);
	RUN(grub_version_empty_buf);
	RUN(grub_version_too_small_buf);
	RUN(grub_version_kaspersky_zero_prefix);
	RUN(grub_version_nonstandard_suffix);
	RUN(grub_version_gdie_suffix);
	RUN(grub_version_null_source_no_crash);
	RUN(grub_version_206_appends_label);

	printf("\n  GetGrubFs\n");
	RUN(grub_fs_finds_fat);
	RUN(grub_fs_finds_ext2);
	RUN(grub_fs_deduplicates);
	RUN(grub_fs_ignores_too_long_name);
	RUN(grub_fs_empty_buf);
	RUN(grub_fs_too_small_buf);
	RUN(grub_fs_null_filesystems_no_crash);
	RUN(grub_fs_multiple_entries);

	printf("\n  GetEfiBootInfo\n");
	RUN(efi_boot_info_shim_detected);
	RUN(efi_boot_info_systemd_boot_detected);
	RUN(efi_boot_info_empty_buf);
	RUN(efi_boot_info_too_small);
	RUN(efi_boot_info_no_match);
	RUN(efi_boot_info_null_source_no_crash);
	RUN(efi_boot_info_version_at_offset);

	TEST_RESULTS();
}
