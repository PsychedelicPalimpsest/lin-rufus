/*
 * test_format_common.c — Tests for common format helper functions
 *
 * Tests ToValidLabel() from src/common/format.c.
 * The function is portable and compiled for both Linux and Windows builds.
 *
 * Test coverage:
 *   - NULL input (no crash)
 *   - Empty label unchanged
 *   - Basic ASCII label: uppercase for FAT, unchanged for NTFS
 *   - Unauthorized chars removed (*, ?, ,, ;, :, /, \, |, +, =, <, >, [, ], ")
 *   - Period → underscore for both FAT and NTFS
 *   - Tab → underscore for both FAT and NTFS
 *   - FAT truncation at 11 characters
 *   - NTFS truncation at 32 characters
 *   - Non-ASCII UTF-8 sequence → single underscore for FAT
 *   - Non-ASCII UTF-8 sequence passes through for NTFS
 *   - img_report.usb_label updated to match
 *   - Mostly-underscore FAT fallback to SizeToHumanReadable
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "framework.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Include the common format module under test                          */
/* ------------------------------------------------------------------ */
#include "../src/common/label.h"
#include "../src/common/drive.h"

/* ------------------------------------------------------------------ */
/* Minimal stubs for globals and functions used by ToValidLabel()       */
/* ------------------------------------------------------------------ */

RUFUS_DRIVE_INFO SelectedDrive = {0};
RUFUS_IMG_REPORT img_report = {0};

BOOL right_to_left_mode = FALSE;

/* uprintf stub: discard output in tests */
void uprintf(const char *fmt, ...)
{
	(void)fmt;
}

/* SizeToHumanReadable stub: returns a simple ASCII string */
char *SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units)
{
	static char buf[32];
	(void)copy_to_log;
	(void)fake_units;
	/* For simplicity: return "X.X GB" or "XXX MB" based on size */
	if (size >= (uint64_t)1024 * 1024 * 1024) {
		double gb = (double)size / (1024.0 * 1024.0 * 1024.0);
		snprintf(buf, sizeof(buf), "%.1f GB", gb);
	} else {
		double mb = (double)size / (1024.0 * 1024.0);
		snprintf(buf, sizeof(buf), "%.1f MB", mb);
	}
	return buf;
}

/* ------------------------------------------------------------------ */
/* Helper: reset img_report.usb_label before each test                 */
/* ------------------------------------------------------------------ */
static void reset_state(void)
{
	memset(&img_report, 0, sizeof(img_report));
	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
}

/* ================================================================== */
/* Tests                                                               */
/* ================================================================== */

/* Null input must not crash */
TEST(to_valid_label_null_no_crash)
{
	ToValidLabel(NULL, TRUE);
	/* If we get here without crashing the test passes */
	CHECK(1);
}

/* Empty label stays empty */
TEST(to_valid_label_empty_fat)
{
	char label[64] = "";
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_STR_EQ("", label);
}

TEST(to_valid_label_empty_ntfs)
{
	char label[64] = "";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("", label);
}

/* Basic ASCII: FAT forces uppercase */
TEST(to_valid_label_lowercase_to_upper_fat)
{
	char label[64] = "hello";
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_STR_EQ("HELLO", label);
}

/* Basic ASCII: NTFS preserves case */
TEST(to_valid_label_lowercase_preserved_ntfs)
{
	char label[64] = "hello";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("hello", label);
}

/* Mixed case preserved for NTFS */
TEST(to_valid_label_mixed_case_ntfs)
{
	char label[64] = "MyDrive";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("MyDrive", label);
}

/* Unauthorized chars are removed from FAT label */
TEST(to_valid_label_unauthorized_removed_fat)
{
	char label[64] = "A*B?C";
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_STR_EQ("ABC", label);
}

/* Unauthorized chars are removed from NTFS label */
TEST(to_valid_label_unauthorized_removed_ntfs)
{
	char label[64] = "A/B\\C";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("ABC", label);
}

/* All unauthorized chars removed */
TEST(to_valid_label_all_unauthorized)
{
	char label[64] = "*?,;:/\\|+=<>[]\"";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("", label);
}

/* Period → underscore for FAT */
TEST(to_valid_label_dot_to_underscore_fat)
{
	char label[64] = "A.B";
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_STR_EQ("A_B", label);
}

/* Period → underscore for NTFS */
TEST(to_valid_label_dot_to_underscore_ntfs)
{
	char label[64] = "A.B";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("A_B", label);
}

/* Tab → underscore for FAT */
TEST(to_valid_label_tab_to_underscore_fat)
{
	char label[64] = "A\tB";
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_STR_EQ("A_B", label);
}

/* Tab → underscore for NTFS */
TEST(to_valid_label_tab_to_underscore_ntfs)
{
	char label[64] = "A\tB";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("A_B", label);
}

/* FAT truncation at 11 chars */
TEST(to_valid_label_fat_truncate_at_11)
{
	char label[64] = "ABCDEFGHIJKLMNOP";  /* 16 chars */
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_INT_EQ(11, (int)strlen(label));
	CHECK_STR_EQ("ABCDEFGHIJK", label);
}

/* NTFS truncation at 32 chars */
TEST(to_valid_label_ntfs_truncate_at_32)
{
	/* 40 chars */
	char label[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJ";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_INT_EQ(32, (int)strlen(label));
}

/* FAT: non-ASCII UTF-8 → single underscore per codepoint */
TEST(to_valid_label_utf8_to_underscore_fat)
{
	/* "café" — c, a, f, then U+00E9 (0xC3 0xA9) → 4 codepoints */
	char label[64] = "caf\xc3\xa9";
	reset_state();
	ToValidLabel(label, TRUE);
	/* c→C, a→A, f→F, é→_ */
	CHECK_STR_EQ("CAF_", label);
}

/* FAT: multiple non-ASCII codepoints each become one underscore.
 * Use "AB\xc3\xa9" (ABé → AB_): 3 chars, 1 underscore.
 * 3 < 2*1=2 is FALSE → no fallback. */
TEST(to_valid_label_utf8_multiple_fat)
{
	/* U+0041 U+0042 U+00E9 = "ABé" → A, B, _ (1 non-ASCII → 1 underscore) */
	char label[64] = "AB\xc3\xa9";
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_STR_EQ("AB_", label);
}

/* NTFS: non-ASCII UTF-8 passes through unchanged */
TEST(to_valid_label_utf8_passthrough_ntfs)
{
	/* "café" — must survive NTFS sanitization */
	char label[64] = "caf\xc3\xa9";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("caf\xc3\xa9", label);
}

/* NTFS: multi-byte sequence near 32-codepoint limit */
TEST(to_valid_label_utf8_ntfs_truncate_at_32_cp)
{
	/* 33 codepoints where the last is a 2-byte sequence */
	/* "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" = 32 codepoints, then "é" = 33rd */
	char label[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\xc3\xa9";
	reset_state();
	ToValidLabel(label, FALSE);
	/* Should stop at 32 codepoints — the é is codepoint 33, should not appear */
	CHECK_INT_EQ(32, (int)strlen(label));
	/* Last char should be '5', not a UTF-8 lead byte */
	CHECK_INT_EQ('5', (int)(unsigned char)label[31]);
}

/* img_report.usb_label is updated to match the sanitized label */
TEST(to_valid_label_updates_usb_label)
{
	char label[64] = "test";
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_STR_EQ("TEST", img_report.usb_label);
}

TEST(to_valid_label_updates_usb_label_ntfs)
{
	char label[64] = "MyVolume";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("MyVolume", img_report.usb_label);
}

/* All-underscore label should trigger fallback for FAT (if DiskSize set) */
TEST(to_valid_label_all_underscore_fallback_fat)
{
	char label[64] = "___";   /* All underscores — triggers fallback */
	reset_state();
	SelectedDrive.DiskSize = (uint64_t)8 * 1024 * 1024 * 1024ULL;  /* 8 GB */
	ToValidLabel(label, TRUE);
	/* After fallback, label should be a size string, not all underscores */
	CHECK(strchr(label, '_') == NULL || strlen(label) > 0);
	/* The label must not be "___" any more */
	CHECK(strcmp(label, "___") != 0);
}

/* The mostly-underscore test: "___A" (3 underscores, length 4, 3 < 2*1=2 is false)
 * but "____" (4 underscores, length 4, 4 < 2*4=8 is true) triggers fallback */
TEST(to_valid_label_mostly_underscore_triggers_fallback)
{
	char label[64] = "____";  /* 4 underscores: 4 < 2*4=8 → TRUE */
	reset_state();
	SelectedDrive.DiskSize = (uint64_t)4 * 1024 * 1024 * 1024ULL;  /* 4 GB */
	ToValidLabel(label, TRUE);
	/* The fallback converts size to label; result should not be "____" */
	CHECK(strcmp(label, "____") != 0);
}

/* Non-mostly-underscore does NOT trigger fallback */
TEST(to_valid_label_not_mostly_underscore_no_fallback)
{
	char label[64] = "USB_DRIVE";  /* 1 underscore in 9 chars: 9 < 2*1=2 is FALSE */
	reset_state();
	ToValidLabel(label, TRUE);
	/* Should stay as USB_DRIVE (uppercase, underscore preserved, 9 chars < 11 limit) */
	CHECK_STR_EQ("USB_DRIVE", label);
}

/* Verify "USB_DRIVE" (9 chars) fits in 11 and is not truncated */
TEST(to_valid_label_nine_chars_not_truncated)
{
	char label[64] = "USBDRIVE1";  /* 9 chars, all uppercase, no special chars */
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_INT_EQ(9, (int)strlen(label));
	CHECK_STR_EQ("USBDRIVE1", label);
}

/* Combination: mixed case + dots + unauthorized for FAT */
TEST(to_valid_label_combined_fat)
{
	char label[64] = "my.usb*drive";
	reset_state();
	ToValidLabel(label, TRUE);
	/* m→M, y→Y, .→_, u→U, s→S, b→B, *→removed, d→D, r→R, i→I, v→V, e→E */
	/* "MY_USBDRIVE" = 11 chars (exactly at FAT limit, no truncation) */
	CHECK_STR_EQ("MY_USBDRIVE", label);
}

/* Digits and spaces pass through unchanged for NTFS */
TEST(to_valid_label_digits_spaces_ntfs)
{
	char label[64] = "Volume 123";
	reset_state();
	ToValidLabel(label, FALSE);
	CHECK_STR_EQ("Volume 123", label);
}

/* Digits pass through for FAT (uppercase doesn't affect digits) */
TEST(to_valid_label_digits_fat)
{
	char label[64] = "USB123";
	reset_state();
	ToValidLabel(label, TRUE);
	CHECK_STR_EQ("USB123", label);
}

/* ------------------------------------------------------------------ */
int main(void)
{
	RUN(to_valid_label_null_no_crash);
	RUN(to_valid_label_empty_fat);
	RUN(to_valid_label_empty_ntfs);
	RUN(to_valid_label_lowercase_to_upper_fat);
	RUN(to_valid_label_lowercase_preserved_ntfs);
	RUN(to_valid_label_mixed_case_ntfs);
	RUN(to_valid_label_unauthorized_removed_fat);
	RUN(to_valid_label_unauthorized_removed_ntfs);
	RUN(to_valid_label_all_unauthorized);
	RUN(to_valid_label_dot_to_underscore_fat);
	RUN(to_valid_label_dot_to_underscore_ntfs);
	RUN(to_valid_label_tab_to_underscore_fat);
	RUN(to_valid_label_tab_to_underscore_ntfs);
	RUN(to_valid_label_fat_truncate_at_11);
	RUN(to_valid_label_ntfs_truncate_at_32);
	RUN(to_valid_label_utf8_to_underscore_fat);
	RUN(to_valid_label_utf8_multiple_fat);
	RUN(to_valid_label_utf8_passthrough_ntfs);
	RUN(to_valid_label_utf8_ntfs_truncate_at_32_cp);
	RUN(to_valid_label_updates_usb_label);
	RUN(to_valid_label_updates_usb_label_ntfs);
	RUN(to_valid_label_all_underscore_fallback_fat);
	RUN(to_valid_label_mostly_underscore_triggers_fallback);
	RUN(to_valid_label_not_mostly_underscore_no_fallback);
	RUN(to_valid_label_nine_chars_not_truncated);
	RUN(to_valid_label_combined_fat);
	RUN(to_valid_label_digits_spaces_ntfs);
	RUN(to_valid_label_digits_fat);
	TEST_RESULTS();
}
