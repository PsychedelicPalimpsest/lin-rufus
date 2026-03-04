/*
 * test_progress_text_linux.c — TDD tests for format_progress_text()
 *
 * Tests are written BEFORE the implementation (TDD contract).
 * These tests exercise the progress display mode text formatting logic:
 *   - UPT_PERCENT: shows "XX.X%"
 *   - UPT_SPEED:   shows "X.X MB/s" / "X.X KB/s" / "N B/s" / "---"
 *   - UPT_ETA:     shows "H:MM:SS" / "-:--:--"
 */

#define _GNU_SOURCE
#include "framework.h"

#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <windows.h>

/* Units under test — progress.h includes rufus.h which defines BADLOCKS_PATTERN_TYPES */
#include "../src/linux/progress.h"
#include "ui.h"   /* UPT_PERCENT / UPT_SPEED / UPT_ETA / UPT_MAX */

/* ── UPT enum sanity ─────────────────────────────────────────────────── */

TEST(upt_enum_values) {
	CHECK_INT_EQ(0, UPT_PERCENT);
	CHECK_INT_EQ(1, UPT_SPEED);
	CHECK_INT_EQ(2, UPT_ETA);
	CHECK_INT_EQ(3, UPT_MAX);
}

/* ── UPT_PERCENT mode ────────────────────────────────────────────────── */

TEST(format_text_percent_mid) {
	char buf[64];
	format_progress_text(buf, sizeof(buf), UPT_PERCENT, 45.2, 0, UINT32_MAX);
	CHECK_STR_EQ("45.2%", buf);
}

TEST(format_text_percent_zero) {
	char buf[64];
	format_progress_text(buf, sizeof(buf), UPT_PERCENT, 0.0, 0, UINT32_MAX);
	CHECK_STR_EQ("0.0%", buf);
}

TEST(format_text_percent_full) {
	char buf[64];
	format_progress_text(buf, sizeof(buf), UPT_PERCENT, 100.0, 0, UINT32_MAX);
	CHECK_STR_EQ("100.0%", buf);
}

/* ── UPT_SPEED mode ──────────────────────────────────────────────────── */

TEST(format_text_speed_megabytes) {
	char buf[64];
	/* 5 MB/s exactly */
	uint64_t speed = (uint64_t)5 * 1024 * 1024;
	format_progress_text(buf, sizeof(buf), UPT_SPEED, 0.0, speed, UINT32_MAX);
	CHECK_STR_EQ("5.0 MB/s", buf);
}

TEST(format_text_speed_kilobytes) {
	char buf[64];
	/* 512 KB/s = 524288 B/s */
	uint64_t speed = (uint64_t)512 * 1024;
	format_progress_text(buf, sizeof(buf), UPT_SPEED, 0.0, speed, UINT32_MAX);
	CHECK_STR_EQ("512.0 KB/s", buf);
}

TEST(format_text_speed_bytes) {
	char buf[64];
	/* 500 B/s — below 1 KB */
	format_progress_text(buf, sizeof(buf), UPT_SPEED, 0.0, 500, UINT32_MAX);
	CHECK_STR_EQ("500 B/s", buf);
}

TEST(format_text_speed_zero_shows_dashes) {
	char buf[64];
	format_progress_text(buf, sizeof(buf), UPT_SPEED, 0.0, 0, UINT32_MAX);
	CHECK_STR_EQ("---", buf);
}

TEST(format_text_speed_boundary_1mb) {
	char buf[64];
	/* Exactly 1 MB/s → should show "1.0 MB/s" not "1024.0 KB/s" */
	uint64_t speed = (uint64_t)1 * 1024 * 1024;
	format_progress_text(buf, sizeof(buf), UPT_SPEED, 0.0, speed, UINT32_MAX);
	CHECK_STR_EQ("1.0 MB/s", buf);
}

TEST(format_text_speed_boundary_1kb) {
	char buf[64];
	/* Exactly 1 KB/s = 1024 B/s → should show "1.0 KB/s" */
	uint64_t speed = (uint64_t)1024;
	format_progress_text(buf, sizeof(buf), UPT_SPEED, 0.0, speed, UINT32_MAX);
	CHECK_STR_EQ("1.0 KB/s", buf);
}

/* ── UPT_ETA mode ────────────────────────────────────────────────────── */

TEST(format_text_eta_seconds_only) {
	char buf[64];
	/* 65 seconds = 0:01:05 */
	format_progress_text(buf, sizeof(buf), UPT_ETA, 0.0, 0, 65);
	CHECK_STR_EQ("0:01:05", buf);
}

TEST(format_text_eta_with_hours) {
	char buf[64];
	/* 7265 seconds = 2*3600 + 1*60 + 5 = 2:01:05 */
	format_progress_text(buf, sizeof(buf), UPT_ETA, 0.0, 0, 7265);
	CHECK_STR_EQ("2:01:05", buf);
}

TEST(format_text_eta_zero) {
	char buf[64];
	/* 0 seconds = 0:00:00 */
	format_progress_text(buf, sizeof(buf), UPT_ETA, 0.0, 0, 0);
	CHECK_STR_EQ("0:00:00", buf);
}

TEST(format_text_eta_unknown_shows_dashes) {
	char buf[64];
	format_progress_text(buf, sizeof(buf), UPT_ETA, 0.0, 0, UINT32_MAX);
	CHECK_STR_EQ("-:--:--", buf);
}

/* ── default / fallback ─────────────────────────────────────────────── */

TEST(format_text_unknown_mode_falls_back_to_percent) {
	char buf[64];
	/* mode 99 (unknown) should fall back to percent display */
	format_progress_text(buf, sizeof(buf), 99, 72.5, 0, UINT32_MAX);
	CHECK_STR_EQ("72.5%", buf);
}

/* ── main ──────────────────────────────────────────────────────────────── */

int main(void)
{
	RUN(upt_enum_values);
	RUN(format_text_percent_mid);
	RUN(format_text_percent_zero);
	RUN(format_text_percent_full);
	RUN(format_text_speed_megabytes);
	RUN(format_text_speed_kilobytes);
	RUN(format_text_speed_bytes);
	RUN(format_text_speed_zero_shows_dashes);
	RUN(format_text_speed_boundary_1mb);
	RUN(format_text_speed_boundary_1kb);
	RUN(format_text_eta_seconds_only);
	RUN(format_text_eta_with_hours);
	RUN(format_text_eta_zero);
	RUN(format_text_eta_unknown_shows_dashes);
	RUN(format_text_unknown_mode_falls_back_to_percent);
	TEST_RESULTS();
}
