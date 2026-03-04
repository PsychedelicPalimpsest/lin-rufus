/*
 * test_dev_usb_speed_linux.c — TDD tests for USB speed detection in dev.c
 *
 * Tests cover the usb_speed_string() helper that converts a sysfs Mbps
 * value (e.g. "480") to a human-readable string ("USB 2.0").
 */

#define _GNU_SOURCE
#include "framework.h"

#include <string.h>
#include <stdlib.h>

/* ---- the function under test ------------------------------------------ */
#include "../src/linux/usb_speed.h"

/* ---- tests ------------------------------------------------------------- */

static void test_usb_speed_480(void)
{
	const char *s = usb_speed_string("480");
	CHECK_STR_EQ(s, "USB 2.0");
}

static void test_usb_speed_5000(void)
{
	const char *s = usb_speed_string("5000");
	CHECK_STR_EQ(s, "USB 3.0");
}

static void test_usb_speed_10000(void)
{
	const char *s = usb_speed_string("10000");
	CHECK_STR_EQ(s, "USB 3.1");
}

static void test_usb_speed_20000(void)
{
	const char *s = usb_speed_string("20000");
	CHECK_STR_EQ(s, "USB 3.2");
}

static void test_usb_speed_40000(void)
{
	const char *s = usb_speed_string("40000");
	CHECK_STR_EQ(s, "USB 4");
}

static void test_usb_speed_12(void)
{
	const char *s = usb_speed_string("12");
	CHECK_STR_EQ(s, "USB 1.1");
}

static void test_usb_speed_1_5(void)
{
	const char *s = usb_speed_string("1.5");
	CHECK_STR_EQ(s, "USB 1.0");
}

static void test_usb_speed_null(void)
{
	const char *s = usb_speed_string(NULL);
	CHECK_STR_EQ(s, "USB");
}

static void test_usb_speed_empty(void)
{
	const char *s = usb_speed_string("");
	CHECK_STR_EQ(s, "USB");
}

static void test_usb_speed_unknown(void)
{
	/* 0 Mbps doesn't match any known speed → falls back to "USB" */
	const char *s = usb_speed_string("0");
	CHECK_STR_EQ(s, "USB");
}

static void test_usb_speed_leading_whitespace(void)
{
	/* sysfs attributes may have trailing newline; the function should be
	 * robust to typical trimmed values; leading space is unusual but should
	 * not crash. */
	const char *s = usb_speed_string(" 480");
	/* Either matches USB 2.0 (if we strip) or falls back to USB — either
	 * is acceptable; we just test it doesn't crash and returns something. */
	CHECK(s != NULL);
}

static void test_usb_speed_1(void)
{
	/* Exactly 1 Mbps → USB 1.0 */
	const char *s = usb_speed_string("1");
	CHECK_STR_EQ(s, "USB 1.0");
}

static void test_usb_speed_negative(void)
{
	/* Negative value is not a valid speed — falls back to "USB" */
	const char *s = usb_speed_string("-1");
	CHECK_STR_EQ(s, "USB");
}

static void test_usb_speed_very_large(void)
{
	/* 80000 Mbps — still USB 4 (≥40000) */
	const char *s = usb_speed_string("80000");
	CHECK_STR_EQ(s, "USB 4");
}

static void test_usb_speed_boundary_5000(void)
{
	/* Exactly 5000 Mbps → USB 3.0 */
	const char *s = usb_speed_string("5000");
	CHECK_STR_EQ(s, "USB 3.0");
}

static void test_usb_speed_boundary_4999(void)
{
	/* 4999 Mbps is below 5000 but ≥480 → USB 2.0 */
	const char *s = usb_speed_string("4999");
	CHECK_STR_EQ(s, "USB 2.0");
}

static void test_usb_speed_text_value(void)
{
	/* Non-numeric string → strtol returns 0 → "USB" */
	const char *s = usb_speed_string("high");
	CHECK_STR_EQ(s, "USB");
}

/* ---- main -------------------------------------------------------------- */
int main(void)
{
	RUN_TEST(test_usb_speed_480);
	RUN_TEST(test_usb_speed_5000);
	RUN_TEST(test_usb_speed_10000);
	RUN_TEST(test_usb_speed_20000);
	RUN_TEST(test_usb_speed_40000);
	RUN_TEST(test_usb_speed_12);
	RUN_TEST(test_usb_speed_1_5);
	RUN_TEST(test_usb_speed_null);
	RUN_TEST(test_usb_speed_empty);
	RUN_TEST(test_usb_speed_unknown);
	RUN_TEST(test_usb_speed_leading_whitespace);
	RUN_TEST(test_usb_speed_1);
	RUN_TEST(test_usb_speed_negative);
	RUN_TEST(test_usb_speed_very_large);
	RUN_TEST(test_usb_speed_boundary_5000);
	RUN_TEST(test_usb_speed_boundary_4999);
	RUN_TEST(test_usb_speed_text_value);

	PRINT_RESULTS();
	return (_fail == 0) ? 0 : 1;
}
