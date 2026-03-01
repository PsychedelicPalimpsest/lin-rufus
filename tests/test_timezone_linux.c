/*
 * Rufus: The Reliable USB Formatting Utility
 * Unit tests for IANA → Windows timezone mapping (Linux)
 * Copyright © 2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

/* ── Pull in the module under test ─────────────────────────────────────── */
#include "timezone.h"   /* IanaToWindowsTimezone, timezone_set_tz_injection */

/* ── Minimal test harness ───────────────────────────────────────────────── */
static int tests_run    = 0;
static int tests_failed = 0;

#define CHECK(cond, msg) do { \
    ++tests_run; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
        ++tests_failed; \
    } else { \
        printf("  ok: %s\n", msg); \
    } \
} while (0)

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/* Runs a single lookup and checks exact expected result. */
static void check_lookup(const char* iana, const char* expected_win)
{
    char label[128];
    timezone_set_tz_injection(iana);
    const char* result = IanaToWindowsTimezone();
    snprintf(label, sizeof(label), "IANA '%s' -> '%s'", iana, expected_win);
    CHECK(result != NULL, label);
    if (result) {
        snprintf(label, sizeof(label), "IANA '%s' value matches", iana);
        CHECK(strcmp(result, expected_win) == 0, label);
    }
}

/* ── Test cases ─────────────────────────────────────────────────────────── */

static void test_utc(void)
{
    printf("\nutc:\n");
    check_lookup("UTC",           "UTC");
    check_lookup("Etc/UTC",       "UTC");
    check_lookup("Etc/GMT",       "UTC");
    check_lookup("Etc/GMT+0",     "UTC");
    check_lookup("Etc/GMT-0",     "UTC");
}

static void test_americas(void)
{
    printf("\namericas:\n");
    check_lookup("America/New_York",       "Eastern Standard Time");
    check_lookup("America/Detroit",        "Eastern Standard Time");
    check_lookup("America/Chicago",        "Central Standard Time");
    check_lookup("America/Denver",         "Mountain Standard Time");
    check_lookup("America/Los_Angeles",    "Pacific Standard Time");
    check_lookup("America/Anchorage",      "Alaskan Standard Time");
    check_lookup("Pacific/Honolulu",       "Hawaiian Standard Time");
    check_lookup("America/Phoenix",        "US Mountain Standard Time");
    check_lookup("America/Toronto",        "Eastern Standard Time");
    check_lookup("America/Vancouver",      "Pacific Standard Time");
    check_lookup("America/Sao_Paulo",      "E. South America Standard Time");
    check_lookup("America/Buenos_Aires",   "Argentina Standard Time");
    check_lookup("America/Argentina/Buenos_Aires", "Argentina Standard Time");
    check_lookup("America/Bogota",         "SA Pacific Standard Time");
    check_lookup("America/Mexico_City",    "Central Standard Time (Mexico)");
    check_lookup("America/Caracas",        "Venezuela Standard Time");
    check_lookup("America/Santiago",       "Pacific SA Standard Time");
    check_lookup("America/Lima",           "SA Pacific Standard Time");
}

static void test_europe(void)
{
    printf("\neurope:\n");
    check_lookup("Europe/London",           "GMT Standard Time");
    check_lookup("Europe/Dublin",           "GMT Standard Time");
    check_lookup("Europe/Paris",            "Romance Standard Time");
    check_lookup("Europe/Berlin",           "W. Europe Standard Time");
    check_lookup("Europe/Amsterdam",        "W. Europe Standard Time");
    check_lookup("Europe/Rome",             "W. Europe Standard Time");
    check_lookup("Europe/Madrid",           "Romance Standard Time");
    check_lookup("Europe/Warsaw",           "Central European Standard Time");
    check_lookup("Europe/Prague",           "Central Europe Standard Time");
    check_lookup("Europe/Helsinki",         "FLE Standard Time");
    check_lookup("Europe/Athens",           "GTB Standard Time");
    check_lookup("Europe/Istanbul",         "Turkey Standard Time");
    check_lookup("Europe/Moscow",           "Russia Time Zone 3");
    check_lookup("Europe/Bucharest",        "GTB Standard Time");
    check_lookup("Europe/Lisbon",           "GMT Standard Time");
    check_lookup("Europe/Stockholm",        "W. Europe Standard Time");
    check_lookup("Europe/Kiev",             "FLE Standard Time");
    check_lookup("Europe/Kyiv",             "FLE Standard Time");
    check_lookup("Europe/Zurich",           "W. Europe Standard Time");
    check_lookup("Europe/Brussels",         "Romance Standard Time");
    check_lookup("Europe/Vienna",           "W. Europe Standard Time");
    check_lookup("Europe/Copenhagen",       "Romance Standard Time");
    check_lookup("Europe/Budapest",         "Central Europe Standard Time");
    check_lookup("Europe/Minsk",            "Belarus Standard Time");
    check_lookup("Europe/Riga",             "FLE Standard Time");
    check_lookup("Europe/Tallinn",          "FLE Standard Time");
    check_lookup("Europe/Vilnius",          "FLE Standard Time");
    check_lookup("Europe/Sofia",            "FLE Standard Time");
    check_lookup("Europe/Belgrade",         "Central Europe Standard Time");
    check_lookup("Europe/Sarajevo",         "Central European Standard Time");
    check_lookup("Europe/Zagreb",           "Central European Standard Time");
    check_lookup("Europe/Skopje",           "Central European Standard Time");
    check_lookup("Europe/Ljubljana",        "Central European Standard Time");
    check_lookup("Europe/Bratislava",       "Central Europe Standard Time");
    check_lookup("Atlantic/Reykjavik",      "Greenwich Standard Time");
    check_lookup("Europe/Kaliningrad",      "Kaliningrad Standard Time");
    check_lookup("Europe/Samara",           "Russia Time Zone 3");
    check_lookup("Europe/Volgograd",        "Volgograd Standard Time");
}

static void test_asia(void)
{
    printf("\nasia:\n");
    check_lookup("Asia/Tokyo",        "Tokyo Standard Time");
    check_lookup("Asia/Shanghai",     "China Standard Time");
    check_lookup("Asia/Hong_Kong",    "China Standard Time");
    check_lookup("Asia/Taipei",       "Taipei Standard Time");
    check_lookup("Asia/Seoul",        "Korea Standard Time");
    check_lookup("Asia/Singapore",    "Singapore Standard Time");
    check_lookup("Asia/Kolkata",      "India Standard Time");
    check_lookup("Asia/Calcutta",     "India Standard Time");
    check_lookup("Asia/Dubai",        "Arabian Standard Time");
    check_lookup("Asia/Riyadh",       "Arab Standard Time");
    check_lookup("Asia/Jerusalem",    "Israel Standard Time");
    check_lookup("Asia/Karachi",      "Pakistan Standard Time");
    check_lookup("Asia/Dhaka",        "Bangladesh Standard Time");
    check_lookup("Asia/Bangkok",      "SE Asia Standard Time");
    check_lookup("Asia/Jakarta",      "SE Asia Standard Time");
    check_lookup("Asia/Kuala_Lumpur", "Singapore Standard Time");
    check_lookup("Asia/Manila",       "Singapore Standard Time");
    check_lookup("Asia/Colombo",      "Sri Lanka Standard Time");
    check_lookup("Asia/Kathmandu",    "Nepal Standard Time");
    check_lookup("Asia/Katmandu",     "Nepal Standard Time");
    check_lookup("Asia/Kabul",        "Afghanistan Standard Time");
    check_lookup("Asia/Tehran",       "Iran Standard Time");
    check_lookup("Asia/Yekaterinburg","Ekaterinburg Standard Time");
    check_lookup("Asia/Omsk",         "Omsk Standard Time");
    check_lookup("Asia/Novosibirsk",  "N. Central Asia Standard Time");
    check_lookup("Asia/Krasnoyarsk",  "North Asia Standard Time");
    check_lookup("Asia/Irkutsk",      "North Asia East Standard Time");
    check_lookup("Asia/Yakutsk",      "Yakutsk Standard Time");
    check_lookup("Asia/Vladivostok",  "Vladivostok Standard Time");
    check_lookup("Asia/Magadan",      "Magadan Standard Time");
    check_lookup("Asia/Tbilisi",      "Georgian Standard Time");
    check_lookup("Asia/Baku",         "Azerbaijan Standard Time");
    check_lookup("Asia/Yerevan",      "Caucasus Standard Time");
    check_lookup("Asia/Almaty",       "Central Asia Standard Time");
    check_lookup("Asia/Tashkent",     "West Asia Standard Time");
    check_lookup("Asia/Baghdad",      "Arabic Standard Time");
    check_lookup("Asia/Beirut",       "Middle East Standard Time");
    check_lookup("Asia/Amman",        "Jordan Standard Time");
    check_lookup("Asia/Damascus",     "Syria Standard Time");
    check_lookup("Asia/Nicosia",      "GTB Standard Time");
    check_lookup("Asia/Ulaanbaatar",  "Ulaanbaatar Standard Time");
    check_lookup("Asia/Rangoon",      "Myanmar Standard Time");
    check_lookup("Asia/Yangon",       "Myanmar Standard Time");
    check_lookup("Asia/Colombo",      "Sri Lanka Standard Time");
}

static void test_africa_pacific_australia(void)
{
    printf("\nafrica/pacific/australia:\n");
    check_lookup("Africa/Cairo",          "Egypt Standard Time");
    check_lookup("Africa/Johannesburg",   "South Africa Standard Time");
    check_lookup("Africa/Lagos",          "W. Central Africa Standard Time");
    check_lookup("Africa/Nairobi",        "E. Africa Standard Time");
    check_lookup("Africa/Casablanca",     "Morocco Standard Time");
    check_lookup("Africa/Harare",         "South Africa Standard Time");
    check_lookup("Africa/Tripoli",        "Libya Standard Time");
    check_lookup("Africa/Khartoum",       "Sudan Standard Time");

    check_lookup("Australia/Sydney",      "AUS Eastern Standard Time");
    check_lookup("Australia/Melbourne",   "AUS Eastern Standard Time");
    check_lookup("Australia/Brisbane",    "E. Australia Standard Time");
    check_lookup("Australia/Adelaide",    "Cen. Australia Standard Time");
    check_lookup("Australia/Darwin",      "AUS Central Standard Time");
    check_lookup("Australia/Perth",       "W. Australia Standard Time");
    check_lookup("Australia/Hobart",      "Tasmania Standard Time");

    check_lookup("Pacific/Auckland",      "New Zealand Standard Time");
    check_lookup("Pacific/Fiji",          "Fiji Standard Time");
    check_lookup("Pacific/Guam",          "West Pacific Standard Time");
    check_lookup("Pacific/Port_Moresby",  "West Pacific Standard Time");
    check_lookup("Pacific/Tongatapu",     "Tonga Standard Time");
    check_lookup("Pacific/Apia",          "Samoa Standard Time");
    check_lookup("Pacific/Chatham",       "Chatham Islands Standard Time");
}

static void test_etc_gmt_offsets(void)
{
    printf("\netc/gmt offsets:\n");
    /* Note: Etc/GMT+N is UTC-N (POSIX sign convention) */
    check_lookup("Etc/GMT+12",  "Dateline Standard Time");
    check_lookup("Etc/GMT+11",  "UTC-11");
    check_lookup("Etc/GMT+2",   "UTC-02");
    check_lookup("Etc/GMT-1",   "Cape Verde Standard Time");
    check_lookup("Etc/GMT-8",   "Singapore Standard Time");
    check_lookup("Etc/GMT-9",   "Tokyo Standard Time");
    check_lookup("Etc/GMT-10",  "West Pacific Standard Time");
    check_lookup("Etc/GMT-11",  "Central Pacific Standard Time");
    check_lookup("Etc/GMT-12",  "UTC+12");
}

static void test_unknown_falls_back_to_utc(void)
{
    printf("\nunknown_fallback:\n");
    timezone_set_tz_injection("Fake/Imaginary_Zone");
    const char* result = IanaToWindowsTimezone();
    CHECK(result != NULL, "unknown timezone returns non-NULL");
    if (result)
        CHECK(strcmp(result, "UTC") == 0, "unknown timezone falls back to UTC");
}

static void test_null_injection_returns_system_tz(void)
{
    printf("\nnull_injection_uses_system_tz:\n");
    /* With NULL injection, the function should read the real system timezone.
     * We can't predict the exact value, but it must return a non-NULL,
     * non-empty string. */
    timezone_set_tz_injection(NULL);
    const char* result = IanaToWindowsTimezone();
    CHECK(result != NULL, "system timezone returns non-NULL");
    if (result)
        CHECK(result[0] != '\0', "system timezone returns non-empty string");
}

static void test_etc_timezone_file(void)
{
    printf("\netc_timezone_file:\n");
    /* Write a fake /etc/timezone-style file and inject the path */
    char tmpdir[] = "/tmp/test_tz_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    assert(dir != NULL);

    char tz_file[256];
    snprintf(tz_file, sizeof(tz_file), "%s/timezone", dir);
    FILE* f = fopen(tz_file, "w");
    assert(f);
    fprintf(f, "Asia/Tokyo\n");
    fclose(f);

    timezone_set_etc_timezone_path(tz_file);
    timezone_set_tz_injection(NULL); /* use file, not injection */
    const char* result = IanaToWindowsTimezone();
    CHECK(result != NULL, "etc_timezone result non-NULL");
    if (result)
        CHECK(strcmp(result, "Tokyo Standard Time") == 0, "etc_timezone Tokyo");

    /* Clean up */
    unlink(tz_file);
    rmdir(dir);
    timezone_set_etc_timezone_path(NULL); /* restore default */
}

static void test_localtime_symlink(void)
{
    printf("\nlocaltime_symlink:\n");
    /* Create a symlink pointing to a zoneinfo path and inject it */
    char tmpdir[] = "/tmp/test_tz_XXXXXX";
    char* dir = mkdtemp(tmpdir);
    assert(dir != NULL);

    /* Create a fake zoneinfo root: <dir>/zoneinfo/Europe/Paris */
    char zi_dir[256], zone_file[256], link_path[256];
    snprintf(zi_dir, sizeof(zi_dir), "%s/zoneinfo/Europe", dir);
    mkdir(zi_dir - strlen("/Europe"), 0755);  /* won't work - use two mkdirs */

    char zi_root[256];
    snprintf(zi_root, sizeof(zi_root), "%s/zoneinfo", dir);
    mkdir(zi_root, 0755);
    mkdir(zi_dir, 0755);

    snprintf(zone_file, sizeof(zone_file), "%s/zoneinfo/Europe/Paris", dir);
    FILE* f = fopen(zone_file, "w");
    assert(f);
    fclose(f);

    snprintf(link_path, sizeof(link_path), "%s/localtime", dir);
    symlink(zone_file, link_path);

    timezone_set_localtime_path(link_path);
    timezone_set_zoneinfo_root(zi_root);
    timezone_set_etc_timezone_path(NULL);
    timezone_set_tz_injection(NULL);

    const char* result = IanaToWindowsTimezone();
    CHECK(result != NULL, "localtime symlink result non-NULL");
    if (result)
        CHECK(strcmp(result, "Romance Standard Time") == 0, "localtime symlink Europe/Paris");

    /* Clean up */
    unlink(link_path);
    unlink(zone_file);
    rmdir(zi_dir);
    rmdir(zi_root);
    rmdir(dir);

    timezone_set_localtime_path(NULL);
    timezone_set_zoneinfo_root(NULL);
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(void)
{
    printf("timezone_linux tests\n");
    printf("====================\n");

    test_utc();
    test_americas();
    test_europe();
    test_asia();
    test_africa_pacific_australia();
    test_etc_gmt_offsets();
    test_unknown_falls_back_to_utc();
    test_null_injection_returns_system_tz();
    test_etc_timezone_file();
    test_localtime_symlink();

    printf("\n%d passed, %d failed\n", tests_run - tests_failed, tests_failed);
    return tests_failed ? 1 : 0;
}
