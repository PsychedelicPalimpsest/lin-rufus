/*
 * iso_report_linux_glue.c — minimal stubs for test_iso_report_linux
 *
 * Provides:
 *  - uprintf / rufus_set_log_handler  (replaces linux/stdio.c)
 *  - SizeToHumanReadable              (simple portable implementation)
 *  - old_c32_name[]                   (from iso.c; needed by log_iso_report)
 *  - img_report                       (global RUFUS_IMG_REPORT)
 *  - Notification stub                (never called on Linux builds)
 *  - lmprintf stub                    (returns empty string; Notification path only)
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

/* ---- global required by log_iso_report ---- */
RUFUS_IMG_REPORT img_report = { 0 };

/* ---- old_c32_name (defined in iso.c for normal builds) ---- */
const char* old_c32_name[NB_OLD_C32] = OLD_C32_NAMES;

/* ---- minimal uprintf / log handler ---- */
static void (*g_log_handler)(const char *msg) = NULL;

void rufus_set_log_handler(void (*fn)(const char *msg))
{
    g_log_handler = fn;
}

void uprintf(const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = '\0';
    if (g_log_handler)
        g_log_handler(buf);
    else
        fprintf(stderr, "%s\n", buf);
}

/* ---- SizeToHumanReadable ---- */
char* SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units)
{
    static char str[32];
    static const char* suffix[] = { "B", "KB", "MB", "GB", "TB", "PB" };
    double hr = (double)size;
    int s = 0;
    const double div = fake_units ? 1000.0 : 1024.0;
    (void)copy_to_log;
    while (s < 5 && hr >= div) { hr /= div; s++; }
    if (s == 0)
        snprintf(str, sizeof(str), "%d %s", (int)hr, suffix[s]);
    else
        snprintf(str, sizeof(str), (hr - (int)hr < 0.05) ? "%.0f %s" : "%.1f %s", hr, suffix[s]);
    return str;
}

/* ---- lmprintf stub (only needed for Windows Notification path) ---- */
char* lmprintf(uint32_t msg_id, ...)
{
    (void)msg_id;
    return "";
}
