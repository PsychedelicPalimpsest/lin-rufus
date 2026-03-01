/*
 * dos_linux_glue.c — stubs for symbols needed by the dos_linux tests
 * that are not provided by test_dos_linux.c, globals.c, stdio.c, or stdfn.c.
 */
#include <stdarg.h>
#include <stdint.h>
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/windows/localization.h"

/* ------------------------------------------------------------------ */
/* Log / progress stubs                                                */
/* ------------------------------------------------------------------ */

char* lmprintf(uint32_t msg_id, ...) { (void)msg_id; return (char*)""; }
void UpdateProgress(int op, float percent) { (void)op; (void)percent; }

void _UpdateProgressWithInfo(int op, int msg, uint64_t processed, uint64_t total, BOOL force) {
    (void)op; (void)msg; (void)processed; (void)total; (void)force;
}

/* ------------------------------------------------------------------ */
/* bled stubs — ExtractFreeDOS doesn't use zip extraction              */
/* ------------------------------------------------------------------ */

void bled_init(const char* src, const char* dst, int* fd,
               void (*pfn)(const uint64_t, const uint64_t)) {
    (void)src; (void)dst; (void)fd; (void)pfn;
}
int bled_uncompress_to_dir(const char* src, const char* dst, int type, const char* filter) {
    (void)src; (void)dst; (void)type; (void)filter; return -1;
}
void bled_exit(void) {}
