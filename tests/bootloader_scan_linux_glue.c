/*
 * bootloader_scan_linux_glue.c — build stubs for test_bootloader_scan_linux
 *
 * Provides stubs for symbols referenced by image_scan.c's ImageScanThread
 * (ExtractISO, IsBootableImage, PopulateWindowsVersion) and by stdio.c
 * (bled, _UpdateProgressWithInfo).  Not needed functionally — the tests only
 * call GetBootladerInfo() which has its own injectable helpers.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

/* ---- image_scan.c → ImageScanThread stubs ---- */
BOOL  ExtractISO(const char *src, const char *dst, BOOL scan)
{ (void)src; (void)dst; (void)scan; return FALSE; }
int8_t IsBootableImage(const char *path) { (void)path; return 0; }
BOOL  PopulateWindowsVersion(void) { return FALSE; }

/* ---- stdio.c → progress / bled stubs ---- */
void _UpdateProgressWithInfo(int op, int msg, uint64_t processed, uint64_t total, BOOL force)
{ (void)op; (void)msg; (void)processed; (void)total; (void)force; }
void bled_init(void *a, void *b, void *c, void *d, void *e, void *f, void *g)
{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; }
int  bled_uncompress_to_dir(const char *a, const char *b, int c)
{ (void)a; (void)b; (void)c; return -1; }
void bled_exit(void) {}
