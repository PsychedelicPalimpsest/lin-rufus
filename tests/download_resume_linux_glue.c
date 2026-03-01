/*
 * download_resume_linux_glue.c — minimal stubs for the test_download_resume_linux build.
 *
 * The download_resume.c helpers are pure POSIX — they only need BOOL/TRUE/FALSE
 * from the compat layer.  There are no network, UI, or settings dependencies.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>

/* compat layer */
#include "windows.h"
#include "rufus.h"

/* uprintf stub (download_resume.c never calls it, but the linker may need it) */
void uprintf(const char *fmt, ...) { (void)fmt; }
