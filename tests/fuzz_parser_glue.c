/*
 * fuzz_parser_glue.c — minimal stubs for the fuzz_parser build.
 * The fuzz harness uses real parser.c; we just need globals + uprintf.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "windows.h"
#include "rufus.h"

RUFUS_UPDATE update              = { {0,0,0}, {0,0}, NULL, NULL, NULL, 0 };
windows_version_t WindowsVersion = { 0 };
BOOL right_to_left_mode          = FALSE;
char *ini_file                   = NULL;

void uprintf(const char *fmt, ...)
{
	(void)fmt;
}
void uprintfs(const char *s)
{
	(void)s;
}
