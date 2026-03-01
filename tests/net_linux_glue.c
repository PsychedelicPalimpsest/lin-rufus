/*
 * net_linux_glue.c — stubs needed by test_net_linux to link net.c with
 * the CheckForUpdates implementation.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

/* ---- compat layer (windows.h etc.) ---- */
#include "windows.h"
#include "commctrl.h"
#include "rufus.h"

/* ---- parse_update stub ---- */
void parse_update(char *buf, size_t len)
{
	(void)buf; (void)len;
	/* In the test environment we don't parse anything. */
}

/* ---- DownloadNewVersion stub ---- */
void DownloadNewVersion(void) {}

/* ---- PostMessage / SendMessage stubs ----
 * msg_dispatch.c provides the real PostMessageA / SendMessageA in the build,
 * but the test link doesn't include it.  Provide minimal no-ops. */
BOOL PostMessageA(HWND h, UINT msg, WPARAM w, LPARAM l)
{
	(void)h; (void)msg; (void)w; (void)l;
	return TRUE;
}
LRESULT SendMessageA(HWND h, UINT msg, WPARAM w, LPARAM l)
{
	(void)h; (void)msg; (void)w; (void)l;
	return 0;
}

/* ---- bled stubs (used by stdio.c's ExtractZip) ---- */
typedef void (*bled_printf_t)(const char *, ...);
void bled_init(bled_printf_t fn) { (void)fn; }
long bled_uncompress_to_dir(const char *src, const char *dst, bled_printf_t fn)
{
	(void)src; (void)dst; (void)fn;
	return -1;
}
void bled_exit(void) {}

/* ---- settings parser stubs ----
 * ReadSetting* / WriteSetting* in settings.h call get_token_data_file_indexed
 * (via the get_token_data_file macro) and set_token_data_file.
 * The inline guards already return early when ini_file==NULL, but the linker
 * still needs the symbols to exist. */
char *get_token_data_file_indexed(const char *token, const char *filename, int index)
{
	(void)token; (void)filename; (void)index;
	return NULL;
}

char *set_token_data_file(const char *token, const char *data, const char *filename)
{
	(void)token; (void)data; (void)filename;
	return NULL;
}

char *get_sanitized_token_data_buffer(const char *token, int index,
                                       const char *buf, size_t buf_len)
{
	(void)token; (void)index; (void)buf; (void)buf_len;
	return NULL;
}
