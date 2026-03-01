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

/* ---- bled stubs (used by stdio.c's ExtractZip and DownloadISOThread) ---- */
typedef void (*bled_printf_t)(const char *, ...);
typedef long ssize_t;
int bled_init(uint32_t buffer_size, void *printf_fn, void *read_fn, void *write_fn,
              void *progress_fn, void *switch_fn, unsigned long *cancel_request)
{
	(void)buffer_size; (void)printf_fn; (void)read_fn; (void)write_fn;
	(void)progress_fn; (void)switch_fn; (void)cancel_request;
	return 0;
}
long bled_uncompress_to_dir(const char *src, const char *dst, bled_printf_t fn)
{
	(void)src; (void)dst; (void)fn;
	return -1;
}
ssize_t bled_uncompress_from_buffer_to_buffer(const uint8_t *in, size_t in_size,
                                               uint8_t **out, size_t *out_size)
{
	(void)in; (void)in_size; (void)out; (void)out_size;
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

char *get_token_data_buffer(const char *token, unsigned int n,
                             const char *buffer, size_t buffer_size)
{
	(void)token; (void)n; (void)buffer; (void)buffer_size;
	return NULL;
}

/* ---- localization stubs ---- */
char *lmprintf(uint32_t msg_id, ...)
{
	(void)msg_id;
	return "";
}

/* ---- dialog stubs (FileDialog, NotificationEx) ---- */
char *FileDialog(BOOL save, char *path, const ext_t *ext, UINT *selected_ext)
{
	(void)save; (void)path; (void)ext; (void)selected_ext;
	return NULL;
}

int NotificationEx(int type, const char *dont_display_setting,
                   const notification_info *more_info,
                   const char *title, const char *format, ...)
{
	(void)type; (void)dont_display_setting; (void)more_info;
	(void)title; (void)format;
	return IDOK;
}
