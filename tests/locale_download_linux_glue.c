/*
 * locale_download_linux_glue.c — build shim for test_locale_download_linux.
 *
 * Provides stubs for everything net.c needs that isn't supplied by the
 * other source files in the test build (real net.c, parser.c, stdfn.c,
 * stdio.c, common/parser.c, common/localization.c).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "windows.h"
#include "commctrl.h"
#include "rufus.h"
#include "localization.h"

/* ---- globals that net.c externs ---- */
RUFUS_UPDATE update              = { {0,0,0}, {0,0}, NULL, NULL, NULL, 0 };
windows_version_t WindowsVersion = { 0 };
char app_data_dir[MAX_PATH]      = "";
char temp_dir[MAX_PATH]          = "/tmp";
HWND hMainDialog                 = NULL;
DWORD ErrorStatus                = 0;
DWORD DownloadStatus             = 0;
char *fido_url                   = NULL;
char *image_path                 = NULL;
char *ini_file                   = NULL;
loc_cmd *selected_locale         = NULL;
BOOL right_to_left_mode          = FALSE;
uint16_t rufus_version[3]        = { 4, 0, 0 };

/* ---- efi_archname (defined in iso.c; referenced by net.c) ---- */
const char* efi_archname[] = {
	"", "ia32", "x64", "arm", "aa64", "ia64", "riscv64", "loongarch64", "ebc"
};

/* ---- PostMessage / SendMessage ---- */
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

/* ---- bled stubs ---- */
typedef void (*bled_printf_t)(const char *, ...);
typedef long ssize_t;
int bled_init(uint32_t sz, void *pf, void *rf, void *wf,
              void *pg, void *sw, unsigned long *cr)
{
	(void)sz; (void)pf; (void)rf; (void)wf; (void)pg; (void)sw; (void)cr;
	return 0;
}
long bled_uncompress_to_dir(const char *src, const char *dst, bled_printf_t fn)
{
	(void)src; (void)dst; (void)fn;
	return -1;
}
ssize_t bled_uncompress_from_buffer_to_buffer(const uint8_t *in, size_t in_sz,
                                               uint8_t **out, size_t *out_sz)
{
	(void)in; (void)in_sz; (void)out; (void)out_sz;
	return -1;
}
void bled_exit(void) {}

/* ---- dialog stubs ---- */
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
	return IDNO;
}

/* ---- ValidateOpensslSignature stub ---- */
BOOL ValidateOpensslSignature(BYTE *pbBuffer, DWORD dwBufferLen,
                               BYTE *pbSignature, DWORD dwSigLen)
{
	(void)pbBuffer; (void)dwBufferLen; (void)pbSignature; (void)dwSigLen;
	return FALSE;
}

/* ---- Progress stubs ---- */
void UpdateProgress(int op, float pct) { (void)op; (void)pct; }
void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL f)
{
	(void)op; (void)msg; (void)cur; (void)tot; (void)f;
}
