/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: net.c — networking via libcurl
 * Copyright © 2015-2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <curl/curl.h>

#include "rufus.h"
#include "missing.h"
#include "localization.h"
#include "resource.h"
#include "bled/bled.h"

/* Globals from globals.c / ui_gtk.c not declared in headers */
extern loc_cmd *selected_locale;
extern char   *fido_url;
extern char   *image_path;
extern HWND    hMainDialog;
extern DWORD   ErrorStatus;
extern char    temp_dir[];

/* Maximum download buffer chunk */
#define DOWNLOAD_BUFFER_SIZE (16 * 1024)

/* Extract the filename from a URL (last path component, trim query/fragment) */
static char *GetShortName(const char *url)
{
	static char short_name[128];
	size_t i, len = safe_strlen(url);
	char *p;

	if (len < 5)
		return NULL;

	for (i = len - 2; i > 0; i--) {
		if (url[i] == '/') {
			i++;
			break;
		}
	}
	memset(short_name, 0, sizeof(short_name));
	static_strcpy(short_name, &url[i]);
	/* Strip query string / fragment */
	if ((p = strstr(short_name, "%3F")) != NULL) *p = '\0';
	if ((p = strstr(short_name, "%3f")) != NULL) *p = '\0';
	for (i = 0; i < strlen(short_name); i++) {
		if (short_name[i] == '?' || short_name[i] == '#') {
			short_name[i] = '\0';
			break;
		}
	}
	return short_name;
}

/* ---- Context structs for libcurl write callbacks ---- */

/* Buffer-mode: accumulate data in a malloc'd block */
struct write_ctx_buf {
	uint8_t *data;
	size_t   len;
};

/* File-mode: write data directly to a FILE* */
struct write_ctx_file {
	FILE    *fp;
	uint64_t written;
};

/* ---- libcurl write callbacks ---- */

static size_t write_to_buf(void *ptr, size_t sz, size_t nmemb, void *ud)
{
	struct write_ctx_buf *ctx = (struct write_ctx_buf *)ud;
	size_t total = sz * nmemb;
	uint8_t *tmp = (uint8_t *)realloc(ctx->data, ctx->len + total + 1);
	if (tmp == NULL)
		return 0; /* CURLE_WRITE_ERROR */
	ctx->data = tmp;
	memcpy(ctx->data + ctx->len, ptr, total);
	ctx->len += total;
	ctx->data[ctx->len] = '\0';
	return total;
}

static size_t write_to_file(void *ptr, size_t sz, size_t nmemb, void *ud)
{
	struct write_ctx_file *ctx = (struct write_ctx_file *)ud;
	size_t total = sz * nmemb;
	size_t n = fwrite(ptr, 1, total, ctx->fp);
	ctx->written += n;
	return n;
}

/* ---- Internal URL helper ---- */

static const char *net_short_name(const char *url)
{
	static char name[128];
	size_t i, len;

	if (url == NULL)
		return "";
	len = strlen(url);
	for (i = len; i > 0; i--) {
		if (url[i - 1] == '/')
			break;
	}
	snprintf(name, sizeof(name), "%s", url + i);
	/* Strip query string */
	char *p = strchr(name, '?');
	if (p) *p = '\0';
	p = strchr(name, '#');
	if (p) *p = '\0';
	return name;
}

/* ---- IsDownloadable ---- */

/*
 * Return TRUE if `url` is a downloadable HTTP or HTTPS URL.
 * Only lowercase schemes are accepted (RFC 3986 §3.1 requires
 * case-insensitive comparison, but Rufus only generates lowercase URLs).
 */
BOOL IsDownloadable(const char *url)
{
	if (url == NULL || *url == '\0')
		return FALSE;
	return (strncmp(url, "http://",  7) == 0 ||
	        strncmp(url, "https://", 8) == 0);
}

/* ---- DownloadToFileOrBufferEx ---- */

/*
 * Download `url` to either a file or a heap buffer.
 *
 *  url    — HTTP or HTTPS URL to download (must not be NULL)
 *  file   — if non-NULL, write data to this path
 *  ua     — optional User-Agent string (NULL = libcurl default)
 *  buf    — if non-NULL and file==NULL, allocate a buffer and store pointer
 *            here; caller must free(*buf)
 *  hDlg   — HWND of the progress dialog (currently unused on Linux; kept for
 *            API compatibility with Windows)
 *  silent — if TRUE, suppress uprintf() output on error
 *
 * Returns the number of bytes downloaded, or 0 on error.
 * Sets global DownloadStatus to the HTTP response code.
 */
uint64_t DownloadToFileOrBufferEx(const char *url, const char *file,
    const char *ua, uint8_t **buf, HWND hDlg, BOOL silent)
{
	CURL *curl = NULL;
	CURLcode res;
	long http_code = 0;
	uint64_t size = 0;
	struct write_ctx_buf bctx = { NULL, 0 };
	struct write_ctx_file fctx = { NULL, 0 };

	(void)hDlg; /* progress dialog integration is a TODO */

	ErrorStatus   = 0;
	DownloadStatus = 404;

	if (url == NULL || (file == NULL && buf == NULL))
		return 0;

	if (!silent)
		uprintf("Downloading %s", net_short_name(url));

	curl = curl_easy_init();
	if (curl == NULL) {
		if (!silent)
			uprintf("curl_easy_init() failed");
		return 0;
	}

	/* Common options */
	curl_easy_setopt(curl, CURLOPT_URL,            url);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "identity");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR,    0L); /* check manually */
	if (ua != NULL && *ua != '\0')
		curl_easy_setopt(curl, CURLOPT_USERAGENT, ua);

	/* Set write callback */
	if (file != NULL) {
		fctx.fp = fopen(file, "wb");
		if (fctx.fp == NULL) {
			if (!silent)
				uprintf("Failed to open '%s' for writing", file);
			goto out;
		}
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_file);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &fctx);
	} else {
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_buf);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &bctx);
	}

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		if (!silent)
			uprintf("Download of '%s' failed: %s",
			        net_short_name(url), curl_easy_strerror(res));
		goto out;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	DownloadStatus = (DWORD)http_code;

	if (http_code != 200) {
		if (!silent)
			uprintf("HTTP %ld for '%s'", http_code, url);
		goto out;
	}

	/* Success — return data */
	if (file != NULL) {
		size = fctx.written;
	} else {
		size = bctx.len;
		if (buf != NULL) {
			*buf = bctx.data;
			bctx.data = NULL; /* ownership transferred to caller */
		}
	}

out:
	curl_easy_cleanup(curl);
	if (fctx.fp != NULL)
		fclose(fctx.fp);
	free(bctx.data); /* no-op if ownership was transferred */
	return size;
}

/* ---- Stubs for functions that depend on Windows-only subsystems ---- */

/*
 * DownloadSignedFile: download a file and verify its Authenticode signature.
 * On Linux, PKI/signature validation is not yet implemented.
 * Falls back to DownloadToFileOrBufferEx without signature verification.
 */
DWORD DownloadSignedFile(const char *url, const char *file, HWND hDlg, BOOL silent)
{
	uint64_t n = DownloadToFileOrBufferEx(url, file, NULL, NULL, hDlg, silent);
	return (n > 0) ? (DWORD)n : 0;
}

/* Threaded download: run DownloadSignedFile in a background thread */
typedef struct {
	const char *url;
	const char *file;
	HWND        hDlg;
	BOOL        silent;
} DownloadSignedFileArgs;

static DWORD WINAPI DownloadSignedFileThread(LPVOID param)
{
	DownloadSignedFileArgs *a = (DownloadSignedFileArgs *)param;
	DWORD r = DownloadSignedFile(a->url, a->file, a->hDlg, a->silent);
	free(a);
	ExitThread(r);
	return r;
}

HANDLE DownloadSignedFileThreaded(const char *url, const char *file,
    HWND hDlg, BOOL silent)
{
	DownloadSignedFileArgs *a = malloc(sizeof(*a));
	if (!a) return NULL;
	a->url    = url;
	a->file   = file;
	a->hDlg   = hDlg;
	a->silent = silent;
	HANDLE h = CreateThread(NULL, 0, DownloadSignedFileThread, a, 0, NULL);
	if (!h) free(a);
	return h;
}

/* ---- Update check ---- */

#include <time.h>
#include "settings.h"

#define DEFAULT_UPDATE_INTERVAL (24 * 3600)  /* seconds between update checks */

/* Convert a 3-component version array to a uint64 for comparison */
static __inline uint64_t ver_to_u64(uint16_t v[3])
{
	return ((uint64_t)v[0] << 32) | ((uint64_t)v[1] << 16) | (uint64_t)v[2];
}

/* Public helper: returns TRUE if server version is strictly newer than current. */
BOOL rufus_is_newer_version(uint16_t server[3], uint16_t current[3])
{
	return (ver_to_u64(server) > ver_to_u64(current)) ? TRUE : FALSE;
}

static BOOL force_update_check = FALSE;
static HANDLE update_check_thread = NULL;

static DWORD WINAPI CheckForUpdatesThread(LPVOID param)
{
	(void)param;
	uint8_t *buf = NULL;
	DWORD downloaded = 0;
	char url[256];

	/* Try to fetch a Linux version file from the Rufus release server.
	 * We attempt the generic "rufus_linux.ver" path. */
	snprintf(url, sizeof(url), "%s/rufus_linux.ver", RUFUS_URL);
	downloaded = DownloadToFileOrBuffer(url, NULL, &buf, NULL, FALSE);

	if (downloaded > 0 && buf != NULL) {
		/* NUL-terminate (buf already has downloaded bytes) */
		uint8_t *tmp = realloc(buf, downloaded + 1);
		if (tmp) {
			buf = tmp;
			buf[downloaded] = '\0';
		}
		/* Record check time */
		WriteSetting64(SETTING_LAST_UPDATE, (int64_t)time(NULL));
		/* Parse version/URL out of the buffer */
		parse_update((char *)buf, (size_t)downloaded + 1);

		if (rufus_is_newer_version(update.version, rufus_version)) {
			uprintf("New version %d.%d.%d available!",
			        update.version[0], update.version[1], update.version[2]);
			DownloadNewVersion();
		} else {
			uprintf("Rufus is up to date (%d.%d.%d).",
			        rufus_version[0], rufus_version[1], rufus_version[2]);
			PostMessage(hMainDialog, UM_NO_UPDATE, 0, 0);
		}
	} else {
		/* Network failure: silently post UM_NO_UPDATE */
		PostMessage(hMainDialog, UM_NO_UPDATE, 0, 0);
	}

	safe_free(buf);
	force_update_check = FALSE;
	update_check_thread = NULL;
	ExitThread(0);
}

/* UseLocalDbx: use a locally cached DBX (UEFI Secure Boot revocation) database.
 * The DBX download and caching subsystem is not yet implemented on Linux. */
BOOL UseLocalDbx(int arch)
{
	(void)arch;
	return FALSE;
}

/* CheckForUpdates: check for a newer version of Rufus on the project server. */
BOOL CheckForUpdates(BOOL force)
{
	force_update_check = force;

	/* Do not start a second check if one is already in progress */
	if (update_check_thread != NULL)
		return FALSE;

	/* Unless forced, respect the update interval */
	if (!force) {
		int32_t interval = ReadSetting32(SETTING_UPDATE_INTERVAL);
		if (interval == -1) {
			uprintf("Update checks are disabled.");
			return FALSE;
		}
		if (interval == 0) {
			WriteSetting32(SETTING_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL);
			interval = DEFAULT_UPDATE_INTERVAL;
		}
		int64_t last = ReadSetting64(SETTING_LAST_UPDATE);
		int64_t now  = (int64_t)time(NULL);
		if (now < last + (int64_t)interval) {
			uprintf("Next update check in %" PRId64 " seconds.",
			        last + (int64_t)interval - now);
			return FALSE;
		}
	}

	update_check_thread = CreateThread(NULL, 0, CheckForUpdatesThread, NULL, 0, NULL);
	if (update_check_thread == NULL) {
		uprintf("Unable to start update check thread");
		return FALSE;
	}
	return TRUE;
}

/* DownloadISO: launch the Fido script to download an ISO from the internet.
 *
 * Linux implementation:
 * 1. Checks that fido_url is set (by SetFidoCheck) and pwsh is in PATH.
 * 2. Downloads + decompresses the Fido PowerShell script to a temp file.
 * 3. Creates a POSIX FIFO for the script to return the download URL.
 * 4. Runs pwsh in a subprocess; reads the URL from the FIFO.
 * 5. Asks the user where to save the ISO (FileDialog) then downloads it.
 */

/* Detect if 'pwsh' (PowerShell 7) is available */
static BOOL find_pwsh(char *out, size_t out_len)
{
	static const char *candidates[] = {
		"/usr/bin/pwsh",
		"/usr/local/bin/pwsh",
		"/snap/bin/pwsh",
		"/opt/microsoft/powershell/7/pwsh",
		NULL
	};
	for (int i = 0; candidates[i]; i++) {
		if (access(candidates[i], X_OK) == 0) {
			snprintf(out, out_len, "%s", candidates[i]);
			return TRUE;
		}
	}
	return FALSE;
}

/* Thread: downloads Fido.ver, validates and stores the fido_url.
 * On success posts UM_ENABLE_DOWNLOAD_ISO so the UI can show the option. */
static DWORD WINAPI CheckForFidoThread(LPVOID param)
{
	static BOOL is_active = FALSE;
	char *loc = NULL;
	uint64_t len;

	(void)param;
	if (is_active)
		return (DWORD)-1;
	is_active = TRUE;

	safe_free(fido_url);

	/* Fetch the Fido version descriptor from the Rufus server */
	len = DownloadToFileOrBuffer(RUFUS_URL "/Fido.ver", NULL, (BYTE**)&loc, NULL, FALSE);
	if (len == 0 || len >= 4 * 1024)
		goto out;

	len++;  /* DownloadToFileOrBuffer null-terminates, count that byte */
	fido_url = get_token_data_buffer(FIDO_VERSION, 1, loc, (size_t)len);
	if (fido_url == NULL ||
	    safe_strncmp(fido_url, "https://github.com/pbatard/Fido", 31) != 0) {
		uprintf("SetFidoCheck: unexpected Fido URL: %s",
		        fido_url ? fido_url : "(null)");
		safe_free(fido_url);
		goto out;
	}

	if (IsDownloadable(fido_url)) {
		uprintf("Fido download script available: %s", fido_url);
		PostMessage(hMainDialog, UM_ENABLE_DOWNLOAD_ISO, 0, 0);
	} else {
		uprintf("Fido URL is not reachable: %s", fido_url);
		safe_free(fido_url);
	}

out:
	free(loc);
	is_active = FALSE;
	return 0;
}

/*
 * SetFidoCheck — detect PowerShell + Fido availability and arm the UI.
 * Called once at startup (from on_app_activate) or after language change.
 */
void SetFidoCheck(void)
{
	char pwsh_path[512];
	if (!find_pwsh(pwsh_path, sizeof(pwsh_path))) {
		uprintf("SetFidoCheck: pwsh not found; ISO download feature disabled.");
		return;
	}
	uprintf("SetFidoCheck: pwsh found at %s", pwsh_path);
	CreateThread(NULL, 0, CheckForFidoThread, NULL, 0, NULL);
}

/* ---- DownloadISO thread ---- */

/* Context passed to DownloadISOThread */
typedef struct {
	char pwsh_path[512];
} download_iso_ctx_t;

static DWORD WINAPI DownloadISOThread(LPVOID param)
{
	download_iso_ctx_t *ctx = (download_iso_ctx_t *)param;
	char script_path[512], fifo_path[512], cmdline[2048];
	char url_buf[4096];
	BYTE *compressed = NULL;
	char *fido_script_buf = NULL;
	uint64_t dwCompressedSize = 0;
	uint64_t uncompressed_size = 0;
	int64_t  bled_size = 0;
	int fifo_fd = -1;
	FILE *fp = NULL;
	char *save_path = NULL;
	pid_t child_pid = -1;
	BOOL success = FALSE;

	/* Build temp file paths */
	snprintf(script_path, sizeof(script_path), "%s/rufus-fido-XXXXXX.ps1", temp_dir);
	snprintf(fifo_path,   sizeof(fifo_path),   "%s/rufus-fifo-XXXXXX",     temp_dir);

	/* Create a unique FIFO path */
	int tmpfd = mkstemps(script_path, 4);  /* suffix length 4 = ".ps1" */
	if (tmpfd < 0) {
		uprintf("DownloadISO: cannot create temp script file: %s", strerror(errno));
		goto out;
	}
	close(tmpfd);
	unlink(script_path);  /* will re-create below */

	/* Unique fifo path via mkstemp then unlink + mkfifo */
	{
		int ffd = mkstemp(fifo_path);
		if (ffd < 0) {
			uprintf("DownloadISO: cannot create temp FIFO path: %s", strerror(errno));
			goto out;
		}
		close(ffd);
		unlink(fifo_path);
		if (mkfifo(fifo_path, 0600) != 0) {
			uprintf("DownloadISO: mkfifo failed: %s", strerror(errno));
			goto out;
		}
	}

	/* Download the Fido script (compressed lzma) */
	dwCompressedSize = DownloadToFileOrBuffer(fido_url, NULL, &compressed, hMainDialog, FALSE);
	if (dwCompressedSize == 0) {
		uprintf("DownloadISO: failed to download Fido script from %s", fido_url);
		goto out;
	}

	/* The first 8 bytes of the compressed payload are the uncompressed size (uint64_t LE) */
	if (dwCompressedSize < 13) {  /* LZMA header is 13 bytes */
		uprintf("DownloadISO: Fido script too small (%llu bytes)", (unsigned long long)dwCompressedSize);
		goto out;
	}
	uncompressed_size = *((uint64_t *)&compressed[5]);
	if (uncompressed_size < 1024 || uncompressed_size > 4 * 1024 * 1024) {
		uprintf("DownloadISO: implausible uncompressed size: %llu", (unsigned long long)uncompressed_size);
		goto out;
	}

	fido_script_buf = malloc((size_t)uncompressed_size + 1);
	if (!fido_script_buf) {
		uprintf("DownloadISO: out of memory");
		goto out;
	}

	if (bled_init(0, uprintf, NULL, NULL, NULL, NULL, (unsigned long *)&ErrorStatus) >= 0) {
		bled_size = bled_uncompress_from_buffer_to_buffer(
			(const char *)compressed, (size_t)dwCompressedSize,
			fido_script_buf, (size_t)uncompressed_size,
			BLED_COMPRESSION_LZMA);
		bled_exit();
	}
	if (bled_size != (int64_t)uncompressed_size) {
		uprintf("DownloadISO: decompression failed (%lld vs %llu)",
		        (long long)bled_size, (unsigned long long)uncompressed_size);
		goto out;
	}
	fido_script_buf[uncompressed_size] = '\0';

	/* Write script to temp file */
	fp = fopen(script_path, "w");
	if (!fp || fwrite(fido_script_buf, 1, (size_t)uncompressed_size, fp) != (size_t)uncompressed_size) {
		uprintf("DownloadISO: cannot write script to %s", script_path);
		if (fp) fclose(fp);
		fp = NULL;
		goto out;
	}
	fclose(fp);
	fp = NULL;

	/* Build locale string for Fido */
	{
		char locale_str[1024] = "";
		if (selected_locale && selected_locale->txt[0])
			snprintf(locale_str, sizeof(locale_str),
			         "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
			         selected_locale->txt[0],
			         lmprintf(MSG_135), lmprintf(MSG_136), lmprintf(MSG_137),
			         lmprintf(MSG_138), lmprintf(MSG_139), lmprintf(MSG_040),
			         lmprintf(MSG_140), lmprintf(MSG_141),
			         lmprintf(MSG_006), lmprintf(MSG_007), lmprintf(MSG_042),
			         lmprintf(MSG_142), lmprintf(MSG_143),
			         lmprintf(MSG_144), lmprintf(MSG_145), lmprintf(MSG_146),
			         lmprintf(MSG_199));

		snprintf(cmdline, sizeof(cmdline),
		         "\"%s\" -NonInteractive -Sta -NoProfile -ExecutionPolicy Bypass"
		         " -File \"%s\" -PipeName \"%s\" -LocData \"%s\""
		         " -AppTitle \"%s\"",
		         ctx->pwsh_path, script_path, fifo_path,
		         locale_str, lmprintf(MSG_149));
	}

	uprintf("DownloadISO: launching: %s", cmdline);

	/* Launch pwsh in a child process */
	child_pid = fork();
	if (child_pid < 0) {
		uprintf("DownloadISO: fork failed: %s", strerror(errno));
		goto out;
	}

	if (child_pid == 0) {
		/* Child: exec pwsh */
		execl("/bin/sh", "sh", "-c", cmdline, NULL);
		_exit(127);
	}

	/* Parent: open FIFO for reading (blocks until child writes) */
	fifo_fd = open(fifo_path, O_RDONLY);
	if (fifo_fd < 0) {
		uprintf("DownloadISO: cannot open FIFO: %s", strerror(errno));
		goto out;
	}

	ssize_t n = read(fifo_fd, url_buf, sizeof(url_buf) - 1);
	close(fifo_fd);
	fifo_fd = -1;

	if (n <= 4) {
		uprintf("DownloadISO: no URL received from Fido script");
		goto out;
	}
	url_buf[n] = '\0';
	/* Trim any trailing newline */
	while (n > 0 && (url_buf[n-1] == '\n' || url_buf[n-1] == '\r'))
		url_buf[--n] = '\0';

	uprintf("DownloadISO: Fido returned URL: %s", url_buf);

	/* Ask user where to save the file */
	{
		EXT_DECL(img_ext, GetShortName(url_buf),
		         __VA_GROUP__("*.iso"),
		         __VA_GROUP__(lmprintf(MSG_036)));
		save_path = FileDialog(TRUE, NULL, &img_ext, NULL);
	}
	if (!save_path)
		goto out;

	/* Download the ISO */
	PostMessage(hMainDialog, UM_PROGRESS_INIT, 0, 0);
	ErrorStatus = 0;
	if (DownloadToFileOrBuffer(url_buf, save_path, NULL, hMainDialog, TRUE) == 0) {
		PostMessage(hMainDialog, UM_PROGRESS_EXIT, 0, 0);
		if (SCODE_CODE(ErrorStatus) == ERROR_CANCELLED) {
			uprintf("DownloadISO: download cancelled by user");
			Notification(MB_ICONINFORMATION | MB_CLOSE, lmprintf(MSG_211), lmprintf(MSG_041));
		} else {
			Notification(MB_ICONERROR | MB_CLOSE,
			             lmprintf(MSG_194, GetShortName(url_buf)),
			             lmprintf(MSG_043, WindowsErrorString()));
		}
	} else {
		/* Success: set image_path and trigger scan */
		image_path = safe_strdup(save_path);
		PostMessage(hMainDialog, UM_SELECT_ISO, 0, 0);
		success = TRUE;
	}

out:
	if (child_pid > 0)
		waitpid(child_pid, NULL, WNOHANG);
	if (fifo_fd >= 0)
		close(fifo_fd);
	if (script_path[0])
		unlink(script_path);
	if (fifo_path[0])
		unlink(fifo_path);
	free(compressed);
	free(fido_script_buf);
	free(save_path);
	free(ctx);
	PostMessage(hMainDialog, UM_ENABLE_CONTROLS, 0, 0);
	ExitThread(success ? 0 : 1);
}

BOOL DownloadISO(void)
{
	char pwsh_path[512];

	/* Quick sanity checks before spawning a thread */
	if (fido_url == NULL) {
		uprintf("DownloadISO: fido_url is not set (SetFidoCheck not run or Fido unavailable)");
		return FALSE;
	}
	if (!find_pwsh(pwsh_path, sizeof(pwsh_path))) {
		uprintf("DownloadISO: pwsh not found in standard locations");
		return FALSE;
	}

	download_iso_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) return FALSE;
	snprintf(ctx->pwsh_path, sizeof(ctx->pwsh_path), "%s", pwsh_path);

	HANDLE h = CreateThread(NULL, 0, DownloadISOThread, ctx, 0, NULL);
	if (!h) {
		uprintf("DownloadISO: unable to start download thread");
		free(ctx);
		ErrorStatus = RUFUS_ERROR(APPERR(ERROR_CANT_START_THREAD));
		PostMessage(hMainDialog, UM_ENABLE_CONTROLS, 0, 0);
		return FALSE;
	}
	CloseHandle(h);
	return TRUE;
}

