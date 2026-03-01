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
#include <curl/curl.h>

#include "rufus.h"
#include "missing.h"

/* Maximum download buffer chunk */
#define DOWNLOAD_BUFFER_SIZE (16 * 1024)

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
 * Fido script execution is not yet implemented on Linux. */
BOOL DownloadISO(void)
{
	return FALSE;
}
