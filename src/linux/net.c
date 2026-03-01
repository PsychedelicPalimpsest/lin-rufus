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

#define _GNU_SOURCE  /* for timegm() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <curl/curl.h>

#include "rufus.h"
#include "missing.h"
#include "localization.h"
#include "resource.h"
#include "bled/bled.h"
#include "dbx/dbx_info.h"
#include "download_resume.h"

/* Globals from globals.c / ui_gtk.c not declared in headers */
extern loc_cmd *selected_locale;
extern char   *fido_url;
extern char   *image_path;
extern HWND    hMainDialog;
extern DWORD   ErrorStatus;
extern char    temp_dir[];
extern const char* efi_archname[];

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

/* ---- libcurl progress callback ---- */

static int download_xferinfo_cb(void *ud, curl_off_t dltotal, curl_off_t dlnow,
                                 curl_off_t ultotal, curl_off_t ulnow)
{
	(void)ud; (void)ultotal; (void)ulnow;
	if (dltotal > 0) {
		float pct = (float)((double)dlnow / (double)dltotal * 100.0);
		UpdateProgress(OP_NOOP, pct);
	}
	return 0; /* returning non-zero aborts the transfer */
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

/* ---- is_network_available — connectivity pre-check ---- */

/*
 * Test-injection support: when RUFUS_TEST is defined, tests can call
 * set_test_no_network(1) to force is_network_available() to return FALSE,
 * simulating a disconnected machine without real interface manipulation.
 */
#ifdef RUFUS_TEST
static volatile int _test_force_no_network = 0;
void set_test_no_network(int no_network) { _test_force_no_network = no_network; }
#endif

/*
 * is_network_available — return TRUE if at least one non-loopback network
 * interface is UP and has an IPv4 or IPv6 address.
 *
 * This provides a fast pre-check before libcurl download attempts so Rufus
 * can give a "no network" error immediately instead of waiting for a timeout.
 */
BOOL is_network_available(void)
{
	struct ifaddrs *ifap = NULL, *ifa;
	BOOL found = FALSE;

#ifdef RUFUS_TEST
	if (_test_force_no_network)
		return FALSE;
#endif

	if (getifaddrs(&ifap) != 0)
		return FALSE;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		/* Skip loopback interfaces */
		if (ifa->ifa_flags & IFF_LOOPBACK)
			continue;
		/* Interface must be UP */
		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		/* Must have an IPv4 or IPv6 address */
		int family = ifa->ifa_addr->sa_family;
		if (family == AF_INET || family == AF_INET6) {
			found = TRUE;
			break;
		}
	}

	freeifaddrs(ifap);
	return found;
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
	uint64_t resume_from = 0;
	struct write_ctx_buf bctx = { NULL, 0 };
	struct write_ctx_file fctx = { NULL, 0 };

	(void)hDlg; /* progress dialog integration is a TODO */

	ErrorStatus   = 0;
	DownloadStatus = 404;

	if (url == NULL || (file == NULL && buf == NULL))
		return 0;

	/* Pre-check: refuse to attempt downloads when no network interface is UP.
	 * This avoids waiting for a TCP/TLS timeout when the machine is offline. */
	if (!is_network_available()) {
		if (!silent)
			uprintf("No network connection available — skipping download of '%s'",
			        net_short_name(url));
		DownloadStatus = 503;
		return 0;
	}

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

	/* Progress callback — reports download percentage via UpdateProgress */
	curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, download_xferinfo_cb);
	curl_easy_setopt(curl, CURLOPT_XFERINFODATA,     NULL);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS,       0L);

	/* Set write callback */
	if (file != NULL) {
		char partial[4096];

		if (!get_partial_path(file, partial, sizeof(partial))) {
			if (!silent)
				uprintf("Failed to build partial path for '%s'", file);
			goto out;
		}

		resume_from = get_partial_size(file);
		if (resume_from > 0) {
			/* A partial download exists — try to resume */
			fctx.fp = fopen(partial, "ab");
			if (fctx.fp == NULL) {
				if (!silent)
					uprintf("Failed to open '%s' for append", partial);
				goto out;
			}
			curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
			                 (curl_off_t)resume_from);
			if (!silent)
				uprintf("Resuming download of %s from offset %"PRIu64,
				        net_short_name(url), resume_from);
		} else {
			/* Fresh download — write to .partial */
			fctx.fp = fopen(partial, "wb");
			if (fctx.fp == NULL) {
				if (!silent)
					uprintf("Failed to open '%s' for writing", partial);
				goto out;
			}
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
		/* Keep .partial for potential future resume */
		goto out;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	DownloadStatus = (DWORD)http_code;

	if (http_code == 200 && file != NULL && resume_from > 0) {
		/* Server ignored our Range request and sent the full file again.
		 * The .partial is now corrupted — discard it and start fresh. */
		if (!silent)
			uprintf("Server returned HTTP 200 on resume request for '%s' — discarding partial",
			        net_short_name(url));
		if (fctx.fp != NULL) { fclose(fctx.fp); fctx.fp = NULL; }
		abandon_partial_download(file);
		goto out;
	}

	if (http_code != 200 && http_code != 206) {
		if (!silent)
			uprintf("HTTP %ld for '%s'", http_code, url);
		/* Keep .partial so the resume can be attempted later */
		goto out;
	}

	/* Success — finalize or return data */
	if (file != NULL) {
		/* Close the .partial file before renaming */
		fclose(fctx.fp);
		fctx.fp = NULL;
		if (!finalize_partial_download(file)) {
			if (!silent)
				uprintf("Failed to finalize download of '%s'", net_short_name(url));
			goto out;
		}
		/* Total bytes = previously downloaded (resume_from) + this session */
		size = resume_from + fctx.written;
	} else {
		size = bctx.len;
		if (buf != NULL) {
			*buf = bctx.data;
			bctx.data = NULL; /* ownership transferred to caller */
		}
	}
	/* Report 100% completion so the progress bar reaches the end */
	UpdateProgress(OP_NOOP, 100.0f);

out:
	curl_easy_cleanup(curl);
	if (fctx.fp != NULL)
		fclose(fctx.fp);
	free(bctx.data); /* no-op if ownership was transferred */
	return size;
}

/* ---- DownloadSignedFile: download + RSA-SHA256 signature verify ---- */

extern BOOL ValidateOpensslSignature(BYTE *pbBuffer, DWORD dwBufferLen,
                                      BYTE *pbSignature, DWORD dwSigLen);

/*
 * DownloadSignedFile — download `url` to `file` after verifying its detached
 * RSA-SHA256 `.sig` file (same protocol as the Windows implementation).
 *
 * 1. Downloads `url` into a memory buffer.
 * 2. Downloads `url + ".sig"` into a memory buffer.
 * 3. Calls ValidateOpensslSignature() to verify the signature.
 * 4. On success, writes the buffer to `file` and returns its byte count.
 *    On failure, sets DownloadStatus = 403 and returns 0.
 */
DWORD DownloadSignedFile(const char *url, const char *file, HWND hDlg, BOOL silent)
{
	char *url_sig = NULL;
	uint8_t *buf = NULL, *sig = NULL;
	uint64_t buf_len = 0, sig_len = 0;
	DWORD ret = 0;
	FILE *fp = NULL;
	size_t written;

	if (url == NULL)
		return 0;

	url_sig = malloc(strlen(url) + 5);
	if (url_sig == NULL) {
		uprintf("DownloadSignedFile: could not allocate signature URL");
		return 0;
	}
	strcpy(url_sig, url);
	strcat(url_sig, ".sig");

	/* Download file content to memory */
	buf_len = DownloadToFileOrBufferEx(url, NULL, NULL, &buf, hDlg, silent);
	if (buf_len == 0)
		goto out;

	/* Download and verify the detached signature */
	sig_len = DownloadToFileOrBufferEx(url_sig, NULL, NULL, &sig, NULL, TRUE);
	if (sig_len != RSA_SIGNATURE_SIZE ||
	    !ValidateOpensslSignature(buf, (DWORD)buf_len, sig, (DWORD)sig_len)) {
		uprintf("FATAL: Download signature is invalid \xe2\x9c\x97");
		DownloadStatus = 403;
		goto out;
	}

	uprintf("Download signature is valid \xe2\x9c\x93");
	DownloadStatus = 206;

	fp = fopen(file, "wb");
	if (fp == NULL) {
		uprintf("Unable to create '%s': %s", file, strerror(errno));
		goto out;
	}
	written = fwrite(buf, 1, (size_t)buf_len, fp);
	if (written != (size_t)buf_len) {
		uprintf("Error writing '%s': only %zu/%zu bytes written",
		        file, written, (size_t)buf_len);
		goto out;
	}
	ret = (DWORD)buf_len;
	DownloadStatus = 200;

out:
	if (fp != NULL)
		fclose(fp);
	free(url_sig);
	free(buf);
	free(sig);
	return ret;
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

/* Forward declaration — defined below */
void CheckForDBXUpdates(void);

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
			/* Notify the main thread so it can show the update dialog */
			PostMessage(hMainDialog, UM_NEW_VERSION, 0, 0);
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
	/* Also check for DBX revocation database updates */
	CheckForDBXUpdates();
	update_check_thread = NULL;
	ExitThread(0);
	return 0;
}

/*
 * dbx_build_timestamp_url: convert a GitHub "contents" API URL to the "commits"
 * query URL needed to fetch the timestamp of the latest commit to that file.
 *
 * Example:
 *   in:  https://api.github.com/repos/microsoft/secureboot_objects/contents/PostSignedObjects/DBX/amd64/DBXUpdate.bin
 *   out: https://api.github.com/repos/microsoft/secureboot_objects/commits?path=PostSignedObjects%2FDBX%2Famd64%2FDBXUpdate.bin&page=1&per_page=1
 *
 * Returns TRUE on success, FALSE if URL is invalid or output buffer is too small.
 */
BOOL dbx_build_timestamp_url(const char *content_url, char *out, size_t out_len)
{
	const char *marker = "contents/";
	const char *p, *path_part;
	char encoded[512];
	size_t base_len, ei;
	int n;

	if (content_url == NULL || out == NULL || out_len == 0)
		return FALSE;

	p = strstr(content_url, marker);
	if (p == NULL)
		return FALSE;

	base_len  = (size_t)(p - content_url);
	path_part = p + strlen(marker);

	/* URL-encode '/' as '%2F' within the file path */
	ei = 0;
	for (const char *s = path_part; *s && ei < sizeof(encoded) - 3; s++) {
		if (*s == '/') {
			encoded[ei++] = '%';
			encoded[ei++] = '2';
			encoded[ei++] = 'F';
		} else {
			encoded[ei++] = *s;
		}
	}
	encoded[ei] = '\0';

	n = snprintf(out, out_len, "%.*scommits?path=%s&page=1&per_page=1",
	             (int)base_len, content_url, encoded);
	return (n > 0 && (size_t)n < out_len);
}

/*
 * dbx_parse_github_timestamp: extract the UTC epoch timestamp from a GitHub
 * commits API JSON response.
 *
 * Looks for the first occurrence of:  "date":[ ]*"YYYY-MM-DDTHH:MM:SSZ"
 *
 * Returns TRUE on success and stores the epoch in *ts; FALSE on any parse error.
 */
BOOL dbx_parse_github_timestamp(const char *json, uint64_t *ts)
{
	const char *p, *c;
	struct tm t = { 0 };
	int r;
	time_t epoch;

	if (json == NULL || ts == NULL)
		return FALSE;

	p = strstr(json, "\"date\":");
	if (p == NULL)
		return FALSE;

	c = p + 7; /* skip past "date": */
	while (*c == ' ' || *c == '"')
		c++;

	r = sscanf(c, "%d-%d-%dT%d:%d:%dZ",
	           &t.tm_year, &t.tm_mon, &t.tm_mday,
	           &t.tm_hour, &t.tm_min, &t.tm_sec);
	if (r != 6)
		return FALSE;

	t.tm_year -= 1900;
	t.tm_mon  -= 1;

	epoch = timegm(&t);
	if (epoch == (time_t)-1)
		return FALSE;

	*ts = (uint64_t)epoch;
	return TRUE;
}

/* UseLocalDbx: return TRUE when we have a locally cached DBX file that is
 * newer than the embedded baseline in dbx_info (checked via saved timestamp). */
BOOL UseLocalDbx(int arch)
{
	char setting_name[48];

	/* dbx_info covers ARCH_X86_32..ARCH_LOONGARCH_64 (indices 0..6 → arch 1..7) */
	if (arch <= ARCH_UNKNOWN || (size_t)(arch - 1) >= ARRAYSIZE(dbx_info))
		return FALSE;

	snprintf(setting_name, sizeof(setting_name), "DBXTimestamp_%s", efi_archname[arch]);
	return (uint64_t)ReadSetting64(setting_name) > dbx_info[arch - 1].timestamp;
}

/*
 * CheckForDBXUpdates: query GitHub for the latest DBX commit timestamp for
 * each architecture.  If a newer DBX is available and the user consents,
 * download it to app_data_dir/FILES_DIR/dbx_<arch>.bin and record the
 * timestamp so UseLocalDbx() returns TRUE for that arch.
 */
void CheckForDBXUpdates(void)
{
	size_t i;
	char timestamp_url[512], setting_name[48], path[MAX_PATH];
	char *buf = NULL;
	uint64_t timestamp;
	BOOL already_prompted = FALSE;
	int r;

	for (i = 0; i < ARRAYSIZE(dbx_info); i++) {
		int arch = (int)i + 1; /* dbx_info[0] → ARCH_X86_32 = 1 */
		timestamp = 0;

		/* Build the commits API URL from the contents URL */
		if (!dbx_build_timestamp_url(dbx_info[i].url, timestamp_url, sizeof(timestamp_url)))
			continue;

		uprintf("Querying %s for DBX update timestamp", timestamp_url);

		DWORD size = DownloadToFileOrBuffer(timestamp_url, NULL, (BYTE **)&buf, NULL, FALSE);
		if (size == 0 || buf == NULL) {
			safe_free(buf);
			continue;
		}
		/* NUL-terminate the downloaded JSON */
		char *tmp = realloc(buf, size + 1);
		if (tmp == NULL) {
			safe_free(buf);
			continue;
		}
		buf = tmp;
		buf[size] = '\0';

		if (!dbx_parse_github_timestamp(buf, &timestamp)) {
			safe_free(buf);
			continue;
		}
		safe_free(buf);

		uprintf("DBX update timestamp for %s is %" PRIu64, efi_archname[arch], timestamp);

		snprintf(setting_name, sizeof(setting_name), "DBXTimestamp_%s", efi_archname[arch]);
		uint64_t stored = (uint64_t)ReadSetting64(setting_name);
		uint64_t baseline = dbx_info[i].timestamp;
		uint64_t best = (stored > baseline) ? stored : baseline;

		if (timestamp <= best)
			continue; /* no update needed */

		if (!already_prompted) {
			r = Notification(MB_YESNO | MB_ICONWARNING,
			                 lmprintf(MSG_353), lmprintf(MSG_354));
			already_prompted = TRUE;
			if (r != IDYES)
				break;
			/* Ensure the FILES_DIR directory exists under app_data_dir */
			char files_dir[MAX_PATH];
			snprintf(files_dir, sizeof(files_dir), "%s/" FILES_DIR, app_data_dir);
			mkdir(files_dir, 0755);
		}

		snprintf(path, sizeof(path), "%s/" FILES_DIR "/dbx_%s.bin",
		         app_data_dir, efi_archname[arch]);
		if (DownloadToFileOrBuffer(dbx_info[i].url, path, NULL, NULL, FALSE) != 0) {
			WriteSetting64(setting_name, (int64_t)timestamp);
			uprintf("Saved DBX as '%s'", path);
		} else {
			uprintf("WARNING: Failed to download DBX for %s", efi_archname[arch]);
		}
	}
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

/*
 * Compare new_url against the cached SETTING_FIDO_URL.
 * If they differ (or no URL was cached), saves new_url and returns TRUE.
 * Returns FALSE if new_url is NULL or matches the cached value.
 * This is the core version-check helper for Fido script auto-update detection.
 */
BOOL fido_check_url_updated(const char *new_url)
{
	const char *stored;
	if (new_url == NULL)
		return FALSE;
	stored = ReadSettingStr(SETTING_FIDO_URL);
	if (stored[0] != '\0' && strcmp(stored, new_url) == 0)
		return FALSE;
	WriteSettingStr(SETTING_FIDO_URL, new_url);
	return TRUE;
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

	if (fido_check_url_updated(fido_url))
		uprintf("Fido: newer download script available: %s", fido_url);

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

	/* Re-fetch Fido.ver to ensure we use the latest script URL in case it
	 * changed since startup (transparent auto-update). */
	{
		char *loc2 = NULL;
		uint64_t loc_len = DownloadToFileOrBuffer(RUFUS_URL "/Fido.ver", NULL,
		                                          (BYTE**)&loc2, NULL, FALSE);
		if (loc_len > 0 && loc_len < 4 * 1024) {
			loc_len++;
			char *fresh = get_token_data_buffer(FIDO_VERSION, 1, loc2, (size_t)loc_len);
			if (fresh && safe_strncmp(fresh, "https://github.com/pbatard/Fido", 31) == 0) {
				if (fido_check_url_updated(fresh)) {
					uprintf("DownloadISO: using updated Fido script: %s", fresh);
					free(fido_url);
					fido_url = strdup(fresh);
				}
				free(fresh);
			}
		}
		free(loc2);
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
	return 0;
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

