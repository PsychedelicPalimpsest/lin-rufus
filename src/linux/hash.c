/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: hash.c
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
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

#include "rufus.h"
#include "resource.h"
#include "missing.h"

/*
 * Include the portable algorithm implementations (MD5, SHA1, SHA256, SHA512),
 * the hash_init / hash_write / hash_final function-pointer tables, and HashBuffer().
 */
#include "../../common/hash_algos.c"

/*
 * Linux-specific HashFile: read a file and hash it using the portable algorithm.
 */
BOOL HashFile(const unsigned type, const char* path, uint8_t* hash)
{
	BOOL r = FALSE;
	HASH_CONTEXT hash_ctx = { {0} };
	int fd = -1;
	ssize_t nr;
	uint8_t buf[4096];

	if ((type >= HASH_MAX) || (path == NULL) || (hash == NULL))
		goto out;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;

	hash_init[type](&hash_ctx);
	while ((nr = read(fd, buf, sizeof(buf))) > 0)
		hash_write[type](&hash_ctx, buf, (size_t)nr);

	if (nr < 0)
		goto out;   /* read error */

	hash_final[type](&hash_ctx);
	memcpy(hash, hash_ctx.buf, hash_count[type]);
	r = TRUE;

out:
	if (fd >= 0)
		close(fd);
	return r;
}

/*
 * Convert an (unprefixed) hex string to a binary hash value.
 * Non-concurrent (returns pointer to a static buffer).
 */
uint8_t* StringToHash(const char* str)
{
	static uint8_t ret[MAX_HASHSIZE];
	size_t i, len = safe_strlen(str);
	uint8_t val = 0;
	char c;

	if_assert_fails(len / 2 == MD5_HASHSIZE || len / 2 == SHA1_HASHSIZE ||
	                len / 2 == SHA256_HASHSIZE || len / 2 == SHA512_HASHSIZE)
		return NULL;
	memset(ret, 0, sizeof(ret));

	for (i = 0; i < len; i++) {
		val <<= 4;
		c = (char)tolower((unsigned char)str[i]);
		if_assert_fails((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
			return NULL;
		val |= ((c - '0') < 0xa) ? (c - '0') : (c - 'a' + 0xa);
		if (i % 2)
			ret[i / 2] = val;
	}
	return ret;
}

/* ---- DB lookup functions ---- */
#include "../windows/db.h"

BOOL IsBufferInDB(const unsigned char* buf, const size_t len)
{
	int i;
	uint8_t hash[SHA256_HASHSIZE];
	if (!HashBuffer(HASH_SHA256, buf, len, hash))
		return FALSE;
	for (i = 0; i < (int)ARRAYSIZE(sha256db); i += SHA256_HASHSIZE)
		if (memcmp(hash, &sha256db[i], SHA256_HASHSIZE) == 0)
			return TRUE;
	return FALSE;
}

BOOL IsFileInDB(const char* path)
{
	int i;
	uint8_t hash[SHA256_HASHSIZE];
	if (!HashFile(HASH_SHA256, path, hash))
		return FALSE;
	for (i = 0; i < (int)ARRAYSIZE(sha256db); i += SHA256_HASHSIZE)
		if (memcmp(hash, &sha256db[i], SHA256_HASHSIZE) == 0)
			return TRUE;
	return FALSE;
}

BOOL FileMatchesHash(const char* path, const char* str)
{
	uint8_t hash[SHA256_HASHSIZE];
	if (!HashFile(HASH_SHA256, path, hash))
		return FALSE;
	return (memcmp(hash, StringToHash(str), SHA256_HASHSIZE) == 0);
}

BOOL BufferMatchesHash(const uint8_t* buf, const size_t len, const char* str)
{
	uint8_t hash[SHA256_HASHSIZE];
	if (buf == NULL || str == NULL)
		return FALSE;
	if (!HashBuffer(HASH_SHA256, buf, len, hash))
		return FALSE;
	return (memcmp(hash, StringToHash(str), SHA256_HASHSIZE) == 0);
}

/* ---- Stubs for functions not yet ported ---- */

BOOL IsSignedBySecureBootAuthority(uint8_t* b, uint32_t l)       { (void)b; (void)l; return FALSE; }
int  IsBootloaderRevoked(uint8_t* b, uint32_t l)                  { (void)b; (void)l; return 0; }
void UpdateMD5Sum(const char* d, const char* m)                   { (void)d; (void)m; }
BOOL efi_image_parse(uint8_t* e, size_t l, struct efi_image_regions** r)
                                                                   { (void)e; (void)l; (void)r; return FALSE; }
BOOL PE256Buffer(uint8_t* b, uint32_t l, uint8_t* h)              { (void)b; (void)l; (void)h; return FALSE; }
INT_PTR CALLBACK HashCallback(HWND h, UINT msg, WPARAM w, LPARAM lp)
                                                                   { (void)h; (void)msg; (void)w; (void)lp; return 0; }

/* ---- Parallel hashing infrastructure ---- */

/*
 * NUM_BUFFERS: double-buffer for reading while hashing.  We mirror the
 * Windows implementation (3 buffers) so the same producer/consumer
 * synchronisation logic can be used unchanged.
 */
#define NUM_BUFFERS  3

/* Per-type synchronisation events (auto-reset, initially unsignalled) */
static HANDLE data_ready[HASH_MAX];
static HANDLE thread_ready[HASH_MAX];

/* Shared read-buffer pool */
static DWORD    read_size[NUM_BUFFERS];
static uint32_t proc_bufnum;
static uint8_t  ht_buffer[NUM_BUFFERS][BUFFER_SIZE];

/* Globals provided by globals.c (or the test glue) */
extern char  hash_str[HASH_MAX][150];
extern BOOL  enable_extra_hashes;
extern HWND  hMainDialog;
extern int   default_thread_priority;

/*
 * IndividualHashThread — computes one hash algorithm in a worker thread.
 *
 * param: (uint32_t)(uintptr_t) hash-type index (HASH_MD5 … HASH_SHA512)
 *
 * Protocol (mirrors Windows implementation):
 *   1. Initialise hash context, signal thread_ready[i].
 *   2. Loop: wait on data_ready[i].
 *      • read_size[proc_bufnum] != 0 → hash the chunk, signal thread_ready[i].
 *      • read_size[proc_bufnum] == 0 → finalise, format hash_str[i], return 0.
 */
DWORD WINAPI IndividualHashThread(void* param)
{
	HASH_CONTEXT hash_ctx = { {0} };
	uint32_t i = (uint32_t)(uintptr_t)param, j;

	hash_init[i](&hash_ctx);

	if (!SetEvent(thread_ready[i]))
		goto error;

	while (1) {
		if (WaitForSingleObject(data_ready[i], WAIT_TIME) != WAIT_OBJECT_0) {
			uprintf("Hash thread #%d: timed out waiting for data", i);
			return 1;
		}

		if (read_size[proc_bufnum] != 0) {
			hash_write[i](&hash_ctx, ht_buffer[proc_bufnum],
			              (size_t)read_size[proc_bufnum]);
			if (!SetEvent(thread_ready[i]))
				goto error;
		} else {
			/* read_size == 0 → EOF: finalise and format the hex string */
			hash_final[i](&hash_ctx);
			memset(&hash_str[i], 0, sizeof(hash_str[i]));
			for (j = 0; j < hash_count[i]; j++) {
				hash_str[i][2 * j] = ((hash_ctx.buf[j] >> 4) < 10) ?
					((hash_ctx.buf[j] >> 4) + '0') :
					((hash_ctx.buf[j] >> 4) - 0xa + 'a');
				hash_str[i][2 * j + 1] = ((hash_ctx.buf[j] & 15) < 10) ?
					((hash_ctx.buf[j] & 15) + '0') :
					((hash_ctx.buf[j] & 15) - 0xa + 'a');
			}
			hash_str[i][2 * j] = '\0';
			return 0;
		}
	}
error:
	uprintf("Hash thread #%d: failed to signal event", i);
	return 1;
}

/*
 * HashThread — reads image_path and fans out to IndividualHashThread workers.
 *
 * param: DWORD_PTR* thread_affinity — array of HASH_MAX+1 CPU affinity masks.
 *   Pass NULL or an all-zeros array to skip CPU affinity (Linux default).
 *
 * On success: hash_str[0..2] (and [3] if enable_extra_hashes) contain hex
 *   digest strings; a hash-display dialog is invoked.
 * On failure: ErrorStatus set, thread exits with code 1.
 */
DWORD WINAPI HashThread(void* param)
{
	DWORD_PTR* thread_affinity = (DWORD_PTR*)param;
	HANDLE hash_thread[HASH_MAX] = { NULL, NULL, NULL, NULL };
	DWORD wr;
	int fd = -1;
	int read_bufnum, i, r = -1;
	int num_hashes = HASH_MAX - (enable_extra_hashes ? 0 : 1);
	uint64_t processed_bytes = 0;

	if (image_path == NULL)
		ExitThread(1);

	/*
	 * Thread affinity is optional on Linux: ignore NULL or all-zero arrays.
	 */
	if (thread_affinity != NULL && thread_affinity[0] != 0)
		SetThreadAffinityMask(GetCurrentThread(), thread_affinity[0]);

	uprintf("\r\nComputing hash for '%s'...", image_path);

	/* Create synchronisation events and spawn one hash-worker per algorithm */
	for (i = 0; i < num_hashes; i++) {
		data_ready[i]   = CreateEvent(NULL, FALSE, FALSE, NULL);
		thread_ready[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (data_ready[i] == NULL || thread_ready[i] == NULL) {
			uprintf("HashThread: unable to create event for hash #%d", i);
			goto out;
		}
		hash_thread[i] = CreateThread(NULL, 0, IndividualHashThread,
		                              (LPVOID)(uintptr_t)i, 0, NULL);
		if (hash_thread[i] == NULL) {
			uprintf("HashThread: unable to start hash thread #%d", i);
			goto out;
		}
		SetThreadPriority(hash_thread[i], default_thread_priority);
		if (thread_affinity != NULL && thread_affinity[i + 1] != 0)
			SetThreadAffinityMask(hash_thread[i], thread_affinity[i + 1]);
	}

	/* Open the image file */
	fd = open(image_path, O_RDONLY);
	if (fd < 0) {
		uprintf("HashThread: could not open '%s': %s", image_path, strerror(errno));
		ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
		goto out;
	}

	read_bufnum = 0;
	proc_bufnum = 1;
	read_size[proc_bufnum] = 1;   /* sentinel: prevent early loop exit */

	UpdateProgressWithInfoInit(hMainDialog, FALSE);

	/*
	 * Double-buffered read loop: read chunk into read_bufnum while
	 * workers process proc_bufnum.
	 */
	do {
		UpdateProgressWithInfo(OP_NOOP_WITH_TASKBAR, MSG_271,
		                       processed_bytes, img_report.image_size);
		CHECK_FOR_USER_CANCEL;

		/* Fill read buffer */
		ssize_t nr = read(fd, ht_buffer[read_bufnum], BUFFER_SIZE);
		if (nr < 0) {
			uprintf("HashThread: read error on '%s': %s",
			        image_path, strerror(errno));
			ErrorStatus = RUFUS_ERROR(ERROR_READ_FAULT);
			goto out;
		}
		read_size[read_bufnum] = (DWORD)nr;

		/* Rotate read-buffer index */
		read_bufnum = (read_bufnum + 1) % NUM_BUFFERS;

		/* Wait for all workers to finish the previous chunk */
		wr = WaitForMultipleObjects(num_hashes, thread_ready, TRUE, WAIT_TIME);
		if (wr != WAIT_OBJECT_0) {
			uprintf("HashThread: workers did not signal ready in time");
			goto out;
		}

		/* Expose the freshly-read chunk to workers */
		proc_bufnum = (read_bufnum + NUM_BUFFERS - 1) % NUM_BUFFERS;

		/* Wake all workers */
		for (i = 0; i < num_hashes; i++) {
			if (!SetEvent(data_ready[i])) {
				uprintf("HashThread: could not signal hash thread #%d", i);
				goto out;
			}
		}

		processed_bytes += read_size[proc_bufnum];
	} while (read_size[proc_bufnum] != 0);

	/* All chunks dispatched; wait for workers to write hash_str[] */
	if (WaitForMultipleObjects(num_hashes, hash_thread, TRUE, WAIT_TIME)
	    != WAIT_OBJECT_0) {
		uprintf("HashThread: workers did not finalize");
		goto out;
	}

	uprintf("  MD5:    %s", hash_str[HASH_MD5]);
	uprintf("  SHA1:   %s", hash_str[HASH_SHA1]);
	uprintf("  SHA256: %s", hash_str[HASH_SHA256]);
	if (enable_extra_hashes)
		uprintf("  SHA512: %s", hash_str[HASH_SHA512]);

	r = 0;

out:
	for (i = 0; i < num_hashes; i++) {
		if (hash_thread[i] != NULL)
			TerminateThread(hash_thread[i], 1);
		safe_closehandle(data_ready[i]);
		safe_closehandle(thread_ready[i]);
	}
	if (fd >= 0)
		close(fd);

	PostMessage(hMainDialog, UM_FORMAT_COMPLETED, (WPARAM)FALSE, 0);
	if (r == 0)
		MyDialogBox(NULL, IDD_HASH, hMainDialog, HashCallback);
	ExitThread(r);
}
