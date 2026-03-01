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

/* Globals provided by globals.c — must be visible to hash_algos.c (included below) */
extern BOOL cpu_has_sha1_accel, cpu_has_sha256_accel;
extern BOOL validate_md5sum;

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
void UpdateMD5Sum(const char* dest_dir, const char* md5sum_name)
{
    if (!img_report.has_md5sum && !validate_md5sum)
        return;

    char md5_path[MAX_PATH];
    snprintf(md5_path, sizeof(md5_path), "%s/%s", dest_dir, md5sum_name);

    char *md5_data = NULL;
    uint32_t md5_size = read_file(md5_path, (uint8_t **)&md5_data);
    if (md5_size == 0)
        return;

    BOOL display_header = TRUE;

    /* Update MD5 entries for each modified file */
    for (uint32_t i = 0; i < modified_files.Index; i++) {
        char *file_path = modified_files.String[i];

        /* Convert all backslashes to forward slashes (Windows compat) */
        for (size_t j = 0; j < strlen(file_path); j++)
            if (file_path[j] == '\\')
                file_path[j] = '/';

        /* Find the basename portion starting after the mount point
         * (strip leading dest_dir prefix, then one path separator) */
        const char *rel = file_path;
        if (strncmp(file_path, dest_dir, strlen(dest_dir)) == 0)
            rel = file_path + strlen(dest_dir) + 1; /* skip dest_dir + '/' */

        /* Look for this relative path in the md5sum file */
        char *str_pos = strstr(md5_data, rel);
        if (str_pos == NULL)
            continue;  /* file not listed */

        if (display_header) {
            uprintf("Updating %s:", md5_path);
            display_header = FALSE;
        }
        uprintf("● %s", rel);

        /* Walk back to start of this line */
        intptr_t pos = str_pos - md5_data;
        while (pos > 0 && md5_data[pos - 1] != '\n')
            pos--;

        /* Recompute MD5 and patch the hex string in-place */
        uint8_t sum[MD5_HASHSIZE];
        HashFile(HASH_MD5, file_path, sum);
        for (uint32_t j = 0; j < MD5_HASHSIZE; j++) {
            static const char hx[] = "0123456789abcdef";
            md5_data[pos + 2*j]     = hx[sum[j] >> 4];
            md5_data[pos + 2*j + 1] = hx[sum[j] & 0x0F];
        }
    }

    write_file(md5_path, (const uint8_t *)md5_data, md5_size);
    free(md5_data);
}

/* A part of an image, used for hashing */
struct image_region {
    const uint8_t *data;
    uint32_t       size;
};

struct efi_image_regions {
    int max;
    int num;
    struct image_region reg[];
};

static BOOL efi_image_region_add(struct efi_image_regions *regs,
    const void *start, const void *end, int nocheck)
{
    struct image_region *reg;
    int i, j;
    if (regs->num >= regs->max) return FALSE;
    if (end < start) return FALSE;
    for (i = 0; i < regs->num; i++) {
        reg = &regs->reg[i];
        if (nocheck) continue;
        if ((uint8_t *)start >= reg->data + reg->size) continue;
        if ((uint8_t *)end <= reg->data) {
            for (j = regs->num - 1; j >= i; j--)
                memcpy(&regs->reg[j + 1], &regs->reg[j], sizeof(*reg));
            break;
        }
        return FALSE;
    }
    reg = &regs->reg[i];
    reg->data = start;
    reg->size = (uint32_t)((uintptr_t)end - (uintptr_t)start);
    regs->num++;
    return TRUE;
}

static int cmp_pe_section(const void *arg1, const void *arg2)
{
    const IMAGE_SECTION_HEADER *s1 = *((const IMAGE_SECTION_HEADER **)arg1);
    const IMAGE_SECTION_HEADER *s2 = *((const IMAGE_SECTION_HEADER **)arg2);
    if (s1->VirtualAddress < s2->VirtualAddress) return -1;
    if (s1->VirtualAddress == s2->VirtualAddress) return 0;
    return 1;
}

BOOL efi_image_parse(uint8_t *efi, size_t len, struct efi_image_regions **regp)
{
    struct efi_image_regions *regs;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS32 *nt;
    IMAGE_SECTION_HEADER *sections, **sorted;
    int num_regions, num_sections, i;
    DWORD ctidx = IMAGE_DIRECTORY_ENTRY_SECURITY;
    uint32_t align, size, authsz;
    size_t bytes_hashed;

    if (len < 0x80) return FALSE;
    dos = (void *)efi;
    if (dos->e_lfanew > (LONG)len - 0x40) return FALSE;
    nt = (void *)(efi + dos->e_lfanew);
    authsz = 0;

    num_regions = 3 + nt->FileHeader.NumberOfSections + 1;
    regs = calloc(sizeof(*regs) + sizeof(struct image_region) * num_regions, 1);
    if (!regs) return FALSE;
    regs->max = num_regions;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64 *nt64 = (void *)nt;
        IMAGE_OPTIONAL_HEADER64 *opt = &nt64->OptionalHeader;
        efi_image_region_add(regs, efi, &opt->CheckSum, 0);
        if (nt64->OptionalHeader.NumberOfRvaAndSizes <= ctidx) {
            efi_image_region_add(regs, &opt->Subsystem, efi + opt->SizeOfHeaders, 0);
        } else {
            efi_image_region_add(regs, &opt->Subsystem, &opt->DataDirectory[ctidx], 0);
            efi_image_region_add(regs, &opt->DataDirectory[ctidx] + 1, efi + opt->SizeOfHeaders, 0);
            authsz = opt->DataDirectory[ctidx].Size;
        }
        bytes_hashed = opt->SizeOfHeaders;
        align = opt->FileAlignment;
    } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 *opt = &nt->OptionalHeader;
        efi_image_region_add(regs, efi, &opt->CheckSum, 0);
        if (nt->OptionalHeader.NumberOfRvaAndSizes <= ctidx) {
            efi_image_region_add(regs, &opt->Subsystem, efi + opt->SizeOfHeaders, 0);
        } else {
            efi_image_region_add(regs, &opt->Subsystem, &opt->DataDirectory[ctidx], 0);
            efi_image_region_add(regs, &opt->DataDirectory[ctidx] + 1, efi + opt->SizeOfHeaders, 0);
            authsz = opt->DataDirectory[ctidx].Size;
        }
        bytes_hashed = opt->SizeOfHeaders;
        align = opt->FileAlignment;
    } else {
        free(regs);
        return FALSE;
    }

    num_sections = nt->FileHeader.NumberOfSections;
    sections = (void *)((uint8_t *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    sorted = calloc(sizeof(IMAGE_SECTION_HEADER *), num_sections);
    if (!sorted) { free(regs); return FALSE; }
    for (i = 0; i < num_sections; i++) sorted[i] = &sections[i];
    qsort(sorted, num_sections, sizeof(sorted[0]), cmp_pe_section);
    for (i = 0; i < num_sections; i++) {
        if (!sorted[i]->SizeOfRawData) continue;
        size = (sorted[i]->SizeOfRawData + align - 1) & ~(align - 1);
        efi_image_region_add(regs, efi + sorted[i]->PointerToRawData,
            efi + sorted[i]->PointerToRawData + size, 0);
        bytes_hashed += size;
    }
    free(sorted);
    if (bytes_hashed + authsz < len)
        efi_image_region_add(regs, efi + bytes_hashed, efi + len - authsz, 0);
    *regp = regs;
    return TRUE;
}

BOOL PE256Buffer(uint8_t *buf, uint32_t len, uint8_t *hash)
{
    BOOL r = FALSE;
    HASH_CONTEXT hash_ctx = { {0} };
    int i;
    struct efi_image_regions *regs = NULL;

    if (!buf || !len || len < 1 * KB || len > 64 * MB || !hash)
        goto out;
    if (!efi_image_parse(buf, len, &regs))
        goto out;

    sha256_init(&hash_ctx);
    for (i = 0; i < regs->num; i++)
        sha256_write(&hash_ctx, regs->reg[i].data, regs->reg[i].size);
    sha256_final(&hash_ctx);
    memcpy(hash, hash_ctx.buf, SHA256_HASHSIZE);
    r = TRUE;
out:
    free(regs);
    return r;
}
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
		PostMessage(hMainDialog, UM_HASH_COMPLETED, 0, 0);
	ExitThread(r);
}
