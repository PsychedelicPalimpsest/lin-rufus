/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: badblocks.c — bad sector detection
 * Copyright © 2011-2024 Pete Batard <pete@akeo.ie>
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

/*
 * badblocks.c - Bad blocks checker (Linux implementation)
 *
 * Copyright 1992-1994 Remy Card <card@masi.ibp.fr>
 * Copyright 1995-1999 Theodore Ts'o
 * Copyright 1999 David Beattie
 * Copyright 2011-2024 Pete Batard <pete@akeo.ie>
 * Copyright 2024-2025 Rufus Linux contributors
 *
 * Ported from windows/badblocks.c.  Key changes vs. Windows:
 *   - I/O via pread/pwrite (HANDLE is a POSIX fd cast to pointer)
 *   - Time-based progress reporting (clock_gettime) instead of SetTimer
 *   - posix_memalign / free instead of _mm_malloc / _mm_free
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public License.
 * %End-Header%
 */

#define _GNU_SOURCE  /* posix_memalign, pread, pwrite */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

#include "rufus.h"
#include "resource.h"
#include "localization.h"
#include "badblocks.h"

/* -------------------------------------------------------------------------
 * Internal constants
 * --------------------------------------------------------------------- */
static FILE       *log_fd   = NULL;
static const char  abort_msg[]  = "Too many bad blocks, aborting test\n";
static const char  bb_prefix[]  = "Bad Blocks: ";

/* -------------------------------------------------------------------------
 * Portable bad-blocks list — lifted verbatim from windows/badblocks.c
 * (pure C, no OS dependency)
 * --------------------------------------------------------------------- */

struct bb_struct_u64_list {
int        magic;
int        num;
int        size;
uint64_t  *list;
int        badblocks_flags;
};

struct bb_struct_u64_iterate {
int         magic;
bb_u64_list bb;
int         ptr;
};

static errcode_t make_u64_list(int size, int num, uint64_t *list, bb_u64_list *ret)
{
bb_u64_list bb = calloc(1, sizeof(struct bb_struct_u64_list));
if (!bb) return BB_ET_NO_MEMORY;
bb->magic = BB_ET_MAGIC_BADBLOCKS_LIST;
bb->size  = size ? size : 10;
bb->num   = num;
bb->list  = malloc(sizeof(blk64_t) * bb->size);
if (!bb->list) { free(bb); return BB_ET_NO_MEMORY; }
if (list)
memcpy(bb->list, list, bb->size * sizeof(blk64_t));
else
memset(bb->list, 0, bb->size * sizeof(blk64_t));
*ret = bb;
return 0;
}

static errcode_t bb_badblocks_list_create(bb_badblocks_list *ret, int size)
{
return make_u64_list(size, 0, 0, (bb_badblocks_list *)ret);
}

static errcode_t bb_u64_list_add(bb_u64_list bb, uint64_t blk)
{
int i, j;
uint64_t *old_list;

BB_CHECK_MAGIC(bb, BB_ET_MAGIC_BADBLOCKS_LIST);

if (bb->num >= bb->size) {
old_list  = bb->list;
bb->size += 100;
bb->list  = realloc(bb->list, bb->size * sizeof(uint64_t));
if (!bb->list) {
bb->list  = old_list;
bb->size -= 100;
return BB_ET_NO_MEMORY;
}
memset(&bb->list[bb->size - 100], 0, 100 * sizeof(uint64_t));
}

i = bb->num - 1;
if (bb->num != 0 && bb->list[i] == blk) return 0;
if (bb->num == 0 || bb->list[i] < blk) { bb->list[bb->num++] = blk; return 0; }

j = bb->num;
for (i = 0; i < bb->num; i++) {
if (bb->list[i] == blk) return 0;
if (bb->list[i] > blk) { j = i; break; }
}
for (i = bb->num; i > j; i--) bb->list[i] = bb->list[i - 1];
bb->list[j] = blk;
bb->num++;
return 0;
}

static errcode_t bb_badblocks_list_add(bb_badblocks_list bb, blk64_t blk)
{
return bb_u64_list_add((bb_u64_list)bb, blk);
}

static int bb_u64_list_find(bb_u64_list bb, blk64_t blk)
{
int low, high, mid;
if (bb->magic != BB_ET_MAGIC_BADBLOCKS_LIST) return -1;
if (bb->num == 0) return -1;
low = 0; high = bb->num - 1;
if (blk == bb->list[low]) return low;
if (blk == bb->list[high]) return high;
while (low < high) {
mid = ((unsigned)low + (unsigned)high) / 2;
if (mid == low || mid == high) break;
if (blk == bb->list[mid]) return mid;
if (blk < bb->list[mid]) high = mid;
else                      low  = mid;
}
return -1;
}

static int bb_u64_list_test(bb_u64_list bb, blk64_t blk)
{
return (bb_u64_list_find(bb, blk) >= 0) ? 1 : 0;
}

static int bb_badblocks_list_test(bb_badblocks_list bb, blk64_t blk)
{
return bb_u64_list_test((bb_u64_list)bb, blk);
}

static int bb_u64_list_iterate(bb_u64_iterate iter, blk64_t *blk)
{
bb_u64_list bb;
if (iter->magic != BB_ET_MAGIC_BADBLOCKS_ITERATE) return 0;
bb = iter->bb;
if (bb->magic != BB_ET_MAGIC_BADBLOCKS_LIST) return 0;
if (iter->ptr < bb->num) { *blk = bb->list[iter->ptr++]; return 1; }
*blk = 0; return 0;
}

static int bb_badblocks_list_iterate(bb_badblocks_iterate iter, blk64_t *blk)
{
return bb_u64_list_iterate((bb_u64_iterate)iter, blk);
}

/* -------------------------------------------------------------------------
 * Runtime state (static to this translation unit)
 * --------------------------------------------------------------------- */
static int           v_flag    = 1;   /* verbose */
static int           s_flag    = 1;   /* show progress */
static int           cancel_ops = 0;  /* abort flag */
static int           cur_pattern, nr_pattern;
static int           cur_op;
static unsigned int  max_bb    = BB_BAD_BLOCKS_THRESHOLD;
static blk64_t       currently_testing = 0;
static blk64_t       num_blocks        = 0;
static uint32_t      num_read_errors   = 0;
static uint32_t      num_write_errors  = 0;
static uint32_t      num_corruption_errors = 0;
static bb_badblocks_list     bb_list = NULL;
static blk64_t               next_bad = 0;
static bb_badblocks_iterate  bb_iter  = NULL;

/* -------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

/* Return monotonic time in milliseconds */
static unsigned long long ms_clock(void)
{
struct timespec ts;
clock_gettime(CLOCK_MONOTONIC, &ts);
return (unsigned long long)ts.tv_sec * 1000ULL +
       (unsigned long long)ts.tv_nsec / 1000000ULL;
}

static void *allocate_buffer(size_t size)
{
void *p = NULL;
if (posix_memalign(&p, BB_SYS_PAGE_SIZE, size) != 0) return NULL;
return p;
}

static void free_buffer(void *p) { free(p); }

static int bb_output(blk64_t bad, enum error_types error_type)
{
errcode_t error_code;

if (bb_badblocks_list_test(bb_list, bad)) return 0;

uprintf("%s%lu\n", bb_prefix, (unsigned long)bad);
if (log_fd) {
fprintf(log_fd, "Block %lu: %s error\n",
        (unsigned long)bad,
        (error_type == READ_ERROR) ? "read" :
        (error_type == WRITE_ERROR) ? "write" : "corruption");
fflush(log_fd);
}

error_code = bb_badblocks_list_add(bb_list, bad);
if (error_code) {
uprintf("%sError %ld adding to in-memory bad block list",
        bb_prefix, (long)error_code);
return 0;
}

if (bb_iter && bad < next_bad)
bb_badblocks_list_iterate(bb_iter, &next_bad);

if      (error_type == READ_ERROR)        num_read_errors++;
else if (error_type == WRITE_ERROR)       num_write_errors++;
else if (error_type == CORRUPTION_ERROR)  num_corruption_errors++;
return 1;
}

static float calc_percent(unsigned long current, unsigned long total)
{
if (total == 0) return 0.0f;
if (current >= total) return 100.0f;
return 100.0f * (float)current / (float)total;
}

static void print_status(void)
{
float percent = calc_percent((unsigned long)currently_testing,
                             (unsigned long)num_blocks);
PrintInfo(0, MSG_235,
          lmprintf(MSG_191 + ((cur_op == OP_WRITE) ? 0 : 1)),
          cur_pattern, nr_pattern, percent,
          num_read_errors, num_write_errors, num_corruption_errors);
percent = (percent / 2.0f) + ((cur_op == OP_READ) ? 50.0f : 0.0f);
UpdateProgress(OP_BADBLOCKS,
               (((cur_pattern - 1) * 100.0f) + percent) / nr_pattern);
}

static void pattern_fill(unsigned char *buffer, unsigned int pattern, size_t n)
{
unsigned int   i, nb;
unsigned char  bpattern[sizeof(pattern)], *ptr;

if (pattern == (unsigned int)~0) {
PrintInfo(3500, MSG_236);
srand((unsigned int)(ms_clock() & 0xFFFFFFFFU));
for (ptr = buffer; ptr < buffer + n; ptr++)
*ptr = (unsigned char)(rand() % 256);
} else {
PrintInfo(3500, MSG_237, pattern);
bpattern[0] = 0;
for (i = 0; i < sizeof(bpattern); i++) {
if (pattern == 0) break;
bpattern[i] = pattern & 0xFF;
pattern >>= 8;
}
nb = i ? (i - 1) : 0;
for (ptr = buffer, i = nb; ptr < buffer + n; ptr++) {
*ptr = bpattern[i];
if (i == 0) i = nb; else i--;
}
cur_pattern++;
}
}

/* -------------------------------------------------------------------------
 * POSIX I/O helpers  (HANDLE is a POSIX fd cast to (HANDLE)(intptr_t)fd)
 * --------------------------------------------------------------------- */

static int64_t do_read(HANDLE hDrive, unsigned char *buf,
                       uint64_t tryout, uint64_t block_size,
                       blk64_t current_block)
{
int     fd  = (int)(intptr_t)hDrive;
off_t   off = (off_t)(current_block * block_size);
size_t  sz  = (size_t)(tryout * block_size);
ssize_t got = pread(fd, buf, sz, off);
if (got < 0) return 0;
return (int64_t)got;
}

static int64_t do_write(HANDLE hDrive, const unsigned char *buf,
                        uint64_t tryout, uint64_t block_size,
                        blk64_t current_block)
{
int     fd  = (int)(intptr_t)hDrive;
off_t   off = (off_t)(current_block * block_size);
size_t  sz  = (size_t)(tryout * block_size);
ssize_t got = pwrite(fd, buf, sz, off);
if (got < 0) { LastWriteError = RUFUS_ERROR((DWORD)errno); return 0; }
return (int64_t)got;
}

/* -------------------------------------------------------------------------
 * Main test loop
 * --------------------------------------------------------------------- */

static unsigned int test_rw(HANDLE hDrive, blk64_t last_block,
                             size_t block_size, blk64_t first_block,
                             size_t blocks_at_once,
                             int pattern_type, int nb_passes)
{
const unsigned int pattern[BADLOCKS_PATTERN_TYPES][BADBLOCK_PATTERN_COUNT] = {
BADBLOCK_PATTERN_ONE_PASS,
BADBLOCK_PATTERN_TWO_PASSES,
BADBLOCK_PATTERN_SLC,
BADCLOCK_PATTERN_MLC,
BADBLOCK_PATTERN_TLC
};
unsigned char *buffer = NULL, *read_buffer;
int           i, pat_idx;
unsigned int  bb_count = 0;
blk64_t       got, tryout, recover_block = (blk64_t)~0;
size_t        id_offset = 0;
blk64_t      *blk_id;
unsigned long long last_status_ms;

if (pattern_type < 0 || pattern_type >= BADLOCKS_PATTERN_TYPES) {
uprintf("%sInvalid pattern type\n", bb_prefix);
cancel_ops = -1;
return 0;
}
if (nb_passes < 1 || nb_passes > BADBLOCK_PATTERN_COUNT) {
uprintf("%sInvalid number of passes\n", bb_prefix);
cancel_ops = -1;
return 0;
}
if (first_block * block_size > (uint64_t)1 * PB ||
    last_block  * block_size > (uint64_t)1 * PB) {
uprintf("%sDisk is too large\n", bb_prefix);
cancel_ops = -1;
return 0;
}

buffer = allocate_buffer(2 * blocks_at_once * block_size);
if (!buffer) {
uprintf("%sError while allocating buffers\n", bb_prefix);
cancel_ops = -1;
return 0;
}
read_buffer = buffer + blocks_at_once * block_size;

uprintf("%sChecking from block %lu to %lu (1 block = %s)\n", bb_prefix,
        (unsigned long)first_block, (unsigned long)last_block - 1,
        SizeToHumanReadable(BADBLOCK_BLOCK_SIZE, FALSE, FALSE));

nr_pattern = nb_passes;
cur_pattern = 0;
last_status_ms = ms_clock();

for (pat_idx = 0; pat_idx < nb_passes; pat_idx++) {
if (cancel_ops || ErrorStatus) goto out;

if (detect_fakes && pat_idx == 0) {
id_offset = (size_t)((ms_clock() & 0xFFFFFFFFU) *
             (block_size - sizeof(blk64_t)) / 0xFFFFFFFFU);
uprintf("%sUsing offset %zu for fake device check\n",
        bb_prefix, id_offset);
}

pattern_fill(buffer, pattern[pattern_type][pat_idx],
             blocks_at_once * block_size);

num_blocks = last_block - 1;
currently_testing = first_block;
if (s_flag || v_flag)
uprintf("%sWriting test pattern 0x%02X\n", bb_prefix,
        pattern[pattern_type][pat_idx]);
cur_op = OP_WRITE;
tryout = blocks_at_once;

while (currently_testing < last_block) {
if (cancel_ops || ErrorStatus) goto out;
if (max_bb && bb_count >= max_bb) {
if (s_flag || v_flag) {
uprintf("%s", abort_msg);
if (log_fd) { fprintf(log_fd, "%s", abort_msg); fflush(log_fd); }
}
cancel_ops = -1;
goto out;
}
if (currently_testing + tryout > last_block)
tryout = last_block - currently_testing;

if (detect_fakes && pat_idx == 0) {
for (i = 0; i < (int)blocks_at_once; i++) {
blk_id = (blk64_t *)(buffer + id_offset + i * block_size);
*blk_id = (blk64_t)(currently_testing + i);
}
}

got = (blk64_t)do_write(hDrive, buffer, tryout, block_size,
                        currently_testing);
if (v_flag > 1 || ms_clock() - last_status_ms >= 1000) {
print_status();
last_status_ms = ms_clock();
}
if (got == 0 && tryout == 1)
bb_count += bb_output(currently_testing++, WRITE_ERROR);
currently_testing += got / block_size;
if (got / block_size != tryout) {
tryout = 1;
if (recover_block == (blk64_t)~0)
recover_block = currently_testing - got / block_size + blocks_at_once;
continue;
} else if (currently_testing == recover_block) {
tryout = blocks_at_once;
recover_block = (blk64_t)~0;
}
}

num_blocks = 0;
if (s_flag || v_flag) uprintf("%sReading and comparing\n", bb_prefix);
cur_op = OP_READ;
num_blocks = last_block;
currently_testing = first_block;
tryout = blocks_at_once;

while (currently_testing < last_block) {
if (cancel_ops || ErrorStatus) goto out;
if (max_bb && bb_count >= max_bb) {
if (s_flag || v_flag) {
uprintf("%s", abort_msg);
if (log_fd) { fprintf(log_fd, "%s", abort_msg); fflush(log_fd); }
}
cancel_ops = -1;
goto out;
}
if (currently_testing + tryout > last_block)
tryout = last_block - currently_testing;

if (detect_fakes && pat_idx == 0) {
for (i = 0; i < (int)blocks_at_once; i++) {
blk_id = (blk64_t *)(buffer + id_offset + i * block_size);
*blk_id = (blk64_t)(currently_testing + i);
}
}

got = (blk64_t)do_read(hDrive, read_buffer, tryout, block_size,
                       currently_testing);
if (got == 0 && tryout == 1)
bb_count += bb_output(currently_testing++, READ_ERROR);
currently_testing += got / block_size;
if (got / block_size != tryout) {
tryout = 1;
if (recover_block == (blk64_t)~0)
recover_block = currently_testing - got / block_size + blocks_at_once;
continue;
} else if (currently_testing == recover_block) {
tryout = blocks_at_once;
recover_block = (blk64_t)~0;
}

for (i = 0; i < (int)(got / block_size); i++) {
if (memcmp(read_buffer + (size_t)i * block_size,
           buffer     + (size_t)i * block_size,
           block_size) != 0) {
if (currently_testing * block_size >= (uint64_t)1 * PB)
goto out;
bb_count += bb_output(currently_testing + i - got / block_size,
                      CORRUPTION_ERROR);
}
}
if (v_flag > 1 || ms_clock() - last_status_ms >= 1000) {
print_status();
last_status_ms = ms_clock();
}
}
num_blocks = 0;
}

out:
free_buffer(buffer);
return bb_count;
}

/* -------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

BOOL BadBlocks(HANDLE hPhysicalDrive, ULONGLONG disk_size, int nb_passes,
               int flash_type, badblocks_report *report, FILE *fd)
{
errcode_t  error_code;
blk64_t    last_block;

if (!report) return FALSE;

num_read_errors        = 0;
num_write_errors       = 0;
num_corruption_errors  = 0;
report->bb_count       = 0;
log_fd = fd ? fd : stderr;

/* Zero-size or invalid handle — nothing to test */
if (!hPhysicalDrive || hPhysicalDrive == INVALID_HANDLE_VALUE ||
    disk_size == 0)
return TRUE;

last_block = disk_size / BADBLOCK_BLOCK_SIZE;
if (last_block == 0) return TRUE;

error_code = bb_badblocks_list_create(&bb_list, 0);
if (error_code) {
uprintf("%sError %ld while creating in-memory bad blocks list",
        bb_prefix, (long)error_code);
return FALSE;
}

cancel_ops = ErrorStatus ? -1 : 0;

report->bb_count = test_rw(hPhysicalDrive, last_block,
                           BADBLOCK_BLOCK_SIZE, 0, BB_BLOCKS_AT_ONCE,
                           flash_type, nb_passes);

free(bb_list->list);
free(bb_list);
bb_list = NULL;

report->num_read_errors        = num_read_errors;
report->num_write_errors       = num_write_errors;
report->num_corruption_errors  = num_corruption_errors;

if (cancel_ops && !report->bb_count) return FALSE;
return TRUE;
}
