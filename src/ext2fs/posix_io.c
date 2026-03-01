/*
 * posix_io.c — POSIX-based io_manager for the bundled ext2fs library.
 *
 * The bundled ext2fs was compiled with nt_io.c (Windows NT I/O manager).
 * unix_io.c is not included in the source tree, so we provide our own
 * minimal POSIX implementation using pread(2)/pwrite(2).
 *
 * Used on Linux instead of nt_io_manager in format_ext.c.
 *
 * Copyright © 2024 Rufus Linux Port contributors
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#ifdef __linux__

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/fs.h>   /* BLKGETSIZE64 */

#include "ext2fs.h"

#define POSIX_IO_MAGIC  0x10EF   /* arbitrary, distinct from EXT2_ET_MAGIC_* */

typedef struct {
	int      magic;
	int      fd;
	int      flags;
	uint64_t size;        /* partition/device size in bytes, 0 if unknown */
	uint64_t base_offset; /* byte offset within the file (image partitions) */
} posix_private_t;

/* Forward declarations */
static errcode_t posix_open(const char* name, int flags, io_channel* channel);
static errcode_t posix_close(io_channel ch);
static errcode_t posix_set_blksize(io_channel ch, int blksize);
static errcode_t posix_read_blk(io_channel ch, unsigned long block, int count, void* buf);
static errcode_t posix_read_blk64(io_channel ch, unsigned long long block, int count, void* buf);
static errcode_t posix_write_blk(io_channel ch, unsigned long block, int count, const void* buf);
static errcode_t posix_write_blk64(io_channel ch, unsigned long long block, int count, const void* buf);
static errcode_t posix_flush(io_channel ch);

static struct struct_io_manager struct_posix_manager = {
	.magic       = EXT2_ET_MAGIC_IO_MANAGER,
	.name        = "POSIX I/O Manager",
	.open        = posix_open,
	.close       = posix_close,
	.set_blksize = posix_set_blksize,
	.read_blk    = posix_read_blk,
	.read_blk64  = posix_read_blk64,
	.write_blk   = posix_write_blk,
	.write_blk64 = posix_write_blk64,
	.flush       = posix_flush
};

io_manager posix_io_manager = &struct_posix_manager;

static errcode_t posix_open(const char* name, int flags, io_channel* channel)
{
	io_channel      ch   = NULL;
	posix_private_t* prv = NULL;
	int oflags, fd;
	uint64_t size = 0, base_offset = 0;
	struct stat st;

	if (!name || !channel)
		return EXT2_ET_INVALID_ARGUMENT;

	/*
	 * Support "path@offset:size" for raw image file partitions.
	 * GetExtPartitionName() appends this when no sysfs entry exists.
	 */
	char *real_name = NULL;
	const char *at = strrchr(name, '@');
	if (at) {
		uint64_t off = 0, sz = 0;
		if (sscanf(at + 1, "%" SCNu64 ":%" SCNu64, &off, &sz) == 2) {
			real_name = strndup(name, (size_t)(at - name));
			base_offset = off;
			size        = sz;
		}
	}

	const char *open_path = real_name ? real_name : name;
	oflags = (flags & IO_FLAG_RW) ? O_RDWR : O_RDONLY;
	fd = open(open_path, oflags);
	free(real_name);
	if (fd < 0)
		return EXT2_ET_BAD_DEVICE_NAME;

	/* Determine device/file size (only if not supplied via @offset:size) */
	if (size == 0) {
		if (ioctl(fd, BLKGETSIZE64, &size) != 0) {
			if (fstat(fd, &st) == 0 && st.st_size > 0)
				size = (uint64_t)st.st_size;
		}
	}

	ch  = calloc(1, sizeof(*ch));
	prv = calloc(1, sizeof(*prv));
	if (!ch || !prv) {
		free(ch); free(prv); close(fd);
		return EXT2_ET_NO_MEMORY;
	}

	prv->magic       = POSIX_IO_MAGIC;
	prv->fd          = fd;
	prv->flags       = flags;
	prv->size        = size;
	prv->base_offset = base_offset;

	ch->magic        = EXT2_ET_MAGIC_IO_CHANNEL;
	ch->manager      = posix_io_manager;
	ch->name         = strdup(name);
	ch->block_size   = 1024;   /* default; ext2fs will call set_blksize */
	ch->private_data = prv;
	ch->read_error   = NULL;
	ch->write_error  = NULL;
	ch->refcount     = 1;

	*channel = ch;
	return 0;
}

static errcode_t posix_close(io_channel ch)
{
	posix_private_t* prv;
	if (!ch) return 0;
	prv = (posix_private_t*)ch->private_data;
	if (prv) {
		if (prv->fd >= 0) close(prv->fd);
		free(prv);
	}
	free(ch->name);
	memset(ch, 0, sizeof(*ch));
	free(ch);
	return 0;
}

static errcode_t posix_set_blksize(io_channel ch, int blksize)
{
	ch->block_size = blksize;
	return 0;
}

/*
 * Perform a pread or pwrite of count blocks (or |count| bytes when count<0)
 * starting at 'block'.
 */
static errcode_t posix_do_io(io_channel ch, unsigned long long block,
                              int count, void* buf, int writing)
{
	posix_private_t* prv = (posix_private_t*)ch->private_data;
	uint64_t offset, nbytes;
	ssize_t  r;

	if (count == 0) return 0;

	if (count < 0) {
		/* Negative count = read/write exactly -count bytes */
		nbytes = (uint64_t)(-count);
	} else {
		nbytes = (uint64_t)count * (uint64_t)ch->block_size;
	}
	offset = block * (uint64_t)ch->block_size + prv->base_offset;

	if (writing)
		r = pwrite(prv->fd, buf, (size_t)nbytes, (off_t)offset);
	else
		r = pread(prv->fd, buf, (size_t)nbytes, (off_t)offset);

	if (r != (ssize_t)nbytes)
		return writing ? EXT2_ET_SHORT_WRITE : EXT2_ET_SHORT_READ;

	return 0;
}

static errcode_t posix_read_blk(io_channel ch, unsigned long block,
                                 int count, void* buf)
{
	return posix_do_io(ch, (unsigned long long)block, count, buf, 0);
}

static errcode_t posix_read_blk64(io_channel ch, unsigned long long block,
                                   int count, void* buf)
{
	return posix_do_io(ch, block, count, buf, 0);
}

static errcode_t posix_write_blk(io_channel ch, unsigned long block,
                                  int count, const void* buf)
{
	return posix_do_io(ch, (unsigned long long)block, count, (void*)buf, 1);
}

static errcode_t posix_write_blk64(io_channel ch, unsigned long long block,
                                    int count, const void* buf)
{
	return posix_do_io(ch, block, count, (void*)buf, 1);
}

static errcode_t posix_flush(io_channel ch)
{
	posix_private_t* prv = (posix_private_t*)ch->private_data;
	if (prv && prv->fd >= 0)
		fsync(prv->fd);
	return 0;
}


/*
 * ext2fs_get_device_size2 — POSIX implementation.
 *
 * Called by FormatExtFs() to determine the number of blocks on a device or
 * image file.  The bundled ext2fs library was compiled against nt_io.c so
 * the original implementation is not in libext2fs.a; we provide our own
 * here so callers on Linux do not need to change their code.
 *
 * file      : path to the block device or regular file, or
 *             "path@offset:size" for raw image file partitions
 * blocksize : logical block size (e.g. 1024)
 * retblocks : receives total number of blocksize-byte blocks
 */
errcode_t ext2fs_get_device_size2(const char *file, int blocksize,
                                   blk64_t *retblocks)
{
	uint64_t size = 0;
	struct stat st;
	int fd;

	if (!file || blocksize <= 0 || !retblocks)
		return EXT2_ET_INVALID_ARGUMENT;

	/* Handle "path@offset:size" suffix for image file partitions */
	const char *at = strrchr(file, '@');
	if (at) {
		uint64_t off = 0, sz = 0;
		if (sscanf(at + 1, "%" SCNu64 ":%" SCNu64, &off, &sz) == 2 && sz > 0) {
			*retblocks = (blk64_t)(sz / (uint64_t)blocksize);
			return 0;
		}
	}

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return EXT2_ET_BAD_DEVICE_NAME;

	if (ioctl(fd, BLKGETSIZE64, &size) == 0 && size > 0) {
		close(fd);
		*retblocks = (blk64_t)(size / (uint64_t)blocksize);
		return 0;
	}

	if (fstat(fd, &st) == 0 && st.st_size > 0) {
		close(fd);
		*retblocks = (blk64_t)((uint64_t)st.st_size / (uint64_t)blocksize);
		return 0;
	}

	close(fd);
	return EXT2_ET_TOOSMALL;
}

/*
 * ext2fs_check_mount_point — POSIX implementation (replaces nt_io.c version).
 *
 * Checks whether `device` is currently mounted by scanning /proc/mounts.
 * Sets EXT2_MF_MOUNTED in *mount_flags if it is, and optionally copies the
 * mount-point path into mtpt[0..mtlen-1].  EXT2_MF_READONLY is also set if
 * the device is mounted read-only.
 */
errcode_t ext2fs_check_mount_point(const char *device, int *mount_flags,
                                    char *mtpt, int mtlen)
{
	FILE *f;
	char line[512], mdev[256], mpath[256], mopts[256], mtype[64];
	int dummy1, dummy2;

	if (!device || !mount_flags)
		return EXT2_ET_INVALID_ARGUMENT;

	*mount_flags = 0;
	if (mtpt && mtlen > 0)
		mtpt[0] = '\0';

	f = fopen("/proc/mounts", "r");
	if (!f)
		return 0; /* treat as unmounted if we can't read */

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%255s %255s %63s %255s %d %d",
		           mdev, mpath, mtype, mopts, &dummy1, &dummy2) < 4)
			continue;
		if (strcmp(mdev, device) != 0)
			continue;
		*mount_flags |= EXT2_MF_MOUNTED;
		if (strstr(mopts, "ro") || strncmp(mopts, "ro,", 3) == 0)
			*mount_flags |= EXT2_MF_READONLY;
		if (mtpt && mtlen > 0)
			strncpy(mtpt, mpath, (size_t)(mtlen - 1));
		break;
	}

	fclose(f);
	return 0;
}

/*
 * __isoc23_strtoul compatibility shim.
 *
 * libext2fs.a was compiled against glibc 2.38+ where the C23 standard
 * renamed strtoul's internal entry point to __isoc23_strtoul.  On older
 * glibc (< 2.38) that symbol does not exist, so we provide it here as a
 * thin wrapper around the classic strtoul.
 */
#include <stdlib.h>
unsigned long __isoc23_strtoul(const char *nptr, char **endptr, int base);
unsigned long __isoc23_strtoul(const char *nptr, char **endptr, int base)
{
	return strtoul(nptr, endptr, base);
}

#endif /* __linux__ */
