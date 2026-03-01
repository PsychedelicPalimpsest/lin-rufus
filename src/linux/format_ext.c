/*
 * Rufus: The Reliable USB Formatting Utility — Linux ext2/ext3 formatter
 *
 * Ported from src/windows/format_ext.c (Pete Batard).
 * Uses posix_io_manager (pread/pwrite) instead of nt_io_manager, and
 * CoCreateGuid() from the compat layer (reads /dev/urandom).
 *
 * Copyright © 2019-2025 Pete Batard <pete@akeo.ie>
 * Linux port © 2024 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>   /* BLKGETSIZE64 */

#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "resource.h"
#include "localization.h"
#include "ext2fs/ext2fs.h"

extern const char* FileSystemLabel[FS_MAX];
extern io_manager posix_io_manager;
extern DWORD ext2_last_winerror(DWORD default_error);

static float ext2_percent_start = 0.0f, ext2_percent_share = 0.5f;

#define SET_EXT2_FORMAT_ERROR(x) \
	do { if (!IS_ERROR(ErrorStatus)) ErrorStatus = ext2_last_winerror(x); } while(0)

typedef struct {
	uint64_t max_size;
	uint32_t block_size;
	uint32_t inode_size;
	uint32_t inode_ratio;
} ext2fs_default_t;

const char* error_message(errcode_t error_code)
{
	static char error_string[256];

	switch (error_code) {
	case EXT2_ET_MAGIC_EXT2FS_FILSYS:
	case EXT2_ET_MAGIC_BADBLOCKS_LIST:
	case EXT2_ET_MAGIC_BADBLOCKS_ITERATE:
	case EXT2_ET_MAGIC_INODE_SCAN:
	case EXT2_ET_MAGIC_IO_CHANNEL:
	case EXT2_ET_MAGIC_IO_MANAGER:
	case EXT2_ET_MAGIC_BLOCK_BITMAP:
	case EXT2_ET_MAGIC_INODE_BITMAP:
	case EXT2_ET_MAGIC_GENERIC_BITMAP:
	case EXT2_ET_MAGIC_ICOUNT:
	case EXT2_ET_MAGIC_EXTENT_HANDLE:
	case EXT2_ET_BAD_MAGIC:          return "Bad magic";
	case EXT2_ET_RO_FILSYS:          return "Read-only file system";
	case EXT2_ET_GDESC_BAD_BLOCK_MAP:
	case EXT2_ET_GDESC_BAD_INODE_MAP:
	case EXT2_ET_GDESC_BAD_INODE_TABLE: return "Bad map or table";
	case EXT2_ET_UNEXPECTED_BLOCK_SIZE: return "Unexpected block size";
	case EXT2_ET_DIR_CORRUPTED:      return "Corrupted entry";
	case EXT2_ET_GDESC_READ:
	case EXT2_ET_GDESC_WRITE:
	case EXT2_ET_INODE_BITMAP_WRITE:
	case EXT2_ET_INODE_BITMAP_READ:
	case EXT2_ET_BLOCK_BITMAP_WRITE:
	case EXT2_ET_BLOCK_BITMAP_READ:
	case EXT2_ET_INODE_TABLE_WRITE:
	case EXT2_ET_INODE_TABLE_READ:
	case EXT2_ET_NEXT_INODE_READ:
	case EXT2_ET_SHORT_READ:
	case EXT2_ET_SHORT_WRITE:        return "read/write error";
	case EXT2_ET_DIR_NO_SPACE:       return "no space left";
	case EXT2_ET_TOOSMALL:           return "Too small";
	case EXT2_ET_BAD_DEVICE_NAME:    return "Bad device name";
	case EXT2_ET_MISSING_INODE_TABLE: return "Missing inode table";
	case EXT2_ET_CORRUPT_SUPERBLOCK: return "Superblock is corrupted";
	case EXT2_ET_CALLBACK_NOTHANDLED: return "Unhandled callback";
	case EXT2_ET_BAD_BLOCK_IN_INODE_TABLE: return "Bad block in inode table";
	case EXT2_ET_UNSUPP_FEATURE:
	case EXT2_ET_RO_UNSUPP_FEATURE:
	case EXT2_ET_UNIMPLEMENTED:      return "Unsupported feature";
	case EXT2_ET_LLSEEK_FAILED:      return "Seek failed";
	case EXT2_ET_NO_MEMORY:
	case EXT2_ET_BLOCK_ALLOC_FAIL:
	case EXT2_ET_INODE_ALLOC_FAIL:   return "Out of memory";
	case EXT2_ET_INVALID_ARGUMENT:   return "Invalid argument";
	case EXT2_ET_NO_DIRECTORY:       return "No directory";
	case EXT2_ET_FILE_NOT_FOUND:     return "File not found";
	case EXT2_ET_FILE_RO:            return "File is read-only";
	case EXT2_ET_DIR_EXISTS:         return "Directory already exists";
	case EXT2_ET_CANCEL_REQUESTED:   return "Cancel requested";
	case EXT2_ET_FILE_TOO_BIG:       return "File too big";
	case EXT2_ET_JOURNAL_NOT_BLOCK:
	case EXT2_ET_NO_JOURNAL_SB:      return "No journal superblock";
	case EXT2_ET_JOURNAL_TOO_SMALL:  return "Journal too small";
	case EXT2_ET_NO_JOURNAL:         return "No journal";
	case EXT2_ET_TOO_MANY_INODES:    return "Too many inodes";
	case EXT2_ET_NO_CURRENT_NODE:    return "No current node";
	case EXT2_ET_OP_NOT_SUPPORTED:   return "Operation not supported";
	case EXT2_ET_IO_CHANNEL_NO_SUPPORT_64: return "I/O Channel does not support 64-bit";
	case EXT2_ET_BAD_DESC_SIZE:      return "Bad descriptor size";
	case EXT2_ET_INODE_CSUM_INVALID:
	case EXT2_ET_INODE_BITMAP_CSUM_INVALID:
	case EXT2_ET_EXTENT_CSUM_INVALID:
	case EXT2_ET_DIR_CSUM_INVALID:
	case EXT2_ET_EXT_ATTR_CSUM_INVALID:
	case EXT2_ET_SB_CSUM_INVALID:
	case EXT2_ET_BLOCK_BITMAP_CSUM_INVALID:
	case EXT2_ET_MMP_CSUM_INVALID:   return "Invalid checksum";
	case EXT2_ET_UNKNOWN_CSUM:       return "Unknown checksum";
	case EXT2_ET_FILE_EXISTS:        return "File exists";
	case EXT2_ET_INODE_IS_GARBAGE:   return "Inode is garbage";
	case EXT2_ET_JOURNAL_FLAGS_WRONG: return "Wrong journal flags";
	case EXT2_ET_FILESYSTEM_CORRUPTED: return "File system is corrupted";
	case EXT2_ET_BAD_CRC:            return "Bad CRC";
	case EXT2_ET_CORRUPT_JOURNAL_SB: return "Journal Superblock is corrupted";
	case EXT2_ET_INODE_CORRUPTED:
	case EXT2_ET_EA_INODE_CORRUPTED: return "Inode is corrupted";
	case EXT2_ET_NO_GDESC:           return "Group descriptors not loaded";
	default:
		if (error_code > EXT2_ET_BASE && error_code < EXT2_ET_BASE + 1000) {
			snprintf(error_string, sizeof(error_string),
			         "Unknown ext2fs error %ld (EXT2_ET_BASE + %ld)",
			         (long)error_code, (long)(error_code - EXT2_ET_BASE));
		} else {
			SetLastError(IS_ERROR(ErrorStatus) ? ErrorStatus
			             : RUFUS_ERROR((DWORD)(error_code & 0xFFFF)));
			snprintf(error_string, sizeof(error_string), "%s",
			         WindowsErrorString());
		}
		return error_string;
	}
}

errcode_t ext2fs_print_progress(int64_t cur_value, int64_t max_value)
{
	UpdateProgressWithInfo(OP_FORMAT, MSG_217,
	    (uint64_t)((ext2_percent_start * max_value) + (ext2_percent_share * cur_value)),
	    (uint64_t)max_value);
	uprint_progress((uint64_t)cur_value, (uint64_t)max_value);
	return IS_ERROR(ErrorStatus) ? EXT2_ET_CANCEL_REQUESTED : 0;
}

const char* GetExtFsLabel(DWORD DriveIndex, uint64_t PartitionOffset)
{
	static char label[EXT2_LABEL_LEN + 1];
	errcode_t r;
	ext2_filsys ext2fs = NULL;
	char* volume_name = GetExtPartitionName(DriveIndex, PartitionOffset);

	if (!volume_name) return NULL;
	r = ext2fs_open(volume_name, EXT2_FLAG_SKIP_MMP, 0, 0,
	                posix_io_manager, &ext2fs);
	free(volume_name);
	if (r == 0) {
		assert(ext2fs != NULL);
		strncpy(label, ext2fs->super->s_volume_name, EXT2_LABEL_LEN);
		label[EXT2_LABEL_LEN] = 0;
	}
	if (ext2fs) ext2fs_close(ext2fs);
	return (r == 0) ? label : NULL;
}

DWORD ext2_last_winerror(DWORD default_error)
{
	(void)default_error;
	return RUFUS_ERROR(ERROR_WRITE_FAULT);
}

BOOL FormatExtFs(DWORD DriveIndex, uint64_t PartitionOffset, DWORD BlockSize,
                 LPCSTR FSName, LPCSTR Label, DWORD Flags)
{
	const float reserve_ratio = 0.05f;
	const ext2fs_default_t ext2fs_default[5] = {
		{   3 * MB,  1024, 128, 3 },   /* floppy  */
		{ 512 * MB,  1024, 128, 2 },   /* small   */
		{   4 * GB,  4096, 256, 2 },   /* default */
		{  16 * GB,  4096, 256, 3 },   /* big     */
		{ 1024 * TB, 4096, 256, 4 }    /* huge    */
	};

	BOOL ret = FALSE;
	char* volume_name = NULL;
	int i, count;
	struct ext2_super_block features = { 0 };
	blk_t    journal_size;
	blk64_t  size = 0, cur;
	ext2_filsys ext2fs = NULL;
	errcode_t r;
	uint8_t* buf = NULL;

	volume_name = GetExtPartitionName(DriveIndex, PartitionOffset);
	if (!volume_name ||
	    strlen(FSName) != 4 || strncmp(FSName, "ext", 3) != 0) {
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		goto out;
	}

	if (strcmp(FSName, FileSystemLabel[FS_EXT2]) != 0 &&
	    strcmp(FSName, FileSystemLabel[FS_EXT3]) != 0) {
		if (strcmp(FSName, FileSystemLabel[FS_EXT4]) == 0)
			uprintf("ext4 not supported, defaulting to ext3");
		else
			uprintf("Invalid ext version, defaulting to ext3");
		FSName = FileSystemLabel[FS_EXT3];
	}

	PrintInfoDebug(0, MSG_222, FSName);
	UpdateProgressWithInfoInit(NULL, TRUE);

	/* Get device size. If volume_name has "@offset:size" suffix (image file
	 * partition), parse it directly; otherwise query the opened device. */
	{
		uint64_t img_off = 0, img_sz = 0;
		const char *at = strrchr(volume_name, '@');
		if (at && sscanf(at + 1, "%" SCNu64 ":%" SCNu64, &img_off, &img_sz) == 2
		    && img_sz > 0) {
			size = (blk64_t)img_sz;
		} else {
			int dev_fd = open(volume_name, O_RDONLY);
			struct stat st;
			if (dev_fd < 0) {
				SET_EXT2_FORMAT_ERROR(ERROR_READ_FAULT);
				uprintf("Could not open '%s': %s", volume_name, strerror(errno));
				goto out;
			}
			if (fstat(dev_fd, &st) == 0 && S_ISREG(st.st_mode)) {
				size = (blk64_t)st.st_size;
			} else {
				uint64_t sz64 = 0;
				if (ioctl(dev_fd, BLKGETSIZE64, &sz64) == 0)
					size = (blk64_t)sz64;
			}
			close(dev_fd);
		}
	}
	if (size == 0) {
		SET_EXT2_FORMAT_ERROR(ERROR_READ_FAULT);
		uprintf("Could not read device size for '%s'", volume_name);
		goto out;
	}

	/* Select defaults based on size */
	for (i = 0; i < (int)(sizeof(ext2fs_default) / sizeof(ext2fs_default[0])); i++) {
		if (size < ext2fs_default[i].max_size) break;
	}
	assert(i < (int)(sizeof(ext2fs_default) / sizeof(ext2fs_default[0])));

	if (BlockSize == 0 || BlockSize < EXT2_MIN_BLOCK_SIZE)
		BlockSize = ext2fs_default[i].block_size;
	assert(IS_POWER_OF_2(BlockSize));

	for (features.s_log_block_size = 0;
	     EXT2_BLOCK_SIZE_BITS(&features) <= EXT2_MAX_BLOCK_LOG_SIZE;
	     features.s_log_block_size++) {
		if (EXT2_BLOCK_SIZE(&features) == (int)BlockSize) break;
	}
	assert(EXT2_BLOCK_SIZE_BITS(&features) <= EXT2_MAX_BLOCK_LOG_SIZE);
	features.s_log_cluster_size = features.s_log_block_size;
	size /= BlockSize;   /* now in blocks */

	/* ext2/ext3 volume size limit */
	if ((strcmp(FSName, FileSystemLabel[FS_EXT2]) == 0 ||
	     strcmp(FSName, FileSystemLabel[FS_EXT3]) == 0) &&
	    size >= 0x100000000ULL) {
		SET_EXT2_FORMAT_ERROR(ERROR_INVALID_VOLUME_SIZE);
		uprintf("Volume too large for ext2/ext3");
		goto out;
	}

	ext2fs_blocks_count_set(&features, size);
	ext2fs_r_blocks_count_set(&features, (blk64_t)(reserve_ratio * size));
	features.s_rev_level    = 1;
	features.s_inode_size   = ext2fs_default[i].inode_size;
	features.s_inodes_count =
		((ext2fs_blocks_count(&features) >> ext2fs_default[i].inode_ratio) > UINT32_MAX)
		? UINT32_MAX
		: (uint32_t)(ext2fs_blocks_count(&features) >> ext2fs_default[i].inode_ratio);

	uprintf("%d inodes, %lld blocks (block size=%d)",
	        features.s_inodes_count, (long long)size, EXT2_BLOCK_SIZE(&features));
	uprintf("%lld blocks (%.1f%%) reserved for super user",
	        (long long)ext2fs_r_blocks_count(&features), reserve_ratio * 100.0f);

	/* Set filesystem features */
	ext2fs_set_feature_dir_index(&features);
	ext2fs_set_feature_filetype(&features);
	ext2fs_set_feature_large_file(&features);
	ext2fs_set_feature_sparse_super(&features);
	ext2fs_set_feature_xattr(&features);
	if (FSName[3] != '2')
		ext2fs_set_feature_journal(&features);
	features.s_default_mount_opts = EXT2_DEFM_XATTR_USER | EXT2_DEFM_ACL;

	/* Initialise virtual superblock with posix_io_manager */
	r = ext2fs_initialize(volume_name,
	                      EXT2_FLAG_EXCLUSIVE | EXT2_FLAG_64BITS,
	                      &features, posix_io_manager, &ext2fs);
	if (r != 0) {
		SET_EXT2_FORMAT_ERROR(ERROR_INVALID_DATA);
		uprintf("Could not initialize %s features: %s", FSName, error_message(r));
		goto out;
	}

	/* Zero first 16 blocks */
	buf = calloc(16, ext2fs->io->block_size);
	assert(buf != NULL);
	r = io_channel_write_blk64(ext2fs->io, 0, 16, buf);
	free(buf); buf = NULL;
	if (r != 0) {
		SET_EXT2_FORMAT_ERROR(ERROR_WRITE_FAULT);
		uprintf("Could not zero superblock area: %s", error_message(r));
		goto out;
	}

	/* UUID, hash seed, misc superblock fields */
	CoCreateGuid((GUID*)ext2fs->super->s_uuid);
	ext2fs_init_csum_seed(ext2fs);
	ext2fs->super->s_def_hash_version  = EXT2_HASH_HALF_MD4;
	CoCreateGuid((GUID*)ext2fs->super->s_hash_seed);
	ext2fs->super->s_max_mnt_count     = -1;
	ext2fs->super->s_creator_os        = EXT2_OS_LINUX;
	ext2fs->super->s_errors            = EXT2_ERRORS_CONTINUE;
	if (Label)
		static_strcpy(ext2fs->super->s_volume_name, Label);

	r = ext2fs_allocate_tables(ext2fs);
	if (r != 0) {
		SET_EXT2_FORMAT_ERROR(ERROR_INVALID_DATA);
		uprintf("Could not allocate %s tables: %s", FSName, error_message(r));
		goto out;
	}
	r = ext2fs_convert_subcluster_bitmap(ext2fs, &ext2fs->block_map);
	if (r != 0) {
		uprintf("Could not set cluster bitmap: %s", error_message(r));
		goto out;
	}

	/* Create inode tables */
	ext2_percent_start = 0.0f;
	ext2_percent_share = (FSName[3] == '2') ? 1.0f : 0.5f;
	uprintf("Creating %d inode sets...", ext2fs->group_desc_count);
	for (i = 0; i < (int)ext2fs->group_desc_count; i++) {
		if (ext2fs_print_progress((int64_t)i, (int64_t)ext2fs->group_desc_count))
			goto out;
		cur   = ext2fs_inode_table_loc(ext2fs, i);
		count = ext2fs_div_ceil(
		    (ext2fs->super->s_inodes_per_group -
		     ext2fs_bg_itable_unused(ext2fs, i)) *
		    EXT2_INODE_SIZE(ext2fs->super),
		    EXT2_BLOCK_SIZE(ext2fs->super));
		r = ext2fs_zero_blocks2(ext2fs, cur, count, &cur, &count);
		if (r != 0) {
			SET_EXT2_FORMAT_ERROR(ERROR_WRITE_FAULT);
			uprintf("Could not zero inode set at %llu (%d blocks): %s",
			        (unsigned long long)cur, count, error_message(r));
			goto out;
		}
	}
	uprintfs("\r\n");

	/* Create root directory and lost+found */
	r = ext2fs_mkdir(ext2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, 0);
	if (r != 0) {
		SET_EXT2_FORMAT_ERROR(ERROR_FILE_CORRUPT);
		uprintf("Failed to create root dir: %s", error_message(r));
		goto out;
	}
	ext2fs->umask = 077;
	r = ext2fs_mkdir(ext2fs, EXT2_ROOT_INO, 0, "lost+found");
	if (r != 0) {
		SET_EXT2_FORMAT_ERROR(ERROR_FILE_CORRUPT);
		uprintf("Failed to create lost+found: %s", error_message(r));
		goto out;
	}

	/* Allocate reserved inodes */
	for (i = EXT2_ROOT_INO + 1; i < (int)EXT2_FIRST_INODE(ext2fs->super); i++)
		ext2fs_inode_alloc_stats(ext2fs, i, 1);
	ext2fs_mark_ib_dirty(ext2fs);

	r = ext2fs_mark_inode_bitmap2(ext2fs->inode_map, EXT2_BAD_INO);
	if (r != 0) {
		SET_EXT2_FORMAT_ERROR(ERROR_WRITE_FAULT);
		uprintf("Could not set inode bitmaps: %s", error_message(r));
		goto out;
	}
	ext2fs_inode_alloc_stats(ext2fs, EXT2_BAD_INO, 1);
	r = ext2fs_update_bb_inode(ext2fs, NULL);
	if (r != 0) {
		SET_EXT2_FORMAT_ERROR(ERROR_WRITE_FAULT);
		uprintf("Could not update bb inode: %s", error_message(r));
		goto out;
	}

	/* Create journal for ext3 */
	if (FSName[3] != '2') {
		ext2_percent_start = 0.5f;
		journal_size = ext2fs_default_journal_size(ext2fs_blocks_count(ext2fs->super));
		journal_size /= 2;
		uprintf("Creating %d journal blocks...", journal_size);
		r = ext2fs_add_journal_inode(ext2fs, journal_size,
		    EXT2_MKJOURNAL_NO_MNT_CHECK |
		    ((Flags & FP_QUICK) ? EXT2_MKJOURNAL_LAZYINIT : 0));
		uprintfs("\r\n");
		if (r != 0) {
			SET_EXT2_FORMAT_ERROR(ERROR_WRITE_FAULT);
			uprintf("Could not create journal: %s", error_message(r));
			goto out;
		}
	}

	/* Persistence config (for Debian Live) */
	if (Flags & FP_CREATE_PERSISTENCE_CONF) {
		const char* name = "persistence.conf";
		const char  data[] = "/ union\n";
		int written = 0, fsize = (int)(sizeof(data) - 1);
		ext2_file_t ext2fd;
		ext2_ino_t  inode_id;
		time_t ctime = time(NULL);
		struct ext2_inode inode = { 0 };
		if (ctime > UINT32_MAX) ctime = UINT32_MAX;
		inode.i_mode       = 0100644;
		inode.i_links_count = 1;
		inode.i_atime = inode.i_ctime = inode.i_mtime = (uint32_t)ctime;
		inode.i_size  = fsize;

		ext2fs_namei(ext2fs, EXT2_ROOT_INO, EXT2_ROOT_INO, name, &inode_id);
		ext2fs_new_inode(ext2fs, EXT2_ROOT_INO, 010755, 0, &inode_id);
		ext2fs_link(ext2fs, EXT2_ROOT_INO, name, inode_id, EXT2_FT_REG_FILE);
		ext2fs_inode_alloc_stats(ext2fs, inode_id, 1);
		ext2fs_write_new_inode(ext2fs, inode_id, &inode);
		ext2fs_file_open(ext2fs, inode_id, EXT2_FILE_WRITE, &ext2fd);
		if (ext2fs_file_write(ext2fd, data, fsize, &written) != 0 || written != fsize)
			uprintf("Could not create persistence.conf");
		else
			uprintf("Created persistence.conf");
		ext2fs_file_close(ext2fd);
	}

	/* Finalise and write filesystem */
	r = ext2fs_close(ext2fs);
	if (r == 0) {
		ext2fs = NULL;
	} else {
		SET_EXT2_FORMAT_ERROR(ERROR_WRITE_FAULT);
		uprintf("Could not create %s volume: %s", FSName, error_message(r));
		goto out;
	}

	UpdateProgressWithInfo(OP_FORMAT, MSG_217, 100, 100);
	ret = TRUE;

out:
	free(volume_name);
	if (ext2fs) ext2fs_free(ext2fs);
	free(buf);
	return ret;
}

#endif /* __linux__ */

