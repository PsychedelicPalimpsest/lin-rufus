/*
 * format_ext.c — portable ext2/3/4 helper functions (shared by Linux and Windows)
 *
 * This file is #included by src/linux/format_ext.c and src/windows/format_ext.c.
 * Do NOT compile it as a stand-alone translation unit.
 *
 * Callers must define EXT_IO_MANAGER to the platform I/O manager before
 * including this file, e.g.:
 *   #define EXT_IO_MANAGER posix_io_manager   // Linux
 *   #define EXT_IO_MANAGER nt_io_manager      // Windows
 *
 * Copyright © 2019-2025 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/*
 * Map an ext2fs error code to a human-readable string.
 * Returns a pointer to a static buffer for unknown codes.
 */
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
	case EXT2_ET_BAD_MAGIC:              return "Bad magic";
	case EXT2_ET_RO_FILSYS:              return "Read-only file system";
	case EXT2_ET_GDESC_BAD_BLOCK_MAP:
	case EXT2_ET_GDESC_BAD_INODE_MAP:
	case EXT2_ET_GDESC_BAD_INODE_TABLE:  return "Bad map or table";
	case EXT2_ET_UNEXPECTED_BLOCK_SIZE:  return "Unexpected block size";
	case EXT2_ET_DIR_CORRUPTED:          return "Corrupted entry";
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
	case EXT2_ET_SHORT_WRITE:            return "read/write error";
	case EXT2_ET_DIR_NO_SPACE:           return "no space left";
	case EXT2_ET_TOOSMALL:               return "Too small";
	case EXT2_ET_BAD_DEVICE_NAME:        return "Bad device name";
	case EXT2_ET_MISSING_INODE_TABLE:    return "Missing inode table";
	case EXT2_ET_CORRUPT_SUPERBLOCK:     return "Superblock is corrupted";
	case EXT2_ET_CALLBACK_NOTHANDLED:    return "Unhandled callback";
	case EXT2_ET_BAD_BLOCK_IN_INODE_TABLE: return "Bad block in inode table";
	case EXT2_ET_UNSUPP_FEATURE:
	case EXT2_ET_RO_UNSUPP_FEATURE:
	case EXT2_ET_UNIMPLEMENTED:          return "Unsupported feature";
	case EXT2_ET_LLSEEK_FAILED:          return "Seek failed";
	case EXT2_ET_NO_MEMORY:
	case EXT2_ET_BLOCK_ALLOC_FAIL:
	case EXT2_ET_INODE_ALLOC_FAIL:       return "Out of memory";
	case EXT2_ET_INVALID_ARGUMENT:       return "Invalid argument";
	case EXT2_ET_NO_DIRECTORY:           return "No directory";
	case EXT2_ET_FILE_NOT_FOUND:         return "File not found";
	case EXT2_ET_FILE_RO:                return "File is read-only";
	case EXT2_ET_DIR_EXISTS:             return "Directory already exists";
	case EXT2_ET_CANCEL_REQUESTED:       return "Cancel requested";
	case EXT2_ET_FILE_TOO_BIG:           return "File too big";
	case EXT2_ET_JOURNAL_NOT_BLOCK:
	case EXT2_ET_NO_JOURNAL_SB:          return "No journal superblock";
	case EXT2_ET_JOURNAL_TOO_SMALL:      return "Journal too small";
	case EXT2_ET_NO_JOURNAL:             return "No journal";
	case EXT2_ET_TOO_MANY_INODES:        return "Too many inodes";
	case EXT2_ET_NO_CURRENT_NODE:        return "No current node";
	case EXT2_ET_OP_NOT_SUPPORTED:       return "Operation not supported";
	case EXT2_ET_IO_CHANNEL_NO_SUPPORT_64: return "I/O Channel does not support 64-bit operation";
	case EXT2_ET_BAD_DESC_SIZE:          return "Bad descriptor size";
	case EXT2_ET_INODE_CSUM_INVALID:
	case EXT2_ET_INODE_BITMAP_CSUM_INVALID:
	case EXT2_ET_EXTENT_CSUM_INVALID:
	case EXT2_ET_DIR_CSUM_INVALID:
	case EXT2_ET_EXT_ATTR_CSUM_INVALID:
	case EXT2_ET_SB_CSUM_INVALID:
	case EXT2_ET_BLOCK_BITMAP_CSUM_INVALID:
	case EXT2_ET_MMP_CSUM_INVALID:       return "Invalid checksum";
	case EXT2_ET_UNKNOWN_CSUM:           return "Unknown checksum";
	case EXT2_ET_FILE_EXISTS:            return "File exists";
	case EXT2_ET_INODE_IS_GARBAGE:       return "Inode is garbage";
	case EXT2_ET_JOURNAL_FLAGS_WRONG:    return "Wrong journal flags";
	case EXT2_ET_FILESYSTEM_CORRUPTED:   return "File system is corrupted";
	case EXT2_ET_BAD_CRC:                return "Bad CRC";
	case EXT2_ET_CORRUPT_JOURNAL_SB:     return "Journal Superblock is corrupted";
	case EXT2_ET_INODE_CORRUPTED:
	case EXT2_ET_EA_INODE_CORRUPTED:     return "Inode is corrupted";
	case EXT2_ET_NO_GDESC:               return "Group descriptors not loaded";
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

/*
 * Progress callback used by the ext2fs library during formatting.
 * Returns EXT2_ET_CANCEL_REQUESTED when a Rufus error/cancel is detected.
 */
errcode_t ext2fs_print_progress(int64_t cur_value, int64_t max_value)
{
	UpdateProgressWithInfo(OP_FORMAT, MSG_217,
	    (uint64_t)((ext2_percent_start * max_value) + (ext2_percent_share * cur_value)),
	    (uint64_t)max_value);
	uprint_progress((uint64_t)cur_value, (uint64_t)max_value);
	return IS_ERROR(ErrorStatus) ? EXT2_ET_CANCEL_REQUESTED : 0;
}

/*
 * Read the ext2/3/4 volume label from a partition.
 * Uses the EXT_IO_MANAGER macro defined by the including platform file.
 */
const char* GetExtFsLabel(DWORD DriveIndex, uint64_t PartitionOffset)
{
	static char label[EXT2_LABEL_LEN + 1];
	errcode_t r;
	ext2_filsys ext2fs = NULL;
	char* volume_name = GetExtPartitionName(DriveIndex, PartitionOffset);

	if (volume_name == NULL)
		return NULL;
	r = ext2fs_open(volume_name, EXT2_FLAG_SKIP_MMP, 0, 0,
	                EXT_IO_MANAGER, &ext2fs);
	free(volume_name);
	if (r == 0) {
		assert(ext2fs != NULL);
		strncpy(label, ext2fs->super->s_volume_name, EXT2_LABEL_LEN);
		label[EXT2_LABEL_LEN] = 0;
	}
	if (ext2fs != NULL)
		ext2fs_close(ext2fs);
	return (r == 0) ? label : NULL;
}
