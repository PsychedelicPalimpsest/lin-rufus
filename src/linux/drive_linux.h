/*
 * drive_linux.h — Internal API for Linux drive.c
 *
 * These symbols are exposed only for unit-testing purposes.  Production
 * code should always go through the standard drive.h interface.
 */
#pragma once

#ifndef _WIN32

#include "rufus.h"
#include "drive.h"

/* ---- Parsed partition descriptor ---------------------------------------- */
typedef struct {
	uint64_t offset;      /* byte offset of partition start on disk */
	uint64_t size;        /* byte size of partition */
	uint8_t  mbr_type;   /* MBR type byte (0 for GPT partitions) */
	uint8_t  type_guid[16]; /* GPT partition type GUID (zeroed for MBR) */
	uint8_t  part_guid[16]; /* GPT partition unique GUID (zeroed for MBR) */
} parsed_partition_t;

/* ---- Test-support helpers ------------------------------------------------ */

/*
 * Reset the global rufus_drive[] table and drive count to zero.
 * Only for tests — not part of the production API.
 */
void drive_linux_reset_drives(void);

/*
 * Append a drive to the global rufus_drive[] table (up to MAX_DRIVES).
 * Assigns drive index = DRIVE_INDEX_MIN + current_count.
 * Only for tests.
 */
void drive_linux_add_drive(const char *id, const char *name,
                           const char *display_name, uint64_t size);

/*
 * Parse a 512-byte MBR sector.  Fills parts[] (up to 4 entries) and
 * *nparts with the number of non-empty entries found.
 *
 * Returns PARTITION_STYLE_MBR if the signature (0x55AA) is present,
 * PARTITION_STYLE_RAW otherwise.
 */
int drive_linux_parse_mbr(const uint8_t sector[512],
                          parsed_partition_t parts[4], int *nparts);

/*
 * Parse a GPT header sector and partition-entry array.
 * header_buf  : 512-byte GPT header (sector 1).
 * entries_buf : GPT partition entries array (128 * entry_size bytes).
 * entries_sz  : size in bytes of entries_buf.
 * parts[]     : output array; caller must supply >= 128 slots.
 * *nparts     : number of non-empty partitions found.
 *
 * Returns PARTITION_STYLE_GPT if the header signature is valid,
 * PARTITION_STYLE_RAW otherwise.
 */
int drive_linux_parse_gpt(const uint8_t *header_buf,
                          const uint8_t *entries_buf, size_t entries_sz,
                          parsed_partition_t *parts, int *nparts);

/*
 * GetLogicalName variant with injectable sysfs/devfs roots.
 * sysfs_root : path that replaces "/sys"  (e.g. "/tmp/fake_sys")
 * dev_root   : path that replaces "/dev"  (e.g. "/tmp/fake_dev")
 */
char *GetLogicalNameWithRoot(DWORD DriveIndex, uint64_t PartitionOffset,
                             BOOL bKeepTrailingSlash, BOOL bSilent,
                             const char *sysfs_root, const char *dev_root);

/* ---- UEFI:NTFS support -------------------------------------------------- */

/*
 * Load res/uefi/uefi-ntfs.img into a malloc'd buffer.
 * On success sets *out_size and returns the buffer; caller must free() it.
 * Returns NULL if the file cannot be found.
 */
uint8_t *load_uefi_ntfs_data(size_t *out_size);

/*
 * Write 'data' (size bytes) to the drive at byte offset 'offset'.
 * Returns FALSE for NULL data, zero size, or invalid handle.
 */
BOOL write_uefi_ntfs_partition(HANDLE hDrive, uint64_t offset,
                               const uint8_t *data, size_t size);

/*
 * Return TRUE when the given boot/fs/image combination requires a UEFI:NTFS
 * extra partition (XP_UEFI_NTFS).  Pass NULL for 'report' to force FALSE.
 */
BOOL uefi_ntfs_needs_extra_partition(int boot_type, int fs_type,
                                     int target_type,
                                     const RUFUS_IMG_REPORT *report);

#endif /* !_WIN32 */
