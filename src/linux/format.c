/* Linux implementation: format.c - FormatPartition, WritePBR, FormatThread */
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "ms-sys/inc/file.h"
#include "ms-sys/inc/br.h"
#include "ms-sys/inc/fat32.h"
#include "ms-sys/inc/partition_info.h"

extern const char* FileSystemLabel[FS_MAX];

static int actual_fs_type = FS_FAT32;

BOOL FormatPartition(DWORD DriveIndex, uint64_t PartitionOffset, DWORD UnitAllocationSize,
                     USHORT FSType, LPCSTR Label, DWORD Flags)
{
	if ((DriveIndex < DRIVE_INDEX_MIN) || (DriveIndex > DRIVE_INDEX_MAX) ||
	    (FSType >= FS_MAX) ||
	    ((UnitAllocationSize != 0) && (!IS_POWER_OF_2(UnitAllocationSize)))) {
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	actual_fs_type = FSType;
	if (FSType == FS_FAT32)
		return FormatLargeFAT32(DriveIndex, PartitionOffset, UnitAllocationSize,
		                        FileSystemLabel[FSType], Label, Flags);
	if (IS_EXT(FSType))
		return FormatExtFs(DriveIndex, PartitionOffset, UnitAllocationSize,
		                   FileSystemLabel[FSType], Label, Flags);
	/* NTFS, exFAT, UDF, ReFS not supported on Linux */
	ErrorStatus = RUFUS_ERROR(ERROR_NOT_SUPPORTED);
	return FALSE;
}

BOOL WritePBR(HANDLE hLogicalVolume)
{
	FAKE_FD fake_fd = { 0 };
	FILE* fp = (FILE*)&fake_fd;
	DWORD sector_size;

	if (hLogicalVolume == INVALID_HANDLE_VALUE || hLogicalVolume == NULL)
		return FALSE;

	fake_fd._handle = hLogicalVolume;
	sector_size = SelectedDrive.SectorSize ? SelectedDrive.SectorSize : 512;
	set_bytes_per_sector(sector_size);

	switch (actual_fs_type) {
	case FS_FAT32:
		/* Write boot record for both primary (sector 0) and backup (sector 6) */
		for (int i = 0; i < 2; i++) {
			if (!is_fat_32_fs(fp)) {
				uprintf("Volume does not have a %s FAT32 boot sector - aborting",
				        i ? "secondary" : "primary");
				return FALSE;
			}
			if (!write_fat_32_br(fp, 0)) return FALSE;
			if (!write_partition_physical_disk_drive_id_fat32(fp)) return FALSE;
			fake_fd._offset += 6 * sector_size;
		}
		return TRUE;
	case FS_EXT2:
	case FS_EXT3:
	case FS_EXT4:
		/* ext filesystems don't use a Windows-style partition boot record */
		return TRUE;
	default:
		return FALSE;
	}
}

DWORD WINAPI FormatThread(void* param)
{
	(void)param;
	return 0;
}

