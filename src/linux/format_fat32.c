/*
 * Rufus: The Reliable USB Formatting Utility — Linux FAT32 formatter
 *
 * Ported from src/windows/format_fat32.c (Tom Thornhill / Pete Batard).
 * All Windows-specific I/O (DeviceIoControl, SetVolumeLabel, etc.) is
 * replaced by POSIX equivalents.  The FAT32 on-disk layout is identical
 * to the Windows implementation so the resulting filesystem is fully
 * compatible.
 *
 * Copyright © 2007-2009 Tom Thornhill/Ridgecrop
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
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
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>   /* BLKGETSIZE64, BLKSSZGET */

#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "file.h"
#include "resource.h"
#include "localization.h"

#define die(msg, err) \
	do { uprintf(msg); ErrorStatus = RUFUS_ERROR(err); goto out; } while(0)

extern BOOL write_as_esp;

/* FAT32 boot sector */
#pragma pack(push, 1)
typedef struct {
	uint8_t  sJmpBoot[3];
	uint8_t  sOEMName[8];
	uint16_t wBytsPerSec;
	uint8_t  bSecPerClus;
	uint16_t wRsvdSecCnt;
	uint8_t  bNumFATs;
	uint16_t wRootEntCnt;
	uint16_t wTotSec16;
	uint8_t  bMedia;
	uint16_t wFATSz16;
	uint16_t wSecPerTrk;
	uint16_t wNumHeads;
	uint32_t dHiddSec;
	uint32_t dTotSec32;
	uint32_t dFATSz32;
	uint16_t wExtFlags;
	uint16_t wFSVer;
	uint32_t dRootClus;
	uint16_t wFSInfo;
	uint16_t wBkBootSec;
	uint8_t  Reserved[12];
	uint8_t  bDrvNum;
	uint8_t  Reserved1;
	uint8_t  bBootSig;
	uint32_t dBS_VolID;
	uint8_t  sVolLab[11];
	uint8_t  sBS_FilSysType[8];
} FAT_BOOTSECTOR32;

typedef struct {
	uint32_t dLeadSig;
	uint8_t  sReserved1[480];
	uint32_t dStrucSig;
	uint32_t dFree_Count;
	uint32_t dNxt_Free;
	uint8_t  sReserved2[12];
	uint32_t dTrailSig;
} FAT_FSINFO;
#pragma pack(pop)

/* Generate a FAT32 volume serial number from the current time */
static uint32_t GetVolumeID(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm* t = localtime(&ts.tv_sec);
	if (!t) return (uint32_t)(ts.tv_sec ^ ts.tv_nsec);

	uint16_t lo = (uint16_t)t->tm_mday + (uint16_t)((t->tm_mon + 1) << 8);
	uint16_t tmp = (uint16_t)(ts.tv_nsec / 10000000) + (uint16_t)(t->tm_sec << 8);
	lo += tmp;
	uint16_t hi = (uint16_t)t->tm_min + (uint16_t)(t->tm_hour << 8);
	hi += (uint16_t)(t->tm_year + 1900);
	return (uint32_t)lo + ((uint32_t)hi << 16);
}

/* Proper FAT size computation (matches Windows version) */
static uint32_t GetFATSizeSectors(uint32_t DskSize, uint32_t ReservedSecCnt,
                                   uint32_t SecPerClus, uint32_t NumFATs,
                                   uint32_t BytesPerSect)
{
	uint64_t Numerator   = DskSize - ReservedSecCnt + 2ULL * SecPerClus;
	uint64_t Denominator = (uint64_t)SecPerClus * BytesPerSect / 4 + NumFATs;
	return (uint32_t)(Numerator / Denominator + 1);
}

/*
 * Get the size (in bytes) and logical sector size of a file descriptor.
 * Works for both block devices (ioctl) and regular files (fstat).
 */
static int get_device_geometry(int fd, uint64_t* size_bytes, uint32_t* sector_size)
{
	uint64_t sz = 0;
	uint32_t bsz = 512;
	struct stat st;

	/* For image file partitions, use the registered partition size */
	uint64_t part_sz = linux_get_fd_part_size(fd);
	if (part_sz > 0) {
		*size_bytes  = part_sz;
		*sector_size = 512;
		return 0;
	}

	if (ioctl(fd, BLKGETSIZE64, &sz) == 0 && sz > 0) {
		/* Block device */
		uint32_t ssize = 512;
		ioctl(fd, BLKSSZGET, &ssize);
		if (ssize >= 512) bsz = ssize;
	} else {
		/* Regular file or other; use fstat */
		if (fstat(fd, &st) != 0 || st.st_size <= 0)
			return -1;
		sz = (uint64_t)st.st_size;
	}

	*size_bytes  = sz;
	*sector_size = bsz;
	return 0;
}

BOOL FormatLargeFAT32(DWORD DriveIndex, uint64_t PartitionOffset,
                      DWORD ClusterSize, LPCSTR FSName, LPCSTR Label, DWORD Flags)
{
	BOOL r = FALSE;
	DWORD i;
	HANDLE hLogicalVolume = INVALID_HANDLE_VALUE;

	/* Recommended values */
	uint32_t ReservedSectCount = 32;
	const uint32_t NumFATs     = 2;
	const uint32_t BackupBootSect = 6;
	uint32_t VolumeId          = 0;

	/* Calculated later */
	uint32_t FatSize           = 0;
	uint32_t BytesPerSect      = 0;
	uint32_t SectorsPerCluster = 0;
	uint32_t TotalSectors      = 0;
	uint32_t AlignSectors      = 0;
	uint32_t SystemAreaSize    = 0;
	uint32_t UserAreaSize      = 0;
	uint64_t PartitionBytes    = 0;

	/* Structures written to disk */
	FAT_BOOTSECTOR32* pFAT32BootSect = NULL;
	FAT_FSINFO*       pFAT32FsInfo   = NULL;
	uint32_t*         pFirstSectOfFat = NULL;
	uint8_t*          pZeroSect      = NULL;
	const uint32_t    BurstSize      = 128; /* sectors per zero-write burst */
	char              VolId[12]      = "NO NAME    ";

	uint64_t FatNeeded, ClusterCount;

	if (safe_strncmp(FSName, "FAT", 3) != 0) {
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		goto out;
	}

	if (!(Flags & FP_NO_PROGRESS)) {
		PrintInfoDebug(0, MSG_222, "Large FAT32");
		UpdateProgressWithInfoInit(NULL, TRUE);
	}

	VolumeId = GetVolumeID();

	/* Encode the user-supplied label (up to 11 uppercase chars, space-padded) */
	if (Label && Label[0] != '\0') {
		memset(VolId, ' ', 11);
		VolId[11] = '\0';
		for (int li = 0; li < 11 && Label[li] != '\0'; li++)
			VolId[li] = (char)toupper((unsigned char)Label[li]);
	}

	/* Open the device/file */
	hLogicalVolume = write_as_esp
		? AltGetLogicalHandle(DriveIndex, PartitionOffset, TRUE, TRUE, FALSE)
		:     GetLogicalHandle(DriveIndex, PartitionOffset, TRUE, TRUE, FALSE);

	if (hLogicalVolume == INVALID_HANDLE_VALUE || hLogicalVolume == NULL)
		die("Invalid logical volume handle", ERROR_INVALID_HANDLE);
	if (IS_ERROR(ErrorStatus))
		goto out;

	/* Flush any existing mount */
	UnmountVolume(hLogicalVolume);

	/* Determine geometry from file/device */
	{
		int fd = (int)(intptr_t)hLogicalVolume;
		if (get_device_geometry(fd, &PartitionBytes, &BytesPerSect) != 0)
			die("Failed to get device geometry", ERROR_NOT_SUPPORTED);
	}

	if (BytesPerSect < 512)
		BytesPerSect = 512;

	/* Validate size */
	uint64_t qTotalSectors = PartitionBytes / BytesPerSect;
	if (qTotalSectors < 65536)
		die("This drive is too small for FAT32 - there must be at least 64K clusters",
		    APPERR(ERROR_INVALID_CLUSTER_SIZE));
	if (qTotalSectors >= 0xFFFFFFFFULL)
		die("This drive is too big for FAT32 - max 2TB supported",
		    APPERR(ERROR_INVALID_VOLUME_SIZE));

	/* Default cluster size (matches Windows behaviour) */
	if (ClusterSize == 0) {
		if (PartitionBytes < 64 * MB)          ClusterSize = 512;
		else if (PartitionBytes < 128 * MB)    ClusterSize = 1 * KB;
		else if (PartitionBytes < 256 * MB)    ClusterSize = 2 * KB;
		else if (PartitionBytes < 8ULL * GB)   ClusterSize = 4 * KB;
		else if (PartitionBytes < 16ULL * GB)  ClusterSize = 8 * KB;
		else if (PartitionBytes < 32ULL * GB)  ClusterSize = 16 * KB;
		else                                    ClusterSize = 32 * KB;
	}

	pFAT32BootSect  = (FAT_BOOTSECTOR32*)calloc(BytesPerSect, 1);
	pFAT32FsInfo    = (FAT_FSINFO*)calloc(BytesPerSect, 1);
	pFirstSectOfFat = (uint32_t*)calloc(BytesPerSect, 1);
	if (!pFAT32BootSect || !pFAT32FsInfo || !pFirstSectOfFat)
		die("Failed to allocate memory", ERROR_NOT_ENOUGH_MEMORY);

	/* Fill boot sector */
	pFAT32BootSect->sJmpBoot[0] = 0xEB;
	pFAT32BootSect->sJmpBoot[1] = 0x58;
	pFAT32BootSect->sJmpBoot[2] = 0x90;
	memcpy(pFAT32BootSect->sOEMName, "MSWIN4.1", 8);
	pFAT32BootSect->wBytsPerSec  = (uint16_t)BytesPerSect;
	SectorsPerCluster             = ClusterSize / BytesPerSect;
	pFAT32BootSect->bSecPerClus  = (uint8_t)SectorsPerCluster;
	pFAT32BootSect->bNumFATs     = (uint8_t)NumFATs;
	pFAT32BootSect->wRootEntCnt  = 0;
	pFAT32BootSect->wTotSec16    = 0;
	pFAT32BootSect->bMedia       = 0xF8;
	pFAT32BootSect->wFATSz16     = 0;
	pFAT32BootSect->wSecPerTrk   = 63;    /* typical USB geometry */
	pFAT32BootSect->wNumHeads    = 255;
	pFAT32BootSect->dHiddSec     = 0;
	TotalSectors                  = (uint32_t)qTotalSectors;
	pFAT32BootSect->dTotSec32    = TotalSectors;

	FatSize = GetFATSizeSectors(pFAT32BootSect->dTotSec32,
	                             pFAT32BootSect->wRsvdSecCnt,
	                             pFAT32BootSect->bSecPerClus,
	                             pFAT32BootSect->bNumFATs, BytesPerSect);

	/* Align start of data region to 1 MB boundary */
	SystemAreaSize = ReservedSectCount + NumFATs * FatSize;
	AlignSectors   = (1U * MB) / BytesPerSect;
	SystemAreaSize = (SystemAreaSize + AlignSectors - 1) / AlignSectors * AlignSectors;
	ReservedSectCount = SystemAreaSize - NumFATs * FatSize;

	pFAT32BootSect->wRsvdSecCnt  = (uint16_t)ReservedSectCount;
	pFAT32BootSect->dFATSz32     = FatSize;
	pFAT32BootSect->wExtFlags    = 0;
	pFAT32BootSect->wFSVer       = 0;
	pFAT32BootSect->dRootClus    = 2;
	pFAT32BootSect->wFSInfo      = 1;
	pFAT32BootSect->wBkBootSec   = (uint16_t)BackupBootSect;
	pFAT32BootSect->bDrvNum      = 0x80;
	pFAT32BootSect->Reserved1    = 0;
	pFAT32BootSect->bBootSig     = 0x29;
	pFAT32BootSect->dBS_VolID    = VolumeId;
	memcpy(pFAT32BootSect->sVolLab, VolId, 11);
	memcpy(pFAT32BootSect->sBS_FilSysType, "FAT32   ", 8);
	((uint8_t*)pFAT32BootSect)[510] = 0x55;
	((uint8_t*)pFAT32BootSect)[511] = 0xAA;
	if (BytesPerSect != 512) {
		((uint8_t*)pFAT32BootSect)[BytesPerSect - 2] = 0x55;
		((uint8_t*)pFAT32BootSect)[BytesPerSect - 1] = 0xAA;
	}

	/* FSInfo sector */
	pFAT32FsInfo->dLeadSig   = 0x41615252u;
	pFAT32FsInfo->dStrucSig  = 0x61417272u;
	pFAT32FsInfo->dFree_Count = (uint32_t)-1;
	pFAT32FsInfo->dNxt_Free  = (uint32_t)-1;
	pFAT32FsInfo->dTrailSig  = 0xAA550000u;

	/* First FAT sector entries */
	pFirstSectOfFat[0] = 0x0FFFFFF8u;
	pFirstSectOfFat[1] = 0x0FFFFFFFu;
	pFirstSectOfFat[2] = 0x0FFFFFFFu;

	/* Sanity checks */
	UserAreaSize  = TotalSectors - ReservedSectCount - (NumFATs * FatSize);
	assert(SectorsPerCluster > 0);
	ClusterCount  = UserAreaSize / SectorsPerCluster;

	if (ClusterCount > 0x0FFFFFFF)
		die("Too many clusters (>2^28); use a larger cluster size",
		    ERROR_INVALID_CLUSTER_SIZE);
	if (ClusterCount < 65536)
		die("FAT32 must have at least 65536 clusters; use a smaller cluster size",
		    ERROR_INVALID_CLUSTER_SIZE);

	FatNeeded  = ClusterCount * 4;
	FatNeeded += BytesPerSect - 1;
	FatNeeded /= BytesPerSect;
	if (FatNeeded > FatSize)
		die("Drive too big for large FAT32 format", APPERR(ERROR_INVALID_VOLUME_SIZE));

	uprintf("Size: %s, %lu sectors", SizeToHumanReadable(PartitionBytes, TRUE, FALSE), TotalSectors);
	uprintf("Cluster size %lu bytes, %lu bytes/sector", SectorsPerCluster * BytesPerSect, BytesPerSect);
	uprintf("Volume ID %08x, %lu reserved sectors, %lu FAT sectors, %lu FATs",
	        VolumeId, ReservedSectCount, FatSize, NumFATs);

	/* Fix up FSInfo */
	pFAT32FsInfo->dFree_Count = (UserAreaSize / SectorsPerCluster) - 1;
	pFAT32FsInfo->dNxt_Free   = 3;

	/* Zero system area + root cluster */
	SystemAreaSize = ReservedSectCount + NumFATs * FatSize + SectorsPerCluster;
	uprintf("Clearing %lu sectors for reserved/FAT/root...", SystemAreaSize);

	pZeroSect = (uint8_t*)calloc(BytesPerSect, BurstSize);
	if (!pZeroSect)
		die("Failed to allocate zero buffer", ERROR_NOT_ENOUGH_MEMORY);

	for (i = 0; i < (SystemAreaSize + BurstSize - 1); i += BurstSize) {
		if (!(Flags & FP_NO_PROGRESS))
			UpdateProgressWithInfo(OP_FORMAT, MSG_217, (uint64_t)i,
			                       (uint64_t)SystemAreaSize + BurstSize);
		CHECK_FOR_USER_CANCEL;
		if (write_sectors(hLogicalVolume, BytesPerSect, i, BurstSize, pZeroSect)
		    != (int64_t)(BytesPerSect * BurstSize)) {
			die("Error clearing reserved sectors", ERROR_WRITE_FAULT);
		}
	}

	uprintf("Writing boot sectors and FATs...");

	/* Write boot sector and FSInfo at sector 0 and at backup location */
	for (i = 0; i < 2; i++) {
		uint32_t SectorStart = (i == 0) ? 0 : BackupBootSect;
		write_sectors(hLogicalVolume, BytesPerSect, SectorStart,     1, pFAT32BootSect);
		write_sectors(hLogicalVolume, BytesPerSect, SectorStart + 1, 1, pFAT32FsInfo);
	}

	/* Write first sector of each FAT */
	for (i = 0; i < NumFATs; i++) {
		uint32_t SectorStart = ReservedSectCount + i * FatSize;
		uprintf("FAT #%d at sector %lu", i, SectorStart);
		write_sectors(hLogicalVolume, BytesPerSect, SectorStart, 1, pFirstSectOfFat);
	}

	if (!(Flags & FP_NO_BOOT)) {
		if (!(Flags & FP_NO_PROGRESS))
			PrintInfoDebug(0, MSG_229);
		if (!WritePBR(hLogicalVolume))
			uprintf("Could not write PBR — drive may not boot");
	}

	/* On Linux we cannot call SetVolumeLabel, but the volume name is
	 * already encoded in the FAT boot sector's sVolLab field. */

	uprintf("FAT32 format completed.");
	r = TRUE;

out:
	safe_closehandle(hLogicalVolume);
	safe_free(pFAT32BootSect);
	safe_free(pFAT32FsInfo);
	safe_free(pFirstSectOfFat);
	safe_free(pZeroSect);
	return r;
}

#endif /* __linux__ */

