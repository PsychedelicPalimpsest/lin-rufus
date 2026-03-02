/*
 * Rufus: The Reliable USB Formatting Utility
 * Common drive-utility declarations — shared between Linux and Windows builds.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdint.h>
#include "rufus.h"
#include "winioctl.h"

/* ---- Extra-partition bit flags (XP_*) ---------------------------------- */
#ifndef XP_MSR
#define XP_MSR                              0x01
#define XP_ESP                              0x02
#define XP_UEFI_NTFS                        0x04
#define XP_COMPAT                           0x08
#define XP_PERSISTENCE                      0x10
#endif

/* ---- Partition index constants ----------------------------------------- */
#ifndef PI_MAIN
#define PI_MAIN                             0
#define PI_ESP                              1
#define PI_CASPER                           2
#define PI_UEFI_NTFS                        3
#define PI_MAX                              4
#endif

/* ---- Format-parameter flags (FP_*) ------------------------------------- */
#ifndef FP_FORCE
#define FP_FORCE                            0x00000001
#define FP_QUICK                            0x00000002
#define FP_COMPRESSION                      0x00000004
#define FP_DUPLICATE_METADATA               0x00000008
#define FP_LARGE_FAT32                      0x00010000
#define FP_NO_BOOT                          0x00020000
#define FP_CREATE_PERSISTENCE_CONF          0x00040000
#define FP_NO_PROGRESS                      0x00080000
#endif

/* ---- Current-drive info struct ----------------------------------------- */
/*
 * RUFUS_DRIVE_INFO describes the currently selected drive.  It is defined
 * here (common) so that both the Linux and Windows builds, and the shared
 * test suite, can all use the same type without going through
 * windows/drive.h (which pulls in many Windows-only COM/VDS headers).
 *
 * All field types are available via the compat windows.h / winioctl.h.
 */
#ifndef RUFUS_DRIVE_INFO_DEFINED
#define RUFUS_DRIVE_INFO_DEFINED
typedef struct {
	LONGLONG DiskSize;
	DWORD DeviceNumber;
	DWORD SectorsPerTrack;
	DWORD SectorSize;
	DWORD FirstDataSector;
	MEDIA_TYPE MediaType;
	int PartitionStyle;
	int nPartitions;
	struct {
		wchar_t Name[36];
		uint64_t Offset;
		uint64_t Size;
	} Partition[MAX_PARTITIONS];
	int FSType;
	char proposed_label[16];
	BOOL has_protective_mbr;
	BOOL has_mbr_uefi_marker;
	struct {
		ULONG Allowed;
		ULONG Default;
	} ClusterSize[FS_MAX];
} RUFUS_DRIVE_INFO;
extern RUFUS_DRIVE_INFO SelectedDrive;
extern int partition_index[PI_MAX];
#endif /* RUFUS_DRIVE_INFO_DEFINED */

/*
 * Cross-platform drive API — implemented by linux/drive.c on Linux,
 * windows/drive.c on Windows.  These declarations are needed by format.c
 * and other common code that calls into the drive layer.
 */
BOOL SetAutoMount(BOOL enable);
BOOL GetAutoMount(BOOL *enabled);
char *GetPhysicalName(DWORD DriveIndex);
HANDLE GetPhysicalHandle(DWORD DriveIndex, BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare);
char *GetLogicalName(DWORD DriveIndex, uint64_t PartitionOffset, BOOL bKeepTrailingBackslash, BOOL bSilent);
char *AltGetLogicalName(DWORD DriveIndex, uint64_t PartitionOffset, BOOL bKeepTrailingBackslash, BOOL bSilent);
char *GetExtPartitionName(DWORD DriveIndex, uint64_t PartitionOffset);
BOOL WaitForLogical(DWORD DriveIndex, uint64_t PartitionOffset);
HANDLE GetLogicalHandle(DWORD DriveIndex, uint64_t PartitionOffset, BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare);
HANDLE AltGetLogicalHandle(DWORD DriveIndex, uint64_t PartitionOffset, BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare);
int GetDriveNumber(HANDLE hDrive, char *path);
BOOL GetDriveLetters(DWORD DriveIndex, char *drive_letters);
UINT GetDriveTypeFromIndex(DWORD DriveIndex);
char GetUnusedDriveLetter(void);
BOOL IsDriveLetterInUse(const char drive_letter);
char RemoveDriveLetters(DWORD DriveIndex, BOOL bUseLast, BOOL bSilent);
BOOL GetDriveLabel(DWORD DriveIndex, char *letters, char **label, BOOL bSilent);
uint64_t GetDriveSize(DWORD DriveIndex);
BOOL IsMediaPresent(DWORD DriveIndex);
BOOL AnalyzeMBR(HANDLE hPhysicalDrive, const char *TargetName, BOOL bSilent);
BOOL AnalyzePBR(HANDLE hLogicalVolume);
BOOL GetDrivePartitionData(DWORD DriveIndex, char *FileSystemName, DWORD FileSystemNameSize, BOOL bSilent);
BOOL UnmountVolume(HANDLE hDrive);
BOOL MountVolume(char *drive_name, char *drive_guid);
BOOL AltUnmountVolume(const char *drive_name, BOOL bSilent);
char *AltMountVolume(DWORD DriveIndex, uint64_t PartitionOffset, BOOL bSilent);
BOOL RemountVolume(char *drive_name, BOOL bSilent);
BOOL CreatePartition(HANDLE hDrive, int partition_style, int file_system, BOOL mbr_uefi_marker, uint8_t extra_partitions);
BOOL InitializeDisk(HANDLE hDrive);
BOOL RefreshDriveLayout(HANDLE hDrive);
const char *GetExtFsLabel(DWORD DriveIndex, uint64_t PartitionOffset);
void ClearDrives(void);
BOOL GetDevices(DWORD devnum);
BOOL CyclePort(int index);
int CycleDevice(int index);
BOOL RefreshLayout(DWORD DriveIndex);
BOOL DeletePartition(DWORD DriveIndex, ULONGLONG PartitionOffset, BOOL bSilent);
BOOL IsVdsAvailable(BOOL bSilent);

/*
 * GetMBRPartitionType — look up a human-readable name for an MBR
 * partition-type byte (0x00–0xFF).
 *
 * Returns a pointer to a constant string.  Unknown types return "Unknown".
 * The pointer is always non-NULL.
 */
const char *GetMBRPartitionType(uint8_t type);

/*
 * GetGPTPartitionType — look up a human-readable name for a GPT partition
 * GUID.
 *
 * Returns a pointer to a string.  Unknown GUIDs return the GUID formatted as
 * a hex string (via GuidToString).  The pointer is always non-NULL.
 */
const char *GetGPTPartitionType(const GUID *guid);
