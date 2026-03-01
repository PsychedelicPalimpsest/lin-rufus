/*
 * Linux implementation: format.c
 * FormatPartition, WritePBR, FormatThread, and internal helpers
 * (ClearMBRGPT, WriteMBR, WriteDrive) exposed via format_linux.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "rufus.h"
#include "resource.h"
#include "drive.h"
#include "format.h"
#include "format_linux.h"
#include "ms-sys/inc/file.h"
#include "ms-sys/inc/br.h"
#include "ms-sys/inc/fat32.h"
#include "ms-sys/inc/partition_info.h"

extern const char* FileSystemLabel[FS_MAX];
extern BOOL force_large_fat32, enable_ntfs_compression, lock_drive, zero_drive, fast_zeroing;
extern BOOL write_as_image, write_as_esp;
extern BOOL use_rufus_mbr;
extern BOOL quick_format;
extern char *image_path;

/* Updated by FormatPartition so that WritePBR knows which FS was formatted */
static int actual_fs_type = FS_FAT32;

/* =========================================================================
 * FormatPartition
 * ======================================================================= */

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
	if (FSType == FS_NTFS)
		return FormatNTFS(DriveIndex, PartitionOffset, UnitAllocationSize, Label, Flags);
	if (FSType == FS_EXFAT)
		return FormatExFAT(DriveIndex, PartitionOffset, UnitAllocationSize, Label, Flags);
	/* UDF, ReFS not yet supported on Linux */
	ErrorStatus = RUFUS_ERROR(ERROR_NOT_SUPPORTED);
	return FALSE;
}

/* =========================================================================
 * WritePBR_fs
 *
 * Write the partition boot record for the specified filesystem type.
 * This is the implementation used by both WritePBR() (which passes the
 * cached actual_fs_type) and tests (which supply the type directly).
 * ======================================================================= */

BOOL WritePBR_fs(HANDLE hLogicalVolume, int fs_type)
{
	FAKE_FD fake_fd = { 0 };
	FILE* fp = (FILE*)&fake_fd;
	DWORD sector_size;

	if (hLogicalVolume == INVALID_HANDLE_VALUE || hLogicalVolume == NULL)
		return FALSE;

	fake_fd._handle = hLogicalVolume;
	sector_size = SelectedDrive.SectorSize ? SelectedDrive.SectorSize : 512;
	set_bytes_per_sector(sector_size);

	switch (fs_type) {
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
	case FS_NTFS:
	case FS_EXFAT:
		/* mkntfs / mkfs.exfat write their own boot sectors; no PBR step needed */
		return TRUE;
	default:
		return FALSE;
	}
}

/* =========================================================================
 * WritePBR
 * ======================================================================= */

BOOL WritePBR(HANDLE hLogicalVolume)
{
	return WritePBR_fs(hLogicalVolume, actual_fs_type);
}

/* =========================================================================
 * Internal helpers (non-static so tests can call them via format_linux.h)
 * ======================================================================= */

/*
 * format_linux_clear_mbr_gpt - zero the MBR/GPT areas of a drive.
 *
 * Zeroes MAX_SECTORS_TO_CLEAR sectors at the start and
 * MAX_SECTORS_TO_CLEAR/8 sectors at the end.
 */
BOOL format_linux_clear_mbr_gpt(HANDLE hDrive, LONGLONG DiskSize, DWORD SectorSize)
{
	if (!hDrive || hDrive == INVALID_HANDLE_VALUE) return FALSE;
	int fd = (int)(intptr_t)hDrive;

	DWORD head_count = MAX_SECTORS_TO_CLEAR;
	DWORD tail_count = MAX_SECTORS_TO_CLEAR / 8;
	if (SectorSize == 0) SectorSize = 512;

	size_t buf_sz = (size_t)SectorSize * head_count;
	uint8_t *zeros = (uint8_t*)calloc(1, buf_sz);
	if (!zeros) {
		ErrorStatus = RUFUS_ERROR(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}

	/* Zero the head of the drive */
	ssize_t written = pwrite(fd, zeros, buf_sz, 0);
	if (written != (ssize_t)buf_sz) {
		free(zeros);
		ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
		return FALSE;
	}
	uprintf("Zeroed %s at the top of the drive",
	        SizeToHumanReadable(buf_sz, FALSE, FALSE));

	/* Zero the tail of the drive (non-fatal on error) */
	LONGLONG tail_off = DiskSize - (LONGLONG)SectorSize * tail_count;
	if (tail_off > 0) {
		size_t tail_sz = (size_t)SectorSize * tail_count;
		uint8_t *tail_zeros = (uint8_t*)calloc(1, tail_sz);
		if (tail_zeros) {
			if (pwrite(fd, tail_zeros, tail_sz, (off_t)tail_off) == (ssize_t)tail_sz)
				uprintf("Zeroed %s at the end of the drive",
				        SizeToHumanReadable(tail_sz, FALSE, FALSE));
			else
				uprintf("WARNING: Could not clear the backup GPT area: %s", strerror(errno));
			free(tail_zeros);
		}
	}

	free(zeros);
	return TRUE;
}

/*
 * format_linux_write_mbr - write appropriate MBR boot code based on boot_type.
 *
 * Uses the ms-sys write_*_mbr() family which write only the boot code
 * (bytes 0–445) plus the 0x55AA signature — partition table entries
 * (bytes 446–509) are left untouched.
 */
BOOL format_linux_write_mbr(HANDLE hDrive)
{
	if (!hDrive || hDrive == INVALID_HANDLE_VALUE) return FALSE;

	FAKE_FD fake_fd = { 0 };
	FILE* fp = (FILE*)&fake_fd;
	fake_fd._handle = hDrive;

	DWORD sector_size = SelectedDrive.SectorSize ? SelectedDrive.SectorSize : 512;
	set_bytes_per_sector(sector_size);

	int r;
	int sub_type = boot_type;

	/* GPT: write a protective MBR with a Rufus message */
	if (partition_type == PARTITION_STYLE_GPT) {
		uprintf("Writing protective MBR");
		r = write_rufus_msg_mbr(fp);
		return r ? TRUE : FALSE;
	}

	/* UEFI target: zeroed MBR */
	if (target_type == TT_UEFI) {
		uprintf("Writing zero MBR (UEFI target)");
		r = write_zero_mbr(fp);
		return r ? TRUE : FALSE;
	}

	/* Non-bootable: zeroed MBR */
	if (boot_type == BT_NON_BOOTABLE) {
		uprintf("Writing zero MBR (non-bootable)");
		r = write_zero_mbr(fp);
		return r ? TRUE : FALSE;
	}

	/* Determine sub_type for BT_IMAGE */
	if (boot_type == BT_IMAGE) {
		if (img_report.has_grub4dos)
			sub_type = BT_GRUB4DOS;
		if (img_report.has_grub2)
			sub_type = BT_GRUB2;
		/* Syslinux takes precedence over Grub */
		if (HAS_SYSLINUX(img_report))
			sub_type = BT_SYSLINUX_V6;
	}

	switch (sub_type) {
	case BT_SYSLINUX_V4:
	case BT_SYSLINUX_V6:
		uprintf("Writing Syslinux MBR");
		r = write_syslinux_mbr(fp);
		break;
	case BT_GRUB2:
		uprintf("Writing Grub 2.0 MBR");
		r = write_grub2_mbr(fp);
		break;
	case BT_GRUB4DOS:
		uprintf("Writing Grub4DOS MBR");
		r = write_grub4dos_mbr(fp);
		break;
	case BT_REACTOS:
		uprintf("Writing ReactOS MBR");
		r = write_reactos_mbr(fp);
		break;
	default:
		if (use_rufus_mbr) {
			uprintf("Writing Rufus MBR");
			r = write_rufus_mbr(fp);
		} else {
			uprintf("Writing Windows 7 MBR");
			r = write_win7_mbr(fp);
		}
		break;
	}

	return r ? TRUE : FALSE;
}

/*
 * format_linux_write_drive - raw image write or zero-drive.
 *
 * If bZeroDrive is TRUE, writes zeros across the entire SelectedDrive.DiskSize.
 * If bZeroDrive is FALSE, copies from global image_path to hDrive.
 */
BOOL format_linux_write_drive(HANDLE hDrive, BOOL bZeroDrive)
{
	if (!hDrive || hDrive == INVALID_HANDLE_VALUE) return FALSE;
	int dst_fd = (int)(intptr_t)hDrive;

	if (bZeroDrive) {
		/* Zero the entire drive */
		LONGLONG disk_size = SelectedDrive.DiskSize;
		if (disk_size <= 0) return FALSE;
		const size_t chunk = 4 * 1024 * 1024;  /* 4 MB chunks */
		uint8_t *buf = (uint8_t*)calloc(1, chunk);
		if (!buf) {
			ErrorStatus = RUFUS_ERROR(ERROR_NOT_ENOUGH_MEMORY);
			return FALSE;
		}
		LONGLONG off = 0;
		BOOL ok = TRUE;
		while (off < disk_size) {
			CHECK_FOR_USER_CANCEL;
			size_t to_write = (size_t)((disk_size - off) < (LONGLONG)chunk
			                           ? (disk_size - off) : (LONGLONG)chunk);
			ssize_t w = pwrite(dst_fd, buf, to_write, (off_t)off);
			if (w != (ssize_t)to_write) {
				LastWriteError = RUFUS_ERROR(ERROR_WRITE_FAULT);
				ok = FALSE;
				break;
			}
			off += (LONGLONG)to_write;
			UpdateProgressWithInfo(OP_FILE_COPY, MSG_261,
			                       (uint64_t)off, (uint64_t)disk_size);
		}
		free(buf);
		return ok;
	}

	/* Image copy mode */
	if (!image_path) {
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	int src_fd = open(image_path, O_RDONLY | O_CLOEXEC);
	if (src_fd < 0) {
		ErrorStatus = RUFUS_ERROR(ERROR_FILE_NOT_FOUND);
		uprintf("Could not open image '%s': %s", image_path, strerror(errno));
		return FALSE;
	}

	/* Determine image size */
	struct stat st;
	if (fstat(src_fd, &st) != 0) {
		close(src_fd);
		ErrorStatus = RUFUS_ERROR(ERROR_READ_FAULT);
		return FALSE;
	}
	uint64_t img_size = (uint64_t)st.st_size;

	const size_t chunk = 4 * 1024 * 1024;
	uint8_t *buf = (uint8_t*)malloc(chunk);
	if (!buf) {
		close(src_fd);
		ErrorStatus = RUFUS_ERROR(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}

	BOOL ok = TRUE;
	uint64_t off = 0;
	while (off < img_size) {
		CHECK_FOR_USER_CANCEL;
		size_t to_read = (size_t)((img_size - off) < (uint64_t)chunk
		                          ? (img_size - off) : (uint64_t)chunk);
		ssize_t r = pread(src_fd, buf, to_read, (off_t)off);
		if (r <= 0) break;
		ssize_t w = pwrite(dst_fd, buf, (size_t)r, (off_t)off);
		if (w != r) {
			LastWriteError = RUFUS_ERROR(ERROR_WRITE_FAULT);
			ok = FALSE;
			break;
		}
		off += (uint64_t)r;
		UpdateProgressWithInfo(OP_FILE_COPY, MSG_261, off, img_size);
	}

	free(buf);
	close(src_fd);
	return ok;

out:
	free(buf);
	close(src_fd);
	ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED);
	return FALSE;
}

/* =========================================================================
 * InstallGrub2 — install GRUB2 boot files to the device/partition
 *
 * Calls grub-install (or grub2-install) with i386-pc target.  mount_path is
 * the already-mounted partition root (e.g. /tmp/rufus-mount-XXXXXX) where
 * GRUB files were extracted.  dev_path is the raw block device (e.g. /dev/sdb).
 * ======================================================================= */
BOOL InstallGrub2(const char *dev_path, const char *mount_path)
{
	if (!dev_path || !mount_path) return FALSE;

	/* Find grub-install binary */
	static const char * const candidates[] = {
		"/usr/bin/grub-install",
		"/usr/sbin/grub-install",
		"/usr/bin/grub2-install",
		"/usr/sbin/grub2-install",
		NULL
	};
	const char *grub_install = NULL;
	for (int i = 0; candidates[i]; i++) {
		if (access(candidates[i], X_OK) == 0) {
			grub_install = candidates[i];
			break;
		}
	}
	if (!grub_install) {
		uprintf("grub-install not found; skipping GRUB2 core install");
		return FALSE;
	}

	/* Build boot-directory path */
	char boot_dir[512];
	snprintf(boot_dir, sizeof(boot_dir), "%s/boot", mount_path);

	/* Construct and run grub-install */
	char cmd[1024];
	snprintf(cmd, sizeof(cmd),
		"%s --target=i386-pc --boot-directory=%s --removable --no-floppy %s",
		grub_install, boot_dir, dev_path);
	uprintf("Running: %s", cmd);
	int r = system(cmd);
	if (r != 0) {
		uprintf("grub-install failed with exit code %d", r);
		return FALSE;
	}
	return TRUE;
}

/* =========================================================================
 * FormatThread
 * ======================================================================= */

DWORD WINAPI FormatThread(void* param)
{
	DWORD DriveIndex = (DWORD)(uintptr_t)param;
	HANDLE hPhysicalDrive  = INVALID_HANDLE_VALUE;
	HANDLE hLogicalVolume  = INVALID_HANDLE_VALUE;
	char fs_name[32]       = "";
	char label[64]         = "";

	/* Validate drive index early */
	if ((DriveIndex < DRIVE_INDEX_MIN) || (DriveIndex > DRIVE_INDEX_MAX)) {
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		goto out;
	}

	/* ---------------------------------------------------------------
	 * Zero-drive mode: wipe the whole device and exit
	 * ------------------------------------------------------------- */
	if (zero_drive) {
		GetDrivePartitionData(DriveIndex, fs_name, sizeof(fs_name), TRUE);
		hPhysicalDrive = GetPhysicalHandle(DriveIndex, FALSE, TRUE, TRUE);
		if (hPhysicalDrive == INVALID_HANDLE_VALUE) {
			ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
			goto out;
		}
		format_linux_write_drive(hPhysicalDrive, TRUE);
		goto out;
	}

	/* ---------------------------------------------------------------
	 * Write-as-image mode: copy raw image to device and exit
	 * ------------------------------------------------------------- */
	if (write_as_image && boot_type == BT_IMAGE) {
		GetDrivePartitionData(DriveIndex, fs_name, sizeof(fs_name), TRUE);
		hPhysicalDrive = GetPhysicalHandle(DriveIndex, FALSE, TRUE, TRUE);
		if (hPhysicalDrive == INVALID_HANDLE_VALUE) {
			ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
			goto out;
		}
		format_linux_write_drive(hPhysicalDrive, FALSE);
		goto out;
	}

	/* ---------------------------------------------------------------
	 * Normal format path
	 * ------------------------------------------------------------- */

	PrintStatusInfo(FALSE, FALSE, 0, MSG_225);

	/* Get disk size/geometry (read-only) */
	GetDrivePartitionData(DriveIndex, fs_name, sizeof(fs_name), TRUE);
	if (SelectedDrive.DiskSize == 0) {
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		goto out;
	}

	/* Open physical drive for writing */
	hPhysicalDrive = GetPhysicalHandle(DriveIndex, FALSE, TRUE, TRUE);
	if (hPhysicalDrive == INVALID_HANDLE_VALUE) {
		ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
		goto out;
	}
	PrintStatusInfo(FALSE, FALSE, 0, MSG_226);

	/* Clear MBR/GPT areas */
	if (!format_linux_clear_mbr_gpt(hPhysicalDrive,
	                                 SelectedDrive.DiskSize,
	                                 SelectedDrive.SectorSize)) {
		ErrorStatus = RUFUS_ERROR(ERROR_PARTITION_FAILURE);
		goto out;
	}
	CHECK_FOR_USER_CANCEL;
	UpdateProgress(OP_ZERO_MBR, -1.0f);

	/* Initialize disk (zero sector 0) */
	if (!InitializeDisk(hPhysicalDrive)) {
		ErrorStatus = RUFUS_ERROR(ERROR_PARTITION_FAILURE);
		goto out;
	}

	/* Create partition table */
	PrintStatusInfo(FALSE, FALSE, 0, MSG_228);
	BOOL mbr_is_bootable = (partition_type == PARTITION_STYLE_MBR) &&
	                       (target_type == TT_UEFI ? FALSE : TRUE);
	if (!CreatePartition(hPhysicalDrive, partition_type, fs_type,
	                     mbr_is_bootable, 0)) {
		ErrorStatus = RUFUS_ERROR(ERROR_PARTITION_FAILURE);
		goto out;
	}
	UpdateProgress(OP_PARTITION, -1.0f);
	CHECK_FOR_USER_CANCEL;

	/* Refresh kernel's view of the partition table */
	RefreshDriveLayout(hPhysicalDrive);

	/* Re-read partition data so SelectedDrive.Partition[] is up to date */
	GetDrivePartitionData(DriveIndex, fs_name, sizeof(fs_name), TRUE);

	/* Main partition is always entry 0 in the simple single-partition case */
	partition_index[PI_MAIN] = 0;

	if (SelectedDrive.nPartitions == 0 && partition_type == PARTITION_STYLE_MBR) {
		/* Fallback: manually set the partition offset to LBA 2048 */
		SelectedDrive.Partition[0].Offset = 2048ULL * 512;
		SelectedDrive.Partition[0].Size   = SelectedDrive.DiskSize - SelectedDrive.Partition[0].Offset;
		SelectedDrive.nPartitions = 1;
	}
	uint64_t part_offset = SelectedDrive.Partition[partition_index[PI_MAIN]].Offset;

	CHECK_FOR_USER_CANCEL;

	/* Format the main partition */
	PrintStatusInfo(FALSE, FALSE, 0, MSG_229);
	/* Get label from UI (may be empty) */
	GetWindowTextA(hLabel, label, (int)sizeof(label));
	DWORD fmt_flags = FP_FORCE;
	if (quick_format && !IS_EXT(fs_type))
		fmt_flags |= FP_QUICK;
	if (!FormatPartition(DriveIndex, part_offset, 0, fs_type, label, fmt_flags)) {
		uprintf("Format error: %s", WindowsErrorString());
		if (!IS_ERROR(ErrorStatus))
			ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
		goto out;
	}
	CHECK_FOR_USER_CANCEL;

	/* Write MBR boot code */
	if (!format_linux_write_mbr(hPhysicalDrive)) {
		if (!IS_ERROR(ErrorStatus))
			ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
		goto out;
	}
	UpdateProgress(OP_FIX_MBR, -1.0f);

	/* Write partition boot record (PBR) */
	hLogicalVolume = GetLogicalHandle(DriveIndex, part_offset, FALSE, TRUE, FALSE);
	if (hLogicalVolume != INVALID_HANDLE_VALUE && hLogicalVolume != NULL) {
		if (!WritePBR(hLogicalVolume)) {
			if (!IS_ERROR(ErrorStatus))
				ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
			/* Non-fatal: continue */
		}
		safe_closehandle(hLogicalVolume);
	}
	CHECK_FOR_USER_CANCEL;

	/* Copy ISO files if in ISO boot mode */
	if (boot_type == BT_IMAGE && !write_as_image && image_path != NULL
	    && img_report.is_iso) {
		UpdateProgress(OP_FILE_COPY, 0.0f);
		char *mount_path = GetExtPartitionName(DriveIndex, part_offset);
		if (mount_path != NULL) {
			if (!ExtractISO(image_path, mount_path, FALSE)) {
				if (!IS_ERROR(ErrorStatus))
					ErrorStatus = RUFUS_ERROR(APPERR(ERROR_ISO_EXTRACT));
			}

			/* Install GRUB2 core.img for BIOS-boot GRUB2 images */
			if (!IS_ERROR(ErrorStatus) && img_report.has_grub2
			    && target_type == TT_BIOS && partition_type == PARTITION_STYLE_MBR) {
				char *dev_path = GetPhysicalName(DriveIndex);
				if (dev_path != NULL) {
					if (!InstallGrub2(dev_path, mount_path))
						uprintf("GRUB2 core install failed; BIOS boot may not work");
					free(dev_path);
				}
			}
			free(mount_path);
		}
	}
	CHECK_FOR_USER_CANCEL;

	/* Install Syslinux bootloader when applicable */
	if ( (boot_type == BT_SYSLINUX_V4) || (boot_type == BT_SYSLINUX_V6) ||
	     ((boot_type == BT_IMAGE) && (HAS_SYSLINUX(img_report) || HAS_REACTOS(img_report))) ) {
		if (!InstallSyslinux(DriveIndex, 0, fs_type)) {
			uprintf("Syslinux installation failed");
			if (!IS_ERROR(ErrorStatus))
				ErrorStatus = RUFUS_ERROR(ERROR_INSTALL_FAILURE);
		}
	}

	UpdateProgress(OP_FINALIZE, -1.0f);

out:
	safe_closehandle(hLogicalVolume);
	safe_closehandle(hPhysicalDrive);
	PostMessage(hMainDialog, UM_FORMAT_COMPLETED, (WPARAM)TRUE, 0);
	ExitThread(IS_ERROR(ErrorStatus) ? 1 : 0);
	return IS_ERROR(ErrorStatus) ? 1 : 0; /* unreachable, but silences -Wreturn-type */
}

