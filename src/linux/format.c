/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: format.c — drive formatting routines
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
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
#include <inttypes.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/limits.h>

#include "rufus.h"
#include "resource.h"
#include "compat/windowsx.h"
#include "bled/bled.h"
#include "localization.h"
#include "drive.h"
#include "format.h"
#include "format_linux.h"
#include "../common/label.h"
#include "badblocks.h"
#include "settings.h"
#include "verify.h"
#include "wue.h"
#include "dos.h"
#include "ms-sys/inc/file.h"
#include "ms-sys/inc/br.h"
#include "ms-sys/inc/fat32.h"
#include "ms-sys/inc/partition_info.h"
#include "../../res/grub/grub_version.h"
#include "drive_linux.h"
#include "vhd.h"

extern const char* FileSystemLabel[FS_MAX];
extern BOOL force_large_fat32, enable_ntfs_compression, lock_drive, zero_drive, fast_zeroing;
extern BOOL write_as_image, write_as_esp;
extern BOOL use_rufus_mbr;
extern BOOL quick_format;
extern BOOL enable_bad_blocks;
extern BOOL enable_verify_write;
extern int  nb_passes_sel;
extern char *image_path;
extern const char *md5sum_name[2];
extern void UpdateMD5Sum(const char *dest_dir, const char *md5sum_name_arg);

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
	if (FSType == FS_FAT16)
		return FormatFAT16(DriveIndex, PartitionOffset, UnitAllocationSize, Label, Flags);
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
	if (FSType == FS_UDF)
		return FormatUDF(DriveIndex, PartitionOffset, UnitAllocationSize, Label, Flags);
	/* ReFS not yet supported on Linux */
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
			/* Choose VBR based on boot type, matching Windows format.c logic */
			if (boot_type == BT_FREEDOS) {
				if (!write_fat_32_fd_br(fp, 0)) return FALSE;
			} else {
				if (!write_fat_32_br(fp, 0)) return FALSE;
			}
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
	case FS_FAT16:
		/* mkntfs / mkfs.exfat / mkfs.fat write their own boot sectors; no PBR step needed */
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
				uprintf_errno("WARNING: Could not clear the backup GPT area");
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
		/* KolibriOS: uses its own MBR but only on FAT volumes */
		if (boot_type == BT_IMAGE && HAS_KOLIBRIOS(img_report) && IS_FAT(fs_type)) {
			uprintf("Writing KolibriOS MBR");
			r = write_kolibrios_mbr(fp);
			break;
		}
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
		uprintf_errno("Could not open image '%s'", image_path);
		return FALSE;
	}

	/* Determine image size — use BLKGETSIZE64 for block devices (e.g. NBD) */
	struct stat st;
	if (fstat(src_fd, &st) != 0) {
		close(src_fd);
		ErrorStatus = RUFUS_ERROR(ERROR_READ_FAULT);
		return FALSE;
	}
	uint64_t img_size = 0;
	if (S_ISBLK(st.st_mode)) {
		if (ioctl(src_fd, BLKGETSIZE64, &img_size) != 0) {
			close(src_fd);
			ErrorStatus = RUFUS_ERROR(ERROR_READ_FAULT);
			return FALSE;
		}
	} else {
		img_size = (uint64_t)st.st_size;
	}

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
 * InstallGrub4DOS — copy grldr to the mounted partition root
 *
 * Looks for the Grub4DOS loader file at:
 *   <app_data_dir>/<FILES_DIR>/grub4dos-<GRUB4DOS_VERSION>/grldr
 * and copies it to <mount_dir>/grldr.
 *
 * Returns TRUE on success, FALSE if the source file is not found or the
 * copy fails (non-fatal: caller should log a warning and continue).
 * ======================================================================= */
BOOL InstallGrub4DOS(const char *mount_dir)
{
	if (!mount_dir) return FALSE;

	char src[MAX_PATH];
	char dst[MAX_PATH];

	/* Build source path: app_data_dir/Rufus/grub4dos-VERSION/grldr */
	if (snprintf(src, sizeof(src), "%s/" FILES_DIR "/grub4dos-%s/grldr",
	             app_data_dir, GRUB4DOS_VERSION) >= (int)sizeof(src)) {
		uprintf("InstallGrub4DOS: path too long");
		return FALSE;
	}

	/* Build destination path: mount_dir/grldr */
	if (snprintf(dst, sizeof(dst), "%s/grldr", mount_dir) >= (int)sizeof(dst)) {
		uprintf("InstallGrub4DOS: dest path too long");
		return FALSE;
	}

	/* Open source */
	int src_fd = open(src, O_RDONLY | O_CLOEXEC);
	if (src_fd < 0) {
		uprintf("InstallGrub4DOS: '%s' not found — download Grub4DOS first", src);
		return FALSE;
	}

	/* Get size */
	struct stat st;
	if (fstat(src_fd, &st) != 0 || st.st_size == 0) {
		close(src_fd);
		uprintf("InstallGrub4DOS: '%s' is empty or unreadable", src);
		return FALSE;
	}

	/* Open/create destination */
	int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (dst_fd < 0) {
		close(src_fd);
		uprintf_errno("InstallGrub4DOS: could not create '%s'", dst);
		return FALSE;
	}

	/* Copy */
	char buf[65536];
	BOOL ok = TRUE;
	ssize_t n;
	while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
		if (write(dst_fd, buf, (size_t)n) != n) {
			uprintf_errno("InstallGrub4DOS: write to '%s' failed", dst);
			ok = FALSE;
			break;
		}
	}

	close(src_fd);
	close(dst_fd);

	if (ok)
		uprintf("Installing: %s/grldr (Grub4DOS loader)", mount_dir);
	else
		unlink(dst);

	return ok;
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
		char *vhd_nbd_path = NULL;
		BOOL is_vhd_image = (img_report.compression_type == IMG_COMPRESSION_VHD ||
		                     img_report.compression_type == IMG_COMPRESSION_VHDX);

		/* For VHD/VHDX images, mount them first so we write the virtual
		 * disk contents rather than the raw container bytes. */
		if (is_vhd_image && image_path != NULL) {
			uint64_t vhd_disk_size = 0;
			vhd_nbd_path = VhdMountImageAndGetSize(image_path, &vhd_disk_size);
			if (vhd_nbd_path == NULL) {
				uprintf("Failed to mount VHD/VHDX image '%s'", image_path);
				ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
				goto out;
			}
			uprintf("VHD/VHDX mounted at %s (%" PRIu64 " bytes)", vhd_nbd_path, vhd_disk_size);
		}

		GetDrivePartitionData(DriveIndex, fs_name, sizeof(fs_name), TRUE);
		hPhysicalDrive = GetPhysicalHandle(DriveIndex, FALSE, TRUE, TRUE);
		if (hPhysicalDrive == INVALID_HANDLE_VALUE) {
			ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
			goto out;
		}

		/* Temporarily redirect image_path to NBD device for VHD images */
		const char *orig_image_path = image_path;
		if (is_vhd_image && vhd_nbd_path != NULL)
			image_path = vhd_nbd_path;

		if (!format_linux_write_drive(hPhysicalDrive, FALSE)) {
			image_path = orig_image_path;
			goto out;
		}

		/* Restore image_path before verify/cleanup */
		image_path = orig_image_path;

		/* Skip write-verify for VHD images (source is now unmounted) */
		if (!is_vhd_image && enable_verify_write && image_path) {
			struct stat _vst;
			uint64_t img_sz = (stat(image_path, &_vst) == 0) ? (uint64_t)_vst.st_size : 0;
			if (img_sz > 0) {
				uprintf("Starting write-verify pass (%llu bytes)...",
				        (unsigned long long)img_sz);
				UpdateProgress(OP_VERIFY, 0.0f);
				int dev_fd = (int)(intptr_t)hPhysicalDrive;
				if (!verify_write_pass(image_path, dev_fd, img_sz)) {
					if (!IS_ERROR(ErrorStatus))
						ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
					goto out;
				}
				uprintf("Write-verify pass completed successfully.");
			}
		}
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

	/* -----------------------------------------------------------
	 * Optional bad-blocks check: runs between ClearMBRGPT and
	 * CreatePartition so a destructive test sees the full disk.
	 * --------------------------------------------------------- */
	if (enable_bad_blocks) {
		int r = IDOK;
		int sel    = nb_passes_sel;
		int passes = (sel >= 2) ? 4 : (sel + 1);
		int ft     = sel;   /* flash_type index */
		badblocks_report report = { 0 };
		do {
			char   logpath[PATH_MAX];
			FILE  *log_fd = NULL;
			time_t now = time(NULL);
			struct tm lt_buf, *lt = localtime_r(&now, &lt_buf);
			snprintf(logpath, sizeof(logpath),
			         "/tmp/rufus_%04d%02d%02d_%02d%02d%02d.log",
			         lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
			         lt->tm_hour, lt->tm_min, lt->tm_sec);
			log_fd = fopen(logpath, "w+");
			if (!log_fd) {
				uprintf("Error: Could not create log file for bad blocks check");
				goto out;
			}
			fprintf(log_fd,
			        APPLICATION_NAME " bad blocks check started on: "
			        "%04d-%02d-%02d %02d:%02d:%02d\n",
			        lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
			        lt->tm_hour, lt->tm_min, lt->tm_sec);
			fflush(log_fd);

			if (!BadBlocks(hPhysicalDrive, SelectedDrive.DiskSize,
			               passes, ft, &report, log_fd)) {
				uprintf("Bad blocks: Check failed.");
				if (!IS_ERROR(ErrorStatus))
					ErrorStatus = RUFUS_ERROR(APPERR(ERROR_BADBLOCKS_FAILURE));
				fclose(log_fd);
				unlink(logpath);
				goto out;
			}
			uprintf("Bad Blocks: Check completed, %d bad block%s found."
			        " (%d/%d/%d errors)",
			        report.bb_count, (report.bb_count == 1) ? "" : "s",
			        report.num_read_errors, report.num_write_errors,
			        report.num_corruption_errors);
			r = IDOK;
			if (report.bb_count) {
				char *bb_msg = lmprintf(MSG_011, report.bb_count,
				                        report.num_read_errors,
				                        report.num_write_errors,
				                        report.num_corruption_errors);
				fprintf(log_fd, "%s", bb_msg);
				fclose(log_fd);
				r = Notification(MB_ABORTRETRYIGNORE | MB_ICONWARNING,
				                 lmprintf(MSG_010),
				                 lmprintf(MSG_012, bb_msg, logpath));
			} else {
				fclose(log_fd);
				unlink(logpath);
			}
		} while (r == IDRETRY);

		if (r == IDABORT) {
			ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED);
			goto out;
		}

		/* After a destructive bad-blocks pass, zero MBR/GPT again */
		if (!format_linux_clear_mbr_gpt(hPhysicalDrive,
		                                SelectedDrive.DiskSize,
		                                SelectedDrive.SectorSize)) {
			uprintf("Could not zero MBR/GPT after bad blocks check");
			if (!IS_ERROR(ErrorStatus))
				ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
			goto out;
		}
		if (!InitializeDisk(hPhysicalDrive)) {
			ErrorStatus = RUFUS_ERROR(ERROR_PARTITION_FAILURE);
			goto out;
		}
	}

	/* Create partition table */
	PrintStatusInfo(FALSE, FALSE, 0, MSG_228);
	BOOL mbr_is_bootable = (partition_type == PARTITION_STYLE_MBR) &&
	                       (target_type == TT_UEFI ? FALSE : TRUE);
	uint8_t extra_partitions = 0;
	/* Detect Windows To Go: needs BT_IMAGE + IMOP_WINTOGO + HAS_WINTOGO + combo selection */
	BOOL windows_to_go = (image_options & IMOP_WINTOGO) && (boot_type == BT_IMAGE) &&
	    HAS_WINTOGO(img_report) &&
	    (ComboBox_GetCurItemData(hImageOption) == IMOP_WIN_TO_GO);
	if (boot_type == BT_IMAGE && !write_as_image &&
	    HAS_PERSISTENCE(img_report) && persistence_size > 0)
		extra_partitions |= XP_PERSISTENCE;
	/* For Windows To Go on UEFI/GPT, add ESP + MSR before the main partition */
	if (windows_to_go && target_type == TT_UEFI && partition_type == PARTITION_STYLE_GPT)
		extra_partitions |= XP_ESP | XP_MSR;
	else if (!write_as_image &&
	    uefi_ntfs_needs_extra_partition(boot_type, fs_type, target_type, &img_report))
		extra_partitions |= XP_UEFI_NTFS;
	if (!CreatePartition(hPhysicalDrive, partition_type, fs_type,
	                     mbr_is_bootable, extra_partitions)) {
		ErrorStatus = RUFUS_ERROR(ERROR_PARTITION_FAILURE);
		goto out;
	}
	UpdateProgress(OP_PARTITION, -1.0f);
	CHECK_FOR_USER_CANCEL;

	/* Refresh kernel's view of the partition table */
	RefreshDriveLayout(hPhysicalDrive);

	/* Wait for the partition device node to appear (needed for loopback
	 * devices where udev creates /dev/loopNp1 asynchronously). */
	uint64_t main_part_off = SelectedDrive.Partition[partition_index[PI_MAIN]].Offset;
	if (main_part_off == 0) {
		uint32_t sec = SelectedDrive.SectorSize ? SelectedDrive.SectorSize : 512;
		main_part_off = 2048ULL * sec;
	}
	WaitForLogical(DriveIndex, main_part_off);

	/* Re-read partition data so SelectedDrive.Partition[] is up to date */
	GetDrivePartitionData(DriveIndex, fs_name, sizeof(fs_name), TRUE);

	/* Re-locate main partition by its known offset in the (possibly re-ordered)
	 * partition array returned by GetDrivePartitionData.  This is necessary
	 * for multi-partition layouts (WTG: ESP→MSR→main) where the main partition
	 * is not always at index 0.  Fall back to index 0 only if not found. */
	partition_index[PI_MAIN] = 0;
	for (int _pi = 0; _pi < (int)SelectedDrive.nPartitions; _pi++) {
		if (SelectedDrive.Partition[_pi].Offset == main_part_off) {
			partition_index[PI_MAIN] = _pi;
			break;
		}
	}

	if (SelectedDrive.nPartitions == 0 && partition_type == PARTITION_STYLE_MBR) {
		/* Fallback: manually set the partition offset to LBA 2048 */
		uint32_t sec = SelectedDrive.SectorSize ? SelectedDrive.SectorSize : 512;
		uint32_t pers_sects  = (extra_partitions & XP_PERSISTENCE) ?
		                       (uint32_t)(persistence_size / sec) : 0;
		uint32_t uefi_sects  = (extra_partitions & XP_UEFI_NTFS) ?
		                       (uint32_t)(1048576ULL / sec) : 0;
		uint64_t total_sects = (uint64_t)SelectedDrive.DiskSize / sec;
		uint32_t main_sects  = (uint32_t)(total_sects - 2048 - pers_sects - uefi_sects);
		SelectedDrive.Partition[0].Offset = 2048ULL * sec;
		SelectedDrive.Partition[0].Size   = (uint64_t)main_sects * sec;
		SelectedDrive.nPartitions = 1;
		int next_slot = 1;
		if (extra_partitions & XP_PERSISTENCE) {
			SelectedDrive.Partition[next_slot].Offset = SelectedDrive.Partition[0].Offset +
			                                            SelectedDrive.Partition[0].Size;
			SelectedDrive.Partition[next_slot].Size   = persistence_size;
			SelectedDrive.nPartitions++;
			next_slot++;
		}
		if (extra_partitions & XP_UEFI_NTFS) {
			SelectedDrive.Partition[PI_UEFI_NTFS].Offset = (total_sects - uefi_sects) * sec;
			SelectedDrive.Partition[PI_UEFI_NTFS].Size   = (uint64_t)uefi_sects * sec;
			SelectedDrive.nPartitions++;
		}
	}

	/* If persistence partition was created, record its index */
	if ((extra_partitions & XP_PERSISTENCE) && SelectedDrive.nPartitions >= 2)
		partition_index[PI_CASPER] = 1;
	uint64_t part_offset = SelectedDrive.Partition[partition_index[PI_MAIN]].Offset;

	CHECK_FOR_USER_CANCEL;

	/* Format the main partition */
	PrintStatusInfo(FALSE, FALSE, 0, MSG_229);
	/* Get label from UI (may be empty) */
	GetWindowTextA(hLabel, label, (int)sizeof(label));
	/* Sanitize label for the target filesystem */
	ToValidLabel(label, (fs_type == FS_FAT16) || (fs_type == FS_FAT32) || (fs_type == FS_EXFAT));
	DWORD fmt_flags = FP_FORCE;
	if (quick_format && !IS_EXT(fs_type))
		fmt_flags |= FP_QUICK;
	if ((fs_type == FS_NTFS) && enable_ntfs_compression)
		fmt_flags |= FP_COMPRESSION;
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
	if (boot_type == BT_IMAGE && !write_as_image && image_path != NULL && windows_to_go) {
		/* Windows To Go: mount the target NTFS partition and apply the WIM */
		UpdateProgress(OP_FILE_COPY, 0.0f);
		PrintInfo(0, MSG_268);
		char *wtg_mount = AltMountVolume(DriveIndex, part_offset, FALSE);
		if (wtg_mount != NULL) {
			if (!SetupWinToGo(DriveIndex, wtg_mount, (extra_partitions & XP_ESP) != 0)) {
				if (!IS_ERROR(ErrorStatus))
					ErrorStatus = RUFUS_ERROR(APPERR(ERROR_ISO_EXTRACT));
			}
			if (!IS_ERROR(ErrorStatus) && unattend_xml_path != NULL) {
				wue_set_mount_path(wtg_mount);
				if (!ApplyWindowsCustomization(0, unattend_xml_flags | UNATTEND_WINDOWS_TO_GO))
					uprintf("WARNING: Windows customisation could not be applied to WTG drive");
				wue_set_mount_path(NULL);
			}
			AltUnmountVolume(wtg_mount, FALSE);
			free(wtg_mount);
		} else {
			uprintf("Windows To Go: failed to mount partition at offset 0x%" PRIx64, part_offset);
			if (!IS_ERROR(ErrorStatus))
				ErrorStatus = RUFUS_ERROR(APPERR(ERROR_ISO_EXTRACT));
		}
		if (IS_ERROR(ErrorStatus)) goto out;
	}

	if (boot_type == BT_IMAGE && !write_as_image && image_path != NULL
	    && img_report.is_iso) {
		UpdateProgress(OP_FILE_COPY, 0.0f);
		char *mount_path = GetExtPartitionName(DriveIndex, part_offset);
		if (mount_path != NULL) {
			if (!ExtractISO(image_path, mount_path, FALSE)) {
				if (!IS_ERROR(ErrorStatus))
					ErrorStatus = RUFUS_ERROR(APPERR(ERROR_ISO_EXTRACT));
			}

			/* Apply Windows User Experience customisation (unattend.xml) if set */
			if (!IS_ERROR(ErrorStatus) && unattend_xml_path != NULL) {
				wue_set_mount_path(mount_path);
				if (!ApplyWindowsCustomization(0, unattend_xml_flags))
					uprintf("WARNING: Windows customization could not be applied");
				wue_set_mount_path(NULL);
				free(unattend_xml_path);
				unattend_xml_path = NULL;
			}

			/* Apply WinPE fixup for BIOS-boot WinPE images */
			if (!IS_ERROR(ErrorStatus) && (target_type == TT_BIOS) && HAS_WINPE(img_report)) {
				wue_set_mount_path(mount_path);
				if (!SetupWinPE(0))
					ErrorStatus = RUFUS_ERROR(APPERR(ERROR_CANT_PATCH));
				wue_set_mount_path(NULL);
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

			/* For Grub4DOS images, grldr should have been extracted from the ISO.
			 * If not (e.g. the ISO only had grldr.mbr), try a fresh install from cache. */
			if (!IS_ERROR(ErrorStatus) && img_report.has_grub4dos) {
				char grldr_check[MAX_PATH];
				snprintf(grldr_check, sizeof(grldr_check), "%s/grldr", mount_path);
				struct stat st_check;
				if (stat(grldr_check, &st_check) != 0) {
					if (!InstallGrub4DOS(mount_path))
						uprintf("Grub4DOS grldr not found in ISO and not in cache; BIOS boot may not work");
				}
			}

			/* KolibriOS: install the USB loader from the ISO */
			if (!IS_ERROR(ErrorStatus) && HAS_KOLIBRIOS(img_report)) {
				char kolibri_dst[MAX_PATH];
				snprintf(kolibri_dst, sizeof(kolibri_dst), "%s/MTLD_F32", mount_path);
				uprintf("Installing: %s (KolibriOS loader)", kolibri_dst);
				if (ExtractISOFile(image_path, "HD_Load/USB_Boot/MTLD_F32",
				                   kolibri_dst, 0) == 0)
					uprintf("WARNING: Loader installation failed - KolibriOS will not boot!");
			}

			/* Update MD5 sums for any modified files */
			if (!IS_ERROR(ErrorStatus) && !windows_to_go)
				UpdateMD5Sum(mount_path,
				             md5sum_name[img_report.has_md5sum ? img_report.has_md5sum - 1 : 0]);

			free(mount_path);
		}
	}
	CHECK_FOR_USER_CANCEL;

	/* For standalone BT_GRUB4DOS, mount the partition and install grldr */
	if (boot_type == BT_GRUB4DOS) {
		UpdateProgress(OP_FILE_COPY, 0.0f);
		char *mount_dir = AltMountVolume(DriveIndex, part_offset, FALSE);
		if (mount_dir != NULL) {
			if (!InstallGrub4DOS(mount_dir))
				uprintf("WARNING: Grub4DOS grldr not installed; BIOS boot will not work");
			AltUnmountVolume(mount_dir, FALSE);
			free(mount_dir);
		} else {
			uprintf("WARNING: Could not mount partition for Grub4DOS grldr installation");
		}
	}
	CHECK_FOR_USER_CANCEL;

	/* Extract DOS boot files for FreeDOS / MS-DOS boot types */
	if ((boot_type == BT_FREEDOS) || (boot_type == BT_MSDOS)) {
		UpdateProgress(OP_FILE_COPY, -1.0f);
		char *mount_dir = AltMountVolume(DriveIndex, part_offset, FALSE);
		if (mount_dir != NULL) {
			if (!ExtractDOS(mount_dir)) {
				uprintf("ERROR: Could not extract DOS boot files");
				if (!IS_ERROR(ErrorStatus))
					ErrorStatus = RUFUS_ERROR(ERROR_CANNOT_COPY);
			}
			AltUnmountVolume(mount_dir, FALSE);
			free(mount_dir);
		} else {
			uprintf("WARNING: Could not mount partition for DOS extraction");
			if (!IS_ERROR(ErrorStatus))
				ErrorStatus = RUFUS_ERROR(ERROR_CANNOT_COPY);
		}
		if (IS_ERROR(ErrorStatus))
			goto out;
	}
	CHECK_FOR_USER_CANCEL;

	/* Format persistence partition if one was created */
	if (extra_partitions & XP_PERSISTENCE) {
		uint64_t pers_offset = SelectedDrive.Partition[partition_index[PI_CASPER]].Offset;
		int ext_version = ReadSetting32(SETTING_USE_EXT_VERSION);
		if (ext_version < 2 || ext_version > 4) ext_version = 3;
		int pers_fs = FS_EXT2 + (ext_version - 2);
		const char *pers_label = img_report.uses_casper ? "casper-rw" : "persistence";
		DWORD pers_flags = FP_FORCE;
		if (!img_report.uses_casper)
			pers_flags |= FP_CREATE_PERSISTENCE_CONF;
		if (!FormatPartition(DriveIndex, pers_offset, 0, pers_fs, pers_label, pers_flags))
			uprintf("WARNING: Persistence partition format failed: %s", WindowsErrorString());
	}

	/* Write UEFI:NTFS bridge partition if one was allocated */
	if (extra_partitions & XP_UEFI_NTFS) {
		size_t   uefi_sz   = 0;
		uint8_t *uefi_data = load_uefi_ntfs_data(&uefi_sz);
		if (uefi_data == NULL) {
			uprintf("Could not load uefi-ntfs.img; UEFI:NTFS boot bridge unavailable");
		} else {
			uint64_t uefi_off = SelectedDrive.Partition[PI_UEFI_NTFS].Offset;
			if (!write_uefi_ntfs_partition(hPhysicalDrive, uefi_off, uefi_data, uefi_sz))
				uprintf("WARNING: Failed to write UEFI:NTFS partition: %s",
				        WindowsErrorString());
			free(uefi_data);
		}
	}

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
	VhdUnmountImage();
	safe_closehandle(hLogicalVolume);
	safe_closehandle(hPhysicalDrive);
	PostMessage(hMainDialog, UM_FORMAT_COMPLETED, (WPARAM)TRUE, 0);
	ExitThread(IS_ERROR(ErrorStatus) ? 1 : 0);
	return IS_ERROR(ErrorStatus) ? 1 : 0; /* unreachable, but silences -Wreturn-type */
}

