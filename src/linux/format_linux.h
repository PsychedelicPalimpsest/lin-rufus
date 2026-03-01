/*
 * format_linux.h — Linux-specific format helpers exposed for testing
 *
 * These functions are implemented in linux/format.c as non-static
 * helpers so that tests can call them directly.
 */
#pragma once

#include <stdint.h>
#include "windows.h"

/*
 * format_linux_clear_mbr_gpt - zero the MBR/GPT areas of a drive.
 *
 * Zeroes MAX_SECTORS_TO_CLEAR sectors at the beginning of the drive and
 * MAX_SECTORS_TO_CLEAR/8 sectors at the end.
 */
BOOL format_linux_clear_mbr_gpt(HANDLE hDrive, LONGLONG DiskSize, DWORD SectorSize);

/*
 * format_linux_write_mbr - write the appropriate MBR boot code.
 *
 * Selects the MBR type based on the global boot_type, target_type, and
 * img_report, then writes only the boot code bytes (0–445) plus the
 * 0x55AA signature — partition table entries (bytes 446–509) are untouched.
 */
BOOL format_linux_write_mbr(HANDLE hDrive);

/*
 * format_linux_write_drive - raw image write or zero-drive.
 *
 * If bZeroDrive is TRUE, writes zeros across the entire drive (SelectedDrive.DiskSize).
 * If bZeroDrive is FALSE, copies from global image_path to hDrive.
 */
BOOL format_linux_write_drive(HANDLE hDrive, BOOL bZeroDrive);

/*
 * InstallGrub4DOS - copy the Grub4DOS loader (grldr) to the mounted partition.
 *
 * Looks for grldr in the local Rufus data directory:
 *   <app_data_dir>/Rufus/grub4dos-<GRUB4DOS_VERSION>/grldr
 * and copies it to <mount_dir>/grldr.
 *
 * Returns TRUE on success, FALSE if the file is not in the cache or the
 * copy fails (non-fatal — caller should log a warning).
 */
BOOL InstallGrub4DOS(const char *mount_dir);

/*
 * InstallGrub2 - install GRUB2 bootloader to the device.
 *
 * Calls grub-install (i386-pc target) with --boot-directory=<mount_path>/boot.
 * dev_path is the raw block device (e.g. /dev/sdb).
 * mount_path is the root of the mounted partition.
 * Returns FALSE if grub-install is not found or fails.
 */
BOOL InstallGrub2(const char *dev_path, const char *mount_path);

/*
 * WritePBR_fs - write partition boot record for the given filesystem type.
 *
 * Like WritePBR() but accepts the filesystem type as an explicit parameter
 * instead of relying on the internal static variable.  Exposed for testing.
 */
BOOL WritePBR_fs(HANDLE hLogicalVolume, int fs_type);

/*
 * FormatNTFS - format a partition as NTFS using mkntfs.
 *
 * Locates mkntfs at runtime, resolves the partition path, and calls it via
 * RunCommandWithProgress().  Returns FALSE if mkntfs is not installed.
 */
BOOL FormatNTFS(DWORD DriveIndex, uint64_t PartitionOffset,
                DWORD UnitAllocationSize, LPCSTR Label, DWORD Flags);

/*
 * FormatExFAT - format a partition as exFAT using mkfs.exfat (or mkexfatfs).
 *
 * Returns FALSE if neither mkfs.exfat nor mkexfatfs is installed.
 */
BOOL FormatExFAT(DWORD DriveIndex, uint64_t PartitionOffset,
                 DWORD UnitAllocationSize, LPCSTR Label, DWORD Flags);

/*
 * format_ntfs_build_cmd - build a mkntfs command string (testable helper).
 *
 *   tool         - absolute path to mkntfs binary
 *   part_path    - partition device/file path
 *   cluster_size - bytes per cluster (0 = let mkntfs choose)
 *   label        - volume label (NULL or empty = omit -L)
 *   quick        - if TRUE, add -Q (quick format)
 *   cmd_buf      - output buffer
 *   cmd_buf_len  - size of cmd_buf
 *
 * Returns TRUE on success, FALSE on NULL argument or buffer overflow.
 */
BOOL format_ntfs_build_cmd(const char *tool, const char *part_path,
                            DWORD cluster_size, const char *label, BOOL quick,
                            BOOL force,
                            char *cmd_buf, size_t cmd_buf_len);

/*
 * format_exfat_build_cmd - build a mkfs.exfat command string (testable helper).
 *
 *   tool         - absolute path to mkfs.exfat (or mkexfatfs) binary
 *   part_path    - partition device/file path
 *   cluster_size - bytes per cluster (0 = let tool choose)
 *   label        - volume label (NULL or empty = omit -n)
 *   cmd_buf      - output buffer
 *   cmd_buf_len  - size of cmd_buf
 *
 * Returns TRUE on success, FALSE on NULL argument or buffer overflow.
 */
BOOL format_exfat_build_cmd(const char *tool, const char *part_path,
                             DWORD cluster_size, const char *label,
                             char *cmd_buf, size_t cmd_buf_len);
