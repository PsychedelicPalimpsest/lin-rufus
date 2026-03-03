/*
 * test_real_device_linux.c — CLI end-to-end tests against a real block device.
 *
 * All tests require:
 *   - Root privileges (SKIP_NOT_ROOT)
 *   - RUFUS_TEST_DEVICE env var set to a block device (SKIP_NO_TEST_DEVICE)
 *
 * WARNING: This test is DESTRUCTIVE — it will wipe all data on the target device.
 *
 * Usage:
 *   sudo RUFUS_TEST_DEVICE=/dev/sdX ./test_real_device_linux
 *
 * Tests:
 *   real_device_fat32     — cli_run() FAT32+MBR; verifies MBR 0x55AA + FAT32 OEM ID
 *   real_device_freedos   — cli_run() BT_FREEDOS; verifies MBR + KERNEL.SYS present
 *   real_device_ntfs      — cli_run() NTFS+MBR; verifies MBR 0x55AA + NTFS OEM ID
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <pthread.h>

#include "framework.h"

/* ---- compat + rufus headers ---- */
#include "windows.h"
#include "commctrl.h"
#include "rufus.h"
#include "drive.h"
#include "format.h"
#include "dos.h"
#include "resource.h"
#include "localization.h"
#include "../src/linux/cli.h"

/* ================================================================
 * Required globals
 * ================================================================ */

extern char              app_dir[MAX_PATH];
extern RUFUS_DRIVE       rufus_drive[MAX_DRIVES];
extern RUFUS_DRIVE_INFO  SelectedDrive;
extern int               partition_index[PI_MAX];
extern DWORD             ErrorStatus;
extern DWORD             LastWriteError;
extern BOOL              quick_format;
extern BOOL              write_as_image;
extern BOOL              write_as_esp;
extern BOOL              force_large_fat32;
extern BOOL              use_rufus_mbr;
extern BOOL              mbr_selected;
extern int               boot_type;
extern int               partition_type;
extern int               fs_type;
extern int               target_type;
extern char             *image_path;
extern RUFUS_IMG_REPORT  img_report;
extern DWORD             zero_drive;

/* ================================================================
 * Skip macros
 * ================================================================ */

#define SKIP_NOT_ROOT() do { \
	if (geteuid() != 0) { \
		printf("SKIP: requires root\n"); \
		return; \
	} \
} while (0)

#define SKIP_NO_TEST_DEVICE() do { \
	const char *_dev = getenv("RUFUS_TEST_DEVICE"); \
	if (!_dev || _dev[0] == '\0') { \
		printf("SKIP: RUFUS_TEST_DEVICE not set\n"); \
		return; \
	} \
} while (0)

/* ================================================================
 * Helpers
 * ================================================================ */

/* Get the test device path from env.  Caller must check for NULL. */
static const char *test_device(void)
{
	return getenv("RUFUS_TEST_DEVICE");
}

/* Build partition device path.
 * NVMe style: /dev/nvme0n2  → /dev/nvme0n2p1  (ends in digit)
 * SCSI style: /dev/sdb      → /dev/sdb1        (ends in alpha)
 */
static void partition_path(const char *dev, char *buf, size_t bufsz)
{
	size_t len = strlen(dev);
	if (len > 0 && isdigit((unsigned char)dev[len - 1]))
		snprintf(buf, bufsz, "%sp1", dev);
	else
		snprintf(buf, bufsz, "%s1", dev);
}

/* Read n bytes from block device at given byte offset.
 * Issues sync() first to flush all kernel write buffers so that writes
 * to a partition device (e.g. /dev/nvme0n2p1) are visible when reading
 * through the parent physical device (e.g. /dev/nvme0n2). */
static int dev_read_at(const char *dev, off_t off, void *buf, size_t n)
{
	sync(); /* flush pending writes before reading */
	int fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -1;
	ssize_t r = pread(fd, buf, n, off);
	close(fd);
	return (r == (ssize_t)n) ? 0 : -1;
}

/* Wait for partition device node to appear (up to ~3 seconds). */
static BOOL wait_for_partition(const char *part_dev)
{
	for (int i = 0; i < 30; i++) {
		struct stat st;
		if (stat(part_dev, &st) == 0 && S_ISBLK(st.st_mode))
			return TRUE;
		/* Attempt to re-read partition table */
		if (i % 5 == 0) {
			char cmd[256];
			snprintf(cmd, sizeof(cmd),
			         "partprobe %s 2>/dev/null || partx -u %s 2>/dev/null",
			         test_device(), test_device());
			system(cmd);
		}
		usleep(100000); /* 100 ms */
	}
	return FALSE;
}

/* Set up app_dir so Rufus can find resource files (FreeDOS image, etc.) */
static void set_app_dir_to_project_root(void)
{
	char candidate[MAX_PATH];
	snprintf(candidate, sizeof(candidate), "%sres/freedos/COMMAND.COM", app_dir);
	if (access(candidate, F_OK) == 0)
		return;
	snprintf(candidate, sizeof(candidate), "%s../res/freedos/COMMAND.COM", app_dir);
	if (access(candidate, F_OK) == 0) {
		char parent[MAX_PATH];
		snprintf(parent, sizeof(parent), "%s../", app_dir);
		strncpy(app_dir, parent, sizeof(app_dir) - 1);
		app_dir[sizeof(app_dir) - 1] = '\0';
	}
}

/* Reset format-relevant globals to a clean state */
static void reset_globals(void)
{
	boot_type        = BT_NON_BOOTABLE;
	partition_type   = PARTITION_STYLE_MBR;
	fs_type          = FS_FAT32;
	target_type      = TT_BIOS;
	write_as_image   = FALSE;
	write_as_esp     = FALSE;
	zero_drive       = FALSE;
	image_path       = NULL;
	ErrorStatus      = 0;
	LastWriteError   = 0;
	img_report       = (RUFUS_IMG_REPORT){ 0 };
	use_rufus_mbr    = TRUE;
}

/* ================================================================
 * Tests
 * ================================================================ */

/*
 * real_device_fat32  (ROOT + RUFUS_TEST_DEVICE required)
 *
 * Format the target device as FAT32 + MBR via cli_run().
 * Verify:
 *   1. cli_run() returns 0
 *   2. MBR boot signature 0x55AA at bytes 510–511
 *   3. FAT32 OEM ID "FAT32   " at partition offset + 3
 */
TEST(real_device_fat32)
{
	SKIP_NOT_ROOT();
	SKIP_NO_TEST_DEVICE();
	set_app_dir_to_project_root();
	reset_globals();

	const char *dev = test_device();

	cli_options_t opts;
	cli_options_init(&opts);
	strncpy(opts.device, dev, sizeof(opts.device) - 1);
	opts.fs          = FS_FAT32;
	opts.part_scheme = PARTITION_STYLE_MBR;
	opts.target      = TT_BIOS;
	opts.quick       = 1;
	opts.no_prompt   = 1;

	memset(partition_index, 0, sizeof(partition_index));
	ErrorStatus = 0;

	int rc = cli_run(&opts);

	/* Check MBR signature (physical device) */
	uint8_t mbr_sig[2] = { 0, 0 };
	dev_read_at(dev, 510, mbr_sig, 2);

	/* Check FAT32 type string at VBR offset 0x52.
	 * Read from the PARTITION device to avoid cross-device page cache staleness. */
	char part_dev_fat32[256];
	partition_path(dev, part_dev_fat32, sizeof(part_dev_fat32));
	uint8_t oem[8] = { 0 };
	dev_read_at(part_dev_fat32, 0x52, oem, 8);

	CHECK_MSG(rc == 0, "cli_run FAT32 must succeed");
	CHECK_MSG(mbr_sig[0] == 0x55 && mbr_sig[1] == 0xAA,
	          "MBR must have 0x55AA after FAT32 format");
	CHECK_MSG(memcmp(oem, "FAT32   ", 8) == 0,
	          "FAT32 type string 'FAT32   ' must be present at VBR offset 0x52");
}

/*
 * real_device_freedos  (ROOT + RUFUS_TEST_DEVICE required)
 *
 * Format the target device as FreeDOS via cli_run().
 * Verify:
 *   1. cli_run() returns 0
 *   2. MBR boot signature 0x55AA at bytes 510–511
 *   3. KERNEL.SYS present on the FAT32 partition
 */
TEST(real_device_freedos)
{
	SKIP_NOT_ROOT();
	SKIP_NO_TEST_DEVICE();
	set_app_dir_to_project_root();
	reset_globals();

	const char *dev = test_device();

	cli_options_t opts;
	cli_options_init(&opts);
	strncpy(opts.device, dev, sizeof(opts.device) - 1);
	opts.fs          = FS_FAT32;
	opts.part_scheme = PARTITION_STYLE_MBR;
	opts.target      = TT_BIOS;
	opts.boot_type   = BT_FREEDOS;
	opts.quick       = 1;
	opts.no_prompt   = 1;

	memset(partition_index, 0, sizeof(partition_index));
	ErrorStatus = 0;

	int rc = cli_run(&opts);

	/* Check MBR signature */
	uint8_t mbr_sig[2] = { 0, 0 };
	dev_read_at(dev, 510, mbr_sig, 2);

	/* Mount partition to check for KERNEL.SYS */
	BOOL has_kernel = FALSE;
	if (rc == 0) {
		char part_dev[256];
		partition_path(dev, part_dev, sizeof(part_dev));

		/* Wait for partition device node */
		BOOL has_part_node = wait_for_partition(part_dev);

		char mnt_tmpl[] = "/tmp/rufus_real_mnt_XXXXXX";
		char *mnt = mkdtemp(mnt_tmpl);
		if (mnt) {
			int mnt_rc = -1;

			if (has_part_node) {
				char mount_cmd[512];
				snprintf(mount_cmd, sizeof(mount_cmd),
				         "mount %s %s 2>/dev/null", part_dev, mnt);
				mnt_rc = system(mount_cmd);
			}

			if (mnt_rc != 0) {
				/* Fallback: mount via offset */
				char mount_cmd[512];
				snprintf(mount_cmd, sizeof(mount_cmd),
				         "mount -o offset=%llu %s %s 2>/dev/null",
				         (unsigned long long)(2048ULL * 512), dev, mnt);
				mnt_rc = system(mount_cmd);
			}

			if (mnt_rc == 0) {
				char path[512];
				snprintf(path, sizeof(path), "%s/KERNEL.SYS", mnt);
				has_kernel = (access(path, F_OK) == 0);
				if (!has_kernel) {
					snprintf(path, sizeof(path), "%s/kernel.sys", mnt);
					has_kernel = (access(path, F_OK) == 0);
				}
				char umount_cmd[256];
				snprintf(umount_cmd, sizeof(umount_cmd),
				         "umount %s 2>/dev/null", mnt);
				system(umount_cmd);
			}
			rmdir(mnt);
		}
	}

	CHECK_MSG(rc == 0, "cli_run FreeDOS must succeed");
	CHECK_MSG(mbr_sig[0] == 0x55 && mbr_sig[1] == 0xAA,
	          "MBR must have 0x55AA after FreeDOS format");
	CHECK_MSG(has_kernel, "KERNEL.SYS must be present after FreeDOS format");
}

/*
 * real_device_ntfs  (ROOT + RUFUS_TEST_DEVICE required)
 *
 * Format the target device as NTFS + MBR via cli_run().
 * Verify:
 *   1. cli_run() returns 0
 *   2. MBR boot signature 0x55AA at bytes 510–511
 *   3. NTFS OEM ID "NTFS    " at partition offset + 3
 */
TEST(real_device_ntfs)
{
	SKIP_NOT_ROOT();
	SKIP_NO_TEST_DEVICE();
	set_app_dir_to_project_root();
	reset_globals();

	const char *dev = test_device();

	cli_options_t opts;
	cli_options_init(&opts);
	strncpy(opts.device, dev, sizeof(opts.device) - 1);
	opts.fs          = FS_NTFS;
	opts.part_scheme = PARTITION_STYLE_MBR;
	opts.target      = TT_BIOS;
	opts.quick       = 1;
	opts.no_prompt   = 1;

	memset(partition_index, 0, sizeof(partition_index));
	ErrorStatus = 0;

	int rc = cli_run(&opts);

	/* Check MBR signature */
	uint8_t mbr_sig[2] = { 0, 0 };
	dev_read_at(dev, 510, mbr_sig, 2);

	/* Check NTFS OEM ID at offset 3 of partition sector 0.
	 * Read from the PARTITION device to avoid cross-device page cache staleness. */
	char part_dev_ntfs[256];
	partition_path(dev, part_dev_ntfs, sizeof(part_dev_ntfs));
	uint8_t oem[8] = { 0 };
	dev_read_at(part_dev_ntfs, 3, oem, 8);

	CHECK_MSG(rc == 0, "cli_run NTFS must succeed");
	CHECK_MSG(mbr_sig[0] == 0x55 && mbr_sig[1] == 0xAA,
	          "MBR must have 0x55AA after NTFS format");
	CHECK_MSG(memcmp(oem, "NTFS    ", 8) == 0,
	          "NTFS OEM ID 'NTFS    ' must be present at partition offset");
}

/*
 * real_device_fat32_gpt  (ROOT + RUFUS_TEST_DEVICE required)
 *
 * Format the target device as FAT32 + GPT via cli_run().
 * Verify:
 *   1. cli_run() returns 0
 *   2. GPT header signature "EFI PART" at LBA 1 (byte offset 512)
 */
TEST(real_device_fat32_gpt)
{
	SKIP_NOT_ROOT();
	SKIP_NO_TEST_DEVICE();
	set_app_dir_to_project_root();
	reset_globals();

	const char *dev = test_device();

	cli_options_t opts;
	cli_options_init(&opts);
	strncpy(opts.device, dev, sizeof(opts.device) - 1);
	opts.fs          = FS_FAT32;
	opts.part_scheme = PARTITION_STYLE_GPT;
	opts.target      = TT_UEFI;
	opts.quick       = 1;
	opts.no_prompt   = 1;

	memset(partition_index, 0, sizeof(partition_index));
	ErrorStatus = 0;

	int rc = cli_run(&opts);

	/* GPT header at LBA 1 (byte 512), starts with "EFI PART" */
	uint8_t gpt_sig[8] = { 0 };
	dev_read_at(dev, 512, gpt_sig, 8);

	CHECK_MSG(rc == 0, "cli_run FAT32+GPT must succeed");
	CHECK_MSG(memcmp(gpt_sig, "EFI PART", 8) == 0,
	          "GPT signature 'EFI PART' must be at LBA 1 after GPT format");
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
	const char *dev = getenv("RUFUS_TEST_DEVICE");

	printf("=== Real device Linux tests ===\n");
	if (dev && dev[0] != '\0')
		printf("Target device: %s\n", dev);
	else
		printf("Note: RUFUS_TEST_DEVICE not set — all tests will be skipped\n");

	set_app_dir_to_project_root();

	RUN(real_device_fat32);
	RUN(real_device_freedos);
	RUN(real_device_ntfs);
	RUN(real_device_fat32_gpt);

	TEST_RESULTS();
}

#endif /* __linux__ */
