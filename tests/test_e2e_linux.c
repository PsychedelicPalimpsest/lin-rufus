/*
 * test_e2e_linux.c — End-to-end integration tests for the Rufus Linux port.
 *
 * Tests:
 *   iso_dd_write_structure        — BT_IMAGE + write_as_image=TRUE; copies an ISO
 *                                   verbatim to a temp file; verifies ISO 9660 PVD.
 *   freedos_mbr_signature         — FormatThread BT_FREEDOS; verifies MBR 0x55AA.
 *   freedos_format_and_verify     — FormatThread BT_FREEDOS; mounts FAT32 partition;
 *                                   verifies KERNEL.SYS + COMMAND.COM are present.
 *   cli_format_fat32_loop         — cli_run() with FAT32+MBR+non-bootable on a loop
 *                                   device; verifies MBR 0x55AA boot signature.
 *   cli_format_freedos_loop       — cli_run() with BT_FREEDOS on a loop device;
 *                                   verifies MBR 0x55AA and KERNEL.SYS present.
 *   cli_image_scan_populates_img_report — regression test: cli_run() with --image
 *                                   (no --write-as-image) must call ImageScanThread
 *                                   so img_report.is_iso is set before FormatThread.
 *
 * The ISO test is non-root; the rest require root (loopback + mount).
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
#include <sys/stat.h>
#include <sys/types.h>
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
 * Required globals (defined in globals.c, included via DOS_LINUX_SRC)
 * ================================================================ */

extern RUFUS_DRIVE       rufus_drive[MAX_DRIVES];
extern RUFUS_DRIVE_INFO  SelectedDrive;
extern int               partition_index[PI_MAX];
extern DWORD             ErrorStatus;
extern DWORD             LastWriteError;
extern BOOL              quick_format;
extern BOOL              write_as_image;
extern BOOL              write_as_esp;
extern BOOL              zero_drive;
extern BOOL              use_rufus_mbr;
extern int               fs_type;
extern int               boot_type;
extern int               partition_type;
extern int               target_type;
extern uint64_t          persistence_size;
extern char              app_dir[MAX_PATH];
extern char             *image_path;
extern RUFUS_IMG_REPORT  img_report;

/* ================================================================
 * Root-check macro
 * ================================================================ */

#define SKIP_NOT_ROOT() \
	do { \
		if (geteuid() != 0) { \
			printf("  (SKIP — requires root)\n"); \
			return; \
		} \
	} while (0)

/* ================================================================
 * Loopback infrastructure
 * ================================================================ */

#define LOOP_IMG_SIZE   ((uint64_t)512 * 1024 * 1024)   /* 512 MiB */

typedef struct {
	char img_path[256];
	char dev_path[64];
	int  img_fd;
} loop_ctx_t;

static BOOL loop_setup(loop_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->img_fd = -1;

	strncpy(ctx->img_path, "/tmp/rufus_e2e_XXXXXX", sizeof(ctx->img_path) - 1);
	ctx->img_fd = mkstemp(ctx->img_path);
	if (ctx->img_fd < 0) return FALSE;
	if (ftruncate(ctx->img_fd, (off_t)LOOP_IMG_SIZE) != 0) {
		close(ctx->img_fd); ctx->img_fd = -1;
		unlink(ctx->img_path);
		return FALSE;
	}

	char cmd[320];
	snprintf(cmd, sizeof(cmd), "losetup -f --show %s 2>/dev/null", ctx->img_path);
	FILE *fp = popen(cmd, "r");
	if (!fp) {
		close(ctx->img_fd); ctx->img_fd = -1;
		unlink(ctx->img_path);
		return FALSE;
	}
	if (!fgets(ctx->dev_path, sizeof(ctx->dev_path), fp)) {
		pclose(fp);
		close(ctx->img_fd); ctx->img_fd = -1;
		unlink(ctx->img_path);
		return FALSE;
	}
	pclose(fp);

	/* Strip trailing newline */
	size_t len = strlen(ctx->dev_path);
	if (len > 0 && ctx->dev_path[len - 1] == '\n')
		ctx->dev_path[len - 1] = '\0';

	struct stat st;
	if (stat(ctx->dev_path, &st) != 0 || !S_ISBLK(st.st_mode)) {
		close(ctx->img_fd); ctx->img_fd = -1;
		unlink(ctx->img_path);
		memset(ctx->dev_path, 0, sizeof(ctx->dev_path));
		return FALSE;
	}
	return TRUE;
}

static void loop_teardown(loop_ctx_t *ctx)
{
	if (ctx->dev_path[0] != '\0') {
		char cmd[128];
		snprintf(cmd, sizeof(cmd), "losetup -d %s 2>/dev/null", ctx->dev_path);
		system(cmd);
	}
	if (ctx->img_fd >= 0) { close(ctx->img_fd); ctx->img_fd = -1; }
	if (ctx->img_path[0] != '\0') unlink(ctx->img_path);
	memset(ctx, 0, sizeof(*ctx));
}

static DWORD loop_register(loop_ctx_t *ctx)
{
	memset(rufus_drive, 0, sizeof(rufus_drive));
	rufus_drive[0].id           = ctx->dev_path;
	rufus_drive[0].name         = "E2ETest";
	rufus_drive[0].display_name = "E2E Test Drive";
	rufus_drive[0].label        = "";
	rufus_drive[0].index        = DRIVE_INDEX_MIN;
	rufus_drive[0].port         = 0;
	rufus_drive[0].size         = LOOP_IMG_SIZE;

	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	SelectedDrive.DiskSize   = (LONGLONG)LOOP_IMG_SIZE;
	SelectedDrive.SectorSize = 512;

	return DRIVE_INDEX_MIN;
}

static void loop_unregister(void)
{
	memset(rufus_drive, 0, sizeof(rufus_drive));
	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	memset(partition_index, 0, sizeof(partition_index));
	ErrorStatus = 0;
}

/* Read N bytes from fd at a given byte offset */
static int read_fd_at(int fd, off_t offset, void *buf, size_t n)
{
	ssize_t r = pread(fd, buf, n, offset);
	return (r == (ssize_t)n) ? 0 : -1;
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
	quick_format     = TRUE;
	persistence_size = 0;
}

/* Run FormatThread in a pthread; wait up to 120 s (FreeDOS can be slow) */
static DWORD run_format_thread(DWORD DriveIndex)
{
	HANDLE t = CreateThread(NULL, 0, FormatThread,
	                        (void *)(uintptr_t)DriveIndex, 0, NULL);
	if (t == NULL) return (DWORD)-1;
	WaitForSingleObject(t, 120000);
	DWORD code = 1;
	GetExitCodeThread(t, &code);
	CloseHandle(t);
	return code;
}

/*
 * Point app_dir at the project root so that get_freedos_source_dir()
 * can locate res/freedos/.  Mirrors the helper in test_dos_linux.c.
 */
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

/* ================================================================
 * Tests
 * ================================================================ */

/*
 * iso_dd_write_structure
 *
 * Creates a small ISO with genisoimage, then uses FormatThread in
 * write_as_image mode to copy it verbatim to a temp file.
 * Verifies the ISO 9660 Primary Volume Descriptor magic "CD001" at
 * byte offset 0x8001.
 */
TEST(iso_dd_write_structure)
{
	/* Skip if genisoimage is not installed */
	if (access("/usr/bin/genisoimage", X_OK) != 0 &&
	    access("/usr/local/bin/genisoimage", X_OK) != 0) {
		printf("  (SKIP — genisoimage not found)\n");
		return;
	}

	/* Build a tiny ISO source tree */
	char src_tmpl[] = "/tmp/rufus_e2e_isosrc_XXXXXX";
	char *iso_src = mkdtemp(src_tmpl);
	if (!iso_src) { CHECK_MSG(0, "mkdtemp for ISO source"); return; }

	char testfile[300];
	snprintf(testfile, sizeof(testfile), "%s/test.txt", iso_src);
	FILE *tf = fopen(testfile, "w");
	if (!tf) { rmdir(iso_src); CHECK_MSG(0, "create test file for ISO"); return; }
	fprintf(tf, "rufus e2e iso test\n");
	fclose(tf);

	char iso_path[256];
	snprintf(iso_path, sizeof(iso_path), "/tmp/rufus_e2e_test_%d.iso", (int)getpid());

	char gi_cmd[512];
	snprintf(gi_cmd, sizeof(gi_cmd),
	         "genisoimage -quiet -o %s -R -J %s 2>/dev/null",
	         iso_path, iso_src);
	int gi_rc = system(gi_cmd);
	unlink(testfile);
	rmdir(iso_src);

	if (gi_rc != 0) {
		printf("  (SKIP — genisoimage failed)\n");
		return;
	}

	struct stat iso_st;
	if (stat(iso_path, &iso_st) != 0 || iso_st.st_size < 0x8006) {
		unlink(iso_path);
		CHECK_MSG(0, "ISO too small for PVD verification");
		return;
	}

	/* Create a target file (same size as ISO) */
	char target_path[256];
	snprintf(target_path, sizeof(target_path),
	         "/tmp/rufus_e2e_ddtgt_%d.img", (int)getpid());
	int tfd = open(target_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (tfd < 0) { unlink(iso_path); CHECK_MSG(0, "create target image"); return; }
	ftruncate(tfd, iso_st.st_size);
	close(tfd);

	/* Register target as rufus drive 0 */
	memset(rufus_drive, 0, sizeof(rufus_drive));
	rufus_drive[0].id           = target_path;
	rufus_drive[0].name         = "DDTest";
	rufus_drive[0].display_name = "DD Test Drive";
	rufus_drive[0].label        = "";
	rufus_drive[0].index        = DRIVE_INDEX_MIN;
	rufus_drive[0].size         = (uint64_t)iso_st.st_size;

	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	SelectedDrive.DiskSize   = (LONGLONG)iso_st.st_size;
	SelectedDrive.SectorSize = 2048;

	reset_globals();
	boot_type      = BT_IMAGE;
	write_as_image = TRUE;
	image_path     = iso_path;

	DWORD rc = run_format_thread(DRIVE_INDEX_MIN);

	/* Read PVD from target */
	int vfd = open(target_path, O_RDONLY);
	BOOL pvd_ok = FALSE;
	if (vfd >= 0) {
		uint8_t pvd[6] = { 0 };
		if (read_fd_at(vfd, 0x8000, pvd, 6) == 0) {
			pvd_ok = (pvd[1] == 'C' && pvd[2] == 'D' && pvd[3] == '0' &&
			          pvd[4] == '0' && pvd[5] == '1');
		}
		close(vfd);
	}

	unlink(iso_path);
	unlink(target_path);
	loop_unregister();

	CHECK_MSG(rc == 0 && !IS_ERROR(ErrorStatus),
	          "FormatThread write_as_image must succeed");
	CHECK_MSG(pvd_ok,
	          "ISO 9660 PVD magic 'CD001' must survive DD copy at offset 0x8001");
}

/*
 * freedos_mbr_signature   (ROOT required)
 *
 * Formats a 512 MiB loopback with BT_FREEDOS and verifies that the
 * MBR written by FormatThread has the valid boot signature 0x55 0xAA
 * at bytes 510–511.
 */
TEST(freedos_mbr_signature)
{
	SKIP_NOT_ROOT();
	set_app_dir_to_project_root();

	loop_ctx_t ctx;
	if (!loop_setup(&ctx)) {
		CHECK_MSG(0, "loop_setup for MBR test");
		return;
	}

	DWORD di = loop_register(&ctx);
	reset_globals();
	boot_type      = BT_FREEDOS;
	partition_type = PARTITION_STYLE_MBR;
	fs_type        = FS_FAT32;
	target_type    = TT_BIOS;
	quick_format   = TRUE;

	DWORD rc = run_format_thread(di);

	uint8_t sig[2] = { 0 };
	int read_rc = read_fd_at(ctx.img_fd, 510, sig, 2);

	loop_unregister();
	loop_teardown(&ctx);

	CHECK_MSG(rc == 0 && !IS_ERROR(ErrorStatus),
	          "FormatThread BT_FREEDOS must succeed");
	CHECK_MSG(read_rc == 0, "reading MBR tail must succeed");
	CHECK_MSG(sig[0] == 0x55 && sig[1] == 0xAA,
	          "MBR must have boot signature 0x55 0xAA at bytes 510-511");
}

/*
 * freedos_format_and_verify   (ROOT required)
 *
 * Full end-to-end: formats a 512 MiB loopback with BT_FREEDOS+FAT32+MBR,
 * then mounts the resulting partition with a loopback offset mount and
 * checks that KERNEL.SYS and COMMAND.COM were extracted.
 */
TEST(freedos_format_and_verify)
{
	SKIP_NOT_ROOT();
	set_app_dir_to_project_root();

	loop_ctx_t ctx;
	if (!loop_setup(&ctx)) {
		CHECK_MSG(0, "loop_setup for FreeDOS E2E test");
		return;
	}

	DWORD di = loop_register(&ctx);
	reset_globals();
	boot_type      = BT_FREEDOS;
	partition_type = PARTITION_STYLE_MBR;
	fs_type        = FS_FAT32;
	target_type    = TT_BIOS;
	quick_format   = TRUE;

	DWORD rc = run_format_thread(di);

	if (rc != 0 || IS_ERROR(ErrorStatus)) {
		loop_unregister();
		loop_teardown(&ctx);
		CHECK_MSG(0, "FormatThread BT_FREEDOS must succeed before file verification");
		return;
	}

	/* Mount the FAT32 partition at LBA 2048 (byte offset 1 048 576) */
	char mnt_tmpl[] = "/tmp/rufus_e2e_mnt_XXXXXX";
	char *mnt = mkdtemp(mnt_tmpl);
	if (!mnt) {
		loop_unregister();
		loop_teardown(&ctx);
		CHECK_MSG(0, "mkdtemp for verify mount");
		return;
	}

	char mount_cmd[512];
	snprintf(mount_cmd, sizeof(mount_cmd),
	         "mount -o offset=%llu,sizelimit=%llu %s %s 2>/dev/null",
	         (unsigned long long)(2048ULL * 512),
	         (unsigned long long)(LOOP_IMG_SIZE - 2048ULL * 512),
	         ctx.img_path, mnt);

	int mount_rc = system(mount_cmd);
	if (mount_rc != 0) {
		/* Try mounting via the partition device if offset mount failed */
		char part_dev[80];
		snprintf(part_dev, sizeof(part_dev), "%sp1", ctx.dev_path);
		if (access(part_dev, F_OK) == 0) {
			char mount_cmd2[256];
			snprintf(mount_cmd2, sizeof(mount_cmd2), "mount %s %s 2>/dev/null",
			         part_dev, mnt);
			mount_rc = system(mount_cmd2);
		}
	}

	/* Verify files whether or not the mount succeeded */
	BOOL has_kernel  = FALSE;
	BOOL has_command = FALSE;

	if (mount_rc == 0) {
		char p[512];

		snprintf(p, sizeof(p), "%s/KERNEL.SYS", mnt);
		has_kernel = (access(p, F_OK) == 0);
		if (!has_kernel) {
			snprintf(p, sizeof(p), "%s/kernel.sys", mnt);
			has_kernel = (access(p, F_OK) == 0);
		}

		snprintf(p, sizeof(p), "%s/COMMAND.COM", mnt);
		has_command = (access(p, F_OK) == 0);
		if (!has_command) {
			snprintf(p, sizeof(p), "%s/command.com", mnt);
			has_command = (access(p, F_OK) == 0);
		}

		char umount_cmd[256];
		snprintf(umount_cmd, sizeof(umount_cmd), "umount %s 2>/dev/null", mnt);
		system(umount_cmd);
	}
	rmdir(mnt);
	loop_unregister();
	loop_teardown(&ctx);

	CHECK_MSG(mount_rc == 0, "FAT32 partition must be mountable after FreeDOS format");
	CHECK_MSG(has_kernel,  "KERNEL.SYS must be present on FreeDOS drive");
	CHECK_MSG(has_command, "COMMAND.COM must be present on FreeDOS drive");
}

/* ================================================================
 * CLI E2E tests
 * ================================================================ */

/*
 * cli_format_fat32_loop   (ROOT required)
 *
 * Exercises cli_run() as the entry point for a non-bootable FAT32 + MBR
 * format on a loopback image.  Verifies that the MBR boot signature
 * (0x55 0xAA at bytes 510–511) is present after the operation.
 */
TEST(cli_format_fat32_loop)
{
	SKIP_NOT_ROOT();
	set_app_dir_to_project_root();

	loop_ctx_t ctx;
	if (!loop_setup(&ctx)) {
		CHECK_MSG(0, "loop_setup for CLI FAT32 test");
		return;
	}

	cli_options_t opts;
	cli_options_init(&opts);
	strncpy(opts.device, ctx.dev_path, sizeof(opts.device) - 1);
	opts.fs          = FS_FAT32;
	opts.part_scheme = PARTITION_STYLE_MBR;
	opts.target      = TT_BIOS;
	opts.quick       = 1;    /* quick format */
	opts.no_prompt   = 1;    /* suppress confirmation dialogs */

	/* Reset shared globals that cli_run() does not clear */
	memset(partition_index, 0, sizeof(partition_index));
	ErrorStatus = 0;

	/* cli_run() opens the device, registers it, applies options, runs FormatThread */
	int cli_rc = cli_run(&opts);

	/* Read MBR boot signature */
	uint8_t sig[2] = { 0, 0 };
	if (ctx.img_fd >= 0) {
		pread(ctx.img_fd, sig, 2, 510);
	}

	loop_teardown(&ctx);

	CHECK_MSG(cli_rc == 0, "cli_run FAT32 must succeed (return 0)");
	CHECK_MSG(sig[0] == 0x55 && sig[1] == 0xAA,
	          "MBR must have 0x55AA boot signature after cli FAT32 format");
}

/*
 * cli_format_freedos_loop   (ROOT required)
 *
 * Exercises cli_run() with a FreeDOS boot disk configuration.
 * Verifies MBR 0x55AA signature and that KERNEL.SYS is present on the
 * FAT32 partition after extraction.
 */
TEST(cli_format_freedos_loop)
{
	SKIP_NOT_ROOT();
	set_app_dir_to_project_root();

	loop_ctx_t ctx;
	if (!loop_setup(&ctx)) {
		CHECK_MSG(0, "loop_setup for CLI FreeDOS test");
		return;
	}

	cli_options_t opts;
	cli_options_init(&opts);
	strncpy(opts.device, ctx.dev_path, sizeof(opts.device) - 1);
	opts.fs          = FS_FAT32;
	opts.part_scheme = PARTITION_STYLE_MBR;
	opts.target      = TT_BIOS;
	opts.boot_type   = BT_FREEDOS;
	opts.quick       = 1;
	opts.no_prompt   = 1;

	memset(partition_index, 0, sizeof(partition_index));
	ErrorStatus = 0;

	int cli_rc = cli_run(&opts);

	/* Read MBR boot signature */
	uint8_t sig[2] = { 0, 0 };
	if (ctx.img_fd >= 0)
		pread(ctx.img_fd, sig, 2, 510);

	/* Mount partition and verify KERNEL.SYS */
	BOOL has_kernel = FALSE;
	if (cli_rc == 0) {
		char mnt_tmpl[] = "/tmp/rufus_e2e_cli_mnt_XXXXXX";
		char *mnt = mkdtemp(mnt_tmpl);
		if (mnt) {
			char mount_cmd[512];
			snprintf(mount_cmd, sizeof(mount_cmd),
			         "mount -o offset=%llu,sizelimit=%llu %s %s 2>/dev/null",
			         (unsigned long long)(2048ULL * 512),
			         (unsigned long long)(LOOP_IMG_SIZE - 2048ULL * 512),
			         ctx.img_path, mnt);
			int mnt_rc = system(mount_cmd);
			if (mnt_rc != 0) {
				/* Fallback: partition device node created by BLKRRPART in FormatThread */
				char part_dev[80];
				snprintf(part_dev, sizeof(part_dev), "%sp1", ctx.dev_path);
				if (access(part_dev, F_OK) == 0) {
					char mount_cmd2[256];
					snprintf(mount_cmd2, sizeof(mount_cmd2),
					         "mount %s %s 2>/dev/null", part_dev, mnt);
					mnt_rc = system(mount_cmd2);
				}
			}
			if (mnt_rc == 0) {
				char p[512];
				snprintf(p, sizeof(p), "%s/KERNEL.SYS", mnt);
				has_kernel = (access(p, F_OK) == 0);
				if (!has_kernel) {
					snprintf(p, sizeof(p), "%s/kernel.sys", mnt);
					has_kernel = (access(p, F_OK) == 0);
				}
				char umount_cmd[256];
				snprintf(umount_cmd, sizeof(umount_cmd), "umount %s 2>/dev/null", mnt);
				system(umount_cmd);
			}
			rmdir(mnt);
		}
	}

	loop_teardown(&ctx);

	CHECK_MSG(cli_rc == 0, "cli_run FreeDOS must succeed (return 0)");
	CHECK_MSG(sig[0] == 0x55 && sig[1] == 0xAA,
	          "MBR must have 0x55AA boot signature after cli FreeDOS format");
	CHECK_MSG(has_kernel, "KERNEL.SYS must be present after cli FreeDOS format");
}

/*
 * cli_image_scan_populates_img_report   (ROOT required)
 *
 * Regression test for the CLI ImageScanThread fix: when cli_run() is given
 * --image without --write-as-image, it must call ImageScanThread before
 * launching FormatThread so that img_report.is_iso is set.
 *
 * This test creates a tiny ISO with genisoimage, runs cli_run() with that
 * image, and verifies that img_report.is_iso is TRUE after the call.
 * (The ImageScanThread stub in e2e_linux_glue.c delegates to ExtractISO
 * which sets img_report.is_iso = TRUE; without the fix, ImageScanThread
 * would never be called and img_report.is_iso would remain FALSE.)
 */
TEST(cli_image_scan_populates_img_report)
{
	SKIP_NOT_ROOT();
	set_app_dir_to_project_root();

	/* Require genisoimage to create a tiny ISO */
	if (system("which genisoimage >/dev/null 2>&1") != 0) {
		printf("  SKIP cli_image_scan_populates_img_report: genisoimage not found\n");
		return;
	}

	/* Create a tiny ISO from a temp dir */
	char iso_dir[]  = "/tmp/rufus_e2e_isodir_XXXXXX";
	char iso_path[] = "/tmp/rufus_e2e_XXXXXX.iso";
	/* mkstemp doesn't give us .iso extension — use a fixed-suffix name */
	char iso_file[256];
	char *d = mkdtemp(iso_dir);
	if (!d) {
		CHECK_MSG(0, "mkdtemp for ISO source dir must succeed");
		return;
	}
	/* Put a single file in the dir so the ISO is non-empty */
	char sentinel[512];
	snprintf(sentinel, sizeof(sentinel), "%s/test.txt", d);
	FILE *f = fopen(sentinel, "w");
	if (f) { fputs("rufus-e2e\n", f); fclose(f); }

	snprintf(iso_file, sizeof(iso_file), "/tmp/rufus_e2e_img_scan_%d.iso", (int)getpid());
	char cmd[768];
	snprintf(cmd, sizeof(cmd),
	         "genisoimage -quiet -o %s -R %s 2>/dev/null", iso_file, d);
	system(cmd);
	/* cleanup source dir */
	snprintf(cmd, sizeof(cmd), "rm -rf %s", d);
	system(cmd);

	if (access(iso_file, F_OK) != 0) {
		CHECK_MSG(0, "genisoimage must produce an ISO file");
		return;
	}

	loop_ctx_t ctx;
	if (!loop_setup(&ctx)) {
		unlink(iso_file);
		CHECK_MSG(0, "loop_setup for img_scan test");
		return;
	}

	/* Reset img_report so we can detect whether it was set */
	memset(&img_report, 0, sizeof(img_report));

	cli_options_t opts;
	cli_options_init(&opts);
	strncpy(opts.device, ctx.dev_path, sizeof(opts.device) - 1);
	strncpy(opts.image,  iso_file,     sizeof(opts.image)  - 1);
	opts.fs            = FS_FAT32;
	opts.part_scheme   = PARTITION_STYLE_MBR;
	opts.write_as_image = 0;   /* extraction mode — must trigger ImageScanThread */
	opts.quick         = 1;
	opts.no_prompt     = 1;

	ErrorStatus = 0;
	memset(partition_index, 0, sizeof(partition_index));

	cli_run(&opts);

	BOOLEAN iso_was_scanned = img_report.is_iso;

	loop_teardown(&ctx);
	unlink(iso_file);

	CHECK_MSG(iso_was_scanned,
	          "img_report.is_iso must be TRUE after cli_run with --image "
	          "(ImageScanThread must be called before FormatThread)");
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
	printf("=== E2E Linux tests ===\n");
	set_app_dir_to_project_root();

	RUN(iso_dd_write_structure);
	RUN(freedos_mbr_signature);
	RUN(freedos_format_and_verify);
	RUN(cli_format_fat32_loop);
	RUN(cli_format_freedos_loop);
	RUN(cli_image_scan_populates_img_report);

	TEST_RESULTS();
}

#endif /* __linux__ */
