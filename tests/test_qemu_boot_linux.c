/*
 * test_qemu_boot_linux.c — QEMU boot verification tests for the Rufus Linux port.
 *
 * Tests:
 *   qemu_available           — Skip-capable probe: checks that qemu-system-i386
 *                              (or qemu-system-x86_64) is in PATH.  Non-root.
 *
 *   freedos_qemu_boot        — Full-pipeline FreeDOS boot test (ROOT required):
 *                              1. Format a 128 MiB loopback image with BT_FREEDOS.
 *                              2. Mount the FAT32 partition, inject an AUTOEXEC.BAT
 *                                 that writes "RUFUS_FREEDOS_BOOT_OK" to C:\RESULT.TXT
 *                                 (the boot disk, no second drive needed).
 *                              3. Unmount FreeDOS partition.
 *                              4. Boot the image in qemu-system-i386 (or x86_64)
 *                                 with cache=writethrough and a 30 s timeout.
 *                              5. Re-mount the FreeDOS partition and verify that
 *                                 C:\RESULT.TXT contains "RUFUS_FREEDOS_BOOT_OK".
 *
 * Requires:
 *   - root access (loopback setup + offset-mount)
 *   - qemu-system-i386 or qemu-system-x86_64 installed
 *
 * Both tests skip gracefully when prerequisites are absent.
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
 * QEMU availability helpers
 * ================================================================ */

/*
 * Return path to a QEMU x86 binary, or NULL if none found.
 * Prefers i386 variant (better for 16-bit FreeDOS DOS boot).
 * Caller must NOT free the returned string.
 */
static const char *find_qemu(void)
{
	static const char *candidates[] = {
		"/usr/bin/qemu-system-i386",
		"/usr/local/bin/qemu-system-i386",
		"/bin/qemu-system-i386",
		"/usr/bin/qemu-system-x86_64",
		"/usr/local/bin/qemu-system-x86_64",
		NULL
	};
	for (int i = 0; candidates[i]; i++) {
		if (access(candidates[i], X_OK) == 0)
			return candidates[i];
	}
	return NULL;
}

/* ================================================================
 * Loopback infrastructure (same pattern as test_e2e_linux.c)
 * ================================================================ */

/* 128 MiB is plenty for FreeDOS and keeps the test fast */
#define QEMU_IMG_SIZE   ((uint64_t)128 * 1024 * 1024)

typedef struct {
	char img_path[256];
	char dev_path[64];
	int  img_fd;
} loop_ctx_t;

static BOOL loop_setup(loop_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->img_fd = -1;

	strncpy(ctx->img_path, "/tmp/rufus_qemu_XXXXXX", sizeof(ctx->img_path) - 1);
	ctx->img_fd = mkstemp(ctx->img_path);
	if (ctx->img_fd < 0) return FALSE;
	if (ftruncate(ctx->img_fd, (off_t)QEMU_IMG_SIZE) != 0) {
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
	rufus_drive[0].name         = "QEMUTest";
	rufus_drive[0].display_name = "QEMU Boot Test Drive";
	rufus_drive[0].label        = "";
	rufus_drive[0].index        = DRIVE_INDEX_MIN;
	rufus_drive[0].port         = 0;
	rufus_drive[0].size         = QEMU_IMG_SIZE;

	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	SelectedDrive.DiskSize   = (LONGLONG)QEMU_IMG_SIZE;
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

/* Reset format-relevant globals */
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

/* Run FormatThread in a pthread; wait up to 120 s */
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

/* Locate project root so get_freedos_source_dir() can find res/freedos/ */
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
 * qemu_available
 *
 * Non-root probe: just checks that a QEMU x86 binary exists.
 * Skips the rest of the suite if QEMU is absent so that the other
 * tests can use find_qemu() without an unconditional failure.
 */
TEST(qemu_available)
{
	const char *qemu = find_qemu();
	if (qemu == NULL) {
		printf("  (SKIP — qemu-system-i386 / qemu-system-x86_64 not found)\n");
		return;
	}
	printf("  Found QEMU at: %s\n", qemu);
	CHECK_MSG(access(qemu, X_OK) == 0, "QEMU binary must be executable");
}

/*
 * freedos_qemu_boot   (ROOT + QEMU required)
 *
 * Full pipeline test:
 *   1. Format a 128 MiB loopback image with BT_FREEDOS + FAT32 + MBR.
 *   2. Offset-mount (or partition-node mount) the FAT32 partition.
 *   3. Replace AUTOEXEC.BAT with a version that writes "RUFUS_FREEDOS_BOOT_OK"
 *      to a virtual floppy (B:\result.txt, presented as a second QEMU drive).
 *   4. Unmount the FreeDOS hard disk partition.
 *   5. Create a 1.44 MiB FAT12 floppy image (results drive).
 *   6. Boot the hard disk image in QEMU with the floppy as a second drive.
 *      QEMU is run under `timeout 30` so the test never hangs.
 *   7. Mount the floppy image and check for "RUFUS_FREEDOS_BOOT_OK" in result.txt.
 *
 * This approach avoids CTTY serial (which has baud-rate/FIFO init complexities)
 * and uses FreeDOS's ordinary file I/O to verify the OS executed our commands.
 */
TEST(freedos_qemu_boot)
{
	SKIP_NOT_ROOT();

	/* Require QEMU */
	const char *qemu = find_qemu();
	if (qemu == NULL) {
		printf("  (SKIP — qemu-system-i386 / qemu-system-x86_64 not found)\n");
		return;
	}

	/* Require mkfs.fat for the results floppy */
	if (access("/sbin/mkfs.fat", X_OK) != 0 &&
	    access("/usr/sbin/mkfs.fat", X_OK) != 0 &&
	    access("/bin/mkfs.fat", X_OK) != 0 &&
	    access("/usr/bin/mkfs.fat", X_OK) != 0) {
		printf("  (SKIP — mkfs.fat not found; install dosfstools)\n");
		return;
	}

	set_app_dir_to_project_root();

	/* ---- 1. Format FreeDOS on a loopback image ---- */
	loop_ctx_t ctx;
	if (!loop_setup(&ctx)) {
		CHECK_MSG(0, "loop_setup failed");
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
		CHECK_MSG(0, "FormatThread BT_FREEDOS must succeed before QEMU boot test");
		return;
	}

	loop_unregister();

	/* ---- 2. Mount the FAT32 partition ---- */
	char mnt_tmpl[] = "/tmp/rufus_qemu_mnt_XXXXXX";
	char *mnt = mkdtemp(mnt_tmpl);
	if (!mnt) {
		loop_teardown(&ctx);
		CHECK_MSG(0, "mkdtemp for partition mount");
		return;
	}

	/* Partition starts at LBA 2048 = 1 048 576 bytes */
	const uint64_t part_offset    = 2048ULL * 512;
	const uint64_t part_sizelimit = QEMU_IMG_SIZE - part_offset;

	char mount_cmd[512];
	snprintf(mount_cmd, sizeof(mount_cmd),
	         "mount -o offset=%llu,sizelimit=%llu %s %s 2>/dev/null",
	         (unsigned long long)part_offset,
	         (unsigned long long)part_sizelimit,
	         ctx.img_path, mnt);

	int mount_rc = system(mount_cmd);
	if (mount_rc != 0) {
		/* Fallback: use partition device node created by BLKRRPART in FormatThread */
		char part_dev[80];
		snprintf(part_dev, sizeof(part_dev), "%sp1", ctx.dev_path);
		if (access(part_dev, F_OK) == 0) {
			char mount_cmd2[256];
			snprintf(mount_cmd2, sizeof(mount_cmd2),
			         "mount %s %s 2>/dev/null", part_dev, mnt);
			mount_rc = system(mount_cmd2);
		}
	}

	if (mount_rc != 0) {
		rmdir(mnt);
		loop_teardown(&ctx);
		CHECK_MSG(0, "FAT32 partition must be mountable for AUTOEXEC.BAT injection");
		return;
	}

	/* ---- 3. Inject result-writing AUTOEXEC.BAT ---- */
	/*
	 * FreeDOS presents the second IDE drive as D:.  However, mapping
	/* ---- 3. Inject result-writing AUTOEXEC.BAT and minimal FDCONFIG.SYS ---- */
	/*
	 * AUTOEXEC.BAT: write the boot marker to C:\RESULT.TXT.
	 * FDCONFIG.SYS: SWITCHES=/N disables the "Press F8 to trace" countdown.
	 * We omit DEVICE= lines so no external drivers are loaded — COMMAND.COM
	 * and KERNEL.SYS alone are sufficient to run AUTOEXEC.BAT.
	 *
	 * cache=writethrough on the IDE drive ensures QEMU flushes each DOS write
	 * immediately to the host file so the data survives the timeout-kill.
	 * CR+LF line endings are required for DOS.
	 */
	char bat_path[512];
	snprintf(bat_path, sizeof(bat_path), "%s/AUTOEXEC.BAT", mnt);

	FILE *bat = fopen(bat_path, "w");
	if (!bat) {
		char umount_cmd[256];
		snprintf(umount_cmd, sizeof(umount_cmd), "umount %s 2>/dev/null", mnt);
		system(umount_cmd);
		rmdir(mnt);
		loop_teardown(&ctx);
		CHECK_MSG(0, "Cannot write AUTOEXEC.BAT for boot test");
		return;
	}
	fprintf(bat, "@ECHO OFF\r\n");
	fprintf(bat, "ECHO RUFUS_FREEDOS_BOOT_OK > C:\\RESULT.TXT\r\n");
	fclose(bat);

	char fdconfig_path[512];
	snprintf(fdconfig_path, sizeof(fdconfig_path), "%s/FDCONFIG.SYS", mnt);
	FILE *fdcfg = fopen(fdconfig_path, "w");
	if (fdcfg) {
		fprintf(fdcfg, "SWITCHES=/N\r\n");
		fclose(fdcfg);
	}

	/* ---- Unmount FreeDOS partition ---- */
	char umount_cmd[256];
	snprintf(umount_cmd, sizeof(umount_cmd), "umount %s 2>/dev/null", mnt);
	system(umount_cmd);
	rmdir(mnt);

	/* ---- 5. Create an empty "second disk" for the Rufus MBR ---- */
	/*
	 * The Rufus MBR reads sector 0 from BIOS disk 0x81 (second HD) before
	 * deciding how to boot.  Without a second disk, SeaBIOS may time out on
	 * the INT 13h call (10–30 s), delaying or preventing the boot.  We
	 * supply a small empty disk image as if=ide,index=1 so the MBR gets an
	 * immediate "no active partition" result from the all-zero sector and
	 * falls through to the boot_usb path without waiting.
	 */
	char dummy_img[256];
	snprintf(dummy_img, sizeof(dummy_img),
	         "/tmp/rufus_qemu_dummy_%d.img", (int)getpid());
	{
		int dfd = open(dummy_img, O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (dfd >= 0) {
			ftruncate(dfd, 1024 * 1024);  /* 1 MiB of zeroes */
			close(dfd);
		}
	}

	/* ---- 6. Run QEMU ---- */
	/*
	 * Drive layout:
	 *   if=ide,index=0 : our FreeDOS hard disk → BIOS 0x80 / C: in FreeDOS
	 *   if=ide,index=1 : empty dummy disk      → BIOS 0x81 (so MBR probe
	 *                    returns quickly with no active partition)
	 * cache=writethrough on index 0: each DOS write is immediately flushed
	 * to the host file so data survives SIGKILL from timeout.
	 * -display none : headless (no VGA window)
	 * -no-reboot    : quit instead of rebooting when FreeDOS halts/reboots
	 * -boot c       : boot from hard disk
	 * -m 32         : 32 MiB RAM (more than enough for FreeDOS)
	 */
	char qemu_cmd[1024];
	snprintf(qemu_cmd, sizeof(qemu_cmd),
	         "timeout 30 %s"
	         " -drive file=%s,if=ide,index=0,format=raw,cache=writethrough"
	         " -drive file=%s,if=ide,index=1,format=raw"
	         " -cpu pentium2"
	         " -display none"
	         " -no-reboot"
	         " -boot c"
	         " -m 32"
	         " < /dev/null"
	         " > /dev/null 2>&1"
	         " || true",
	         qemu, ctx.img_path, dummy_img);

	printf("  Running QEMU (up to 30 s)...\n");
	fflush(stdout);
	system(qemu_cmd);

	/* ---- 6. Check FreeDOS disk for boot marker ---- */
	/*
	 * Re-mount the FAT32 partition and look for C:\RESULT.TXT.
	 * The loop device is still attached (loop_teardown happens at end).
	 */
	BOOL marker_found = FALSE;

	char res_mnt_tmpl[] = "/tmp/rufus_qemu_res_XXXXXX";
	char *res_mnt = mkdtemp(res_mnt_tmpl);
	if (res_mnt) {
		/* Prefer partition device node (loop still attached) */
		char part_dev[80];
		snprintf(part_dev, sizeof(part_dev), "%sp1", ctx.dev_path);
		char res_mount_cmd[256];
		int rmc;
		if (access(part_dev, F_OK) == 0) {
			snprintf(res_mount_cmd, sizeof(res_mount_cmd),
			         "mount -o ro %s %s 2>/dev/null", part_dev, res_mnt);
		} else {
			snprintf(res_mount_cmd, sizeof(res_mount_cmd),
			         "mount -o ro,loop,offset=%llu,sizelimit=%llu %s %s 2>/dev/null",
			         (unsigned long long)(2048ULL * 512),
			         (unsigned long long)(QEMU_IMG_SIZE - 2048ULL * 512),
			         ctx.img_path, res_mnt);
		}
		rmc = system(res_mount_cmd);
		if (rmc == 0) {
			char result_path[512];
			snprintf(result_path, sizeof(result_path), "%s/RESULT.TXT", res_mnt);
			FILE *rf = fopen(result_path, "r");
			if (rf) {
				char line[256];
				while (fgets(line, sizeof(line), rf)) {
					if (strstr(line, "RUFUS_FREEDOS_BOOT_OK")) {
						marker_found = TRUE;
					}
				}
				fclose(rf);
			}
			char res_umount_cmd[256];
			snprintf(res_umount_cmd, sizeof(res_umount_cmd),
			         "umount %s 2>/dev/null", res_mnt);
			system(res_umount_cmd);
		}
		rmdir(res_mnt);
	}

	CHECK_MSG(marker_found,
	          "C:\\RESULT.TXT on FreeDOS disk must contain RUFUS_FREEDOS_BOOT_OK "
	          "after FreeDOS boots and runs AUTOEXEC.BAT");

	/* Cleanup */
	unlink(dummy_img);
	loop_teardown(&ctx);
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
	printf("=== QEMU Boot Linux tests ===\n");
	set_app_dir_to_project_root();

	RUN(qemu_available);
	RUN(freedos_qemu_boot);

	TEST_RESULTS();
}

#endif /* __linux__ */
