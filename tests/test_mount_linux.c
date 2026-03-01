/*
 * test_mount_linux.c — Tests for Linux mount/unmount API (src/linux/drive.c)
 *
 * Tests cover AltMountVolume, AltUnmountVolume, MountVolume, RemountVolume.
 *
 * All tests run without root privileges: only error-path and basic contract
 * behaviour is verified.  Actual mounting would require a loop device and root.
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
#include <stdarg.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "framework.h"
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/linux/drive_linux.h"

/* ------------------------------------------------------------------ */
/* Required globals — defined in src/linux/globals.c (linked in)       */
/* ------------------------------------------------------------------ */
extern DWORD  ErrorStatus;
extern DWORD  MainThreadId;
extern DWORD  DownloadStatus;
extern DWORD  LastWriteError;
extern HWND   hMainDialog;
extern BOOL   usb_debug;

/* uprintf / uprintfs / lmprintf / UpdateProgress come from stdio.c and ui.c */
extern void uprintf(const char *fmt, ...);
extern void uprintfs(const char *s);
extern char *lmprintf(uint32_t id, ...);

/* Forward declarations */
extern BOOL   MountVolume(char *drive_name, char *drive_guid);
extern char  *AltMountVolume(DWORD DriveIndex, uint64_t PartitionOffset, BOOL bSilent);
extern BOOL   AltUnmountVolume(const char *drive_name, BOOL bSilent);
extern BOOL   RemountVolume(char *drive_name, BOOL bSilent);

/* ================================================================== */
/* AltUnmountVolume — error-path tests                                 */
/* ================================================================== */

TEST(alt_unmount_null_returns_false)
{
    BOOL r = AltUnmountVolume(NULL, TRUE);
    CHECK_MSG(r == FALSE, "AltUnmountVolume(NULL) must return FALSE");
}

TEST(alt_unmount_nonexistent_path_returns_false)
{
    BOOL r = AltUnmountVolume("/tmp/__rufus_test_does_not_exist_xyz__", TRUE);
    CHECK_MSG(r == FALSE,
              "AltUnmountVolume with nonexistent path must return FALSE");
}

TEST(alt_unmount_empty_string_returns_false)
{
    BOOL r = AltUnmountVolume("", TRUE);
    CHECK_MSG(r == FALSE, "AltUnmountVolume('') must return FALSE");
}

/*
 * Create a real temp directory, then verify that AltUnmountVolume
 * correctly reports FALSE (because the directory is not a mount point).
 * On Linux, umount2() of a non-mount-point returns EINVAL.
 */
TEST(alt_unmount_plain_dir_returns_false)
{
    char tmpdir[] = "/tmp/rufus_test_XXXXXX";
    char *result = mkdtemp(tmpdir);
    if (!result) {
        printf("  [SKIP] mkdtemp failed: %s\n", strerror(errno));
        return;
    }
    BOOL r = AltUnmountVolume(tmpdir, TRUE);
    /* On a non-root run the dir is not a mount point; expect FALSE */
    CHECK_MSG(r == FALSE,
              "AltUnmountVolume on a plain (unmounted) dir must return FALSE");
    /* Cleanup if the call didn't remove the dir (it shouldn't on failure) */
    rmdir(tmpdir);
}

/* ================================================================== */
/* AltMountVolume — error-path tests                                   */
/* ================================================================== */

TEST(alt_mount_invalid_drive_index_returns_null)
{
    /*
     * Drive index 0xDEADBEEF almost certainly has no registered device.
     * AltMountVolume must return NULL gracefully.
     */
    char *mp = AltMountVolume(0xDEADBEEF, 0, TRUE);
    CHECK_MSG(mp == NULL,
              "AltMountVolume with invalid drive index must return NULL");
    free(mp);   /* safe: free(NULL) is a no-op */
}

TEST(alt_mount_does_not_leave_temp_dir_on_failure)
{
    /*
     * If AltMountVolume fails, it must not leave a stale temp directory
     * behind.  We can detect leaked dirs by counting /tmp entries before
     * and after the call.
     */
    DIR *dp;
    struct dirent *de;
    int before = 0, after = 0;
    const char *prefix = "rufus_";

    dp = opendir("/tmp");
    if (dp) {
        while ((de = readdir(dp)) != NULL)
            if (strncmp(de->d_name, prefix, strlen(prefix)) == 0) before++;
        closedir(dp);
    }

    char *mp = AltMountVolume(0xDEADBEEF, 0, TRUE);
    free(mp);

    dp = opendir("/tmp");
    if (dp) {
        while ((de = readdir(dp)) != NULL)
            if (strncmp(de->d_name, prefix, strlen(prefix)) == 0) after++;
        closedir(dp);
    }

    CHECK_MSG(after <= before,
              "AltMountVolume must not leak temp directories on failure");
}

/* ================================================================== */
/* MountVolume — error-path tests                                      */
/* ================================================================== */

TEST(mount_volume_null_device_returns_false)
{
    BOOL r = MountVolume(NULL, "/tmp");
    CHECK_MSG(r == FALSE, "MountVolume(NULL, ...) must return FALSE");
}

TEST(mount_volume_null_mountpoint_returns_false)
{
    BOOL r = MountVolume("/dev/nonexistent", NULL);
    CHECK_MSG(r == FALSE, "MountVolume(..., NULL) must return FALSE");
}

TEST(mount_volume_both_null_returns_false)
{
    BOOL r = MountVolume(NULL, NULL);
    CHECK_MSG(r == FALSE, "MountVolume(NULL, NULL) must return FALSE");
}

TEST(mount_volume_nonexistent_device_returns_false)
{
    BOOL r = MountVolume("/dev/__rufus_test_nosuchdev__", "/tmp");
    CHECK_MSG(r == FALSE,
              "MountVolume with nonexistent device must return FALSE");
}

/* ================================================================== */
/* RemountVolume — error-path tests                                    */
/* ================================================================== */

TEST(remount_volume_null_returns_false)
{
    BOOL r = RemountVolume(NULL, TRUE);
    CHECK_MSG(r == FALSE, "RemountVolume(NULL) must return FALSE");
}

/* ================================================================== */
/* main                                                                 */
/* ================================================================== */
int main(void)
{
    printf("=== mount_linux tests ===\n");

    RUN(alt_unmount_null_returns_false);
    RUN(alt_unmount_nonexistent_path_returns_false);
    RUN(alt_unmount_empty_string_returns_false);
    RUN(alt_unmount_plain_dir_returns_false);

    RUN(alt_mount_invalid_drive_index_returns_null);
    RUN(alt_mount_does_not_leave_temp_dir_on_failure);

    RUN(mount_volume_null_device_returns_false);
    RUN(mount_volume_null_mountpoint_returns_false);
    RUN(mount_volume_both_null_returns_false);
    RUN(mount_volume_nonexistent_device_returns_false);

    RUN(remount_volume_null_returns_false);

    TEST_RESULTS();
}

#endif /* __linux__ */
