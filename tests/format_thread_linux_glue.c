/*
 * format_thread_linux_glue.c — stubs for symbols needed by drive.c that
 * are not defined by test_format_thread_linux.c's own stub section.
 *
 * These symbols live in stdio.c and stdfn.c in production but are not
 * needed functionally by the format-thread tests.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/windows/badblocks.h"

DWORD _win_last_error = 0;

char *GuidToString(const GUID *guid, BOOL bDecorated)
{
    (void)guid; (void)bDecorated; return NULL;
}

GUID *StringToGuid(const char *str)
{
    (void)str; return NULL;
}

BOOL CompareGUID(const GUID *g1, const GUID *g2)
{
    if (!g1 || !g2) return FALSE;
    return (__builtin_memcmp(g1, g2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}

/* Stubs for parser.c symbols (needed by settings.h / IsFilteredDrive) */
windows_version_t WindowsVersion = { 0 };

char *get_token_data_file_indexed(const char *token, const char *filename,
                                   const int index)
{
    (void)token; (void)filename; (void)index; return NULL;
}

/*
 * RunCommandWithProgress — execute the command in a child process and wait
 * for it to finish.  In tests the real stdio.c is not linked, so we provide
 * a lightweight version here that actually runs the tool (needed so that
 * FormatNTFS / FormatExFAT can succeed on systems where mkntfs/mkfs.exfat
 * are installed, which is required for UEFI:NTFS partition tests).
 */
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
DWORD RunCommandWithProgress(const char *cmd, const char *dir,
                              BOOL log, int msg, const char *pattern)
{
    (void)log; (void)msg; (void)pattern;
    if (!cmd) return ERROR_INVALID_PARAMETER;
    pid_t pid = fork();
    if (pid < 0) return (DWORD)errno;
    if (pid == 0) {
        if (dir != NULL && chdir(dir) != 0) _exit(127);
        execl("/bin/sh", "sh", "-c", cmd, (char*)NULL);
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return (DWORD)errno;
    return WIFEXITED(status) ? (DWORD)WEXITSTATUS(status) : 1;
}

/*
 * InstallSyslinux stub — always returns FALSE so that tests can verify the
 * FormatThread wiring (it should set ErrorStatus to ERROR_INSTALL_FAILURE)
 * without requiring real syslinux/libfat infrastructure.
 *
 * The call_count lets tests assert whether InstallSyslinux was called at all.
 */
int install_syslinux_call_count = 0;

BOOL InstallSyslinux(DWORD drive_index, char drive_letter, int file_system)
{
    (void)drive_index; (void)drive_letter; (void)file_system;
    install_syslinux_call_count++;
    return FALSE; /* simulate failure: no real ldlinux data in tests */
}

/*
 * enable_bad_blocks / nb_passes_sel globals — owned by globals.c in
 * production but defined here so the format-thread test binary links.
 */
BOOL enable_bad_blocks = FALSE;
BOOL enable_verify_write = FALSE;
int  nb_passes_sel     = 0;

/*
 * BadBlocks stub — the format-thread tests don't exercise real block I/O;
 * a separate dedicated integration test (test_badblocks_integration) does.
 * Here we just record the call and return success with zero bad blocks.
 */
int bad_blocks_call_count = 0;

BOOL BadBlocks(HANDLE hPhysicalDrive, ULONGLONG disk_size, int nb_passes,
               int flash_type, badblocks_report *report, FILE *fd)
{
    (void)hPhysicalDrive; (void)disk_size; (void)nb_passes;
    (void)flash_type; (void)fd;
    bad_blocks_call_count++;
    if (report) {
        report->bb_count             = 0;
        report->num_read_errors      = 0;
        report->num_write_errors     = 0;
        report->num_corruption_errors = 0;
    }
    return TRUE;
}

/*
 * NotificationEx stub — returns IDOK for all calls in format-thread tests.
 */
int NotificationEx(int type, const char *dont_display_setting,
                   const notification_info *more_info, const char *title,
                   const char *format, ...)
{
    (void)type; (void)dont_display_setting; (void)more_info;
    (void)title; (void)format;
    return IDOK;
}

/* WUE stubs — format.c calls these after ISO extraction.  In
 * format-thread tests we don't exercise the Windows customisation path
 * so simple no-ops are sufficient. */
char *unattend_xml_path = NULL;
int   unattend_xml_flags = 0;
int   wintogo_index = -1;

void wue_set_mount_path(const char *path) { (void)path; }

BOOL SetupWinPE(char drive_letter)
{ (void)drive_letter; return TRUE; }

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{
    (void)drive_letter; (void)flags; return TRUE;
}

int setup_wintogo_call_count = 0;

BOOL SetupWinToGo(DWORD di, const char *dn, BOOL use_esp)
{
    setup_wintogo_call_count++;
    (void)di; (void)dn; (void)use_esp;
    return TRUE;
}

/* AltMountVolume/AltUnmountVolume stubs — for format_thread tests that use
 * image files (not block devices), the real implementation rejects non-block
 * paths.  Return a temporary directory so the WTG branch in format.c can
 * reach SetupWinToGo() without a real block device. */
#include <stdlib.h>
char *AltMountVolume(DWORD di, uint64_t off, BOOL bSilent)
{
    (void)di; (void)off; (void)bSilent;
    char template[] = "/tmp/rufus_wtg_XXXXXX";
    char *dir = mkdtemp(template);
    return dir ? strdup(dir) : NULL;
}

BOOL AltUnmountVolume(const char *dn, BOOL bSilent)
{
    (void)bSilent;
    if (!dn || dn[0] == '\0') return FALSE;
    rmdir(dn);
    return TRUE;
}

/* ExtractDOS is provided by dos.c which is only in DOS_LINUX_SRC / E2E tests.
 * For format_thread tests, use a no-op stub so the format path compiles and
 * returns success without actually extracting any files. */
BOOL ExtractDOS(const char *path) { (void)path; return TRUE; }

/* ExtractISOFile is provided by iso.c which is not linked in format_thread
 * tests.  The stub returns 0 (failure) so that HAS_KOLIBRIOS loader
 * installation just logs a warning but does not crash. */
int64_t extract_iso_file_call_count = 0;
char    extract_iso_file_last_src[256] = "";

int64_t ExtractISOFile(const char *iso, const char *iso_file,
                       const char *dest_file, DWORD attributes)
{
    extract_iso_file_call_count++;
    if (iso_file)
        snprintf(extract_iso_file_last_src, sizeof(extract_iso_file_last_src),
                 "%s", iso_file);
    (void)iso; (void)dest_file; (void)attributes;
    return 0; /* simulate "not found" */
}

/* vhd.c symbols needed when vhd.c is linked into format thread tests */
BOOL   ignore_boot_marker = FALSE;
BOOL   has_ffu_support    = FALSE;
FILE*    fd_md5sum    = NULL;
uint64_t total_blocks = 0, extra_blocks = 0, nb_blocks = 0, last_nb_blocks = 0;
BOOL HashFile(unsigned type, const char* path, uint8_t* sum)
{ (void)type; (void)path; (void)sum; return FALSE; }

void wuprintf(const wchar_t *fmt, ...) { (void)fmt; }
