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
 * RunCommandWithProgress stub — format_ext_tools.c (FormatNTFS/FormatExFAT)
 * calls this for external formatters.  In the format-thread tests we don't
 * need real NTFS/exFAT output, so just return failure so the test can
 * observe that the function was reachable.
 */
DWORD RunCommandWithProgress(const char *cmd, const char *dir,
                              BOOL log, int msg, const char *pattern)
{
    (void)cmd; (void)dir; (void)log; (void)msg; (void)pattern;
    return 1; /* simulate "tool not found / failed" */
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

void wue_set_mount_path(const char *path) { (void)path; }

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{
    (void)drive_letter; (void)flags; return TRUE;
}
