/*
 * format_thread_linux_glue.c — stubs for symbols needed by drive.c that
 * are not defined by test_format_thread_linux.c's own stub section.
 *
 * These symbols live in stdio.c and stdfn.c in production but are not
 * needed functionally by the format-thread tests.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

char *GuidToString(const GUID *guid, BOOL bDecorated)
{
    (void)guid; (void)bDecorated; return NULL;
}

BOOL CompareGUID(const GUID *g1, const GUID *g2)
{
    if (!g1 || !g2) return FALSE;
    return (__builtin_memcmp(g1, g2, sizeof(GUID)) == 0) ? TRUE : FALSE;
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
