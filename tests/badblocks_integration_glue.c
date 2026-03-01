/*
 * badblocks_integration_glue.c
 *
 * Stubs needed by the format.c / drive.c compilation unit in the
 * test_badblocks_integration_linux binary.  The symbols that are
 * test-specific (BadBlocks, NotificationEx, enable_bad_blocks,
 * nb_passes_sel, InstallSyslinux, RunCommandWithProgress) are
 * defined directly in test_badblocks_integration_linux.c.
 */
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

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

windows_version_t WindowsVersion = { 0 };

char *get_token_data_file_indexed(const char *token, const char *filename,
                                   const int index)
{
    (void)token; (void)filename; (void)index; return NULL;
}

/* _win_last_error — owned by stdfn.c in production */
DWORD _win_last_error = 0;

/* WUE stubs for format.c */
char *unattend_xml_path = NULL;
int   unattend_xml_flags = 0;

void wue_set_mount_path(const char *path) { (void)path; }

BOOL ApplyWindowsCustomization(char drive_letter, int flags)
{
    (void)drive_letter; (void)flags; return TRUE;
}
