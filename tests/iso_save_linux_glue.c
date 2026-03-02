/*
 * iso_save_linux_glue.c — Stubs needed by iso.c in test_iso_save_linux
 * that are NOT provided by the compiled sources (iso.c, stdfn.c, stdio.c,
 * localization.c).
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

/* libfat constants (iso.c uses them; syslinux.c normally defines them) */
uint32_t LIBFAT_SECTOR_SHIFT = 9;
uint32_t LIBFAT_SECTOR_SIZE  = 512;
uint32_t LIBFAT_SECTOR_MASK  = 511;

/* windows_version_t stub */
windows_version_t WindowsVersion = { 0 };

/* InitProgress / UpdateProgress — no-ops (test_iso_save_linux.c provides the
 * tracking _UpdateProgressWithInfo; the others are untested). */
void InitProgress(BOOL b) { (void)b; }
void UpdateProgress(int op, float pct) { (void)op; (void)pct; }

/* GetOpticalMedia: returns FALSE → OpticalDiscSaveImage() returns early. */
BOOL GetOpticalMedia(IMG_SAVE* img_save)
{
(void)img_save;
return FALSE;
}

/* FileDialog: not reached in unit tests. */
char* FileDialog(BOOL save, char* path, const ext_t* ext, UINT* sel)
{
(void)save; (void)path; (void)ext; (void)sel;
return NULL;
}

/* EnableControls: no-op in tests */
void EnableControls(BOOL enable, BOOL remove_checkboxes)
{
(void)enable; (void)remove_checkboxes;
}

/* get_token_data_file_indexed: used by IsFilteredDrive / settings paths */
char* get_token_data_file_indexed(const char* token, const char* filename, int index)
{
	(void)token; (void)filename; (void)index;
	return NULL;
}
