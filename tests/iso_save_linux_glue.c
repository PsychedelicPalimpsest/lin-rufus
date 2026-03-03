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
#include "../src/windows/drive.h"

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

/* img_report is normally defined in globals.c but iso tests don't link it */
RUFUS_IMG_REPORT img_report = { 0 };

/* persistence_size is defined in globals.c; needed by fix_config() in iso.c */
uint64_t persistence_size = 0;

/* update is defined in globals.c; needed by parse_update() in parser.c */
RUFUS_UPDATE update = { {0,0,0}, {0,0}, NULL, NULL };

/* Symbols needed when vhd.c is included */
BOOL has_ffu_support   = FALSE;
BOOL ignore_boot_marker = FALSE;

uint16_t GetSyslinuxVersion(char *buf, size_t buf_size, char **ext)
    { (void)buf; (void)buf_size; (void)ext; return 0; }
uint16_t embedded_sl_version[2] = { 0, 0 };

void GetGrubVersion(char *buf, size_t buf_size, const char *source)
    { (void)buf; (void)buf_size; (void)source; }
void GetGrubFs(char *buf, size_t buf_size, StrArray *filesystems)
    { (void)buf; (void)buf_size; (void)filesystems; }
void GetEfiBootInfo(char *buf, size_t buf_size, const char *source)
    { (void)buf; (void)buf_size; (void)source; }

BOOL AnalyzeMBR(HANDLE h, const char *name, BOOL s)
    { (void)h; (void)name; (void)s; return FALSE; }
BOOL HashFile(unsigned type, const char *path, uint8_t *sum)
    { (void)type; (void)path; memset(sum, 0, 16); return TRUE; }

/* ini_file needed by inline WriteIniKeyStr in settings.h */
char *ini_file = NULL;

/* SaveImage() globals */
char *save_image_type = NULL;
__attribute__((weak)) RUFUS_DRIVE_INFO SelectedDrive = { 0 };
__attribute__((weak)) HWND hDeviceList = NULL;
char *GetPhysicalName(DWORD DriveIndex) { (void)DriveIndex; return NULL; }
