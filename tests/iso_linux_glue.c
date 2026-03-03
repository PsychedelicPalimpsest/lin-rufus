/*
 * iso_linux_glue.c — Test stubs needed by iso.c when libfat is linked in.
 *
 * LIBFAT_SECTOR_SIZE / _SHIFT / _MASK are normally defined in syslinux.c,
 * but the iso test does not include syslinux.c.  A 512-byte sector is the
 * standard size for FAT filesystems embedded in EFI images.
 *
 * Also provides stubs for OpticalDiscSaveImage() dependencies that come
 * from dev.c and stdlg.c in the main binary.
 */
#include <stdint.h>
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

uint32_t LIBFAT_SECTOR_SHIFT = 9;
uint32_t LIBFAT_SECTOR_SIZE  = 512;
uint32_t LIBFAT_SECTOR_MASK  = 511;

/* Stubs for OpticalDiscSaveImage() — dev.c / stdlg.c symbols */
BOOL GetOpticalMedia(IMG_SAVE* s) { (void)s; return FALSE; }

char *FileDialog(BOOL save, char* path, const ext_t* ext, UINT* sel)
{ (void)save; (void)path; (void)ext; (void)sel; return NULL; }

/* img_report is normally defined in globals.c but iso tests don't link it */
RUFUS_IMG_REPORT img_report = { 0 };

/* update / WindowsVersion — needed by linux/parser.c (parse_update) */
RUFUS_UPDATE update = { {0,0,0}, {0,0}, NULL, NULL };
windows_version_t WindowsVersion = { 0 };

/* Syslinux embedded fallback versions (normally set at startup from bundled ldlinux files) */
uint16_t embedded_sl_version[2] = { 0, 0 };

/* --wrap=DumpFatDir: intercept DumpFatDir calls from iso.c for testing */
int g_dumpfatdir_call_count = 0;
const char *g_dumpfatdir_last_path = NULL;

BOOL __real_DumpFatDir(const char *path, int32_t cluster);
BOOL __wrap_DumpFatDir(const char *path, int32_t cluster)
{
    g_dumpfatdir_call_count++;
    g_dumpfatdir_last_path = path;
    return __real_DumpFatDir(path, cluster);
}

/* --wrap=GetWimVersion: intercept GetWimVersion calls from iso.c for testing */
int g_getwimversion_call_count = 0;
char g_getwimversion_last_path[512] = {0};
uint32_t g_getwimversion_return_value = 0x000E0000; /* default: WIM version 14 */

uint32_t __wrap_GetWimVersion(const char* image)
{
    g_getwimversion_call_count++;
    if (image != NULL)
        snprintf(g_getwimversion_last_path, sizeof(g_getwimversion_last_path),
                 "%s", image);
    return g_getwimversion_return_value;
}
