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
