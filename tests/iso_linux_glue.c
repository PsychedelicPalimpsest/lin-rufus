/*
 * iso_linux_glue.c — Test stubs needed by iso.c when libfat is linked in.
 *
 * LIBFAT_SECTOR_SIZE / _SHIFT / _MASK are normally defined in syslinux.c,
 * but the iso test does not include syslinux.c.  A 512-byte sector is the
 * standard size for FAT filesystems embedded in EFI images.
 */
#include <stdint.h>

uint32_t LIBFAT_SECTOR_SHIFT = 9;
uint32_t LIBFAT_SECTOR_SIZE  = 512;
uint32_t LIBFAT_SECTOR_MASK  = 511;
