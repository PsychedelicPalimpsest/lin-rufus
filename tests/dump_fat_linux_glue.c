/*
 * dump_fat_linux_glue.c — minimal stubs for test_dump_fat_linux.
 *
 * Provides LIBFAT_SECTOR_* constants (normally from syslinux.c)
 * and other symbols needed to link dump_fat.c in isolation.
 */
#include <stdint.h>

/* libfat sector constants — real values from syslinux.c */
uint32_t LIBFAT_SECTOR_SHIFT = 9;
uint32_t LIBFAT_SECTOR_SIZE  = 512;
uint32_t LIBFAT_SECTOR_MASK  = 511;
