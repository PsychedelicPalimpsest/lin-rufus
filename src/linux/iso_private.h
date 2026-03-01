/*
 * iso_private.h — Internal types shared between iso.c and its tests.
 *
 * Not a public API; include only from iso.c and iso test files.
 */
#pragma once
#include <stdint.h>
#include <cdio/iso9660.h>
#include "syslinux/libfat/libfat.h"

#define ISO_NB_BLOCKS 16

/* Private structure for the iso9660_readfat sector-reader callback.
 * Caches ISO_NB_BLOCKS ISO blocks (ISO_BLOCKSIZE = 2048 bytes each) so that
 * sequential libfat sector reads avoid re-reading the ISO for every sector. */
typedef struct {
	iso9660_t      *p_iso;
	lsn_t           lsn;
	libfat_sector_t sec_start;
	uint8_t         buf[2048 * ISO_NB_BLOCKS]; /* 2048 = ISO_BLOCKSIZE */
} iso9660_readfat_private;
