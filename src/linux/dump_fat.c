/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: DumpFatDir — extract EFI files from a FAT image in an ISO.
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * DumpFatDir / iso9660_readfat — split out from iso.c so tests can intercept
 * DumpFatDir via the linker --wrap mechanism (intra-TU calls are not wrappable).
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <cdio/iso9660.h>

#include "rufus.h"
#include "missing.h"
#include "syslinux/libfat/libfat.h"
#include "iso_private.h"

/* Globals declared elsewhere */
extern char               *image_path;
extern RUFUS_IMG_REPORT    img_report;
extern DWORD               ErrorStatus;

/*
 * iso9660_readfat - libfat sector-reader callback.
 *
 * Reads sectors from a FAT image residing on an ISO-9660 filesystem.
 * The private structure caches ISO_NB_BLOCKS contiguous ISO blocks so that
 * sequential FAT reads avoid re-reading the ISO for every sector.
 *
 * Returns secsize on success, 0 on error (matches libfat contract).
 */
int iso9660_readfat(intptr_t pp, void *buf, size_t secsize, libfat_sector_t sec)
{
	iso9660_readfat_private *p = (iso9660_readfat_private *)(void *)pp;

	if (sizeof(p->buf) % secsize != 0) {
		uprintf("iso9660_readfat: sector size %zu is not a divisor of %zu",
		        secsize, sizeof(p->buf));
		return 0;
	}

	libfat_sector_t slots = (libfat_sector_t)(sizeof(p->buf) / secsize);
	if (sec < p->sec_start || sec >= p->sec_start + slots) {
		/* Sector is outside the cache window — reload */
		p->sec_start = (libfat_sector_t)(((sec * secsize) / ISO_BLOCKSIZE)
		               * ISO_BLOCKSIZE / secsize);
		ssize_t nr = iso9660_iso_seek_read(p->p_iso, p->buf,
		             p->lsn + (lsn_t)((p->sec_start * secsize) / ISO_BLOCKSIZE),
		             ISO_NB_BLOCKS);
		if (nr != (ssize_t)(ISO_NB_BLOCKS * ISO_BLOCKSIZE)) {
			uprintf("iso9660_readfat: read error at LSN %lu",
			        (long unsigned int)(p->lsn + p->sec_start * secsize / ISO_BLOCKSIZE));
			return 0;
		}
	}

	memcpy(buf, &p->buf[(sec - p->sec_start) * secsize], secsize);
	return (int)secsize;
}

/*
 * wchar16_to_utf8 - Convert a wchar_t[] array containing UTF-16 code units
 * (as stored by libfat's read16() calls on Linux where wchar_t is 4 bytes)
 * to a UTF-8 string.  Returns a pointer to a static buffer (not thread-safe).
 */
static char *wchar16_to_utf8(const wchar_t *wsrc)
{
	static char buf[1024];
	size_t n = 0;
	for (int i = 0; wsrc[i] && n < sizeof(buf) - 4; i++) {
		uint32_t c = (uint32_t)(uint16_t)wsrc[i];
		/* Decode surrogate pair if present */
		if (c >= 0xD800 && c <= 0xDBFF && wsrc[i + 1]) {
			uint32_t low = (uint32_t)(uint16_t)wsrc[i + 1];
			if (low >= 0xDC00 && low <= 0xDFFF) {
				c = 0x10000u + ((c - 0xD800u) << 10) + (low - 0xDC00u);
				i++;
			}
		}
		if (c < 0x80) {
			buf[n++] = (char)c;
		} else if (c < 0x800) {
			buf[n++] = (char)(0xC0 | (c >> 6));
			buf[n++] = (char)(0x80 | (c & 0x3F));
		} else if (c < 0x10000) {
			buf[n++] = (char)(0xE0 | (c >> 12));
			buf[n++] = (char)(0x80 | ((c >> 6) & 0x3F));
			buf[n++] = (char)(0x80 | (c & 0x3F));
		} else {
			buf[n++] = (char)(0xF0 | (c >> 18));
			buf[n++] = (char)(0x80 | ((c >> 12) & 0x3F));
			buf[n++] = (char)(0x80 | ((c >> 6) & 0x3F));
			buf[n++] = (char)(0x80 | (c & 0x3F));
		}
	}
	buf[n] = '\0';
	return buf;
}

/* write_all — write exactly n bytes, retrying on EINTR */
static BOOL dump_write_all(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	while (n > 0) {
		ssize_t w = write(fd, p, n);
		if (w < 0) {
			if (errno == EINTR) continue;
			return FALSE;
		}
		p += w;
		n -= (size_t)w;
	}
	return TRUE;
}

BOOL DumpFatDir(const char* path, int32_t cluster)
{
	/* No concurrent calls — a static lf_fs is safe (mirrors the Windows impl). */
	static struct libfat_filesystem *lf_fs = NULL;
	void *buf;
	char *target = NULL, *name = NULL;
	BOOL ret = FALSE;
	int fd = -1;
	DWORD written;
	libfat_diritem_t diritem = { 0 };
	libfat_dirpos_t dirpos = { cluster, -1, 0 };
	libfat_sector_t s;
	iso9660_t *p_iso = NULL;
	iso9660_stat_t *p_statbuf = NULL;
	iso9660_readfat_private *p_private = NULL;

	if (path == NULL)
		return FALSE;

	if (cluster == 0) {
		/* Root dir — open ISO and mount the FAT image from img_report.efi_img_path */
		if (image_path == NULL)
			return FALSE;
		p_iso = iso9660_open_ext(image_path, ISO_EXTENSION_ALL);
		if (p_iso == NULL) {
			uprintf("Could not open image '%s' as an ISO-9660 file system", image_path);
			goto out;
		}
		p_statbuf = iso9660_ifs_stat_translate(p_iso, img_report.efi_img_path);
		if (p_statbuf == NULL) {
			uprintf("Could not get ISO-9660 file information for file %s", img_report.efi_img_path);
			goto out;
		}
		p_private = malloc(sizeof(iso9660_readfat_private));
		if (p_private == NULL)
			goto out;
		p_private->p_iso = p_iso;
		p_private->lsn = p_statbuf->lsn;
		p_private->sec_start = 0;
		if (iso9660_iso_seek_read(p_private->p_iso, p_private->buf, p_private->lsn, ISO_NB_BLOCKS)
		    != ISO_NB_BLOCKS * ISO_BLOCKSIZE) {
			uprintf("Error reading ISO-9660 file %s at LSN %lu",
			        img_report.efi_img_path, (long unsigned int)p_private->lsn);
			goto out;
		}
		lf_fs = libfat_open(iso9660_readfat, (intptr_t)p_private);
		if (lf_fs == NULL) {
			uprintf("FAT access error");
			goto out;
		}
	}

	do {
		dirpos.cluster = libfat_dumpdir(lf_fs, &dirpos, &diritem);
		if (dirpos.cluster >= 0) {
			name = safe_strdup(wchar16_to_utf8(diritem.name));
			target = malloc(strlen(path) + safe_strlen(name) + 2);
			if ((name == NULL) || (target == NULL)) {
				uprintf("Could not allocate buffer");
				goto out;
			}
			strcpy(target, path);
			strcat(target, "/");
			strcat(target, name);
			if (diritem.attributes & 0x10) {
				/* Directory entry */
				if (mkdir(target, 0755) != 0 && errno != EEXIST) {
					uprintf_errno("Could not create directory '%s'", target);
					/* continue rather than abort */
				} else if (!DumpFatDir(target, dirpos.cluster)) {
					goto out;
				}
			} else if (access(target, F_OK) != 0) {
				/* File does not yet exist — extract it */
				uprintf("Extracting: %s (from '%s', %s)", target,
				        img_report.efi_img_path,
				        SizeToHumanReadable(diritem.size, FALSE, FALSE));
				fd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0644);
				if (fd < 0) {
					uprintf_errno("Could not create '%s'", target);
					/* continue */
				} else {
					written = 0;
					s = libfat_clustertosector(lf_fs, dirpos.cluster);
					while ((s != 0) && (s < 0xFFFFFFFFULL) && (written < diritem.size)) {
						buf = libfat_get_sector(lf_fs, s);
						if (buf == NULL)
							ErrorStatus = RUFUS_ERROR(ERROR_SECTOR_NOT_FOUND);
						if (IS_ERROR(ErrorStatus))
							goto out;
						DWORD size = MIN(LIBFAT_SECTOR_SIZE, diritem.size - written);
						if (!dump_write_all(fd, buf, size)) {
							uprintf_errno("Could not write '%s'", target);
							break;
						}
						written += size;
						s = libfat_nextsector(lf_fs, s);
						libfat_flush(lf_fs);
					}
					close(fd); fd = -1;
				}
			}
			safe_free(target);
			safe_free(name);
		}
	} while (dirpos.cluster >= 0);
	ret = TRUE;

out:
	if (cluster == 0) {
		if (lf_fs != NULL) {
			libfat_close(lf_fs);
			lf_fs = NULL;
		}
		iso9660_stat_free(p_statbuf);
		iso9660_close(p_iso);
		safe_free(p_private);
	}
	if (fd >= 0) { close(fd); fd = -1; }
	safe_free(target);
	safe_free(name);
	return ret;
}
