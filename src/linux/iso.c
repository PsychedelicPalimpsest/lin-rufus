/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: iso.c - ISO image scan and extraction
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

/* Use system libcdio */
#include <cdio/cdio.h>
#include <cdio/logging.h>
#include <cdio/iso9660.h>
#include <cdio/udf.h>

#include "rufus.h"
#include "resource.h"
#include "localization.h"
#include "missing.h"
#include "virtdisk.h"
#include "ui.h"
#include "syslinux/libfat/libfat.h"

/* ---- constants ---- */
#define PROGRESS_THRESHOLD   ((256 * KB) / ISO_BLOCKSIZE)
#define ISO_EXTENSION_MASK   (ISO_EXTENSION_ALL \
	& (enable_joliet    ? ISO_EXTENSION_ALL : ~ISO_EXTENSION_JOLIET) \
	& (enable_rockridge ? ISO_EXTENSION_ALL : ~ISO_EXTENSION_ROCK_RIDGE))

#include "iso_private.h"
#include "iso_scan.h"
#include "../common/iso_config.h"

/* ---- globals (defined here, extern in rufus.h or ui.h) ---- */
FILE*    fd_md5sum          = NULL;
int64_t  iso_blocking_status = -1;
uint64_t total_blocks, extra_blocks, nb_blocks, last_nb_blocks;

BOOL enable_iso        = TRUE;
BOOL enable_joliet     = TRUE;
BOOL enable_rockridge  = TRUE;
BOOL has_ldlinux_c32   = FALSE;

const char* bootmgr_efi_name = "bootmgr.efi";
const char* efi_dirname      = "/efi/boot";
const char* efi_bootname[3]  = { "boot", "grub", "mm" };
const char* efi_archname[ARCH_MAX] = {
	"", "ia32", "x64", "arm", "aa64", "ia64", "riscv64", "loongarch64", "ebc"
};
const char* md5sum_name[2]   = { "md5sum.txt", "MD5SUMS" };
const char* old_c32_name[NB_OLD_C32] = OLD_C32_NAMES;

/* Non-static so the test suite can use them */
StrArray config_path, isolinux_path, grub_filesystems;

/* extern declarations for globals defined in other TUs */
extern uint64_t    md5sum_totalbytes;
extern BOOL        preserve_timestamps, enable_ntfs_compression, validate_md5sum;
extern HANDLE      format_thread;
extern StrArray    modified_files;

/* extern declarations for functions defined in other TUs */
extern BOOL GetOpticalMedia(IMG_SAVE* img_save);
extern void EnableControls(BOOL enable, BOOL remove_checkboxes);

/* ---- file-static state ---- */
static BOOL         scan_only          = FALSE;
static const char*  psz_extract_dir    = NULL;
static uint8_t      joliet_level       = 0;
static uint32_t     md5sum_size        = 0;
static char*        md5sum_data        = NULL;
static char*        md5sum_pos         = NULL;
static char         symlinked_syslinux[MAX_PATH];

/* ---- constants used for file classification ---- */
static const char* bootmgr_name     = "bootmgr";
static const char* grldr_name       = "grldr";
static const char* ldlinux_name     = "ldlinux.sys";
static const char* ldlinux_c32      = "ldlinux.c32";
static const char* casper_dirname   = "/casper";
static const char* proxmox_dirname  = "/proxmox";
static const char* sources_str      = "/sources";
static const char* wininst_name[]   = { "install.wim", "install.esd", "install.swm" };
static const char* grub_dirname[]   = { "/boot/grub/i386-pc", "/boot/grub2/i386-pc" };
static const char* grub_cfg[]       = { "grub.cfg", "loopback.cfg" };
static const char* menu_cfg         = "menu.cfg";
static const char* syslinux_cfg[]   = { "isolinux.cfg", "syslinux.cfg", "extlinux.conf",
                                        "txt.cfg", "live.cfg" };
static const char* isolinux_bin[]   = { "isolinux.bin", "boot.bin" };
static const char* pe_dirname[]     = { "/i386", "/amd64", "/minint" };
static const char* pe_file[]        = { "ntdetect.com", "setupldr.bin", "txtsetup.sif" };
static const char* reactos_name[]   = { "setupldr.sys", "freeldr.sys" };
static const char* kolibri_name     = "kolibri.img";
static const char* manjaro_marker   = ".miso";
static const char* pop_os_name      = "pop-os";
static const int64_t old_c32_threshold[NB_OLD_C32] = OLD_C32_THRESHOLD;

/* ------------------------------------------------------------------ */
/* Internal types (EXTRACT_PROPS is defined in common/iso_config.h)    */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void log_handler(cdio_log_level_t level, const char* message)
{
	if (level >= CDIO_LOG_WARN)
		uprintf("libcdio: %s", message);
}

/*
 * Sanitize a filename: replace characters that are invalid on FAT32/NTFS.
 * Returns a newly allocated copy; the caller must free it.
 */
static char* sanitize_filename(const char* filename, BOOL* is_identical)
{
	static const char bad[] = { '*', '?', '<', '>', ':', '|' };
	size_t i, j;
	char* ret = safe_strdup(filename);
	if (!ret) { uprintf("Could not allocate sanitized path"); return NULL; }
	*is_identical = TRUE;
	for (i = 0; i < strlen(ret); i++) {
		for (j = 0; j < sizeof(bad); j++) {
			if (ret[i] == bad[j]) { ret[i] = '_'; *is_identical = FALSE; }
		}
	}
	return ret;
}

/* Create all parent directories for path (like `mkdir -p`). */
static void mkdirp(const char* path)
{
	char tmp[MAX_PATH];
	char* p;
	size_t len = safe_strlen(path);
	if (len == 0 || len >= sizeof(tmp)) return;
	memcpy(tmp, path, len + 1);
	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(tmp, 0755);
			*p = '/';
		}
	}
	mkdir(tmp, 0755);
}

/* Write all bytes of a buffer to an fd, retrying on EINTR. */
static BOOL write_all(int fd, const void* buf, size_t len)
{
	const uint8_t* p = (const uint8_t*)buf;
	while (len > 0) {
		ssize_t w = write(fd, p, len);
		if (w < 0) {
			if (errno == EINTR) continue;
			return FALSE;
		}
		p   += w;
		len -= (size_t)w;
	}
	return TRUE;
}

/* ------------------------------------------------------------------ */
/* Config-file patching (post-extraction)                              */
/* ------------------------------------------------------------------ */

/* POSIX file copy callback used by iso_patch_config_file for Tails workaround */
static BOOL posix_copy_file(const char* src, const char* dst)
{
	char buf[4096];
	int rfd = open(src, O_RDONLY);
	if (rfd < 0) return FALSE;
	int wfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (wfd < 0) { close(rfd); return FALSE; }
	ssize_t n;
	while ((n = read(rfd, buf, sizeof(buf))) > 0)
		if (write(wfd, buf, (size_t)n) != n) { close(rfd); close(wfd); return FALSE; }
	close(rfd);
	close(wfd);
	return n == 0;
}

/* Wrapper that calls iso_patch_config_file() with runtime globals */
static void fix_config(const char* psz_fullpath, const char* psz_path,
                       const char* psz_basename, EXTRACT_PROPS* props)
{
	iso_patch_config_file(
		psz_fullpath, psz_path, psz_basename, props,
		boot_type,
		persistence_size,
		HAS_PERSISTENCE(img_report),
		img_report.rh8_derivative,
		img_report.has_efi_syslinux,
		img_report.label,
		img_report.usb_label,
		image_path,
		&modified_files,
		posix_copy_file);
}

/* ------------------------------------------------------------------ */
/* Property detection (scan-time and extract-time analysis)            */
/* ------------------------------------------------------------------ */

#include "../common/iso_check.c"

/* ------------------------------------------------------------------ */
/* UDF extraction                                                       */
/* ------------------------------------------------------------------ */

static int udf_extract_files(udf_t* p_udf, udf_dirent_t* p_udf_dirent,
                              const char* psz_path)
{
	EXTRACT_PROPS props;
	int fd = -1, r = 1;
	int64_t file_length;
	char *psz_fullpath = NULL, *psz_sanpath = NULL;
	const char* psz_basename;
	udf_dirent_t* p_udf_dirent2;
	BOOL is_identical;
	uint8_t* buf;
	size_t nb;

	buf = (uint8_t*)malloc(ISO_BUFFER_SIZE);
	if (!p_udf_dirent || !psz_path || !buf) { free(buf); return 1; }

	if (psz_path[0] == '\0')
		UpdateProgressWithInfoInit(NULL, TRUE);

	while ((p_udf_dirent = udf_readdir(p_udf_dirent)) != NULL) {
		if (ErrorStatus) goto out;
		psz_basename = udf_get_filename(p_udf_dirent);
		if (!psz_basename || strlen(psz_basename) == 0) continue;

		int path_len = (int)(3 + strlen(psz_path) + strlen(psz_basename) +
		                     (psz_extract_dir ? strlen(psz_extract_dir) : 0) + 4);
		psz_fullpath = (char*)calloc(1, (size_t)path_len);
		if (!psz_fullpath) { uprintf("Out of memory for path"); goto out; }

		if (psz_extract_dir)
			snprintf(psz_fullpath, (size_t)path_len, "%s%s/%s",
			         psz_extract_dir, psz_path, psz_basename);
		else
			snprintf(psz_fullpath, (size_t)path_len, "%s/%s",
			         psz_path, psz_basename);

		if (udf_is_dir(p_udf_dirent)) {
			if (!scan_only) {
				psz_sanpath = sanitize_filename(psz_fullpath, &is_identical);
				if (psz_sanpath) { mkdirp(psz_sanpath); safe_free(psz_sanpath); }
			}
			p_udf_dirent2 = udf_opendir(p_udf_dirent);
			if (p_udf_dirent2) {
				const char* rel = psz_extract_dir ?
					&psz_fullpath[strlen(psz_extract_dir)] : psz_fullpath;
				if (udf_extract_files(p_udf, p_udf_dirent2, rel))
					goto out;
			}
		} else {
			file_length = udf_get_file_length(p_udf_dirent);
			const char* rel = psz_extract_dir ?
				&psz_fullpath[strlen(psz_extract_dir)] : psz_fullpath;
			if (check_iso_props(psz_path, file_length, psz_basename,
			                    psz_fullpath, &props)) {
				safe_free(psz_fullpath);
				continue;
			}
			uprintf("Extracting: %s", rel);
			psz_sanpath = sanitize_filename(psz_fullpath, &is_identical);
			if (!psz_sanpath) goto out;
			/* Ensure parent directory exists */
			{
				char* slash = strrchr(psz_sanpath, '/');
				if (slash) { *slash = '\0'; mkdirp(psz_sanpath); *slash = '/'; }
			}
			fd = open(psz_sanpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fd < 0) {
				uprintf_errno("  Unable to create '%s'", psz_sanpath);
				goto out;
			}
			while (file_length > 0) {
				if (ErrorStatus) goto out;
				nb = (size_t)MIN(ISO_BUFFER_SIZE / UDF_BLOCKSIZE,
				                 (size_t)((file_length + UDF_BLOCKSIZE - 1) / UDF_BLOCKSIZE));
				ssize_t read_n = udf_read_block(p_udf_dirent, buf, (long int)nb);
				if (read_n < 0) {
					uprintf("  Error reading UDF file %s", rel); goto out;
				}
				size_t to_write = (size_t)MIN(file_length, read_n);
				if (!write_all(fd, buf, to_write)) {
					uprintf_errno("  Error writing"); goto out;
				}
				file_length -= (int64_t)to_write;
				nb_blocks   += nb;
				if (nb_blocks - last_nb_blocks >= PROGRESS_THRESHOLD) {
					UpdateProgressWithInfo(OP_FILE_COPY, MSG_231, nb_blocks, total_blocks);
					last_nb_blocks = nb_blocks;
				}
			}
			close(fd); fd = -1;
			fix_config(psz_sanpath, psz_path, psz_basename, &props);
			safe_free(psz_sanpath);
		}
		safe_free(psz_fullpath);
	}
	r = 0;
out:
	if (fd >= 0) close(fd);
	udf_dirent_free(p_udf_dirent);
	safe_free(psz_sanpath);
	safe_free(psz_fullpath);
	free(buf);
	return r;
}

/* ------------------------------------------------------------------ */
/* ISO9660 extraction                                                   */
/* ------------------------------------------------------------------ */

static int iso_extract_files(iso9660_t* p_iso, const char* psz_path)
{
	EXTRACT_PROPS props;
	CdioListNode_t* p_entnode;
	CdioISO9660FileList_t* p_entlist = NULL;
	iso9660_stat_t* p_statbuf;
	uint8_t* buf;
	int r = 1, fd = -1;
	int64_t file_length;
	BOOL is_identical;
	char psz_fullpath[MAX_PATH], *psz_basename_ptr, *psz_sanpath = NULL;
	lsn_t lsn;
	size_t nb, i;

	buf = (uint8_t*)malloc(ISO_BUFFER_SIZE);
	if (!p_iso || !psz_path || !buf) { free(buf); return 1; }

	/* Build base dir path: "<extract_dir><psz_path>/" */
	int base_len = snprintf(psz_fullpath, sizeof(psz_fullpath), "%s%s/",
	                        psz_extract_dir ? psz_extract_dir : "", psz_path);
	if (base_len < 0 || base_len >= (int)sizeof(psz_fullpath)) goto out;
	psz_basename_ptr = &psz_fullpath[base_len];

	/* The ISO name (relative to extract dir) */
	const char* psz_iso_base = psz_extract_dir ?
		&psz_fullpath[strlen(psz_extract_dir)] : psz_fullpath;

	p_entlist = iso9660_ifs_readdir(p_iso, psz_path[0] ? psz_path : "/");
	if (!p_entlist) { uprintf("Could not read directory '%s'", psz_path); goto out; }

	if (psz_path[0] == '\0')
		UpdateProgressWithInfoInit(NULL, TRUE);

	_CDIO_LIST_FOREACH(p_entnode, p_entlist) {
		if (ErrorStatus) goto out;
		p_statbuf = (iso9660_stat_t*)_cdio_list_node_data(p_entnode);

		if (strcmp(p_statbuf->filename, ".") == 0 ||
		    strcmp(p_statbuf->filename, "..") == 0)
			continue;

		/* Translate filename */
		if ((p_statbuf->rr.b3_rock == yep) && enable_rockridge) {
			safe_strcpy(psz_basename_ptr,
			            sizeof(psz_fullpath) - (size_t)base_len - 1,
			            p_statbuf->filename);
			if (safe_strlen(p_statbuf->filename) > 64)
				img_report.has_long_filename = TRUE;
			if (p_statbuf->rr.psz_symlink)
				img_report.has_symlinks = SYMLINKS_RR;
		} else {
			iso9660_name_translate_ext(p_statbuf->filename, psz_basename_ptr, joliet_level);
		}

		if (p_statbuf->type == _STAT_DIR) {
			if (!scan_only) {
				psz_sanpath = sanitize_filename(psz_fullpath, &is_identical);
				if (psz_sanpath) { mkdirp(psz_sanpath); safe_free(psz_sanpath); }
			}
			r = iso_extract_files(p_iso, psz_iso_base);
			if (r > 0) goto out;
			if (r < 0) break; /* deep dir short-circuit */
		} else {
			file_length = p_statbuf->total_size;

			if (check_iso_props(psz_path, file_length, psz_basename_ptr,
			                    psz_fullpath, &props)) {
				continue; /* scan_only or skip */
			}

			uprintf("Extracting: %s", psz_iso_base);
			psz_sanpath = sanitize_filename(psz_fullpath, &is_identical);
			if (!psz_sanpath) goto out;

			/* Handle symlinks on Linux: create real symlink */
			if ((p_statbuf->rr.b3_rock == yep) && p_statbuf->rr.psz_symlink &&
			    file_length == 0) {
				/* Create symlink relative to directory */
				if (symlink(p_statbuf->rr.psz_symlink, psz_sanpath) < 0 &&
				    errno != EEXIST)
					uprintf_errno("  Could not create symlink");
				safe_free(psz_sanpath);
				continue;
			}

			/* Ensure parent directory exists */
			{
				char* slash = strrchr(psz_sanpath, '/');
				if (slash) { *slash = '\0'; mkdirp(psz_sanpath); *slash = '/'; }
			}

			fd = open(psz_sanpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fd < 0) {
				/* Try creating parent directory and retry */
				char* slash = strrchr(psz_sanpath, '/');
				if (slash) {
					*slash = '\0';
					mkdirp(psz_sanpath);
					*slash = '/';
					fd = open(psz_sanpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
				}
				if (fd < 0) {
					uprintf_errno("  Unable to create '%s'", psz_sanpath);
					goto out;
				}
			}

			for (i = 0; file_length > 0; i += nb) {
				if (ErrorStatus) goto out;
				lsn = p_statbuf->lsn + (lsn_t)i;
				nb  = (size_t)MIN((size_t)(ISO_BUFFER_SIZE / ISO_BLOCKSIZE),
				                  (size_t)((file_length + ISO_BLOCKSIZE - 1) / ISO_BLOCKSIZE));
				ssize_t nrd = iso9660_iso_seek_read(p_iso, buf, lsn, (long int)nb);
				if (nrd != (ssize_t)(nb * ISO_BLOCKSIZE)) {
					uprintf("  Read error at LSN %u for '%s'", (unsigned)lsn, psz_iso_base);
					goto out;
				}
				size_t to_write = (size_t)MIN((int64_t)(nb * ISO_BLOCKSIZE), file_length);
				if (!write_all(fd, buf, to_write)) {
					uprintf_errno("  Write error"); goto out;
				}
				file_length -= (int64_t)to_write;
				nb_blocks   += nb;
				if (nb_blocks - last_nb_blocks >= PROGRESS_THRESHOLD) {
					UpdateProgressWithInfo(OP_FILE_COPY, MSG_231, nb_blocks, total_blocks);
					last_nb_blocks = nb_blocks;
				}
			}
			if (preserve_timestamps) {
				struct utimbuf ut;
				ut.actime = ut.modtime = mktime(&p_statbuf->tm);
				utime(psz_sanpath, &ut);
			}
			close(fd); fd = -1;
			fix_config(psz_sanpath, psz_path, psz_basename_ptr, &props);
			safe_free(psz_sanpath);
		}
	}
	r = 0;

out:
	if (fd >= 0) close(fd);
	if (p_entlist) iso9660_filelist_free(p_entlist);
	safe_free(psz_sanpath);
	free(buf);
	return r;
}

/* ================================================================== */
/* Public API                                                           */
/* ================================================================== */

/*
 * HasEfiImgBootLoaders: return TRUE if img_report indicates an EFI img
 * bootloader was detected during scanning.
 */
BOOL HasEfiImgBootLoaders(void)
{
	return HAS_EFI_IMG(img_report) ? TRUE : FALSE;
}

/*
 * ReadISOFileToBuffer: Read a single file from an ISO image into a newly
 * allocated buffer.  The caller must free *buf.  Returns the file size, or 0
 * on failure.
 */
uint32_t ReadISOFileToBuffer(const char* iso, const char* iso_file, uint8_t** buf)
{
	iso9660_t*    p_iso      = NULL;
	udf_t*        p_udf      = NULL;
	udf_dirent_t* p_udf_root = NULL;
	udf_dirent_t* p_udf_file = NULL;
	iso9660_stat_t* p_statbuf = NULL;
	uint32_t ret = 0, nblocks;
	int64_t  file_length;
	ssize_t  read_size;

	if (!iso || !iso_file || !buf) return 0;
	*buf = NULL;
	cdio_loglevel_default = CDIO_LOG_WARN;

	/* Try UDF first */
	p_udf = udf_open(iso);
	if (p_udf) {
		p_udf_root = udf_get_root(p_udf, true, 0);
		if (!p_udf_root) { uprintf("Could not locate UDF root"); goto try_iso; }
		p_udf_file = udf_fopen(p_udf_root, iso_file);
		if (!p_udf_file) { uprintf("Could not locate '%s' in UDF", iso_file); goto try_iso; }
		file_length = udf_get_file_length(p_udf_file);
		if (file_length > 1 * GB) { uprintf("File too large (>1 GB)"); goto out; }
		nblocks = (uint32_t)((file_length + UDF_BLOCKSIZE - 1) / UDF_BLOCKSIZE);
		*buf = (uint8_t*)malloc((size_t)(nblocks * UDF_BLOCKSIZE) + 1);
		if (!*buf) { uprintf("Out of memory"); goto out; }
		read_size = udf_read_block(p_udf_file, *buf, (long int)nblocks);
		if (read_size < 0 || read_size != file_length) {
			uprintf("UDF read error for '%s'", iso_file);
			free(*buf); *buf = NULL;
			goto out;
		}
		ret = (uint32_t)file_length;
		(*buf)[ret] = 0;
		goto out;
	}

try_iso:
	p_iso = iso9660_open_ext(iso, ISO_EXTENSION_ALL);
	if (!p_iso) { uprintf("Unable to open '%s' as ISO", iso); goto out; }
	p_statbuf = iso9660_ifs_stat_translate(p_iso, iso_file);
	if (!p_statbuf) { uprintf("Could not find '%s' in ISO", iso_file); goto out; }
	file_length = p_statbuf->total_size;
	if (file_length > 1 * GB) { uprintf("File too large (>1 GB)"); goto out; }
	nblocks = (uint32_t)((file_length + ISO_BLOCKSIZE - 1) / ISO_BLOCKSIZE);
	*buf = (uint8_t*)malloc((size_t)(nblocks * ISO_BLOCKSIZE) + 1);
	if (!*buf) { uprintf("Out of memory"); goto out; }
	{
		uint8_t* p = *buf;
		int64_t remaining = file_length;
		lsn_t lsn = p_statbuf->lsn;
		while (remaining > 0) {
			ssize_t nr = iso9660_iso_seek_read(p_iso, p, lsn, 1);
			if (nr != ISO_BLOCKSIZE) {
				uprintf("ISO read error at lsn %u", (unsigned)lsn);
				free(*buf); *buf = NULL;
				goto out;
			}
			size_t chunk = (size_t)MIN(remaining, ISO_BLOCKSIZE);
			p        += chunk;
			remaining -= (int64_t)chunk;
			lsn++;
		}
	}
	ret = (uint32_t)file_length;
	(*buf)[ret] = 0;

out:
	udf_dirent_free(p_udf_root);
	udf_dirent_free(p_udf_file);
	iso9660_stat_free(p_statbuf);
	iso9660_close(p_iso);
	udf_close(p_udf);
	return ret;
}

/*
 * ExtractISOFile: Extract a single named file from an ISO image to a
 * destination path on disk.  Returns number of bytes written, or 0 on
 * failure.
 */
int64_t ExtractISOFile(const char* iso, const char* iso_file,
                       const char* dest_file, DWORD attr)
{
	iso9660_t*    p_iso      = NULL;
	udf_t*        p_udf      = NULL;
	udf_dirent_t* p_udf_root = NULL;
	udf_dirent_t* p_udf_file = NULL;
	iso9660_stat_t* p_statbuf = NULL;
	int64_t  file_length, r = 0;
	int      fd = -1;
	uint8_t  blk_buf[UDF_BLOCKSIZE];
	(void)attr; /* used on Windows for file attributes; unused on Linux */

	if (!iso || !iso_file || !dest_file) return 0;

	fd = open(dest_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { uprintf_errno("Could not create '%s'", dest_file); goto out; }

	/* Try UDF first */
	p_udf = udf_open(iso);
	if (p_udf) {
		p_udf_root = udf_get_root(p_udf, true, 0);
		if (!p_udf_root) { uprintf("Could not locate UDF root"); goto try_iso; }
		p_udf_file = udf_fopen(p_udf_root, iso_file);
		if (!p_udf_file) { uprintf("Could not find '%s' in UDF", iso_file); goto try_iso; }
		file_length = udf_get_file_length(p_udf_file);
		while (file_length > 0) {
			memset(blk_buf, 0, UDF_BLOCKSIZE);
			ssize_t nr = udf_read_block(p_udf_file, blk_buf, 1);
			if (nr < 0) { uprintf("UDF read error"); goto out; }
			size_t to_write = (size_t)MIN(file_length, nr);
			if (!write_all(fd, blk_buf, to_write)) {
				uprintf_errno("Write error"); goto out;
			}
			file_length -= (int64_t)to_write;
			r           += (int64_t)to_write;
		}
		goto out;
	}

try_iso:
	/* Re-open iso9660 if UDF failed */
	if (p_iso) { iso9660_close(p_iso); p_iso = NULL; }
	p_iso = iso9660_open_ext(iso, ISO_EXTENSION_ALL);
	if (!p_iso) { uprintf("Unable to open '%s' as ISO", iso); goto out; }
	p_statbuf = iso9660_ifs_stat_translate(p_iso, iso_file);
	if (!p_statbuf) { uprintf("Could not find '%s' in ISO", iso_file); goto out; }
	file_length = p_statbuf->total_size;
	{
		lsn_t lsn = p_statbuf->lsn;
		int64_t remaining = file_length;
		while (remaining > 0) {
			memset(blk_buf, 0, ISO_BLOCKSIZE);
			ssize_t nr = iso9660_iso_seek_read(p_iso, blk_buf, lsn, 1);
			if (nr != ISO_BLOCKSIZE) {
				uprintf("ISO read error at lsn %u", (unsigned)lsn); goto out;
			}
			size_t to_write = (size_t)MIN(remaining, ISO_BLOCKSIZE);
			if (!write_all(fd, blk_buf, to_write)) {
				uprintf_errno("Write error"); goto out;
			}
			remaining -= (int64_t)to_write;
			r         += (int64_t)to_write;
			lsn++;
		}
	}

out:
	if (fd >= 0) close(fd);
	if (r == 0 && dest_file) unlink(dest_file); /* clean up partial file */
	udf_dirent_free(p_udf_root);
	udf_dirent_free(p_udf_file);
	iso9660_stat_free(p_statbuf);
	iso9660_close(p_iso);
	udf_close(p_udf);
	return r;
}

/*
 * ExtractISO: Main ISO extraction/scanning function.
 * When scan==TRUE, walks the ISO and populates img_report without writing files.
 * When scan==FALSE, extracts all files to dest_dir (must scan first).
 */
BOOL ExtractISO(const char* src_iso, const char* dest_dir, BOOL scan)
{
	iso9660_t*    p_iso      = NULL;
	udf_t*        p_udf      = NULL;
	udf_dirent_t* p_udf_root = NULL;
	char*         tmp        = NULL;
	BOOL          ret        = FALSE;
	int           k;
	iso9660_pvd_t pvd;
	iso_extension_mask_t mask = ISO_EXTENSION_MASK;

	if (!enable_iso || !src_iso || !dest_dir)
		return FALSE;

	scan_only      = scan;
	psz_extract_dir = dest_dir;
	cdio_log_set_handler(log_handler);

	if (scan) {
		uprintf("ISO analysis:");
		total_blocks  = 0;
		extra_blocks  = 0;
		nb_blocks     = 0;
		last_nb_blocks = 0;
		has_ldlinux_c32 = FALSE;
		symlinked_syslinux[0] = 0;
		StrArrayCreate(&config_path,    8);
		StrArrayCreate(&isolinux_path,  8);
		StrArrayCreate(&grub_filesystems, 8);
		PrintInfo(0, MSG_202);
	} else {
		uprintf("Extracting files...");
		if (total_blocks == 0) {
			uprintf("Error: ISO has not been properly scanned.");
			ErrorStatus = RUFUS_ERROR(APPERR(ERROR_ISO_SCAN));
			return FALSE;
		}
		nb_blocks      = 0;
		last_nb_blocks = 0;
		iso_blocking_status = 0;
		symlinked_syslinux[0] = 0;
		StrArrayClear(&modified_files);
		if (validate_md5sum) {
			md5sum_totalbytes = 0;
			if (img_report.has_md5sum != 1) {
				char path[MAX_PATH];
				snprintf(path, sizeof(path), "%s/%s", dest_dir, md5sum_name[0]);
				fd_md5sum = fopen(path, "wb");
				if (!fd_md5sum)
					uprintf("WARNING: Could not create '%s'", md5sum_name[0]);
			} else {
				md5sum_size = ReadISOFileToBuffer(src_iso, md5sum_name[0],
				                                 (uint8_t**)&md5sum_data);
				md5sum_pos  = md5sum_data;
			}
		}
	}

	/* Try UDF first */
	p_udf = udf_open(src_iso);
	if (p_udf) {
		uprintf("%sImage is a UDF image", scan ? "  " : "");
		p_udf_root = udf_get_root(p_udf, true, 0);
		if (!p_udf_root) { uprintf("Could not locate UDF root"); goto try_iso; }
		if (scan) {
			if (udf_get_logical_volume_id(p_udf, img_report.label,
			                             sizeof(img_report.label)) <= 0)
				img_report.label[0] = 0;
			/* Also open ISO9660 view for size information */
			p_iso = iso9660_open(src_iso);
		}
		if (udf_extract_files(p_udf, p_udf_root, "") == 0)
			ret = TRUE;
		goto out;
	}

try_iso:
	/* Adjust extension mask for Rock Ridge vs Joliet */
	if (!enable_joliet || (enable_rockridge && (scan || img_report.has_long_filename ||
	    img_report.has_symlinks == SYMLINKS_RR)))
		mask &= ~ISO_EXTENSION_JOLIET;
	if (!enable_rockridge)
		mask &= ~ISO_EXTENSION_ROCK_RIDGE;

	p_iso = iso9660_open_ext(src_iso, mask);
	if (!p_iso) {
		uprintf("'%s' doesn't look like an ISO image", src_iso);
		goto out;
	}
	uprintf("%sImage is an ISO9660 image", scan ? "  " : "");
	joliet_level = iso9660_ifs_get_joliet_level(p_iso);

	if (scan) {
		if (iso9660_ifs_get_volume_id(p_iso, &tmp)) {
			safe_strcpy(img_report.label, sizeof(img_report.label), tmp);
			safe_free(tmp);
		} else {
			img_report.label[0] = 0;
		}
	} else {
		if (mask & (ISO_EXTENSION_JOLIET | ISO_EXTENSION_ROCK_RIDGE))
			uprintf("  Using %s extensions",
			        (mask & ISO_EXTENSION_JOLIET) ? "Joliet" : "Rock Ridge");
	}

	if (iso_extract_files(p_iso, "") == 0)
		ret = TRUE;

out:
	iso_blocking_status = -1;

	if (scan) {
		struct stat st;
		/* Compute mismatch between PVD and actual file size */
		if (p_iso && iso9660_ifs_read_pvd(p_iso, &pvd) && stat(src_iso, &st) == 0) {
			img_report.mismatch_size =
				(int64_t)(iso9660_get_pvd_space_size(&pvd)) * ISO_BLOCKSIZE
				- (int64_t)st.st_size;
		}
		/* Trim trailing spaces from label */
		for (k = (int)safe_strlen(img_report.label) - 1;
		     k > 0 && isspace((unsigned char)img_report.label[k]); k--)
			img_report.label[k] = 0;

		img_report.projected_size =
			(uint64_t)((double)total_blocks * ISO_BLOCKSIZE * 1.01);

		/* Choose shortest config path */
		if (!IsStrArrayEmpty(config_path)) {
			size_t j;
			memset(img_report.cfg_path, '_', sizeof(img_report.cfg_path) - 1);
			img_report.cfg_path[sizeof(img_report.cfg_path) - 1] = 0;
			for (j = 0; j < config_path.Index; j++) {
				if (safe_strlen(config_path.String[j]) <
				    safe_strlen(img_report.cfg_path))
					safe_strcpy(img_report.cfg_path,
					            sizeof(img_report.cfg_path),
					            config_path.String[j]);
			}
		}

		StrArrayDestroy(&config_path);
		StrArrayDestroy(&isolinux_path);
		StrArrayDestroy(&grub_filesystems);

		/* For WinPE 1.x images, check txtsetup.sif for /minint in OsLoadOptions.
		 * This flag controls whether the disk ID byte in the MBR should be 0x80
		 * or 0x81, so it must be detected during scan. */
		if (HAS_WINPE(img_report)) {
			static const char *basedir[] = { "i386", "amd64", "minint" };
			int pe_idx = ((img_report.winpe & WINPE_I386) == WINPE_I386)   ? 0 :
			             ((img_report.winpe & WINPE_AMD64) == WINPE_AMD64)  ? 1 : 2;
			char pe_path[64];
			uint8_t *pe_buf = NULL;
			snprintf(pe_path, sizeof(pe_path), "/%s/txtsetup.sif", basedir[pe_idx]);
			uint32_t pe_size = ReadISOFileToBuffer(src_iso, pe_path, &pe_buf);
			if (pe_size > 0 && pe_buf != NULL) {
				char *osl = get_token_data_buffer("OsLoadOptions", 1,
				                                  (const char *)pe_buf, pe_size);
				if (osl != NULL) {
					/* Lowercase for case-insensitive match */
					for (size_t si = 0; si < strlen(osl); si++)
						osl[si] = (char)tolower((unsigned char)osl[si]);
					uprintf("  Checking %s: OsLoadOptions = %s", pe_path, osl);
					img_report.uses_minint = (strstr(osl, "/minint") != NULL);
					safe_free(osl);
				}
				safe_free(pe_buf);
			}
		}
	} else {
		if (fd_md5sum) { fclose(fd_md5sum); fd_md5sum = NULL; }
		safe_free(md5sum_data);
	}

	udf_dirent_free(p_udf_root);
	udf_close(p_udf);
	iso9660_close(p_iso);
	safe_free(tmp);
	return ret;
}

/* ------------------------------------------------------------------ */
/* Stubs for functions not yet implemented or N/A on Linux              */
/* ------------------------------------------------------------------ */

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
		p_iso = iso9660_open_ext(image_path, ISO_EXTENSION_MASK);
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
						if (!write_all(fd, buf, size)) {
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

/* -----------------------------------------------------------------------
 * OpticalDiscSaveImage implementation
 *
 * Reads the entire optical disc (or any block device / regular file) at
 * img_save->DevicePath and writes it verbatim to img_save->ImagePath.
 * Progress is reported via UpdateProgressWithInfo(OP_FORMAT, MSG_261, …).
 * UM_FORMAT_COMPLETED is posted to hMainDialog when done (or on error).
 *
 * iso_save_run_sync() is the synchronous core used by unit tests.
 * The public OpticalDiscSaveImage() wraps it in a pthread via CreateThread.
 * ----------------------------------------------------------------------- */

/* Shared state used by the save thread */
static IMG_SAVE s_opt_save = { 0 };

/* Core save logic — runs synchronously.  Returns 0 on success, 1 on error.
 * Frees img_save->DevicePath, ->ImagePath, and ->Label on return. */
DWORD iso_save_run_sync(IMG_SAVE* img_save)
{
	int    src_fd   = -1;
	int    dst_fd   = -1;
	uint8_t* buffer = NULL;
	uint64_t wb     = 0;
	DWORD    ret    = 1;

	if (!img_save || !img_save->DevicePath || !img_save->ImagePath) {
		ErrorStatus = RUFUS_ERROR(ERROR_INVALID_PARAMETER);
		goto out;
	}

	src_fd = open(img_save->DevicePath, O_RDONLY | O_LARGEFILE);
	if (src_fd < 0) {
		uprintf_errno("Could not open '%s'", img_save->DevicePath);
		ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
		goto out;
	}

	dst_fd = open(img_save->ImagePath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (dst_fd < 0) {
		uprintf_errno("Could not create '%s'", img_save->ImagePath);
		ErrorStatus = RUFUS_ERROR(ERROR_OPEN_FAILED);
		goto out;
	}

	if (img_save->BufSize == 0)
		img_save->BufSize = 1 * 1024 * 1024;  /* fallback: 1 MiB */

	buffer = malloc(img_save->BufSize);
	if (!buffer) {
		ErrorStatus = RUFUS_ERROR(ERROR_NOT_ENOUGH_MEMORY);
		goto out;
	}

	uprintf("Saving optical disc to '%s' (%s)…",
	        img_save->ImagePath,
	        SizeToHumanReadable((uint64_t)img_save->DeviceSize, FALSE, FALSE));
	UpdateProgressWithInfoInit(NULL, FALSE);

	while (wb < (uint64_t)img_save->DeviceSize) {
		CHECK_FOR_USER_CANCEL;

		uint64_t to_read = MIN((uint64_t)img_save->BufSize,
		                       (uint64_t)img_save->DeviceSize - wb);
		ssize_t rSize = read(src_fd, buffer, (size_t)to_read);
		if (rSize <= 0) {
			if (rSize < 0)
				uprintf_errno("Read error at offset %" PRIu64, wb);
			else
				uprintf("Premature end of disc at %" PRIu64 " (expected %" PRIu64 ")",
				        wb, (uint64_t)img_save->DeviceSize);
			ErrorStatus = RUFUS_ERROR(ERROR_READ_FAULT);
			goto out;
		}

		/* Write with retries */
		for (int retry = 0; retry < WRITE_RETRIES; retry++) {
			CHECK_FOR_USER_CANCEL;
			ssize_t wSize = write(dst_fd, buffer, (size_t)rSize);
			if (wSize == rSize)
				break;
			if (retry == WRITE_RETRIES - 1) {
				if (wSize < 0)
					uprintf_errno("Write error at offset %" PRIu64, wb);
				else
					uprintf("Write error: wrote %zd of %zd bytes", wSize, rSize);
				ErrorStatus = RUFUS_ERROR(ERROR_WRITE_FAULT);
				goto out;
			}
			uprintf("Write error at offset %" PRIu64 ", retrying…", wb);
			sleep(1);
		}

		wb += (uint64_t)rSize;
		UpdateProgressWithInfo(OP_FORMAT, MSG_261, wb, (uint64_t)img_save->DeviceSize);
	}

	uprintf("Optical disc saved (%s).",
	        SizeToHumanReadable(wb, FALSE, FALSE));
	ret = 0;

out:
	free(buffer);
	if (src_fd >= 0) close(src_fd);
	if (dst_fd >= 0) close(dst_fd);
	if (img_save) {
		safe_free(img_save->DevicePath);
		safe_free(img_save->ImagePath);
		safe_free(img_save->Label);
	}
	PostMessage(hMainDialog, UM_FORMAT_COMPLETED, (WPARAM)TRUE, 0);
	return ret;
}

/* Thread entry point — wraps iso_save_run_sync for use with CreateThread */
static DWORD WINAPI OpticalDiscSaveImageThread(void* param)
{
	IMG_SAVE* img_save = (IMG_SAVE*)param;
	DWORD r = iso_save_run_sync(img_save);
	ExitThread(r);
	return r; /* unreachable, silences -Wreturn-type */
}

void OpticalDiscSaveImage(void)
{
	char filename[128] = "disc_image.iso";
	EXT_DECL(img_ext, filename, __VA_GROUP__("*.iso"),
	         __VA_GROUP__(lmprintf(MSG_036)));

	if (op_in_progress || (format_thread != NULL))
		return;

	memset(&s_opt_save, 0, sizeof(s_opt_save));
	s_opt_save.Type = VIRTUAL_STORAGE_TYPE_DEVICE_ISO;

	if (!GetOpticalMedia(&s_opt_save)) {
		uprintf("No dumpable optical media found.");
		return;
	}

	/* Choose a buffer size proportional to disc size (8–32 MiB) */
	s_opt_save.BufSize = 32 * 1024 * 1024;
	while (s_opt_save.BufSize > 8 * 1024 * 1024 &&
	       s_opt_save.DeviceSize <= (LONGLONG)s_opt_save.BufSize * 64)
		s_opt_save.BufSize /= 2;

	if (s_opt_save.Label && s_opt_save.Label[0])
		snprintf(filename, sizeof(filename), "%s.iso", s_opt_save.Label);

	s_opt_save.ImagePath = FileDialog(TRUE, NULL, &img_ext, 0);
	if (!s_opt_save.ImagePath) {
		safe_free(s_opt_save.DevicePath);
		safe_free(s_opt_save.Label);
		return;
	}

	uprintf("ISO media size %s",
	        SizeToHumanReadable((uint64_t)s_opt_save.DeviceSize, FALSE, FALSE));
	SendMessage(hMainDialog, UM_PROGRESS_INIT, 0, 0);
	ErrorStatus = 0;
	EnableControls(FALSE, FALSE);
	InitProgress(TRUE);

	format_thread = CreateThread(NULL, 0, OpticalDiscSaveImageThread, &s_opt_save, 0, NULL);
	if (format_thread != NULL) {
		uprintf("\r\nSave to ISO operation started");
		PrintInfo(0, -1);
	} else {
		uprintf("Unable to start ISO save thread");
		ErrorStatus = RUFUS_ERROR(APPERR(ERROR_CANT_START_THREAD));
		safe_free(s_opt_save.ImagePath);
		safe_free(s_opt_save.DevicePath);
		safe_free(s_opt_save.Label);
		PostMessage(hMainDialog, UM_FORMAT_COMPLETED, (WPARAM)FALSE, 0);
	}
}

DWORD WINAPI IsoSaveImageThread(void* param) { (void)param; return 0; }

BOOL SaveImage(void) { return FALSE; }
