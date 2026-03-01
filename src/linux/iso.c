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
#include "syslinux/libfat/libfat.h"

/* ---- constants ---- */
#define PROGRESS_THRESHOLD   ((256 * KB) / ISO_BLOCKSIZE)
#define ISO_EXTENSION_MASK   (ISO_EXTENSION_ALL \
	& (enable_joliet    ? ISO_EXTENSION_ALL : ~ISO_EXTENSION_JOLIET) \
	& (enable_rockridge ? ISO_EXTENSION_ALL : ~ISO_EXTENSION_ROCK_RIDGE))

#include "iso_private.h"

/* ---- globals (defined here, extern in rufus.h or ui.h) ---- */
RUFUS_IMG_REPORT img_report;
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
/* Internal types                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
	BOOLEAN is_cfg;
	BOOLEAN is_conf;
	BOOLEAN is_syslinux_cfg;
	BOOLEAN is_grub_cfg;
	BOOLEAN is_menu_cfg;
	BOOLEAN is_old_c32[NB_OLD_C32];
} EXTRACT_PROPS;

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
/* Property detection (scan-time and extract-time analysis)            */
/* ------------------------------------------------------------------ */

static BOOL check_iso_props(const char* psz_dirname, int64_t file_length,
                             const char* psz_basename, const char* psz_fullpath,
                             EXTRACT_PROPS* props)
{
	size_t i, j, k, len;
	char   bootloader_name[32];

	memset(props, 0, sizeof(EXTRACT_PROPS));

	/* Config file check */
	for (i = 0; i < ARRAYSIZE(syslinux_cfg); i++) {
		if (safe_stricmp(psz_basename, syslinux_cfg[i]) == 0) {
			props->is_cfg = TRUE;
			props->is_syslinux_cfg = TRUE;
			if (scan_only && i < 3)
				StrArrayAdd(&config_path, psz_fullpath, TRUE);
			if (scan_only && i == 1 &&
			    safe_stricmp(psz_dirname, efi_dirname) == 0)
				img_report.has_efi_syslinux = TRUE;
		}
	}

	/* Archiso loader/entries conf */
	if (safe_stricmp(psz_dirname, "/loader/entries") == 0) {
		len = safe_strlen(psz_basename);
		props->is_conf = (len > 4 && safe_stricmp(&psz_basename[len - 5], ".conf") == 0);
	}

	/* Old c32 check */
	for (i = 0; i < NB_OLD_C32; i++) {
		if (safe_stricmp(psz_basename, old_c32_name[i]) == 0 &&
		    file_length <= old_c32_threshold[i])
			props->is_old_c32[i] = TRUE;
	}

	if (!scan_only) {
		/* Write-time: grub config detection */
		len = safe_strlen(psz_basename);
		if (len >= 4 && safe_stricmp(&psz_basename[len - 4], ".cfg") == 0) {
			props->is_cfg = TRUE;
			for (i = 0; i < ARRAYSIZE(grub_cfg); i++) {
				if (safe_stricmp(psz_basename, grub_cfg[i]) == 0)
					props->is_grub_cfg = TRUE;
			}
			if (safe_stricmp(psz_basename, menu_cfg) == 0)
				props->is_menu_cfg = TRUE;
		}
		/* Skip ldlinux.sys at root */
		if (psz_dirname && psz_dirname[0] == '\0' &&
		    safe_stricmp(psz_basename, ldlinux_name) == 0) {
			uprintf("Skipping '%s' from ISO (will be written by syslinux)", psz_basename);
			return TRUE;
		}
		return FALSE;
	}

	/* ---- scan-time only ---- */

	/* GRUB directory detection */
	for (i = 0; i < ARRAYSIZE(grub_dirname); i++) {
		if (safe_stricmp(psz_dirname, grub_dirname[i]) == 0)
			img_report.has_grub2 = (uint8_t)i + 1;
	}

	if (safe_stricmp(psz_basename, ldlinux_c32) == 0)
		has_ldlinux_c32 = TRUE;

	if (safe_strnicmp(psz_dirname, casper_dirname, strlen(casper_dirname)) == 0) {
		img_report.uses_casper = TRUE;
		if (safe_strstr(psz_dirname, pop_os_name) != NULL)
			img_report.disable_iso = TRUE;
	}
	if (safe_stricmp(psz_dirname, proxmox_dirname) == 0)
		img_report.disable_iso = TRUE;

	/* Root-level files */
	if (psz_dirname && psz_dirname[0] == '\0') {
		if (safe_stricmp(psz_basename, bootmgr_name) == 0)
			img_report.has_bootmgr = TRUE;
		if (safe_stricmp(psz_basename, bootmgr_efi_name) == 0) {
			for (j = 0; j < ARRAYSIZE(img_report.efi_boot_entry); j++) {
				if (img_report.efi_boot_entry[j].path[0] == 0) {
					img_report.efi_boot_entry[j].type = EBT_BOOTMGR;
					safe_strcpy(img_report.efi_boot_entry[j].path,
					            sizeof(img_report.efi_boot_entry[j].path),
					            psz_fullpath);
					break;
				}
			}
			img_report.has_efi |= 1;
			img_report.has_bootmgr_efi = TRUE;
		}
		if (safe_stricmp(psz_basename, grldr_name) == 0)
			img_report.has_grub4dos = TRUE;
		if (safe_stricmp(psz_basename, kolibri_name) == 0)
			img_report.has_kolibrios = TRUE;
		if (safe_stricmp(psz_basename, manjaro_marker) == 0)
			img_report.disable_iso = TRUE;
		for (i = 0; i < ARRAYSIZE(md5sum_name); i++) {
			if (safe_stricmp(psz_basename, md5sum_name[i]) == 0)
				img_report.has_md5sum = (uint8_t)(i + 1);
		}
	}

	/* ReactOS */
	if (img_report.reactos_path[0] == 0) {
		for (i = 0; i < ARRAYSIZE(reactos_name); i++) {
			if (safe_stricmp(psz_basename, reactos_name[i]) == 0)
				safe_strcpy(img_report.reactos_path,
				            sizeof(img_report.reactos_path), psz_fullpath);
		}
	}

	/* EFI img */
	if (!HAS_EFI_IMG(img_report) && safe_strlen(psz_basename) >= 7 &&
	    safe_strnicmp(psz_basename, "efi", 3) == 0 &&
	    safe_stricmp(&psz_basename[strlen(psz_basename) - 4], ".img") == 0)
		safe_strcpy(img_report.efi_img_path,
		            sizeof(img_report.efi_img_path), psz_fullpath);

	/* EFI boot entries */
	if (safe_stricmp(psz_dirname, efi_dirname) == 0) {
		for (k = 0; k < ARRAYSIZE(efi_bootname); k++) {
			for (i = 0; i < ARRAYSIZE(efi_archname); i++) {
				snprintf(bootloader_name, sizeof(bootloader_name),
				         "%s%s.efi", efi_bootname[k], efi_archname[i]);
				if (safe_stricmp(psz_basename, bootloader_name) == 0) {
					if (k == 0)
						img_report.has_efi |= (uint16_t)(2 << i);
					for (j = 0; j < ARRAYSIZE(img_report.efi_boot_entry); j++) {
						if (img_report.efi_boot_entry[j].path[0] == 0) {
							img_report.efi_boot_entry[j].type = (uint8_t)k;
							safe_strcpy(img_report.efi_boot_entry[j].path,
							            sizeof(img_report.efi_boot_entry[j].path),
							            psz_fullpath);
							break;
						}
					}
				}
			}
		}
		if (safe_stricmp(psz_basename, "bootx64.efi") == 0 && file_length < 256) {
			img_report.has_efi |= 0x4000;
			safe_strcpy(img_report.efi_img_path,
			            sizeof(img_report.efi_img_path),
			            "[BOOT]/1-Boot-NoEmul.img");
		}
	}

	/* Windows installer sources */
	if (psz_dirname) {
		int dlen = (int)safe_strlen(psz_dirname);
		int slen = (int)strlen(sources_str);
		if (safe_stricmp(&psz_dirname[MAX(0, dlen - slen)], sources_str) == 0) {
			for (i = 0; i < ARRAYSIZE(wininst_name); i++) {
				if (safe_stricmp(psz_basename, wininst_name[i]) == 0 &&
				    img_report.wininst_index < MAX_WININST) {
					snprintf(img_report.wininst_path[img_report.wininst_index],
					         sizeof(img_report.wininst_path[0]), "%s", psz_fullpath);
					img_report.wininst_index++;
					if (file_length >= 4 * GB)
						img_report.has_4GB_file |= (0x10u << i);
				}
			}
		}
	}

	/* Windows panther unattend */
	if (safe_stricmp(psz_dirname, "/sources/$OEM$/$$/Panther") == 0 &&
	    safe_stricmp(psz_basename, "unattend.xml") == 0)
		img_report.has_panther_unattend = TRUE;

	/* WinPE / PE detection */
	for (i = 0; i < ARRAYSIZE(pe_dirname); i++)
		if (safe_stricmp(psz_dirname, pe_dirname[i]) == 0)
			for (j = 0; j < ARRAYSIZE(pe_file); j++)
				if (safe_stricmp(psz_basename, pe_file[j]) == 0)
					img_report.winpe |= (1u << j) << (ARRAYSIZE(pe_dirname) * i);

	/* Isolinux path list */
	for (i = 0; i < ARRAYSIZE(isolinux_bin); i++) {
		if (safe_stricmp(psz_basename, isolinux_bin[i]) == 0)
			StrArrayAdd(&isolinux_path, psz_fullpath, TRUE);
	}

	/* old c32 tracking */
	for (i = 0; i < NB_OLD_C32; i++)
		if (props->is_old_c32[i])
			img_report.has_old_c32[i] = TRUE;

	/* 4GB file flag */
	if (file_length >= 4 * GB && (img_report.has_4GB_file & 0x0f) != 0x0f)
		img_report.has_4GB_file++;

	/* Accumulate block count */
	if (file_length != 0)
		total_blocks += (uint64_t)(file_length + ISO_BLOCKSIZE - 1) / ISO_BLOCKSIZE;

	return TRUE; /* scan_only: caller skips actual extraction */
}

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
 * GetGrubVersion: Scan a binary buffer for GRUB version string and update
 * img_report.grub2_version if not already set.
 */
void GetGrubVersion(char* buf, size_t buf_size, const char* source)
{
	const char* grub_version_str[] = { "GRUB  version %s", "GRUB version %s" };
	const char* grub_debug_is_enabled_str = "grub_debug_is_enabled";
	const size_t max_string_size = 32;
	char grub_version[192] = { 0 };
	size_t i, j;
	BOOL has_grub_debug_is_enabled = FALSE;

	if (buf_size > max_string_size) {
		for (i = 0; i < buf_size - max_string_size; i++) {
			for (j = 0; j < ARRAYSIZE(grub_version_str); j++) {
				size_t fmt_len = strlen(grub_version_str[j]);
				/* strip the trailing " %s" (3 chars) to get actual prefix */
				size_t prefix_len = fmt_len - 3;
				if (memcmp(&buf[i], grub_version_str[j], prefix_len) == 0) {
					/* skip past "GRUB version " + one char (the space before version) */
					if (buf[i + prefix_len + 1] == '\0')
						i++;
					safe_strcpy(grub_version, sizeof(grub_version),
					            &buf[i + prefix_len + 1]);
				}
			}
			if (memcmp(&buf[i], grub_debug_is_enabled_str,
			           strlen(grub_debug_is_enabled_str)) == 0)
				has_grub_debug_is_enabled = TRUE;
		}
	}

	uprintf("  Detected GRUB version: %s (from '%s')", grub_version, source);

	if (img_report.grub2_version[0] != 0)
		return;

	safe_strcpy(img_report.grub2_version, sizeof(img_report.grub2_version),
	            grub_version);

	if (img_report.grub2_version[0] == '0')
		img_report.grub2_version[0] = 0;

	if (img_report.grub2_version[0] != 0) {
		BOOL append_label = (safe_strcmp(img_report.grub2_version, "2.06") == 0);
		if ((img_report.has_grub2 & 0x7f) > 1)
			safe_strcat(img_report.grub2_version,
			            sizeof(img_report.grub2_version), "-nonstandard");
		if (has_grub_debug_is_enabled)
			safe_strcat(img_report.grub2_version,
			            sizeof(img_report.grub2_version), "-gdie");
		if (append_label) {
			safe_strcat(img_report.grub2_version,
			            sizeof(img_report.grub2_version), "-");
			safe_strcat(img_report.grub2_version,
			            sizeof(img_report.grub2_version), img_report.label);
		}
		sanitize_label(img_report.grub2_version);
	}
}

/*
 * GetGrubFs: Scan a binary buffer for GRUB filesystem module entries and
 * add any found filesystem names to grub_filesystems.
 */
void GetGrubFs(char* buf, size_t buf_size)
{
	const char* grub_fshelp_str = "fshelp";
	const size_t max_string_size = 32;
	const size_t fshelp_len = 7; /* strlen("fshelp") + 1 for NUL */
	size_t i, fs_len;

	if (buf_size > max_string_size) {
		for (i = 0; i < buf_size - max_string_size; i++) {
			if (memcmp(&buf[i], grub_fshelp_str, fshelp_len) == 0) {
				const char* fs_name = &buf[i + fshelp_len];
				fs_len = safe_strlen(fs_name);
				if (fs_len > 0 && fs_len < 12)
					StrArrayAddUnique(&grub_filesystems, fs_name, TRUE);
			}
		}
	}
}

/*
 * GetEfiBootInfo: Scan a binary buffer for EFI bootloader identification
 * strings and log the version if found.
 */
void GetEfiBootInfo(char* buf, size_t buf_size, const char* source)
{
	const struct { const char* label; const char* search_string; } boot_info[] = {
		{ "Shim",         "UEFI SHIM\n$Version: " },
		{ "systemd-boot", "#### LoaderInfo: systemd-boot " },
	};
	const size_t max_string_size = 64;
	size_t i, j, k;

	if (buf_size > max_string_size) {
		for (i = 0; i < buf_size - max_string_size; i++) {
			for (j = 0; j < ARRAYSIZE(boot_info); j++) {
				size_t slen = strlen(boot_info[j].search_string);
				if (memcmp(&buf[i], boot_info[j].search_string, slen) == 0) {
					i += slen;
					for (k = 0; k < 32 && i + k < buf_size - 1 &&
					     !isspace((unsigned char)buf[i + k]); k++);
					buf[i + k] = '\0';
					uprintf("  Detected %s version: %s (from '%s')",
					        boot_info[j].label, &buf[i], source);
					return;
				}
			}
		}
	}
}

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

BOOL DumpFatDir(const char* path, int32_t cluster)
{
	(void)path; (void)cluster;
	return FALSE;
}

void OpticalDiscSaveImage(void) {}

DWORD WINAPI IsoSaveImageThread(void* param) { (void)param; return 0; }

BOOL SaveImage(void) { return FALSE; }
