/*
 * Rufus: The Reliable USB Formatting Utility
 * Virtual Disk / WIM file handling — Linux port
 * Copyright © 2013-2026 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "rufus.h"
#include "resource.h"
#include "vhd.h"
#include "wimlib.h"
#include "bled/bled.h"

/* These are defined in iso.c; declare them here so WimProgressFunc can use them */
extern FILE*    fd_md5sum;
extern uint64_t total_blocks, extra_blocks, nb_blocks, last_nb_blocks;

/* Forward declaration */
void VhdUnmountImage(void);

extern BOOL ignore_boot_marker, has_ffu_support;

static char physical_path[128] = "";
static char nbd_dev[64] = "";
static int  progress_op  = OP_FILE_COPY;
static int  progress_msg = MSG_267;
static struct wimlib_progress_info_split last_split_progress;

typedef struct {
	const char* ext;
	uint8_t     type;
} comp_assoc;

static comp_assoc file_assoc[] = {
	{ ".zip",  BLED_COMPRESSION_ZIP   },
	{ ".Z",    BLED_COMPRESSION_LZW   },
	{ ".gz",   BLED_COMPRESSION_GZIP  },
	{ ".lzma", BLED_COMPRESSION_LZMA  },
	{ ".bz2",  BLED_COMPRESSION_BZIP2 },
	{ ".xz",   BLED_COMPRESSION_XZ    },
	{ ".vtsi", BLED_COMPRESSION_VTSI  },
	{ ".zst",  BLED_COMPRESSION_ZSTD  },
	{ ".ffu",  BLED_COMPRESSION_MAX   },
	{ ".vhd",  BLED_COMPRESSION_MAX + 1 },
	{ ".vhdx", BLED_COMPRESSION_MAX + 2 },
};

/* Look for a boot marker in the MBR area of the image */
static int8_t IsCompressedBootableImage(const char* path)
{
	char *ext = NULL, *physical_disk = NULL;
	unsigned char *buf = NULL;
	int i;
	FILE* fd = NULL;
	BOOL r = 0;
	int64_t dc = 0;

	img_report.compression_type = BLED_COMPRESSION_NONE;
	if (safe_strlen(path) > 4)
		for (ext = (char*)&path[safe_strlen(path) - 1]; (*ext != '.') && (ext != path); ext--);

	for (i = 0; i < ARRAYSIZE(file_assoc); i++) {
		if (safe_stricmp(ext, file_assoc[i].ext) == 0) {
			img_report.compression_type = file_assoc[i].type;
			buf = malloc(MBR_SIZE);
			if (buf == NULL)
				return 0;
			ErrorStatus = 0;
			if (img_report.compression_type < BLED_COMPRESSION_MAX) {
				bled_init(0, uprintf, NULL, NULL, NULL, NULL, (unsigned long*)&ErrorStatus);
				dc = bled_uncompress_to_buffer(path, (char*)buf, MBR_SIZE, file_assoc[i].type);
				bled_exit();
			} else if (img_report.compression_type == BLED_COMPRESSION_MAX) {
				/* FFU not supported on Linux */
				if (has_ffu_support) {
					fd = fopen(path, "rb");
					if (fd != NULL) {
						img_report.is_vhd = TRUE;
						dc = fread(buf, 1, MBR_SIZE, fd);
						fclose(fd);
						if (strncmp(&buf[4], "SignedImage ", 12) == 0) {
							buf[0x1FE] = 0x55;
							buf[0x1FF] = 0xAA;
						}
					} else {
						uprintf("Could not open %s: %d", path, errno);
					}
				} else {
					uprintf("  An FFU image was selected, but this system does not have FFU support!");
				}
			} else {
				/* VHD/VHDX: mount via qemu-nbd */
				physical_disk = VhdMountImageAndGetSize(path, &img_report.projected_size);
				if (physical_disk != NULL) {
					img_report.is_vhd = TRUE;
					fd = fopen(physical_disk, "rb");
					if (fd != NULL) {
						dc = fread(buf, 1, MBR_SIZE, fd);
						fclose(fd);
					}
				}
				VhdUnmountImage();
			}
			if (dc != MBR_SIZE) {
				free(buf);
				return FALSE;
			}
			if ((buf[0x1FE] == 0x55) && (buf[0x1FF] == 0xAA))
				r = 1;
			else if (ignore_boot_marker)
				r = 2;
			free(buf);
			return r;
		}
	}

	return FALSE;
}

/* 0: non-bootable, 1: bootable, 2: forced bootable, -1/-2: error */
int8_t IsBootableImage(const char* path)
{
	int fd = -1;
	struct stat st;
	uint64_t wim_magic = 0;
	int8_t is_bootable_img;

	uprintf("Disk image analysis:");
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		uprintf("  Could not open image '%s': %s", path, strerror(errno));
		is_bootable_img = -1;
		goto out;
	}

	is_bootable_img = IsCompressedBootableImage(path) ? 1 : 0;
	if (img_report.compression_type == BLED_COMPRESSION_NONE) {
		HANDLE h = (HANDLE)(intptr_t)fd;
		is_bootable_img = AnalyzeMBR(h, "  Image", FALSE) ? 1 : (ignore_boot_marker ? 2 : 0);
	}

	if (fstat(fd, &st) != 0) {
		uprintf("  Could not get image size: %s", strerror(errno));
		is_bootable_img = -2;
		goto out;
	}
	img_report.image_size = (uint64_t)st.st_size;
	if (img_report.projected_size == 0)
		img_report.projected_size = img_report.image_size;

	/* Check for WIM magic */
	lseek(fd, 0, SEEK_SET);
	if (read(fd, &wim_magic, sizeof(wim_magic)) == (ssize_t)sizeof(wim_magic))
		img_report.is_windows_img = (wim_magic == WIM_MAGIC) ? TRUE : FALSE;

out:
	if (fd >= 0)
		close(fd);
	return is_bootable_img;
}

/* WIM operations progress callback */
static enum wimlib_progress_status WimProgressFunc(enum wimlib_progress_msg msg_type,
	union wimlib_progress_info* info, void* progctx)
{
	static BOOL init[3] = { 0 };

	(void)progctx;

	if (IS_ERROR(ErrorStatus))
		return WIMLIB_PROGRESS_STATUS_ABORT;

	switch (msg_type) {
	case WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN:
		memset(init, 0, sizeof(init));
		/* On Linux wimlib uses char* (UTF-8) for paths */
		uprintf("Applying image %d (\"%s\") from '%s' to '%s'",
			info->extract.image,
			info->extract.image_name  ? info->extract.image_name  : "",
			info->extract.wimfile_name ? info->extract.wimfile_name : "",
			info->extract.target       ? info->extract.target       : "");
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE:
		if (!init[0]) {
			uprintf("Creating file structure...");
			init[0] = TRUE;
			uprint_progress(0, 0);
		}
		UpdateProgressWithInfoUpTo(98, progress_op, progress_msg,
			info->extract.current_file_count, info->extract.end_file_count * 6);
		uprint_progress(info->extract.current_file_count, info->extract.end_file_count);
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS:
		if (!init[1]) {
			uprintf("\nExtracting file data...");
			init[1] = TRUE;
			uprint_progress(0, 0);
		}
		UpdateProgressWithInfoUpTo(98, progress_op, progress_msg,
			info->extract.total_bytes + (4 * info->extract.completed_bytes),
			info->extract.total_bytes * 6);
		uprint_progress(info->extract.completed_bytes, info->extract.total_bytes);
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_METADATA:
		if (!init[2]) {
			uprintf("\nApplying metadata to files...");
			init[2] = TRUE;
			uprint_progress(0, 0);
		}
		UpdateProgressWithInfoUpTo(98, progress_op, progress_msg,
			info->extract.current_file_count + (5 * info->extract.end_file_count),
			info->extract.end_file_count * 6);
		uprint_progress(info->extract.current_file_count, info->extract.end_file_count);
		if (info->extract.current_file_count >= info->extract.end_file_count)
			uprintf("\n");
		break;
	case WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART:
		last_split_progress = info->split;
		uprintf("● %s", info->split.part_name ? info->split.part_name : "");
		break;
	case WIMLIB_PROGRESS_MSG_SPLIT_END_PART:
		if (fd_md5sum != NULL) {
			uint8_t sum[MD5_HASHSIZE];
			const char* filename = info->split.part_name;
			if (filename != NULL) {
				HashFile(HASH_MD5, filename, sum);
				for (int j = 0; j < MD5_HASHSIZE; j++)
					fprintf(fd_md5sum, "%02x", sum[j]);
				fprintf(fd_md5sum, "  ./%s\n", filename);
			}
		}
		break;
	case WIMLIB_PROGRESS_MSG_WRITE_STREAMS: {
		uint64_t completed_bytes = last_split_progress.completed_bytes
			+ info->write_streams.completed_compressed_bytes;
		nb_blocks = last_nb_blocks + completed_bytes / 2048;
		UpdateProgressWithInfo(OP_FILE_COPY, MSG_231, nb_blocks, total_blocks + extra_blocks);
		break;
	}
	default:
		break;
	}

	return WIMLIB_PROGRESS_STATUS_CONTINUE;
}

/* Return the WIM version of an image */
uint32_t GetWimVersion(const char* image)
{
	int r;
	WIMStruct* wim;
	struct wimlib_wim_info info;

	if (image == NULL)
		return 0;

	r = wimlib_open_wimU(image, 0, &wim);
	if (r == 0) {
		r = wimlib_get_wim_info(wim, &info);
		wimlib_free(wim);
		if (r == 0)
			return info.wim_version;
	}
	uprintf("WARNING: Could not get WIM version: Error %d", r);
	return 0;
}

/* Extract a file from a WIM image */
BOOL WimExtractFile(const char* image, int index, const char* src, const char* dst)
{
	int r = 1;
	WIMStruct* wim;
	char tmp[MAX_PATH] = "", *p;

	if ((image == NULL) || (src == NULL) || (dst == NULL))
		goto out;

	/* On Linux, use '/' as path separator */
	if (strrchr(src, '/') == NULL || strrchr(dst, '/') == NULL)
		goto out;
	p = strrchr((char*)dst, '/');
	*p = '\0';

	wimlib_global_init(0);
	wimlib_set_print_errors(true);
	r = wimlib_open_wimU(image, 0, &wim);
	if (r == 0) {
		r = wimlib_extract_pathsU(wim, index, dst, &src, 1,
			WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE);
		wimlib_free(wim);
		static_strcpy(tmp, dst);
		static_strcat(tmp, strrchr(src, '/'));
		*p = '/';
		if (rename(tmp, dst) != 0) {
			uprintf("  Could not rename %s to %s: %s", tmp, dst, strerror(errno));
			r = 1;
		}
	}
	wimlib_global_cleanup();

out:
	return (r == 0);
}

/* Split an install.wim for FAT32 limits */
BOOL WimSplitFile(const char* src, const char* dst)
{
	int r = 1;
	WIMStruct* wim;

	if ((src == NULL) || (dst == NULL))
		goto out;

	wimlib_global_init(0);
	wimlib_set_print_errors(true);
	r = wimlib_open_wimU(src, 0, &wim);
	if (r == 0) {
		wimlib_register_progress_function(wim, WimProgressFunc, NULL);
		r = wimlib_splitU(wim, dst, 4094ULL * MB, WIMLIB_WRITE_FLAG_FSYNC);
		wimlib_free(wim);
	}
	wimlib_global_cleanup();

out:
	return (r == 0);
}

BOOL WimApplyImage(const char* image, int index, const char* dst)
{
	int r = 1;
	WIMStruct* wim;

	wimlib_global_init(0);
	wimlib_set_print_errors(true);

	uprintf("Opening: %s:[%d]", image, index);
	r = wimlib_open_wimU(image, 0, &wim);
	if (r == 0) {
		progress_op  = OP_FILE_COPY;
		progress_msg = MSG_267;
		wimlib_register_progress_function(wim, WimProgressFunc, NULL);
		r = wimlib_extract_imageU(wim, index, dst, 0);
		wimlib_free(wim);
	} else {
		uprintf("Failed to open '%s': Wimlib error %d", image, r);
	}
	wimlib_global_cleanup();
	return (r == 0);
}

/*
 * Mount a VHD/VHDX image via qemu-nbd and return its block-device path.
 * Returns the path string on success, NULL on failure.
 */
char* VhdMountImageAndGetSize(const char* path, uint64_t* disk_size)
{
	int fd;
	char cmd[1024];
	const char* ext;

	if (path == NULL)
		return NULL;

	/* Check extension */
	ext = strrchr(path, '.');
	if (ext == NULL)
		return NULL;
	if (strcasecmp(ext, ".vhd") != 0 && strcasecmp(ext, ".vhdx") != 0)
		return NULL;

	/* Unmount any previously mounted image */
	VhdUnmountImage();

	/* Find a free nbd device and connect */
	nbd_dev[0] = '\0';
	for (int i = 0; i < 16; i++) {
		snprintf(nbd_dev, sizeof(nbd_dev), "/dev/nbd%d", i);
		snprintf(cmd, sizeof(cmd),
			"qemu-nbd --connect=%s \"%s\" 2>/dev/null", nbd_dev, path);
		if (system(cmd) == 0) {
			usleep(500000);  /* let the kernel settle */
			break;
		}
		nbd_dev[0] = '\0';
	}

	if (nbd_dev[0] == '\0') {
		uprintf("Could not connect VHD to nbd device");
		return NULL;
	}

	strncpy(physical_path, nbd_dev, sizeof(physical_path) - 1);
	physical_path[sizeof(physical_path) - 1] = '\0';

	if (disk_size != NULL) {
		*disk_size = 0;
		fd = open(nbd_dev, O_RDONLY);
		if (fd >= 0) {
			ioctl(fd, BLKGETSIZE64, disk_size);
			close(fd);
		}
	}

	return physical_path;
}

void VhdUnmountImage(void)
{
	char cmd[128];

	if (nbd_dev[0] == '\0')
		goto out;
	snprintf(cmd, sizeof(cmd), "qemu-nbd --disconnect %s 2>/dev/null", nbd_dev);
	system(cmd);
	nbd_dev[0] = '\0';
out:
	physical_path[0] = '\0';
}
