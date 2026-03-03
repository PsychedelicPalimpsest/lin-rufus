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
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/nbd.h>
#include <endian.h>

#include "rufus.h"
#include "resource.h"
#include "drive.h"
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
static int  nbd_fd_global = -1;   /* /dev/nbdX fd kept open while mounted */
static int  nbd_srv_sock = -1;    /* server end of socket pair */
static pthread_t nbd_server_tid;
static pthread_t nbd_do_it_tid;
static int  progress_op  = OP_FILE_COPY;
static int  progress_msg = MSG_267;
static struct wimlib_progress_info_split last_split_progress;

/* ------------------------------------------------------------------ */
/* VHD footer / NBD server helpers                                     */
/* ------------------------------------------------------------------ */

/* VHD footer layout (little-endian fields stored big-endian on disk) */
#define VHD_COOKIE           "conectix"
#define VHD_DISK_TYPE_FIXED   2
#define VHD_FOOTER_SIZE       512

/*
 * Parse the VHD footer at the last 512 bytes of |path| and return the
 * virtual disk size if it is a fixed-type VHD.  Returns 0 on failure.
 */
uint64_t vhd_get_fixed_disk_size(const char *path)
{
	uint8_t  footer[VHD_FOOTER_SIZE];
	uint32_t disk_type;
	uint64_t current_size;
	struct stat st;
	int fd;

	if (!path) return 0;
	fd = open(path, O_RDONLY);
	if (fd < 0) return 0;
	if (fstat(fd, &st) != 0 || st.st_size < (off_t)VHD_FOOTER_SIZE) {
		close(fd); return 0;
	}
	if (pread(fd, footer, VHD_FOOTER_SIZE,
	          st.st_size - VHD_FOOTER_SIZE) != VHD_FOOTER_SIZE) {
		close(fd); return 0;
	}
	close(fd);

	/* Validate cookie */
	if (memcmp(footer, VHD_COOKIE, 8) != 0)
		return 0;

	/* Disk type is at offset 60, big-endian uint32 */
	memcpy(&disk_type, footer + 60, 4);
	disk_type = be32toh(disk_type);
	if (disk_type != VHD_DISK_TYPE_FIXED)
		return 0;

	/* Current size is at offset 48, big-endian uint64 */
	memcpy(&current_size, footer + 48, 8);
	return be64toh(current_size);
}

/* NBD old-style handshake magic values */
#define NBDMAGIC       0x4e42444d41474943ULL
#define CLISERV_MAGIC  0x00420281861253ULL

/* Per-connection NBD server state */
struct nbd_srv_ctx {
	int      vhd_fd;      /* open VHD fd (O_RDWR) */
	int      sock_fd;     /* userspace socket end */
	uint64_t disk_size;   /* bytes */
};

/* Read exactly n bytes from fd (handles EINTR). Returns 0 on success. */
static int nbd_read_exact(int fd, void *buf, size_t n)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = read(fd, (char *)buf + done, n - done);
		if (r <= 0) return -1;
		done += (size_t)r;
	}
	return 0;
}

/* Write exactly n bytes to fd. Returns 0 on success. */
static int nbd_write_exact(int fd, const void *buf, size_t n)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = write(fd, (const char *)buf + done, n - done);
		if (r <= 0) return -1;
		done += (size_t)r;
	}
	return 0;
}

/*
 * NBD server thread: performs old-style handshake then serves
 * read/write/disc requests until the client disconnects.
 */
void *nbd_server_thread(void *arg)
{
	struct nbd_srv_ctx *ctx = (struct nbd_srv_ctx *)arg;
	int      sock   = ctx->sock_fd;
	int      vfd    = ctx->vhd_fd;
	uint64_t dsz    = ctx->disk_size;
	void    *buf    = NULL;
	uint32_t bufcap = 0;

	/* ---- Old-style NBD handshake ---- */
	{
		uint64_t m1    = htobe64(NBDMAGIC);
		uint64_t m2    = htobe64(CLISERV_MAGIC);
		uint64_t esz   = htobe64(dsz);
		uint32_t flags = htobe32(NBD_FLAG_HAS_FLAGS);
		uint8_t  pad[124] = {0};

		if (nbd_write_exact(sock, &m1,    8)   != 0) goto out;
		if (nbd_write_exact(sock, &m2,    8)   != 0) goto out;
		if (nbd_write_exact(sock, &esz,   8)   != 0) goto out;
		if (nbd_write_exact(sock, &flags, 4)   != 0) goto out;
		if (nbd_write_exact(sock, pad,    124) != 0) goto out;
	}

	/* ---- Request loop ---- */
	for (;;) {
		struct nbd_request req;
		struct nbd_reply   rep;
		uint32_t type, len;
		uint64_t off;
		int32_t  err = 0;

		if (nbd_read_exact(sock, &req, sizeof(req)) != 0) break;
		if (be32toh(req.magic) != NBD_REQUEST_MAGIC)      break;

		type = be32toh(req.type) & 0xffff;
		off  = be64toh(req.from);
		len  = be32toh(req.len);

		if (type == NBD_CMD_DISC) break;

		/* Grow buffer if needed */
		if (len > bufcap) {
			free(buf);
			buf = malloc(len);
			if (!buf) { err = ENOMEM; break; }
			bufcap = len;
		}

		if (type == NBD_CMD_READ) {
			ssize_t n = pread(vfd, buf, len, (off_t)off);
			if (n < 0) err = errno;
			else if ((uint32_t)n < len) memset((char *)buf + n, 0, len - (size_t)n);

			rep.magic  = htobe32(NBD_REPLY_MAGIC);
			rep.error  = htobe32((uint32_t)err);
			memcpy(rep.handle, req.handle, 8);
			if (nbd_write_exact(sock, &rep, sizeof(rep)) != 0) break;
			if (!err && nbd_write_exact(sock, buf, len)  != 0) break;

		} else if (type == NBD_CMD_WRITE) {
			if (nbd_read_exact(sock, buf, len) != 0) break;
			ssize_t n = pwrite(vfd, buf, len, (off_t)off);
			if (n < 0) err = errno;

			rep.magic  = htobe32(NBD_REPLY_MAGIC);
			rep.error  = htobe32((uint32_t)err);
			memcpy(rep.handle, req.handle, 8);
			if (nbd_write_exact(sock, &rep, sizeof(rep)) != 0) break;

		} else if (type == NBD_CMD_FLUSH) {
			fsync(vfd);
			rep.magic  = htobe32(NBD_REPLY_MAGIC);
			rep.error  = 0;
			memcpy(rep.handle, req.handle, 8);
			if (nbd_write_exact(sock, &rep, sizeof(rep)) != 0) break;

		} else {
			/* Unknown command — reply with EINVAL, swallow any data */
			rep.magic  = htobe32(NBD_REPLY_MAGIC);
			rep.error  = htobe32(EINVAL);
			memcpy(rep.handle, req.handle, 8);
			if (nbd_write_exact(sock, &rep, sizeof(rep)) != 0) break;
		}
	}

out:
	free(buf);
	close(sock);
	free(ctx);
	return NULL;
}

/* Thread that calls NBD_DO_IT (blocks until device disconnected) */
static void *nbd_do_it_thread(void *arg)
{
	int fd = *(int *)arg;
	ioctl(fd, NBD_DO_IT);
	return NULL;
}

/*
 * Connect |vhd_fd| (a fixed VHD file, already open) to the first free
 * /dev/nbdX device using kernel NBD ioctls + a userspace server thread.
 * On success, sets nbd_dev[] and nbd_fd_global, returns nbd_dev.
 * On failure returns NULL.
 */
static char *nbd_kernel_connect(int vhd_fd, uint64_t disk_size)
{
	int  socks[2];
	char devpath[64];
	int  nbdfd = -1;

	/* Find a free /dev/nbdX */
	for (int i = 0; i < 16; i++) {
		snprintf(devpath, sizeof(devpath), "/dev/nbd%d", i);
		nbdfd = open(devpath, O_RDWR);
		if (nbdfd >= 0) break;
	}
	if (nbdfd < 0) {
		uprintf("kernel NBD: no free /dev/nbd* device found");
		return NULL;
	}

	/* Socket pair: socks[0] → kernel, socks[1] → userspace server */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) != 0) {
		uprintf("kernel NBD: socketpair failed: %s", strerror(errno));
		close(nbdfd);
		return NULL;
	}

	/* Configure kernel NBD */
	if (ioctl(nbdfd, NBD_SET_SOCK,     socks[0])  != 0 ||
	    ioctl(nbdfd, NBD_SET_BLKSIZE,  512)        != 0 ||
	    ioctl(nbdfd, NBD_SET_SIZE,     disk_size)  != 0) {
		uprintf("kernel NBD: ioctl setup failed: %s", strerror(errno));
		close(socks[0]); close(socks[1]);
		close(nbdfd);
		return NULL;
	}

	/* Start userspace NBD server thread */
	struct nbd_srv_ctx *ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		close(socks[0]); close(socks[1]);
		close(nbdfd);
		return NULL;
	}
	ctx->vhd_fd    = vhd_fd;
	ctx->sock_fd   = socks[1];
	ctx->disk_size = disk_size;

	if (pthread_create(&nbd_server_tid, NULL, nbd_server_thread, ctx) != 0) {
		uprintf("kernel NBD: failed to start server thread: %s", strerror(errno));
		free(ctx);
		close(socks[0]); close(socks[1]);
		close(nbdfd);
		return NULL;
	}

	/* Start the NBD_DO_IT thread (blocks until device is disconnected) */
	static int nbdfd_copy;
	nbdfd_copy = nbdfd;
	if (pthread_create(&nbd_do_it_tid, NULL, nbd_do_it_thread, &nbdfd_copy) != 0) {
		uprintf("kernel NBD: failed to start do_it thread: %s", strerror(errno));
		ioctl(nbdfd, NBD_CLEAR_SOCK);
		pthread_cancel(nbd_server_tid);
		close(socks[0]);
		close(nbdfd);
		return NULL;
	}

	/* Give the device a moment to become ready */
	usleep(200000);

	strncpy(nbd_dev, devpath, sizeof(nbd_dev) - 1);
	nbd_fd_global = nbdfd;
	nbd_srv_sock  = socks[0];
	uprintf("kernel NBD: connected %s to %s", devpath, "VHD");
	return nbd_dev;
}

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
	if (!path) {
		uprintf("  Could not open image: path is NULL");
		return -1;
	}
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		uprintf_errno("  Could not open image '%s'", path);
		is_bootable_img = -1;
		goto out;
	}

	is_bootable_img = IsCompressedBootableImage(path) ? 1 : 0;
	if (img_report.compression_type == BLED_COMPRESSION_NONE) {
		HANDLE h = (HANDLE)(intptr_t)fd;
		is_bootable_img = AnalyzeMBR(h, "  Image", FALSE) ? 1 : (ignore_boot_marker ? 2 : 0);
	}

	if (fstat(fd, &st) != 0) {
		uprintf_errno("  Could not get image size");
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
			uprintf_errno("  Could not rename %s to %s", tmp, dst);
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
 * Mount a VHD/VHDX image and return its block-device path.
 * Tries qemu-nbd first (supports VHDX and dynamic VHDs).
 * Falls back to the kernel NBD server for fixed VHDs only.
 * Returns the path string on success, NULL on failure.
 */
char* VhdMountImageAndGetSize(const char* path, uint64_t* disk_size)
{
	int fd;
	char cmd[1024];
	const char* ext;
	BOOL use_qemu_nbd;

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

	/* Prefer qemu-nbd (handles VHDX + dynamic VHDs) */
	use_qemu_nbd = (access("/usr/bin/qemu-nbd", X_OK) == 0 ||
	                system("which qemu-nbd >/dev/null 2>&1") == 0);

	if (use_qemu_nbd) {
		/* Find a free nbd device and connect via qemu-nbd */
		nbd_dev[0] = '\0';
		for (int i = 0; i < 16; i++) {
			snprintf(nbd_dev, sizeof(nbd_dev), "/dev/nbd%d", i);
			/* Pass explicit format to avoid qemu-nbd probing ambiguity */
			const char *fmt_arg = (strcasecmp(ext, ".vhdx") == 0)
			                       ? "--format=vhdx" : "--format=vpc";
			snprintf(cmd, sizeof(cmd),
				"qemu-nbd %s --connect=%s \"%s\" 2>/dev/null",
				fmt_arg, nbd_dev, path);
			if (system(cmd) == 0) {
				usleep(1000000);  /* let the kernel settle (1 s) */
				break;
			}
			nbd_dev[0] = '\0';
		}

		if (nbd_dev[0] == '\0') {
			uprintf("qemu-nbd: could not connect VHD to nbd device");
			use_qemu_nbd = FALSE;  /* fall through to kernel NBD */
		}
	}

	if (!use_qemu_nbd) {
		/* Kernel NBD fallback: only works for fixed VHDs */
		uint64_t vhd_size = vhd_get_fixed_disk_size(path);
		if (vhd_size == 0) {
			uprintf("kernel NBD: '%s' is not a fixed VHD (dynamic/VHDX requires qemu-nbd)", path);
			return NULL;
		}
		int vfd = open(path, O_RDWR);
		if (vfd < 0) {
			uprintf_errno("kernel NBD: open '%s'", path);
			return NULL;
		}
		if (!nbd_kernel_connect(vfd, vhd_size)) {
			close(vfd);
			return NULL;
		}
		/* nbd_fd_global now owns vfd */
	}

	strncpy(physical_path, nbd_dev, sizeof(physical_path) - 1);
	physical_path[sizeof(physical_path) - 1] = '\0';

	if (disk_size != NULL) {
		/* Poll until the device reports a non-zero size (up to 3 s) */
		*disk_size = 0;
		for (int try = 0; try < 6 && *disk_size == 0; try++) {
			fd = open(nbd_dev, O_RDONLY);
			if (fd >= 0) {
				ioctl(fd, BLKGETSIZE64, disk_size);
				close(fd);
			}
			if (*disk_size == 0)
				usleep(500000); /* wait 500 ms and retry */
		}
	}

	return physical_path;
}

void VhdUnmountImage(void)
{
	char cmd[128];

	if (nbd_dev[0] == '\0')
		goto out;

	if (nbd_fd_global >= 0) {
		/* Kernel NBD path: signal disconnect, join threads, close fds */
		ioctl(nbd_fd_global, NBD_DISCONNECT);
		ioctl(nbd_fd_global, NBD_CLEAR_SOCK);
		pthread_join(nbd_do_it_tid, NULL);
		/* Server thread closes its own socket end and frees ctx */
		pthread_join(nbd_server_tid, NULL);
		close(nbd_fd_global);
		nbd_fd_global = -1;
		nbd_srv_sock  = -1;
	} else {
		/* qemu-nbd path */
		snprintf(cmd, sizeof(cmd),
		         "qemu-nbd --disconnect %s 2>/dev/null", nbd_dev);
		system(cmd);
		sync();
		usleep(200000); /* allow the kernel to fully release the device */
	}

	nbd_dev[0] = '\0';
out:
	physical_path[0] = '\0';
}
