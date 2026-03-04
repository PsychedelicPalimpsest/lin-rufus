/*
 * ventoy_detect.c — Detect existing Ventoy installation on a block device.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <blkid/blkid.h>

#include "ventoy_detect.h"

/* ---- Internal helpers ---- */

/*
 * Build the Nth partition device path from a disk device path.
 * e.g. "/dev/sdb" + 1  → "/dev/sdb1"
 *      "/dev/nvme0n1"+1 → "/dev/nvme0n1p1"
 */
static void make_part_path(const char *dev, int n, char *out, size_t outsz)
{
	/* nvme / mmcblk devices use "p" before the partition number */
	int use_p = (strstr(dev, "nvme") != NULL || strstr(dev, "mmcblk") != NULL);
	snprintf(out, outsz, "%s%s%d", dev, use_p ? "p" : "", n);
}

/* ---- Public API ---- */

BOOL ventoy_check_mbr(const char *dev_path) // cppcheck-suppress staticFunction
{
	if (!dev_path)
		return FALSE;

	int fd = open(dev_path, O_RDONLY);
	if (fd < 0)
		return FALSE;

	uint8_t buf[VENTOY_MBR_MAGIC_LEN];
	ssize_t r = pread(fd, buf, sizeof(buf), VENTOY_MBR_OFFSET);
	close(fd);

	if (r != (ssize_t)sizeof(buf))
		return FALSE;

	return (memcmp(buf, VENTOY_MBR_MAGIC, VENTOY_MBR_MAGIC_LEN) == 0) ? TRUE : FALSE;
}

BOOL ventoy_detect_by_label(const char *dev_path) // cppcheck-suppress staticFunction
{
	if (!dev_path)
		return FALSE;

	char part[64];
	for (int n = 1; n <= 16; n++) {
		make_part_path(dev_path, n, part, sizeof(part));

		blkid_probe pr = blkid_new_probe_from_filename(part);
		if (!pr)
			break;   /* no more partitions */

		blkid_probe_enable_superblocks(pr, 1);
		blkid_probe_set_superblocks_flags(pr, BLKID_SUBLKS_LABEL);

		if (blkid_do_probe(pr) == 0) {
			const char *val = NULL;
			if (blkid_probe_lookup_value(pr, "LABEL", &val, NULL) == 0 && val) {
				if (strcasecmp(val, VENTOY_LABEL_DATA) == 0 ||
				    strcasecmp(val, VENTOY_LABEL_EFI) == 0) {
					blkid_free_probe(pr);
					return TRUE;
				}
			}
		}
		blkid_free_probe(pr);
	}
	return FALSE;
}

BOOL ventoy_detect(const char *dev_path)
{
	if (!dev_path)
		return FALSE;

	/* Strategy 1: MBR magic */
	if (ventoy_check_mbr(dev_path))
		return TRUE;

	/* Strategy 2: partition label scan */
	if (ventoy_detect_by_label(dev_path))
		return TRUE;

	return FALSE;
}
