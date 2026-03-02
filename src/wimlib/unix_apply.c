/*
 * unix_apply.c — UNIX extraction backend for wimlib.
 *
 * Extracts files from WIM images to a POSIX filesystem.
 * Supports regular files, directories, and symlinks.
 * Does not support Windows-specific features (ACLs, reparse points, etc.).
 *
 * Copyright © 2024 Rufus Linux Port contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _WIN32

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "wimlib/apply.h"
#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/inode.h"
#include "wimlib/list.h"
#include "wimlib/reparse.h"
#include "wimlib/resource.h"
#include "wimlib/util.h"
#include "wimlib.h"

struct unix_apply_ctx {
	/* Must be first */
	struct apply_ctx common;

	/* Open file descriptors for the current blob's extraction targets.
	 * At most MAX_OPEN_FILES descriptors are open at a time.  */
	int open_fds[MAX_OPEN_FILES];
	u32 num_open_fds;
};

/*
 * Build the output path for a dentry on the local filesystem.
 * The returned string is malloc'd and must be freed by the caller.
 *
 * For dentries in NO_PRESERVE_DIR_STRUCTURE mode, we stop walking up the
 * parent chain as soon as we reach a parent not in the extraction list.
 */
static char *
unix_build_extraction_path(const struct apply_ctx *ctx,
			   const struct wim_dentry *dentry)
{
	/* Compute total length of the path */
	size_t total = ctx->target_nchars;
	const struct wim_dentry *d = dentry;

	while (!dentry_is_root(d) &&
	       (d == dentry || will_extract_dentry(d))) {
		total += 1 + d->d_extraction_name_nchars;
		d = d->d_parent;
	}

	char *path = MALLOC(total + 1);
	if (!path)
		return NULL;

	/* Fill from end to start */
	char *p = path + total;
	*p = '\0';

	d = dentry;
	while (!dentry_is_root(d) &&
	       (d == dentry || will_extract_dentry(d))) {
		p -= d->d_extraction_name_nchars;
		memcpy(p, (const char *)d->d_extraction_name,
		       d->d_extraction_name_nchars);
		p--;
		*p = '/';
		d = d->d_parent;
	}

	memcpy(path, ctx->target, ctx->target_nchars);
	return path;
}

/* Create all missing directories in the path */
static int
unix_make_parent_dirs(const char *path)
{
	char *tmp = STRDUP(path);
	if (!tmp)
		return WIMLIB_ERR_NOMEM;

	int ret = 0;
	for (char *p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(tmp, 0755) && errno != EEXIST) {
				ERROR_WITH_ERRNO("Failed to create directory \"%s\"", tmp);
				ret = WIMLIB_ERR_MKDIR;
				goto out;
			}
			*p = '/';
		}
	}
out:
	FREE(tmp);
	return ret;
}

/*
 * Blob callback: open the output file(s) for the current blob.
 */
static int
unix_begin_extract_blob(struct blob_descriptor *blob, void *_ctx)
{
	struct unix_apply_ctx *ctx = _ctx;
	const struct blob_extraction_target *targets = blob_extraction_targets(blob);
	int ret;

	ctx->num_open_fds = 0;

	for (u32 i = 0; i < blob->out_refcnt; i++) {
		const struct wim_inode *inode = targets[i].inode;
		const struct wim_dentry *dentry = inode_first_extraction_dentry(inode);

		if (!dentry)
			continue;

		/* Skip alternate data streams (ADS) - only handle unnamed streams */
		if (!stream_is_unnamed_data_stream(targets[i].stream))
			continue;

		char *path = unix_build_extraction_path(&ctx->common, dentry);
		if (!path)
			return WIMLIB_ERR_NOMEM;

		ret = unix_make_parent_dirs(path);
		if (ret) {
			FREE(path);
			return ret;
		}

		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			ERROR_WITH_ERRNO("Failed to open \"%s\" for writing", path);
			FREE(path);
			return WIMLIB_ERR_OPEN;
		}
		FREE(path);

		ctx->open_fds[ctx->num_open_fds++] = fd;
	}

	return 0;
}

/*
 * Blob callback: write a chunk to all open file descriptors.
 */
static int
unix_continue_extract_blob(const struct blob_descriptor *blob, u64 offset,
			   const void *chunk, size_t size, void *_ctx)
{
	struct unix_apply_ctx *ctx = _ctx;

	(void)blob;
	(void)offset;

	for (u32 i = 0; i < ctx->num_open_fds; i++) {
		const u8 *p = chunk;
		size_t remaining = size;

		while (remaining > 0) {
			ssize_t n = write(ctx->open_fds[i], p, remaining);
			if (n < 0) {
				ERROR_WITH_ERRNO("Failed to write file data");
				return WIMLIB_ERR_WRITE;
			}
			p += n;
			remaining -= n;
		}
	}
	return 0;
}

/*
 * Blob callback: close all open file descriptors.
 */
static int
unix_end_extract_blob(struct blob_descriptor *blob, int status, void *_ctx)
{
	struct unix_apply_ctx *ctx = _ctx;

	(void)blob;

	for (u32 i = 0; i < ctx->num_open_fds; i++) {
		if (close(ctx->open_fds[i]) && !status) {
			ERROR_WITH_ERRNO("Failed to close extracted file");
			status = WIMLIB_ERR_WRITE;
		}
	}
	ctx->num_open_fds = 0;
	return status;
}

static int
unix_get_supported_features(const tchar *target,
			    struct wim_features *supported_features)
{
	(void)target;
	supported_features->timestamps = 1;
	return 0;
}

static int
unix_extract(struct list_head *dentry_list, struct apply_ctx *_ctx)
{
	struct unix_apply_ctx *ctx = (struct unix_apply_ctx *)_ctx;
	struct wim_dentry *dentry;
	int ret;

	/* First pass: create directories */
	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		if (!dentry_is_directory(dentry))
			continue;

		char *path = unix_build_extraction_path(&ctx->common, dentry);
		if (!path)
			return WIMLIB_ERR_NOMEM;

		if (mkdir(path, 0755) && errno != EEXIST) {
			ERROR_WITH_ERRNO("Failed to create directory \"%s\"", path);
			FREE(path);
			return WIMLIB_ERR_MKDIR;
		}
		FREE(path);
	}

	/* Second pass: create empty regular files (those without blobs) */
	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		const struct wim_inode *inode = dentry->d_inode;

		if (dentry_is_directory(dentry))
			continue;
		if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
			continue;

		/* Only create here if there is no unnamed data stream blob.
		 * Files with blobs will be created by the blob callbacks.  */
		if (inode_get_blob_for_unnamed_data_stream_resolved(inode))
			continue;

		char *path = unix_build_extraction_path(&ctx->common, dentry);
		if (!path)
			return WIMLIB_ERR_NOMEM;

		ret = unix_make_parent_dirs(path);
		if (ret) {
			FREE(path);
			return ret;
		}

		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0 && errno != EEXIST) {
			ERROR_WITH_ERRNO("Failed to create \"%s\"", path);
			FREE(path);
			return WIMLIB_ERR_OPEN;
		}
		if (fd >= 0)
			close(fd);
		FREE(path);
	}

	/* Third pass: extract blob data using callbacks */
	struct read_blob_callbacks cbs = {
		.begin_blob    = unix_begin_extract_blob,
		.continue_blob = unix_continue_extract_blob,
		.end_blob      = unix_end_extract_blob,
		.ctx           = ctx,
	};
	ret = extract_blob_list(&ctx->common, &cbs);
	if (ret)
		return ret;

	return 0;
}

static int
unix_will_back_from_wim(struct wim_dentry *dentry, struct apply_ctx *ctx)
{
	(void)dentry;
	(void)ctx;
	return -1; /* Not externally backed */
}

const struct apply_operations unix_apply_ops = {
	.name                   = "UNIX",
	.get_supported_features = unix_get_supported_features,
	.extract                = unix_extract,
	.will_back_from_wim     = unix_will_back_from_wim,
	.context_size           = sizeof(struct unix_apply_ctx),
};

#endif /* !_WIN32 */
