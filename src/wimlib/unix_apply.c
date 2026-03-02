/*
 * unix_apply.c — Stub UNIX extraction backend for wimlib.
 *
 * On Linux, WIM extraction to a UNIX filesystem is not yet implemented.
 * This stub provides the required unix_apply_ops symbol so the binary links.
 *
 * TODO: implement proper UNIX WIM extraction using POSIX APIs (Phase 5+).
 *
 * Copyright © 2024 Rufus Linux Port contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _WIN32

#include "wimlib/apply.h"
#include "wimlib.h"

static int
unix_get_supported_features(const tchar *target,
			     struct wim_features *supported_features)
{
	(void)target;
	(void)supported_features;
	/* Indicate no supported features — extraction will be refused gracefully. */
	return 0;
}

static int
unix_extract(struct list_head *dentry_list, struct apply_ctx *ctx)
{
	(void)dentry_list;
	(void)ctx;
	return WIMLIB_ERR_UNSUPPORTED;
}

static int
unix_will_back_from_wim(struct wim_dentry *dentry, struct apply_ctx *ctx)
{
	(void)dentry;
	(void)ctx;
	return 0;
}

const struct apply_operations unix_apply_ops = {
	.name                 = "UNIX (stub)",
	.get_supported_features = unix_get_supported_features,
	.extract              = unix_extract,
	.will_back_from_wim   = unix_will_back_from_wim,
	.context_size         = 0,
};

#endif /* !_WIN32 */
