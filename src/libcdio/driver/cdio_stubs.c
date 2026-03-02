/*
 * cdio_stubs.c — Stub implementations of cdio_open/cdio_destroy for Linux.
 *
 * Rufus bundles only the ISO9660, UDF, and driver sub-libraries from libcdio.
 * The full cdio_open (CD-ROM driver enumeration) is NOT needed — Rufus always
 * opens disc images as streams, never as physical CD-ROM drives.
 *
 * udf_fs.c calls cdio_open() and falls back to cdio_stdio_new() on NULL.
 * These stubs return NULL / are no-ops so the fallback path is always taken.
 *
 * Copyright © 2024 Rufus Linux Port contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef _WIN32

#include "../cdio/cdio.h"
#include "../cdio/device.h"

CdIo_t *cdio_open(const char *psz_source, driver_id_t driver_id)
{
	(void)psz_source;
	(void)driver_id;
	return NULL;
}

void cdio_destroy(CdIo_t *p_cdio)
{
	(void)p_cdio;
}

#endif /* !_WIN32 */
