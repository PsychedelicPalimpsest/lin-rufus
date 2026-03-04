/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux: progress.c — write-speed and ETA ring-buffer tracking
 * Copyright © 2024-2025 PsychedelicPalimpsest
 *
 * Ported from the GNU wget progress algorithm used in src/windows/ui.c.
 * Key differences from the Windows version:
 *   - No Win32 GetTickCount64(); callers supply elapsed_ms themselves.
 *   - bar_get_speed() / bar_get_eta() are separate pure functions.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>

#include "progress.h"

/* ── bar_reset ─────────────────────────────────────────────────────────── */

void bar_reset(struct bar_progress *bp, uint64_t total_length)
{
	memset(bp, 0, sizeof(*bp));
	bp->total_length = total_length;
}

/* ── bar_update ────────────────────────────────────────────────────────── */
/*
 * Record that @howmuch bytes were written at @dltime ms since start.
 * Maintains the ring buffer of (duration, bytes) pairs used for speed
 * and ETA calculation.  Mirrors bar_update() in src/windows/ui.c.
 */
void bar_update(struct bar_progress *bp, uint64_t howmuch, uint64_t dltime)
{
	struct bar_progress_hist *hist = &bp->hist;
	uint64_t recent_age = dltime - bp->recent_start;

	bp->recent_bytes += howmuch;

	/* Not enough time has elapsed to add a new ring entry yet. */
	if (recent_age < SPEED_SAMPLE_MIN)
		return;

	if (howmuch == 0) {
		/* Zero-byte call: check for stall condition. */
		if (recent_age >= STALL_START_TIME) {
			bp->stalled = TRUE;
			memset(hist, 0, sizeof(*hist));
			bp->recent_bytes = 0;
		}
		return;
	}

	/* If recovering from stall, use a short artificial age to avoid a
	 * bogus low-speed reading covering the whole stall period. */
	if (bp->stalled) {
		bp->stalled    = FALSE;
		recent_age     = 1000;
	}

	/* Evict the oldest entry at position hist->pos. */
	hist->total_time  -= hist->times[hist->pos];
	hist->total_bytes -= hist->bytes[hist->pos];

	/* Store the new sample. */
	hist->times[hist->pos]  = recent_age;
	hist->bytes[hist->pos]  = bp->recent_bytes;
	hist->total_time        += recent_age;
	hist->total_bytes       += bp->recent_bytes;

	/* Start a fresh "recent" window. */
	bp->recent_start = dltime;
	bp->recent_bytes = 0;

	/* Advance ring position. */
	if (++hist->pos == SPEED_HISTORY_SIZE)
		hist->pos = 0;
}

/* ── bar_get_speed ─────────────────────────────────────────────────────── */
/*
 * Returns the current transfer speed in bytes/second, or 0 if unknown.
 * @dl_total_time: total elapsed ms since the transfer started.
 *
 * Mirrors the speed calculation inside _UpdateProgressWithInfo() in
 * src/windows/ui.c:
 *   speed = (hist->total_bytes + recent_bytes) * 1000
 *           / (hist->total_time + (dl_total_time - recent_start))
 */
uint64_t bar_get_speed(const struct bar_progress *bp, uint64_t dl_total_time)
{
	if (bp->hist.total_time <= 999 || bp->hist.total_bytes == 0)
		return 0;

	uint64_t dlquant = bp->hist.total_bytes + bp->recent_bytes;
	uint64_t dltime  = bp->hist.total_time + (dl_total_time - bp->recent_start);

	if (dltime == 0)
		return 0;

	return (dlquant * 1000) / dltime;
}

/* ── bar_get_eta ───────────────────────────────────────────────────────── */
/*
 * Returns estimated remaining seconds, or UINT32_MAX if unknown.
 * @dl_total_time: total elapsed ms since the transfer started.
 *
 * Caches the ETA for ETA_REFRESH_INTERVAL ms to prevent flicker.
 * Mirrors the ETA block inside _UpdateProgressWithInfo() in
 * src/windows/ui.c.
 */
uint32_t bar_get_eta(struct bar_progress *bp, uint64_t dl_total_time)
{
	/* Need at least 3 s of history and a non-zero byte count. */
	if (bp->total_length == 0 || bp->count == 0 || dl_total_time < 3000)
		return UINT32_MAX;

	/* Return the cached value if the refresh interval hasn't passed. */
	if (bp->last_eta_value != 0 &&
	    bp->total_length != bp->count &&
	    dl_total_time - bp->last_eta_time < ETA_REFRESH_INTERVAL)
		return bp->last_eta_value;

	uint64_t bytes_remaining = bp->total_length - bp->count;
	/* ETA = elapsed_s × bytes_remaining / bytes_done */
	double d_eta = ((double)dl_total_time / 1000.0) *
	               ((double)bytes_remaining / (double)bp->count);

	if (d_eta < 0.0 || d_eta >= (double)(UINT32_MAX - 1))
		return UINT32_MAX;

	uint32_t eta = (uint32_t)(d_eta + 0.5);
	bp->last_eta_value = eta;
	bp->last_eta_time  = dl_total_time;
	return eta;
}

/* ── format_progress_text ──────────────────────────────────────────────── */

void format_progress_text(char *out, size_t sz, int mode,
                          double percent, uint64_t speed_bps, uint32_t eta_s)
{
	/* Use integer values matching UPT_SPEED=1 and UPT_ETA=2 from ui.h,
	 * so this file does not need to include ui.h (which depends on rufus.h
	 * context not available here). */
	switch (mode) {
	case 1: /* UPT_SPEED */
		if (speed_bps == 0) {
			snprintf(out, sz, "---");
		} else if (speed_bps >= (uint64_t)1024 * 1024) {
			snprintf(out, sz, "%.1f MB/s",
			         (double)speed_bps / (1024.0 * 1024.0));
		} else if (speed_bps >= 1024) {
			snprintf(out, sz, "%.1f KB/s",
			         (double)speed_bps / 1024.0);
		} else {
			snprintf(out, sz, "%" PRIu64 " B/s", speed_bps);
		}
		break;

	case 2: /* UPT_ETA */
		if (eta_s == UINT32_MAX) {
			snprintf(out, sz, "-:--:--");
		} else {
			snprintf(out, sz, "%u:%02u:%02u",
			         eta_s / 3600,
			         (eta_s % 3600) / 60,
			         eta_s % 60);
		}
		break;

	default: /* UPT_PERCENT (0) and anything unrecognised */
		snprintf(out, sz, "%.1f%%", percent);
		break;
	}
}
