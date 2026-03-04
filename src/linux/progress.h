/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux: progress.h — write-speed and ETA ring-buffer tracking
 * Copyright © 2024-2025 PsychedelicPalimpsest
 *
 * Ported from the GNU wget progress algorithm used in src/windows/ui.c.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#pragma once

#include <stdint.h>
#include "rufus.h"   /* BOOL */

/* ---- tunables (match Windows ui.h) ------------------------------------ */
#define SPEED_HISTORY_SIZE       20   /* ring-buffer slots                 */
#define SPEED_SAMPLE_MIN        150   /* ms — minimum sample interval      */
#define STALL_START_TIME       5000   /* ms — stall threshold              */
#define SCREEN_REFRESH_INTERVAL 200   /* ms — min time between UI updates  */
#define ETA_REFRESH_INTERVAL    990   /* ms — min time between ETA updates */

/* ---- ring-buffer history --------------------------------------------- */
struct bar_progress_hist {
	uint64_t pos;
	uint64_t times[SPEED_HISTORY_SIZE];   /* sample durations (ms)   */
	uint64_t bytes[SPEED_HISTORY_SIZE];   /* bytes during that slot  */
	uint64_t total_time;                  /* sum of times[]          */
	uint64_t total_bytes;                 /* sum of bytes[]          */
};

/* ---- main progress state --------------------------------------------- */
struct bar_progress {
	uint64_t total_length;        /* expected total bytes               */
	uint64_t count;               /* bytes processed so far             */
	uint64_t last_screen_update;  /* timestamp of last UI refresh       */
	struct bar_progress_hist hist;
	uint64_t recent_start;        /* timestamp of current sample period */
	uint64_t recent_bytes;        /* bytes accumulated in current period */
	BOOL     stalled;             /* TRUE while no data is arriving     */
	uint64_t last_eta_time;       /* timestamp of last ETA calculation  */
	uint32_t last_eta_value;      /* last ETA value shown (seconds)     */
};

/* ---- public API ------------------------------------------------------- */

/** Initialise (or reset) the progress state for a new transfer. */
void bar_reset(struct bar_progress *bp, uint64_t total_length);

/**
 * Record that @howmuch bytes were written at elapsed time @dltime (ms).
 * Call this every time new data is processed; it drives the ring buffer.
 */
void bar_update(struct bar_progress *bp, uint64_t howmuch, uint64_t dltime);

/**
 * Return the current transfer speed in bytes/second, or 0 if unknown.
 * @dl_total_time — elapsed time since the transfer started (ms).
 */
uint64_t bar_get_speed(const struct bar_progress *bp, uint64_t dl_total_time);

/**
 * Return estimated remaining seconds, or UINT32_MAX if unknown.
 * Updates the cached ETA value in @bp when the refresh interval has passed.
 * @dl_total_time — elapsed time since the transfer started (ms).
 */
uint32_t bar_get_eta(struct bar_progress *bp, uint64_t dl_total_time);

/**
 * Format the progress display text according to the current display mode.
 *
 * @out       — output buffer (NUL-terminated string written here)
 * @sz        — size of @out in bytes
 * @mode      — UPT_PERCENT / UPT_SPEED / UPT_ETA (values from ui.h)
 * @percent   — completion percentage (0.0–100.0)
 * @speed_bps — transfer speed in bytes/second (0 = unknown)
 * @eta_s     — estimated remaining seconds (UINT32_MAX = unknown)
 *
 * Produces:
 *   UPT_PERCENT  → "XX.X%"
 *   UPT_SPEED    → "X.X MB/s" / "X.X KB/s" / "N B/s" / "---" (if speed=0)
 *   UPT_ETA      → "H:MM:SS" / "-:--:--" (if eta=UINT32_MAX)
 *   (anything else falls back to UPT_PERCENT)
 */
void format_progress_text(char *out, size_t sz, int mode,
                          double percent, uint64_t speed_bps, uint32_t eta_s);
