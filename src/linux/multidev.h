/*
 * multidev.h — Multi-device simultaneous write support (Linux).
 *
 * Pure C logic (no GTK dependency) so it can be unit-tested.
 * The GTK dialog integration lives in ui_gtk.c.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once
#ifndef RUFUS_MULTIDEV_H
#define RUFUS_MULTIDEV_H

#include <stdint.h>

/* Use the Linux compat layer for BOOL/DWORD when building on Linux */
#ifndef _WIN32
#  include "compat/windows.h"
#else
#  include "../windows/rufus.h"
#endif

/* Maximum number of simultaneous write targets */
#define MULTIDEV_MAX_TARGETS  32

/* Per-target state */
typedef struct {
	DWORD    DriveIndex;         /* index into drive enumeration */
	char     name[256];          /* human-readable label */
	uint64_t size;               /* drive size in bytes */
	BOOL     selected;           /* whether this target is selected */
	float    progress;           /* 0.0 – 100.0 */
	int      result;             /* MULTIDEV_RESULT_* */
} multidev_target_t;

/* Result codes */
#define MULTIDEV_RESULT_PENDING  0
#define MULTIDEV_RESULT_SUCCESS  1
#define MULTIDEV_RESULT_FAILURE -1

/* Session holding all state for one multi-write operation */
typedef struct {
	int               n_targets;
	multidev_target_t targets[MULTIDEV_MAX_TARGETS];
} multidev_session_t;

/* ---- API ---- */

/*
 * Initialise a session to empty state.
 */
void multidev_init(multidev_session_t *s);

/*
 * Add a target to the session.  Returns the target index (0-based) on
 * success, or -1 if the session is full.
 */
int multidev_add_target(multidev_session_t *s, DWORD DriveIndex,
                        const char *name, uint64_t size);

/*
 * Set/clear the selected flag for target |idx|.
 * Returns 0 on success, -1 on out-of-range index.
 */
int multidev_set_selected(multidev_session_t *s, int idx, BOOL selected);

/*
 * Return the number of targets that have selected == TRUE.
 */
int multidev_count_selected(const multidev_session_t *s);

/*
 * Update the progress value for target |idx| (0.0–100.0).
 * Returns 0 on success, -1 on out-of-range.
 */
int multidev_set_progress(multidev_session_t *s, int idx, float progress);

/*
 * Set the result for target |idx| (MULTIDEV_RESULT_SUCCESS or _FAILURE).
 * Returns 0 on success, -1 on out-of-range.
 */
int multidev_set_result(multidev_session_t *s, int idx, int result);

/*
 * Return TRUE if all *selected* targets have a non-PENDING result.
 * Returns FALSE if any selected target is still pending, or if there
 * are no selected targets.
 */
BOOL multidev_all_done(const multidev_session_t *s);

/*
 * Return the number of selected targets with MULTIDEV_RESULT_SUCCESS.
 */
int multidev_count_success(const multidev_session_t *s);

/*
 * Return the number of selected targets with MULTIDEV_RESULT_FAILURE.
 */
int multidev_count_failure(const multidev_session_t *s);

#endif /* RUFUS_MULTIDEV_H */
