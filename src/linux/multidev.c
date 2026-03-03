/*
 * multidev.c — Multi-device simultaneous write logic (Linux).
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <string.h>
#include "multidev.h"

void multidev_init(multidev_session_t *s)
{
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
}

int multidev_add_target(multidev_session_t *s, DWORD DriveIndex,
                        const char *name, uint64_t size)
{
	if (!s || s->n_targets >= MULTIDEV_MAX_TARGETS)
		return -1;

	int idx = s->n_targets;
	s->targets[idx].DriveIndex = DriveIndex;
	s->targets[idx].size       = size;
	s->targets[idx].selected   = FALSE;
	s->targets[idx].progress   = 0.0f;
	s->targets[idx].result     = MULTIDEV_RESULT_PENDING;

	if (name)
		strncpy(s->targets[idx].name, name, sizeof(s->targets[idx].name) - 1);
	else
		s->targets[idx].name[0] = '\0';

	s->n_targets++;
	return idx;
}

int multidev_set_selected(multidev_session_t *s, int idx, BOOL selected)
{
	if (!s || idx < 0 || idx >= s->n_targets)
		return -1;
	s->targets[idx].selected = selected;
	return 0;
}

int multidev_count_selected(const multidev_session_t *s)
{
	if (!s)
		return 0;
	int count = 0;
	for (int i = 0; i < s->n_targets; i++)
		if (s->targets[i].selected)
			count++;
	return count;
}

int multidev_set_progress(multidev_session_t *s, int idx, float progress)
{
	if (!s || idx < 0 || idx >= s->n_targets)
		return -1;
	s->targets[idx].progress = progress;
	return 0;
}

int multidev_set_result(multidev_session_t *s, int idx, int result)
{
	if (!s || idx < 0 || idx >= s->n_targets)
		return -1;
	s->targets[idx].result = result;
	return 0;
}

BOOL multidev_all_done(const multidev_session_t *s)
{
	if (!s)
		return FALSE;

	int n_selected = 0;
	for (int i = 0; i < s->n_targets; i++) {
		if (!s->targets[i].selected)
			continue;
		n_selected++;
		if (s->targets[i].result == MULTIDEV_RESULT_PENDING)
			return FALSE;
	}
	return (n_selected > 0) ? TRUE : FALSE;
}

int multidev_count_success(const multidev_session_t *s)
{
	if (!s)
		return 0;
	int count = 0;
	for (int i = 0; i < s->n_targets; i++)
		if (s->targets[i].selected &&
		    s->targets[i].result == MULTIDEV_RESULT_SUCCESS)
			count++;
	return count;
}

int multidev_count_failure(const multidev_session_t *s)
{
	if (!s)
		return 0;
	int count = 0;
	for (int i = 0; i < s->n_targets; i++)
		if (s->targets[i].selected &&
		    s->targets[i].result == MULTIDEV_RESULT_FAILURE)
			count++;
	return count;
}
