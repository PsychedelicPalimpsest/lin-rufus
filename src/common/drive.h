/*
 * Rufus: The Reliable USB Formatting Utility
 * Common drive-utility declarations — shared between Linux and Windows builds.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdint.h>
#include "rufus.h"

/*
 * GetMBRPartitionType — look up a human-readable name for an MBR
 * partition-type byte (0x00–0xFF).
 *
 * Returns a pointer to a constant string.  Unknown types return "Unknown".
 * The pointer is always non-NULL.
 */
const char *GetMBRPartitionType(uint8_t type);

/*
 * GetGPTPartitionType — look up a human-readable name for a GPT partition
 * GUID.
 *
 * Returns a pointer to a string.  Unknown GUIDs return the GUID formatted as
 * a hex string (via GuidToString).  The pointer is always non-NULL.
 */
const char *GetGPTPartitionType(const GUID *guid);
