/*
 * Rufus: The Reliable USB Formatting Utility
 * Common partition-type lookup — shared between Linux and Windows builds.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * On Linux the GUID constants in gpt_types.h need to be instantiated in
 * exactly one translation unit.  INITGUID makes DEFINE_GUID emit definitions
 * (not extern declarations).  On Windows DEFINE_GUID uses DECLSPEC_SELECTANY
 * so every TU gets its own copy and the linker folds them — INITGUID is not
 * needed and must NOT be forced here (it would override the Windows default).
 */

#ifndef _WIN32
#define INITGUID
#endif

#include <stdint.h>
#include <string.h>

#include "rufus.h"
#include "../windows/mbr_types.h"
#include "../windows/gpt_types.h"
#include "drive.h"

const char *GetMBRPartitionType(const uint8_t type)
{
    for (int i = 0; i < (int)(sizeof(mbr_type) / sizeof(mbr_type[0])); i++) {
        if (mbr_type[i].type == type)
            return mbr_type[i].name;
    }
    return "Unknown";
}

const char *GetGPTPartitionType(const GUID *guid)
{
    for (int i = 0; i < (int)(sizeof(gpt_type) / sizeof(gpt_type[0])); i++) {
        if (CompareGUID(guid, gpt_type[i].guid))
            return gpt_type[i].name;
    }
    return GuidToString(guid, TRUE);
}
