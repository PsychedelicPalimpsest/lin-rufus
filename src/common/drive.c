/*
 * Rufus: The Reliable USB Formatting Utility
 * Common drive utilities — shared between Linux and Windows builds.
 *
 * Provides:
 *  - GetMBRPartitionType() / GetGPTPartitionType() — partition-type lookup
 *  - AnalyzeMBR() / AnalyzePBR() — boot-sector analysis via ms-sys FAKE_FD
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

/* ms-sys headers for boot-record analysis */
#include "../ms-sys/inc/file.h"
#include "../ms-sys/inc/br.h"
#include "../ms-sys/inc/fat16.h"
#include "../ms-sys/inc/fat32.h"

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

/* ---- Boot-sector analysis ------------------------------------------------
 *
 * Both AnalyzeMBR() and AnalyzePBR() use the ms-sys FAKE_FD trick: they cast
 * the HANDLE (a file descriptor on Linux, a Win32 HANDLE on Windows) into the
 * _handle field of a zeroed FAKE_FD struct and alias that struct as a FILE*.
 * The ms-sys read_data/contains_data paths then use SetFilePointerEx/ReadFile
 * (real on Windows, compat-mapped to lseek/read on Linux) to access the data.
 */

static const struct { int (*fn)(FILE *fp); const char *str; } known_mbr[] = {
    { is_dos_mbr,         "DOS/NT/95A" },
    { is_dos_f2_mbr,      "DOS/NT/95A (F2)" },
    { is_95b_mbr,         "Windows 95B/98/98SE/ME" },
    { is_2000_mbr,        "Windows 2000/XP/2003" },
    { is_vista_mbr,       "Windows Vista" },
    { is_win7_mbr,        "Windows 7" },
    { is_rufus_mbr,       "Rufus" },
    { is_syslinux_mbr,    "Syslinux" },
    { is_reactos_mbr,     "ReactOS" },
    { is_kolibrios_mbr,   "KolibriOS" },
    { is_grub4dos_mbr,    "Grub4DOS" },
    { is_grub2_mbr,       "Grub 2.0" },
    { is_zero_mbr_not_including_disk_signature_or_copy_protect, "Zeroed" },
};

static const struct { int (*fn)(FILE *fp); const char *str; } known_pbr[] = {
    { entire_fat_16_br_matches,     "FAT16 DOS" },
    { entire_fat_16_fd_br_matches,  "FAT16 FreeDOS" },
    { entire_fat_16_ros_br_matches, "FAT16 ReactOS" },
    { entire_fat_32_br_matches,     "FAT32 DOS" },
    { entire_fat_32_nt_br_matches,  "FAT32 NT" },
    { entire_fat_32_fd_br_matches,  "FAT32 FreeDOS" },
    { entire_fat_32_ros_br_matches, "FAT32 ReactOS" },
    { entire_fat_32_kos_br_matches, "FAT32 KolibriOS" },
};

/* Returns TRUE if the drive seems bootable, FALSE otherwise */
BOOL AnalyzeMBR(HANDLE hPhysicalDrive, const char *TargetName, BOOL bSilent)
{
    FAKE_FD fake_fd = { 0 };
    FILE *fp = (FILE *)&fake_fd;
    int i;

    if (!hPhysicalDrive || hPhysicalDrive == INVALID_HANDLE_VALUE)
        return FALSE;

    fake_fd._handle = (void *)hPhysicalDrive;
    set_bytes_per_sector(SelectedDrive.SectorSize ? SelectedDrive.SectorSize : 512);

    if (!is_br(fp)) {
        suprintf("%s does not have a Boot Marker", TargetName ? TargetName : "Drive");
        return FALSE;
    }
    for (i = 0; i < (int)(sizeof(known_mbr) / sizeof(known_mbr[0])); i++) {
        if (known_mbr[i].fn(fp)) {
            suprintf("%s has a %s Master Boot Record",
                     TargetName ? TargetName : "Drive", known_mbr[i].str);
            return TRUE;
        }
    }
    suprintf("%s has an unknown Master Boot Record", TargetName ? TargetName : "Drive");
    return TRUE;
}

BOOL AnalyzePBR(HANDLE hLogicalVolume)
{
    const char *pbr_name = "Partition Boot Record";
    FAKE_FD fake_fd = { 0 };
    FILE *fp = (FILE *)&fake_fd;
    int i;

    if (!hLogicalVolume || hLogicalVolume == INVALID_HANDLE_VALUE)
        return FALSE;

    fake_fd._handle = (void *)hLogicalVolume;
    set_bytes_per_sector(SelectedDrive.SectorSize ? SelectedDrive.SectorSize : 512);

    if (!is_br(fp)) {
        uprintf("Volume does not have an x86 %s", pbr_name);
        return FALSE;
    }

    if (is_fat_16_br(fp) || is_fat_32_br(fp)) {
        for (i = 0; i < (int)(sizeof(known_pbr) / sizeof(known_pbr[0])); i++) {
            if (known_pbr[i].fn(fp)) {
                uprintf("Drive has a %s %s", known_pbr[i].str, pbr_name);
                return TRUE;
            }
        }
        uprintf("Volume has an unknown FAT16 or FAT32 %s", pbr_name);
    } else {
        uprintf("Volume has an unknown %s", pbr_name);
    }
    return TRUE;
}
