/* Linux stub: format_fat32.c - FAT32 formatting (stub for porting) */
#include "rufus.h"
#include "format.h"

BOOL FormatLargeFAT32(DWORD DriveIndex, uint64_t PartitionOffset, DWORD ClusterSize,
                      LPCSTR FSName, LPCSTR Label, DWORD Flags)
{
    (void)DriveIndex;(void)PartitionOffset;(void)ClusterSize;
    (void)FSName;(void)Label;(void)Flags;
    return FALSE;
}
