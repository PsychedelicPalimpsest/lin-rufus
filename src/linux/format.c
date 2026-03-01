/* Linux stub: format.c - disk formatting (stub for porting) */
#include "rufus.h"
#include "format.h"

BOOL FormatPartition(DWORD di, uint64_t off, DWORD uas, USHORT fs, LPCSTR label, DWORD flags)
{
    (void)di;(void)off;(void)uas;(void)fs;(void)label;(void)flags;
    return FALSE;
}

BOOL WritePBR(HANDLE hLogicalVolume)
{
    (void)hLogicalVolume;
    return FALSE;
}

DWORD WINAPI FormatThread(void* param)
{
    (void)param;
    return 0;
}

