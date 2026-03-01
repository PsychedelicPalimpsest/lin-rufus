/* Linux stub: format_ext.c - ext filesystem formatting (stub for porting) */
#include "rufus.h"
#include "format.h"
#include "ext2fs/ext2fs.h"

const char* error_message(errcode_t error_code)
{
    (void)error_code;
    return "error";
}

errcode_t ext2fs_print_progress(int64_t cur_value, int64_t max_value)
{
    (void)cur_value;(void)max_value;
    return 0;
}

const char* GetExtFsLabel(DWORD DriveIndex, uint64_t PartitionOffset)
{
    (void)DriveIndex;(void)PartitionOffset;
    return NULL;
}

BOOL FormatExtFs(DWORD DriveIndex, uint64_t PartitionOffset, DWORD BlockSize,
                 LPCSTR FSName, LPCSTR Label, DWORD Flags)
{
    (void)DriveIndex;(void)PartitionOffset;(void)BlockSize;
    (void)FSName;(void)Label;(void)Flags;
    return FALSE;
}

DWORD ext2_last_winerror(DWORD default_error)
{
    (void)default_error;
    return 0;
}
