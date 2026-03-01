/* Linux stub: badblocks.c - bad block checking (stub for porting) */
#include "rufus.h"
#include "badblocks.h"

BOOL BadBlocks(HANDLE hPhysicalDrive, ULONGLONG disk_size, int nb_passes,
               int flash_type, badblocks_report *report, FILE* fd)
{
    (void)hPhysicalDrive; (void)disk_size; (void)nb_passes;
    (void)flash_type; (void)report; (void)fd;
    return FALSE;
}
