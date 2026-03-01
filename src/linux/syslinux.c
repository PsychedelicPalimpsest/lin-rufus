/* Linux stub: syslinux.c - syslinux bootloader installation (stub) */
#include "rufus.h"

typedef uint32_t libfat_sector_t;
int libfat_readfile(intptr_t pp, void* buf, size_t secsize, libfat_sector_t sector)
    { (void)pp;(void)buf;(void)secsize;(void)sector; return -1; }
BOOL InstallSyslinux(DWORD drive_index, char drive_letter, int file_system)
    { (void)drive_index;(void)drive_letter;(void)file_system; return FALSE; }
uint16_t GetSyslinuxVersion(char* buf, size_t buf_size, char** ext)
    { (void)ext; if(buf&&buf_size) buf[0]=0; return 0; }
