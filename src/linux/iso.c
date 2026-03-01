/* Linux stub: iso.c - ISO file handling (stub for porting) */
#include "rufus.h"
#include "resource.h"
#include "vhd.h"
#include "syslinux/libfat/libfat.h"


void GetGrubVersion(char* buf, size_t sz, const char* src) { (void)src; if(buf&&sz) buf[0]=0; }
void GetGrubFs(char* buf, size_t sz)                       { if(buf&&sz) buf[0]=0; }
void GetEfiBootInfo(char* buf, size_t sz, const char* src) { (void)src; if(buf&&sz) buf[0]=0; }
BOOL ExtractISO(const char* src, const char* dst, BOOL scan) { (void)src;(void)dst;(void)scan; return FALSE; }
int64_t ExtractISOFile(const char* iso, const char* isofile, const char* dst, DWORD attr) { (void)iso;(void)isofile;(void)dst;(void)attr; return -1; }
uint32_t ReadISOFileToBuffer(const char* iso, const char* isofile, uint8_t** buf) { (void)iso;(void)isofile;(void)buf; return 0; }
int iso9660_readfat(intptr_t pp, void* buf, size_t sec, libfat_sector_t s) { (void)pp;(void)buf;(void)sec;(void)s; return -1; }
BOOL HasEfiImgBootLoaders(void)                            { return FALSE; }
BOOL DumpFatDir(const char* path, int32_t cluster)         { (void)path;(void)cluster; return FALSE; }
void OpticalDiscSaveImage(void)                            {}
DWORD WINAPI IsoSaveImageThread(void* param)               { (void)param; return 0; }
BOOL SaveImage(void)                                       { return FALSE; }
