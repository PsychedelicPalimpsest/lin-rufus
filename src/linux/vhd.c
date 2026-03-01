/* Linux stub: vhd.c - VHD/WIM file handling (stub for porting) */
#include "rufus.h"
#include "vhd.h"

int8_t IsBootableImage(const char* path)             { (void)path; return 0; }
uint32_t GetWimVersion(const char* image)            { (void)image; return 0; }
BOOL WimExtractFile(const char* img, int idx, const char* src, const char* dst) { (void)img;(void)idx;(void)src;(void)dst; return FALSE; }
BOOL WimSplitFile(const char* src, const char* dst)  { (void)src;(void)dst; return FALSE; }
BOOL WimApplyImage(const char* img, int idx, const char* dst) { (void)img;(void)idx;(void)dst; return FALSE; }
char* VhdMountImageAndGetSize(const char* path, uint64_t* ds) { (void)path;(void)ds; return NULL; }
void VhdUnmountImage(void)                           {}
