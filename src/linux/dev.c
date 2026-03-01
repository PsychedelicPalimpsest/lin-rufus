/* Linux stub: dev.c - device enumeration (stub for porting) */
#include "rufus.h"
#include "dev.h"
#include "drive.h"

BOOL CyclePort(int index)                            { (void)index; return FALSE; }
int  CycleDevice(int index)                          { (void)index; return 0; }
BOOL GetOpticalMedia(IMG_SAVE* img_save)             { (void)img_save; return FALSE; }
void ClearDrives(void)                               {}
BOOL GetDevices(DWORD devnum)                        { (void)devnum; return FALSE; }
