/* Linux stub: smart.c - S.M.A.R.T. disk data (stub for porting) */
#include "rufus.h"
#include "smart.h"

const char* SptStrerr(int errcode)           { (void)errcode; return ""; }
BOOL Identify(HANDLE hPhysical)              { (void)hPhysical; return FALSE; }
BOOL SmartGetVersion(HANDLE hdevice)         { (void)hdevice; return FALSE; }
int IsHDD(DWORD di, uint16_t vid, uint16_t pid, const char* strid)
    { (void)di;(void)vid;(void)pid;(void)strid; return 0; }
