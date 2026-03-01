/* Linux stub: process.c - process management (stub for porting) */
#include "rufus.h"

NTSTATUS PhEnumHandlesEx(void* Handles)            { (void)Handles; return 0; }
NTSTATUS PhOpenProcess(HANDLE* h, DWORD access, HANDLE pid) { (void)h;(void)access;(void)pid; return 0; }
DWORD    GetPPID(DWORD pid)                        { (void)pid; return 0; }
BOOL     StartProcessSearch(void)                  { return FALSE; }
void     StopProcessSearch(void)                   {}
BOOL     SetProcessSearch(DWORD devnum)            { (void)devnum; return FALSE; }
BYTE     GetProcessSearch(uint32_t t, uint8_t m, BOOL b) { (void)t;(void)m;(void)b; return 0; }
BOOL     SearchProcessAlt(char* name)              { (void)name; return FALSE; }
BOOL     EnablePrivileges(void)                    { return TRUE; }
char*    NtStatusError(NTSTATUS s)                 { (void)s; return ""; }
