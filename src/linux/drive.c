/* Linux stub: drive.c - drive operations (stub for porting) */
#include "rufus.h"
#include "drive.h"

BOOL SetAutoMount(BOOL enable)                        { (void)enable; return FALSE; }
BOOL GetAutoMount(BOOL* enabled)                      { (void)enabled; return FALSE; }
char* GetPhysicalName(DWORD DriveIndex)               { (void)DriveIndex; return NULL; }
BOOL DeletePartition(DWORD di, ULONGLONG off, BOOL s) { (void)di;(void)off;(void)s; return FALSE; }
BOOL IsVdsAvailable(BOOL bSilent)                     { (void)bSilent; return FALSE; }
BOOL ListVdsVolumes(BOOL bSilent)                     { (void)bSilent; return FALSE; }
BOOL VdsRescan(DWORD rt, DWORD st, BOOL s)            { (void)rt;(void)st;(void)s; return FALSE; }
HANDLE GetPhysicalHandle(DWORD di, BOOL lock, BOOL wr, BOOL ws) { (void)di;(void)lock;(void)wr;(void)ws; return INVALID_HANDLE_VALUE; }
char* GetLogicalName(DWORD di, uint64_t off, BOOL trail, BOOL s) { (void)di;(void)off;(void)trail;(void)s; return NULL; }
char* AltGetLogicalName(DWORD di, uint64_t off, BOOL trail, BOOL s) { (void)di;(void)off;(void)trail;(void)s; return NULL; }
char* GetExtPartitionName(DWORD di, uint64_t off)     { (void)di;(void)off; return NULL; }
BOOL WaitForLogical(DWORD di, uint64_t off)           { (void)di;(void)off; return FALSE; }
HANDLE GetLogicalHandle(DWORD di, uint64_t off, BOOL lock, BOOL wr, BOOL ws) { (void)di;(void)off;(void)lock;(void)wr;(void)ws; return INVALID_HANDLE_VALUE; }
HANDLE AltGetLogicalHandle(DWORD di, uint64_t off, BOOL lock, BOOL wr, BOOL ws) { (void)di;(void)off;(void)lock;(void)wr;(void)ws; return INVALID_HANDLE_VALUE; }
int GetDriveNumber(HANDLE hDrive, char* path)         { (void)hDrive;(void)path; return -1; }
BOOL GetDriveLetters(DWORD di, char* dl)              { (void)di;(void)dl; return FALSE; }
UINT GetDriveTypeFromIndex(DWORD di)                  { (void)di; return 0; }
char GetUnusedDriveLetter(void)                       { return 0; }
BOOL IsDriveLetterInUse(const char dl)                { (void)dl; return FALSE; }
char RemoveDriveLetters(DWORD di, BOOL last, BOOL s)  { (void)di;(void)last;(void)s; return 0; }
BOOL GetDriveLabel(DWORD di, char* letters, char** label, BOOL s) { (void)di;(void)letters;(void)label;(void)s; return FALSE; }
uint64_t GetDriveSize(DWORD di)                       { (void)di; return 0; }
BOOL IsMediaPresent(DWORD di)                         { (void)di; return FALSE; }
BOOL AnalyzeMBR(HANDLE h, const char* name, BOOL s)   { (void)h;(void)name;(void)s; return FALSE; }
BOOL AnalyzePBR(HANDLE h)                             { (void)h; return FALSE; }
BOOL GetDrivePartitionData(DWORD di, char* fs, DWORD fss, BOOL s) { (void)di;(void)fs;(void)fss;(void)s; return FALSE; }
BOOL UnmountVolume(HANDLE hDrive)                     { (void)hDrive; return FALSE; }
BOOL MountVolume(char* dn, char* dg)                  { (void)dn;(void)dg; return FALSE; }
BOOL AltUnmountVolume(const char* dn, BOOL s)         { (void)dn;(void)s; return FALSE; }
char* AltMountVolume(DWORD di, uint64_t off, BOOL s)  { (void)di;(void)off;(void)s; return NULL; }
BOOL RemountVolume(char* dn, BOOL s)                  { (void)dn;(void)s; return FALSE; }
BOOL CreatePartition(HANDLE h, int ps, int fs, BOOL mbr, uint8_t extra) { (void)h;(void)ps;(void)fs;(void)mbr;(void)extra; return FALSE; }
BOOL InitializeDisk(HANDLE hDrive)                    { (void)hDrive; return FALSE; }
BOOL RefreshDriveLayout(HANDLE hDrive)                { (void)hDrive; return FALSE; }
const char* GetMBRPartitionType(const uint8_t type)   { (void)type; return ""; }
const char* GetGPTPartitionType(const GUID* guid)     { (void)guid; return ""; }
BOOL RefreshLayout(DWORD di)                          { (void)di; return FALSE; }
uint64_t GetEspOffset(DWORD di)                       { (void)di; return 0; }
BOOL ToggleEsp(DWORD di, uint64_t off)                { (void)di;(void)off; return FALSE; }
BOOL IsMsDevDrive(DWORD di)                           { (void)di; return FALSE; }
BOOL IsFilteredDrive(DWORD di)                        { (void)di; return FALSE; }
