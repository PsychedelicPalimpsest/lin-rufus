/* Linux stub: wue.c - Windows Update Experience (stub for porting) */
#include "rufus.h"
#include "wue.h"


char* CreateUnattendXml(int arch, int flags)                    { (void)arch;(void)flags; return NULL; }
BOOL  SetupWinPE(char drive_letter)                             { (void)drive_letter; return FALSE; }
BOOL  PopulateWindowsVersion(void)                              { return FALSE; }
BOOL  CopySKUSiPolicy(const char* drive_name)                   { (void)drive_name; return FALSE; }
int   SetWinToGoIndex(void)                                     { return -1; }
BOOL  SetupWinToGo(DWORD di, const char* dn, BOOL use_esp)      { (void)di;(void)dn;(void)use_esp; return FALSE; }
BOOL  ApplyWindowsCustomization(char drive_letter, int flags)   { (void)drive_letter;(void)flags; return FALSE; }
