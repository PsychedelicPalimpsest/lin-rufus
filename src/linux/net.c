/* Linux stub: net.c - networking (stub for porting) */
#include "rufus.h"


DWORD  DownloadSignedFile(const char* url, const char* file, HWND h, BOOL b) { (void)url;(void)file;(void)h;(void)b; return 0; }
HANDLE DownloadSignedFileThreaded(const char* url, const char* file, HWND h, BOOL b) { (void)url;(void)file;(void)h;(void)b; return NULL; }
BOOL   UseLocalDbx(int arch)           { (void)arch; return FALSE; }
BOOL   CheckForUpdates(BOOL force)     { (void)force; return FALSE; }
BOOL   DownloadISO(void)               { return FALSE; }
BOOL   IsDownloadable(const char* url) { (void)url; return FALSE; }
uint64_t DownloadToFileOrBufferEx(const char* url, const char* file, const char* ua,
    uint8_t** buf, HWND hDlg, BOOL silent) { (void)url;(void)file;(void)ua;(void)buf;(void)hDlg;(void)silent; return 0; }
