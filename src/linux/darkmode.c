/* Linux stub: darkmode.c - Windows dark mode (no-op on Linux) */
#include "rufus.h"
#include "darkmode.h"

BOOL is_darkmode_enabled = FALSE;

BOOL GetDarkModeFromRegistry(void)             { return FALSE; }
void InitDarkMode(HWND hWnd)                   { (void)hWnd; }
void SetDarkTitleBar(HWND hWnd)                { (void)hWnd; }
void SetDarkTheme(HWND hWnd)                   { (void)hWnd; }
BOOL InitAccentColor(void)                     { return FALSE; }
BOOL ChangeIconColor(HICON* hIcon, COLORREF c) { (void)hIcon; (void)c; return FALSE; }
void DestroyDarkModeGDIObjects(void)           {}
void SubclassCtlColor(HWND hWnd)               { (void)hWnd; }
void SubclassNotifyCustomDraw(HWND hWnd)       { (void)hWnd; }
void SubclassStatusBar(HWND hWnd)              { (void)hWnd; }
void SubclassProgressBarControl(HWND hWnd)     { (void)hWnd; }
void SetDarkModeForChild(HWND hParent)         { (void)hParent; }
