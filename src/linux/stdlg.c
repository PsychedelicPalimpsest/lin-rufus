/* Linux stub: stdlg.c - standard dialogs (no-op on Linux) */
#include "rufus.h"
#include <stdarg.h>
#include <stdio.h>

void SetDialogFocus(HWND hDlg, HWND hCtrl)                { (void)hDlg;(void)hCtrl; }
char* FileDialog(BOOL save, char* path, const ext_t* ext, UINT* sel) { (void)save;(void)path;(void)ext;(void)sel; return NULL; }
void CreateStatusBar(HFONT* hFont)                         { (void)hFont; }
void CenterDialog(HWND hDlg, HWND hParent)                 { (void)hDlg;(void)hParent; }
SIZE GetBorderSize(HWND hDlg)                              { SIZE s={0,0}; (void)hDlg; return s; }
void ResizeMoveCtrl(HWND hDlg, HWND hCtrl, int dx, int dy, int dw, int dh, float sc) { (void)hDlg;(void)hCtrl;(void)dx;(void)dy;(void)dw;(void)dh;(void)sc; }
void ResizeButtonHeight(HWND hDlg, int id)                 { (void)hDlg;(void)id; }
INT_PTR CALLBACK LicenseCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CALLBACK AboutCallback(HWND h, UINT m, WPARAM w, LPARAM l)   { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CreateAboutBox(void)                               { return 0; }
HICON FixWarningIcon(HICON hIcon)                          { return hIcon; }
INT_PTR CALLBACK NotificationCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
int NotificationEx(int type, const char* d, const notification_info* mi, const char* title, const char* fmt, ...) {
    (void)type;(void)d;(void)mi;(void)title;
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fputc('\n', stderr);
    return 0;
}
int CustomSelectionDialog(int style, char* title, char* msg, char** choices, int sz, int mask, int un) { (void)style;(void)title;(void)msg;(void)choices;(void)sz;(void)mask;(void)un; return 0; }
INT_PTR CALLBACK ListCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
void ListDialog(char* title, char* msg, char** items, int sz) { (void)title;(void)msg;(void)items;(void)sz; }
INT_PTR CALLBACK TooltipCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
BOOL CreateTooltip(HWND hCtrl, const char* msg, int dur)   { (void)hCtrl;(void)msg;(void)dur; return FALSE; }
void DestroyTooltip(HWND hCtrl)                            { (void)hCtrl; }
void DestroyAllTooltips(void)                              {}
BOOL SetTaskbarProgressValue(ULONGLONG done, ULONGLONG total) { (void)done;(void)total; return FALSE; }
INT_PTR CALLBACK UpdateCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
void SetFidoCheck(void)                                    {}
BOOL SetUpdateCheck(void)                                  { return FALSE; }
void CreateStaticFont(HDC hDC, HFONT* hFont, BOOL ul)     { (void)hDC;(void)hFont;(void)ul; }
void SetHyperLinkFont(HWND h, HDC hDC, HFONT* hFont, BOOL ul) { (void)h;(void)hDC;(void)hFont;(void)ul; }
INT_PTR CALLBACK update_subclass_callback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CALLBACK NewVersionCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
void DownloadNewVersion(void)                              {}
void SetTitleBarIcon(HWND hDlg)                            { (void)hDlg; }
SIZE GetTextSize(HWND hCtrl, char* txt)                    { SIZE s={0,0}; (void)hCtrl;(void)txt; return s; }
void* GetDialogTemplate(int dlg_id)                        { (void)dlg_id; return NULL; }
HWND MyCreateDialog(HINSTANCE hi, int dlg_id, HWND parent, DLGPROC fn) { (void)hi;(void)dlg_id;(void)parent;(void)fn; return NULL; }
INT_PTR MyDialogBox(HINSTANCE hi, int dlg_id, HWND parent, DLGPROC fn) { (void)hi;(void)dlg_id;(void)parent;(void)fn; return 0; }
void SetAlertPromptMessages(void)                          {}
BOOL SetAlertPromptHook(void)                              { return FALSE; }
void FlashTaskbar(HANDLE handle)                           { (void)handle; }
HICON CreateMirroredIcon(HICON hIcon)                      { return hIcon; }
INT_PTR CALLBACK SelectionDynCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
int SelectionDyn(char* title, char* msg, char** choices, int n) { (void)title;(void)msg;(void)choices;(void)n; return 0; }
