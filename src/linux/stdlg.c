/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux standard dialogs — non-GTK fallback + test injection
 *
 * This file is used by:
 *   - Unit tests (no GTK available)
 *   - Non-GTK console builds
 *
 * The GTK-backed dialog implementation lives in stdlg_gtk.c, which is
 * compiled instead of this file for the GTK production build.
 *
 * Test injection API
 * ------------------
 * Call stdlg_set_test_response(response, file_path) to make the dialog
 * functions return a preset value without showing any UI.  Call
 * stdlg_clear_test_mode() to restore normal behaviour.
 *
 * One-shot semantics: the test mode is automatically cleared after the
 * first call to FileDialog() so that a single stdlg_set_test_response()
 * affects only one FileDialog call.  NotificationEx and
 * CustomSelectionDialog do NOT clear the mode automatically — call
 * stdlg_clear_test_mode() explicitly.
 */
#include "rufus.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Test-injection state
 * =========================================================================*/

static int  _test_response  = -1;   /* -1 = no test mode */
static char _test_file_path[4096];  /* preset file path for FileDialog */
static int  _test_active     = 0;

/**
 * stdlg_set_test_response - enter test mode with a preset response.
 *
 * @response:  The value the next dialog call should return (IDOK, IDYES,
 *             IDNO, IDCANCEL, IDCANCEL, or a bitmask for
 *             CustomSelectionDialog).  Ignored by FileDialog if file_path
 *             is non-NULL.
 * @file_path: Preset path for FileDialog; pass NULL to make it return NULL.
 */
void stdlg_set_test_response(int response, const char *file_path)
{
    _test_response = response;
    if (file_path) {
        strncpy(_test_file_path, file_path, sizeof(_test_file_path) - 1);
        _test_file_path[sizeof(_test_file_path) - 1] = '\0';
    } else {
        _test_file_path[0] = '\0';
    }
    _test_active = 1;
}

/**
 * stdlg_clear_test_mode - leave test mode; subsequent calls use real UI.
 */
void stdlg_clear_test_mode(void)
{
    _test_response  = -1;
    _test_file_path[0] = '\0';
    _test_active    = 0;
}

/* =========================================================================
 * Notification dialog
 * =========================================================================*/

int NotificationEx(int type, const char* dont_display_setting,
                   const notification_info* more_info,
                   const char* title, const char* fmt, ...)
{
    (void)dont_display_setting; (void)more_info;

    /* Format the message for logging regardless of test mode */
    char msg[2048];
    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
    } else {
        msg[0] = '\0';
    }

    /* In test mode, return the preset value without showing any UI */
    if (_test_active && _test_response >= 0)
        return _test_response;

    /* Fallback: log to stderr and return IDOK for MB_OK / IDCANCEL for others */
    fprintf(stderr, "[Notification] %s: %s\n",
            title ? title : "Rufus", msg);

    /* Map button style to a sensible default */
    int buttons = type & 0x0F;
    if (buttons == MB_YESNO || buttons == MB_YESNOCANCEL)
        return IDNO;
    return IDOK;
}

/* =========================================================================
 * File chooser dialog
 * =========================================================================*/

char* FileDialog(BOOL save, char* path, const ext_t* ext, UINT* selected_ext)
{
    (void)save; (void)path; (void)ext; (void)selected_ext;

    if (_test_active) {
        /* One-shot: clear test mode after use so a single
         * stdlg_set_test_response() call only affects one FileDialog. */
        _test_active = 0;

        if (_test_file_path[0] != '\0')
            return strdup(_test_file_path);
        return NULL; /* IDCANCEL or empty path → no selection */
    }

    /* No GTK available in this build — cannot show a dialog */
    return NULL;
}

/* =========================================================================
 * Custom selection dialog (radio-button / checkbox grid)
 * =========================================================================*/

int CustomSelectionDialog(int style, char* title, char* msg,
                          char** choices, int sz, int mask, int username_index)
{
    (void)style; (void)title; (void)msg;
    (void)choices; (void)sz; (void)username_index;

    if (_test_active) {
        int r = _test_response;
        /* IDCANCEL → return 0 (no selection) */
        if (r == IDCANCEL)
            return 0;
        /* Positive value → treat as a bitmask of selected choices */
        return (r >= 0) ? r : mask;
    }

    /* Fallback: return the default mask unchanged */
    return mask;
}

/* =========================================================================
 * List dialog (informational list)
 * =========================================================================*/

void ListDialog(char* title, char* msg, char** items, int sz)
{
    if (!title || !msg) return;
    /* In test/non-GTK builds: dump the list to stderr */
    fprintf(stderr, "[ListDialog] %s — %s (%d items)\n", title, msg, sz);
    if (items) {
        for (int i = 0; i < sz && items[i]; i++)
            fprintf(stderr, "  [%d] %s\n", i, items[i]);
    }
}

/* =========================================================================
 * Remaining no-op stubs (UI layout helpers, Windows-only features)
 * =========================================================================*/

void SetDialogFocus(HWND hDlg, HWND hCtrl)  { (void)hDlg;(void)hCtrl; }
void CreateStatusBar(HFONT* hFont)           { (void)hFont; }
void CenterDialog(HWND hDlg, HWND hParent)  { (void)hDlg;(void)hParent; }
SIZE GetBorderSize(HWND hDlg)               { SIZE s={0,0}; (void)hDlg; return s; }
void ResizeMoveCtrl(HWND hDlg, HWND hCtrl, int dx, int dy,
                    int dw, int dh, float sc)
    { (void)hDlg;(void)hCtrl;(void)dx;(void)dy;(void)dw;(void)dh;(void)sc; }
void ResizeButtonHeight(HWND hDlg, int id)  { (void)hDlg;(void)id; }
INT_PTR CALLBACK LicenseCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CALLBACK AboutCallback(HWND h, UINT m, WPARAM w, LPARAM l)   { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CreateAboutBox(void)                { return 0; }
HICON FixWarningIcon(HICON hIcon)           { return hIcon; }
INT_PTR CALLBACK NotificationCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CALLBACK ListCallback(HWND h, UINT m, WPARAM w, LPARAM l)    { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CALLBACK TooltipCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
BOOL CreateTooltip(HWND hCtrl, const char* msg, int dur) { (void)hCtrl;(void)msg;(void)dur; return FALSE; }
void DestroyTooltip(HWND hCtrl)             { (void)hCtrl; }
void DestroyAllTooltips(void)               {}
BOOL SetTaskbarProgressValue(ULONGLONG done, ULONGLONG total) { (void)done;(void)total; return FALSE; }
INT_PTR CALLBACK UpdateCallback(HWND h, UINT m, WPARAM w, LPARAM l)  { (void)h;(void)m;(void)w;(void)l; return 0; }
void SetFidoCheck(void)                     {}
BOOL SetUpdateCheck(void)                   { return FALSE; }
void CreateStaticFont(HDC hDC, HFONT* hFont, BOOL ul) { (void)hDC;(void)hFont;(void)ul; }
void SetHyperLinkFont(HWND h, HDC hDC, HFONT* hFont, BOOL ul) { (void)h;(void)hDC;(void)hFont;(void)ul; }
INT_PTR CALLBACK update_subclass_callback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CALLBACK NewVersionCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
void DownloadNewVersion(void)
{
	/* Open the Rufus downloads page in the default browser.
	 * Use xdg-open so it works on any desktop environment. */
	if (system("xdg-open " DOWNLOAD_URL " 2>/dev/null &") != 0)
		uprintf("DownloadNewVersion: failed to open browser");
}
void SetTitleBarIcon(HWND hDlg)             { (void)hDlg; }
SIZE GetTextSize(HWND hCtrl, char* txt)     { SIZE s={0,0}; (void)hCtrl;(void)txt; return s; }
void* GetDialogTemplate(int dlg_id)         { (void)dlg_id; return NULL; }
HWND MyCreateDialog(HINSTANCE hi, int dlg_id, HWND parent, DLGPROC fn) { (void)hi;(void)dlg_id;(void)parent;(void)fn; return NULL; }
INT_PTR MyDialogBox(HINSTANCE hi, int dlg_id, HWND parent, DLGPROC fn) { (void)hi;(void)dlg_id;(void)parent;(void)fn; return 0; }
void SetAlertPromptMessages(void)           {}
BOOL SetAlertPromptHook(void)               { return FALSE; }
void FlashTaskbar(HANDLE handle)            { (void)handle; }
HICON CreateMirroredIcon(HICON hIcon)       { return hIcon; }
INT_PTR CALLBACK SelectionDynCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
int SelectionDyn(char* title, char* msg, char** choices, int n) { (void)title;(void)msg;(void)choices;(void)n; return 0; }
LONG GetEntryWidth(HWND hDropDown, const char* entry) { (void)hDropDown;(void)entry; return 0; }
