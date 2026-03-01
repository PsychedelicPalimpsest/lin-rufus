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
#include "settings.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef USE_GTK
#include <gtk/gtk.h>
#endif

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

#ifdef USE_GTK
    {
        GtkMessageType msg_type;
        GtkButtonsType btn_type;
        int buttons = type & 0x0F;

        if (type & MB_ICONERROR)
            msg_type = GTK_MESSAGE_ERROR;
        else if (type & MB_ICONWARNING)
            msg_type = GTK_MESSAGE_WARNING;
        else if (type & MB_ICONQUESTION)
            msg_type = GTK_MESSAGE_QUESTION;
        else
            msg_type = GTK_MESSAGE_INFO;

        if (buttons == MB_YESNO || buttons == MB_YESNOCANCEL)
            btn_type = GTK_BUTTONS_YES_NO;
        else if (buttons == MB_OKCANCEL)
            btn_type = GTK_BUTTONS_OK_CANCEL;
        else
            btn_type = GTK_BUTTONS_OK;

        GtkWidget *dlg = gtk_message_dialog_new(
            hMainDialog ? GTK_WINDOW((GtkWidget*)hMainDialog) : NULL,
            GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
            msg_type, btn_type, "%s", msg);
        if (title)
            gtk_window_set_title(GTK_WINDOW(dlg), title);

        gint response = gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);

        if (response == GTK_RESPONSE_YES)    return IDYES;
        if (response == GTK_RESPONSE_NO)     return IDNO;
        if (response == GTK_RESPONSE_CANCEL ||
            response == GTK_RESPONSE_DELETE_EVENT)
            return (buttons == MB_OK) ? IDOK : IDCANCEL;
        return IDOK;  /* GTK_RESPONSE_OK */
    }
#endif

    /* Fallback: log to stderr and return IDOK for MB_OK / IDNO for others */
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
    (void)ext; (void)selected_ext;

    if (_test_active) {
        /* One-shot: clear test mode after use so a single
         * stdlg_set_test_response() call only affects one FileDialog. */
        _test_active = 0;

        if (_test_file_path[0] != '\0')
            return strdup(_test_file_path);
        return NULL; /* IDCANCEL or empty path → no selection */
    }

#ifdef USE_GTK
    {
        GtkFileChooserAction action = save ?
            GTK_FILE_CHOOSER_ACTION_SAVE : GTK_FILE_CHOOSER_ACTION_OPEN;
        GtkWidget *dlg = gtk_file_chooser_dialog_new(
            save ? "Save file" : "Open file",
            hMainDialog ? GTK_WINDOW((GtkWidget*)hMainDialog) : NULL,
            action,
            "Cancel", GTK_RESPONSE_CANCEL,
            save ? "Save" : "Open", GTK_RESPONSE_ACCEPT,
            NULL);
        if (path && path[0])
            gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dlg), path);

        char *result = NULL;
        if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT)
            result = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        gtk_widget_destroy(dlg);
        return result;  /* caller must g_free() — but rufus uses free(), which works
                         * with glib's g_malloc on Linux */
    }
#endif

    /* No GTK available in this build — cannot show a dialog */
    return NULL;
}

/* =========================================================================
 * Custom selection dialog (radio-button / checkbox grid)
 * =========================================================================*/

int CustomSelectionDialog(int style, char* title, char* msg,
                          char** choices, int sz, int mask, int username_index)
{
    if (_test_active) {
        int r = _test_response;
        /* IDCANCEL → return 0 (no selection) */
        if (r == IDCANCEL)
            return 0;
        /* Positive value → treat as a bitmask of selected choices */
        return (r >= 0) ? r : mask;
    }

#ifdef USE_GTK
    extern HWND hMainDialog;
    GtkWidget *dlg, *content_area, *vbox, *label, *widget;
    GtkWidget *entries[64];   /* text entry widgets for username_index slots */
    GtkWidget *checks[64];    /* toggle widgets (check or radio) */
    GSList *radio_group = NULL;
    int i, result, ret = 0;

    if (sz <= 0 || sz > 64)
        return mask;

    memset(entries, 0, sizeof(entries));
    memset(checks,  0, sizeof(checks));

    dlg = gtk_dialog_new_with_buttons(
        title ? title : APPLICATION_NAME,
        hMainDialog ? GTK_WINDOW(hMainDialog) : NULL,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_OK",     GTK_RESPONSE_OK, NULL);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content_area), 12);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);

    /* Message label */
    if (msg && msg[0]) {
        label = gtk_label_new(msg);
        gtk_widget_set_halign(label, GTK_ALIGN_START);
        gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    }

    /* Build toggle widgets */
    for (i = 0; i < sz; i++) {
        const char *text = (choices && choices[i]) ? choices[i] : "";
        if (style == BS_AUTORADIOBUTTON) {
            widget = gtk_radio_button_new_with_label(radio_group, text);
            radio_group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(widget));
            if (mask & (1 << i))
                gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
        } else {
            widget = gtk_check_button_new_with_label(text);
            if (mask & (1 << i))
                gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
        }
        checks[i] = widget;

        if (i == username_index) {
            /* This choice has an editable username field below it */
            GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
            gtk_box_pack_start(GTK_BOX(hbox), widget,          TRUE,  TRUE,  0);
            GtkWidget *entry = gtk_entry_new();
            gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Username");
            gtk_box_pack_start(GTK_BOX(hbox), entry, FALSE, FALSE, 0);
            entries[i] = entry;
            gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
        } else {
            gtk_box_pack_start(GTK_BOX(vbox), widget, FALSE, FALSE, 0);
        }
    }

    gtk_widget_show_all(dlg);
    result = gtk_dialog_run(GTK_DIALOG(dlg));

    if (result == GTK_RESPONSE_OK) {
        ret = 0;
        for (i = 0; i < sz; i++) {
            if (checks[i] && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(checks[i])))
                ret |= (1 << i);
        }
        /* If username entry was provided, store it via uprintf for now */
        if (username_index >= 0 && username_index < sz && entries[username_index]) {
            const char *uname = gtk_entry_get_text(GTK_ENTRY(entries[username_index]));
            if (uname && uname[0])
                uprintf("Username set to: %s", uname);
        }
    } else {
        ret = 0; /* cancelled */
    }

    gtk_widget_destroy(dlg);
    return ret;
#else
    /* Fallback: return the default mask unchanged */
    (void)style; (void)title; (void)msg;
    (void)choices; (void)sz; (void)username_index;
    return mask;
#endif
}

/* =========================================================================
 * List dialog (informational list)
 * =========================================================================*/

void ListDialog(char* title, char* msg, char** items, int sz)
{
    if (!title || !msg) return;

#ifdef USE_GTK
    extern HWND hMainDialog;
    GtkWidget *dlg, *content_area, *vbox, *scrolled, *lbox, *label;
    int i;

    dlg = gtk_dialog_new_with_buttons(
        title,
        hMainDialog ? GTK_WINDOW(hMainDialog) : NULL,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_OK", GTK_RESPONSE_OK, NULL);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content_area), 12);
    gtk_widget_set_size_request(dlg, 480, 320);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);

    label = gtk_label_new(msg);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

    lbox = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(lbox), GTK_SELECTION_NONE);
    gtk_container_add(GTK_CONTAINER(scrolled), lbox);

    if (items) {
        for (i = 0; i < sz && items[i]; i++) {
            GtkWidget *row_label = gtk_label_new(items[i]);
            gtk_widget_set_halign(row_label, GTK_ALIGN_START);
            gtk_container_add(GTK_CONTAINER(lbox), row_label);
        }
    }

    gtk_widget_show_all(dlg);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
#else
    /* In non-GTK builds: dump the list to stderr */
    fprintf(stderr, "[ListDialog] %s — %s (%d items)\n", title, msg, sz);
    if (items) {
        for (int i = 0; i < sz && items[i]; i++)
            fprintf(stderr, "  [%d] %s\n", i, items[i]);
    }
#endif
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

/*
 * find_license_file() — locate the LICENSE.txt file relative to app_dir.
 *
 * Searches in order:
 *   1. <app_dir>/LICENSE.txt      (running from build root)
 *   2. <app_dir>/../LICENSE.txt   (one level up, e.g. build subdirectory)
 *   3. RUFUS_DATADIR/LICENSE.txt  (compile-time installed path, if defined)
 *
 * Returns a pointer to a static buffer on success, or NULL if not found.
 */
const char* find_license_file(void)
{
	static char path[MAX_PATH];
	extern char app_dir[MAX_PATH];
	struct stat st;

	/* 1. Same directory as binary */
	snprintf(path, sizeof(path), "%sLICENSE.txt", app_dir);
	if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
		return path;

	/* 2. One level up (running from tests/ or a build subdir) */
	snprintf(path, sizeof(path), "%s../LICENSE.txt", app_dir);
	if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
		return path;

#ifdef RUFUS_DATADIR
	/* 3. Compile-time data directory */
	snprintf(path, sizeof(path), "%s/LICENSE.txt", RUFUS_DATADIR);
	if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
		return path;
#endif

	return NULL;
}

INT_PTR CALLBACK LicenseCallback(HWND h, UINT m, WPARAM w, LPARAM l)
{
	(void)h;(void)m;(void)w;(void)l;
#ifdef USE_GTK
	/* GTK build: show LICENSE.txt in a scrollable dialog */
	const char *license_path = find_license_file();
	GtkWidget *dlg = gtk_dialog_new_with_buttons(
		"License", NULL,
		GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
		"_Close", GTK_RESPONSE_CLOSE,
		NULL);
	gtk_window_set_default_size(GTK_WINDOW(dlg), 640, 480);

	GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	GtkWidget *text_view = gtk_text_view_new();
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD_CHAR);
	gtk_text_view_set_left_margin(GTK_TEXT_VIEW(text_view), 6);
	gtk_text_view_set_right_margin(GTK_TEXT_VIEW(text_view), 6);

	if (license_path != NULL) {
		gchar *contents = NULL;
		gsize length = 0;
		if (g_file_get_contents(license_path, &contents, &length, NULL)) {
			gtk_text_buffer_set_text(
				gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view)),
				contents, (gint)length);
			g_free(contents);
		}
	} else {
		gtk_text_buffer_set_text(
			gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view)),
			"GNU General Public License v3.0\n\n"
			"This program is free software: you can redistribute it and/or\n"
			"modify it under the terms of the GNU General Public License as\n"
			"published by the Free Software Foundation, either version 3 of\n"
			"the License, or (at your option) any later version.\n\n"
			"See https://www.gnu.org/licenses/gpl-3.0.html for full text.",
			-1);
	}

	gtk_container_add(GTK_CONTAINER(scroll), text_view);
	GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
	gtk_box_pack_start(GTK_BOX(content_area), scroll, TRUE, TRUE, 0);
	gtk_widget_show_all(dlg);
	gtk_dialog_run(GTK_DIALOG(dlg));
	gtk_widget_destroy(dlg);
#endif
	return (INT_PTR)TRUE;
}

INT_PTR CALLBACK AboutCallback(HWND h, UINT m, WPARAM w, LPARAM l)   { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CreateAboutBox(void)                { return 0; }
HICON FixWarningIcon(HICON hIcon)           { return hIcon; }
INT_PTR CALLBACK NotificationCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CALLBACK ListCallback(HWND h, UINT m, WPARAM w, LPARAM l)    { (void)h;(void)m;(void)w;(void)l; return 0; }
INT_PTR CALLBACK TooltipCallback(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }

BOOL CreateTooltip(HWND hCtrl, const char* msg, int dur)
{
	if (hCtrl == NULL || msg == NULL)
		return FALSE;
#ifdef USE_GTK
	GtkWidget *w = (GtkWidget *)hCtrl;
	gtk_widget_set_tooltip_text(w, msg);
	gtk_widget_set_has_tooltip(w, TRUE);
	/* GTK controls tooltip display timing globally; dur is ignored */
	(void)dur;
#else
	(void)dur;
#endif
	return TRUE;
}

void DestroyTooltip(HWND hCtrl)
{
	if (hCtrl == NULL)
		return;
#ifdef USE_GTK
	GtkWidget *w = (GtkWidget *)hCtrl;
	gtk_widget_set_has_tooltip(w, FALSE);
	gtk_widget_set_tooltip_text(w, NULL);
#endif
}

void DestroyAllTooltips(void)               {}
BOOL SetTaskbarProgressValue(ULONGLONG done, ULONGLONG total) { (void)done;(void)total; return FALSE; }
INT_PTR CALLBACK UpdateCallback(HWND h, UINT m, WPARAM w, LPARAM l)  { (void)h;(void)m;(void)w;(void)l; return 0; }
/* SetFidoCheck is implemented in net.c */

BOOL SetUpdateCheck(void)
{
	uint64_t commcheck = (uint64_t)time(NULL);

	/* Test that settings storage is available */
	WriteSetting64(SETTING_COMM_CHECK, commcheck);
	if (ReadSetting64(SETTING_COMM_CHECK) != commcheck)
		return FALSE;

	int32_t interval = (int32_t)ReadSetting32(SETTING_UPDATE_INTERVAL);

	if (interval < 0) {
		/* Updates explicitly disabled by the user — respect the choice */
		return FALSE;
	}

	if (interval == 0) {
		/* First run: ask the user whether they want automatic update checks.
		 * NotificationEx() uses test-injection in tests and a GTK dialog in
		 * production, so no separate dialog implementation is needed here. */
		int r = NotificationEx(MB_YESNO | MB_ICONQUESTION, NULL, NULL,
		                       "Rufus Update Check",
		                       "Would you like Rufus to automatically check for updates?\n\n"
		                       "You can change this setting later in the application options.");
		if (r == IDYES) {
			WriteSetting32(SETTING_UPDATE_INTERVAL, 86400); /* daily */
		} else {
			WriteSetting32(SETTING_UPDATE_INTERVAL, -1);    /* disabled */
			return FALSE;
		}
	}

	return TRUE;
}
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
void SetTitleBarIcon(HWND hDlg)
{
#ifdef USE_GTK
    if (hDlg && GTK_IS_WINDOW((GtkWidget *)hDlg))
        gtk_window_set_icon_name(GTK_WINDOW((GtkWidget *)hDlg), "ie.akeo.rufus");
#else
    (void)hDlg;
#endif
}
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
