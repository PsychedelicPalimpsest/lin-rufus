/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux-specific localization functions
 * Copyright © 2013-2026 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Linux-specific UI hooks for localization.
 * The portable core (parse_cmd, message tables, dispatch_loc_cmd, lmprintf, etc.)
 * lives in src/common/localization.c.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "rufus.h"
#include "resource.h"
#include "localization.h"

/* loc_dlg[] is accessed via get_loc_dlg_count() / get_loc_dlg_entry() from
 * common/localization.c to avoid including localization_data.h directly here. */

/* GTK widget registry — only available when building the full UI */
#ifdef __linux__
#ifndef RUFUS_TEST
#include <gtk/gtk.h>
#include "ui_gtk.h"
#endif
#endif

/* -----------------------------------------------------------------------
 * ctrl_id_to_widget — map a Windows control ID to the corresponding
 * GTK widget pointer stored in the global rw struct.
 * Returns NULL if the ID is unknown or GTK is not initialised.
 * --------------------------------------------------------------------- */
#if !defined(RUFUS_TEST) && !defined(_WIN32)
static GtkWidget *ctrl_id_to_widget(int ctrl_id)
{
	switch (ctrl_id) {
	/* ---- Buttons / checkboxes ---- */
	case IDC_SELECT:               return rw.select_btn;
	case IDC_START:                return rw.start_btn;
	case IDCANCEL:                 return rw.close_btn;
	case IDC_LANG:                 return rw.lang_btn;
	case IDC_ABOUT:                return rw.about_btn;
	case IDC_SETTINGS:             return rw.settings_btn;
	case IDC_LOG:                  return rw.log_btn;
	case IDC_SAVE:                 return rw.save_btn;
	case IDC_HASH:                 return rw.hash_btn;
	case IDC_LIST_USB_HDD:         return rw.list_usb_hdd_check;
	case IDC_UEFI_MEDIA_VALIDATION: return rw.uefi_validation_check;
	case IDC_QUICK_FORMAT:         return rw.quick_format_check;
	case IDC_BAD_BLOCKS:           return rw.bad_blocks_check;
	case IDC_OLD_BIOS_FIXES:       return rw.old_bios_check;

	/* ---- Row label widgets (IDS_* IDs) ---- */
	case IDS_DEVICE_TXT:           return rw.device_label;
	case IDS_PARTITION_TYPE_TXT:   return rw.partition_type_label;
	case IDS_FILE_SYSTEM_TXT:      return rw.filesystem_label;
	case IDS_CLUSTER_SIZE_TXT:     return rw.cluster_size_label;
	case IDS_LABEL_TXT:            return rw.volume_label_label;
	case IDS_TARGET_SYSTEM_TXT:    return rw.target_system_label;
	case IDS_IMAGE_OPTION_TXT:     return rw.image_option_label;
	case IDS_BOOT_SELECTION_TXT:   return rw.boot_selection_label;
	case IDS_DRIVE_PROPERTIES_TXT: return rw.drive_props_label;
	case IDS_FORMAT_OPTIONS_TXT:   return rw.format_options_label;
	case IDS_STATUS_TXT:           return rw.status_txt_label;

	default:
		return NULL;
	}
}

/* -----------------------------------------------------------------------
 * set_widget_text — call the right GTK setter for the widget type.
 * --------------------------------------------------------------------- */
static void set_widget_text(GtkWidget *widget, const char *text)
{
	if (!widget || !text || text[0] == '\0')
		return;
	if (GTK_IS_BUTTON(widget))
		gtk_button_set_label(GTK_BUTTON(widget), text);
	else if (GTK_IS_LABEL(widget))
		gtk_label_set_text(GTK_LABEL(widget), text);
	/* Other widget types (combos, entries) are not updated from localization */
}
#endif /* !RUFUS_TEST && !_WIN32 */

/*
 * Apply stored localization commands to the GTK widgets.
 *
 * dlg_id == 0        → apply all registered dialogs
 * dlg_id == IDD_DIALOG (101) → apply main dialog only
 * dlg_id outside IDD_DIALOG … IDD_DIALOG+ARRAYSIZE(loc_dlg) → no-op
 *
 * hDlg is ignored on Linux (we use the global rw struct).
 */
void apply_localization(int dlg_id, HWND hDlg)
{
	(void)hDlg;

#if defined(RUFUS_TEST) || defined(_WIN32)
	/* No GTK in test or Windows builds — nothing to do */
	(void)dlg_id;
#else
	loc_cmd *lcmd;
	int id_start = IDD_DIALOG;
	int id_end   = IDD_DIALOG + get_loc_dlg_count();

	if ((dlg_id >= id_start) && (dlg_id < id_end)) {
		id_start = dlg_id;
		id_end   = dlg_id + 1;
	} else if (dlg_id != 0) {
		/* Out-of-range non-zero dlg_id: nothing to do */
		return;
	}

	for (dlg_id = id_start; dlg_id < id_end; dlg_id++) {
		int idx = dlg_id - IDD_DIALOG;
		loc_dlg_list *entry = get_loc_dlg_entry(idx);
		if (list_empty(&entry->list))
			continue;

		list_for_each_entry(lcmd, &entry->list, loc_cmd, list) {
			if (lcmd->command != LC_TEXT)
				continue;
			if (lcmd->txt[1] == NULL || lcmd->txt[1][0] == '\0')
				continue;

			GtkWidget *widget = ctrl_id_to_widget(lcmd->ctrl_id);
			set_widget_text(widget, lcmd->txt[1]);
		}
	}
#endif
}

/*
 * Notify the localization system that a dialog has been destroyed.
 * On Linux the GTK widgets persist as long as the window is alive,
 * so this is a no-op beyond clearing the hDlg pointer.
 */
void reset_localization(int dlg_id)
{
	(void)dlg_id;
}

/*
 * Display a localized status/info message.
 * Routes the formatted text to the registered status handler (e.g. the GTK
 * status label).  When debug is TRUE also logs to uprintf (the log view).
 * The duration parameter is accepted but not yet used for auto-clear.
 */

/* -----------------------------------------------------------------------
 * Status handler callback — set by rufus_set_status_handler().
 * The GTK UI registers rufus_gtk_update_status() here so that every
 * PrintStatusInfo call updates the status bar widget.
 * --------------------------------------------------------------------- */
static void (*status_handler_fn)(const char *msg) = NULL;

void rufus_set_status_handler(void (*fn)(const char *msg))
{
	status_handler_fn = fn;
}

void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration, int msg_id, ...)
{
	char buf[512];
	char *format = NULL;
	va_list args;

	(void)info; (void)duration;

	if (msg_id < 0)
		return;

	if ((msg_id < MSG_000) || (msg_id >= MSG_MAX))
		return;

	if (msg_table != NULL)
		format = msg_table[msg_id - MSG_000];
	if (format == NULL)
		return;

	va_start(args, msg_id);
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);
	buf[sizeof(buf) - 1] = '\0';

	/* Route to the UI status label (no-op if no handler is registered) */
	if (status_handler_fn)
		status_handler_fn(buf);

	/* Also log to the log view when debug mode is requested */
	if (debug)
		uprintf("%s", buf);
}

/*
 * Return the language ID for the current locale.
 * On Linux, Windows language IDs do not apply; return neutral.
 */
WORD get_language_id(loc_cmd* lcmd)
{
	(void)lcmd;
	return 0;
}

