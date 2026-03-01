/*
 * Rufus: The Reliable USB Formatting Utility
 * GTK UI implementation
 * Copyright © 2024 Rufus contributors
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

#include "ui_gtk.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libgen.h>
#include <pthread.h>

/* Pull in shared Rufus headers through the compat layer */
#include "rufus.h"
#include "resource.h"
#include "localization.h"
#include "missing.h"
#include "drive.h"
#include "format.h"
#include <windowsx.h>
#include <msg_dispatch.h>
#include "device_monitor.h"
#include "combo_bridge.h"

/* Log handler registration — implemented in linux/stdio.c */
extern void rufus_set_log_handler(void (*fn)(const char *msg));
/* Status bar handler registration — implemented in linux/localization.c */
extern void rufus_set_status_handler(void (*fn)(const char *msg));

/* Update check — implemented in linux/stdlg.c and linux/net.c */
extern BOOL SetUpdateCheck(void);
extern BOOL CheckForUpdates(BOOL force);
extern BOOL quick_format, zero_drive;

/* format_thread and dialog_handle are defined in globals.c */
extern HANDLE format_thread;
extern HANDLE dialog_handle;

/* Localization globals — defined in globals.c */
extern loc_cmd *selected_locale;
extern UINT_PTR UM_LANGUAGE_MENU_MAX;

/* ---- Global widget registry ---- */
RufusWidgets rw = { 0 };

/* ---- Combo state objects (one per logical combo box) ---- */
static combo_state_t *cs_device   = NULL;
static combo_state_t *cs_boot     = NULL;
static combo_state_t *cs_part     = NULL;
static combo_state_t *cs_target   = NULL;
static combo_state_t *cs_fs       = NULL;
static combo_state_t *cs_cluster  = NULL;
static combo_state_t *cs_imgopt   = NULL;

/* Struct used to pass progress data to the GTK main thread via g_idle_add. */
typedef struct { int op; float pct; } ProgressData;

/* FileSystemLabel[] is defined in linux/format.c */
extern const char* FileSystemLabel[FS_MAX];
extern char hash_str[HASH_MAX][150];
extern BOOL enable_extra_hashes;
extern char *image_path;

/* Forward declaration for combo registration helper */
static void combo_register_all(void);
/* Forward declaration for initial combo population */
static void populate_boot_combo(void);
static void populate_partition_combos(void);
static void populate_fs_combo(void);
static void populate_cluster_combo(int fs);
/* Forward declaration for EnableControls (defined later in this file) */
void EnableControls(BOOL enable, BOOL remove_checkboxes);

/* Idle callback: update progress bar from main thread. */
static gboolean idle_update_progress(gpointer data)
{
	ProgressData *p = (ProgressData *)data;
	if (rw.progress_bar)
		gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(rw.progress_bar),
			CLAMP((double)p->pct / 100.0, 0.0, 1.0));
	free(p);
	return G_SOURCE_REMOVE;
}

/* ---- Forward declarations ---- */
static void on_start_clicked(GtkButton *btn, gpointer data);
static void on_close_clicked(GtkButton *btn, gpointer data);
static void on_select_clicked(GtkButton *btn, gpointer data);
static void on_lang_clicked(GtkButton *btn, gpointer data);
static void on_lang_menu_activate(GtkMenuItem *item, gpointer data);
static void on_device_changed(GtkComboBox *combo, gpointer data);
static void on_boot_changed(GtkComboBox *combo, gpointer data);
static void on_log_clicked(GtkButton *btn, gpointer data);
static void on_about_clicked(GtkButton *btn, gpointer data);
void ShowLanguageMenu(RECT rcExclude);
extern DWORD WINAPI ImageScanThread(LPVOID param); /* image_scan.c */
extern void SetFSFromISO(void);                    /* rufus.c stubs */
extern void SetPartitionSchemeAndTargetSystem(BOOL only_target);
static GtkWidget *build_toolbar(void);
static GtkWidget *build_device_row(void);
static GtkWidget *build_boot_row(void);
static GtkWidget *build_image_option_row(void);
static GtkWidget *build_drive_properties(void);
static GtkWidget *build_format_options(void);
static GtkWidget *build_persistence_row(void);
static GtkWidget *build_status_section(void);
static GtkWidget *build_action_buttons(void);
static GtkWidget *make_section_label(const char *text);

/* ---- Helpers ---- */

/* Append text to the log text buffer from any thread via an idle callback. */
static gboolean idle_append_log(gpointer data)
{
	char *msg = (char *)data;
	if (rw.log_textbuf) {
		GtkTextIter end;
		gtk_text_buffer_get_end_iter(rw.log_textbuf, &end);
		gtk_text_buffer_insert(rw.log_textbuf, &end, msg, -1);
		gtk_text_buffer_insert(rw.log_textbuf, &end, "\n", 1);
	}
	free(msg);
	return G_SOURCE_REMOVE;
}

void rufus_gtk_append_log(const char *msg)
{
	g_idle_add(idle_append_log, strdup(msg));
}

static gboolean idle_update_status(gpointer data)
{
	char *msg = (char *)data;
	if (rw.status_label)
		gtk_label_set_text(GTK_LABEL(rw.status_label), msg);
	free(msg);
	return G_SOURCE_REMOVE;
}

void rufus_gtk_update_status(const char *msg)
{
	g_idle_add(idle_update_status, strdup(msg));
}

/* ---- Section label (bold, with separator line) ---- */
static GtkWidget *make_section_label(const char *text)
{
	GtkWidget *lbl = gtk_label_new(NULL);
	char *markup = g_markup_printf_escaped("<b>%s</b>", text);
	gtk_label_set_markup(GTK_LABEL(lbl), markup);
	g_free(markup);
	gtk_widget_set_halign(lbl, GTK_ALIGN_START);
	return lbl;
}

/* ---- Toolbar (language / about / settings / log / save / hash) ---- */
static GtkWidget *build_toolbar(void)
{
	GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);

	rw.lang_btn     = gtk_button_new_with_label("🌐");
	rw.about_btn    = gtk_button_new_with_label("ℹ");
	rw.settings_btn = gtk_button_new_with_label("⚙");
	rw.log_btn      = gtk_button_new_with_label("📋");
	rw.save_btn     = gtk_button_new_with_label("💾");
	rw.hash_btn     = gtk_button_new_with_label("#");

	gtk_widget_set_tooltip_text(rw.lang_btn,     "Language");
	gtk_widget_set_tooltip_text(rw.about_btn,    "About");
	gtk_widget_set_tooltip_text(rw.settings_btn, "Settings");
	gtk_widget_set_tooltip_text(rw.log_btn,      "Log");
	gtk_widget_set_tooltip_text(rw.save_btn,     "Save");
	gtk_widget_set_tooltip_text(rw.hash_btn,     "Hash");

	g_signal_connect(rw.log_btn,   "clicked", G_CALLBACK(on_log_clicked),   NULL);
	g_signal_connect(rw.about_btn, "clicked", G_CALLBACK(on_about_clicked), NULL);
	g_signal_connect(rw.lang_btn,  "clicked", G_CALLBACK(on_lang_clicked),  NULL);

	gtk_box_pack_start(GTK_BOX(bar), rw.lang_btn,     FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.about_btn,    FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.settings_btn, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.log_btn,      FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.save_btn,     FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.hash_btn,     FALSE, FALSE, 0);

	return bar;
}

/* ---- Device row ---- */
static GtkWidget *build_device_row(void)
{
	GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	rw.device_label = gtk_label_new("Device");
	gtk_widget_set_halign(rw.device_label, GTK_ALIGN_START);

	rw.device_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.device_combo, TRUE);
	gtk_widget_set_tooltip_text(rw.device_combo, "Select the USB drive to format");

	g_signal_connect(rw.device_combo, "changed", G_CALLBACK(on_device_changed), NULL);

	GtkWidget *toolbar = build_toolbar();

	gtk_box_pack_start(GTK_BOX(hbox), rw.device_label, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.device_combo, TRUE,  TRUE,  0);
	gtk_box_pack_end  (GTK_BOX(hbox), toolbar,         FALSE, FALSE, 0);

	return hbox;
}

/* ---- Boot selection row ---- */
static GtkWidget *build_boot_row(void)
{
	GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	rw.boot_selection_label = gtk_label_new("Boot selection");
	gtk_widget_set_halign(rw.boot_selection_label, GTK_ALIGN_START);

	rw.boot_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.boot_combo, TRUE);
	g_signal_connect(rw.boot_combo, "changed", G_CALLBACK(on_boot_changed), NULL);

	rw.select_btn = gtk_button_new_with_label("SELECT");
	g_signal_connect(rw.select_btn, "clicked", G_CALLBACK(on_select_clicked), NULL);

	gtk_box_pack_start(GTK_BOX(hbox), rw.boot_selection_label, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.boot_combo,           TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.select_btn,           FALSE, FALSE, 0);

	return hbox;
}

/* ---- Image option row ---- */
static GtkWidget *build_image_option_row(void)
{
	GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	rw.image_option_label = gtk_label_new("Image option");
	gtk_widget_set_halign(rw.image_option_label, GTK_ALIGN_START);

	rw.image_option_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.image_option_combo, TRUE);

	gtk_box_pack_start(GTK_BOX(hbox), rw.image_option_label,  FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.image_option_combo,  TRUE,  TRUE,  0);

	rw.image_option_row = hbox;
	gtk_widget_set_no_show_all(hbox, TRUE); /* hidden until needed */
	return hbox;
}

/* ---- Drive properties section ---- */
static GtkWidget *build_drive_properties(void)
{
	GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	rw.drive_props_label = make_section_label("Drive Properties");
	gtk_box_pack_start(GTK_BOX(vbox), rw.drive_props_label, FALSE, FALSE, 2);

	/* Row: Partition scheme + Target system */
	GtkWidget *row1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	rw.partition_type_label = gtk_label_new("Partition scheme");
	rw.partition_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.partition_combo, TRUE);
	rw.target_system_label = gtk_label_new("Target system");
	rw.target_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.target_combo, TRUE);
	gtk_box_pack_start(GTK_BOX(row1), rw.partition_type_label, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(row1), rw.partition_combo,      TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(row1), rw.target_system_label,  FALSE, FALSE, 8);
	gtk_box_pack_start(GTK_BOX(row1), rw.target_combo,         TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(vbox), row1, FALSE, FALSE, 0);

	/* Row: File system + Cluster size */
	GtkWidget *row2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	rw.filesystem_label = gtk_label_new("File system");
	rw.filesystem_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.filesystem_combo, TRUE);
	rw.cluster_size_label = gtk_label_new("Cluster size");
	rw.cluster_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.cluster_combo, TRUE);
	gtk_box_pack_start(GTK_BOX(row2), rw.filesystem_label,     FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(row2), rw.filesystem_combo,     TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(row2), rw.cluster_size_label,   FALSE, FALSE, 8);
	gtk_box_pack_start(GTK_BOX(row2), rw.cluster_combo,        TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(vbox), row2, FALSE, FALSE, 0);

	/* Row: Volume label */
	GtkWidget *row3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	rw.volume_label_label = gtk_label_new("Volume label");
	rw.label_entry = gtk_entry_new();
	gtk_widget_set_hexpand(rw.label_entry, TRUE);
	gtk_box_pack_start(GTK_BOX(row3), rw.volume_label_label, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(row3), rw.label_entry,        TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(vbox), row3, FALSE, FALSE, 0);

	/* Advanced device options (expander) */
	rw.adv_device_expander = gtk_expander_new("Show advanced drive properties");
	GtkWidget *adv_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	rw.list_usb_hdd_check    = gtk_check_button_new_with_label("List USB Hard Drives");
	rw.uefi_validation_check = gtk_check_button_new_with_label("Enable UEFI media validation");
	gtk_box_pack_start(GTK_BOX(adv_box), rw.list_usb_hdd_check,    FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(adv_box), rw.uefi_validation_check, FALSE, FALSE, 0);
	gtk_container_add(GTK_CONTAINER(rw.adv_device_expander), adv_box);
	gtk_box_pack_start(GTK_BOX(vbox), rw.adv_device_expander, FALSE, FALSE, 2);

	return vbox;
}

/* ---- Format options section ---- */
static GtkWidget *build_format_options(void)
{
	GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	rw.format_options_label = make_section_label("Format Options");
	gtk_box_pack_start(GTK_BOX(vbox), rw.format_options_label, FALSE, FALSE, 2);

	/* Row: Quick format + Bad blocks */
	GtkWidget *row1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
	rw.quick_format_check = gtk_check_button_new_with_label("Quick format");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.quick_format_check), TRUE);
	rw.bad_blocks_check = gtk_check_button_new_with_label("Check device for bad blocks");
	GtkWidget *lbl_np  = gtk_label_new("Passes");
	rw.nb_passes_combo = gtk_combo_box_text_new();
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rw.nb_passes_combo), "1");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rw.nb_passes_combo), "2");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rw.nb_passes_combo), "4 (SLC)");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rw.nb_passes_combo), "4 (MLC)");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rw.nb_passes_combo), "4 (TLC)");
	gtk_combo_box_set_active(GTK_COMBO_BOX(rw.nb_passes_combo), 0);
	gtk_widget_set_sensitive(rw.nb_passes_combo, FALSE);
	g_signal_connect_swapped(rw.bad_blocks_check, "toggled",
		G_CALLBACK(gtk_widget_set_sensitive), rw.nb_passes_combo);
	gtk_box_pack_start(GTK_BOX(row1), rw.quick_format_check, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(row1), rw.bad_blocks_check,   FALSE, FALSE, 8);
	gtk_box_pack_start(GTK_BOX(row1), lbl_np,                FALSE, FALSE, 8);
	gtk_box_pack_start(GTK_BOX(row1), rw.nb_passes_combo,    FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), row1, FALSE, FALSE, 0);

	/* Advanced format options (expander) */
	rw.adv_format_expander = gtk_expander_new("Show advanced format options");
	GtkWidget *adv_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	rw.old_bios_check = gtk_check_button_new_with_label("Add fixes for old BIOS (extra partition, align, etc.)");
	gtk_box_pack_start(GTK_BOX(adv_box), rw.old_bios_check, FALSE, FALSE, 0);
	gtk_container_add(GTK_CONTAINER(rw.adv_format_expander), adv_box);
	gtk_box_pack_start(GTK_BOX(vbox), rw.adv_format_expander, FALSE, FALSE, 2);

	return vbox;
}

/* ---- Persistence row ---- */
static GtkWidget *build_persistence_row(void)
{
	GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

	GtkWidget *lbl = gtk_label_new("Persistent partition size");

	rw.persistence_size  = gtk_label_new("0 MB");
	rw.persistence_scale = gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL, 0, 100, 1);
	gtk_widget_set_hexpand(rw.persistence_scale, TRUE);
	gtk_scale_set_draw_value(GTK_SCALE(rw.persistence_scale), FALSE);

	rw.persistence_units = gtk_combo_box_text_new();
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rw.persistence_units), "MB");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(rw.persistence_units), "GB");
	gtk_combo_box_set_active(GTK_COMBO_BOX(rw.persistence_units), 0);

	gtk_box_pack_start(GTK_BOX(hbox), lbl,                    FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.persistence_scale,   TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.persistence_size,    FALSE, FALSE, 4);
	gtk_box_pack_start(GTK_BOX(hbox), rw.persistence_units,   FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

	rw.persistence_row = vbox;
	gtk_widget_set_no_show_all(vbox, TRUE); /* hidden until needed */
	return vbox;
}

/* ---- Status / progress section ---- */
static GtkWidget *build_status_section(void)
{
	GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	rw.status_txt_label = make_section_label("Status");
	gtk_box_pack_start(GTK_BOX(vbox), rw.status_txt_label, FALSE, FALSE, 2);

	rw.progress_bar  = gtk_progress_bar_new();
	gtk_widget_set_hexpand(rw.progress_bar, TRUE);

	rw.status_label = gtk_label_new("Ready");
	gtk_widget_set_halign(rw.status_label, GTK_ALIGN_START);
	gtk_label_set_ellipsize(GTK_LABEL(rw.status_label), PANGO_ELLIPSIZE_END);

	gtk_box_pack_start(GTK_BOX(vbox), rw.progress_bar,  FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), rw.status_label,  FALSE, FALSE, 0);

	return vbox;
}

/* ---- Action buttons ---- */
static GtkWidget *build_action_buttons(void)
{
	GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

	rw.start_btn = gtk_button_new_with_label("START");
	rw.close_btn = gtk_button_new_with_label("CLOSE");

	gtk_widget_set_hexpand(rw.start_btn, TRUE);
	gtk_widget_set_hexpand(rw.close_btn, TRUE);

	g_signal_connect(rw.start_btn, "clicked", G_CALLBACK(on_start_clicked), NULL);
	g_signal_connect(rw.close_btn, "clicked", G_CALLBACK(on_close_clicked), NULL);

	gtk_box_pack_start(GTK_BOX(hbox), rw.start_btn, TRUE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.close_btn, TRUE, TRUE, 0);

	return hbox;
}

/* ---- Build the log dialog ---- */
/* ---- Log dialog response callback ---- */
static void on_log_response(GtkDialog *dlg, gint r, gpointer data)
{
	(void)data;
	if (r == GTK_RESPONSE_REJECT) {
		gtk_text_buffer_set_text(rw.log_textbuf, "", 0);
	} else if (r == GTK_RESPONSE_ACCEPT) {
		GtkWidget *fs = gtk_file_chooser_dialog_new(
			"Save log", GTK_WINDOW(dlg),
			GTK_FILE_CHOOSER_ACTION_SAVE,
			"Cancel", GTK_RESPONSE_CANCEL,
			"Save",   GTK_RESPONSE_ACCEPT,
			NULL);
		gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(fs), "rufus.log");
		if (gtk_dialog_run(GTK_DIALOG(fs)) == GTK_RESPONSE_ACCEPT) {
			char *fn = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs));
			GtkTextIter s, e;
			gtk_text_buffer_get_bounds(rw.log_textbuf, &s, &e);
			char *txt = gtk_text_buffer_get_text(rw.log_textbuf, &s, &e, FALSE);
			FILE *f = fopen(fn, "w");
			if (f) { fputs(txt, f); fclose(f); }
			g_free(txt); g_free(fn);
		}
		gtk_widget_destroy(fs);
	} else {
		gtk_widget_hide(GTK_WIDGET(dlg));
	}
}

static GtkWidget *build_log_dialog(GtkWidget *parent)
{
	GtkWidget *dlg = gtk_dialog_new_with_buttons(
		"Rufus Log", GTK_WINDOW(parent),
		GTK_DIALOG_DESTROY_WITH_PARENT,
		"Clear", GTK_RESPONSE_REJECT,
		"Save",  GTK_RESPONSE_ACCEPT,
		"Close", GTK_RESPONSE_CLOSE,
		NULL);
	gtk_window_set_default_size(GTK_WINDOW(dlg), 600, 400);
	gtk_window_set_resizable(GTK_WINDOW(dlg), TRUE);

	GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
		GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_widget_set_vexpand(scroll, TRUE);
	gtk_widget_set_hexpand(scroll, TRUE);

	rw.log_textbuf  = gtk_text_buffer_new(NULL);
	rw.log_textview = gtk_text_view_new_with_buffer(rw.log_textbuf);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(rw.log_textview), FALSE);
	gtk_text_view_set_monospace(GTK_TEXT_VIEW(rw.log_textview), TRUE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(rw.log_textview), GTK_WRAP_WORD_CHAR);

	gtk_container_add(GTK_CONTAINER(scroll), rw.log_textview);
	gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dlg))),
		scroll, TRUE, TRUE, 0);
	gtk_widget_show_all(gtk_dialog_get_content_area(GTK_DIALOG(dlg)));

	/* Handle response buttons */
	g_signal_connect(dlg, "response", G_CALLBACK(on_log_response), NULL);

	/* Suppress destroy; just hide on close */
	g_signal_connect(dlg, "delete-event", G_CALLBACK(gtk_widget_hide_on_delete), NULL);
	return dlg;
}

/* ---- Main window construction ---- */
GtkWidget *rufus_gtk_create_window(GtkApplication *app)
{
	GtkWidget *win = gtk_application_window_new(app);
	rw.window = win;
	gtk_window_set_title(GTK_WINDOW(win), "Rufus");
	gtk_window_set_resizable(GTK_WINDOW(win), FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(win), 8);

	/* Vertical stack: all sections */
	GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
	gtk_container_add(GTK_CONTAINER(win), vbox);

	gtk_box_pack_start(GTK_BOX(vbox), build_device_row(),      FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), build_boot_row(),        FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), build_image_option_row(),FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(vbox), build_drive_properties(), FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(vbox), build_format_options(),   FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), build_persistence_row(),  FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(vbox), build_status_section(),   FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), build_action_buttons(),   FALSE, FALSE, 4);

	/* Build log dialog (hidden by default) */
	rw.log_dialog = build_log_dialog(win);

	gtk_widget_show_all(win);

	/* Default state: hide optional rows */
	gtk_widget_hide(rw.image_option_row);
	gtk_widget_hide(rw.persistence_row);

	return win;
}

/* ---- Signal handlers ---- */

static void on_close_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	if (op_in_progress) {
		/* Signal cancellation — the format/hash thread checks this flag
		 * via CHECK_FOR_USER_CANCEL and will exit cleanly. */
		ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED);
		uprintf("Cancellation requested by user.");
		rufus_gtk_update_status("Cancelling...");
	} else {
		device_monitor_stop();
		rufus_set_log_handler(NULL);
		gtk_main_quit();
	}
}

static void on_start_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	int sel = ComboBox_GetCurSel(hDeviceList);
	if (sel < 0) {
		rufus_gtk_update_status("No device selected");
		return;
	}
	DWORD di = (DWORD)ComboBox_GetItemData(hDeviceList, sel);

	/* Read current combo selections into globals */
	int fs_sel   = ComboBox_GetCurSel(hFileSystem);
	int pt_sel   = ComboBox_GetCurSel(hPartitionScheme);
	int ts_sel   = ComboBox_GetCurSel(hTargetSystem);
	int bt_sel   = ComboBox_GetCurSel(hBootType);
	if (fs_sel >= 0) fs_type        = (int)ComboBox_GetItemData(hFileSystem,      fs_sel);
	if (pt_sel >= 0) partition_type = (int)ComboBox_GetItemData(hPartitionScheme, pt_sel);
	if (ts_sel >= 0) target_type    = (int)ComboBox_GetItemData(hTargetSystem,    ts_sel);
	if (bt_sel >= 0) boot_type      = (int)ComboBox_GetItemData(hBootType,        bt_sel);

	/* Read format options from checkboxes */
	quick_format = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rw.quick_format_check));
	zero_drive   = FALSE;  /* future: read from UI when zero-drive option added */

	uprintf("Format started by user (drive=%u, fs=%d, part=%d, target=%d, boot=%d, quick=%d)",
	        di, fs_type, partition_type, target_type, boot_type, quick_format);

	/* Show "WARNING: ALL DATA ON DEVICE WILL BE DESTROYED" confirmation */
	{
		char dev_name[256] = "the selected device";
		SendMessageA(hDeviceList, CB_GETLBTEXT, (WPARAM)sel, (LPARAM)dev_name);
		if (Notification(MB_OKCANCEL | MB_ICONWARNING, APPLICATION_NAME,
		                 lmprintf(MSG_003, dev_name)) != IDOK)
			return;
	}

	if (format_thread == NULL) {
		op_in_progress = TRUE;
		ErrorStatus = 0;
		EnableControls(FALSE, FALSE);
		format_thread = CreateThread(NULL, 0, FormatThread, (void*)(uintptr_t)di, 0, NULL);
		if (format_thread == NULL) {
			op_in_progress = FALSE;
			rufus_gtk_update_status("Failed to start format thread");
			EnableControls(TRUE, FALSE);
		}
	}
}

static void on_select_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;

	GtkWidget *dlg = gtk_file_chooser_dialog_new(
		"Select image file", GTK_WINDOW(rw.window),
		GTK_FILE_CHOOSER_ACTION_OPEN,
		"Cancel", GTK_RESPONSE_CANCEL,
		"Open",   GTK_RESPONSE_ACCEPT,
		NULL);

	/* Common image file filters */
	GtkFileFilter *ff_img = gtk_file_filter_new();
	gtk_file_filter_set_name(ff_img, "Disk images (*.iso, *.img, *.vhd, *.wim, *.esd, *.ffu)");
	gtk_file_filter_add_pattern(ff_img, "*.iso");
	gtk_file_filter_add_pattern(ff_img, "*.img");
	gtk_file_filter_add_pattern(ff_img, "*.vhd");
	gtk_file_filter_add_pattern(ff_img, "*.vhdx");
	gtk_file_filter_add_pattern(ff_img, "*.wim");
	gtk_file_filter_add_pattern(ff_img, "*.esd");
	gtk_file_filter_add_pattern(ff_img, "*.ffu");
	gtk_file_filter_add_pattern(ff_img, "*.zip");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), ff_img);

	GtkFileFilter *ff_all = gtk_file_filter_new();
	gtk_file_filter_set_name(ff_all, "All files (*.*)");
	gtk_file_filter_add_pattern(ff_all, "*");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), ff_all);

	if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
		char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
		free(image_path);
		image_path = strdup(filename);
		g_free(filename);
		uprintf("Image selected: %s", image_path);
		/* Launch ImageScanThread to populate img_report; it posts
		 * UM_IMAGE_SCANNED when done so the UI can refresh. */
		HANDLE scan_thr = CreateThread(NULL, 0, ImageScanThread, NULL, 0, NULL);
		safe_closehandle(scan_thr);
		rufus_gtk_update_status(image_path);
	}
	gtk_widget_destroy(dlg);
}

static void on_device_changed(GtkComboBox *combo, gpointer data)
{
	(void)data;
	(void)combo;

	/* Read the selected drive index from the combo state */
	int sel = ComboBox_GetCurSel(hDeviceList);
	if (sel < 0)
		return;
	DWORD di = (DWORD)ComboBox_GetItemData(hDeviceList, sel);

	/* Read partition / FS data for the selected drive */
	char fs_name[32] = "";
	GetDrivePartitionData(di, fs_name, sizeof(fs_name), TRUE);

	/* Refresh partition scheme + target system combos */
	populate_partition_combos();

	/* Refresh FS and cluster size combos */
	populate_fs_combo();
}

static void on_boot_changed(GtkComboBox *combo, gpointer data)
{
	(void)data;
	(void)combo;

	/* Update global boot_type from the combo */
	int sel = ComboBox_GetCurSel(hBootType);
	if (sel >= 0)
		boot_type = (int)ComboBox_GetItemData(hBootType, sel);

	/* Partition / FS combos may need to change depending on boot type */
	populate_partition_combos();
	populate_fs_combo();
}

static void on_log_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	if (rw.log_dialog) {
		gtk_widget_show_all(rw.log_dialog);
		gtk_window_present(GTK_WINDOW(rw.log_dialog));
	}
}

static void on_about_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;

	GtkWidget *dlg = gtk_about_dialog_new();
	gtk_about_dialog_set_program_name(GTK_ABOUT_DIALOG(dlg), "Rufus");
	gtk_about_dialog_set_version(GTK_ABOUT_DIALOG(dlg), "4.13");
	gtk_about_dialog_set_comments(GTK_ABOUT_DIALOG(dlg),
		"The Reliable USB Formatting Utility");
	gtk_about_dialog_set_website(GTK_ABOUT_DIALOG(dlg), "https://rufus.ie");
	gtk_about_dialog_set_license_type(GTK_ABOUT_DIALOG(dlg), GTK_LICENSE_GPL_3_0);
	gtk_dialog_run(GTK_DIALOG(dlg));
	gtk_widget_destroy(dlg);
}

static void on_lang_menu_activate(GtkMenuItem *item, gpointer data)
{
	(void)data;
	guint msg_id = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(item), "lang-msg-id"));
	PostMessage(hMainDialog, (UINT)msg_id, 0, 0);
}

static void on_lang_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	RECT rc = {0, 0, 0, 0};
	ShowLanguageMenu(rc);
}

/* ======================================================================
 * ui.h API implementation for GTK
 * ====================================================================== */

void SetAccessibleName(HWND hCtrl, const char *name)
{
	GtkWidget *w = (GtkWidget *)hCtrl;
	if (w && name)
		gtk_widget_set_tooltip_text(w, name);
}

void SetComboEntry(HWND hDlg, int data)
{
	GtkWidget *w = (GtkWidget *)hDlg;
	if (w && GTK_IS_COMBO_BOX(w))
		gtk_combo_box_set_active(GTK_COMBO_BOX(w), data);
}

/* Layout helpers — GTK manages its own layout so most of these are no-ops. */
void GetBasicControlsWidth(HWND hDlg)   { (void)hDlg; }
void GetMainButtonsWidth(HWND hDlg)     { (void)hDlg; }
void GetHalfDropwdownWidth(HWND hDlg)   { (void)hDlg; }
void GetFullWidth(HWND hDlg)            { (void)hDlg; }

void PositionMainControls(HWND hDlg)
{
	(void)hDlg;
	/* GTK lays out controls automatically — nothing to do. */
}

void AdjustForLowDPI(HWND hDlg)
{
	(void)hDlg;
	/* GTK handles DPI scaling natively via GDK. */
}

void SetSectionHeaders(HWND hDlg, HFONT *hFont)
{
	(void)hDlg; (void)hFont;
	/* Section headers are static GTK labels built once. */
}

void SetPersistencePos(uint64_t pos)
{
	if (!rw.persistence_scale) return;
	gtk_range_set_value(GTK_RANGE(rw.persistence_scale), (gdouble)pos);
}

void SetPersistenceSize(void)
{
	if (!rw.persistence_size) return;
	char buf[64];
	gdouble val = gtk_range_get_value(GTK_RANGE(rw.persistence_scale));
	snprintf(buf, sizeof(buf), "%.0f MB", val);
	gtk_label_set_text(GTK_LABEL(rw.persistence_size), buf);
}

void TogglePersistenceControls(BOOL display)
{
	if (!rw.persistence_row) return;
	if (display) {
		gtk_widget_show_all(rw.persistence_row);
	} else {
		gtk_widget_hide(rw.persistence_row);
	}
}

void ToggleAdvancedDeviceOptions(BOOL enable)
{
	if (!rw.adv_device_expander) return;
	gtk_expander_set_expanded(GTK_EXPANDER(rw.adv_device_expander), enable ? TRUE : FALSE);
}

void ToggleAdvancedFormatOptions(BOOL enable)
{
	if (!rw.adv_format_expander) return;
	gtk_expander_set_expanded(GTK_EXPANDER(rw.adv_format_expander), enable ? TRUE : FALSE);
}

void ToggleImageOptions(void)
{
	if (!rw.image_option_row) return;
	if (gtk_widget_get_visible(rw.image_option_row))
		gtk_widget_hide(rw.image_option_row);
	else
		gtk_widget_show_all(rw.image_option_row);
}

void CreateSmallButtons(HWND hDlg)    { (void)hDlg; }
void CreateAdditionalControls(HWND hDlg) { (void)hDlg; }

void EnableControls(BOOL enable, BOOL remove_checkboxes)
{
	(void)remove_checkboxes;
	gboolean e = enable ? TRUE : FALSE;
	if (rw.device_combo)      gtk_widget_set_sensitive(rw.device_combo,      e);
	if (rw.boot_combo)        gtk_widget_set_sensitive(rw.boot_combo,        e);
	if (rw.select_btn)        gtk_widget_set_sensitive(rw.select_btn,        e);
	if (rw.partition_combo)   gtk_widget_set_sensitive(rw.partition_combo,   e);
	if (rw.target_combo)      gtk_widget_set_sensitive(rw.target_combo,      e);
	if (rw.filesystem_combo)  gtk_widget_set_sensitive(rw.filesystem_combo,  e);
	if (rw.cluster_combo)     gtk_widget_set_sensitive(rw.cluster_combo,     e);
	if (rw.label_entry)       gtk_widget_set_sensitive(rw.label_entry,       e);
	if (rw.start_btn)         gtk_widget_set_sensitive(rw.start_btn,         e);

	/* While an operation is in progress, repurpose the close button as Cancel */
	if (rw.close_btn) {
		gtk_button_set_label(GTK_BUTTON(rw.close_btn), enable ? "CLOSE" : "CANCEL");
		gtk_widget_set_sensitive(rw.close_btn, TRUE);
	}
}

void InitProgress(BOOL bOnlyFormat)
{
	(void)bOnlyFormat;
	if (rw.progress_bar) {
		gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(rw.progress_bar), 0.0);
		gtk_progress_bar_set_text(GTK_PROGRESS_BAR(rw.progress_bar), NULL);
		gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(rw.progress_bar), FALSE);
	}
}

void ShowLanguageMenu(RECT rcExclude)
{
	(void)rcExclude;

	if (list_empty(&locale_list))
		return;

	GtkWidget *menu = gtk_menu_new();
	UINT_PTR index = 0;
	loc_cmd *lcmd = NULL;
	UM_LANGUAGE_MENU_MAX = UM_LANGUAGE_MENU;

	list_for_each_entry(lcmd, &locale_list, loc_cmd, list) {
		const char *label = (lcmd->txt[1] && lcmd->txt[1][0]) ? lcmd->txt[1] : lcmd->txt[0];
		GtkWidget *item = gtk_check_menu_item_new_with_label(label ? label : "?");
		gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item),
		                               lcmd == selected_locale);
		/* Store the message ID for this locale as user data */
		g_object_set_data(G_OBJECT(item), "lang-msg-id",
		                  GUINT_TO_POINTER((guint)(UM_LANGUAGE_MENU + index)));
		g_signal_connect(item, "activate", G_CALLBACK(on_lang_menu_activate), NULL);
		gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
		UM_LANGUAGE_MENU_MAX++;
		index++;
	}

	gtk_widget_show_all(menu);
	gtk_menu_popup_at_widget(GTK_MENU(menu), rw.lang_btn,
	                         GDK_GRAVITY_SOUTH_WEST, GDK_GRAVITY_NORTH_WEST, NULL);
}

void SetPassesTooltip(void)
{
	if (!rw.nb_passes_combo) return;
	gtk_widget_set_tooltip_text(rw.nb_passes_combo,
		"Number of passes for bad block check");
}

void SetBootTypeDropdownWidth(void)
{
	/* GTK auto-sizes combo boxes — nothing to do. */
}

void OnPaint(HDC hdc)
{
	(void)hdc;
	/* GTK handles all drawing via CSS/cairo — no custom paint needed. */
}

/* UpdateProgress is called from worker threads. */
void UpdateProgress(int op, float percent)
{
	(void)op;
	if (!rw.progress_bar) return;
	/* Must marshal to the GTK main thread via an idle callback. */
	ProgressData *pd = malloc(sizeof(*pd));
	if (!pd) return;
	pd->op  = op;
	pd->pct = percent;
	g_idle_add(idle_update_progress, pd);
}

void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL f)
{
	(void)op; (void)msg; (void)f;
	if (tot == 0) return;
	float pct = (float)((double)cur / (double)tot * 100.0);
	UpdateProgress(op, pct);
}

/* ======================================================================
 * Message dispatch — GTK integration
 *
 * msg_gtk_scheduler() is installed as the MsgPostScheduler so that every
 * call to PostMessage() and cross-thread SendMessage() is dispatched safely
 * through the GLib main loop.
 * ====================================================================== */

typedef struct { void (*fn)(void *); void *data; } GtkSchedItem;

static gboolean gtk_sched_idle(gpointer ud)
{
	GtkSchedItem *item = (GtkSchedItem *)ud;
	item->fn(item->data);
	free(item);
	return G_SOURCE_REMOVE;
}

static void msg_gtk_scheduler(void (*fn)(void *), void *data)
{
	GtkSchedItem *item = malloc(sizeof(*item));
	if (!item) { fn(data); return; }  /* fallback if OOM */
	item->fn   = fn;
	item->data = data;
	g_idle_add(gtk_sched_idle, item);
}

/* -----------------------------------------------------------------------
 * Main dialog message handler
 *
 * Handles UM_* messages sent/posted by worker threads (format, hash, net,
 * etc.) to hMainDialog.  Runs on the GTK main thread — safe to touch
 * any widget here.
 * --------------------------------------------------------------------- */
static LRESULT main_dialog_handler(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
	(void)hwnd; (void)l;

	switch (msg) {
	case UM_FORMAT_COMPLETED:
		/* w = TRUE on success, FALSE on failure */
		op_in_progress = FALSE;
		safe_closehandle(format_thread);
		format_thread = NULL;
		EnableControls((BOOL)w, TRUE);
		if (w)
			rufus_gtk_update_status("Format completed successfully.");
		else
			rufus_gtk_update_status("Format failed.");
		uprintf("*** Format completed (success=%d) ***", (int)w);
		break;

	case UM_ENABLE_CONTROLS:
		EnableControls(TRUE, TRUE);
		break;

	case UM_PROGRESS_INIT:
		InitProgress(TRUE);
		break;

	case UM_PROGRESS_EXIT:
		/* Nothing extra needed on Linux — progress bar stays visible. */
		break;

	case UM_TIMER_START:
		/* On Windows this starts an elapsed-time timer. On Linux we rely
		 * on progress callbacks from the format thread. */
		break;

	case UM_SELECT_ISO:
		/* The Fido download thread finished; show a file-chooser so the
		 * user can select the downloaded ISO.  Re-use the SELECT handler. */
		on_select_clicked(NULL, NULL);
		break;

	case UM_NO_UPDATE:
		rufus_gtk_update_status("No updates available.");
		break;

	case UM_IMAGE_SCANNED:
		/* ImageScanThread finished — img_report is now populated.
		 * Refresh boot type, filesystem, and partition-scheme combos
		 * to reflect the scanned image content. */
		uprintf("Image scan complete (is_iso=%d, is_bootable=%d)",
		        (int)img_report.is_iso, (int)img_report.is_bootable_img);
		SetFSFromISO();
		SetPartitionSchemeAndTargetSystem(FALSE);
		break;

	case UM_HASH_COMPLETED: {
		/* HashThread finished — show a dialog with MD5/SHA1/SHA256/(SHA512) results */
		const char *hash_labels[] = { "MD5", "SHA-1", "SHA-256", "SHA-512" };
		GtkWidget *dlg, *content_area, *grid, *label;
		char title[256];
		int row = 0;
		int i;

		/* Build window title from image filename */
		if (image_path && image_path[0]) {
			/* basename may modify its argument, so pass a copy */
			char path_copy[512];
			strncpy(path_copy, image_path, sizeof(path_copy) - 1);
			path_copy[sizeof(path_copy) - 1] = '\0';
			snprintf(title, sizeof(title), "Checksums — %s", basename(path_copy));
		} else {
			snprintf(title, sizeof(title), "Checksums");
		}

		dlg = gtk_dialog_new_with_buttons(
			title, GTK_WINDOW(rw.window),
			GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
			"_OK", GTK_RESPONSE_OK, NULL);

		content_area = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
		gtk_container_set_border_width(GTK_CONTAINER(content_area), 12);

		grid = gtk_grid_new();
		gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
		gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
		gtk_container_add(GTK_CONTAINER(content_area), grid);

		for (i = 0; i < HASH_MAX; i++) {
			if (hash_str[i][0] == '\0')
				continue;
			/* Label column */
			label = gtk_label_new(hash_labels[i]);
			gtk_widget_set_halign(label, GTK_ALIGN_END);
			gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1);
			/* Value column — monospace */
			label = gtk_label_new(hash_str[i]);
			gtk_widget_set_halign(label, GTK_ALIGN_START);
			gtk_label_set_selectable(GTK_LABEL(label), TRUE);
			PangoFontDescription *font = pango_font_description_from_string("Monospace");
			gtk_widget_override_font(label, font);
			pango_font_description_free(font);
			gtk_grid_attach(GTK_GRID(grid), label, 1, row, 1, 1);
			row++;
		}

		gtk_widget_show_all(dlg);
		gtk_dialog_run(GTK_DIALOG(dlg));
		gtk_widget_destroy(dlg);
		break;
	}

	case UM_MEDIA_CHANGE:
		/* Block-device hotplug event — refresh the device list.
		 * Guard against triggering a refresh while a format is in progress. */
		if (!op_in_progress) {
			uprintf("Device change detected, refreshing device list.");
			GetDevices((DWORD)ComboBox_GetCurItemData(hDeviceList));
			EnableControls(TRUE, FALSE);
		}
		break;

	default:
		/* Language menu items (UM_LANGUAGE_MENU … UM_LANGUAGE_MENU + N) */
		if (msg >= UM_LANGUAGE_MENU && msg < UM_LANGUAGE_MENU_MAX) {
			UINT selected_index = (UINT)(msg - UM_LANGUAGE_MENU);
			UINT i = 0;
			loc_cmd *lcmd = NULL;
			list_for_each_entry(lcmd, &locale_list, loc_cmd, list) {
				if (i++ == selected_index) {
					if (selected_locale != lcmd) {
						selected_locale = lcmd;
						get_loc_data_file(loc_filename, selected_locale);
						apply_localization(0, hMainDialog);
						uprintf("Language switched to %s",
						        lcmd->txt[1] ? lcmd->txt[1] : lcmd->txt[0]);
					}
					break;
				}
			}
		}
		break;
	}

	return 0;
}

/* ======================================================================
 * Device hotplug — udev → GTK main thread bridge
 * ====================================================================== */

/* Called by the device_monitor background thread when a block device is
 * added or removed.  Posts UM_MEDIA_CHANGE to the main dialog so that the
 * device list is refreshed on the GTK main thread. */
static void on_device_change(void *user_data)
{
	(void)user_data;
	PostMessage(hMainDialog, UM_MEDIA_CHANGE, 0, 0);
}

/* ======================================================================
 * Combo-state population helpers
 * ====================================================================== */

/*
 * populate_boot_combo — fill the boot type dropdown.
 *
 * On Linux we offer: Non-bootable, Disk/ISO image, FreeDOS.
 * More entries (Syslinux, GRUB, etc.) can be added as support lands.
 */
static void populate_boot_combo(void)
{
	IGNORE_RETVAL(ComboBox_ResetContent(hBootType));
	IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
	    ComboBox_AddString(hBootType, "Non-bootable"), BT_NON_BOOTABLE));
	IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
	    ComboBox_AddString(hBootType, "Disk or ISO image (Please SELECT)"), BT_IMAGE));
	IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
	    ComboBox_AddString(hBootType, "FreeDOS"), BT_FREEDOS));

	/* Select "Non-bootable" as the default */
	IGNORE_RETVAL(ComboBox_SetCurSel(hBootType, 0));
	boot_type = BT_NON_BOOTABLE;
}

/*
 * populate_partition_combos — fill Partition Scheme and Target System dropdowns
 * based on the current boot_type.
 */
static void populate_partition_combos(void)
{
	IGNORE_RETVAL(ComboBox_ResetContent(hPartitionScheme));
	IGNORE_RETVAL(ComboBox_SetItemData(hPartitionScheme,
	    ComboBox_AddString(hPartitionScheme, "MBR"), PARTITION_STYLE_MBR));
	IGNORE_RETVAL(ComboBox_SetItemData(hPartitionScheme,
	    ComboBox_AddString(hPartitionScheme, "GPT"), PARTITION_STYLE_GPT));
	IGNORE_RETVAL(ComboBox_SetCurSel(hPartitionScheme, 0));
	partition_type = PARTITION_STYLE_MBR;

	IGNORE_RETVAL(ComboBox_ResetContent(hTargetSystem));
	IGNORE_RETVAL(ComboBox_SetItemData(hTargetSystem,
	    ComboBox_AddString(hTargetSystem, "BIOS (or UEFI-CSM)"), TT_BIOS));
	IGNORE_RETVAL(ComboBox_SetItemData(hTargetSystem,
	    ComboBox_AddString(hTargetSystem, "UEFI (non-CSM)"), TT_UEFI));
	IGNORE_RETVAL(ComboBox_SetCurSel(hTargetSystem, 0));
	target_type = TT_BIOS;
}

/*
 * populate_fs_combo — fill the File System dropdown.
 *
 * On Linux we support FAT32 and ext2/ext3/ext4.
 * NTFS, exFAT, UDF, ReFS are shown as placeholders only when explicitly
 * selecting an image that requires them (not yet implemented).
 */
static void populate_fs_combo(void)
{
	IGNORE_RETVAL(ComboBox_ResetContent(hFileSystem));
	IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
	    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_FAT32]), FS_FAT32));
	IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
	    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_EXT2]),  FS_EXT2));
	IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
	    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_EXT3]),  FS_EXT3));
	IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
	    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_EXT4]),  FS_EXT4));

	/* Default to FAT32 */
	IGNORE_RETVAL(ComboBox_SetCurSel(hFileSystem, 0));
	fs_type = FS_FAT32;

	populate_cluster_combo(FS_FAT32);
}

/*
 * populate_cluster_combo — fill Cluster Size dropdown for the given FS type.
 *
 * For FAT32 we offer common cluster sizes.
 * For ext* the cluster size is determined automatically by mkfs.ext*.
 */
static void populate_cluster_combo(int fs)
{
	IGNORE_RETVAL(ComboBox_ResetContent(hClusterSize));

	if (IS_EXT(fs)) {
		IGNORE_RETVAL(ComboBox_SetItemData(hClusterSize,
		    ComboBox_AddString(hClusterSize, "4096 bytes (Default)"), 4096));
		IGNORE_RETVAL(ComboBox_SetCurSel(hClusterSize, 0));
		return;
	}

	/* FAT32 common cluster sizes */
	static const struct { const char *label; DWORD size; } fat_clusters[] = {
		{ "512 bytes",   512   },
		{ "1024 bytes",  1024  },
		{ "2048 bytes",  2048  },
		{ "4096 bytes",  4096  },
		{ "8192 bytes",  8192  },
		{ "16384 bytes", 16384 },
		{ "32768 bytes", 32768 },
		{ NULL, 0 }
	};
	int def = 3; /* 4096 bytes default */
	for (int i = 0; fat_clusters[i].label; i++) {
		IGNORE_RETVAL(ComboBox_SetItemData(hClusterSize,
		    ComboBox_AddString(hClusterSize, fat_clusters[i].label),
		    fat_clusters[i].size));
	}
	IGNORE_RETVAL(ComboBox_SetCurSel(hClusterSize, def));
}

/* ======================================================================
 * Combo-state registration
 * ====================================================================== */

/*
 * combo_register_all — create and register combo states for every combo HWND.
 *
 * Must be called after the GTK widgets have been created (i.e. after
 * rufus_gtk_create_window()) but before msg_dispatch is first used to
 * send CB_* messages.
 *
 * The function:
 *   1. Allocates a combo_state_t for each combo, binding it to the GTK widget.
 *   2. Registers each state with msg_dispatch so SendMessageA routes correctly.
 *   3. Updates the hXxx HWND globals to point at the state objects.
 *   4. Performs initial population of all dropdowns.
 */
static void combo_register_all(void)
{
	/* Allocate states (binding to GTK widget for sync) */
	cs_device  = combo_state_alloc(rw.device_combo);
	cs_boot    = combo_state_alloc(rw.boot_combo);
	cs_part    = combo_state_alloc(rw.partition_combo);
	cs_target  = combo_state_alloc(rw.target_combo);
	cs_fs      = combo_state_alloc(rw.filesystem_combo);
	cs_cluster = combo_state_alloc(rw.cluster_combo);
	cs_imgopt  = combo_state_alloc(rw.image_option_combo);

	/* Register handlers */
	msg_dispatch_register((HWND)cs_device,  combo_msg_handler);
	msg_dispatch_register((HWND)cs_boot,    combo_msg_handler);
	msg_dispatch_register((HWND)cs_part,    combo_msg_handler);
	msg_dispatch_register((HWND)cs_target,  combo_msg_handler);
	msg_dispatch_register((HWND)cs_fs,      combo_msg_handler);
	msg_dispatch_register((HWND)cs_cluster, combo_msg_handler);
	msg_dispatch_register((HWND)cs_imgopt,  combo_msg_handler);

	/* Re-map the HWND globals to the combo state objects.
	 * hLabel / hProgress keep their original GTK widget pointers because
	 * they are not combo boxes. */
	hDeviceList      = (HWND)cs_device;
	hBootType        = (HWND)cs_boot;
	hPartitionScheme = (HWND)cs_part;
	hTargetSystem    = (HWND)cs_target;
	hFileSystem      = (HWND)cs_fs;
	hClusterSize     = (HWND)cs_cluster;
	hImageOption     = (HWND)cs_imgopt;

	/* Initial population */
	populate_boot_combo();
	populate_partition_combos();
	populate_fs_combo();
}

static void on_app_activate(GtkApplication *app, gpointer data)
{
	(void)data;

	/* Initialise application paths (app_dir, app_data_dir, user_dir, ini_file)
	 * using XDG Base Directory conventions. */
	rufus_init_paths();

	/* Load the embedded locale data file, populate locale_list, and apply
	 * the best match for the system language to the UI strings. */
	{
		const char *loc_path = find_loc_file();
		if (loc_path != NULL) {
			uprintf("localization: loading '%s'", loc_path);
			if (get_supported_locales(loc_path)) {
				char *sys_locale = ToLocaleName(0);
				loc_cmd *sel = get_locale_from_name(sys_locale, TRUE);
				if (sel != NULL)
					get_loc_data_file(loc_path, sel);
				else
					uprintf("localization: no locale match for '%s'", sys_locale);
			} else {
				uprintf("localization: failed to parse '%s'", loc_path);
			}
		} else {
			uprintf("localization: embedded.loc not found — UI strings will be untranslated");
		}
	}

	/* Initialise the message dispatch system on the main thread and hook
	 * it up to the GTK scheduler so worker threads can safely drive UI
	 * updates via PostMessage() / SendMessage(). */
	msg_dispatch_init();
	msg_dispatch_set_scheduler(msg_gtk_scheduler);

	/* Route uprintf() output to the GTK log widget so all log messages
	 * appear in the on-screen log window rather than just stderr. */
	rufus_set_log_handler(rufus_gtk_append_log);
	/* Route PrintStatusInfo() to the GTK status label. */
	rufus_set_status_handler(rufus_gtk_update_status);

	GtkWidget *win = rufus_gtk_create_window(app);
	(void)win;

	/* Map the non-combo HWND globals to their GTK widget pointers. */
	hMainDialog = (HWND)rw.window;
	hLabel      = (HWND)rw.label_entry;
	hProgress   = (HWND)rw.progress_bar;

	/* Check for root privileges: Rufus requires them to write to block devices.
	 * Warn the user — but still let the app run so they can browse options.
	 * On most distributions users will run via 'sudo rufus' or 'pkexec rufus'. */
	if (!IsCurrentProcessElevated()) {
		uprintf("WARNING: Rufus is not running as root — device writes will fail.");
		Notification(MB_OK | MB_ICONWARNING,
		             lmprintf(MSG_288),
		             lmprintf(MSG_289));
	}

	/* Register the main dialog message handler. */
	msg_dispatch_register(hMainDialog, main_dialog_handler);

	/* Create and register combo bridge states for every combo box.
	 * This re-maps hDeviceList / hBootType / hPartitionScheme / hTargetSystem /
	 * hFileSystem / hClusterSize / hImageOption to their combo_state_t objects
	 * so that SendMessageA(hCombo, CB_*, …) calls work correctly, and
	 * performs the initial population of each dropdown. */
	combo_register_all();

	/* Set tooltips on key UI controls, using localized strings if available. */
	CreateTooltip((HWND)rw.filesystem_combo, lmprintf(MSG_157), -1);
	CreateTooltip((HWND)rw.cluster_combo,    lmprintf(MSG_158), -1);
	CreateTooltip((HWND)rw.label_entry,      lmprintf(MSG_159), -1);
	CreateTooltip((HWND)rw.boot_combo,       lmprintf(MSG_164), -1);
	CreateTooltip((HWND)rw.select_btn,       lmprintf(MSG_165), -1);
	CreateTooltip((HWND)rw.start_btn,        lmprintf(MSG_171), -1);

	/* Enumerate attached block devices and fill the device list. */
	GetDevices(0);

	/* Start the udev block-device hotplug monitor.  Events are debounced
	 * and delivered to hMainDialog as UM_MEDIA_CHANGE via PostMessage. */
	device_monitor_start(on_device_change, NULL);

	rufus_gtk_update_status("Ready.");
	uprintf("*** Rufus GTK UI started ***");

	/* Run update check in background (SetUpdateCheck configures the interval,
	 * CheckForUpdates respects it and only actually contacts the server when
	 * the configured interval has elapsed since the last successful check). */
	if (SetUpdateCheck())
		CheckForUpdates(FALSE);
}

int main(int argc, char *argv[])
{
	GtkApplication *app;
	int status;

	/* G_APPLICATION_DEFAULT_FLAGS was added in GLib 2.74; use the older name for broader compat. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	app = gtk_application_new("ie.rufus.Rufus", G_APPLICATION_FLAGS_NONE);
#pragma GCC diagnostic pop
	g_signal_connect(app, "activate", G_CALLBACK(on_app_activate), NULL);
	status = g_application_run(G_APPLICATION(app), argc, argv);
	g_object_unref(app);

	return status;
}
