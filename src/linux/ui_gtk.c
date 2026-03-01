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

/* format_thread and dialog_handle are defined in globals.c */
extern HANDLE format_thread;
extern HANDLE dialog_handle;

/* ---- Global widget registry ---- */
RufusWidgets rw = { 0 };

/* Struct used to pass progress data to the GTK main thread via g_idle_add. */
typedef struct { int op; float pct; } ProgressData;

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
static void on_device_changed(GtkComboBox *combo, gpointer data);
static void on_boot_changed(GtkComboBox *combo, gpointer data);
static void on_log_clicked(GtkButton *btn, gpointer data);
static void on_about_clicked(GtkButton *btn, gpointer data);
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
	GtkWidget *lbl  = gtk_label_new("Device");
	gtk_widget_set_halign(lbl, GTK_ALIGN_START);

	rw.device_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.device_combo, TRUE);
	gtk_widget_set_tooltip_text(rw.device_combo, "Select the USB drive to format");

	g_signal_connect(rw.device_combo, "changed", G_CALLBACK(on_device_changed), NULL);

	GtkWidget *toolbar = build_toolbar();

	gtk_box_pack_start(GTK_BOX(hbox), lbl,             FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.device_combo, TRUE,  TRUE,  0);
	gtk_box_pack_end  (GTK_BOX(hbox), toolbar,         FALSE, FALSE, 0);

	return hbox;
}

/* ---- Boot selection row ---- */
static GtkWidget *build_boot_row(void)
{
	GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *lbl  = gtk_label_new("Boot selection");
	gtk_widget_set_halign(lbl, GTK_ALIGN_START);

	rw.boot_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.boot_combo, TRUE);
	g_signal_connect(rw.boot_combo, "changed", G_CALLBACK(on_boot_changed), NULL);

	rw.select_btn = gtk_button_new_with_label("SELECT");
	g_signal_connect(rw.select_btn, "clicked", G_CALLBACK(on_select_clicked), NULL);

	gtk_box_pack_start(GTK_BOX(hbox), lbl,            FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.boot_combo,  TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.select_btn,  FALSE, FALSE, 0);

	return hbox;
}

/* ---- Image option row ---- */
static GtkWidget *build_image_option_row(void)
{
	GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *lbl  = gtk_label_new("Image option");
	gtk_widget_set_halign(lbl, GTK_ALIGN_START);

	rw.image_option_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.image_option_combo, TRUE);

	gtk_box_pack_start(GTK_BOX(hbox), lbl,                    FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.image_option_combo,  TRUE,  TRUE,  0);

	rw.image_option_row = hbox;
	gtk_widget_set_no_show_all(hbox, TRUE); /* hidden until needed */
	return hbox;
}

/* ---- Drive properties section ---- */
static GtkWidget *build_drive_properties(void)
{
	GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	gtk_box_pack_start(GTK_BOX(vbox), make_section_label("Drive Properties"), FALSE, FALSE, 2);

	/* Row: Partition scheme + Target system */
	GtkWidget *row1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *lbl_pt = gtk_label_new("Partition scheme");
	rw.partition_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.partition_combo, TRUE);
	GtkWidget *lbl_ts = gtk_label_new("Target system");
	rw.target_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.target_combo, TRUE);
	gtk_box_pack_start(GTK_BOX(row1), lbl_pt,             FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(row1), rw.partition_combo, TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(row1), lbl_ts,             FALSE, FALSE, 8);
	gtk_box_pack_start(GTK_BOX(row1), rw.target_combo,    TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(vbox), row1, FALSE, FALSE, 0);

	/* Row: File system + Cluster size */
	GtkWidget *row2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *lbl_fs = gtk_label_new("File system");
	rw.filesystem_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.filesystem_combo, TRUE);
	GtkWidget *lbl_cs = gtk_label_new("Cluster size");
	rw.cluster_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.cluster_combo, TRUE);
	gtk_box_pack_start(GTK_BOX(row2), lbl_fs,              FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(row2), rw.filesystem_combo, TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(row2), lbl_cs,              FALSE, FALSE, 8);
	gtk_box_pack_start(GTK_BOX(row2), rw.cluster_combo,    TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(vbox), row2, FALSE, FALSE, 0);

	/* Row: Volume label */
	GtkWidget *row3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *lbl_lbl = gtk_label_new("Volume label");
	rw.label_entry = gtk_entry_new();
	gtk_widget_set_hexpand(rw.label_entry, TRUE);
	gtk_box_pack_start(GTK_BOX(row3), lbl_lbl,        FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(row3), rw.label_entry, TRUE,  TRUE,  0);
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
	gtk_box_pack_start(GTK_BOX(vbox), make_section_label("Format Options"), FALSE, FALSE, 2);

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
	gtk_box_pack_start(GTK_BOX(vbox), make_section_label("Status"), FALSE, FALSE, 2);

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
		/* TODO: cancel the running operation */
		uprintf("Cancel requested by user");
	} else {
		device_monitor_stop();
		gtk_main_quit();
	}
}

static void on_start_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	if (ComboBox_GetCurSel(hDeviceList) < 0) {
		rufus_gtk_update_status("No device selected");
		return;
	}
	uprintf("Format started by user");
	if (format_thread == NULL) {
		format_thread = CreateThread(NULL, 0, FormatThread, NULL, 0, NULL);
		if (format_thread == NULL)
			rufus_gtk_update_status("Failed to start format thread");
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
		/* Trigger image scan — same hook as Windows */
		/* PostMessage(hMainDialog, UM_FORMAT_START, 0, 0); */
		rufus_gtk_update_status(image_path);
	}
	gtk_widget_destroy(dlg);
}

static void on_device_changed(GtkComboBox *combo, gpointer data)
{
	(void)data;
	int sel = gtk_combo_box_get_active(combo);
	if (sel < 0)
		return;
	/* Propagate to the shared device selection logic */
	/* GetDevices() and UpdateDriveInfo() are called by the format layer */
}

static void on_boot_changed(GtkComboBox *combo, gpointer data)
{
	(void)data;
	(void)combo;
	/* Propagate to partition/fs dropdowns */
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
	/* TODO: Build a GTK popover/menu with the available locales. */
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
		if (msg >= UM_LANGUAGE_MENU)
			uprintf("Language menu item %u selected.", msg - UM_LANGUAGE_MENU);
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
 * main() — GTK application entry point
 * ====================================================================== */

static void on_app_activate(GtkApplication *app, gpointer data)
{
	(void)data;

	/* Initialise application paths (app_dir, app_data_dir, user_dir, ini_file)
	 * using XDG Base Directory conventions. */
	rufus_init_paths();

	/* Initialise the message dispatch system on the main thread and hook
	 * it up to the GTK scheduler so worker threads can safely drive UI
	 * updates via PostMessage() / SendMessage(). */
	msg_dispatch_init();
	msg_dispatch_set_scheduler(msg_gtk_scheduler);

	GtkWidget *win = rufus_gtk_create_window(app);
	(void)win;

	/* Map the Windows-style HWND globals to their GTK counterparts so that
	 * shared business logic (drive detection, formatting, etc.) can use them
	 * via the compat layer's no-op inline functions. */
	hMainDialog  = (HWND)rw.window;
	hDeviceList  = (HWND)rw.device_combo;
	hBootType    = (HWND)rw.boot_combo;
	hPartitionScheme = (HWND)rw.partition_combo;
	hTargetSystem    = (HWND)rw.target_combo;
	hFileSystem      = (HWND)rw.filesystem_combo;
	hClusterSize     = (HWND)rw.cluster_combo;
	hLabel           = (HWND)rw.label_entry;
	hProgress        = (HWND)rw.progress_bar;
	hImageOption     = (HWND)rw.image_option_combo;

	/* Register the main dialog message handler. */
	msg_dispatch_register(hMainDialog, main_dialog_handler);

	/* Start the udev block-device hotplug monitor.  Events are debounced
	 * and delivered to hMainDialog as UM_MEDIA_CHANGE via PostMessage. */
	device_monitor_start(on_device_change, NULL);

	rufus_gtk_update_status("Ready.");
	uprintf("*** Rufus GTK UI started ***");
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
