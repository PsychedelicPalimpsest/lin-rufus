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
#include <inttypes.h>
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
#include "settings.h"
#include "version.h"
#include "window_text_bridge.h"
#include "crash_handler.h"
#include "device_combo.h"
#include "status_history.h"
#include "notify.h"
#include "system_info.h"
#include "darkmode.h"
#include "wue.h"
#include "polkit.h"
#include "hyperlink.h"
#include "csm_help.h"
#include "multidev.h"
#include "ventoy_detect.h"
#include "kbd_shortcuts.h"
#include "ui_enable_opts.h"
#include "boot_validation.h"
#include "drag_drop.h"
#include "../../res/grub/grub_version.h"
#include "../../res/grub2/grub2_version.h"

/* Log handler registration — implemented in linux/stdio.c */
extern void rufus_set_log_handler(void (*fn)(const char *msg));
/* Status bar handler registration — implemented in linux/localization.c */
extern void rufus_set_status_handler(void (*fn)(const char *msg));

/* Update check — implemented in linux/stdlg.c and linux/net.c */
extern BOOL SetUpdateCheck(void);
extern BOOL CheckForUpdates(BOOL force);
extern BOOL quick_format, zero_drive;
extern BOOL enable_bad_blocks;
extern BOOL enable_verify_write;
extern int  nb_passes_sel;
extern BOOL write_as_image, write_as_esp;
extern BOOL size_check;         /* globals.c */
extern BOOL fast_zeroing;       /* globals.c */
extern BOOL force_large_fat32;  /* globals.c */
extern BOOL use_rufus_mbr;      /* globals.c */
extern BOOL use_fake_units;     /* globals.c */
extern BOOL preserve_timestamps;/* globals.c */
extern BOOL enable_vmdk;        /* globals.c */
extern BOOL enable_ntfs_compression; /* globals.c */
extern BOOL allow_dual_uefi_bios;    /* globals.c */
extern BOOL enable_VHDs;        /* globals.c */
extern BOOL lock_drive;         /* globals.c */
extern BOOL user_deleted_rufus_dir;   /* globals.c */
extern BOOL previous_enable_HDDs;     /* globals.c */
extern BOOL list_non_usb_removable_drives; /* globals.c */
extern BOOL enable_file_indexing; /* globals.c */
extern uint8_t image_options;     /* globals.c */

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
extern char *archive_path;      /* globals.c */
extern BOOL expert_mode;        /* globals.c */
extern BOOL enable_HDDs;        /* globals.c */
extern BOOL enable_joliet;      /* iso.c */
extern BOOL enable_rockridge;   /* iso.c */

#include "ui_combo_logic.h"   /* populate_fs_combo, populate_cluster_combo,
                                * SetFSFromISO, SetPartitionSchemeAndTargetSystem */
#include "proposed_label.h"   /* get_iso_proposed_label */

/* Tracks whether the user has manually edited the label since the last scan. */
static BOOL user_changed_label = FALSE;
/* Set TRUE while SetProposedLabel() is updating the entry to avoid false
 * user_changed_label triggers from the "changed" signal. */
static BOOL app_changed_label  = FALSE;

/* Set TRUE while SetPersistenceSize() is updating the entry to avoid feedback loop. */
static BOOL app_changed_persistence = FALSE;
static void on_persistence_size_entry_changed(GtkWidget *w, gpointer data);
static gboolean on_persistence_size_entry_focus_out(GtkWidget *w, GdkEventFocus *event, gpointer data);
static void on_nb_passes_changed(GtkComboBox *combo, gpointer data);

/* Elapsed time counter and GLib timer source ID (mirrors Windows ClockTimer). */
static unsigned int elapsed_timer_count = 0;
static guint elapsed_timer_source = 0;

/* Forward declaration for combo registration helper */
static void combo_register_all(void);
/* Forward declaration for initial combo population */
static void populate_boot_combo(void);
/* Forward declaration for EnableControls (defined later in this file) */
void EnableControls(BOOL enable, BOOL remove_checkboxes);
/* Forward declaration for update_advanced_controls (defined later in this file) */
void update_advanced_controls(void);

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

/* Elapsed-time ticker — fired every 1000 ms while a format is in progress.
 * Mirrors the Windows ClockTimer callback. */
static gboolean clock_timer_cb(gpointer data)
{
	(void)data;
	elapsed_timer_count++;
	if (rw.elapsed_label) {
		char buf[16];
		snprintf(buf, sizeof(buf), "%02u:%02u:%02u",
		         elapsed_timer_count / 3600,
		         (elapsed_timer_count % 3600) / 60,
		         elapsed_timer_count % 60);
		gtk_label_set_text(GTK_LABEL(rw.elapsed_label), buf);
	}
	return G_SOURCE_CONTINUE;
}

static void start_clock_timer(void)
{
	elapsed_timer_count = 0;
	if (rw.elapsed_label)
		gtk_label_set_text(GTK_LABEL(rw.elapsed_label), "00:00:00");
	if (elapsed_timer_source == 0)
		elapsed_timer_source = g_timeout_add(1000, clock_timer_cb, NULL);
}

static void stop_clock_timer(void)
{
	if (elapsed_timer_source != 0) {
		g_source_remove(elapsed_timer_source);
		elapsed_timer_source = 0;
	}
	if (rw.elapsed_label)
		gtk_label_set_text(GTK_LABEL(rw.elapsed_label), "");
}

/* Blocking I/O timer — mirrors Windows BlockingTimer (3 s interval).
 * Detects when ISO extraction gets stuck after user requests cancel. */
static guint blocking_timer_source = 0;
static int64_t last_iso_blocking_status_val = -1;
static BOOL blocking_user_notified = FALSE;

static gboolean blocking_timer_cb(gpointer data)
{
	(void)data;
	extern int64_t iso_blocking_status;
	if (iso_blocking_status < 0) {
		blocking_timer_source = 0;
		blocking_user_notified = FALSE;
		uprintf("Killed blocking I/O timer\n");
		return G_SOURCE_REMOVE;
	}
	if (!blocking_user_notified) {
		if (last_iso_blocking_status_val == iso_blocking_status) {
			blocking_user_notified = TRUE;
			uprintf("Blocking I/O operation detected\n");
			Notification(MB_OK | MB_ICONINFORMATION,
			             lmprintf(MSG_048), lmprintf(MSG_080));
		} else {
			last_iso_blocking_status_val = iso_blocking_status;
		}
	}
	return G_SOURCE_CONTINUE;
}

static void start_blocking_timer(void)
{
	extern int64_t iso_blocking_status;
	if (iso_blocking_status < 0)
		return;
	last_iso_blocking_status_val = iso_blocking_status;
	blocking_user_notified = FALSE;
	if (blocking_timer_source == 0)
		blocking_timer_source = g_timeout_add(3000, blocking_timer_cb, NULL);
}


static void on_start_clicked(GtkButton *btn, gpointer data);
static void on_close_clicked(GtkButton *btn, gpointer data);
static void on_select_clicked(GtkButton *btn, gpointer data);
static void on_download_iso_clicked(GtkButton *btn, gpointer data);
static void on_lang_clicked(GtkButton *btn, gpointer data);
static void on_lang_menu_activate(GtkMenuItem *item, gpointer data);
static void on_device_changed(GtkComboBox *combo, gpointer data);
static void on_boot_changed(GtkComboBox *combo, gpointer data);
static void on_fs_changed(GtkComboBox *combo, gpointer data);
static void on_target_changed(GtkComboBox *combo, gpointer data);
static void on_partition_changed(GtkComboBox *combo, gpointer data);
static void on_image_option_changed(GtkComboBox *combo, gpointer data);
static void on_log_clicked(GtkButton *btn, gpointer data);
static void on_about_clicked(GtkButton *btn, gpointer data);
static void on_settings_clicked(GtkButton *btn, gpointer data);
static void on_toggle_dark_mode(GtkWidget *w, gpointer data);
static void SetProposedLabel(void);
void ToggleImageOptions(void);
static void on_toggle_expert_mode(GtkWidget *w, gpointer data);
static void on_toggle_joliet(GtkWidget *w, gpointer data);
static void on_toggle_rockridge(GtkWidget *w, gpointer data);
static void on_toggle_usb_hdd(GtkWidget *w, gpointer data);
static void on_list_usb_hdd_toggled(GtkToggleButton *btn, gpointer data);
static void on_uefi_validation_toggled(GtkToggleButton *btn, gpointer data);
static void on_adv_device_toggled(GtkExpander *exp, gpointer data);
static void on_adv_format_toggled(GtkExpander *exp, gpointer data);
static void on_old_bios_check_toggled(GtkToggleButton *btn, gpointer data);
static void on_extended_label_toggled(GtkToggleButton *btn, gpointer data);
/* New Alt+key shortcuts */
static void on_toggle_rufus_mbr(GtkWidget *w, gpointer data);
static void on_toggle_detect_fakes(GtkWidget *w, gpointer data);
static void on_toggle_dual_uefi_bios(GtkWidget *w, gpointer data);
static void on_toggle_vhds(GtkWidget *w, gpointer data);
static void on_toggle_extra_hashes(GtkWidget *w, gpointer data);
static void on_toggle_iso(GtkWidget *w, gpointer data);
static void on_toggle_large_fat32(GtkWidget *w, gpointer data);
static void on_toggle_boot_marker(GtkWidget *w, gpointer data);
static void on_toggle_ntfs_compression(GtkWidget *w, gpointer data);
static void on_toggle_size_check(GtkWidget *w, gpointer data);
static void on_toggle_preserve_ts(GtkWidget *w, gpointer data);
static void on_toggle_proper_units(GtkWidget *w, gpointer data);
static void on_toggle_vmdk(GtkWidget *w, gpointer data);
static void on_toggle_force_update(GtkWidget *w, gpointer data);
static void on_toggle_force_update_strict(GtkWidget *w, gpointer data);
static void on_toggle_usb_debug(GtkWidget *w, gpointer data);
static void on_toggle_lock_drive(GtkWidget *w, gpointer data);
static void on_toggle_file_indexing(GtkWidget *w, gpointer data);
static void on_toggle_non_usb_removable(GtkWidget *w, gpointer data);
static void on_toggle_esp(GtkWidget *w, gpointer data);
static void on_delete_app_data_dir(GtkWidget *w, gpointer data);
static void on_delete_settings(GtkWidget *w, gpointer data);
static void on_zero_drive(GtkWidget *w, gpointer data);
static void on_fast_zero_drive(GtkWidget *w, gpointer data);
static void on_cycle_port(GtkWidget *w, gpointer data);
static void on_hash_clicked(GtkButton *btn, gpointer data);
void InitProgress(BOOL bOnlyFormat);
static void on_save_clicked(GtkButton *btn, gpointer data);
static void on_drag_data_received(GtkWidget *w, GdkDragContext *ctx,
                                  gint x, gint y, GtkSelectionData *sel,
                                  guint info, guint t, gpointer data);
static void on_persistence_changed(GtkWidget *w, gpointer data);
static void on_multi_write_clicked(GtkButton *btn, gpointer data);
void SetPersistenceSize(void);   /* defined later in this file */
extern DWORD WINAPI HashThread(void *param);  /* hash.c */
void ShowLanguageMenu(RECT rcExclude);
extern DWORD WINAPI ImageScanThread(LPVOID param); /* image_scan.c */
extern void SetFidoCheck(void);                    /* net.c */
extern BOOL DownloadISO(void);                     /* net.c */
void init_rufus_version(void);                     /* rufus.c */
static GtkWidget *build_toolbar(void);
static GtkWidget *build_device_row(void);
static void on_device_combo_right_click(GtkWidget *widget, GdkEventButton *event, gpointer data);
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
	if (rw.status_label) {
		status_history_push(msg);
		gtk_label_set_text(GTK_LABEL(rw.status_label), msg);
		/* Update tooltip with history of previous messages */
		char tooltip[STATUS_HISTORY_SIZE * 260];
		status_history_tooltip(tooltip, sizeof(tooltip));
		gtk_widget_set_tooltip_text(rw.status_label,
		                            tooltip[0] ? tooltip : NULL);
	}
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

	rw.lang_btn       = gtk_button_new_with_label("🌐");
	rw.about_btn      = gtk_button_new_with_label("ℹ");
	rw.settings_btn   = gtk_button_new_with_label("⚙");
	rw.log_btn        = gtk_button_new_with_label("📋");
	rw.save_btn       = gtk_button_new_with_label("💾");
	rw.hash_btn       = gtk_button_new_with_label("#");
	rw.multi_write_btn = gtk_button_new_with_label("⊕");

	gtk_widget_set_tooltip_text(rw.lang_btn,        "Language");
	gtk_widget_set_tooltip_text(rw.about_btn,        "About");
	gtk_widget_set_tooltip_text(rw.settings_btn,     "Settings");
	gtk_widget_set_tooltip_text(rw.log_btn,          "Log");
	gtk_widget_set_tooltip_text(rw.save_btn,         "Save");
	gtk_widget_set_tooltip_text(rw.hash_btn,         "Hash");
	gtk_widget_set_tooltip_text(rw.multi_write_btn,  "Write to multiple devices");

	g_signal_connect(rw.log_btn,          "clicked", G_CALLBACK(on_log_clicked),         NULL);
	g_signal_connect(rw.about_btn,        "clicked", G_CALLBACK(on_about_clicked),        NULL);
	g_signal_connect(rw.lang_btn,         "clicked", G_CALLBACK(on_lang_clicked),         NULL);
	g_signal_connect(rw.hash_btn,         "clicked", G_CALLBACK(on_hash_clicked),         NULL);
	g_signal_connect(rw.save_btn,         "clicked", G_CALLBACK(on_save_clicked),         NULL);
	g_signal_connect(rw.multi_write_btn,  "clicked", G_CALLBACK(on_multi_write_clicked),  NULL);
	g_signal_connect(rw.settings_btn,     "clicked", G_CALLBACK(on_settings_clicked),     NULL);

	gtk_box_pack_start(GTK_BOX(bar), rw.lang_btn,        FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.about_btn,       FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.settings_btn,    FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.log_btn,         FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.save_btn,        FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.hash_btn,        FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(bar), rw.multi_write_btn, FALSE, FALSE, 0);

	return bar;
}

/* ---- Device combo right-click context menu ---- */

/* Callback: "Refresh" menu item — rescan devices. */
static void on_device_ctx_refresh(GtkMenuItem *item, gpointer data)
{
	(void)item; (void)data;
	if (!op_in_progress)
		GetDevices((DWORD)ComboBox_GetCurItemData(hDeviceList));
}

/* Callback: "Open in File Manager" menu item — xdg-open the device path. */
static void on_device_ctx_open_fm(GtkMenuItem *item, gpointer data)
{
	(void)item; (void)data;

	int sel = ComboBox_GetCurSel(hDeviceList);
	if (sel < 0)
		return;

	DWORD di = (DWORD)ComboBox_GetItemData(hDeviceList, sel);
	char *dev_path = GetPhysicalName(di);
	if (!dev_path)
		return;

	char cmd[512];
	if (device_open_in_fm_build_cmd(dev_path, cmd, sizeof(cmd))) {
		uprintf("Opening device in file manager: %s", cmd);
		if (system(cmd) != 0)
			uprintf("xdg-open returned non-zero for %s", dev_path);
	}
	free(dev_path);
}

/* Signal handler for button-press-event on the device combo.
 * Shows a popup context menu on right-click (button 3). */
static void on_device_combo_right_click(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	(void)widget; (void)data;

	if (event->type != GDK_BUTTON_PRESS || event->button != 3)
		return;

	GtkWidget *menu      = gtk_menu_new();
	GtkWidget *refresh   = gtk_menu_item_new_with_label("🔄 Refresh");
	GtkWidget *open_fm   = gtk_menu_item_new_with_label("📂 Open in File Manager");

	gtk_menu_shell_append(GTK_MENU_SHELL(menu), refresh);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), open_fm);

	g_signal_connect(refresh, "activate", G_CALLBACK(on_device_ctx_refresh), NULL);
	g_signal_connect(open_fm, "activate", G_CALLBACK(on_device_ctx_open_fm),  NULL);

	gtk_widget_show_all(menu);
	gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent *)event);
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

	g_signal_connect(rw.device_combo, "changed",            G_CALLBACK(on_device_changed),          NULL);
	g_signal_connect(rw.device_combo, "button-press-event", G_CALLBACK(on_device_combo_right_click), NULL);

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

	rw.download_iso_btn = gtk_button_new_with_label("⬇ Download ISO");
	gtk_widget_set_tooltip_text(rw.download_iso_btn,
		"Download an ISO image using the Fido script");
	g_signal_connect(rw.download_iso_btn, "clicked",
		G_CALLBACK(on_download_iso_clicked), NULL);
	gtk_widget_set_visible(rw.download_iso_btn, FALSE);

	gtk_box_pack_start(GTK_BOX(hbox), rw.boot_selection_label, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.boot_combo,           TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.select_btn,           FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), rw.download_iso_btn,     FALSE, FALSE, 0);

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

	g_signal_connect(rw.image_option_combo, "changed",
	                 G_CALLBACK(on_image_option_changed), NULL);
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
	g_signal_connect(rw.partition_combo, "changed", G_CALLBACK(on_partition_changed), NULL);
	rw.target_system_label = gtk_label_new("Target system");
	rw.target_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.target_combo, TRUE);
	g_signal_connect(rw.target_combo, "changed", G_CALLBACK(on_target_changed), NULL);

	/* CSM help indicator: "ⓘ" label with tooltip showing MSG_151/MSG_152.
	 * Starts hidden; on_target_changed() will show/hide it as needed. */
	rw.csm_help_label = gtk_label_new(NULL);
	gtk_label_set_markup(GTK_LABEL(rw.csm_help_label),
	    "<span color=\"#4a90d9\" underline=\"single\">ⓘ</span>");
	gtk_widget_set_no_show_all(rw.csm_help_label, TRUE);

	gtk_box_pack_start(GTK_BOX(row1), rw.partition_type_label, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(row1), rw.partition_combo,      TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(row1), rw.target_system_label,  FALSE, FALSE, 8);
	gtk_box_pack_start(GTK_BOX(row1), rw.target_combo,         TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(row1), rw.csm_help_label,       FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(vbox), row1, FALSE, FALSE, 0);

	/* Row: File system + Cluster size */
	GtkWidget *row2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
	rw.filesystem_label = gtk_label_new("File system");
	rw.filesystem_combo = gtk_combo_box_text_new();
	gtk_widget_set_hexpand(rw.filesystem_combo, TRUE);
	g_signal_connect(rw.filesystem_combo, "changed", G_CALLBACK(on_fs_changed), NULL);
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
	g_signal_connect(rw.list_usb_hdd_check,    "toggled",
		G_CALLBACK(on_list_usb_hdd_toggled), NULL);
	g_signal_connect(rw.uefi_validation_check, "toggled",
		G_CALLBACK(on_uefi_validation_toggled), NULL);
	gtk_box_pack_start(GTK_BOX(adv_box), rw.list_usb_hdd_check,    FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(adv_box), rw.uefi_validation_check, FALSE, FALSE, 0);
	gtk_container_add(GTK_CONTAINER(rw.adv_device_expander), adv_box);
	gtk_box_pack_start(GTK_BOX(vbox), rw.adv_device_expander, FALSE, FALSE, 2);
	g_signal_connect(rw.adv_device_expander, "activate",
	                 G_CALLBACK(on_adv_device_toggled), NULL);

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
	g_signal_connect(rw.nb_passes_combo, "changed",
		G_CALLBACK(on_nb_passes_changed), NULL);
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
	g_signal_connect(rw.old_bios_check, "toggled",
		G_CALLBACK(on_old_bios_check_toggled), NULL);
	rw.extended_label_check = gtk_check_button_new_with_label("Create extended label and icon files");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.extended_label_check), TRUE);
	gtk_box_pack_start(GTK_BOX(adv_box), rw.extended_label_check, FALSE, FALSE, 0);
	g_signal_connect(rw.extended_label_check, "toggled",
		G_CALLBACK(on_extended_label_toggled), NULL);
	rw.verify_write_check = gtk_check_button_new_with_label("Verify write (re-read and compare after write)");
	gtk_box_pack_start(GTK_BOX(adv_box), rw.verify_write_check, FALSE, FALSE, 0);
	gtk_container_add(GTK_CONTAINER(rw.adv_format_expander), adv_box);
	gtk_box_pack_start(GTK_BOX(vbox), rw.adv_format_expander, FALSE, FALSE, 2);
	/* When format options are toggled, refresh the FS combo (mirrors Windows IDC_ADVANCED_FORMAT_OPTIONS) */
	g_signal_connect(rw.adv_format_expander, "activate",
	                 G_CALLBACK(on_adv_format_toggled), NULL);

	return vbox;
}

/* ---- Persistence row ---- */
static GtkWidget *build_persistence_row(void)
{
	GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

	GtkWidget *lbl = gtk_label_new("Persistent partition size");

	rw.persistence_size  = gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(rw.persistence_size), 7);
	gtk_entry_set_width_chars(GTK_ENTRY(rw.persistence_size), 7);
	gtk_entry_set_text(GTK_ENTRY(rw.persistence_size), "0");
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

	g_signal_connect(rw.persistence_scale, "value-changed",
	                 G_CALLBACK(on_persistence_changed), NULL);
	g_signal_connect(rw.persistence_units, "changed",
	                 G_CALLBACK(on_persistence_changed), NULL);
	g_signal_connect(rw.persistence_size, "changed",
	                 G_CALLBACK(on_persistence_size_entry_changed), NULL);
	g_signal_connect(rw.persistence_size, "focus-out-event",
	                 G_CALLBACK(on_persistence_size_entry_focus_out), NULL);

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

	/* Status row: left-aligned message + right-aligned elapsed time */
	GtkWidget *status_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
	rw.status_label = gtk_label_new("Ready");
	gtk_widget_set_halign(rw.status_label, GTK_ALIGN_START);
	gtk_label_set_ellipsize(GTK_LABEL(rw.status_label), PANGO_ELLIPSIZE_END);
	gtk_widget_set_hexpand(rw.status_label, TRUE);

	rw.elapsed_label = gtk_label_new("");
	gtk_widget_set_halign(rw.elapsed_label, GTK_ALIGN_END);

	gtk_box_pack_start(GTK_BOX(status_row), rw.status_label,  TRUE,  TRUE,  0);
	gtk_box_pack_start(GTK_BOX(status_row), rw.elapsed_label, FALSE, FALSE, 4);

	gtk_box_pack_start(GTK_BOX(vbox), rw.progress_bar,  FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), status_row,        FALSE, FALSE, 0);

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
	{
		extern uint16_t rufus_version[3];
		char title[32];
		snprintf(title, sizeof(title), "Rufus %d.%d",
		         rufus_version[0], rufus_version[1]);
		gtk_window_set_title(GTK_WINDOW(win), title);
	}
	gtk_window_set_resizable(GTK_WINDOW(win), FALSE);
	gtk_window_set_icon_name(GTK_WINDOW(win), "ie.akeo.rufus");
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

	/* Image info expander — hidden until an image is scanned */
	rw.img_info_label    = gtk_label_new("");
	gtk_widget_set_halign(rw.img_info_label, GTK_ALIGN_START);
	gtk_label_set_selectable(GTK_LABEL(rw.img_info_label), TRUE);
	gtk_label_set_line_wrap(GTK_LABEL(rw.img_info_label), TRUE);
	rw.img_info_expander = gtk_expander_new("Image info");
	gtk_container_add(GTK_CONTAINER(rw.img_info_expander), rw.img_info_label);
	gtk_box_pack_start(GTK_BOX(vbox), rw.img_info_expander, FALSE, FALSE, 2);

	gtk_box_pack_start(GTK_BOX(vbox), build_status_section(),   FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), build_action_buttons(),   FALSE, FALSE, 4);

	/* Build log dialog (hidden by default) */
	rw.log_dialog = build_log_dialog(win);

	/* Register keyboard shortcuts */
	GtkAccelGroup *accel = gtk_accel_group_new();
	gtk_window_add_accel_group(GTK_WINDOW(win), accel);
	/* Ctrl+O: open/select image */
	gtk_widget_add_accelerator(rw.select_btn, "clicked", accel,
	                           GDK_KEY_o, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
	/* Escape: cancel or quit */
	gtk_widget_add_accelerator(rw.close_btn, "clicked", accel,
	                           GDK_KEY_Escape, 0, GTK_ACCEL_VISIBLE);
	/* Ctrl+Alt+D: toggle dark mode */
	gtk_accel_group_connect(accel, GDK_KEY_d,
	                        GDK_CONTROL_MASK | GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_dark_mode), NULL, NULL));
	/* Ctrl+Alt+E: toggle expert mode */
	gtk_accel_group_connect(accel, GDK_KEY_e,
	                        GDK_CONTROL_MASK | GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_expert_mode), NULL, NULL));
	/* Alt+J: toggle Joliet (ISO) support */
	gtk_accel_group_connect(accel, GDK_KEY_j,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_joliet), NULL, NULL));
	/* Alt+K: toggle Rock Ridge (ISO) support */
	gtk_accel_group_connect(accel, GDK_KEY_k,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_rockridge), NULL, NULL));
	/* Alt+F: toggle USB HDD detection */
	gtk_accel_group_connect(accel, GDK_KEY_f,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_usb_hdd), NULL, NULL));
	/* Alt+A: toggle Rufus MBR */
	gtk_accel_group_connect(accel, GDK_KEY_a,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_rufus_mbr), NULL, NULL));
	/* Alt+B: toggle fake drive detection */
	gtk_accel_group_connect(accel, GDK_KEY_b,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_detect_fakes), NULL, NULL));
	/* Alt+C: cycle (reset) USB port for currently selected device */
	gtk_accel_group_connect(accel, GDK_KEY_c,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_cycle_port), NULL, NULL));
	/* Alt+E: toggle dual UEFI/BIOS mode */
	gtk_accel_group_connect(accel, GDK_KEY_e,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_dual_uefi_bios), NULL, NULL));
	/* Alt+G: toggle VHD/virtual disk detection */
	gtk_accel_group_connect(accel, GDK_KEY_g,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_vhds), NULL, NULL));
	/* Alt+H: toggle extra hash (SHA-512) computation */
	gtk_accel_group_connect(accel, GDK_KEY_h,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_extra_hashes), NULL, NULL));
	/* Alt+I: toggle ISO support (force DD mode when disabled) */
	gtk_accel_group_connect(accel, GDK_KEY_i,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_iso), NULL, NULL));
	/* Alt+O: save optical disc to ISO image (mirrors Windows Alt+O → OpticalDiscSaveImage) */
	gtk_accel_group_connect(accel, GDK_KEY_o,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_save_clicked), NULL, NULL));
	/* Alt+L: force large FAT32 format */
	gtk_accel_group_connect(accel, GDK_KEY_l,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_large_fat32), NULL, NULL));
	/* Alt+M: toggle boot marker check */
	gtk_accel_group_connect(accel, GDK_KEY_m,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_boot_marker), NULL, NULL));
	/* Alt+N: toggle NTFS compression */
	gtk_accel_group_connect(accel, GDK_KEY_n,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_ntfs_compression), NULL, NULL));
	/* Alt+S: toggle ISO-vs-disk size check */
	gtk_accel_group_connect(accel, GDK_KEY_s,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_size_check), NULL, NULL));
	/* Alt+T: preserve timestamps */
	gtk_accel_group_connect(accel, GDK_KEY_t,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_preserve_ts), NULL, NULL));
	/* Alt+U: use proper (binary) size units */
	gtk_accel_group_connect(accel, GDK_KEY_u,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_proper_units), NULL, NULL));
	/* Alt+W: toggle VMware/VMDK disk detection */
	gtk_accel_group_connect(accel, GDK_KEY_w,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_vmdk), NULL, NULL));
	/* Alt+Y: force update check */
	gtk_accel_group_connect(accel, GDK_KEY_y,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_force_update), NULL, NULL));
	/* Alt+Z: zero the drive */
	gtk_accel_group_connect(accel, GDK_KEY_z,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_zero_drive), NULL, NULL));
	/* Alt+. (period): toggle USB enumeration debug */
	gtk_accel_group_connect(accel, GDK_KEY_period,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_usb_debug), NULL, NULL));
	/* Alt+, (comma): toggle physical drive locking */
	gtk_accel_group_connect(accel, GDK_KEY_comma,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_lock_drive), NULL, NULL));
	/* Alt+D: delete app data files directory */
	gtk_accel_group_connect(accel, GDK_KEY_d,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_delete_app_data_dir), NULL, NULL));
	/* Alt+Q: toggle file indexing */
	gtk_accel_group_connect(accel, GDK_KEY_q,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_file_indexing), NULL, NULL));
	/* Alt+P: toggle GPT ESP ↔ MS Basic Data for currently selected device */
	gtk_accel_group_connect(accel, GDK_KEY_p,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_esp), NULL, NULL));
	/* Alt+R: delete the Rufus settings file (mirrors Windows Alt+R registry delete) */
	gtk_accel_group_connect(accel, GDK_KEY_r,
	                        GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_delete_settings), NULL, NULL));
	/* Ctrl+Alt+F: toggle listing of non-USB removable drives */
	gtk_accel_group_connect(accel, GDK_KEY_f,
	                        GDK_CONTROL_MASK | GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_non_usb_removable), NULL, NULL));
	/* Ctrl+Alt+Y: force update check (strict - ignores timestamp errors) */
	gtk_accel_group_connect(accel, GDK_KEY_y,
	                        GDK_CONTROL_MASK | GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_toggle_force_update_strict), NULL, NULL));
	/* Ctrl+Alt+Z: zero the drive with fast-zeroing (skip empty blocks) */
	gtk_accel_group_connect(accel, GDK_KEY_z,
	                        GDK_CONTROL_MASK | GDK_MOD1_MASK, GTK_ACCEL_VISIBLE,
	                        g_cclosure_new(G_CALLBACK(on_fast_zero_drive), NULL, NULL));

	/* Enable drag-and-drop of image files onto the window (mirrors WM_DROPFILES) */
	gtk_drag_dest_set(win, GTK_DEST_DEFAULT_ALL, NULL, 0, GDK_ACTION_COPY);
	gtk_drag_dest_add_uri_targets(win);
	g_signal_connect(win, "drag-data-received",
	                 G_CALLBACK(on_drag_data_received), NULL);

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
		rufus_gtk_update_status(lmprintf(MSG_201));
		/* Start a blocking I/O detector if we're in the middle of ISO extraction,
		 * mirroring Windows BlockingTimer. */
		start_blocking_timer();
	} else {
		device_monitor_stop();
		rufus_set_log_handler(NULL);
		gtk_main_quit();
	}
}

static void on_start_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	extern RUFUS_DRIVE_INFO SelectedDrive;
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
	quick_format     = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rw.quick_format_check));
	zero_drive       = FALSE;  /* set to TRUE by Alt+Z / Ctrl+Alt+Z keyboard shortcut */
	write_as_image   = FALSE;  /* may be set below by ISOHybrid logic */
	write_as_esp     = FALSE;
	enable_bad_blocks = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rw.bad_blocks_check));
	nb_passes_sel     = gtk_combo_box_get_active(GTK_COMBO_BOX(rw.nb_passes_combo));
	if (nb_passes_sel < 0) nb_passes_sel = 0;
	enable_verify_write = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rw.verify_write_check));

	uprintf("Format started by user (drive=%u, fs=%d, part=%d, target=%d, boot=%d, quick=%d, bad_blocks=%d, passes_sel=%d)",
	        di, fs_type, partition_type, target_type, boot_type, quick_format,
	        enable_bad_blocks, nb_passes_sel);

	/* Enforce image size check (Alt+S disables this) */
	if (boot_type == BT_IMAGE) {
		if (size_check && img_report.projected_size > (uint64_t)SelectedDrive.DiskSize) {
			Notification(MB_OK | MB_ICONERROR, lmprintf(MSG_088), lmprintf(MSG_089));
			return;
		}
	}

	/* Show "WARNING: ALL DATA ON DEVICE WILL BE DESTROYED" confirmation */
	/* Mirror Windows UM_FORMAT_START pre-format checks */
	{
		/* MBR on > 2 TB disk */
		if (partition_type == PARTITION_STYLE_MBR
		    && (uint64_t)SelectedDrive.DiskSize > 2ULL * TB
		    && Notification(MB_YESNO | MB_ICONWARNING,
		                    lmprintf(MSG_128, "MBR"),
		                    lmprintf(MSG_134,
		                             SizeToHumanReadable(
		                                 (uint64_t)SelectedDrive.DiskSize - 2ULL * TB,
		                                 FALSE, FALSE))) != IDYES)
			return;
		/* UDF formatting can take a very long time — warn the user */
		if (!zero_drive && fs_type == FS_UDF) {
			uint32_t dur_secs = (uint32_t)(((double)SelectedDrive.DiskSize)
			                               / 1073741824.0f / UDF_FORMAT_SPEED);
			if (dur_secs > UDF_FORMAT_WARN) {
				uint32_t dur_mins = dur_secs / 60;
				dur_secs -= dur_mins * 60;
				Notification(MB_OK | MB_ICONINFORMATION,
				             lmprintf(MSG_113),
				             lmprintf(MSG_112, dur_mins, dur_secs));
			}
		}
		/* GetProcessSearch is Windows-only; on Linux skip straight to confirm */
		PrintStatus(0, MSG_142);
		char dev_name[256] = "the selected device";
		SendMessageA(hDeviceList, CB_GETLBTEXT, (WPARAM)sel, (LPARAM)dev_name);
		if (Notification(MB_OKCANCEL | MB_ICONWARNING, APPLICATION_NAME,
		                 lmprintf(MSG_003, dev_name)) != IDOK)
			return;
		/* Multiple partition warning — mirrors Windows UM_FORMAT_START */
		if (SelectedDrive.nPartitions > 1
		    && Notification(MB_OKCANCEL | MB_ICONWARNING, lmprintf(MSG_094),
		                    lmprintf(MSG_093)) != IDOK)
			return;
		/* Non-512-byte sector warning */
		if (!zero_drive && boot_type != BT_NON_BOOTABLE
		    && SelectedDrive.SectorSize != 512
		    && Notification(MB_OKCANCEL | MB_ICONWARNING, lmprintf(MSG_197),
		                    lmprintf(MSG_196, SelectedDrive.SectorSize)) != IDOK)
			return;
	}

	/* Warn if any UEFI bootloader in the image has been revoked */
	if (boot_type == BT_IMAGE && (img_report.has_secureboot_bootloader & 0xfe)) {
		const char *msg;
		/* MSG_341 is for the Windows SSP (0xc0000428) case (bit 2 = 1<<2 = 4) */
		if ((img_report.has_secureboot_bootloader & 0xfe) == 4)
			msg = lmprintf(MSG_341, "Error code: 0xc0000428");
		else
			msg = lmprintf(MSG_340);
		if (Notification(MB_OKCANCEL | MB_ICONWARNING,
		                 lmprintf(MSG_338), lmprintf(MSG_339, msg)) != IDOK)
			return;
	}

	/* Windows User Experience dialog — show before formatting a Windows 10/11 image.
	 * WinToGo path has different options from the standard installer path. */
	if (boot_type == BT_IMAGE && IS_WINDOWS_1X(img_report)) {
		BOOL is_windows_to_go = (image_options & IMOP_WINTOGO)
		    && (hImageOption != NULL)
		    && (ComboBox_GetCurItemData(hImageOption) == IMOP_WIN_TO_GO);

		if (is_windows_to_go) {
			/* WinToGo requires NTFS */
			if (fs_type != FS_NTFS) {
				Notification(MB_OK | MB_ICONERROR,
				             lmprintf(MSG_092), lmprintf(MSG_097, "Windows To Go"));
				return;
			}
			/* Let the user pick the Windows edition (shows dialog if multiple) */
			switch (SetWinToGoIndex()) {
			case -1:
				Notification(MB_OK | MB_ICONERROR,
				             lmprintf(MSG_291), lmprintf(MSG_073));
				/* fall through */
			case -2:
				return;
			default:
				break;
			}
			/* WinToGo WUE dialog */
			if (!img_report.has_panther_unattend) {
				StrArray options;
				int arch = _log2(img_report.has_efi >> 1);
				uint16_t map[16] = { 0 }, b = 1;
				int username_index = -1;
				StrArrayCreate(&options, 8);
				StrArrayAdd(&options, lmprintf(MSG_332), TRUE);
				MAP_BIT(UNATTEND_OFFLINE_INTERNAL_DRIVES);
				if (img_report.win_version.build >= 22500) {
					StrArrayAdd(&options, lmprintf(MSG_330), TRUE);
					MAP_BIT(UNATTEND_NO_ONLINE_ACCOUNT);
				}
				StrArrayAdd(&options, lmprintf(MSG_333), TRUE);
				username_index = _log2(b);
				MAP_BIT(UNATTEND_SET_USER);
				StrArrayAdd(&options, lmprintf(MSG_334), TRUE);
				MAP_BIT(UNATTEND_DUPLICATE_LOCALE);
				StrArrayAdd(&options, lmprintf(MSG_331), TRUE);
				MAP_BIT(UNATTEND_NO_DATA_COLLECTION);
				if (expert_mode) {
					StrArrayAdd(&options, lmprintf(MSG_346), TRUE);
					MAP_BIT(UNATTEND_FORCE_S_MODE);
				}
				int i = CustomSelectionDialog(BS_AUTOCHECKBOX,
				        lmprintf(MSG_327), lmprintf(MSG_328),
				        options.String, options.Index,
				        remap16(unattend_xml_mask, map, FALSE),
				        username_index);
				StrArrayDestroy(&options);
				if (i < 0)
					return;
				i = remap16((uint16_t)i, map, TRUE);
				free(unattend_xml_path);
				unattend_xml_path = CreateUnattendXml(arch,
				                        i | UNATTEND_WINDOWS_TO_GO);
				unattend_xml_mask &= ~((int)remap16(0x1ff, map, TRUE));
				unattend_xml_mask |= i;
				WriteSetting32(SETTING_WUE_OPTIONS,
				               (UNATTEND_DEFAULT_MASK << 16) | unattend_xml_mask);
			}
		} else if (img_report.has_panther_unattend) {
			uprintf("NOTICE: A '/sources/$OEM$/$$/Panther/unattend.xml' was detected. "
			        "The Windows User Experience dialog will not be displayed.");
		} else {
			StrArray options;
			int arch = _log2(img_report.has_efi >> 1);
			uint16_t map[16] = { 0 }, b = 1;
			int username_index = -1;
			StrArrayCreate(&options, 10);
			if (IS_WINDOWS_11(img_report)) {
				StrArrayAdd(&options, lmprintf(MSG_329), TRUE);
				MAP_BIT(UNATTEND_SECUREBOOT_TPM_MINRAM);
			}
			if (img_report.win_version.build >= 22500) {
				StrArrayAdd(&options, lmprintf(MSG_330), TRUE);
				MAP_BIT(UNATTEND_NO_ONLINE_ACCOUNT);
			}
			StrArrayAdd(&options, lmprintf(MSG_333), TRUE);
			username_index = _log2(b);
			MAP_BIT(UNATTEND_SET_USER);
			StrArrayAdd(&options, lmprintf(MSG_334), TRUE);
			MAP_BIT(UNATTEND_DUPLICATE_LOCALE);
			StrArrayAdd(&options, lmprintf(MSG_331), TRUE);
			MAP_BIT(UNATTEND_NO_DATA_COLLECTION);
			StrArrayAdd(&options, lmprintf(MSG_335), TRUE);
			MAP_BIT(UNATTEND_DISABLE_BITLOCKER);
			if (img_report.win_version.build >= 26200) {
				StrArrayAdd(&options, lmprintf(MSG_350), TRUE);
				MAP_BIT(UNATTEND_USE_MS2023_BOOTLOADERS);
			}
			if (expert_mode) {
				StrArrayAdd(&options, lmprintf(MSG_346), TRUE);
				MAP_BIT(UNATTEND_FORCE_S_MODE);
			}

			int i = CustomSelectionDialog(BS_AUTOCHECKBOX, lmprintf(MSG_327), lmprintf(MSG_328),
			        options.String, options.Index, remap16(unattend_xml_mask, map, FALSE),
			        username_index);
			StrArrayDestroy(&options);
			if (i < 0) {
				/* User cancelled the WUE dialog — abort the format */
				return;
			}
			i = remap16((uint16_t)i, map, TRUE);
			free(unattend_xml_path);
			unattend_xml_path = (i != 0) ? CreateUnattendXml(arch, i) : NULL;
			/* Remember the user preferences for this session */
			unattend_xml_mask &= ~((int)remap16(UNATTEND_FULL_MASK, map, TRUE));
			unattend_xml_mask |= i;
			WriteSetting32(SETTING_WUE_OPTIONS,
			               (UNATTEND_DEFAULT_MASK << 16) | unattend_xml_mask);
		}
	}

	if (boot_type == BT_IMAGE) {
		/* Compatibility checks — mirror Windows BootCheckThread */
		if (boot_check_uefi_compat_fails(img_report, target_type)) {
			Notification(MB_OK | MB_ICONERROR, lmprintf(MSG_090), lmprintf(MSG_091));
			goto abort_format;
		}
		if (boot_check_fat_4gb_fails(img_report, fs_type)) {
			Notification(MB_OK | MB_ICONERROR, lmprintf(MSG_099), lmprintf(MSG_100));
			goto abort_format;
		}
		if (boot_check_fat16_kolibrios_fails(img_report, fs_type)) {
			Notification(MB_OK | MB_ICONERROR, lmprintf(MSG_099), lmprintf(MSG_189));
			goto abort_format;
		}
		if (boot_check_fat_compat_fails(img_report, fs_type, target_type,
		                                allow_dual_uefi_bios)) {
			Notification(MB_OK | MB_ICONERROR, lmprintf(MSG_092), lmprintf(MSG_096));
			goto abort_format;
		}

		/* ISOHybrid / DD-mode selection */
		if (IS_DD_BOOTABLE(img_report)) {
			BOOL esp_asked = FALSE;
			if (!img_report.is_iso) {
				/* Pure DD image (raw USB dump etc.) — write as DD, no dialog */
				write_as_image = TRUE;
			} else if (persistence_size == 0) {
				/* ISOHybrid: ask ISO vs DD; offer ISO→ESP when applicable */
				char *iso_image = lmprintf(MSG_036);
				char *dd_image  = lmprintf(MSG_095);
				int isoh_choice;
				if (boot_check_can_write_as_esp(img_report, partition_type, fs_type)) {
					StrArray choices;
					StrArrayCreate(&choices, 3);
					StrArrayAdd(&choices, lmprintf(MSG_276, iso_image), TRUE);
					StrArrayAdd(&choices, lmprintf(MSG_277, "ISO \xe2\x86\x92 ESP"), TRUE);
					StrArrayAdd(&choices, lmprintf(MSG_277, dd_image), TRUE);
					isoh_choice = SelectionDialog(
						lmprintf(MSG_274, "ISOHybrid"),
						lmprintf(MSG_275, iso_image, dd_image, iso_image, dd_image),
						choices.String, (int)choices.Index);
					StrArrayDestroy(&choices);
					if (isoh_choice < 0)
						goto abort_format;
					write_as_esp   = (isoh_choice & 2) ? TRUE : FALSE;
					write_as_image = (isoh_choice & 4) ? TRUE : FALSE;
					esp_asked = TRUE;
				} else {
					StrArray choices;
					StrArrayCreate(&choices, 2);
					StrArrayAdd(&choices, lmprintf(MSG_276, iso_image), TRUE);
					StrArrayAdd(&choices, lmprintf(MSG_277, dd_image),  TRUE);
					isoh_choice = SelectionDialog(
						lmprintf(MSG_274, "ISOHybrid"),
						lmprintf(MSG_275, iso_image, dd_image, iso_image, dd_image),
						choices.String, (int)choices.Index);
					StrArrayDestroy(&choices);
					if (isoh_choice < 0)
						goto abort_format;
					write_as_image = (isoh_choice & 2) ? TRUE : FALSE;
				}
			}
			if (write_as_image) {
				/* DD write — skip further ISO→ESP check */
				goto start_format;
			}
			/* Offer standalone ISO→ESP when ESP dialog wasn't already shown */
			if (!esp_asked && boot_check_can_write_as_esp(img_report,
			                                              partition_type, fs_type)) {
				char *iso_image = lmprintf(MSG_036);
				char *choices[2] = { lmprintf(MSG_276, iso_image),
				                     lmprintf(MSG_277, "ISO \xe2\x86\x92 ESP") };
				int r = SelectionDialog(lmprintf(MSG_274, "ESP"),
				                        lmprintf(MSG_310), choices, 2);
				if (r < 0)
					goto abort_format;
				write_as_esp = (r & 2) ? TRUE : FALSE;
			}
		}
	}

start_format:
	/* MS-DOS: cannot boot from 64 KiB cluster size */
	if (boot_type == BT_MSDOS) {
		if (size_check && (ComboBox_GetCurItemData(hClusterSize) >= 65536)) {
			Notification(MB_OK | MB_ICONERROR, lmprintf(MSG_111), lmprintf(MSG_110));
			goto abort_format;
		}
	}
	/* UEFI:NTFS requires NTFS or exFAT */
	if (boot_type == BT_UEFI_NTFS) {
		fs_type = (int)ComboBox_GetCurItemData(hFileSystem);
		if (fs_type != FS_NTFS && fs_type != FS_EXFAT) {
			Notification(MB_OK | MB_ICONERROR, lmprintf(MSG_092), lmprintf(MSG_097, "UEFI:NTFS"));
			goto abort_format;
		}
	}
	if (format_thread == NULL) {
		op_in_progress = TRUE;
		ErrorStatus = 0;
		EnableControls(FALSE, FALSE);
		InitProgress(zero_drive || write_as_image);
		format_thread = CreateThread(NULL, 0, FormatThread, (void*)(uintptr_t)di, 0, NULL);
		if (format_thread == NULL) {
			op_in_progress = FALSE;
			rufus_gtk_update_status(lmprintf(MSG_212));
			EnableControls(TRUE, FALSE);
		}
	}
	return;

abort_format:
	/* User cancelled or validation failed — mirrors Windows aborted_start path */
	zero_drive = FALSE;
	if (unattend_xml_path != NULL) {
		unlink(unattend_xml_path);
		safe_free(unattend_xml_path);
	}
	{
		int nb_devices = ComboBox_GetCount(hDeviceList);
		rufus_gtk_update_status(lmprintf(
		    (nb_devices == 1) ? MSG_208 : MSG_209, nb_devices));
	}
}
static void on_select_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	extern BOOL has_ffu_support;

	/* Ctrl+click: select a supplemental ZIP archive (mirrors Windows Ctrl+SELECT) */
	GdkEvent *ev = gtk_get_current_event();
	if (ev) {
		guint mods = 0;
		gdk_event_get_state(ev, (GdkModifierType *)&mods);
		gdk_event_free(ev);
		if (mods & GDK_CONTROL_MASK) {
			EXT_DECL(arch_ext, NULL, __VA_GROUP__("*.zip"),
			         __VA_GROUP__(lmprintf(MSG_309)));
			char *p = FileDialog(FALSE, NULL, &arch_ext, NULL);
			if (p != NULL) {
				safe_free(archive_path);
				archive_path = p;
				uprintf("Using archive: %s", archive_path);
			}
			return;
		}
	}

	/* Build the extension string, matching Windows rufus.c */
	char extensions[160] = "*.iso;*.img;*.vhd;*.vhdx;*.usb;*.bz2;*.bzip2;*.gz;*.lzma;*.xz;*.Z;*.zip;*.zst;*.wic;*.wim;*.esd;*.vtsi";
	if (has_ffu_support)
		strcat(extensions, ";*.ffu");

	EXT_DECL(img_ext, NULL, __VA_GROUP__(extensions),
	         __VA_GROUP__(lmprintf(MSG_280)));

	char *old_image_path = image_path;
	char *new_path = FileDialog(FALSE, NULL, &img_ext, NULL);
	if (new_path == NULL) {
		if (old_image_path != NULL) {
			/* User cancelled — keep the previously selected image */
			image_path = old_image_path;
		}
		return;
	}
	free(old_image_path);
	image_path = new_path;

	/* Reset DD/ESP mode on each new image selection */
	write_as_image = FALSE;
	write_as_esp   = FALSE;
	safe_free(archive_path);
	uprintf("Image selected: %s", image_path);
	/* Launch ImageScanThread to populate img_report; it posts
	 * UM_IMAGE_SCANNED when done so the UI can refresh. */
	HANDLE scan_thr = CreateThread(NULL, 0, ImageScanThread, NULL, 0, NULL);
	safe_closehandle(scan_thr);
	rufus_gtk_update_status(image_path);
}

static void on_download_iso_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	DownloadISO();
}

/*
 * on_multi_write_clicked — "Write to multiple devices" dialog.
 *
 * Shows a checklist of all currently enumerated drives. The user selects
 * one or more targets and clicks "Write". Rufus then writes the selected
 * image to each drive in sequence, showing per-device status.
 *
 * Sequential (not parallel) to avoid global-state conflicts in FormatThread.
 */
typedef struct {
	GtkWidget *check;  /* GtkCheckButton per device row */
	int        idx;    /* index in the device combo */
	DWORD      di;     /* DriveIndex */
	char       name[256];
} MultiWriteRow;

static void on_multi_write_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;

	if (op_in_progress) {
		rufus_gtk_update_status("Cannot open multi-device dialog while operation is in progress");
		return;
	}

	/* Enumerate all drives currently in the device combo */
	int n = ComboBox_GetCount(hDeviceList);
	if (n <= 0) {
		Notification(MB_OK | MB_ICONINFORMATION, APPLICATION_NAME,
		             "No devices found. Please insert a USB drive and refresh.");
		return;
	}

	if (image_path == NULL || image_path[0] == '\0') {
		Notification(MB_OK | MB_ICONINFORMATION, APPLICATION_NAME,
		             "Please select a boot image before using multi-device write.");
		return;
	}

	/* Build the dialog */
	GtkWidget *dlg = gtk_dialog_new_with_buttons(
		"Write to Multiple Devices",
		GTK_WINDOW(rw.window),
		GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
		"Cancel", GTK_RESPONSE_CANCEL,
		"Write",  GTK_RESPONSE_OK,
		NULL);
	gtk_window_set_default_size(GTK_WINDOW(dlg), 480, 320);

	GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
	GtkWidget *vbox    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	GtkWidget *header = gtk_label_new(
		"Select the devices to write to.\n"
		"All selected devices will be formatted — ALL DATA WILL BE DESTROYED.");
	gtk_label_set_line_wrap(GTK_LABEL(header), TRUE);
	gtk_label_set_xalign(GTK_LABEL(header), 0.0f);
	gtk_box_pack_start(GTK_BOX(vbox), header, FALSE, FALSE, 0);

	/* Scrolled window containing check buttons */
	GtkWidget *sw   = gtk_scrolled_window_new(NULL, NULL);
	GtkWidget *list = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	gtk_container_add(GTK_CONTAINER(sw), list);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
	                               GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_widget_set_vexpand(sw, TRUE);
	gtk_box_pack_start(GTK_BOX(vbox), sw, TRUE, TRUE, 0);

	/* Allocate row info array */
	MultiWriteRow *rows = calloc((size_t)n, sizeof(MultiWriteRow));
	if (!rows) {
		gtk_widget_destroy(dlg);
		return;
	}

	char dev_name[256];
	for (int i = 0; i < n; i++) {
		rows[i].idx = i;
		rows[i].di  = (DWORD)ComboBox_GetItemData(hDeviceList, i);
		dev_name[0] = '\0';
		SendMessageA(hDeviceList, CB_GETLBTEXT, (WPARAM)i, (LPARAM)dev_name);
		strncpy(rows[i].name, dev_name, sizeof(rows[i].name) - 1);

		char label[320];
		snprintf(label, sizeof(label), "%s", rows[i].name);
		rows[i].check = gtk_check_button_new_with_label(label);
		gtk_box_pack_start(GTK_BOX(list), rows[i].check, FALSE, FALSE, 0);
	}

	gtk_box_pack_start(GTK_BOX(content), vbox, TRUE, TRUE, 0);
	gtk_widget_show_all(dlg);

	int response = gtk_dialog_run(GTK_DIALOG(dlg));
	if (response != GTK_RESPONSE_OK) {
		gtk_widget_destroy(dlg);
		free(rows);
		return;
	}

	/* Collect selected targets */
	multidev_session_t session;
	multidev_init(&session);
	for (int i = 0; i < n; i++) {
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rows[i].check)))
			multidev_add_target(&session, rows[i].di, rows[i].name, 0);
	}
	gtk_widget_destroy(dlg);
	free(rows);

	int n_sel = multidev_count_selected(&session);
	if (n_sel == 0) {
		/* User clicked Write without selecting any device — nothing to do */
		return;
	}

	/* Mark all selected */
	for (int i = 0; i < session.n_targets; i++)
		multidev_set_selected(&session, i, TRUE);

	/* Confirm */
	{
		char msg[512];
		snprintf(msg, sizeof(msg),
		         "You are about to write to %d device(s).\n"
		         "ALL DATA ON THOSE DEVICES WILL BE DESTROYED.\n\n"
		         "Are you sure?", session.n_targets);
		if (Notification(MB_OKCANCEL | MB_ICONWARNING, APPLICATION_NAME, msg) != IDOK)
			return;
	}

	/* Build progress dialog */
	GtkWidget *prog_dlg = gtk_dialog_new_with_buttons(
		"Multi-Device Write Progress",
		GTK_WINDOW(rw.window),
		GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
		"Close", GTK_RESPONSE_CLOSE,
		NULL);
	gtk_window_set_default_size(GTK_WINDOW(prog_dlg), 520, 280);
	gtk_dialog_set_response_sensitive(GTK_DIALOG(prog_dlg), GTK_RESPONSE_CLOSE, FALSE);

	GtkWidget *pcontent = gtk_dialog_get_content_area(GTK_DIALOG(prog_dlg));
	GtkWidget *pgrid    = gtk_grid_new();
	gtk_grid_set_column_spacing(GTK_GRID(pgrid), 12);
	gtk_grid_set_row_spacing(GTK_GRID(pgrid), 6);
	gtk_container_set_border_width(GTK_CONTAINER(pgrid), 12);
	gtk_box_pack_start(GTK_BOX(pcontent), pgrid, TRUE, TRUE, 0);

	/* Allocate per-device widget arrays */
	GtkWidget **pbars    = calloc((size_t)session.n_targets, sizeof(GtkWidget *));
	GtkWidget **plabels  = calloc((size_t)session.n_targets, sizeof(GtkWidget *));
	if (!pbars || !plabels) {
		free(pbars); free(plabels);
		gtk_widget_destroy(prog_dlg);
		return;
	}

	for (int i = 0; i < session.n_targets; i++) {
		GtkWidget *name_lbl = gtk_label_new(session.targets[i].name);
		gtk_label_set_xalign(GTK_LABEL(name_lbl), 0.0f);
		gtk_widget_set_hexpand(name_lbl, FALSE);
		gtk_grid_attach(GTK_GRID(pgrid), name_lbl, 0, i, 1, 1);

		pbars[i] = gtk_progress_bar_new();
		gtk_widget_set_hexpand(pbars[i], TRUE);
		gtk_grid_attach(GTK_GRID(pgrid), pbars[i], 1, i, 1, 1);

		plabels[i] = gtk_label_new("Pending");
		gtk_label_set_xalign(GTK_LABEL(plabels[i]), 0.0f);
		gtk_grid_attach(GTK_GRID(pgrid), plabels[i], 2, i, 1, 1);
	}
	gtk_widget_show_all(prog_dlg);

	/* Run FormatThread sequentially for each target */
	for (int i = 0; i < session.n_targets; i++) {
		DWORD target_di = session.targets[i].DriveIndex;

		/* Switch the main device combo to this target */
		int n_items = ComboBox_GetCount(hDeviceList);
		for (int j = 0; j < n_items; j++) {
			if ((DWORD)ComboBox_GetItemData(hDeviceList, j) == target_di) {
				ComboBox_SetCurSel(hDeviceList, j);
				break;
			}
		}

		gtk_label_set_text(GTK_LABEL(plabels[i]), "Writing…");
		gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(pbars[i]), 0.0);
		/* Flush GTK events so the progress dialog updates */
		while (gtk_events_pending())
			gtk_main_iteration_do(FALSE);

		op_in_progress = TRUE;
		ErrorStatus    = 0;
		EnableControls(FALSE, FALSE);
		/* Disable Close button on progress dialog while writing */
		gtk_dialog_set_response_sensitive(GTK_DIALOG(prog_dlg), GTK_RESPONSE_CLOSE, FALSE);

		HANDLE thr = CreateThread(NULL, 0, FormatThread,
		                          (void*)(uintptr_t)target_di, 0, NULL);
		if (thr == NULL) {
			multidev_set_result(&session, i, MULTIDEV_RESULT_FAILURE);
			gtk_label_set_text(GTK_LABEL(plabels[i]), "Failed to start");
			continue;
		}

		/* Poll until thread finishes, reading progress from the main progress bar */
		while (WaitForSingleObject(thr, 200) == WAIT_TIMEOUT) {
			if (rw.progress_bar) {
				double frac = gtk_progress_bar_get_fraction(
				                  GTK_PROGRESS_BAR(rw.progress_bar));
				gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(pbars[i]), frac);
			}
			while (gtk_events_pending())
				gtk_main_iteration_do(FALSE);
		}
		safe_closehandle(thr);

		BOOL ok = (ErrorStatus == 0);
		multidev_set_result(&session, i, ok ? MULTIDEV_RESULT_SUCCESS : MULTIDEV_RESULT_FAILURE);
		multidev_set_progress(&session, i, 100.0f);
		gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(pbars[i]), ok ? 1.0f : 0.0f);
		gtk_label_set_text(GTK_LABEL(plabels[i]), ok ? "✓ Done" : "✗ Failed");

		op_in_progress = FALSE;
		EnableControls(TRUE, FALSE);
		while (gtk_events_pending())
			gtk_main_iteration_do(FALSE);
	}

	/* Summary */
	{
		int n_ok   = multidev_count_success(&session);
		int n_fail = multidev_count_failure(&session);
		char summary[256];
		snprintf(summary, sizeof(summary),
		         "Multi-device write complete: %d succeeded, %d failed.",
		         n_ok, n_fail);
		rufus_gtk_update_status(summary);
		uprintf("%s", summary);
	}

	gtk_dialog_set_response_sensitive(GTK_DIALOG(prog_dlg), GTK_RESPONSE_CLOSE, TRUE);
	gtk_dialog_run(GTK_DIALOG(prog_dlg));
	gtk_widget_destroy(prog_dlg);
	free(pbars);
	free(plabels);
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

	/* Show device count in debug log (mirrors Windows IDC_DEVICE CBN_SELCHANGE PrintStatusDebug) */
	int nb_devices = ComboBox_GetCount(hDeviceList);
	uprintf("%s", lmprintf((nb_devices == 1) ? MSG_208 : MSG_209, nb_devices));

	/* Read partition / FS data for the selected drive */
	char fs_name[32] = "";
	GetDrivePartitionData(di, fs_name, sizeof(fs_name), TRUE);

	/* Ventoy detection — warn the user if the selected device has a
	 * Ventoy installation so they don't accidentally overwrite it. */
	{
		char *dev_path = GetPhysicalName(di);
		if (dev_path) {
			if (ventoy_detect(dev_path))
				rufus_gtk_update_status("⚠ Ventoy installation detected on this device");
			free(dev_path);
		}
	}

	/* Smart refresh: partition scheme + target system based on boot type */
	SetPartitionSchemeAndTargetSystem(FALSE);

	/* Repopulate FS combo and apply smart default for the current image */
	populate_fs_combo();
	SetFSFromISO();

	/* Propose a label for the label entry based on current state */
	SetProposedLabel();

	/* Watch for open handles on this device (mirrors Windows process search) */
	if (nb_devices == 0) {
		StopProcessSearch();
	} else if (!StartProcessSearch() || !SetProcessSearch(di)) {
		uprintf("Failed to start conflicting process search");
		StopProcessSearch();
	}
}

static void on_boot_changed(GtkComboBox *combo, gpointer data)
{
	extern int selection_default;
	(void)data;
	(void)combo;

	/* Update global boot_type from the combo */
	int sel = ComboBox_GetCurSel(hBootType);
	if (sel >= 0)
		boot_type = (int)ComboBox_GetItemData(hBootType, sel);

	/* Early exit if selection didn't change (mirrors Windows IDC_BOOT_SELECTION guard) */
	if (boot_type == selection_default)
		return;
	selection_default = boot_type;

	/* Smart refresh of partition scheme + target system */
	SetPartitionSchemeAndTargetSystem(FALSE);

	/* Repopulate FS combo and apply smart default for the current image */
	populate_fs_combo();
	SetFSFromISO();
	ToggleImageOptions();

	/* Propose a label appropriate for the new boot type */
	SetProposedLabel();

	/* Re-enable controls for the new selection state */
	EnableControls(TRUE, FALSE);

	/* Update advanced-options checkbox sensitivity */
	update_advanced_controls();
}

static void on_fs_changed(GtkComboBox *combo, gpointer data)
{
	(void)data;
	(void)combo;

	/* Update fs_type from the combo and refresh cluster size options */
	int sel = ComboBox_GetCurSel(hFileSystem);
	if (sel >= 0) {
		fs_type = (int)ComboBox_GetItemData(hFileSystem, sel);
		populate_cluster_combo(fs_type);
		/* Record user's explicit FS choice so SetFSFromISO won't override it
		 * (mirrors Windows: if (set_selected_fs && (fs_type > 0)) selected_fs = fs_type) */
		set_user_selected_fs(fs_type);
	}

	/* Update advanced-options checkbox sensitivity (quick format depends on fs_type) */
	update_advanced_controls();
}

/*
 * Image option combo changed — mirrors Windows IDC_IMAGE_OPTION CBN_SELCHANGE.
 * Updates filesystem combo and UEFI validation checkbox for the new mode.
 */
static void on_image_option_changed(GtkComboBox *combo, gpointer data)
{
	(void)combo; (void)data;
	if (!hImageOption) return;
	/* Refresh FS combo for the new image option (e.g. WinToGo needs NTFS) */
	populate_fs_combo();
	SetFSFromISO();
	/* UEFI media validation sensitivity depends on image option */
	update_advanced_controls();
}

/* Update the CSM help label visibility and tooltip when the target combo changes */
static void on_target_changed(GtkComboBox *combo, gpointer data)
{
	(void)combo; (void)data;

	/* Update target_type global from combo */
	int sel = ComboBox_GetCurSel(hTargetSystem);
	if (sel >= 0)
		target_type = (int)ComboBox_GetItemData(hTargetSystem, sel);
	if (!rw.csm_help_label)
		return;
	if (csm_help_should_show(target_type, has_uefi_csm)) {
		gtk_widget_set_tooltip_text(rw.csm_help_label,
		    lmprintf(csm_help_get_msg_id(target_type, has_uefi_csm)));
		gtk_widget_show(rw.csm_help_label);
	} else {
		gtk_widget_hide(rw.csm_help_label);
	}

	/* Update advanced-options checkbox sensitivity (old BIOS / UEFI val depend on target) */
	update_advanced_controls();
}

/* Partition scheme changed — refresh target system and filesystem combos.
 * Mirrors Windows IDC_PARTITION_TYPE CBN_SELCHANGE handler. */
static void on_partition_changed(GtkComboBox *combo, gpointer data)
{
	(void)combo; (void)data;

	/* Update partition_type global */
	int sel = ComboBox_GetCurSel(hPartitionScheme);
	if (sel >= 0)
		partition_type = (int)ComboBox_GetItemData(hPartitionScheme, sel);

	/* Refresh target system options and filesystem/cluster combos */
	SetPartitionSchemeAndTargetSystem(TRUE);
	populate_fs_combo();
	SetFSFromISO();

	/* Update advanced-options checkbox sensitivity */
	update_advanced_controls();
}

static void on_persistence_changed(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	if (!rw.persistence_scale || !rw.persistence_units) return;
	gdouble val = gtk_range_get_value(GTK_RANGE(rw.persistence_scale));
	int unit = gtk_combo_box_get_active(GTK_COMBO_BOX(rw.persistence_units));
	/* unit 0 = MB, unit 1 = GB */
	uint64_t mult = (unit == 1) ? (1024ULL * 1024 * 1024) : (1024ULL * 1024);
	persistence_size = (uint64_t)val * mult;
	persistence_unit_selection = unit;
	SetPersistenceSize();
}

/*
 * Called when the user types directly in the persistence size entry field.
 * Mirrors Windows IDC_PERSISTENCE_SIZE EN_CHANGE: parses the typed value,
 * clamps it to the slider range, updates persistence_size and the slider.
 */
static void on_persistence_size_entry_changed(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	if (app_changed_persistence) return;
	if (!rw.persistence_scale || !rw.persistence_units || !rw.persistence_size) return;

	const char *text = gtk_entry_get_text(GTK_ENTRY(rw.persistence_size));
	char *end = NULL;
	double val = strtod(text, &end);
	if (end == text || val < 0) return; /* not a valid number */

	double max = gtk_adjustment_get_upper(gtk_range_get_adjustment(GTK_RANGE(rw.persistence_scale)));
	if (val > max) val = max;

	int unit = gtk_combo_box_get_active(GTK_COMBO_BOX(rw.persistence_units));
	uint64_t mult = (unit == 1) ? (1024ULL * 1024 * 1024) : (1024ULL * 1024);
	persistence_size = (uint64_t)val * mult;
	persistence_unit_selection = unit;

	/* Update slider without triggering entry re-entry */
	app_changed_persistence = TRUE;
	gtk_range_set_value(GTK_RANGE(rw.persistence_scale), val);
	app_changed_persistence = FALSE;
}

/* Enforce minimum persistence size (MIN_EXT_SIZE) when the entry loses focus.
 * Mirrors Windows IDC_PERSISTENCE_SIZE EN_KILLFOCUS handler (rufus.c ~line 2374). */
static gboolean on_persistence_size_entry_focus_out(GtkWidget *w, GdkEventFocus *event, gpointer data)
{
	(void)event; (void)data;
	if (persistence_size == 0) return FALSE;
	if (persistence_size < MIN_EXT_SIZE) {
		char tmp[16];
		int unit = gtk_combo_box_get_active(GTK_COMBO_BOX(rw.persistence_units));
		uint64_t mult = (unit == 1) ? (1024ULL * 1024 * 1024) : (1024ULL * 1024);
		uint64_t min_units = (MIN_EXT_SIZE + mult - 1) / mult; /* round up */
		persistence_size = min_units * mult;
		snprintf(tmp, sizeof(tmp), "%" PRIu64, min_units);
		app_changed_persistence = TRUE;
		gtk_entry_set_text(GTK_ENTRY(w), tmp);
		gtk_range_set_value(GTK_RANGE(rw.persistence_scale), (double)min_units);
		app_changed_persistence = FALSE;
	}
	return FALSE;
}

/* Update the bad-blocks write-pattern tooltip when the passes count changes.
 * Mirrors Windows IDC_NB_PASSES CBN_SELCHANGE → SetPassesTooltip() (rufus.c ~line 2408). */
static void on_nb_passes_changed(GtkComboBox *combo, gpointer data)
{
	(void)data;
	static const unsigned int pattern[BADLOCKS_PATTERN_TYPES][BADBLOCK_PATTERN_COUNT] = {
		BADBLOCK_PATTERN_ONE_PASS, BADBLOCK_PATTERN_TWO_PASSES, BADBLOCK_PATTERN_SLC,
		BADCLOCK_PATTERN_MLC, BADBLOCK_PATTERN_TLC };
	int sel = gtk_combo_box_get_active(combo);
	if (sel < 0 || sel >= BADLOCKS_PATTERN_TYPES) return;
	/* MSG_153 (1 pass), MSG_154 (2 passes), MSG_156 (4 passes SLC/MLC/TLC) */
	int msg_id = MSG_153 + ((sel >= 2) ? 3 : sel);
	CreateTooltip((HWND)rw.nb_passes_combo,
		lmprintf(msg_id, pattern[sel][0], pattern[sel][1], pattern[sel][2], pattern[sel][3]), -1);
	nb_passes_sel = sel;
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
	extern uint16_t rufus_version[3];
	char version_str[16];
	snprintf(version_str, sizeof(version_str), "%d.%d",
	         rufus_version[0], rufus_version[1]);
	GtkWidget *dlg = gtk_about_dialog_new();
	gtk_about_dialog_set_program_name(GTK_ABOUT_DIALOG(dlg), "Rufus");
	gtk_about_dialog_set_version(GTK_ABOUT_DIALOG(dlg), version_str);
	gtk_about_dialog_set_comments(GTK_ABOUT_DIALOG(dlg),
		"The Reliable USB Formatting Utility");
	gtk_about_dialog_set_website(GTK_ABOUT_DIALOG(dlg), "https://rufus.ie");
	gtk_about_dialog_set_license_type(GTK_ABOUT_DIALOG(dlg), GTK_LICENSE_GPL_3_0);
	gtk_dialog_run(GTK_DIALOG(dlg));
	gtk_widget_destroy(dlg);
}

/*
 * Settings dialog — shown when the ⚙ toolbar button is clicked.
 *
 * Shows a checklist of boolean preferences that can be toggled and
 * saved to the INI settings file.  Mirrors the Windows "Application
 * Options" section from the update policy dialog.
 */
static void on_settings_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;

	extern BOOL detect_fakes;
	extern BOOL ignore_boot_marker;
	extern BOOL usb_debug;

	GtkWidget *dlg = gtk_dialog_new_with_buttons(
		"Application Settings",
		GTK_WINDOW(rw.window),
		GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
		"Cancel", GTK_RESPONSE_CANCEL,
		"OK",     GTK_RESPONSE_OK,
		NULL);
	gtk_window_set_default_size(GTK_WINDOW(dlg), 420, 340);

	GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
	GtkWidget *vbox    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);
	gtk_box_pack_start(GTK_BOX(content), vbox, TRUE, TRUE, 0);

	/* --- Update interval --- */
	GtkWidget *updates_frame = gtk_frame_new("Update Checks");
	GtkWidget *updates_box   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	gtk_container_set_border_width(GTK_CONTAINER(updates_box), 8);
	gtk_container_add(GTK_CONTAINER(updates_frame), updates_box);
	gtk_box_pack_start(GTK_BOX(vbox), updates_frame, FALSE, FALSE, 0);

	int32_t cur_interval = (int32_t)ReadSetting32(SETTING_UPDATE_INTERVAL);
	GtkWidget *rb_daily    = gtk_radio_button_new_with_label(NULL, "Check for updates daily");
	GtkWidget *rb_weekly   = gtk_radio_button_new_with_label_from_widget(
	                             GTK_RADIO_BUTTON(rb_daily), "Check for updates weekly");
	GtkWidget *rb_disabled = gtk_radio_button_new_with_label_from_widget(
	                             GTK_RADIO_BUTTON(rb_daily), "Disable update checks");

	if (cur_interval < 0)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rb_disabled), TRUE);
	else if (cur_interval > 86400)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rb_weekly), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rb_daily), TRUE);

	gtk_box_pack_start(GTK_BOX(updates_box), rb_daily,    FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(updates_box), rb_weekly,   FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(updates_box), rb_disabled, FALSE, FALSE, 0);

	/* --- Behaviour options --- */
	GtkWidget *opts_frame = gtk_frame_new("Behaviour");
	GtkWidget *opts_box   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	gtk_container_set_border_width(GTK_CONTAINER(opts_box), 8);
	gtk_container_add(GTK_CONTAINER(opts_frame), opts_box);
	gtk_box_pack_start(GTK_BOX(vbox), opts_frame, FALSE, FALSE, 0);

	GtkWidget *cb_dark       = gtk_check_button_new_with_label("Dark mode");
	GtkWidget *cb_expert     = gtk_check_button_new_with_label("Expert mode");
	GtkWidget *cb_usb_debug  = gtk_check_button_new_with_label("USB debug logging");
	GtkWidget *cb_fake_chk   = gtk_check_button_new_with_label("Detect fake flash drives");
	GtkWidget *cb_boot_marker= gtk_check_button_new_with_label("Ignore boot marker");

	BOOL cur_dark = (ReadSetting32(SETTING_DARK_MODE) == 2);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cb_dark),       cur_dark);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cb_expert),     expert_mode);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cb_usb_debug),  usb_debug);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cb_fake_chk),   detect_fakes);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cb_boot_marker),ignore_boot_marker);

	gtk_box_pack_start(GTK_BOX(opts_box), cb_dark,        FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(opts_box), cb_expert,      FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(opts_box), cb_usb_debug,   FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(opts_box), cb_fake_chk,    FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(opts_box), cb_boot_marker, FALSE, FALSE, 0);

	gtk_widget_show_all(dlg);
	int response = gtk_dialog_run(GTK_DIALOG(dlg));

	if (response == GTK_RESPONSE_OK) {
		/* Save update interval */
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb_disabled)))
			WriteSetting32(SETTING_UPDATE_INTERVAL, -1);
		else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb_weekly)))
			WriteSetting32(SETTING_UPDATE_INTERVAL, 7 * 86400);
		else
			WriteSetting32(SETTING_UPDATE_INTERVAL, 86400);

		/* Dark mode */
		BOOL new_dark = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_dark));
		WriteSetting32(SETTING_DARK_MODE, new_dark ? 2 : 1);
		is_darkmode_enabled = new_dark ? TRUE : FALSE;
		{
			GtkSettings *gsettings = gtk_settings_get_default();
			g_object_set(G_OBJECT(gsettings),
			             "gtk-application-prefer-dark-theme",
			             (gboolean)new_dark, NULL);
		}

		/* Expert mode */
		BOOL new_expert = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_expert));
		if (new_expert != expert_mode) {
			expert_mode = new_expert;
			WriteSettingBool(SETTING_EXPERT_MODE, expert_mode);
		}

		/* USB debug */
		BOOL new_usb_debug = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_usb_debug));
		if (new_usb_debug != usb_debug) {
			usb_debug = new_usb_debug;
			WriteSettingBool(SETTING_ENABLE_USB_DEBUG, usb_debug);
		}

		/* Detect fake drives */
		BOOL new_detect_fakes = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_fake_chk));
		if (new_detect_fakes != detect_fakes) {
			detect_fakes = new_detect_fakes;
			WriteSettingBool(SETTING_DISABLE_FAKE_DRIVES_CHECK, !detect_fakes);
		}

		/* Ignore boot marker */
		BOOL new_boot_marker = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_boot_marker));
		if (new_boot_marker != ignore_boot_marker) {
			ignore_boot_marker = new_boot_marker;
			WriteSettingBool(SETTING_IGNORE_BOOT_MARKER, ignore_boot_marker);
		}

		uprintf("Settings saved: dark=%d expert=%d usb_debug=%d detect_fakes=%d ignore_boot_marker=%d",
		        new_dark, expert_mode, usb_debug, detect_fakes, ignore_boot_marker);
	}

	gtk_widget_destroy(dlg);
}


static void on_lang_menu_activate(GtkMenuItem *item, gpointer data)
{
	(void)data;
	guint msg_id = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(item), "lang-msg-id"));
	PostMessage(hMainDialog, (UINT)msg_id, 0, 0);
}

static void on_hash_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	extern char *image_path;
	if (format_thread != NULL || image_path == NULL || image_path[0] == '\0')
		return;
	ErrorStatus = 0;
	format_thread = CreateThread(NULL, 0, HashThread, NULL, 0, NULL);
	if (format_thread == NULL) {
		uprintf("on_hash_clicked: unable to start HashThread");
		ErrorStatus = RUFUS_ERROR(ERROR_CANT_START_THREAD);
	}
}

static void on_lang_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	RECT rc = {0, 0, 0, 0};
	ShowLanguageMenu(rc);
}

static void on_save_clicked(GtkButton *btn, gpointer data)
{
	(void)btn; (void)data;
	extern void OpticalDiscSaveImage(void);
	OpticalDiscSaveImage();
}

/*
 * on_drag_data_received — handle files dragged onto the Rufus window.
 *
 * Mirrors Windows WM_DROPFILES handler: takes the first dropped file URI,
 * converts it to a local path, and triggers an image scan exactly as
 * clicking SELECT with a pre-filled image_path would.
 */
static void on_drag_data_received(GtkWidget *w, GdkDragContext *ctx,
                                  gint x, gint y, GtkSelectionData *sel,
                                  guint info, guint t, gpointer data)
{
	(void)w; (void)x; (void)y; (void)info; (void)data;

	extern BOOL op_in_progress;
	if (op_in_progress) {
		gtk_drag_finish(ctx, FALSE, FALSE, t);
		return;
	}

	gchar **uris = gtk_selection_data_get_uris(sel);
	if (uris && uris[0]) {
		char *path = path_from_file_uri(uris[0]);
		if (path) {
			safe_free(image_path);
			image_path = path;
			write_as_image = FALSE;
			write_as_esp   = FALSE;
			safe_free(archive_path);
			uprintf("Image dropped: %s", image_path);
			HANDLE scan_thr = CreateThread(NULL, 0, ImageScanThread, NULL, 0, NULL);
			safe_closehandle(scan_thr);
			rufus_gtk_update_status(image_path);
		}
		g_strfreev(uris);
	}
	gtk_drag_finish(ctx, TRUE, FALSE, t);
}

static void on_toggle_dark_mode(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	GtkSettings *gsettings = gtk_settings_get_default();
	gboolean current = FALSE;
	g_object_get(G_OBJECT(gsettings),
	             "gtk-application-prefer-dark-theme", &current, NULL);
	gboolean next = !current;
	g_object_set(G_OBJECT(gsettings),
	             "gtk-application-prefer-dark-theme", next, NULL);
	/* Save explicit user preference: 1=light, 2=dark */
	WriteSetting32(SETTING_DARK_MODE, next ? 2 : 1);
	is_darkmode_enabled = next ? TRUE : FALSE;
}

static void on_toggle_expert_mode(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	expert_mode = !expert_mode;
	WriteSettingBool(SETTING_EXPERT_MODE, expert_mode);
	uprintf("Expert mode: %s", expert_mode ? "enabled" : "disabled");
}

static void on_toggle_joliet(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	enable_joliet = !enable_joliet;
	uprintf("Joliet support: %s", enable_joliet ? "enabled" : "disabled");
}

static void on_toggle_rockridge(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	enable_rockridge = !enable_rockridge;
	uprintf("Rock Ridge support: %s", enable_rockridge ? "enabled" : "disabled");
}

/* Mirrors Windows IDC_ADVANCED_FORMAT_OPTIONS: refresh FS+cluster combo after toggle */
static void on_adv_format_toggled(GtkExpander *exp, gpointer data)
{
	(void)data;
	/* GTK fires "activate" before toggling, so the current expanded state
	 * is what we're toggling AWAY from. */
	BOOL now_expanded = !gtk_expander_get_expanded(GTK_EXPANDER(exp));
	WriteSettingBool(SETTING_ADVANCED_MODE_FORMAT, now_expanded);
	populate_fs_combo();
	SetFSFromISO();
}

static void on_adv_device_toggled(GtkExpander *exp, gpointer data)
{
	extern BOOL advanced_mode_device;
	(void)data;
	advanced_mode_device = !gtk_expander_get_expanded(GTK_EXPANDER(exp));
	WriteSettingBool(SETTING_ADVANCED_MODE_DEVICE, advanced_mode_device);
	/* Refresh boot combo (adds/removes Syslinux/ReactOS/GRUB2/GRUB4DOS/UEFI:NTFS) */
	populate_boot_combo();
	boot_type = (int)ComboBox_GetCurItemData(hBootType);
	EnableControls(TRUE, FALSE);
	populate_fs_combo();
	SetFSFromISO();
}

static void on_toggle_usb_hdd(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	enable_HDDs = !enable_HDDs;
	uprintf("USB HDD detection: %s", enable_HDDs ? "enabled" : "disabled");
	/* Sync the Advanced Drive Properties checkbox */
	if (rw.list_usb_hdd_check)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.list_usb_hdd_check), enable_HDDs);
	GetDevices(0);
}

/* Checkbox handler: list USB HDDs checkbox in Advanced Drive Properties */
static void on_list_usb_hdd_toggled(GtkToggleButton *btn, gpointer data)
{
	(void)data;
	enable_HDDs = gtk_toggle_button_get_active(btn) ? TRUE : FALSE;
	uprintf("USB HDD detection: %s", enable_HDDs ? "enabled" : "disabled");
	GetDevices(0);
}

/* Checkbox handler: UEFI media validation checkbox in Advanced Drive Properties */
static void on_uefi_validation_toggled(GtkToggleButton *btn, gpointer data)
{
	(void)data;
	extern BOOL validate_md5sum;
	validate_md5sum = gtk_toggle_button_get_active(btn) ? TRUE : FALSE;
	uprintf("UEFI media validation (md5sum): %s", validate_md5sum ? "enabled" : "disabled");
}

/* Checkbox handler: old BIOS fixes (XP_COMPAT extra partition/align) */
static void on_old_bios_check_toggled(GtkToggleButton *btn, gpointer data)
{
	(void)data;
	extern BOOL use_old_bios_fixes;
	use_old_bios_fixes = gtk_toggle_button_get_active(btn) ? TRUE : FALSE;
	uprintf("Old BIOS fixes: %s", use_old_bios_fixes ? "enabled" : "disabled");
}

/* Checkbox handler: extended label / autorun.inf creation */
static void on_extended_label_toggled(GtkToggleButton *btn, gpointer data)
{
	(void)data;
	extern BOOL use_extended_label;
	use_extended_label = gtk_toggle_button_get_active(btn) ? TRUE : FALSE;
	uprintf("Extended label: %s", use_extended_label ? "enabled" : "disabled");
}

/* --- New Alt+key cheat-mode toggle handlers --- */

static void on_toggle_rufus_mbr(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_rufus_mbr((int*)&use_rufus_mbr);
	WriteSettingBool(SETTING_DISABLE_RUFUS_MBR, !r.new_value);
	uprintf("Rufus MBR: %s", r.new_value ? "enabled" : "disabled");
}

static void on_toggle_detect_fakes(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	extern BOOL detect_fakes;
	kbdshortcut_result_t r = kbdshortcut_toggle_detect_fakes((int*)&detect_fakes);
	WriteSettingBool(SETTING_DISABLE_FAKE_DRIVES_CHECK, !r.new_value);
	uprintf("Fake drive detection: %s", r.new_value ? "enabled" : "disabled");
}

static void on_toggle_dual_uefi_bios(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_dual_uefi_bios((int*)&allow_dual_uefi_bios);
	WriteSettingBool(SETTING_ENABLE_WIN_DUAL_EFI_BIOS, r.new_value);
	uprintf("Dual UEFI/BIOS mode: %s", r.new_value ? "enabled" : "disabled");
	if (r.refresh_part) {
		SetPartitionSchemeAndTargetSystem(FALSE);
	}
}

static void on_toggle_vhds(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_vhds((int*)&enable_VHDs);
	WriteSettingBool(SETTING_DISABLE_VHDS, !r.new_value);
	uprintf("VHD/virtual disk detection: %s", r.new_value ? "enabled" : "disabled");
	if (r.refresh_devs)
		GetDevices(0);
}

static void on_toggle_extra_hashes(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_extra_hashes((int*)&enable_extra_hashes);
	WriteSettingBool(SETTING_ENABLE_EXTRA_HASHES, r.new_value);
	uprintf("Extra hash (SHA-512) computation: %s", r.new_value ? "enabled" : "disabled");
}

static void on_toggle_iso(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	extern BOOL enable_iso;
	kbdshortcut_result_t r = kbdshortcut_toggle_iso((int*)&enable_iso);
	uprintf("ISO support: %s", r.new_value ? "enabled" : "disabled");
	/* Re-scan current image if one is loaded, to apply the new setting */
	if (image_path != NULL) {
		HANDLE scan_thr = CreateThread(NULL, 0, ImageScanThread, NULL, 0, NULL);
		if (scan_thr != NULL)
			CloseHandle(scan_thr);
	}
}

static void on_toggle_large_fat32(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_large_fat32((int*)&force_large_fat32);
	WriteSettingBool(SETTING_FORCE_LARGE_FAT32_FORMAT, r.new_value);
	uprintf("Force large FAT32: %s", r.new_value ? "enabled" : "disabled");
	if (r.refresh_devs)
		GetDevices(0);
}

static void on_toggle_boot_marker(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	extern BOOL ignore_boot_marker;
	kbdshortcut_result_t r = kbdshortcut_toggle_boot_marker((int*)&ignore_boot_marker);
	WriteSettingBool(SETTING_IGNORE_BOOT_MARKER, r.new_value);
	uprintf("Ignore boot marker: %s", r.new_value ? "enabled" : "disabled");
}

static void on_toggle_ntfs_compression(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_ntfs_compression((int*)&enable_ntfs_compression);
	uprintf("NTFS compression: %s", r.new_value ? "enabled" : "disabled");
}

static void on_toggle_size_check(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_size_check((int*)&size_check);
	uprintf("ISO size check: %s", r.new_value ? "enabled" : "disabled");
}

static void on_toggle_preserve_ts(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_preserve_ts((int*)&preserve_timestamps);
	WriteSettingBool(SETTING_PRESERVE_TIMESTAMPS, r.new_value);
	uprintf("Preserve timestamps: %s", r.new_value ? "enabled" : "disabled");
}

static void on_toggle_proper_units(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_proper_units((int*)&use_fake_units);
	WriteSettingBool(SETTING_USE_PROPER_SIZE_UNITS, !r.new_value);
	uprintf("Proper size units (GiB/MiB): %s", r.new_value ? "disabled (SI)" : "enabled (binary)");
	if (r.refresh_devs)
		GetDevices(0);
}

static void on_toggle_vmdk(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_vmdk((int*)&enable_vmdk);
	WriteSettingBool(SETTING_ENABLE_VMDK_DETECTION, r.new_value);
	uprintf("VMware/VMDK detection: %s", r.new_value ? "enabled" : "disabled");
	if (r.refresh_devs)
		GetDevices(0);
}

static void on_toggle_force_update(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	extern int force_update;
	kbdshortcut_result_t r = kbdshortcut_toggle_force_update(&force_update);
	uprintf("Force update check: %s", r.new_value ? "enabled" : "disabled");
}

static void on_zero_drive(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_zero_drive((int*)&zero_drive, (int*)&fast_zeroing);
	uprintf("Zero drive requested (standard)");
	/* Simulate Start button click */
	gtk_button_clicked(GTK_BUTTON(rw.start_btn));
}

static void on_fast_zero_drive(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_fast_zero_drive((int*)&zero_drive, (int*)&fast_zeroing);
	uprintf("Zero drive requested (fast — skip empty blocks)");
	/* Simulate Start button click */
	gtk_button_clicked(GTK_BUTTON(rw.start_btn));
}

static void on_cycle_port(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	int index = ComboBox_GetCurSel(hDeviceList);
	if (index >= 0)
		CyclePort(index);
}

/* Alt+P: toggle GPT partition type between EFI System and MS Basic Data,
 * then cycle the USB port to force re-enumeration (mirrors Windows Alt+P). */
static void on_toggle_esp(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	extern BOOL ToggleEsp(DWORD di, uint64_t off);
	int index = ComboBox_GetCurSel(hDeviceList);
	if (index < 0)
		return;
	DWORD DeviceNum = (DWORD)ComboBox_GetItemData(hDeviceList, index);
	if (ToggleEsp(DeviceNum, 0))
		CyclePort(index);
}

static void on_toggle_usb_debug(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	extern BOOL usb_debug;
	kbdshortcut_result_t r = kbdshortcut_toggle_usb_debug((int*)&usb_debug);
	WriteSettingBool(SETTING_ENABLE_USB_DEBUG, usb_debug);
	uprintf("USB debug: %s", r.new_value ? "enabled" : "disabled");
	if (r.refresh_devs)
		GetDevices(0);
}

static void on_toggle_lock_drive(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_lock_drive((int*)&lock_drive);
	uprintf("Exclusive USB drive locking: %s", r.new_value ? "enabled" : "disabled");
}

static void on_toggle_file_indexing(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_file_indexing((int*)&enable_file_indexing);
	WriteSettingBool(SETTING_ENABLE_FILE_INDEXING, enable_file_indexing);
	uprintf("File indexing: %s", r.new_value ? "enabled" : "disabled");
}

static void on_toggle_non_usb_removable(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_non_usb_removable(
		(int*)&list_non_usb_removable_drives,
		(int*)&enable_HDDs,
		(int*)&previous_enable_HDDs);
	if (list_non_usb_removable_drives)
		uprintf("CAUTION: Listing of non-USB removable drives enabled — you may lose data!");
	else
		uprintf("Listing of non-USB removable drives disabled");
	/* Sync the list-USB-HDDs checkbox to the new enable_HDDs value */
	if (rw.list_usb_hdd_check)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.list_usb_hdd_check), enable_HDDs);
	if (r.refresh_devs)
		GetDevices(0);
}

static void on_toggle_force_update_strict(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	kbdshortcut_result_t r = kbdshortcut_toggle_force_update_strict((int*)&force_update);
	uprintf("Force update check (strict): %s (force_update=%d)",
		r.new_value ? "enabled" : "disabled", r.new_value);
}

static void on_delete_app_data_dir(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	char path[MAX_PATH];
	snprintf(path, sizeof(path), "%s/" FILES_DIR, app_data_dir);
	uprintf("Deleting directory '%s'", path);
	/* Recursively delete the directory using shell command */
	char cmd[MAX_PATH + 32];
	snprintf(cmd, sizeof(cmd), "rm -rf \"%s\"", path);
	system(cmd);
	user_deleted_rufus_dir = TRUE;
}

/* Alt+R: delete the Rufus settings/INI file.
 * Mirrors Windows Alt+R which deletes the REGKEY_HKCU registry key. */
static void on_delete_settings(GtkWidget *w, gpointer data)
{
	(void)w; (void)data;
	extern char *ini_file;
	if (ini_file && ini_file[0]) {
		uprintf("Deleting settings file '%s'", ini_file);
		if (unlink(ini_file) == 0) {
			rufus_gtk_update_status(lmprintf(MSG_248));
			ini_file = NULL;
		} else {
			rufus_gtk_update_status(lmprintf(MSG_249));
		}
	} else {
		uprintf("No settings file to delete");
		rufus_gtk_update_status(lmprintf(MSG_249));
	}
}
static void on_gtk_dark_theme_changed(GObject *object, GParamSpec *pspec,
                                       gpointer data)
{
	(void)pspec; (void)data;
	gboolean dark = FALSE;
	g_object_get(object, "gtk-application-prefer-dark-theme", &dark, NULL);
	is_darkmode_enabled = dark ? TRUE : FALSE;
}

/* ======================================================================
 * ui.h API implementation for GTK
 * ====================================================================== */

void SetAccessibleName(HWND hCtrl, const char *name)
{
	GtkWidget *w = (GtkWidget *)hCtrl;
	if (w && name) {
		gtk_widget_set_tooltip_text(w, name);
		AtkObject *atk = gtk_widget_get_accessible(w);
		if (atk)
			atk_object_set_name(atk, name);
	}
}

/*
 * GTK activate-link signal handler: open URL via GLib default app.
 * Returns TRUE to signal that we handled the link (prevents GTK from
 * trying to open it a second time with its own handler).
 */
static gboolean gtk_show_uri_on_window_open_handler(GtkLabel *label,
    gchar *uri, gpointer data)
{
#ifdef USE_GTK
	(void)label; (void)data;
	GError *err = NULL;
	g_app_info_launch_default_for_uri(uri, NULL, &err);
	if (err) {
		uprintf("set_hyperlink_label: failed to open '%s': %s", uri, err->message);
		g_error_free(err);
	}
	return TRUE; /* handled */
#else
	(void)label; (void)uri; (void)data;
	return FALSE;
#endif
}

/*
 * set_hyperlink_label — make a GtkLabel display a clickable hyperlink.
 *
 *  widget  — a GtkLabel widget (must be non-NULL and a GtkLabel)
 *  url     — the URL to open when clicked (must be non-NULL)
 *  text    — the display text; if NULL or empty, `url` is used as the label
 *
 * The label text is set as Pango markup `<a href="URL">TEXT</a>`.
 * The `activate-link` signal is connected so that clicking opens the URL
 * via GLib's default URI handler (`g_app_info_launch_default_for_uri()`),
 * which delegates to `xdg-open` on most Linux desktops.
 *
 * Calling with a NULL widget or NULL url is a safe no-op.
 */
void set_hyperlink_label(GtkWidget *widget, const char *url, const char *text)
{
#ifdef USE_GTK
	char markup[4096];

	if (widget == NULL || !GTK_IS_LABEL(widget) || url == NULL)
		return;
	if (hyperlink_build_markup(url, text, markup, sizeof(markup)) <= 0)
		return;

	gtk_label_set_markup(GTK_LABEL(widget), markup);
	gtk_label_set_use_markup(GTK_LABEL(widget), TRUE);
	/* Allow the label to track cursor changes for the hyperlink. */
	gtk_label_set_track_visited_links(GTK_LABEL(widget), FALSE);

	/* Connect activate-link to open the URL via GLib's default handler.
	 * Return TRUE to suppress GTK's built-in URI handling (avoid double-open). */
	g_signal_connect(widget, "activate-link",
	    G_CALLBACK(gtk_show_uri_on_window_open_handler), NULL);
#else
	(void)widget; (void)url; (void)text;
#endif
}

void SetComboEntry(HWND hDlg, int data)
{
	int i, nb_entries;
	/* hDlg may be either a real GtkWidget* or a combo_state_t* wrapped as HWND.
	 * Try GtkWidget first; if it's not a ComboBox, fall through to combo_bridge. */
	GtkWidget *w = (GtkWidget *)hDlg;
	if (w && GTK_IS_COMBO_BOX(w)) {
		nb_entries = gtk_tree_model_iter_n_children(
			gtk_combo_box_get_model(GTK_COMBO_BOX(w)), NULL);
		for (i = 0; i < nb_entries; i++) {
			if ((int)ComboBox_GetItemData(hDlg, i) == data) {
				gtk_combo_box_set_active(GTK_COMBO_BOX(w), i);
				return;
			}
		}
		if (nb_entries > 0)
			gtk_combo_box_set_active(GTK_COMBO_BOX(w), 0);
		return;
	}
	/* combo_state_t* path: search item data and use CB_SETCURSEL via bridge */
	nb_entries = (int)ComboBox_GetCount(hDlg);
	for (i = 0; i < nb_entries; i++) {
		if ((int)ComboBox_GetItemData(hDlg, i) == data) {
			ComboBox_SetCurSel(hDlg, i);
			return;
		}
	}
	if (nb_entries > 0)
		ComboBox_SetCurSel(hDlg, 0);
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
	if (!rw.persistence_size || !rw.persistence_scale || !rw.persistence_units) return;
	char buf[32];
	gdouble val = gtk_range_get_value(GTK_RANGE(rw.persistence_scale));
	snprintf(buf, sizeof(buf), "%.0f", val);
	app_changed_persistence = TRUE;
	gtk_entry_set_text(GTK_ENTRY(rw.persistence_size), buf);
	app_changed_persistence = FALSE;
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

/*
 * update_advanced_controls() — mirrors Windows EnableBootOptions().
 * Enables/disables and optionally resets advanced-options checkboxes
 * based on the current boot type, partition scheme, target system,
 * filesystem type, and scanned image report.
 *
 * Called from on_boot_changed(), on_fs_changed(), on_target_changed(),
 * the UM_IMAGE_SCANNED handler, and on_partition_changed() (via combo logic).
 */
void update_advanced_controls(void)
{
	extern BOOL validate_md5sum;
	int imop_sel = (hImageOption != NULL) ?
		(int)ComboBox_GetItemData(hImageOption, ComboBox_GetCurSel(hImageOption)) :
		IMOP_WIN_STANDARD;

	/* --- UEFI media validation --- */
	if (rw.uefi_validation_check) {
		BOOL en = should_enable_uefi_validation(boot_type, target_type,
		                                        (int)image_options, imop_sel,
		                                        allow_dual_uefi_bios, &img_report);
		gtk_widget_set_sensitive(rw.uefi_validation_check, en ? TRUE : FALSE);
		if (!en) {
			/* Force-uncheck when disabled, remember state via validate_md5sum */
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.uefi_validation_check), FALSE);
		} else {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.uefi_validation_check),
			                             validate_md5sum ? TRUE : FALSE);
		}
	}

	/* --- Old BIOS fixes --- */
	if (rw.old_bios_check) {
		BOOL en = should_enable_old_bios(partition_type, target_type,
		                                  boot_type, &img_report);
		gtk_widget_set_sensitive(rw.old_bios_check, en ? TRUE : FALSE);
		if (!en)
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.old_bios_check), FALSE);
	}

	/* --- Extended label / autorun.inf --- */
	if (rw.extended_label_check) {
		BOOL en = should_enable_extended_label(fs_type, boot_type, &img_report);
		gtk_widget_set_sensitive(rw.extended_label_check, en ? TRUE : FALSE);
		if (!en) {
			extern BOOL use_extended_label;
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.extended_label_check), FALSE);
			use_extended_label = FALSE;
		}
	}

	/* --- Quick format --- */
	if (rw.quick_format_check) {
		BOOL force = should_force_quick_format(fs_type, force_large_fat32,
		                                        SelectedDrive.DiskSize);
		BOOL en = should_enable_quick_format(fs_type, boot_type, force_large_fat32,
		                                      SelectedDrive.DiskSize, &img_report);
		if (force) {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.quick_format_check), TRUE);
			gtk_widget_set_sensitive(rw.quick_format_check, FALSE);
		} else {
			gtk_widget_set_sensitive(rw.quick_format_check, en ? TRUE : FALSE);
			if (!en)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rw.quick_format_check), FALSE);
		}
	}
}

void EnableControls(BOOL enable, BOOL remove_checkboxes)
{
	(void)remove_checkboxes;
	gboolean e = enable ? TRUE : FALSE;
	if (rw.device_combo)      gtk_widget_set_sensitive(rw.device_combo,      e);
	if (rw.boot_combo)        gtk_widget_set_sensitive(rw.boot_combo,        e);
	if (rw.select_btn)        gtk_widget_set_sensitive(rw.select_btn,        e);
	if (rw.label_entry)       gtk_widget_set_sensitive(rw.label_entry,       e);
	if (rw.start_btn)         gtk_widget_set_sensitive(rw.start_btn,         e);
	if (rw.multi_write_btn)   gtk_widget_set_sensitive(rw.multi_write_btn,   e);
	if (rw.verify_write_check) gtk_widget_set_sensitive(rw.verify_write_check, e);

	/* Mirror Windows: disable partition/target/fs/cluster combos for pure DD images */
	gboolean dd_combo_enable = e;
	if (enable && (boot_type == BT_IMAGE) && (image_path != NULL) &&
	    !(img_report.is_iso || img_report.is_windows_img))
		dd_combo_enable = FALSE;
	if (rw.partition_combo)   gtk_widget_set_sensitive(rw.partition_combo,   dd_combo_enable);
	if (rw.target_combo)      gtk_widget_set_sensitive(rw.target_combo,      dd_combo_enable);
	if (rw.filesystem_combo)  gtk_widget_set_sensitive(rw.filesystem_combo,  dd_combo_enable);
	if (rw.cluster_combo)     gtk_widget_set_sensitive(rw.cluster_combo,     dd_combo_enable);

	/* While an operation is in progress, repurpose the close button as Cancel */
	if (rw.close_btn) {
		gtk_button_set_label(GTK_BUTTON(rw.close_btn), enable ? "CLOSE" : "CANCEL");
		gtk_widget_set_sensitive(rw.close_btn, TRUE);
	}
}

/* Marquee progress — shown during ISO scan where completion time is unknown.
 * Mirrors Windows PBS_MARQUEE mode; fires every 80 ms to pulse the GTK bar. */
static guint marquee_timer_source = 0;

static gboolean marquee_timer_cb(gpointer data)
{
	(void)data;
	if (rw.progress_bar)
		gtk_progress_bar_pulse(GTK_PROGRESS_BAR(rw.progress_bar));
	return G_SOURCE_CONTINUE;
}

static void start_marquee(void)
{
	if (marquee_timer_source == 0)
		marquee_timer_source = g_timeout_add(80, marquee_timer_cb, NULL);
}

static void stop_marquee(void)
{
	if (marquee_timer_source != 0) {
		g_source_remove(marquee_timer_source);
		marquee_timer_source = 0;
	}
	if (rw.progress_bar)
		gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(rw.progress_bar), 0.0);
}

void InitProgress(BOOL bOnlyFormat)
{
	(void)bOnlyFormat;
	stop_marquee();
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

/* Update the label entry with the ISO volume label after a scan.
 * Mirrors Windows SetProposedLabel(): if the user manually edited the field
 * the update is skipped.  user_changed_label must be cleared by the caller
 * before calling this for a fresh scan. */
static void SetProposedLabel(void)
{
	const char *proposed = get_iso_proposed_label(
	    user_changed_label, image_path, img_report.label);
	if (proposed == NULL)
		return;  /* user changed the label — don't overwrite */
	app_changed_label = TRUE;
	gtk_entry_set_text(GTK_ENTRY(rw.label_entry), proposed);
}

/* "changed" signal handler for the label entry.
 * Sets user_changed_label when the user (not the app) edits the field. */
static void _label_user_changed_handler(GtkEditable *editable, gpointer data)
{
	(void)editable; (void)data;
	if (!app_changed_label)
		user_changed_label = TRUE;
	app_changed_label = FALSE;
}

static LRESULT main_dialog_handler(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
	(void)hwnd; (void)l;

	switch (msg) {
	case UM_FORMAT_COMPLETED: {
		/* w = TRUE on success, FALSE on failure */
		BOOL ok = (BOOL)w;
		extern BOOL save_image;
		op_in_progress = FALSE;
		zero_drive = FALSE;
		safe_closehandle(format_thread);
		format_thread = NULL;
		stop_clock_timer();

		/* Clean up the temporary unattend XML created for this session */
		extern char *unattend_xml_path;
		if (unattend_xml_path != NULL) {
			unlink(unattend_xml_path);
			safe_free(unattend_xml_path);
		}

		EnableControls(ok, TRUE);
		if (ok) {
			rufus_gtk_update_status(lmprintf(MSG_210));
			/* Refresh device list so the new drive label is shown.
			 * Mirrors Windows: skip the refresh when saving an image to disk. */
			if (!save_image)
				GetDevices(0);
		} else if (SCODE_CODE(ErrorStatus) == ERROR_CANCELLED) {
			rufus_gtk_update_status(lmprintf(MSG_211));
			Notification(MB_ICONINFORMATION | MB_CLOSE, lmprintf(MSG_211), lmprintf(MSG_041));
		} else if (SCODE_CODE(ErrorStatus) == ERROR_BAD_SIGNATURE) {
			rufus_gtk_update_status(lmprintf(MSG_283));
		} else {
			rufus_gtk_update_status(lmprintf(MSG_212));
			/* When the device isn't ready, a port cycle usually helps */
			if (SCODE_CODE(ErrorStatus) == ERROR_NOT_READY) {
				int index = ComboBox_GetCurSel(hDeviceList);
				if (index >= 0) {
					uprintf("Device not ready - Trying to cycle port...");
					CyclePort(index);
				}
			}
			Notification(MB_ICONERROR | MB_CLOSE, lmprintf(MSG_042),
			             lmprintf(MSG_043, StrError(ErrorStatus, FALSE)));
		}
		save_image = FALSE;  /* reset after checking above */
		uprintf("*** Format completed (success=%d) ***", (int)ok);
		/* Send desktop notification so the user can come back to Rufus */
		{
			char title[128], body[256];
			notify_format_message(NOTIFY_OP_FORMAT, ok,
			                      title, sizeof(title),
			                      body,  sizeof(body));
			rufus_notify(title, body, ok);
		}
		break;
	}

	case UM_ENABLE_CONTROLS:
		stop_clock_timer();
		if (!IS_ERROR(ErrorStatus))
			rufus_gtk_update_status(lmprintf(MSG_210));
		else if (SCODE_CODE(ErrorStatus) == ERROR_CANCELLED)
			rufus_gtk_update_status(lmprintf(MSG_211));
		else if (SCODE_CODE(ErrorStatus) == ERROR_BAD_SIGNATURE)
			rufus_gtk_update_status(lmprintf(MSG_283));
		else
			rufus_gtk_update_status(lmprintf(MSG_212));
		EnableControls(TRUE, TRUE);
		break;

	case UM_PROGRESS_INIT:
		if (w == PBS_MARQUEE)
			start_marquee();
		else
			InitProgress(TRUE);
		break;

	case UM_PROGRESS_EXIT:
		stop_marquee();
		break;

	case UM_TIMER_START:
		start_clock_timer();
		break;

	case UM_SELECT_ISO:
		/* The Fido download thread finished; show a file-chooser so the
		 * user can select the downloaded ISO.  Re-use the SELECT handler. */
		on_select_clicked(NULL, NULL);
		break;

	case UM_NO_UPDATE:
		rufus_gtk_update_status("No updates available.");
		break;

	case UM_NEW_VERSION: {
		/* CheckForUpdates detected a newer version — show a GTK dialog */
		extern RUFUS_UPDATE update;
		char msg[512];
		if (update.version[0] || update.version[1] || update.version[2])
			snprintf(msg, sizeof(msg),
			         "Rufus %d.%d.%d is available.\n\n"
			         "Would you like to open the download page?",
			         update.version[0], update.version[1], update.version[2]);
		else
			snprintf(msg, sizeof(msg),
			         "A new version of Rufus is available.\n\n"
			         "Would you like to open the download page?");

		GtkWidget *dlg = gtk_message_dialog_new(
			rw.window ? GTK_WINDOW(rw.window) : NULL,
			GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_MESSAGE_INFO,
			GTK_BUTTONS_NONE,
			"%s", msg);
		gtk_window_set_title(GTK_WINDOW(dlg), "New Version Available");

		/* Show release notes if available */
		if (update.release_notes && update.release_notes[0]) {
			GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
			GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
			gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
			                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
			gtk_widget_set_size_request(scroll, 400, 150);
			GtkWidget *tv = gtk_text_view_new();
			gtk_text_view_set_editable(GTK_TEXT_VIEW(tv), FALSE);
			gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(tv), GTK_WRAP_WORD_CHAR);
			gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(tv)),
			                         update.release_notes, -1);
			gtk_container_add(GTK_CONTAINER(scroll), tv);
			gtk_box_pack_start(GTK_BOX(content), scroll, TRUE, TRUE, 4);
			gtk_widget_show_all(content);
		}

		gtk_dialog_add_buttons(GTK_DIALOG(dlg),
			"Remind me later", GTK_RESPONSE_CANCEL,
			"Download", GTK_RESPONSE_ACCEPT,
			NULL);

		if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT)
			DownloadNewVersion();
		gtk_widget_destroy(dlg);
		break;
	}

	case UM_IMAGE_SCANNED: {
		/* ImageScanThread finished — img_report is now populated.
		 * Refresh boot type, filesystem, and partition-scheme combos
		 * to reflect the scanned image content. */
		uprintf("Image scan complete (is_iso=%d, is_bootable=%d)",
		        (int)img_report.is_iso, (int)img_report.is_bootable_img);

		/* If the image has no recognisable boot method, reject it and
		 * reset to the unselected state (mirrors Windows line 1341-1348). */
		if (!IS_DD_BOOTABLE(img_report) && !IS_BIOS_BOOTABLE(img_report) &&
		    !IS_EFI_BOOTABLE(img_report) && !img_report.is_windows_img) {
			rufus_gtk_update_status(lmprintf(MSG_086));
			Notification(MB_OK | MB_ICONINFORMATION, lmprintf(MSG_081), lmprintf(MSG_082));
			safe_free(image_path);
			/* Reset boot combo entry text back to "Please SELECT" */
			if (rw.boot_combo) {
				combo_state_t *cs = (combo_state_t*)(uintptr_t)hBootType;
				int img_idx = 1;
				if (cs && img_idx < cs->count) {
					free(cs->text[img_idx]);
					cs->text[img_idx] = strdup(lmprintf(MSG_281, lmprintf(MSG_280)));
					gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(cs->gtk_widget), img_idx);
					gtk_combo_box_text_insert_text(GTK_COMBO_BOX_TEXT(cs->gtk_widget),
					                              img_idx, cs->text[img_idx]);
				}
			}
			EnableControls(TRUE, FALSE);
			break;
		}

		/* Update boot combo to show image filename (mirrors Windows UpdateImage). */
		if (rw.boot_combo && image_path) {
			combo_state_t *cs = (combo_state_t*)(uintptr_t)hBootType;
			/* BT_IMAGE is at index 1 in populate_boot_combo */
			int img_idx = 1;
			if (cs && img_idx < cs->count) {
				/* Find short filename (after last '/') */
				const char *short_path = image_path;
				for (const char *p = image_path; *p; p++)
					if (*p == '/') short_path = p + 1;
				free(cs->text[img_idx]);
				cs->text[img_idx] = strdup(short_path ? short_path : image_path);
				/* Update GTK display */
				gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(cs->gtk_widget), img_idx);
				gtk_combo_box_text_insert_text(GTK_COMBO_BOX_TEXT(cs->gtk_widget), img_idx,
				                              cs->text[img_idx]);
				/* Keep BT_IMAGE selected */
				gtk_combo_box_set_active(GTK_COMBO_BOX(cs->gtk_widget), img_idx);
			}
		}

		populate_fs_combo();
		SetFSFromISO();
		SetPartitionSchemeAndTargetSystem(FALSE);
		TogglePersistenceControls(HAS_PERSISTENCE(img_report));
		ToggleImageOptions();

		/* Populate the label entry with the ISO volume label.
		 * A fresh scan always overrides any previous auto-fill; only a
		 * manual user edit (tracked via user_changed_label) is preserved. */
		user_changed_label = FALSE;
		SetProposedLabel();

		/* For Windows images, report host TPM and Secure Boot status so
		 * the user can tell if the target machine meets requirements. */
		if (IS_WINDOWS_1X(img_report)) {
			int tpm_ver = GetTPMVersion();
			BOOL sb_on  = IsSecureBootEnabled();
			BOOL sm_on  = IsSetupModeEnabled();
			char info[256];

			/* Build human-readable status for the log */
			snprintf(info, sizeof(info),
			         "Host: TPM %s, Secure Boot %s%s",
			         tpm_ver == 2 ? "2.0" :
			         tpm_ver == 1 ? "1.x" : "not detected",
			         sb_on ? "enabled" : "disabled",
			         sm_on ? " (setup mode)" : "");
			uprintf("%s", info);

			/* Warn if this is a Windows 11 image and TPM 2.0 is missing */
			if (IS_WINDOWS_11(img_report) && tpm_ver < 2) {
				uprintf("WARNING: Windows 11 requires TPM 2.0 — "
				        "this machine may not boot the written image");
			}

			/* Show host info as a tooltip on the boot combo */
			if (rw.boot_combo) {
				char tip[320];
				snprintf(tip, sizeof(tip),
				         "Boot type\n─────────\n%s", info);
				gtk_widget_set_tooltip_text(rw.boot_combo, tip);
			}
		}

		/* Log bootloader revocation status for EFI-bootable images */
		if (IS_EFI_BOOTABLE(img_report)) {
			if (img_report.has_secureboot_bootloader & 0xfe)
				uprintf("WARNING: Image contains a revoked UEFI bootloader "
				        "(revocation mask: 0x%02x)", img_report.has_secureboot_bootloader);
			else if (img_report.has_secureboot_bootloader & 1)
				uprintf("Image bootloaders are signed by a Secure Boot authority");
		}

		/* Populate the image info expander panel */
		if (rw.img_info_label && rw.img_info_expander) {
			char info_buf[512];
			format_img_info(&img_report, info_buf, sizeof(info_buf));
			gtk_label_set_text(GTK_LABEL(rw.img_info_label), info_buf);
			gtk_widget_show(rw.img_info_expander);
			gtk_widget_show(rw.img_info_label);
		}

		/* Update advanced-options checkbox sensitivity based on scanned image */
		update_advanced_controls();
		break;
	}

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
			/* Use CSS for monospace font (gtk_widget_override_font is deprecated). */
			GtkCssProvider *mono_css = gtk_css_provider_new();
			gtk_css_provider_load_from_data(mono_css,
				"label { font-family: monospace; }", -1, NULL);
			gtk_style_context_add_provider(gtk_widget_get_style_context(label),
				GTK_STYLE_PROVIDER(mono_css),
				GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
			g_object_unref(mono_css);
			gtk_grid_attach(GTK_GRID(grid), label, 1, row, 1, 1);
			row++;
		}

		/* Show signer and chain trust info if the file has a PE signature */
		if (image_path && image_path[0]) {
			cert_info_t ci;
			memset(&ci, 0, sizeof(ci));
			if (GetSignatureCertInfo(image_path, &ci) > 0) {
				char sig_val[320];
				snprintf(sig_val, sizeof(sig_val), "%s  (%s)", ci.name,
				         ci.chain_trusted ? "chain trusted ✓" : "chain not trusted ✗");
				label = gtk_label_new("Signer");
				gtk_widget_set_halign(label, GTK_ALIGN_END);
				gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1);
				label = gtk_label_new(sig_val);
				gtk_widget_set_halign(label, GTK_ALIGN_START);
				gtk_label_set_selectable(GTK_LABEL(label), TRUE);
				gtk_grid_attach(GTK_GRID(grid), label, 1, row, 1, 1);
				row++;
			}
		}

		gtk_widget_show_all(dlg);
		gtk_dialog_run(GTK_DIALOG(dlg));
		gtk_widget_destroy(dlg);

		/* Notify the user that hashing finished (they may have switched windows) */
		{
			char ntitle[128], nbody[256];
			notify_format_message(NOTIFY_OP_HASH, TRUE,
			                      ntitle, sizeof(ntitle),
			                      nbody,  sizeof(nbody));
			rufus_notify(ntitle, nbody, TRUE);
		}
		break;
	}

	case UM_ENABLE_DOWNLOAD_ISO:
		/* CheckForFidoThread found a valid Fido URL — enable the "Download ISO" option.
		 * On Linux we reveal a dedicated "Download ISO" button that was hidden at start. */
		if (rw.download_iso_btn)
			gtk_widget_set_visible(rw.download_iso_btn, TRUE);
		break;

	case UM_DOWNLOAD_PROGRESS:
		/* Download progress update from DownloadToFileOrBufferEx().
		 * WPARAM carries the integer percent (0-100).  Update the
		 * main progress bar so the user sees download progress. */
		if (rw.progress_bar) {
			int pct = (int)w;
			gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(rw.progress_bar),
				CLAMP(pct / 100.0, 0.0, 1.0));
		}
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
						/* Persist the user's language choice across sessions */
						if (selected_locale->txt[0])
							WriteSettingStr(SETTING_LOCALE, selected_locale->txt[0]);
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
	char tmp[32];
	extern BOOL advanced_mode_device;

	IGNORE_RETVAL(ComboBox_ResetContent(hBootType));
	IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
	    ComboBox_AddString(hBootType, lmprintf(MSG_279)), BT_NON_BOOTABLE));
	IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
	    ComboBox_AddString(hBootType,
	        (image_path == NULL) ? lmprintf(MSG_281, lmprintf(MSG_280)) :
	            (strrchr(image_path, '/') ? strrchr(image_path, '/') + 1 : image_path)),
	    BT_IMAGE));
	IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
	    ComboBox_AddString(hBootType, "MS-DOS"), BT_MSDOS));
	IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
	    ComboBox_AddString(hBootType, "FreeDOS"), BT_FREEDOS));

	if (advanced_mode_device) {
		static_sprintf(tmp, "Syslinux %s", embedded_sl_version_str[0]);
		IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
		    ComboBox_AddString(hBootType, tmp), BT_SYSLINUX_V4));
		static_sprintf(tmp, "Syslinux %s", embedded_sl_version_str[1]);
		IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
		    ComboBox_AddString(hBootType, tmp), BT_SYSLINUX_V6));
		IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
		    ComboBox_AddString(hBootType, "ReactOS"), BT_REACTOS));
		static_sprintf(tmp, "Grub " GRUB2_PACKAGE_VERSION);
		IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
		    ComboBox_AddString(hBootType, tmp), BT_GRUB2));
		static_sprintf(tmp, "Grub4DOS " GRUB4DOS_VERSION);
		IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
		    ComboBox_AddString(hBootType, tmp), BT_GRUB4DOS));
		IGNORE_RETVAL(ComboBox_SetItemData(hBootType,
		    ComboBox_AddString(hBootType, "UEFI:NTFS"), BT_UEFI_NTFS));
	}

	/* When advanced mode is off and the current boot_type is an advanced entry,
	 * fall back to BT_IMAGE (mirrors Windows SetBootOptions fallback). */
	if (!advanced_mode_device && boot_type >= BT_SYSLINUX_V4)
		boot_type = BT_IMAGE;

	SetComboEntry(hBootType, boot_type);
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
	SetPartitionSchemeAndTargetSystem(FALSE);
	populate_fs_combo();
}

static void on_app_activate(GtkApplication *app, gpointer data)
{
	(void)data;

	/* Initialise version array from compile-time constants */
	init_rufus_version();

	/* Initialise application paths (app_dir, app_data_dir, user_dir, ini_file)
	 * using XDG Base Directory conventions. */
	rufus_init_paths();

	/* Load the embedded locale data file, populate locale_list, and apply
	 * the best match for the system language to the UI strings. */
	{
		const char *loc_path = find_loc_file();
		init_localization();
		if (loc_path != NULL) {
			uprintf("localization: loading '%s'", loc_path);
			if (get_supported_locales(loc_path)) {
				/* Prefer user-saved locale over system locale */
				char *saved_locale = ReadSettingStr(SETTING_LOCALE);
				loc_cmd *sel = NULL;
				if (saved_locale && saved_locale[0]) {
					sel = get_locale_from_name(saved_locale, FALSE);
					if (sel == NULL)
						sel = get_locale_from_name(saved_locale, TRUE);
				}
				if (sel == NULL) {
					char *sys_locale = ToLocaleName(0);
					sel = get_locale_from_name(sys_locale, TRUE);
				}
				if (sel != NULL)
					get_loc_data_file(loc_path, sel);
				else
					uprintf("localization: no locale match found");
			} else {
				uprintf("localization: failed to parse '%s'", loc_path);
			}
		} else {
			uprintf("localization: embedded.loc not found — UI strings will be untranslated");
		}
	}

	/* Restore saved Windows User Experience options */
	{
		uint32_t wue_options = ReadSetting32(SETTING_WUE_OPTIONS);
		if ((wue_options >> 16) != 0) {
			uint32_t mask = wue_options >> 16;
			unattend_xml_mask &= ~(int)mask;
			unattend_xml_mask |= (int)(wue_options & mask);
		}
	}

	/* Restore persisted cheat-mode settings (mirrors Windows startup) */
	{
		extern BOOL detect_fakes, ignore_boot_marker, usb_debug;
		extern BOOL enable_file_indexing, persistent_log;
		use_rufus_mbr         = !ReadSettingBool(SETTING_DISABLE_RUFUS_MBR);
		detect_fakes          = !ReadSettingBool(SETTING_DISABLE_FAKE_DRIVES_CHECK);
		allow_dual_uefi_bios  =  ReadSettingBool(SETTING_ENABLE_WIN_DUAL_EFI_BIOS);
		force_large_fat32     =  ReadSettingBool(SETTING_FORCE_LARGE_FAT32_FORMAT);
		enable_vmdk           =  ReadSettingBool(SETTING_ENABLE_VMDK_DETECTION);
		enable_file_indexing  =  ReadSettingBool(SETTING_ENABLE_FILE_INDEXING);
		enable_VHDs           = !ReadSettingBool(SETTING_DISABLE_VHDS);
		enable_extra_hashes   =  ReadSettingBool(SETTING_ENABLE_EXTRA_HASHES);
		ignore_boot_marker    =  ReadSettingBool(SETTING_IGNORE_BOOT_MARKER);
		persistent_log        =  ReadSettingBool(SETTING_PERSISTENT_LOG);
		preserve_timestamps   =  ReadSettingBool(SETTING_PRESERVE_TIMESTAMPS);
		use_fake_units        = !ReadSettingBool(SETTING_USE_PROPER_SIZE_UNITS);
		usb_debug             =  ReadSettingBool(SETTING_ENABLE_USB_DEBUG);
	}

	/* Apply saved dark mode preference (0=system, 1=light, 2=dark) */
	{
		expert_mode = ReadSettingBool(SETTING_EXPERT_MODE);
		int dark_pref = ReadSetting32(SETTING_DARK_MODE);
		GtkSettings *gsettings = gtk_settings_get_default();
		if (dark_pref == 2) {
			g_object_set(G_OBJECT(gsettings),
			             "gtk-application-prefer-dark-theme", TRUE, NULL);
		} else if (dark_pref == 1) {
			g_object_set(G_OBJECT(gsettings),
			             "gtk-application-prefer-dark-theme", FALSE, NULL);
		}
		/* 0 = follow system default, no override needed */

		/* Sync is_darkmode_enabled with the actual current preference and
		 * connect a signal handler so it stays in sync at runtime. */
		{
			gboolean dark = FALSE;
			g_object_get(G_OBJECT(gsettings),
			             "gtk-application-prefer-dark-theme", &dark, NULL);
			is_darkmode_enabled = dark ? TRUE : FALSE;
		}
		g_signal_connect(G_OBJECT(gsettings),
		                 "notify::gtk-application-prefer-dark-theme",
		                 G_CALLBACK(on_gtk_dark_theme_changed), NULL);
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

	/* Register the label entry with the window-text bridge so that
	 * FormatThread can read the label via GetWindowTextA(hLabel, ...).
	 * The "changed" signal keeps the bridge cache in sync as the user types. */
	window_text_register_gtk(hLabel, rw.label_entry);
	g_signal_connect(rw.label_entry, "changed",
	                 G_CALLBACK(window_text_on_entry_changed), (gpointer)hLabel);

	/* Track user-initiated label edits so SetProposedLabel() doesn't clobber them.
	 * app_changed_label is set TRUE by SetProposedLabel() before it calls
	 * gtk_entry_set_text(), preventing the signal from setting user_changed_label. */
	g_signal_connect(rw.label_entry, "changed",
	                 G_CALLBACK(_label_user_changed_handler), NULL);

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
	CreateTooltip((HWND)rw.filesystem_combo,      lmprintf(MSG_157), -1);
	CreateTooltip((HWND)rw.cluster_combo,         lmprintf(MSG_158), -1);
	CreateTooltip((HWND)rw.label_entry,           lmprintf(MSG_159), -1);
	CreateTooltip((HWND)rw.partition_combo,       lmprintf(MSG_163), -1);
	CreateTooltip((HWND)rw.target_combo,          lmprintf(MSG_150), 30000);
	CreateTooltip((HWND)rw.boot_combo,            lmprintf(MSG_164), -1);
	CreateTooltip((HWND)rw.select_btn,            lmprintf(MSG_165), -1);
	CreateTooltip((HWND)rw.start_btn,             lmprintf(MSG_171), -1);
	if (rw.bad_blocks_check)
		CreateTooltip((HWND)rw.bad_blocks_check,  lmprintf(MSG_161), -1);
	if (rw.quick_format_check)
		CreateTooltip((HWND)rw.quick_format_check,lmprintf(MSG_162), -1);
	if (rw.uefi_validation_check)
		CreateTooltip((HWND)rw.uefi_validation_check, lmprintf(MSG_167), 10000);
	if (rw.old_bios_check)
		CreateTooltip((HWND)rw.old_bios_check,    lmprintf(MSG_169), -1);
	if (rw.extended_label_check)
		CreateTooltip((HWND)rw.extended_label_check, lmprintf(MSG_166), 10000);
	if (rw.list_usb_hdd_check)
		CreateTooltip((HWND)rw.list_usb_hdd_check,lmprintf(MSG_170), -1);
	if (rw.persistence_scale)
		CreateTooltip((HWND)rw.persistence_scale, lmprintf(MSG_125), 30000);
	if (rw.persistence_size)
		CreateTooltip((HWND)rw.persistence_size,  lmprintf(MSG_125), 30000);
	if (rw.persistence_units)
		CreateTooltip((HWND)rw.persistence_units, lmprintf(MSG_126), 30000);

	/* Set ATK accessible names on toolbar buttons so screen readers (Orca)
	 * announce the button function rather than the emoji label glyph name.
	 * Mirrors what SetAccessibleName() does for the Windows toolbar buttons. */
	SetAccessibleName((HWND)rw.lang_btn,     "Language");
	SetAccessibleName((HWND)rw.about_btn,    "About");
	SetAccessibleName((HWND)rw.settings_btn, "Settings");
	SetAccessibleName((HWND)rw.log_btn,      "Log");
	SetAccessibleName((HWND)rw.save_btn,     lmprintf(MSG_313));
	SetAccessibleName((HWND)rw.hash_btn,     lmprintf(MSG_314));
	SetAccessibleName((HWND)rw.select_btn,   lmprintf(MSG_165));
	SetAccessibleName((HWND)rw.start_btn,    lmprintf(MSG_171));
	SetAccessibleName((HWND)rw.close_btn,    "Close");

	/* Restore advanced expander state (mirrors Windows SETTING_ADVANCED_MODE_*) */
	{
		extern BOOL advanced_mode_device;
		if (ReadSettingBool(SETTING_ADVANCED_MODE_DEVICE)) {
			advanced_mode_device = TRUE;
			ToggleAdvancedDeviceOptions(TRUE);
			/* Re-populate boot combo now that advanced_mode_device is set */
			populate_boot_combo();
		}
		if (ReadSettingBool(SETTING_ADVANCED_MODE_FORMAT))
			ToggleAdvancedFormatOptions(TRUE);
	}

	/* Enumerate attached block devices and fill the device list. */
	GetDevices(0);

	/* Start the udev block-device hotplug monitor.  Events are debounced
	 * and delivered to hMainDialog as UM_MEDIA_CHANGE via PostMessage. */
	device_monitor_start(on_device_change, NULL);

	rufus_gtk_update_status(lmprintf(MSG_210));
	uprintf("*** Rufus GTK UI started ***");

	/* Run update check in background (SetUpdateCheck configures the interval,
	 * CheckForUpdates respects it and only actually contacts the server when
	 * the configured interval has elapsed since the last successful check). */
	if (SetUpdateCheck())
		CheckForUpdates(FALSE);

	/* Check for Fido (ISO download script) availability.
	 * If found, this posts UM_ENABLE_DOWNLOAD_ISO to reveal the Download ISO button. */
	SetFidoCheck();
}

int main(int argc, char *argv[])
{
	GtkApplication *app;
	int status;

	install_crash_handlers();

	/* Re-launch under pkexec if not already running as root.
	 * rufus_try_pkexec() does not return on success; on failure (pkexec not
	 * found, execv error) it returns and we continue without elevation — the
	 * existing "not running as root" warning in on_app_activate() will inform
	 * the user. */
	if (rufus_needs_elevation())
		rufus_try_pkexec(argc, argv);

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

