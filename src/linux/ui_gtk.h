/*
 * Rufus: The Reliable USB Formatting Utility
 * GTK UI header — widget registry and helpers
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
#pragma once

#include <gtk/gtk.h>

/* ---- Main window widget registry ---- */
typedef struct {
	GtkWidget *window;

	/* Device row */
	GtkWidget *device_combo;        /* IDC_DEVICE */

	/* Boot selection row */
	GtkWidget *boot_combo;          /* IDC_BOOT_SELECTION */
	GtkWidget *select_btn;          /* IDC_SELECT */

	/* Image option row */
	GtkWidget *image_option_combo;  /* IDC_IMAGE_OPTION */
	GtkWidget *image_option_row;    /* container – hidden when not needed */

	/* Drive properties section */
	GtkWidget *partition_combo;     /* IDC_PARTITION_TYPE */
	GtkWidget *target_combo;        /* IDC_TARGET_SYSTEM */
	GtkWidget *filesystem_combo;    /* IDC_FILE_SYSTEM */
	GtkWidget *cluster_combo;       /* IDC_CLUSTER_SIZE */
	GtkWidget *label_entry;         /* IDC_LABEL */

	/* Advanced device options (collapsible) */
	GtkWidget *adv_device_expander;
	GtkWidget *list_usb_hdd_check;  /* IDC_LIST_USB_HDD */
	GtkWidget *uefi_validation_check; /* IDC_UEFI_MEDIA_VALIDATION */

	/* Format options section */
	GtkWidget *quick_format_check;  /* IDC_QUICK_FORMAT */
	GtkWidget *bad_blocks_check;    /* IDC_BAD_BLOCKS */
	GtkWidget *nb_passes_combo;     /* IDC_NB_PASSES */

	/* Advanced format options (collapsible) */
	GtkWidget *adv_format_expander;
	GtkWidget *old_bios_check;      /* IDC_OLD_BIOS_FIXES */

	/* Persistence row (shown only for compatible images) */
	GtkWidget *persistence_row;
	GtkWidget *persistence_scale;   /* IDC_PERSISTENCE_SLIDER */
	GtkWidget *persistence_size;    /* IDC_PERSISTENCE_SIZE (label) */
	GtkWidget *persistence_units;   /* IDC_PERSISTENCE_UNITS */

	/* Status / progress section */
	GtkWidget *progress_bar;        /* IDC_PROGRESS */
	GtkWidget *status_label;        /* IDC_STATUS */

	/* Main action buttons */
	GtkWidget *start_btn;           /* IDC_START */
	GtkWidget *close_btn;           /* IDCANCEL */

	/* Toolbar buttons (top-right) */
	GtkWidget *lang_btn;            /* IDC_LANG */
	GtkWidget *about_btn;           /* IDC_ABOUT */
	GtkWidget *settings_btn;        /* IDC_SETTINGS */
	GtkWidget *log_btn;             /* IDC_LOG */
	GtkWidget *save_btn;            /* IDC_SAVE */
	GtkWidget *hash_btn;            /* IDC_HASH */

	/* Log dialog */
	GtkWidget *log_dialog;
	GtkWidget *log_textview;
	GtkTextBuffer *log_textbuf;

	/* Row label widgets — updated by apply_localization for IDS_* IDs */
	GtkWidget *device_label;          /* IDS_DEVICE_TXT        (2000) */
	GtkWidget *partition_type_label;  /* IDS_PARTITION_TYPE_TXT (2001) */
	GtkWidget *filesystem_label;      /* IDS_FILE_SYSTEM_TXT    (2002) */
	GtkWidget *cluster_size_label;    /* IDS_CLUSTER_SIZE_TXT   (2003) */
	GtkWidget *volume_label_label;    /* IDS_LABEL_TXT          (2004) */
	GtkWidget *target_system_label;   /* IDS_TARGET_SYSTEM_TXT  (2013) */
	GtkWidget *image_option_label;    /* IDS_IMAGE_OPTION_TXT   (2014) */
	GtkWidget *boot_selection_label;  /* IDS_BOOT_SELECTION_TXT (2015) */
	GtkWidget *drive_props_label;     /* IDS_DRIVE_PROPERTIES_TXT (2016) */
	GtkWidget *format_options_label;  /* IDS_FORMAT_OPTIONS_TXT (2017) */
	GtkWidget *status_txt_label;      /* IDS_STATUS_TXT         (2018) */
} RufusWidgets;

extern RufusWidgets rw;

/* ---- Helper macros ---- */

/* Safely set a GtkComboBoxText entry by index. */
static inline void gtk_combo_set_active_by_data(GtkWidget *combo, gint data)
{
	GtkTreeModel *model = gtk_combo_box_get_model(GTK_COMBO_BOX(combo));
	GtkTreeIter iter;
	gboolean valid = gtk_tree_model_get_iter_first(model, &iter);
	int i = 0;
	while (valid) {
		if (i == data) {
			gtk_combo_box_set_active_iter(GTK_COMBO_BOX(combo), &iter);
			return;
		}
		i++;
		valid = gtk_tree_model_iter_next(model, &iter);
	}
	if (gtk_tree_model_get_iter_first(model, &iter))
		gtk_combo_box_set_active_iter(GTK_COMBO_BOX(combo), &iter);
}

/* GTK-specific prototypes */
GtkWidget *rufus_gtk_create_window(GtkApplication *app);
void       rufus_gtk_update_status(const char *msg);
void       rufus_gtk_append_log(const char *msg);

/* Linux-specific initialization (defined in rufus.c) */
void rufus_init_paths(void);
