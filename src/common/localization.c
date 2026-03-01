/*
 * Rufus: The Reliable USB Formatting Utility
 * Portable localization functions (shared between Windows and Linux builds)
 * Copyright © 2013-2025 Pete Batard <pete@akeo.ie>
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
 * This file contains the platform-independent localization functions extracted
 * from windows/localization.c.  It must not contain any Windows UI calls
 * (no GetDlgItem, no SetWindowTextU, no SetTimer, etc.).
 *
 * OS-specific UI functions (apply_localization, PrintStatusInfo, get_language_id)
 * live in src/windows/localization.c and src/linux/localization.c respectively.
 */

#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>

#include "rufus.h"
#include "localization.h"
#include "localization_data.h"

/*
 * List of supported locale commands, with their parameter syntax:
 *   c: control ID (no space, no quotes)
 *   s: quoted string
 *   i: 32-bit signed integer
 *   u: 32-bit unsigned CSV list
 */
const loc_parse parse_cmd[7] = {
	/* Translation name and Windows LCIDs it should apply to */
	{ 'l', LC_LOCALE,     "ssu" },  /* l "en_US" "English (US)" 0x0009,0x1009 */
	/* Base translation to build on top of */
	{ 'b', LC_BASE,       "s"   },  /* b "en_US" */
	/* Version required for this locale */
	{ 'v', LC_VERSION,    "u"   },  /* v 1.0.2 */
	/* Translate a control's text */
	{ 't', LC_TEXT,       "cs"  },  /* t IDC_CONTROL "Translation" */
	/* Set the dialog section for following commands */
	{ 'g', LC_GROUP,      "c"   },  /* g IDD_DIALOG */
	/* Set the font to use */
	{ 'f', LC_FONT,       "si"  },  /* f "MS Dialog" 10 */
	/* Set locale attributes */
	{ 'a', LC_ATTRIBUTES, "s"   },  /* a "ra" */
};

/* Hash table for reused translation commands */
static htab_table htab_loc = HTAB_EMPTY;

/* Globals */
int    loc_line_nr;
struct list_head locale_list = {NULL, NULL};
char   *loc_filename = NULL, *embedded_loc_filename = (char*)"embedded.loc";
static BOOL localization_initialized = FALSE;

/* Message tables */
char* default_msg_table[MSG_MAX - MSG_000] = {"%s", 0};
char* current_msg_table[MSG_MAX - MSG_000] = {"%s", 0};
char** msg_table = NULL;

static void mtab_destroy(BOOL reinit)
{
	size_t j;
	for (j = 1; j < MSG_MAX - MSG_000; j++) {
		safe_free(current_msg_table[j]);
		if (!reinit)
			safe_free(default_msg_table[j]);
	}
}

/*
 * Add a localization command to a dialog/section.
 */
void add_dialog_command(int index, loc_cmd* lcmd)
{
	char str[128];
	loc_cmd* htab_lcmd;
	uint32_t i;

	if ((lcmd == NULL) || (lcmd->txt[0] == NULL) || (index < 0) || (index >= ARRAYSIZE(loc_dlg))) {
		uprintf("localization: invalid parameter for add_dialog_command\n");
		return;
	}

	str[0] = (char)(index + 0x30);
	str[1] = (char)(lcmd->command + 0x30);
	safe_strcpy(&str[2], sizeof(str) - 2, lcmd->txt[0]);
	i = htab_hash(str, &htab_loc);
	if (i != 0) {
		htab_lcmd = (loc_cmd*)(htab_loc.table[i].data);
		if (htab_lcmd != NULL) {
			list_del(&(htab_lcmd->list));
			free_loc_cmd(htab_lcmd);
		}
		htab_loc.table[i].data = (void*)lcmd;
	}
	list_add(&lcmd->list, &loc_dlg[index].list);
}

/*
 * Add a translated message to the direct lookup table.
 */
void add_message_command(loc_cmd* lcmd)
{
	if (lcmd == NULL) {
		uprintf("localization: invalid parameter for add_message_command\n");
		return;
	}

	if ((lcmd->ctrl_id <= MSG_000) || (lcmd->ctrl_id >= MSG_MAX)) {
		uprintf("localization: invalid MSG_ index\n");
		return;
	}

	safe_free(msg_table[lcmd->ctrl_id - MSG_000]);
	msg_table[lcmd->ctrl_id - MSG_000] = lcmd->txt[1];
	lcmd->txt[1] = NULL;
}

void free_loc_cmd(loc_cmd* lcmd)
{
	if (lcmd == NULL)
		return;
	safe_free(lcmd->txt[0]);
	safe_free(lcmd->txt[1]);
	safe_free(lcmd->unum);
	free(lcmd);
}

void free_dialog_list(void)
{
	size_t i;
	loc_cmd *lcmd, *next;

	for (i = 0; i < ARRAYSIZE(loc_dlg); i++) {
		if (list_empty(&loc_dlg[i].list))
			continue;
		list_for_each_entry_safe(lcmd, next, &loc_dlg[i].list, loc_cmd, list) {
			list_del(&lcmd->list);
			free_loc_cmd(lcmd);
		}
	}
}

void free_locale_list(void)
{
	loc_cmd *lcmd, *next;

	list_for_each_entry_safe(lcmd, next, &locale_list, loc_cmd, list) {
		list_del(&lcmd->list);
		free_loc_cmd(lcmd);
	}
}

/*
 * Initialize/destroy localization lists.
 * Locale list and filename are preserved on reinit.
 */
void _init_localization(BOOL reinit)
{
	size_t i;

	for (i = 0; i < ARRAYSIZE(loc_dlg); i++)
		list_init(&loc_dlg[i].list);
	if (!reinit)
		list_init(&locale_list);
	htab_create(LOC_HTAB_SIZE, &htab_loc);
	localization_initialized = TRUE;
}

void _exit_localization(BOOL reinit)
{
	if (!localization_initialized)
		return;
	if (!reinit) {
		free_locale_list();
		if (loc_filename != embedded_loc_filename)
			safe_free(loc_filename);
	}
	free_dialog_list();
	mtab_destroy(reinit);
	htab_destroy(&htab_loc);
	if (!reinit)
		msg_table = NULL;
	localization_initialized = FALSE;
}

/*
 * Validate and store a localization command.
 */
BOOL dispatch_loc_cmd(loc_cmd* lcmd)
{
	size_t i;
	static int dlg_index = 0;
	loc_cmd* base_locale = NULL;
	const char* msg_prefix = "MSG_";

	if (lcmd == NULL)
		return FALSE;

	if (lcmd->command <= LC_TEXT) {
		if (safe_strncmp(lcmd->txt[0], msg_prefix, 4) == 0) {
			if ((lcmd->txt[0] == NULL) || (lcmd->command != LC_TEXT)) {
				luprint("only the [t]ext command can be applied to a message (MSG_###)\n");
				goto err;
			}
			lcmd->ctrl_id = MSG_000 + atoi(&(lcmd->txt[0][4]));
			if (lcmd->ctrl_id == MSG_000) {
				luprintf("failed to convert the numeric value in '%s'\n", lcmd->txt[0]);
				goto err;
			}
			add_message_command(lcmd);
			free_loc_cmd(lcmd);
			return TRUE;
		}
		for (i = 0; i < ARRAYSIZE(control_id); i++) {
			if (safe_strcmp(lcmd->txt[0], control_id[i].name) == 0) {
				lcmd->ctrl_id = control_id[i].id;
				break;
			}
		}
		if (lcmd->ctrl_id < 0) {
			luprintf("unknown control '%s'\n", lcmd->txt[0]);
			goto err;
		}
	}

	/* Skip UI commands when populating the default table */
	if (msg_table == default_msg_table) {
		free_loc_cmd(lcmd);
		return TRUE;
	}

	switch (lcmd->command) {
	case LC_TEXT:
		add_dialog_command(dlg_index, lcmd);
		break;
	case LC_GROUP:
		if ((lcmd->ctrl_id - IDD_DIALOG) > (int)ARRAYSIZE(loc_dlg)) {
			luprintf("'%s' is not a group ID\n", lcmd->txt[0]);
			goto err;
		}
		dlg_index = lcmd->ctrl_id - IDD_DIALOG;
		free_loc_cmd(lcmd);
		break;
	case LC_BASE:
		base_locale = get_locale_from_name(lcmd->txt[0], FALSE);
		if (base_locale != NULL) {
			uprintf("localization: using locale base '%s'\n", lcmd->txt[0]);
			get_loc_data_file(NULL, base_locale);
		} else {
			luprintf("locale base '%s' not found - ignoring", lcmd->txt[0]);
		}
		free_loc_cmd(lcmd);
		break;
	default:
		free_loc_cmd(lcmd);
		break;
	}
	return TRUE;

err:
	free_loc_cmd(lcmd);
	return FALSE;
}

/*
 * Produce a formatted localized message string.
 * Uses a rolling buffer pool to allow concurrent calls.
 */
char* lmprintf(uint32_t msg_id, ...)
{
	static int buf_id = 0;
	static char buf[LOC_MESSAGE_NB][LOC_MESSAGE_SIZE];
	char *format = NULL;
	size_t pos = 0;
	va_list args;
	BOOL is_rtf = (msg_id & MSG_RTF);

	buf_id %= LOC_MESSAGE_NB;
	buf[buf_id][0] = 0;

	msg_id &= MSG_MASK;
	if ((msg_id >= MSG_000) && (msg_id < MSG_MAX))
		format = msg_table[msg_id - MSG_000];

	if (format == NULL) {
		safe_sprintf(buf[buf_id], LOC_MESSAGE_SIZE - 1, "MSG_%03u UNTRANSLATED", msg_id - MSG_000);
	} else {
		if (right_to_left_mode && (msg_table != default_msg_table)) {
			if (is_rtf) {
				safe_strcpy(&buf[buf_id][pos], LOC_MESSAGE_SIZE - 1, "\\rtlch");
				pos += 6;
			}
			safe_strcpy(&buf[buf_id][pos], LOC_MESSAGE_SIZE - 1, RIGHT_TO_LEFT_EMBEDDING);
			pos += sizeof(RIGHT_TO_LEFT_EMBEDDING) - 1;
		}
		va_start(args, msg_id);
		safe_vsnprintf(&buf[buf_id][pos], LOC_MESSAGE_SIZE - 1 - 2 * pos, format, args);
		va_end(args);
		if (right_to_left_mode && (msg_table != default_msg_table)) {
			safe_strcat(buf[buf_id], LOC_MESSAGE_SIZE - 1, POP_DIRECTIONAL_FORMATTING);
			if (is_rtf)
				safe_strcat(buf[buf_id], LOC_MESSAGE_SIZE - 1, "\\ltrch");
		}
		buf[buf_id][LOC_MESSAGE_SIZE - 1] = '\0';
	}
	return buf[buf_id++];
}

/*
 * Find a locale command by LCID.  Falls back to the first locale if fallback is TRUE.
 */
loc_cmd* get_locale_from_lcid(int lcid, BOOL fallback)
{
	loc_cmd* lcmd = NULL;
	int i;

	if (list_empty(&locale_list)) {
		uprintf("localization: the locale list is empty!\n");
		return NULL;
	}

	list_for_each_entry(lcmd, &locale_list, loc_cmd, list) {
		for (i = 0; i < lcmd->unum_size; i++) {
			if ((int)lcmd->unum[i] == lcid)
				return lcmd;
		}
	}

	if (!fallback)
		return NULL;

	lcmd = list_entry(locale_list.next, loc_cmd, list);
	uprintf("localization: could not find locale for LCID: 0x%04X. Will default to '%s'\n", lcid, lcmd->txt[0]);
	return lcmd;
}

/*
 * Find a locale command by name.  Falls back to the first locale if fallback is TRUE.
 */
loc_cmd* get_locale_from_name(char* locale_name, BOOL fallback)
{
	loc_cmd* lcmd = NULL;

	if (list_empty(&locale_list)) {
		uprintf("localization: the locale list is empty!\n");
		return NULL;
	}

	list_for_each_entry(lcmd, &locale_list, loc_cmd, list) {
		if (safe_strcmp(lcmd->txt[0], locale_name) == 0)
			return lcmd;
	}

	if (!fallback)
		return NULL;

	lcmd = list_entry(locale_list.next, loc_cmd, list);
	uprintf("localization: could not find locale for name '%s'. Will default to '%s'\n", locale_name, lcmd->txt[0]);
	return lcmd;
}

/*
 * Toggle issuing messages with the default (English) locale.
 */
void toggle_default_locale(void)
{
	static char** old_msg_table = NULL;

	if (old_msg_table == NULL) {
		old_msg_table = msg_table;
		msg_table = default_msg_table;
	} else {
		msg_table = old_msg_table;
		old_msg_table = NULL;
	}
}

/*
 * Look up a control name from its integer ID.
 */
const char* get_name_from_id(int id)
{
	int i;
	for (i = 0; i < ARRAYSIZE(control_id); i++) {
		if (control_id[i].id == id)
			return control_id[i].name;
	}
	return "UNKNOWN ID";
}

/* -----------------------------------------------------------------------
 * Accessors so linux/localization.c can use loc_dlg without including
 * localization_data.h (which defines the array via Windows resource IDs).
 * ----------------------------------------------------------------------- */
int get_loc_dlg_count(void)
{
	return (int)ARRAYSIZE(loc_dlg);
}

loc_dlg_list *get_loc_dlg_entry(int i)
{
	return &loc_dlg[i];
}
