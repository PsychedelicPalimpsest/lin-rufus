/*
 * Rufus: The Reliable USB Formatting Utility
 * Localization functions, a.k.a. "Everybody is doing it wrong but me!"
 * Copyright © 2013-2023 Pete Batard <pete@akeo.ie>
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

/* Memory leaks detection - define _CRTDBG_MAP_ALLOC as preprocessor macro */
#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <windows.h>
#include <windowsx.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stddef.h>

#include "rufus.h"
#include "resource.h"
#include "msapi_utf8.h"
#include "localization.h"
#include "localization_data.h"

/* Portable functions (parse_cmd[], globals, free_loc_cmd,
 * dispatch_loc_cmd, lmprintf, get_locale_from_lcid/name,
 * toggle_default_locale, get_name_from_id) are in src/common/localization.c */

/*
 * Apply stored localization commands to a specific dialog
 * If hDlg is NULL, apply the commands against an active Window
 */
void apply_localization(int dlg_id, HWND hDlg)
{
	loc_cmd* lcmd;
	HWND hCtrl = NULL;
	int id_start = IDD_DIALOG, id_end = IDD_DIALOG + ARRAYSIZE(loc_dlg);

	if ((dlg_id >= id_start) && (dlg_id < id_end)) {
		// If we have a valid dialog_id, just process that one dialog
		id_start = dlg_id;
		id_end = dlg_id + 1;
		if (hDlg != NULL) {
			loc_dlg[dlg_id-IDD_DIALOG].hDlg = hDlg;
		}
	}

	for (dlg_id = id_start; dlg_id < id_end; dlg_id++) {
		hDlg = loc_dlg[dlg_id-IDD_DIALOG].hDlg;
		if ((!IsWindow(hDlg)) || (list_empty(&loc_dlg[dlg_id-IDD_DIALOG].list)))
			continue;

		list_for_each_entry(lcmd, &loc_dlg[dlg_id-IDD_DIALOG].list, loc_cmd, list) {
			if (lcmd->command <= LC_TEXT) {
				if (lcmd->ctrl_id == dlg_id) {
					if ((dlg_id == IDD_DIALOG) && (lcmd->txt[1] != NULL) && (lcmd->txt[1][0] != 0)) {
						loc_line_nr = lcmd->line_nr;
						luprint("operation forbidden (main dialog title cannot be changed)");
						continue;
					}
					hCtrl = hDlg;
					if (dlg_id == IDD_DIALOG)
						hDlg = NULL;
				} else {
					hCtrl = GetDlgItem(hDlg, lcmd->ctrl_id);
				}
				if ((hCtrl == NULL) && (hDlg != NULL)) {
					loc_line_nr = lcmd->line_nr;
					luprintf("control '%s' is not part of dialog '%s'\n",
						lcmd->txt[0], control_id[dlg_id-IDD_DIALOG].name);
				}
			}

			switch(lcmd->command) {
			case LC_TEXT:
				if (hCtrl != NULL) {
					if ((lcmd->txt[1] != NULL) && (lcmd->txt[1][0] != 0))
						SetWindowTextU(hCtrl, lcmd->txt[1]);
				}
				break;
			}
		}
	}
}

/*
 * This function should be called when a localized dialog is destroyed
 * NB: we can't use isWindow() against our existing HWND to avoid this call
 * as handles are recycled.
 */
void reset_localization(int dlg_id)
{
	loc_dlg[dlg_id-IDD_DIALOG].hDlg = NULL;
}

}

/*
 * The following calls help display a localized message on the info field or status bar as well as its
 * _English_ counterpart in the log (if debug is set).
 * If duration is non zero, that message is displayed for at least duration ms, regardless of
 * any other incoming message. After that time, the display reverts to the last non-timeout message.
 */
// TODO: handle a timeout message overriding a timeout message
#define MSG_LEN      256
#define MSG_STATUS   0
#define MSG_INFO     1
#define MSG_LOW_PRI  0
#define MSG_HIGH_PRI 1
char szMessage[2][2][MSG_LEN] = { {"", ""}, {"", ""} };
char* szStatusMessage = szMessage[MSG_STATUS][MSG_HIGH_PRI];
static BOOL bStatusTimerArmed = FALSE, bOutputTimerArmed[2] = { FALSE, FALSE };
static char *output_msg[2];
static uint64_t last_msg_time[2] = { 0, 0 };

static void PrintInfoMessage(char* msg) {
	SetWindowTextU(hProgress, msg);
	InvalidateRect(hProgress, NULL, TRUE);
}
static void PrintStatusMessage(char* msg) {
	SendMessageLU(hStatus, SB_SETTEXTW, SBT_OWNERDRAW | SB_SECTION_LEFT, msg);
}
typedef void PRINT_FUNCTION(char*);
PRINT_FUNCTION *PrintMessage[2] = { PrintInfoMessage, PrintStatusMessage };

/*
 * The following timer call is used, along with MAX_REFRESH, to prevent obnoxious flicker
 * on the Info and Status fields due to messages being updated too quickly.
 */
static void CALLBACK OutputMessageTimeout(HWND hWnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
	int i = (idEvent == TID_OUTPUT_INFO)? 0 : 1;

	KillTimer(hMainDialog, idEvent);
	bOutputTimerArmed[i] = FALSE;

	PrintMessage[i](output_msg[i]);
	last_msg_time[i] = GetTickCount64();
}

static void OutputMessage(BOOL info, char* msg)
{
	uint64_t delta;
	int i = info ? 0 : 1;

	if (bOutputTimerArmed[i]) {
		// Already have a delayed message going - just change that message to latest
		output_msg[i] = msg;
	} else {
		// Find if we need to arm a timer
		delta = GetTickCount64() - last_msg_time[i];
		if (delta < (2 * MAX_REFRESH)) {
			// Not enough time has elapsed since our last output => arm a timer
			output_msg[i] = msg;
			SetTimer(hMainDialog, TID_OUTPUT_INFO + i, (UINT)((2 * MAX_REFRESH) - delta), OutputMessageTimeout);
			bOutputTimerArmed[i] = TRUE;
		} else {
			PrintMessage[i](msg);
			last_msg_time[i] = GetTickCount64();
		}
	}
}

static void CALLBACK PrintMessageTimeout(HWND hWnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
	bStatusTimerArmed = FALSE;
	// We're going to print high priority message, so restore our pointer
	if (idEvent != TID_MESSAGE_INFO)
		szStatusMessage = szMessage[MSG_STATUS][MSG_HIGH_PRI];
	OutputMessage((idEvent == TID_MESSAGE_INFO), szMessage[(idEvent == TID_MESSAGE_INFO)?MSG_INFO:MSG_STATUS][MSG_HIGH_PRI]);
	KillTimer(hMainDialog, idEvent);
}

void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration, int msg_id, ...)
{
	char *format = NULL, buf[MSG_LEN];
	char *msg_hi = szMessage[info?MSG_INFO:MSG_STATUS][MSG_HIGH_PRI];
	char *msg_lo = szMessage[info?MSG_INFO:MSG_STATUS][MSG_LOW_PRI];
	char *msg_cur = (duration > 0)?msg_lo:msg_hi;
	va_list args;

	if (msg_id < 0) {
		// A negative msg_id clears the message
		msg_hi[0] = 0;
		OutputMessage(info, msg_hi);
		return;
	}

	if ((msg_id < MSG_000) || (msg_id >= MSG_MAX)) {
		uprintf("PrintStatusInfo: invalid MSG_ID\n");
		return;
	}

	// We need to keep track of where szStatusMessage should point to so that ellipses work
	if (!info)
		szStatusMessage = szMessage[MSG_STATUS][(duration > 0)?MSG_LOW_PRI:MSG_HIGH_PRI];

	if ((msg_id >= MSG_000) && (msg_id < MSG_MAX))
		format = msg_table[msg_id - MSG_000];
	if (format == NULL) {
		safe_sprintf(msg_hi, MSG_LEN, "MSG_%03d UNTRANSLATED", msg_id - MSG_000);
		uprintf(msg_hi);
		OutputMessage(info, msg_hi);
		return;
	}

	va_start(args, msg_id);
	safe_vsnprintf(msg_cur, MSG_LEN, format, args);
	va_end(args);
	msg_cur[MSG_LEN - 1] = '\0';

	if ((duration != 0) || (!bStatusTimerArmed))
		OutputMessage(info, msg_cur);

	if (duration != 0) {
		SetTimer(hMainDialog, (info)?TID_MESSAGE_INFO:TID_MESSAGE_STATUS, duration, PrintMessageTimeout);
		bStatusTimerArmed = TRUE;
	}

	// Because we want the log messages in English, we go through the VA business once more, but this time with default_msg_table
	if (debug) {
		if ((msg_id >= MSG_000) && (msg_id < MSG_MAX))
			format = default_msg_table[msg_id - MSG_000];
		if (format == NULL) {
			safe_sprintf(buf, sizeof(szStatusMessage), "(default) MSG_%03d UNTRANSLATED", msg_id - MSG_000);
			return;
		}
		va_start(args, msg_id);
		safe_vsnprintf(buf, MSG_LEN, format, args);
		va_end(args);
		buf[MSG_LEN - 1] = '\0';
		// buf may(?) containt a '%' so don't feed it as a naked format string
		uprintf("%s", buf);
	}
}

 * pack having been installed.
 */
static BOOL found_lang;
static BOOL CALLBACK EnumUILanguagesProc(LPWSTR lpUILanguageString, LONG_PTR lParam)
{
	wchar_t* wlang = (wchar_t*)lParam;
	if (wcscmp(wlang, lpUILanguageString) == 0)
		found_lang = TRUE;
	return TRUE;
}

WORD get_language_id(loc_cmd* lcmd)
{
	int i;
	wchar_t wlang[5];
	LANGID lang_id = GetUserDefaultUILanguage();

	if (lcmd == NULL)
		return MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

	// Find if the selected language is the user default
	for (i = 0; i<lcmd->unum_size; i++) {
		if (lcmd->unum[i] == lang_id) {
			ubprintf("Will use default UI locale 0x%04X", lang_id);
			return MAKELANGID(lang_id, SUBLANG_DEFAULT);
		}
	}

	// Selected language is not user default - find if a language pack is installed for it
	found_lang = FALSE;
	for (i = 0; (i<lcmd->unum_size); i++) {
		// Always uppercase
		_snwprintf(wlang, ARRAYSIZE(wlang), L"%04X", lcmd->unum[i]);
		// This callback enumeration from Microsoft is retarded. Now we need a global
		// boolean to tell us that we found what we were after.
		EnumUILanguages(EnumUILanguagesProc, 0x4, (LONG_PTR)wlang);	// 0x04 = MUI_LANGUAGE_ID
		if (found_lang) {
			ubprintf("Detected installed Windows Language Pack for 0x%04X (%s)", lcmd->unum[i], lcmd->txt[1]);
			return MAKELANGID(lcmd->unum[i], SUBLANG_DEFAULT);
		}
	}

	ubprintf("NOTE: No Windows Language Pack is installed for %s on this system.\r\n"
		"This means that some controls may still be displayed using the system locale.", lcmd->txt[1]);
	return MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
}
