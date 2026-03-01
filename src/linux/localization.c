/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux-specific localization functions
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
 * Linux-specific UI hooks for localization.
 * The portable core (parse_cmd, message tables, dispatch_loc_cmd, lmprintf, etc.)
 * lives in src/common/localization.c.
 * GTK apply_localization will be implemented here once the GTK UI is in place.
 */

#include <stdio.h>
#include <stdarg.h>

#include "rufus.h"
#include "resource.h"
#include "localization.h"

/*
 * Apply stored localization commands to a dialog.
 * TODO: implement once GTK UI is integrated.
 */
void apply_localization(int dlg_id, HWND hDlg)
{
	(void)dlg_id;
	(void)hDlg;
}

/*
 * Notify the localization system that a dialog has been destroyed.
 */
void reset_localization(int dlg_id)
{
	(void)dlg_id;
}

/*
 * Display a localized status/info message.
 * On Linux we just log via uprintf for now.
 */
void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration, int msg_id, ...)
{
	char buf[256];
	char *format = NULL;
	va_list args;

	(void)info; (void)duration;

	if (msg_id < 0)
		return;

	if ((msg_id >= MSG_000) && (msg_id < MSG_MAX))
		format = msg_table[msg_id - MSG_000];
	if (format == NULL)
		return;

	va_start(args, msg_id);
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);
	buf[sizeof(buf) - 1] = '\0';

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

