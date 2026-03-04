/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux port — Window title progress indicator helper
 * Copyright © 2025 PsychedelicPalimpsest
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

#include <stdio.h>
#include <stddef.h>
#include "rufus.h"     /* for BOOL */

/*
 * build_progress_title - build a window title string reflecting operation progress.
 *
 *  buf         - output buffer
 *  bufsz       - size of output buffer
 *  base        - base window title (e.g. "Rufus 4.6")
 *  in_progress - TRUE while a format/hash/download operation is running
 *  pct         - current progress percentage [0, 100]
 *
 * When in_progress is TRUE and 0 <= pct < 100, the title becomes "(NN%) BASE".
 * Otherwise (operation done or not running), the base title is used as-is.
 */
void build_progress_title(char *buf, size_t bufsz, const char *base,
                           BOOL in_progress, double pct)
{
	if (in_progress && pct >= 0.0 && pct < 100.0)
		snprintf(buf, bufsz, "(%.0f%%) %s", pct, base);
	else
		snprintf(buf, bufsz, "%s", base);
}
