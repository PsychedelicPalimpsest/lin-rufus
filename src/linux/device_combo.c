/*
 * Rufus: The Reliable USB Formatting Utility
 * Device combo context-menu helpers
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

#include "device_combo.h"
#include <stdio.h>
#include <string.h>

/*
 * device_open_in_fm_build_cmd — build "xdg-open <dev_path>" into out[sz].
 *
 * Returns 1 on success, 0 on invalid input or buffer too small.
 */
int device_open_in_fm_build_cmd(const char *dev_path, char *out, size_t sz)
{
	if (!dev_path || dev_path[0] == '\0' || !out || sz == 0)
		return 0;

	int n = snprintf(out, sz, "xdg-open %s", dev_path);
	if (n < 0 || (size_t)n >= sz)
		return 0;

	return 1;
}
