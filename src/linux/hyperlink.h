/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux: Pango-markup hyperlink builder — public API
 * Copyright © 2025 Rufus contributors
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
#include <stddef.h>

/*
 * hyperlink_build_markup — build a Pango "<a href="URL">TEXT</a>" markup
 * string into buf[bufsz].
 *
 *  url    — target URL (must not be NULL)
 *  text   — display text; if NULL or empty, `url` is used as the label
 *  buf    — output buffer
 *  bufsz  — buffer size in bytes
 *
 * XML-special characters (&, <, >, ", ') are escaped.
 *
 * Returns the number of bytes written (not counting NUL), or -1 on error.
 * Output is always NUL-terminated when bufsz > 0.
 */
int hyperlink_build_markup(const char *url, const char *text,
                           char *buf, size_t bufsz);
