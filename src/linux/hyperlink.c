/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux: Pango-markup hyperlink builder
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

#include <stddef.h>
#include "hyperlink.h"

/*
 * hyperlink_build_markup — build a Pango `<a href="URL">TEXT</a>` markup
 * string from url and text into buf[bufsz].
 *
 * XML-special characters in url and text are escaped as XML entities:
 *   & → &amp;   < → &lt;   > → &gt;   " → &quot;   ' → &apos;
 *
 * Returns the number of bytes written (not counting the NUL terminator),
 * or -1 if buf is NULL / bufsz is 0 / url is NULL.
 * The output is always NUL-terminated when bufsz > 0.
 *
 * This function is intentionally free of GLib / GTK so it can be exercised
 * by unit tests that run without a display.
 */
int hyperlink_build_markup(const char *url, const char *text,
                           char *buf, size_t bufsz)
{
	size_t pos = 0;
	const char *display;
	const char *p;

	if (buf == NULL || bufsz == 0 || url == NULL)
		return -1;
	buf[0] = '\0';

	display = (text != NULL && *text != '\0') ? text : url;

#define APPEND_CH(c) do { \
	if (pos + 1 < bufsz) buf[pos++] = (char)(c); \
	else goto trunc; } while(0)
#define APPEND_STR(s) do { \
	const char *_q = (s); \
	while (*_q) { APPEND_CH(*_q); _q++; } } while(0)
/* Emit one XML-escaped character */
#define APPEND_ESC(c) do { \
	switch ((unsigned char)(c)) { \
	case '&':  APPEND_STR("&amp;");  break; \
	case '<':  APPEND_STR("&lt;");   break; \
	case '>':  APPEND_STR("&gt;");   break; \
	case '"':  APPEND_STR("&quot;"); break; \
	case '\'': APPEND_STR("&apos;"); break; \
	default:   APPEND_CH(c);         break; } } while(0)

	APPEND_STR("<a href=\"");
	for (p = url; *p; p++)
		APPEND_ESC(*p);
	APPEND_STR("\">");
	for (p = display; *p; p++)
		APPEND_ESC(*p);
	APPEND_STR("</a>");

#undef APPEND_CH
#undef APPEND_STR
#undef APPEND_ESC

trunc:
	buf[pos < bufsz ? pos : bufsz - 1] = '\0';
	return (int)pos;
}
