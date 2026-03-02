/*
 * format.c — Portable format helper functions
 *
 * Contains pure-C helpers shared by both the Linux and Windows format
 * code paths.  No OS-specific I/O is performed here.
 *
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
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

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "rufus.h"
#include "drive.h"
#include "label.h"

/*
 * utf8_seqlen — return the number of bytes in the UTF-8 sequence starting
 * at byte c, or 1 for any invalid / continuation byte.
 */
static int utf8_seqlen(unsigned char c)
{
	if (c < 0x80) return 1;
	if (c < 0xC0) return 1;  /* continuation byte or invalid: consume one */
	if (c < 0xE0) return 2;
	if (c < 0xF0) return 3;
	return 4;
}

/*
 * ToValidLabel — see format.h for full documentation.
 */
void ToValidLabel(char *Label, BOOL bFAT)
{
	static const char unauthorized[] = "*?,;:/\\|+=<>[]\"";
	static const char to_underscore[] = "\t.";
	/* Maximum output characters (code points, not bytes):
	 *   FAT:  11 (ASCII-only, so chars == bytes)
	 *   NTFS: 32 (may be multi-byte UTF-8, but we count codepoints) */
	const size_t max_cp = bFAT ? 11 : 32;
	/* Output buffer: worst case same length as input + NUL */
	char out[256] = {0};
	size_t k = 0;        /* bytes written to out               */
	size_t cp = 0;       /* codepoints written (for truncation)*/
	size_t in_len;
	const char *p;
	unsigned char c;
	size_t underscore_count, i;

	if (Label == NULL)
		return;

	in_len = strlen(Label);
	p      = Label;

	while ((size_t)(p - Label) < in_len && cp < max_cp && k < sizeof(out) - 4) {
		c = (unsigned char)*p;

		/* --- Non-ASCII byte ------------------------------------------- */
		if (c >= 0x80) {
			int seq = utf8_seqlen(c);
			if (bFAT) {
				/* FAT: whole UTF-8 code point → one underscore */
				out[k++] = '_';
				cp++;
			} else {
				/* NTFS: pass through the full UTF-8 sequence */
				int j;
				for (j = 0; j < seq && (size_t)(p - Label) + j < in_len
				     && k < sizeof(out) - 1; j++)
					out[k++] = p[j];
				cp++;
			}
			p += seq;
			continue;
		}

		/* --- Unauthorized char: skip ---------------------------------- */
		if (strchr(unauthorized, (int)c)) {
			p++;
			continue;
		}

		/* --- Convert to underscore ------------------------------------ */
		if (strchr(to_underscore, (int)c)) {
			out[k++] = '_';
			cp++;
			p++;
			continue;
		}

		/* --- FAT: force uppercase ------------------------------------- */
		if (bFAT && c >= 'a' && c <= 'z') {
			out[k++] = (char)(c - 0x20);
		} else {
			out[k++] = (char)c;
		}
		cp++;
		p++;
	}
	out[k] = '\0';

	/* --- FAT: mostly-underscore fallback to SizeToHumanReadable --- */
	if (bFAT && k > 0) {
		underscore_count = 0;
		for (i = 0; i < k; i++)
			if (out[i] == '_') underscore_count++;
		/* Windows condition: label_len < 2 * underscore_count           */
		if (k < 2 * underscore_count) {
			const char *sz = SizeToHumanReadable(SelectedDrive.DiskSize, TRUE, FALSE);
			size_t si;
			k = 0;
			for (si = 0; sz[si] != '\0' && k < 11; si++)
				out[k++] = (sz[si] == '.') ? '_' : sz[si];
			out[k] = '\0';
			uprintf("FAT label is mostly underscores. Using '%s' label instead.", out);
		}
	}

	/* --- Update img_report.usb_label and Label in-place ----------- */
	safe_strcpy(img_report.usb_label, sizeof(img_report.usb_label), out);
	/* Label was allocated with at least strlen(Label)+1 bytes; the
	 * sanitized result is always <= the original length.              */
	safe_strcpy(Label, strlen(Label) + 1, out);
}
