/*
 * Rufus: The Reliable USB Formatting Utility
 * Portable parser functions (shared between Windows and Linux builds)
 * Copyright © 2012-2025 Pete Batard <pete@akeo.ie>
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
 * This file contains the platform-independent parser functions extracted from
 * windows/parser.c.  It must not contain any Windows-specific file I/O
 * (no _wfopen, no fgetws, no wchar_t file APIs).  All string processing uses
 * char-based (UTF-8) APIs.
 *
 * OS-specific functions (get_token_data_file_indexed, set_token_data_file, etc.)
 * live in src/windows/parser.c and src/linux/parser.c respectively.
 */

#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include "rufus.h"
#include "missing.h"
#include "localization.h"

static const char space[] = " \t";

static const struct {char c; int flag;} attr_parse[] = {
	{ 'r', LOC_RIGHT_TO_LEFT },
};

/*
 * Fill a localization command buffer by parsing the line arguments.
 * The command is allocated and must be freed (by calling free_loc_cmd).
 */
static loc_cmd* get_loc_cmd(char c, char* line)
{
	size_t i, j, k, l, r, ti = 0, ii = 0;
	char *endptr, *expected_endptr, *token;
	loc_cmd* lcmd = NULL;

	for (j = 0; j < ARRAYSIZE(parse_cmd); j++) {
		if (c == parse_cmd[j].c)
			break;
	}
	if (j >= ARRAYSIZE(parse_cmd)) {
		luprint("unknown command");
		return NULL;
	}

	lcmd = (loc_cmd*)calloc(sizeof(loc_cmd), 1);
	if (lcmd == NULL) {
		luprint("could not allocate command");
		return NULL;
	}
	lcmd->command = parse_cmd[j].cmd;
	lcmd->ctrl_id = (lcmd->command <= LC_TEXT) ? -1 : 0;
	lcmd->line_nr = (uint16_t)loc_line_nr;

	i = 0;
	for (k = 0; parse_cmd[j].arg_type[k] != 0; k++) {
		/* Skip leading spaces */
		i += strspn(&line[i], space);
		r = i;
		if (line[i] == 0) {
			luprintf("missing parameter for command '%c'", parse_cmd[j].c);
			goto err;
		}
		switch (parse_cmd[j].arg_type[k]) {
		case 's':	/* quoted string */
			if (line[i++] != '"') {
				luprint("no start quote");
				goto err;
			}
			r = i;
			while ((line[i] != 0) && ((line[i] != '"') || ((line[i] == '"') && (line[i-1] == '\\')))) {
				if ((line[i] == '"') && (line[i-1] == '\\')) {
					memmove(&line[i-1], &line[i], strlen(&line[i]) + 1);
				} else {
					i++;
				}
			}
			if (line[i] == 0) {
				luprint("no end quote");
				goto err;
			}
			line[i++] = 0;
			lcmd->txt[ti++] = safe_strdup(&line[r]);
			break;
		case 'c':	/* control ID (single word) */
			while ((line[i] != 0) && (line[i] != space[0]) && (line[i] != space[1]))
				i++;
			if (line[i] != 0)
				line[i++] = 0;
			lcmd->txt[ti++] = safe_strdup(&line[r]);
			break;
		case 'i':	/* 32-bit signed integer */
			if ((line[i] == ',') || (line[i] == '.')) {
				i += strspn(&line[i+1], space);
				r = i;
			}
			while ((line[i] != 0) && (line[i] != space[0]) && (line[i] != space[1])
				&& (line[i] != ',') && (line[i] != '.'))
				i++;
			expected_endptr = &line[i];
			if (line[i] != 0)
				line[i++] = 0;
			lcmd->num[ii++] = (int32_t)strtol(&line[r], &endptr, 0);
			if (endptr != expected_endptr) {
				luprint("invalid integer");
				goto err;
			}
			break;
		case 'u':	/* comma- or dot-separated list of unsigned ints */
			lcmd->unum_size = 1;
			for (l = i; line[l] != 0; l++) {
				if ((line[l] == '.') || (line[l] == ','))
					lcmd->unum_size++;
			}
			free(lcmd->unum);
			lcmd->unum = (uint32_t*)malloc(lcmd->unum_size * sizeof(uint32_t));
			if (lcmd->unum == NULL) {
				luprint("could not allocate memory");
				goto err;
			}
			token = strtok(&line[i], ".,");
			for (l = 0; (l < lcmd->unum_size) && (token != NULL); l++) {
				lcmd->unum[l] = (uint32_t)strtoul(token, &endptr, 0);
				token = strtok(NULL, ".,");
			}
			if ((token != NULL) || (l != lcmd->unum_size)) {
				luprint("internal error (unexpected number of numeric values)");
				goto err;
			}
			break;
		default:
			uprintf("localization: unhandled arg_type '%c'\n", parse_cmd[j].arg_type[k]);
			goto err;
		}
	}

	return lcmd;

err:
	free_loc_cmd(lcmd);
	return NULL;
}

/*
 * Parse a UTF-8 localization command line.
 */
static void get_loc_data_line(char* line)
{
	size_t i;
	loc_cmd* lcmd = NULL;
	char t;

	if ((line == NULL) || (line[0] == 0))
		return;

	/* Skip leading spaces */
	i = strspn(line, space);

	t = line[i++];
	if (t == '#')	/* Comment */
		return;
	if ((t == 0) || ((line[i] != space[0]) && (line[i] != space[1]))) {
		luprintf("syntax error: '%s'", line);
		return;
	}

	lcmd = get_loc_cmd(t, &line[i]);

	if ((lcmd != NULL) && (lcmd->command != LC_LOCALE))
		dispatch_loc_cmd(lcmd);
	else
		free_loc_cmd(lcmd);
}

/*
 * Open a localization file and store its file name, with special case
 * when dealing with the embedded loc file.
 */
FILE* open_loc_file(const char* filename)
{
	FILE* fd = NULL;
	const char* tmp_ext = ".tmp";

	if (filename == NULL)
		return NULL;

	if (loc_filename != embedded_loc_filename) {
		safe_free(loc_filename);
	}
	if (safe_strcmp(tmp_ext, &filename[safe_strlen(filename)-4]) == 0) {
		loc_filename = embedded_loc_filename;
	} else {
		loc_filename = safe_strdup(filename);
	}

	fd = fopen(filename, "rb");
	if (fd == NULL) {
		uprintf("localization: could not open '%s'\n", filename);
	}

	return fd;
}

/*
 * Parse a localization file, to construct the list of available locales.
 * The locale file must be UTF-8 with NO BOM and DOS (CR/LF) line endings.
 */
BOOL get_supported_locales(const char* filename)
{
	FILE* fd = NULL;
	BOOL r = FALSE;
	char line[1024];
	size_t i, j, k;
	loc_cmd *lcmd = NULL, *last_lcmd = NULL;
	long end_of_block;
	int version_line_nr = 0;
	uint32_t loc_base_major = (uint32_t)-1, loc_base_minor = (uint32_t)-1;

	fd = open_loc_file(filename);
	if (fd == NULL)
		goto out;

	/* Check that the file doesn't contain a BOM and was saved in DOS mode */
	i = fread(line, 1, sizeof(line), fd);
	if (i < sizeof(line)) {
		uprintf("Invalid loc file: the file is too small!");
		goto out;
	}
	if (((uint8_t)line[0]) > 0x80) {
		uprintf("Invalid loc file: the file should not have a BOM (Byte Order Mark)");
		goto out;
	}
	for (i = 0; i < sizeof(line)-1; i++)
		if ((((uint8_t)line[i]) == 0x0D) && (((uint8_t)line[i+1]) == 0x0A)) break;
	if (i >= sizeof(line)-1) {
		uprintf("Invalid loc file: the file MUST be saved in DOS mode (CR/LF)");
		goto out;
	}
	fseek(fd, 0, SEEK_SET);

	loc_line_nr = 0;
	line[0] = 0;
	free_locale_list();
	do {
		end_of_block = ftell(fd);
		if (fgets(line, sizeof(line), fd) == NULL)
			break;
		loc_line_nr++;
		i = strspn(line, space);
		if ((line[i] != 'l') && (line[i] != 'v') && (line[i] != 'a'))
			continue;
		lcmd = get_loc_cmd(line[i], &line[i+1]);
		if ((lcmd == NULL) || ((lcmd->command != LC_LOCALE) && (lcmd->command != LC_VERSION) && (lcmd->command != LC_ATTRIBUTES))) {
			free_loc_cmd(lcmd);
			continue;
		}
		switch (lcmd->command) {
		case LC_LOCALE:
			if (last_lcmd != NULL) {
				if (version_line_nr == 0) {
					uprintf("localization: no compatible version was found - this locale will be ignored\n");
					list_del(&last_lcmd->list);
					free_loc_cmd(last_lcmd);
				} else {
					last_lcmd->num[1] = (int32_t)end_of_block;
				}
			}
			lcmd->num[0] = (int32_t)ftell(fd);
			list_add_tail(&lcmd->list, &locale_list);
			uprintf("localization: found locale '%s'\n", lcmd->txt[0]);
			last_lcmd = lcmd;
			version_line_nr = 0;
			break;
		case LC_ATTRIBUTES:
			if (last_lcmd == NULL) {
				luprint("[a]ttributes cannot precede [l]ocale");
			} else for (j = 0; lcmd->txt[0][j] != 0; j++) {
				for (k = 0; k < ARRAYSIZE(attr_parse); k++) {
					if (attr_parse[k].c == lcmd->txt[0][j]) {
						last_lcmd->ctrl_id |= attr_parse[k].flag;
						break;
					}
				}
				if (k >= ARRAYSIZE(attr_parse))
					luprintf("unknown attribute '%c' - ignored", lcmd->txt[0][j]);
			}
			free_loc_cmd(lcmd);
			break;
		case LC_VERSION:
			if (version_line_nr != 0) {
				luprintf("[v]ersion was already provided at line %d", version_line_nr);
			} else if (lcmd->unum_size != 2) {
				luprint("[v]ersion format is invalid");
			} else if (last_lcmd == NULL) {
				luprint("[v]ersion cannot precede [l]ocale");
			} else if (loc_base_major == (uint32_t)-1) {
				loc_base_major = lcmd->unum[0];
				loc_base_minor = lcmd->unum[1];
				version_line_nr = loc_line_nr;
			} else {
				if ((lcmd->unum[0] < loc_base_major) || ((lcmd->unum[0] == loc_base_major) && (lcmd->unum[1] < loc_base_minor))) {
					last_lcmd->ctrl_id |= LOC_NEEDS_UPDATE;
				}
				version_line_nr = loc_line_nr;
			}
			free_loc_cmd(lcmd);
			break;
		}
	} while (1);

	if (last_lcmd != NULL) {
		if (version_line_nr == 0) {
			uprintf("localization: no compatible version was found - this locale will be ignored\n");
			list_del(&last_lcmd->list);
			free_loc_cmd(last_lcmd);
		} else {
			last_lcmd->num[1] = (int32_t)ftell(fd);
		}
	}
	r = !list_empty(&locale_list);
	if (r == FALSE)
		uprintf("localization: '%s' contains no valid locale sections\n", filename);

out:
	if (fd != NULL)
		fclose(fd);
	return r;
}

/*
 * Parse a locale section in a localization file (UTF-8, no BOM).
 * NB: this call is reentrant for the "base" command support.
 */
BOOL get_loc_data_file(const char* filename, loc_cmd* lcmd)
{
	size_t bufsize = 1024;
	static FILE* fd = NULL;
	static BOOL populate_default = FALSE;
	char *buf = NULL;
	size_t i = 0;
	int r = 0, line_nr_incr = 1;
	int c = 0, eol_char = 0;
	int start_line, old_loc_line_nr = 0;
	BOOL ret = FALSE, eol = FALSE, escape_sequence = FALSE, reentrant = (fd != NULL);
	long offset, cur_offset = -1, end_offset;
	loc_cmd* default_locale = list_entry(locale_list.next, loc_cmd, list);

	if ((lcmd == NULL) || (default_locale == NULL)) {
		uprintf("localization: no %slocale", (default_locale == NULL) ? "default " : " ");
		goto out;
	}

	if (msg_table == NULL) {
		msg_table = default_msg_table;
		uprintf("localization: initializing default message table");
		populate_default = TRUE;
		get_loc_data_file(filename, default_locale);
		populate_default = FALSE;
	}

	if (reentrant) {
		cur_offset = ftell(fd);
		old_loc_line_nr = loc_line_nr;
	} else {
		if ((filename == NULL) || (filename[0] == 0))
			return FALSE;
		if (!populate_default) {
			if (lcmd == default_locale) {
				msg_table = default_msg_table;
				return TRUE;
			}
			msg_table = current_msg_table;
		}
		free_dialog_list();
		fd = open_loc_file(filename);
		if (fd == NULL)
			goto out;
	}

	offset = (long)lcmd->num[0];
	end_offset = (long)lcmd->num[1];
	start_line = lcmd->line_nr;
	loc_line_nr = start_line;
	buf = (char*)malloc(bufsize);
	if (buf == NULL) {
		uprintf("localization: could not allocate line buffer\n");
		goto out;
	}

	if (fseek(fd, offset, SEEK_SET) != 0) {
		uprintf("localization: could not rewind\n");
		goto out;
	}

	do {
		c = getc(fd);
		switch (c) {
		case EOF:
			buf[i] = 0;
			if (!eol)
				loc_line_nr += line_nr_incr;
			get_loc_data_line(buf);
			break;
		case '\r':
		case '\n':
			if (escape_sequence) {
				escape_sequence = FALSE;
				break;
			}
			if (eol_char == 0)
				eol_char = c;
			if (c == eol_char) {
				if (eol) {
					line_nr_incr++;
				} else {
					loc_line_nr += line_nr_incr;
					line_nr_incr = 1;
				}
			}
			buf[i] = 0;
			if (!eol) {
				for (r = ((int)i)-1; (r > 0) && ((buf[r] == space[0]) || (buf[r] == space[1])); r--);
				if (r < 0)
					r = 0;
				eol = TRUE;
			}
			break;
		case ' ':
		case '\t':
			if (escape_sequence) {
				escape_sequence = FALSE;
				break;
			}
			if (!eol)
				buf[i++] = (char)c;
			break;
		case '\\':
			if (!escape_sequence) {
				escape_sequence = TRUE;
				break;
			}
			/* fall through on escape sequence */
		default:
			if (escape_sequence) {
				switch (c) {
				case 'n':
					buf[i++] = '\r';
					buf[i++] = '\n';
					break;
				case '"':
					buf[i++] = '\\';
					buf[i++] = '"';
					break;
				case '\\':
					buf[i++] = '\\';
					break;
				default:
					break;
				}
				escape_sequence = FALSE;
			} else {
				if ((eol) && (c == '"') && (buf[r] == '"')) {
					i = r;
					eol = FALSE;
					break;
				}
				if (eol) {
					get_loc_data_line(buf);
					eol = FALSE;
					i = 0;
					r = 0;
				}
				buf[i++] = (char)c;
			}
			break;
		}
		if ((c == EOF) || (ftell(fd) > end_offset))
			break;
		if (i >= bufsize - 2) {
			bufsize *= 2;
			if (bufsize > 32768) {
				uprintf("localization: requested line buffer is larger than 32K!\n");
				goto out;
			}
			buf = (char*)_reallocf(buf, bufsize);
			if (buf == NULL) {
				uprintf("localization: could not grow line buffer\n");
				goto out;
			}
		}
	} while (1);
	ret = TRUE;

out:
	if (reentrant) {
		if ((cur_offset < 0) || (fseek(fd, cur_offset, SEEK_SET) != 0)) {
			uprintf("localization: unable to reset reentrant position\n");
			ret = FALSE;
		}
		loc_line_nr = old_loc_line_nr;
	} else if (fd != NULL) {
		fclose(fd);
		fd = NULL;
	}
	safe_free(buf);
	return ret;
}

/*
 * Replace all 'c' characters in string 'src' with the substring 'rep'.
 * The returned string is allocated and must be freed by the caller.
 */
char* replace_char(const char* src, const char c, const char* rep)
{
	size_t i, j, k, count = 0, str_len = safe_strlen(src), rep_len = safe_strlen(rep);
	char* res;

	if ((src == NULL) || (rep == NULL))
		return NULL;
	for (i = 0; i < str_len; i++) {
		if (src[i] == c)
			count++;
	}
	res = (char*)malloc(str_len + count * rep_len + 1);
	if (res == NULL)
		return NULL;
	for (i = 0, j = 0; i < str_len; i++) {
		if (src[i] == c) {
			for (k = 0; k < rep_len; k++)
				res[j++] = rep[k];
		} else {
			res[j++] = src[i];
		}
	}
	res[j] = 0;
	return res;
}

/*
 * Replace all characters from string 'str' that are present in 'rem' with 'rep'.
 */
void filter_chars(char* str, const char* rem, const char rep)
{
	char *p, *q;

	if (str == NULL || rem == NULL)
		return;
	for (p = str; *p != '\0'; p++) {
		for (q = (char*)rem; *q != '\0'; q++)
			if (*p == *q)
				*p = rep;
	}
}

/*
 * Remove all instances of substring 'sub' from string 'src'.
 * The returned string is allocated and must be freed by the caller.
 */
char* remove_substr(const char* src, const char* sub)
{
	size_t i, j, str_len = safe_strlen(src), sub_len = safe_strlen(sub);
	char* res;

	if ((src == NULL) || (sub == NULL) || (sub_len > str_len))
		return NULL;

	res = (char*)calloc(str_len + 1, 1);
	if (res == NULL)
		return NULL;
	for (i = 0, j = 0; i <= str_len; ) {
		if (i <= str_len - sub_len && memcmp(&src[i], sub, sub_len) == 0)
			i += sub_len;
		else
			res[j++] = src[i++];
	}
	return res;
}

/*
 * Internal recursive call for get_data_from_asn1().
 */
static BOOL get_data_from_asn1_internal(const uint8_t* buf, size_t buf_len, const void* oid,
	size_t oid_len, uint8_t asn1_type, void** data, size_t* data_len, BOOL* matched)
{
	size_t pos = 0, len, len_len, i;
	uint8_t tag;
	BOOL is_sequence, is_universal_tag;

	while (pos < buf_len) {
		is_sequence = buf[pos] & 0x20;
		is_universal_tag = ((buf[pos] & 0xC0) == 0x00);
		tag = buf[pos++] & 0x1F;
		if (tag == 0x1F) {
			uprintf("get_data_from_asn1: Long form tags are unsupported");
			return FALSE;
		}

		len = 0;
		len_len = 1;
		if ((is_universal_tag) && (tag == 0x05)) {
			pos++;
		} else {
			if (buf[pos] & 0x80) {
				len_len = buf[pos++] & 0x7F;
				if (len_len > 2) {
					uprintf("get_data_from_asn1: Length fields larger than 2 bytes are unsupported");
					return FALSE;
				}
				for (i = 0; i < len_len; i++) {
					len <<= 8;
					len += buf[pos++];
				}
			} else {
				len = buf[pos++];
			}

			if (len > buf_len - pos) {
				uprintf("get_data_from_asn1: Overflow error (computed length %zu is larger than remaining data)", len);
				return FALSE;
			}
		}

		if (len != 0) {
			if (is_sequence) {
				if (!get_data_from_asn1_internal(&buf[pos], len, oid, oid_len, asn1_type, data, data_len, matched))
					return FALSE;
				if (*data != NULL)
					return TRUE;
			} else if (is_universal_tag) {
				if ((!*matched) && (tag == 0x06) && (len == oid_len) && (memcmp(&buf[pos], oid, oid_len) == 0)) {
					*matched = TRUE;
				} else if ((*matched) && (tag == asn1_type)) {
					*data_len = len;
					*data = (void*)&buf[pos];
					return TRUE;
				}
			}
			pos += len;
		}
	}

	return TRUE;
}

static size_t make_flagged_int(unsigned long value, uint8_t *buf, size_t buf_len)
{
	BOOL more = FALSE;
	int shift;

	for (shift = 28; shift > 0; shift -= 7) {
		if (more || value >= ((unsigned long)1 << shift)) {
			buf[buf_len++] = (uint8_t)(0x80 | (value >> shift));
			value -= (value >> shift) << shift;
			more = TRUE;
		}
	}
	buf[buf_len++] = (uint8_t)value;
	return buf_len;
}

static uint8_t* oid_from_str(const char* oid_str, size_t* ret_len)
{
	uint8_t* oid = NULL;
	unsigned long val1 = 0, val;
	const char *endp;
	int arcno = 0;
	size_t oid_len = 0;

	if ((oid_str == NULL) || (oid_str[0] == 0))
		return NULL;

	oid = malloc(1 + strlen(oid_str) + 2);
	if (oid == NULL)
		return NULL;

	do {
		arcno++;
		val = strtoul(oid_str, (char**)&endp, 10);
		if (!isdigit(*oid_str) || !(*endp == '.' || !*endp))
			goto err;
		if (*endp == '.')
			oid_str = endp + 1;

		if (arcno == 1) {
			if (val > 2)
				break;
			val1 = val;
		} else if (arcno == 2) {
			if (val1 < 2) {
				if (val > 39)
					goto err;
				oid[oid_len++] = (uint8_t)(val1 * 40 + val);
			} else {
				val += 80;
				oid_len = make_flagged_int(val, oid, oid_len);
			}
		} else {
			oid_len = make_flagged_int(val, oid, oid_len);
		}
	} while (*endp == '.');

	if (arcno == 1 || oid_len < 2 || oid_len > 254)
		goto err;

	*ret_len = oid_len;
	return oid;

err:
	free(oid);
	return NULL;
}

/*
 * Parse an ASN.1 binary buffer and return a pointer to the first instance of
 * OID data matching 'oid_str' (or the first data of type 'asn1_type' if
 * oid_str is NULL).
 */
void* get_data_from_asn1(const uint8_t* buf, size_t buf_len, const char* oid_str, uint8_t asn1_type, size_t* data_len)
{
	void* data = NULL;
	uint8_t* oid = NULL;
	size_t oid_len = 0;
	BOOL matched = ((oid_str == NULL) || (oid_str[0] == 0));

	if (buf == NULL)
		return NULL;

	if (buf_len >= 65536) {
		uprintf("get_data_from_asn1: Buffers larger than 64KB are not supported");
		return NULL;
	}

	if (!matched) {
		oid = oid_from_str(oid_str, &oid_len);
		if (oid == NULL) {
			uprintf("get_data_from_asn1: Could not convert OID string '%s'", oid_str);
			return NULL;
		}
	}

	get_data_from_asn1_internal(buf, buf_len, oid, oid_len, asn1_type, &data, data_len, &matched);
	free(oid);
	return data;
}

/*
 * Sanitize an ISO volume label or GRUB version for bootloader lookup.
 */
int sanitize_label(char* label)
{
	static const char* remove[] = { "-i386", "-i686", "-amd64", "-x86-64", ".x86-64",
		"-x64", "-armhf", "-arm64", "-aarch64", "-32-bit", "-64-bit", "-32bit", "-64bit",
		"-intel", "-cd", "-dvd", "-standard", "-live", "-install", "-server", "-net",
		"-desktop", "-lts", "-studio", "-baseos", "-kde", "-xfce", "-lxde", "-gnome",
		"-mate", "-unstable", "-debug", "-release", "-final", "-stream", "-cinnamon",
		"-cinn", "-leap", "-tumbleweed", "-budgie", "-ws", "-iot", "-ostree", ".iso"
	};
	size_t i, len;
	char *s;

	len = strlen(label);
	for (i = 0; i < len; i++) {
		char c = label[i];
		if (c >= 'A' && c <= 'Z')
			c += 0x20;
		if ((c < '0' && c != '.') || (c > '9' && c < 'a') || (c > 'z'))
			c = '-';
		label[i] = c;
	}

	for (i = 0; i < len && label[i] == '-'; i++);
	if (i != 0)
		memmove(label, &label[i], len - i);
	len = strlen(label);
	if (len <= 1)
		return -1;

	for (i = len - 1; i > 0 && label[i] == '-'; i--)
		label[i] = 0;
	len = strlen(label);
	if (len <= 1)
		return -1;

	for (i = 0; len >= 2 && i < len - 2; i++) {
		if (label[i] == '-' && label[i + 1] == '-') {
			memmove(&label[i + 1], &label[i + 2], len - i - 1);
			len--;
			i--;
		}
	}

	for (i = 0; i < ARRAYSIZE(remove); i++) {
		s = strstr(label, remove[i]);
		if (s != NULL)
			strcpy(s, &s[strlen(remove[i])]);
	}

	return 0;
}

/*
 * Parse an sbat_level.txt file and return an array of (product_name, min_version) tuples.
 * Array must be freed by caller.
 */
sbat_entry_t* GetSbatEntries(char* sbatlevel)
{
	BOOL eol, eof;
	char* version_str;
	uint32_t i, num_entries;
	sbat_entry_t* sbat_list;

	if (sbatlevel == NULL)
		return NULL;

	num_entries = 1;
	for (i = 0; sbatlevel[i] != '\0'; i++) {
		if (sbatlevel[i] == '\n')
			num_entries++;
		if (sbatlevel[i] == '\r')
			sbatlevel[i] = '\n';
	}

	sbat_list = calloc(num_entries + 1, sizeof(sbat_entry_t));
	if (sbat_list == NULL)
		return NULL;

	num_entries = 0;
	for (i = 0; sbatlevel[i] != '\0'; ) {
		if (sbatlevel[i] == '\n') {
			i++;
			continue;
		}
		if (sbatlevel[i] == '#') {
			while (sbatlevel[i] != '\n' && sbatlevel[i] != '\0')
				i++;
			continue;
		}
		sbat_list[num_entries].product = &sbatlevel[i];
		for (; sbatlevel[i] != ',' && sbatlevel[i] != '\0' && sbatlevel[i] != '\n'; i++);
		if (sbatlevel[i] == '\0' || sbatlevel[i] == '\n')
			break;
		sbatlevel[i++] = '\0';
		version_str = &sbatlevel[i];
		for (; sbatlevel[i] != ',' && sbatlevel[i] != '\0' && sbatlevel[i] != '\n'; i++);
		eol = (sbatlevel[i] == '\0' || sbatlevel[i] == '\n');
		eof = (sbatlevel[i] == '\0');
		sbatlevel[i] = '\0';
		if (!eof)
			i++;
		if (version_str[0] == '0' && version_str[1] == 'x')
			sbat_list[num_entries].version = strtoul(version_str, NULL, 16);
		else
			sbat_list[num_entries].version = strtoul(version_str, NULL, 10);
		if (!eol)
			for (; sbatlevel[i] != '\0' && sbatlevel[i] != '\n'; i++);
		if (sbat_list[num_entries].version != 0)
			num_entries++;
	}
	if (num_entries == 0) {
		free(sbat_list);
		return NULL;
	}

	return sbat_list;
}

/*
 * Parse a list of SHA-1 certificate hexascii thumbprints.
 * List must be freed by the caller.
 */
thumbprint_list_t* GetThumbprintEntries(char* thumbprints_txt)
{
	uint32_t i, j, num_entries;
	thumbprint_list_t* thumbprints;

	if (thumbprints_txt == NULL)
		return NULL;

	num_entries = 1;
	for (i = 0; thumbprints_txt[i] != '\0'; i++)
		if (thumbprints_txt[i] == '\n')
			num_entries++;

	thumbprints = calloc(sizeof(thumbprint_list_t) + num_entries * SHA1_HASHSIZE, 1);
	if (thumbprints == NULL)
		return NULL;
	thumbprints->count = 0;

	for (i = 0; thumbprints_txt[i] != '\0'; ) {
		if (thumbprints_txt[i] == '\n') {
			i++;
			continue;
		}
		if (!IS_HEXASCII(thumbprints_txt[i])) {
			while (thumbprints_txt[i] != '\n' && thumbprints_txt[i] != '\0')
				i++;
			continue;
		}
		for (j = 0; thumbprints_txt[i] != '\n' && thumbprints_txt[i] != '\0'; i++, j++) {
			if (!IS_HEXASCII(thumbprints_txt[i]))
				break;
			if ((j / 2) >= SHA1_HASHSIZE)
				break;
			thumbprints->list[thumbprints->count][j / 2] = thumbprints->list[thumbprints->count][j / 2] << 4;
			thumbprints->list[thumbprints->count][j / 2] |= FROM_HEXASCII(thumbprints_txt[i]);
			if (j == 2 * SHA1_HASHSIZE - 1)
				thumbprints->count++;
		}
		while (thumbprints_txt[i] != '\n' && thumbprints_txt[i] != '\0')
			i++;
	}

	if (thumbprints->count == 0) {
		free(thumbprints);
		return NULL;
	}

	return thumbprints;
}
