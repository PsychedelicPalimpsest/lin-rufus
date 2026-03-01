/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux-specific parser functions (UTF-8 file I/O, no wchar)
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
 * Linux-specific implementations of the config-file I/O functions.
 * On Linux all strings are UTF-8 natively, so no wchar_t conversion is needed.
 * The portable string-processing functions live in src/common/parser.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strncasecmp */
#include <unistd.h>    /* unlink */

#include "rufus.h"
#include "missing.h"
#include "localization.h"

static const char space[] = " \t";
#define MAX_OCCURRENCES 4

/*
 * Scan a single (UTF-8) line for a key=value or key>value token.
 * Returns a pointer into 'line' at the value, or NULL if not found.
 * 'line' is modified in-place (NUL-terminated at end of value).
 */
static char* get_token_data_line(const char* token, char* line)
{
	size_t i = 0, r;
	BOOL quoteth = FALSE, xml = FALSE;

	if ((token == NULL) || (line == NULL) || (line[0] == 0))
		return NULL;

	/* Skip leading spaces and optional '<' */
	i += strspn(&line[i], space);
	if (line[i] == '<')
		i++;
	i += strspn(&line[i], space);

	/* Token must begin the (trimmed) line */
	if (strncasecmp(&line[i], token, strlen(token)) != 0)
		return NULL;
	i += strlen(token);

	/* Skip spaces after token */
	i += strspn(&line[i], space);

	/* Must be followed by '=' or '>' */
	if (line[i] == '>')
		xml = TRUE;
	else if (line[i] != '=')
		return NULL;
	i++;

	/* Skip spaces after separator */
	i += strspn(&line[i], space);

	/* Strip optional leading quote */
	if (line[i] == '"') {
		quoteth = TRUE;
		i++;
	}

	r = i;

	/* Scan to end of value */
	while (line[i] != 0 &&
	       !((line[i] == '"' && quoteth) ||
	         (line[i] == '<' && xml)))
		i++;
	line[i--] = 0;

	/* Strip trailing CR/LF */
	while (i >= r && (line[i] == '\r' || line[i] == '\n'))
		line[i--] = 0;

	return (line[r] == 0) ? NULL : &line[r];
}

/*
 * Parse a UTF-8 file and return the 'index'th occurrence of 'token'.
 * Returned string is allocated (UTF-8) and MUST be freed by the caller.
 */
char* get_token_data_file_indexed(const char* token, const char* filename, int index)
{
	int found = 0;
	char buf[1024];
	FILE* fd = NULL;
	char *data = NULL, *ret = NULL;

	if ((token == NULL) || (filename == NULL) || (token[0] == 0) || (filename[0] == 0))
		return NULL;

	fd = fopen(filename, "r");
	if (fd == NULL)
		goto out;

	while (fgets(buf, sizeof(buf), fd) != NULL) {
		data = get_token_data_line(token, buf);
		if (data != NULL && ++found == index) {
			ret = safe_strdup(data);
			break;
		}
	}

out:
	if (fd != NULL)
		fclose(fd);
	return ret;
}

/*
 * Replace or add 'data' for token 'token' in config file 'filename'.
 * On Linux files are always treated as UTF-8 (no BOM handling).
 * Returns 'data' on success, NULL on failure.
 */
char* set_token_data_file(const char* token, const char* data, const char* filename)
{
	char buf[1024], tmpname[4096];
	FILE *fd_in = NULL, *fd_out = NULL;
	size_t i;
	char *ret = NULL;

	if ((filename == NULL) || (token == NULL) || (data == NULL))
		return NULL;
	if ((filename[0] == 0) || (token[0] == 0) || (data[0] == 0))
		return NULL;

	snprintf(tmpname, sizeof(tmpname), "%s~", filename);

	fd_in = fopen(filename, "r");
	if (fd_in == NULL) {
		uprintf("Could not open file '%s'\n", filename);
		goto out;
	}

	fd_out = fopen(tmpname, "w");
	if (fd_out == NULL) {
		uprintf("Could not open temporary output file '%s'\n", tmpname);
		goto out;
	}

	while (fgets(buf, sizeof(buf), fd_in) != NULL) {
		i = strspn(buf, space);

		/* Preserve comment/section lines as-is */
		if (buf[i] == ';' || buf[i] == '[') {
			fputs(buf, fd_out);
			continue;
		}

		/* Token must begin a line */
		if (strncasecmp(&buf[i], token, strlen(token)) != 0) {
			fputs(buf, fd_out);
			continue;
		}
		i += strlen(token);
		i += strspn(&buf[i], space);
		if (buf[i] != '=') {
			fputs(buf, fd_out);
			continue;
		}
		i++;
		i += strspn(&buf[i], space);

		/* Output up to (and including) '= ' then the new data */
		buf[i] = 0;
		fputs(buf, fd_out);
		fprintf(fd_out, "%s\n", data);
		ret = (char*)data;
	}

	if (ret == NULL) {
		/* Token not found: append it */
		fprintf(fd_out, "%s = %s\n", token, data);
		ret = (char*)data;
	}

out:
	if (fd_in != NULL) fclose(fd_in);
	if (fd_out != NULL) fclose(fd_out);

	if (ret != NULL) {
		/* Replace original with the rewritten temp file */
		if (rename(tmpname, filename) != 0) {
			uprintf("Could not replace '%s' with '%s'\n", filename, tmpname);
			ret = NULL;
		}
	} else {
		unlink(tmpname);
	}

	return ret;
}

/*
 * Parse a UTF-8 buffer and return the 'n'th occurrence of 'token'.
 * Returned string is allocated (UTF-8) and MUST be freed by the caller.
 */
char* get_token_data_buffer(const char* token, unsigned int n, const char* buffer, size_t buffer_size)
{
	unsigned int j, curly_count;
	size_t i;
	BOOL done = FALSE;
	char *buf_copy = NULL, *line, *data = NULL, *ret = NULL;

	if ((token == NULL) || (buffer == NULL) || (buffer_size <= 4) || (buffer_size > 65536))
		goto out;
	if (buffer[buffer_size - 1] != 0)
		goto out;

	buf_copy = safe_strdup(buffer);
	if (buf_copy == NULL)
		goto out;

	for (i = 0, j = 0, done = FALSE; (j != n) && (!done); ) {
		line = &buf_copy[i];

		for (curly_count = 0;
		     ((curly_count > 0) || ((buf_copy[i] != '\n') && (buf_copy[i] != '\r'))) && (buf_copy[i] != 0);
		     i++) {
			if (buf_copy[i] == '{') curly_count++;
			if (buf_copy[i] == '}') curly_count--;
		}
		if (buf_copy[i] == 0) {
			done = TRUE;
		} else {
			buf_copy[i++] = 0;
		}
		data = get_token_data_line(token, line);
		if (data != NULL)
			j++;
	}

out:
	if (data != NULL)
		ret = safe_strdup(data);
	safe_free(buf_copy);
	return ret;
}

static __inline char* get_sanitized_token_data_buffer(const char* token, unsigned int n, const char* buffer, size_t buffer_size)
{
	size_t i;
	char* data = get_token_data_buffer(token, n, buffer, buffer_size);
	if (data != NULL) {
		for (i = 0; i < strlen(data); i++) {
			if ((data[i] == '\\') && (data[i+1] == 'n')) {
				data[i] = '\r';
				data[i+1] = '\n';
			}
		}
	}
	return data;
}

/*
 * Parse an update data buffer and populate the global 'update' structure.
 */
void parse_update(char* buf, size_t len)
{
	size_t i;
	char *data = NULL, *token;
	char allowed_rtf_chars[] = "abcdefghijklmnopqrstuvwxyz|~-_:*'";
	char allowed_std_chars[] = "\r\n ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"$%^&+=<>(){}[].,;#@/?";
	char download_url_name[24];

	if ((buf == NULL) || (len < 2) || (len > 64 * KB) || (buf[len-1] != 0) || (buf[len-2] == '\\'))
		return;
	len = safe_strlen(buf) + 1;
	for (i = 0; i < len - 1; i++) {
		if (buf[i] == '\\') {
			if (strchr(allowed_rtf_chars, buf[i+1]) == NULL)
				buf[i] = ' ';
		} else if ((strchr(allowed_rtf_chars, buf[i]) == NULL) && (strchr(allowed_std_chars, buf[i]) == NULL)) {
			buf[i] = ' ';
		}
	}

	for (i = 0; i < 3; i++)
		update.version[i] = 0;
	update.platform_min[0] = 5;
	update.platform_min[1] = 2;
	safe_free(update.download_url);
	safe_free(update.release_notes);
	if ((data = get_sanitized_token_data_buffer("version", 1, buf, len)) != NULL) {
		for (i = 0; (i < 3) && ((token = strtok((i == 0) ? data : NULL, ".")) != NULL); i++)
			update.version[i] = (uint16_t)atoi(token);
		safe_free(data);
	}
	if ((data = get_sanitized_token_data_buffer("platform_min", 1, buf, len)) != NULL) {
		for (i = 0; (i < 2) && ((token = strtok((i == 0) ? data : NULL, ".")) != NULL); i++)
			update.platform_min[i] = (uint32_t)atoi(token);
		safe_free(data);
	}
	static_sprintf(download_url_name, "download_url_%s", GetArchName(WindowsVersion.Arch));
	safe_strtolower(download_url_name);
	update.download_url = get_sanitized_token_data_buffer(download_url_name, 1, buf, len);
	if (update.download_url == NULL)
		update.download_url = get_sanitized_token_data_buffer("download_url", 1, buf, len);
	update.release_notes = get_sanitized_token_data_buffer("release_notes", 1, buf, len);
}

/*
 * Insert 'data' after the line matching 'section' in 'filename'.
 * On Linux files are always UTF-8 (no BOM/CR handling needed).
 */
char* insert_section_data(const char* filename, const char* section, const char* data, BOOL dos2unix)
{
	char buf[1024], tmpname[4096];
	FILE *fd_in = NULL, *fd_out = NULL;
	size_t i;
	char *ret = NULL;

	(void)dos2unix; /* Linux files are always LF; no CR stripping needed */

	if ((filename == NULL) || (section == NULL) || (data == NULL))
		return NULL;
	if ((filename[0] == 0) || (section[0] == 0) || (data[0] == 0))
		return NULL;

	snprintf(tmpname, sizeof(tmpname), "%s~", filename);

	fd_in = fopen(filename, "r");
	if (fd_in == NULL) {
		uprintf("Could not open file '%s'\n", filename);
		goto out;
	}

	fd_out = fopen(tmpname, "w");
	if (fd_out == NULL) {
		uprintf("Could not open temporary output file '%s'\n", tmpname);
		goto out;
	}

	while (fgets(buf, sizeof(buf), fd_in) != NULL) {
		i = strspn(buf, space);

		/* Pass through until we find the section header */
		if (strncasecmp(&buf[i], section, strlen(section)) != 0) {
			fputs(buf, fd_out);
			continue;
		}

		/* Output the section line, then the new data */
		fputs(buf, fd_out);
		fprintf(fd_out, "%s\n", data);
		ret = (char*)data;
	}

out:
	if (fd_in != NULL) fclose(fd_in);
	if (fd_out != NULL) fclose(fd_out);

	if (ret != NULL) {
		if (rename(tmpname, filename) != 0) {
			uprintf("Could not replace '%s'\n", filename);
			ret = NULL;
		}
	} else {
		unlink(tmpname);
	}

	return ret;
}

/*
 * Replace all occurrences of 'src' with 'rep' for lines matching 'token' in 'filename'.
 * Parameters are UTF-8.  Returns a pointer to 'rep' on success, NULL otherwise.
 */
char* replace_in_token_data(const char* filename, const char* token, const char* src,
	const char* rep, BOOL dos2unix)
{
	char buf[1024], tmpname[4096];
	char *fragments[MAX_OCCURRENCES + 1];
	size_t frag_len[MAX_OCCURRENCES + 1];
	FILE *fd_in = NULL, *fd_out = NULL;
	size_t i, ns, src_len;
	int j;
	char *p, *ret = NULL;

	(void)dos2unix;

	if ((filename == NULL) || (token == NULL) || (src == NULL) || (rep == NULL))
		return NULL;
	if ((filename[0] == 0) || (token[0] == 0) || (src[0] == 0))
		return NULL;
	if (strcmp(src, rep) == 0)
		return NULL;

	src_len = strlen(src);
	snprintf(tmpname, sizeof(tmpname), "%s~", filename);

	fd_in = fopen(filename, "r");
	if (fd_in == NULL) {
		uprintf("Could not open file '%s'\n", filename);
		goto out;
	}

	fd_out = fopen(tmpname, "w");
	if (fd_out == NULL) {
		uprintf("Could not open temporary output file '%s'\n", tmpname);
		goto out;
	}

	while (fgets(buf, sizeof(buf), fd_in) != NULL) {
		i = strspn(buf, space);

		/* Token must begin a line */
		if (strncasecmp(&buf[i], token, strlen(token)) != 0) {
			fputs(buf, fd_out);
			continue;
		}
		i += strlen(token);

		/* Must have at least one space after token */
		ns = strspn(&buf[i], space);
		if (ns == 0) {
			fputs(buf, fd_out);
			continue;
		}
		i += ns;

		/* Find up to MAX_OCCURRENCES of src in the remainder */
		p = &buf[i];
		for (j = 0; j < MAX_OCCURRENCES; j++) {
			fragments[j] = p;
			char *found = strstr(p, src);
			if (found == NULL) {
				frag_len[j] = strlen(p);
				j++;
				break;
			}
			frag_len[j] = (size_t)(found - p);
			p = found + src_len;
		}

		if (j == 0 || (j == 1 && strstr(fragments[0], src) == NULL)) {
			/* No replacement found */
			fputs(buf, fd_out);
			continue;
		}

		/* Output: prefix (up to token+spaces), then replaced fragments */
		fwrite(buf, 1, i, fd_out);
		for (int k = 0; k < j - 1; k++) {
			fwrite(fragments[k], 1, frag_len[k], fd_out);
			fputs(rep, fd_out);
		}
		fputs(fragments[j - 1], fd_out);
		ret = (char*)rep;
	}

out:
	if (fd_in != NULL) fclose(fd_in);
	if (fd_out != NULL) fclose(fd_out);

	if (ret != NULL) {
		if (rename(tmpname, filename) != 0) {
			uprintf("Could not replace '%s'\n", filename);
			ret = NULL;
		}
	} else {
		unlink(tmpname);
	}

	return ret;
}

/* PE parsing is Windows-only: return safe no-op stubs on Linux */
uint16_t GetPeArch(uint8_t* buf)
{
	(void)buf;
	return 0;
}

uint8_t* GetPeSection(uint8_t* buf, const char* name, uint32_t* len)
{
	(void)buf; (void)name; (void)len;
	return NULL;
}

uint8_t* RvaToPhysical(uint8_t* buf, uint32_t rva)
{
	(void)buf; (void)rva;
	return NULL;
}

uint32_t FindResourceRva(const wchar_t* name, uint8_t* root, uint8_t* dir, uint32_t* len)
{
	(void)name; (void)root; (void)dir; (void)len;
	return 0;
}

uint8_t* GetPeSignatureData(uint8_t* buf)
{
	(void)buf;
	return NULL;
}

