/*
 * Rufus: The Reliable USB Formatting Utility
 * Elementary Unicode compliant find/replace parser
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

/* Memory leaks detection - define _CRTDBG_MAP_ALLOC as preprocessor macro */
#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <malloc.h>
#include <io.h>
#include <fcntl.h>

#include "rufus.h"
#include "missing.h"
#include "msapi_utf8.h"
#include "localization.h"

static const wchar_t wspace[] = L" \t";
static const char* conversion_error = "Could not convert '%s' to UTF-16";

/* Portable functions (get_loc_cmd, get_loc_data_line, open_loc_file,
 * get_supported_locales, get_loc_data_file, replace_char, filter_chars,
 * remove_substr, get_data_from_asn1, sanitize_label, GetSbatEntries,
 * GetThumbprintEntries) are in src/common/parser.c */



/*
 * Parse a line of UTF-16 text and return the data if it matches the 'token'
 * The parsed line is of the form: [ ][<][ ]token[ ][=|>][ ]["]data["][ ][<] and is
 * modified by the parser
 */
static wchar_t* get_token_data_line(const wchar_t* wtoken, wchar_t* wline)
{
	size_t i, r;
	BOOLEAN quoteth = FALSE;
	BOOLEAN xml = FALSE;

	if ((wtoken == NULL) || (wline == NULL) || (wline[0] == 0))
		return NULL;

	i = 0;

	// Skip leading spaces and opening '<'
	i += wcsspn(&wline[i], wspace);
	if (wline[i] == L'<')
		i++;
	i += wcsspn(&wline[i], wspace);

	// Our token should begin a line
	if (_wcsnicmp(&wline[i], wtoken, wcslen(wtoken)) != 0)
		return NULL;

	// Token was found, move past token
	i += wcslen(wtoken);

	// Skip spaces
	i += wcsspn(&wline[i], wspace);

	// Check for '=' or '>' sign
	if (wline[i] == L'>')
		xml = TRUE;
	else if (wline[i] != L'=')
		return NULL;
	i++;

	// Skip spaces
	i += wcsspn(&wline[i], wspace);

	// eliminate leading quote, if it exists
	if (wline[i] == L'"') {
		quoteth = TRUE;
		i++;
	}

	// Keep the starting pos of our data
	r = i;

	// locate end of string or quote
	while ( (wline[i] != 0) && (((wline[i] != L'"') && (wline[i] != L'<')) || ((wline[i] == L'"') && (!quoteth)) || ((wline[i] == L'<') && (!xml))) )
		i++;
	wline[i--] = 0;

	// Eliminate trailing EOL characters
	while ((i>=r) && ((wline[i] == L'\r') || (wline[i] == L'\n')))
		wline[i--] = 0;

	return (wline[r] == 0)?NULL:&wline[r];
}

/*
 * Parse a file (ANSI or UTF-8 or UTF-16) and return the data for the 'index'th occurrence of 'token'
 * The returned string is UTF-8 and MUST be freed by the caller
 */
char* get_token_data_file_indexed(const char* token, const char* filename, int index)
{
	int i = 0;
	wchar_t *wtoken = NULL, *wdata= NULL, *wfilename = NULL;
	wchar_t buf[1024];
	FILE* fd = NULL;
	char *ret = NULL;

	if ((filename == NULL) || (token == NULL))
		return NULL;
	if ((filename[0] == 0) || (token[0] == 0))
		return NULL;

	wfilename = utf8_to_wchar(filename);
	if (wfilename == NULL) {
		uprintf(conversion_error, filename);
		goto out;
	}
	wtoken = utf8_to_wchar(token);
	if (wtoken == NULL) {
		uprintf(conversion_error, token);
		goto out;
	}
	fd = _wfopen(wfilename, L"r, ccs=UNICODE");
	if (fd == NULL) goto out;

	// Process individual lines. NUL is always appended.
	// Ideally, we'd check that our buffer fits the line
	while (fgetws(buf, ARRAYSIZE(buf), fd) != NULL) {
		wdata = get_token_data_line(wtoken, buf);
		if ((wdata != NULL) && (++i == index)) {
			ret = wchar_to_utf8(wdata);
			break;
		}
	}

out:
	if (fd != NULL)
		fclose(fd);
	safe_free(wfilename);
	safe_free(wtoken);
	return ret;
}

/*
 * replace or add 'data' for token 'token' in config file 'filename'
 */
char* set_token_data_file(const char* token, const char* data, const char* filename)
{
	const wchar_t* outmode[] = { L"w", L"w, ccs=UTF-8", L"w, ccs=UTF-16LE" };
	wchar_t *wtoken = NULL, *wfilename = NULL, *wtmpname = NULL, *wdata = NULL, bom = 0;
	wchar_t buf[1024];
	FILE *fd_in = NULL, *fd_out = NULL;
	size_t i, size;
	int mode = 0;
	char *ret = NULL, tmp[2];

	if ((filename == NULL) || (token == NULL) || (data == NULL))
		return NULL;
	if ((filename[0] == 0) || (token[0] == 0) || (data[0] == 0))
		return NULL;

	wfilename = utf8_to_wchar(filename);
	if (wfilename == NULL) {
		uprintf(conversion_error, filename);
		goto out;
	}
	wtoken = utf8_to_wchar(token);
	if (wtoken == NULL) {
		uprintf(conversion_error, token);
		goto out;
	}
	wdata = utf8_to_wchar(data);
	if (wdata == NULL) {
		uprintf(conversion_error, data);
		goto out;
	}

	fd_in = _wfopen(wfilename, L"r, ccs=UNICODE");
	if (fd_in == NULL) {
		uprintf("Could not open file '%s'\n", filename);
		goto out;
	}
	// Check the input file's BOM and create an output file with the same
	if (fread(&bom, sizeof(bom), 1, fd_in) == 1) {
		switch(bom) {
		case 0xFEFF:
			mode = 2;	// UTF-16 (LE)
			break;
		case 0xBBEF:	// Yeah, the UTF-8 BOM is really 0xEF,0xBB,0xBF, but
			mode = 1;	// find me a non UTF-8 file that actually begins with "ï»"
			break;
		default:
			mode = 0;	// ANSI
			break;
		}
		fseek(fd_in, 0, SEEK_SET);
	}

	wtmpname = (wchar_t*)calloc(wcslen(wfilename)+2, sizeof(wchar_t));
	if (wtmpname == NULL) {
		uprintf("Could not allocate space for temporary output name\n");
		goto out;
	}
	wcscpy(wtmpname, wfilename);
	wtmpname[wcslen(wtmpname)] = '~';

	fd_out = _wfopen(wtmpname, outmode[mode]);
	if (fd_out == NULL) {
		uprintf("Could not open temporary output file '%s~'\n", filename);
		goto out;
	}

	// Process individual lines. NUL is always appended.
	while (fgetws(buf, ARRAYSIZE(buf), fd_in) != NULL) {

		i = 0;

		// Skip leading spaces
		i += wcsspn(&buf[i], wspace);

		// Ignore comments or section headers
		if ((buf[i] == ';') || (buf[i] == '[')) {
			fputws(buf, fd_out);
			continue;
		}

		// Our token should begin a line
		if (_wcsnicmp(&buf[i], wtoken, wcslen(wtoken)) != 0) {
			fputws(buf, fd_out);
			continue;
		}

		// Token was found, move past token
		i += wcslen(wtoken);

		// Skip spaces
		i += wcsspn(&buf[i], wspace);

		// Check for an equal sign
		if (buf[i] != L'=') {
			fputws(buf, fd_out);
			continue;
		}
		i++;

		// Skip spaces after equal sign
		i += wcsspn(&buf[i], wspace);

		// Output the token
		buf[i] = 0;
		fputws(buf, fd_out);

		// Now output the new data
		// coverity[invalid_type]
		fwprintf_s(fd_out, L"%s\n", wdata);
		ret = (char*)data;
	}

	if (ret == NULL) {
		// Didn't find an existing token => append it
		// coverity[invalid_type]
		fwprintf_s(fd_out, L"%s = %s\n", wtoken, wdata);
		ret = (char*)data;
	}

out:
	if (fd_in != NULL) {
		fclose(fd_in);
		fd_in = NULL;
	}
	if (fd_out != NULL)
		fclose(fd_out);

	// If an insertion occurred, delete existing file and use the new one
	if (ret != NULL) {
		// We're in Windows text mode => Remove CRs if requested
		if (wtmpname != NULL)
			fd_in = _wfopen(wtmpname, L"rb");
		fd_out = _wfopen(wfilename, L"wb");
		// Don't check fds
		if ((fd_in != NULL) && (fd_out != NULL)) {
			size = (mode==2)?2:1;
			while(fread(tmp, size, 1, fd_in) == 1)
				fwrite(tmp, size, 1, fd_out);
			fclose(fd_in);
			fclose(fd_out);
		} else {
			uprintf("Could not write '%s' - original file has been left unmodified\n", filename);
			ret = NULL;
			if (fd_in != NULL)
				fclose(fd_in);
			if (fd_out != NULL)
				fclose(fd_out);
		}
	}
	if (wtmpname != NULL)
		_wunlink(wtmpname);
	safe_free(wfilename);
	safe_free(wtmpname);
	safe_free(wtoken);
	safe_free(wdata);

	return ret;
}

/*
 * Parse a buffer (ANSI or UTF-8) and return the data for the 'n'th occurrence of 'token'
 * The returned string is UTF-8 and MUST be freed by the caller
 */
char* get_token_data_buffer(const char* token, unsigned int n, const char* buffer, size_t buffer_size)
{
	unsigned int j, curly_count;
	wchar_t *wtoken = NULL, *wdata = NULL, *wbuffer = NULL, *wline = NULL;
	size_t i;
	BOOL done = FALSE;
	char* ret = NULL;

	// We're handling remote data => better safe than sorry
	if ((token == NULL) || (buffer == NULL) || (buffer_size <= 4) || (buffer_size > 65536))
		goto out;

	// Ensure that our buffer is NUL terminated
	if (buffer[buffer_size-1] != 0)
		goto out;

	wbuffer = utf8_to_wchar(buffer);
	wtoken = utf8_to_wchar(token);
	if ((wbuffer == NULL) || (wtoken == NULL))
		goto out;

	// Process individual lines (or multiple lines when between {}, for RTF)
	for (i=0,j=0,done=FALSE; (j!=n)&&(!done); ) {
		wline = &wbuffer[i];

		for(curly_count=0;((curly_count>0)||((wbuffer[i]!=L'\n')&&(wbuffer[i]!=L'\r')))&&(wbuffer[i]!=0);i++) {
			if (wbuffer[i] == L'{') curly_count++;
			if (wbuffer[i] == L'}') curly_count--;
		}
		if (wbuffer[i]==0) {
			done = TRUE;
		} else {
			wbuffer[i++] = 0;
		}
		wdata = get_token_data_line(wtoken, wline);
		if (wdata != NULL) {
			j++;
		}
	}
out:
	if (wdata != NULL)
		ret = wchar_to_utf8(wdata);
	safe_free(wbuffer);
	safe_free(wtoken);
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
 * Parse an update data file and populates a rufus_update structure.
 * NB: since this is remote data, and we're running elevated, it *IS* considered
 * potentially malicious, even if it comes from a supposedly trusted server.
 * len should be the size of the buffer, including the zero terminator
 */
void parse_update(char* buf, size_t len)
{
	size_t i;
	char *data = NULL, *token;
	char allowed_rtf_chars[] = "abcdefghijklmnopqrstuvwxyz|~-_:*'";
	char allowed_std_chars[] = "\r\n ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"$%^&+=<>(){}[].,;#@/?";
	char download_url_name[24];

	// strchr includes the NUL terminator in the search, so take care of backslash before NUL
	if ((buf == NULL) || (len < 2) || (len > 64 * KB) || (buf[len-1] != 0) || (buf[len-2] == '\\'))
		return;
	// Sanitize the data - Not a silver bullet, but it helps
	len = safe_strlen(buf)+1;	// Someone may be inserting NULs
	for (i = 0; i < len - 1; i++) {
		// Check for valid RTF sequences as well as allowed chars if not RTF
		if (buf[i] == '\\') {
			// NB: we have a zero terminator, so we can afford a +1 without overflow
			if (strchr(allowed_rtf_chars, buf[i+1]) == NULL) {
				buf[i] = ' ';
			}
		} else if ((strchr(allowed_rtf_chars, buf[i]) == NULL) && (strchr(allowed_std_chars, buf[i]) == NULL)) {
			buf[i] = ' ';
		}
	}

	for (i = 0; i < 3; i++)
		update.version[i] = 0;
	update.platform_min[0] = 5;
	update.platform_min[1] = 2;	// XP or later
	safe_free(update.download_url);
	safe_free(update.release_notes);
	if ((data = get_sanitized_token_data_buffer("version", 1, buf, len)) != NULL) {
		for (i = 0; (i < 3) && ((token = strtok((i == 0) ? data : NULL, ".")) != NULL); i++) {
			update.version[i] = (uint16_t)atoi(token);
		}
		safe_free(data);
	}
	if ((data = get_sanitized_token_data_buffer("platform_min", 1, buf, len)) != NULL) {
		for (i = 0; (i < 2) && ((token = strtok((i == 0) ? data : NULL, ".")) != NULL); i++) {
			update.platform_min[i] = (uint32_t)atoi(token);
		}
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
 * Insert entry 'data' under section 'section' of a config file
 * Section must include the relevant delimiters (eg '[', ']') if needed
 */
char* insert_section_data(const char* filename, const char* section, const char* data, BOOL dos2unix)
{
	const wchar_t* outmode[] = { L"w", L"w, ccs=UTF-8", L"w, ccs=UTF-16LE" };
	wchar_t *wsection = NULL, *wfilename = NULL, *wtmpname = NULL, *wdata = NULL, bom = 0;
	wchar_t buf[1024];
	FILE *fd_in = NULL, *fd_out = NULL;
	size_t i, size;
	int mode = 0;
	char *ret = NULL, tmp[2];

	if ((filename == NULL) || (section == NULL) || (data == NULL))
		return NULL;
	if ((filename[0] == 0) || (section[0] == 0) || (data[0] == 0))
		return NULL;

	wfilename = utf8_to_wchar(filename);
	if (wfilename == NULL) {
		uprintf(conversion_error, filename);
		goto out;
	}
	wsection = utf8_to_wchar(section);
	if (wsection == NULL) {
		uprintf(conversion_error, section);
		goto out;
	}
	wdata = utf8_to_wchar(data);
	if (wdata == NULL) {
		uprintf(conversion_error, data);
		goto out;
	}

	fd_in = _wfopen(wfilename, L"r, ccs=UNICODE");
	if (fd_in == NULL) {
		uprintf("Could not open file '%s'\n", filename);
		goto out;
	}
	// Check the input file's BOM and create an output file with the same
	if (fread(&bom, sizeof(bom), 1, fd_in) != 1) {
		uprintf("Could not read file '%s'\n", filename);
		goto out;
	}
	switch(bom) {
	case 0xFEFF:
		mode = 2;	// UTF-16 (LE)
		break;
	case 0xBBEF:	// Yeah, the UTF-8 BOM is really 0xEF,0xBB,0xBF, but
		mode = 1;	// find me a non UTF-8 file that actually begins with "ï»"
		break;
	default:
		mode = 0;	// ANSI
		break;
	}
	fseek(fd_in, 0, SEEK_SET);
//	duprintf("'%s' was detected as %s\n", filename,
//		(mode==0)?"ANSI/UTF8 (no BOM)":((mode==1)?"UTF8 (with BOM)":"UTF16 (with BOM"));

	wtmpname = (wchar_t*)calloc(wcslen(wfilename)+2, sizeof(wchar_t));
	if (wtmpname == NULL) {
		uprintf("Could not allocate space for temporary output name\n");
		goto out;
	}
	wcscpy(wtmpname, wfilename);
	wtmpname[wcslen(wtmpname)] = '~';

	fd_out = _wfopen(wtmpname, outmode[mode]);
	if (fd_out == NULL) {
		uprintf("Could not open temporary output file '%s~'\n", filename);
		goto out;
	}

	// Process individual lines. NUL is always appended.
	while (fgetws(buf, ARRAYSIZE(buf), fd_in) != NULL) {

		i = 0;

		// Skip leading spaces
		i += wcsspn(&buf[i], wspace);

		// Our token should begin a line
		if (_wcsnicmp(&buf[i], wsection, wcslen(wsection)) != 0) {
			fputws(buf, fd_out);
			continue;
		}

		// Section was found, output it
		fputws(buf, fd_out);
		// Now output the new data
		// coverity[invalid_type]
		fwprintf_s(fd_out, L"%s\n", wdata);
		ret = (char*)data;
	}

out:
	if (fd_in != NULL) fclose(fd_in);
	if (fd_out != NULL) fclose(fd_out);

	// If an insertion occurred, delete existing file and use the new one
	if (ret != NULL && wtmpname != NULL && wfilename != NULL) {
		// We're in Windows text mode => Remove CRs if requested
		fd_in = _wfopen(wtmpname, L"rb");
		fd_out = _wfopen(wfilename, L"wb");
		// Don't check fds
		if ((fd_in != NULL) && (fd_out != NULL)) {
			size = (mode==2)?2:1;
			while(fread(tmp, size, 1, fd_in) == 1) {
				if ((!dos2unix) || (tmp[0] != 0x0D))
					fwrite(tmp, size, 1, fd_out);
			}
			fclose(fd_in);
			fclose(fd_out);
		} else {
			uprintf("Could not write '%s' - original file has been left unmodified\n", filename);
			ret = NULL;
			if (fd_in != NULL) fclose(fd_in);
			if (fd_out != NULL) fclose(fd_out);
		}
	}
	if (wtmpname != NULL)
		_wunlink(wtmpname);
	safe_free(wfilename);
	safe_free(wtmpname);
	safe_free(wsection);
	safe_free(wdata);

	return ret;
}

/*
 * Search for a specific 'src' substring data for all occurrences of 'token', and replace
 * it with 'rep'. File can be ANSI or UNICODE and is overwritten. Parameters are UTF-8.
 * The parsed line is of the form: [ ]token[ ]data
 * Returns a pointer to rep if replacement occurred, NULL otherwise
 * TODO: We might have to end up with a regexp engine, so that we can do stuff like: "foo*" -> "bar\1"
 */
#define MAX_OCCURRENCES 4
char* replace_in_token_data(const char* filename, const char* token, const char* src, const char* rep, BOOL dos2unix)
{
	const wchar_t* outmode[] = { L"w", L"w, ccs=UTF-8", L"w, ccs=UTF-16LE" };
	wchar_t *wtoken = NULL, *wfilename = NULL, *wtmpname = NULL, *wsrc = NULL, *wrep = NULL, bom = 0;
	wchar_t buf[1024], *torep[MAX_OCCURRENCES + 1] = { NULL };
	FILE *fd_in = NULL, *fd_out = NULL;
	size_t i, j, p[MAX_OCCURRENCES + 1] = { 0 }, ns, size;
	int mode = 0;
	char *ret = NULL, tmp[2];

	if ((filename == NULL) || (token == NULL) || (src == NULL) || (rep == NULL))
		return NULL;
	if ((filename[0] == 0) || (token[0] == 0) || (src[0] == 0))
		return NULL;
	if (strcmp(src, rep) == 0)	// No need for processing is source is same as replacement
		return NULL;

	wfilename = utf8_to_wchar(filename);
	if (wfilename == NULL) {
		uprintf(conversion_error, filename);
		goto out;
	}
	wtoken = utf8_to_wchar(token);
	if (wtoken == NULL) {
		uprintf(conversion_error, token);
		goto out;
	}
	wsrc = utf8_to_wchar(src);
	if (wsrc == NULL) {
		uprintf(conversion_error, src);
		goto out;
	}
	wrep = utf8_to_wchar(rep);
	if (wrep == NULL) {
		uprintf(conversion_error, rep);
		goto out;
	}

	fd_in = _wfopen(wfilename, L"r, ccs=UNICODE");
	if (fd_in == NULL) {
		uprintf("Could not open file '%s'\n", filename);
		goto out;
	}
	// Check the input file's BOM and create an output file with the same
	if (fread(&bom, sizeof(bom), 1, fd_in) != 1) {
		if (!feof(fd_in))
			uprintf("Could not read file '%s'\n", filename);
		goto out;
	}
	switch(bom) {
	case 0xFEFF:
		mode = 2;	// UTF-16 (LE)
		break;
	case 0xBBEF:	// Yeah, the UTF-8 BOM is really 0xEF,0xBB,0xBF, but
		mode = 1;	// find me a non UTF-8 file that actually begins with "ï»"
		break;
	default:
		mode = 0;	// ANSI
		break;
	}
	fseek(fd_in, 0, SEEK_SET);
//	duprintf("'%s' was detected as %s\n", filename,
//		(mode==0)?"ANSI/UTF8 (no BOM)":((mode==1)?"UTF8 (with BOM)":"UTF16 (with BOM"));

	wtmpname = (wchar_t*)calloc(wcslen(wfilename)+2, sizeof(wchar_t));
	if (wtmpname == NULL) {
		uprintf("Could not allocate space for temporary output name\n");
		goto out;
	}
	wcscpy(wtmpname, wfilename);
	wtmpname[wcslen(wtmpname)] = '~';

	fd_out = _wfopen(wtmpname, outmode[mode]);
	if (fd_out == NULL) {
		uprintf("Could not open temporary output file '%s~'\n", filename);
		goto out;
	}

	// Process individual lines. NUL is always appended.
	while (fgetws(buf, ARRAYSIZE(buf), fd_in) != NULL) {

		i = 0;

		// Skip leading spaces
		i += wcsspn(&buf[i], wspace);

		// Our token should begin a line
		if (_wcsnicmp(&buf[i], wtoken, wcslen(wtoken)) != 0) {
			fputws(buf, fd_out);
			continue;
		}

		// Token was found, move past token
		i += wcslen(wtoken);

		// Skip whitespaces after token (while making sure there's at least one)
		ns = wcsspn(&buf[i], wspace);
		if (ns == 0) {
			fputws(buf, fd_out);
			continue;
		}
		i += ns;

		// p[x] = starting position of the fragment with the replaceable string
		p[0] = 0;
		for (j = 0; j < MAX_OCCURRENCES; j++) {
			torep[j] = wcsstr(&buf[i], wsrc);
			if (torep[j] == NULL)
				break;
			// Next fragment will start after current + replaced string
			i = (torep[j] - buf) + wcslen(wsrc);
			p[j + 1] = i;
			// Truncate each fragment to before the replaced string
			*torep[j] = 0;
		}

		// No replaceable string found => output as is
		if (torep[0] == NULL) {
			fputws(buf, fd_out);
			continue;
		}

		// Output all the truncated fragments + replaced strings
		for (j = 0; torep[j] != NULL; j++)
			// coverity[invalid_type]
			fwprintf_s(fd_out, L"%s%s", &buf[p[j]], wrep);

		// Output the last fragment
		// coverity[invalid_type]
		fwprintf_s(fd_out, L"%s", &buf[p[j]]);

		ret = (char*)rep;
	}

out:
	if (fd_in != NULL) fclose(fd_in);
	if (fd_out != NULL) fclose(fd_out);

	// If a replacement occurred, delete existing file and use the new one
	if (ret != NULL && wtmpname != NULL && wfilename != NULL) {
		// We're in Windows text mode => Remove CRs if requested
		fd_in = _wfopen(wtmpname, L"rb");
		fd_out = _wfopen(wfilename, L"wb");
		// Don't check fds
		if ((fd_in != NULL) && (fd_out != NULL)) {
			size = (mode==2)?2:1;
			while(fread(tmp, size, 1, fd_in) == 1) {
				if ((!dos2unix) || (tmp[0] != 0x0D))
					fwrite(tmp, size, 1, fd_out);
			}
			fclose(fd_in);
			fclose(fd_out);
		} else {
			uprintf("Could not write '%s' - original file has been left unmodified.\n", filename);
			ret = NULL;
			if (fd_in != NULL) fclose(fd_in);
			if (fd_out != NULL) fclose(fd_out);
		}
	}
	if (wtmpname != NULL)
		_wunlink(wtmpname);
	safe_free(wfilename);
	safe_free(wtmpname);
	safe_free(wtoken);
	safe_free(wsrc);
	safe_free(wrep);

	return ret;
}


/*
 * PE parsing functions — moved to common/parser.c.
 * They are platform-independent (pure buffer operations) and are now
 * shared between Windows and Linux builds via common/parser.c.
 */
#ifndef COMMON_PARSER_PE_FUNCTIONS

// Return the arch of a PE executable buffer
uint16_t GetPeArch(uint8_t* buf)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buf;
	IMAGE_NT_HEADERS32* pe_header;

	if (buf == NULL || dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return IMAGE_FILE_MACHINE_UNKNOWN;

	pe_header = (IMAGE_NT_HEADERS32*)&buf[dos_header->e_lfanew];
	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
		return IMAGE_FILE_MACHINE_UNKNOWN;
	return pe_header->FileHeader.Machine;
}

// Return the address and (optionally) the length of a PE section from a PE buffer
uint8_t* GetPeSection(uint8_t* buf, const char* name, uint32_t* len)
{
	char section_name[IMAGE_SIZEOF_SHORT_NAME] = { 0 };
	uint32_t i, nb_sections;
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buf;
	IMAGE_NT_HEADERS32* pe_header;
	IMAGE_NT_HEADERS64* pe64_header;
	IMAGE_SECTION_HEADER* section_header;

	static_strcpy(section_name, name);

	if (buf == NULL || name == NULL || dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pe_header = (IMAGE_NT_HEADERS32*)&buf[dos_header->e_lfanew];
	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
		return NULL;
	if (pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 || pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM) {
		section_header = (IMAGE_SECTION_HEADER*)(&pe_header[1]);
		nb_sections = pe_header->FileHeader.NumberOfSections;
	} else {
		pe64_header = (IMAGE_NT_HEADERS64*)pe_header;
		section_header = (IMAGE_SECTION_HEADER*)(&pe64_header[1]);
		nb_sections = pe64_header->FileHeader.NumberOfSections;
	}
	for (i = 0; i < nb_sections; i++) {
		if (memcmp(section_header[i].Name, section_name, sizeof(section_name)) == 0) {
			if (len != NULL)
				*len = section_header->SizeOfRawData;
			return &buf[section_header[i].PointerToRawData];
		}
	}
	return NULL;
}

// Convert an RVA address to a physical address from a PE buffer
uint8_t* RvaToPhysical(uint8_t* buf, uint32_t rva)
{
	uint32_t i, nb_sections;
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buf;
	IMAGE_NT_HEADERS32* pe_header;
	IMAGE_NT_HEADERS64* pe64_header;
	IMAGE_SECTION_HEADER* section_header;

	if (buf == NULL || dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pe_header = (IMAGE_NT_HEADERS32*)&buf[dos_header->e_lfanew];
	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
		return NULL;
	if (pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 || pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM) {
		section_header = (IMAGE_SECTION_HEADER*)(pe_header + 1);
		nb_sections = pe_header->FileHeader.NumberOfSections;
	} else {
		pe64_header = (IMAGE_NT_HEADERS64*)pe_header;
		section_header = (IMAGE_SECTION_HEADER*)(pe64_header + 1);
		nb_sections = pe64_header->FileHeader.NumberOfSections;
	}

	for (i = 0; i < nb_sections; i++) {
		if ((section_header[i].VirtualAddress <= rva && rva < (section_header[i].VirtualAddress + section_header[i].Misc.VirtualSize)))
			break;
	}
	if (i >= nb_sections)
		return NULL;

	return &buf[section_header[i].PointerToRawData + (rva - section_header[i].VirtualAddress)];
}

// Using the MS APIs to poke the resources of the EFI bootloaders is simply TOO. DAMN. SLOW.
// So, to QUICKLY access the resources we need, we reivent Microsoft's sub-optimal resource parser.
static BOOL FoundResourceRva = FALSE;
uint32_t FindResourceRva(const wchar_t* name, uint8_t* root, uint8_t* dir, uint32_t* len)
{
	uint32_t i, rva;
	IMAGE_RESOURCE_DIRECTORY* _dir = (IMAGE_RESOURCE_DIRECTORY*)dir;
	IMAGE_RESOURCE_DIRECTORY_ENTRY* dir_entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)&_dir[1];
	IMAGE_RESOURCE_DIR_STRING_U* dir_string;
	IMAGE_RESOURCE_DATA_ENTRY* data_entry;

	if (root == NULL || dir == NULL || name == NULL)
		return 0;

	// Initial invocation should always start at the root
	if (root == dir)
		FoundResourceRva = FALSE;

	for (i = 0; i < (uint32_t)_dir->NumberOfNamedEntries + _dir->NumberOfIdEntries; i++) {
		if (!FoundResourceRva && i < _dir->NumberOfNamedEntries) {
			dir_string = (IMAGE_RESOURCE_DIR_STRING_U*)(root + dir_entry[i].NameOffset);
			if (dir_string->Length != wcslen(name) ||
				memcmp(name, dir_string->NameString, wcslen(name)) != 0)
				continue;
			FoundResourceRva = TRUE;
		}
		if (dir_entry[i].OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY) {
			rva = FindResourceRva(name, root, &root[dir_entry[i].OffsetToDirectory], len);
			if (rva != 0)
				return rva;
		} else if (FoundResourceRva) {
			data_entry = (IMAGE_RESOURCE_DATA_ENTRY*)(root + dir_entry[i].OffsetToData);
			if (len != NULL)
				*len = data_entry->Size;
			return data_entry->OffsetToData;
		}
	}
	return 0;
}

uint8_t* GetPeSignatureData(uint8_t* buf)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buf;
	IMAGE_NT_HEADERS32* pe_header;
	IMAGE_NT_HEADERS64* pe64_header;
	IMAGE_DATA_DIRECTORY sec_dir;
	WIN_CERTIFICATE* cert;

	if (buf == NULL || dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pe_header = (IMAGE_NT_HEADERS32*)&buf[dos_header->e_lfanew];
	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if (pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 || pe_header->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM) {
		sec_dir = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	} else {
		pe64_header = (IMAGE_NT_HEADERS64*)pe_header;
		sec_dir = pe64_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	}
	if (sec_dir.VirtualAddress == 0 || sec_dir.Size == 0)
		return NULL;

	cert = (WIN_CERTIFICATE*)&buf[sec_dir.VirtualAddress];
	if (cert->dwLength == 0 || cert->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
		return NULL;

	return (uint8_t*)cert;
}
#endif /* COMMON_PARSER_PE_FUNCTIONS */
