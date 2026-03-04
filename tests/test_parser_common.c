/*
 * test_parser_common.c — Cross-platform tests for parser functions
 *
 * Tests functions from src/common/parser.c, src/common/localization.c,
 * and the platform-specific parser (linux/parser.c or windows/parser.c).
 *
 * Covers: replace_char, filter_chars, remove_substr, sanitize_label,
 *         get_data_from_asn1, GetSbatEntries, GetThumbprintEntries,
 *         open_loc_file, get_supported_locales, get_loc_data_file,
 *         get_token_data_file_indexed, set_token_data_file,
 *         get_token_data_buffer, insert_section_data, replace_in_token_data,
 *         parse_update_into
 *
 * Compiles and runs on both Linux (GCC) and Windows/Wine (MinGW).
 * On Wine, common/parser.c is compiled with -DRUFUS_EXCLUDE_PE_PARSER
 * to skip PE-parsing functions that conflict with MinGW system headers.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include "../src/windows/rufus.h"
#include "../src/windows/missing.h"
#include "../src/windows/localization.h"
#else
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/windows/localization.h"
#endif

/* ---- Minimal stubs ---------------------------------------------------- */

void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s) { (void)s; }

windows_version_t WindowsVersion = {0};
RUFUS_UPDATE update = {{0}, {0}, NULL, NULL};
BOOL en_msg_mode = FALSE;
BOOL right_to_left_mode = FALSE;

/* ---- Cross-platform temp file helpers --------------------------------- */

#ifdef _WIN32
static char *write_tmp_file(const char *content)
{
	char tmp_dir[MAX_PATH], tmp_path[MAX_PATH];
	GetTempPathA(MAX_PATH, tmp_dir);
	GetTempFileNameA(tmp_dir, "ruf", 0, tmp_path);
	FILE *f = fopen(tmp_path, "w");
	if (!f) return NULL;
	fputs(content, f);
	fclose(f);
	return strdup(tmp_path);
}
static void rm_tmp(char *path)
{
	if (path) { DeleteFileA(path); free(path); }
}
#else
#include <unistd.h>
#include <fcntl.h>
static char *write_tmp_file(const char *content)
{
	char *path = strdup("/tmp/test_parser_XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) { free(path); return NULL; }
	size_t len = strlen(content);
	if (write(fd, content, len) != (ssize_t)len) {
		close(fd); unlink(path); free(path); return NULL;
	}
	close(fd);
	return path;
}
static void rm_tmp(char *path)
{
	if (path) { unlink(path); free(path); }
}
#endif

/* ======================================================================
 * replace_char
 * ====================================================================== */

TEST(replace_char_basic)
{
	char *r = replace_char("a/b/c", '/', "-");
	CHECK(r != NULL);
	CHECK(strcmp(r, "a-b-c") == 0);
	free(r);
}

TEST(replace_char_multi_char_rep)
{
	char *r = replace_char("a b c", ' ', "XX");
	CHECK(r != NULL);
	CHECK(strcmp(r, "aXXbXXc") == 0);
	free(r);
}

TEST(replace_char_no_match)
{
	char *r = replace_char("abc", '/', "-");
	CHECK(r != NULL);
	CHECK(strcmp(r, "abc") == 0);
	free(r);
}

TEST(replace_char_empty_src)
{
	char *r = replace_char("", '/', "-");
	CHECK(r != NULL);
	CHECK(strcmp(r, "") == 0);
	free(r);
}

TEST(replace_char_null_src)
{
	char *r = replace_char(NULL, '/', "-");
	CHECK(r == NULL);
}

TEST(replace_char_null_rep)
{
	char *r = replace_char("abc", '/', NULL);
	CHECK(r == NULL);
}

TEST(replace_char_all_match)
{
	char *r = replace_char("///", '/', "AB");
	CHECK(r != NULL);
	CHECK(strcmp(r, "ABABAB") == 0);
	free(r);
}

/* ======================================================================
 * filter_chars
 * ====================================================================== */

TEST(filter_chars_basic)
{
	char s[] = "hello world!";
	filter_chars(s, " !", '-');
	CHECK(strchr(s, ' ') == NULL);
	CHECK(strchr(s, '!') == NULL);
}

TEST(filter_chars_no_match)
{
	char s[] = "hello";
	filter_chars(s, "xyz", '-');
	CHECK(strcmp(s, "hello") == 0);
}

TEST(filter_chars_null_str)
{
	/* Must not crash */
	filter_chars(NULL, "x", '-');
}

TEST(filter_chars_null_rem)
{
	char s[] = "hello";
	/* Must not crash and leave string unchanged */
	filter_chars(s, NULL, '-');
}

/* ======================================================================
 * remove_substr
 * ====================================================================== */

TEST(remove_substr_basic)
{
	char *r = remove_substr("hello world", "world");
	CHECK(r != NULL);
	CHECK(strstr(r, "world") == NULL);
	free(r);
}

TEST(remove_substr_multiple)
{
	char *r = remove_substr("aXbXc", "X");
	CHECK(r != NULL);
	CHECK(strcmp(r, "abc") == 0);
	free(r);
}

TEST(remove_substr_no_match)
{
	char *r = remove_substr("hello", "xyz");
	CHECK(r != NULL);
	CHECK(strcmp(r, "hello") == 0);
	free(r);
}

TEST(remove_substr_null_src)
{
	char *r = remove_substr(NULL, "x");
	CHECK(r == NULL);
}

TEST(remove_substr_null_sub)
{
	char *r = remove_substr("hello", NULL);
	CHECK(r == NULL);
}

TEST(remove_substr_sub_longer_than_src)
{
	char *r = remove_substr("hi", "hello world");
	CHECK(r == NULL);
}

/* ======================================================================
 * sanitize_label
 * ====================================================================== */

TEST(sanitize_label_basic_lowercase)
{
	char s[] = "Ubuntu-22.04-LTS";
	int r = sanitize_label(s);
	CHECK(r == 0);
	CHECK(strstr(s, "LTS") == NULL);
	CHECK(strstr(s, "lts") == NULL);
}

TEST(sanitize_label_strip_known_suffixes)
{
	char s[] = "fedora-x86-64";
	sanitize_label(s);
	CHECK(strstr(s, "x86-64") == NULL);
}

TEST(sanitize_label_leading_dashes_removed)
{
	char s[] = "---ubuntu";
	sanitize_label(s);
	CHECK(s[0] != '-');
}

TEST(sanitize_label_double_dash_collapsed)
{
	char s[] = "foo--bar";
	sanitize_label(s);
	CHECK(strstr(s, "--") == NULL);
}

TEST(sanitize_label_special_chars_replaced)
{
	char s[] = "Hello World!";
	sanitize_label(s);
	CHECK(strchr(s, ' ') == NULL);
	CHECK(strchr(s, '!') == NULL);
}

/* ======================================================================
 * get_data_from_asn1
 * ====================================================================== */

static const uint8_t asn1_seq[] = {
	0x30, 0x0B,
	0x06, 0x02, 0x2A, 0x03,       /* OID 1.2.3 */
	0x04, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F  /* OCTET STRING "hello" */
};

TEST(get_data_from_asn1_find_by_oid)
{
	size_t data_len = 0;
	void *data = get_data_from_asn1(asn1_seq, sizeof(asn1_seq), "1.2.3", 0x04, &data_len);
	CHECK(data != NULL);
	CHECK(data_len == 5);
	CHECK(memcmp(data, "hello", 5) == 0);
}

TEST(get_data_from_asn1_no_oid_match)
{
	size_t data_len = 0;
	void *data = get_data_from_asn1(asn1_seq, sizeof(asn1_seq), "9.9.9", 0x04, &data_len);
	CHECK(data == NULL);
}

TEST(get_data_from_asn1_null_buf)
{
	size_t data_len = 0;
	void *data = get_data_from_asn1(NULL, 10, "1.2.3", 0x04, &data_len);
	CHECK(data == NULL);
}

TEST(get_data_from_asn1_too_large)
{
	size_t data_len = 0;
	void *data = get_data_from_asn1(asn1_seq, 70000, "1.2.3", 0x04, &data_len);
	CHECK(data == NULL);
}

/* ======================================================================
 * GetSbatEntries
 * ====================================================================== */

TEST(GetSbatEntries_basic)
{
	char sbat[] = "shim,1\ngrub,3\n";
	sbat_entry_t *entries = GetSbatEntries(sbat);
	CHECK(entries != NULL);
	CHECK(strcmp(entries[0].product, "shim") == 0);
	CHECK(entries[0].version == 1);
	CHECK(strcmp(entries[1].product, "grub") == 0);
	CHECK(entries[1].version == 3);
	CHECK(entries[2].product == NULL);
	free(entries);
}

TEST(GetSbatEntries_comment_skipped)
{
	char sbat[] = "# this is a comment\nshim,2\n";
	sbat_entry_t *entries = GetSbatEntries(sbat);
	CHECK(entries != NULL);
	CHECK(strcmp(entries[0].product, "shim") == 0);
	CHECK(entries[0].version == 2);
	free(entries);
}

TEST(GetSbatEntries_null_input)
{
	sbat_entry_t *entries = GetSbatEntries(NULL);
	CHECK(entries == NULL);
}

TEST(GetSbatEntries_hex_version)
{
	char sbat[] = "shim,0x0a\n";
	sbat_entry_t *entries = GetSbatEntries(sbat);
	CHECK(entries != NULL);
	CHECK(entries[0].version == 10);
	free(entries);
}

TEST(GetSbatEntries_extra_fields_ignored)
{
	char sbat[] = "shim,1,extra,fields\n";
	sbat_entry_t *entries = GetSbatEntries(sbat);
	CHECK(entries != NULL);
	CHECK(entries[0].version == 1);
	free(entries);
}

/* ======================================================================
 * GetThumbprintEntries
 * ====================================================================== */

#define SHA1_HEX "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3"

TEST(GetThumbprintEntries_basic)
{
	char txt[] = SHA1_HEX "\n";
	thumbprint_list_t *tp = GetThumbprintEntries(txt);
	CHECK(tp != NULL);
	CHECK(tp->count == 1);
	free(tp);
}

TEST(GetThumbprintEntries_null_input)
{
	thumbprint_list_t *tp = GetThumbprintEntries(NULL);
	CHECK(tp == NULL);
}

TEST(GetThumbprintEntries_invalid_skipped)
{
	char txt[] = "not_a_thumbprint\n" SHA1_HEX "\n";
	thumbprint_list_t *tp = GetThumbprintEntries(txt);
	CHECK(tp != NULL);
	CHECK(tp->count == 1);
	free(tp);
}

TEST(GetThumbprintEntries_multiple)
{
	char txt[] = SHA1_HEX "\n" SHA1_HEX "\n";
	thumbprint_list_t *tp = GetThumbprintEntries(txt);
	CHECK(tp != NULL);
	CHECK(tp->count == 2);
	free(tp);
}

/* ======================================================================
 * open_loc_file
 * ====================================================================== */

TEST(open_loc_file_null)
{
	init_localization();
	FILE *fd = open_loc_file(NULL);
	CHECK(fd == NULL);
	exit_localization();
}

TEST(open_loc_file_nonexistent)
{
	init_localization();
	FILE *fd = open_loc_file("/nonexistent/path/to/file.loc");
	CHECK(fd == NULL);
	exit_localization();
}

TEST(open_loc_file_real_file)
{
	init_localization();
	char *path = write_tmp_file("hello");
	CHECK(path != NULL);
	FILE *fd = open_loc_file(path);
	CHECK(fd != NULL);
	fclose(fd);
	rm_tmp(path);
	exit_localization();
}

/* ======================================================================
 * get_supported_locales / get_loc_data_file
 * ====================================================================== */

#define REAL_LOC_PATH "../res/loc/embedded.loc"

TEST(get_supported_locales_null)
{
	init_localization();
	BOOL r = get_supported_locales(NULL);
	CHECK_MSG(r == FALSE, "get_supported_locales(NULL) must return FALSE");
	exit_localization();
}

TEST(get_supported_locales_nonexistent)
{
	init_localization();
	BOOL r = get_supported_locales("/nonexistent/path/rufus.loc");
	CHECK_MSG(r == FALSE,
	          "get_supported_locales with missing file must return FALSE");
	exit_localization();
}

TEST(get_supported_locales_real_file)
{
	init_localization();
	BOOL r = get_supported_locales(REAL_LOC_PATH);
	CHECK_MSG(r == TRUE,
	          "get_supported_locales must succeed with the real embedded.loc");
	CHECK_MSG(!list_empty(&locale_list),
	          "locale_list must be populated");
	exit_localization();
}

TEST(get_supported_locales_contains_en_us)
{
	init_localization();
	get_supported_locales(REAL_LOC_PATH);
	BOOL found = FALSE;
	loc_cmd *lcmd;
	list_for_each_entry(lcmd, &locale_list, loc_cmd, list) {
		if (lcmd->txt[0] && strcmp(lcmd->txt[0], "en-US") == 0) {
			found = TRUE;
			break;
		}
	}
	CHECK_MSG(found, "locale_list must contain en-US after loading embedded.loc");
	exit_localization();
}

TEST(get_loc_data_file_null_locale)
{
	init_localization();
	get_supported_locales(REAL_LOC_PATH);
	BOOL r = get_loc_data_file(REAL_LOC_PATH, NULL);
	CHECK_MSG(r == FALSE,
	          "get_loc_data_file with NULL locale must return FALSE");
	exit_localization();
}

TEST(get_loc_data_file_en_us)
{
	init_localization();
	BOOL r = get_supported_locales(REAL_LOC_PATH);
	CHECK_MSG(r == TRUE, "get_supported_locales must succeed");
	loc_cmd *en = get_locale_from_name((char *)"en-US", TRUE);
	CHECK_MSG(en != NULL, "get_locale_from_name must find en-US");
	r = get_loc_data_file(REAL_LOC_PATH, en);
	CHECK_MSG(r == TRUE, "get_loc_data_file for en-US must succeed");
	exit_localization();
}

TEST(get_loc_data_file_populates_msg_table)
{
	extern char **msg_table;
	init_localization();
	get_supported_locales(REAL_LOC_PATH);
	loc_cmd *en = get_locale_from_name((char *)"en-US", TRUE);
	if (en != NULL)
		get_loc_data_file(REAL_LOC_PATH, en);
	CHECK_MSG(msg_table != NULL, "msg_table must be non-NULL");
	CHECK_MSG(msg_table[1] != NULL,
	          "MSG_001 must be populated after loading en-US locale");
	exit_localization();
}

/* ======================================================================
 * get_token_data_file_indexed
 * ====================================================================== */

TEST(get_token_data_file_indexed_basic)
{
	char *path = write_tmp_file("key = value\n");
	char *r = get_token_data_file_indexed("key", path, 1);
	CHECK(r != NULL);
	CHECK(strcmp(r, "value") == 0);
	free(r);
	rm_tmp(path);
}

TEST(get_token_data_file_indexed_second_occurrence)
{
	char *path = write_tmp_file("key = first\nkey = second\n");
	char *r = get_token_data_file_indexed("key", path, 2);
	CHECK(r != NULL);
	CHECK(strcmp(r, "second") == 0);
	free(r);
	rm_tmp(path);
}

TEST(get_token_data_file_indexed_not_found)
{
	char *path = write_tmp_file("other = value\n");
	char *r = get_token_data_file_indexed("key", path, 1);
	CHECK(r == NULL);
	rm_tmp(path);
}

TEST(get_token_data_file_indexed_null_file)
{
	char *r = get_token_data_file_indexed("key", NULL, 1);
	CHECK(r == NULL);
}

TEST(get_token_data_file_indexed_null_token)
{
	char *r = get_token_data_file_indexed(NULL, "/tmp/dummy", 1);
	CHECK(r == NULL);
}

TEST(get_token_data_file_indexed_xml_style)
{
	char *path = write_tmp_file("<version>1.2.3</version>\n");
	char *r = get_token_data_file_indexed("version", path, 1);
	CHECK(r != NULL);
	CHECK(strcmp(r, "1.2.3") == 0);
	free(r);
	rm_tmp(path);
}

TEST(get_token_data_file_indexed_quoted_value)
{
	char *path = write_tmp_file("name = \"hello world\"\n");
	char *r = get_token_data_file_indexed("name", path, 1);
	CHECK(r != NULL);
	CHECK(strcmp(r, "hello world") == 0);
	free(r);
	rm_tmp(path);
}

/* ======================================================================
 * set_token_data_file
 * ====================================================================== */

TEST(set_token_data_file_replace_existing)
{
	char *path = write_tmp_file("key = old\n");
	char *r = set_token_data_file("key", "new", path);
	CHECK(r != NULL);
	char *v = get_token_data_file_indexed("key", path, 1);
	CHECK(v != NULL);
	CHECK(strcmp(v, "new") == 0);
	free(v);
	rm_tmp(path);
}

TEST(set_token_data_file_append_new)
{
	char *path = write_tmp_file("other = value\n");
	char *r = set_token_data_file("newkey", "newval", path);
	CHECK(r != NULL);
	char *v = get_token_data_file_indexed("newkey", path, 1);
	CHECK(v != NULL);
	CHECK(strcmp(v, "newval") == 0);
	free(v);
	rm_tmp(path);
}

TEST(set_token_data_file_null_args)
{
	CHECK(set_token_data_file(NULL, "val", "/tmp/x") == NULL);
	CHECK(set_token_data_file("key", NULL, "/tmp/x") == NULL);
	CHECK(set_token_data_file("key", "val", NULL) == NULL);
}

TEST(set_token_data_file_preserves_comments)
{
	char *path = write_tmp_file("; comment\nkey = old\n");
	set_token_data_file("key", "new", path);
	char buf[512];
	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = 0;
	CHECK(strstr(buf, "; comment") != NULL);
	rm_tmp(path);
}

/* ======================================================================
 * get_token_data_buffer
 * ====================================================================== */

TEST(get_token_data_buffer_basic)
{
	const char buf[] = "version = 1.2.3\n";
	char *r = get_token_data_buffer("version", 1, buf, sizeof(buf));
	CHECK(r != NULL);
	CHECK(strcmp(r, "1.2.3") == 0);
	free(r);
}

TEST(get_token_data_buffer_nth_occurrence)
{
	const char buf[] = "key = first\nkey = second\n";
	char *r = get_token_data_buffer("key", 2, buf, sizeof(buf));
	CHECK(r != NULL);
	CHECK(strcmp(r, "second") == 0);
	free(r);
}

TEST(get_token_data_buffer_not_found)
{
	const char buf[] = "other = value\n";
	char *r = get_token_data_buffer("missing", 1, buf, sizeof(buf));
	CHECK(r == NULL);
}

TEST(get_token_data_buffer_null_token)
{
	const char buf[] = "key = val\n";
	char *r = get_token_data_buffer(NULL, 1, buf, sizeof(buf));
	CHECK(r == NULL);
}

TEST(get_token_data_buffer_too_small)
{
	const char buf[] = "k=v";
	char *r = get_token_data_buffer("k", 1, buf, 3);
	CHECK(r == NULL);
}

TEST(get_token_data_buffer_no_nul_terminator)
{
	char buf[8] = "key=val";
	char *r = get_token_data_buffer("key", 1, buf, 7);
	CHECK(r == NULL);
}

/* ======================================================================
 * insert_section_data
 * ====================================================================== */

TEST(insert_section_data_basic)
{
	char *path = write_tmp_file("[section]\nfoo=bar\n");
	char *r = insert_section_data(path, "[section]", "newline=1", FALSE);
	CHECK(r != NULL);
	char *v = get_token_data_file_indexed("newline", path, 1);
	CHECK(v != NULL);
	CHECK(strcmp(v, "1") == 0);
	free(v);
	rm_tmp(path);
}

TEST(insert_section_data_null_args)
{
	CHECK(insert_section_data(NULL, "[s]", "data", FALSE) == NULL);
	CHECK(insert_section_data("/tmp/x", NULL, "data", FALSE) == NULL);
	CHECK(insert_section_data("/tmp/x", "[s]", NULL, FALSE) == NULL);
}

TEST(insert_section_data_section_not_found)
{
	char *path = write_tmp_file("[other]\nfoo=bar\n");
	char *r = insert_section_data(path, "[section]", "newline=1", FALSE);
	CHECK(r == NULL);
	rm_tmp(path);
}

/* ======================================================================
 * replace_in_token_data
 * ====================================================================== */

TEST(replace_in_token_data_basic)
{
	char *path = write_tmp_file("key oldval\n");
	char *r = replace_in_token_data(path, "key", "old", "new", FALSE);
	CHECK(r != NULL);
	char buf[256];
	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = 0;
	CHECK(strstr(buf, "new") != NULL);
	CHECK(strstr(buf, "old") == NULL || strstr(buf, "newval") != NULL);
	rm_tmp(path);
}

TEST(replace_in_token_data_no_match)
{
	char *path = write_tmp_file("key something\n");
	char *r = replace_in_token_data(path, "key", "nothere", "new", FALSE);
	CHECK(r == NULL);
	rm_tmp(path);
}

TEST(replace_in_token_data_same_src_rep)
{
	char *path = write_tmp_file("key val\n");
	char *r = replace_in_token_data(path, "key", "val", "val", FALSE);
	CHECK(r == NULL);
	rm_tmp(path);
}

TEST(replace_in_token_data_null_args)
{
	CHECK(replace_in_token_data(NULL, "k", "s", "r", FALSE) == NULL);
	CHECK(replace_in_token_data("/tmp/x", NULL, "s", "r", FALSE) == NULL);
	CHECK(replace_in_token_data("/tmp/x", "k", NULL, "r", FALSE) == NULL);
	CHECK(replace_in_token_data("/tmp/x", "k", "s", NULL, FALSE) == NULL);
}

/* ======================================================================
 * parse_update_into
 * ====================================================================== */

TEST(parse_update_into_basic_version)
{
	char buf[256];
	snprintf(buf, sizeof(buf), "version = 4.2.1\n");
	RUFUS_UPDATE u = { 0 };
	BOOL r = parse_update_into(buf, strlen(buf) + 1, &u);
	CHECK(r == TRUE);
	CHECK_INT_EQ(4, u.version[0]);
	CHECK_INT_EQ(2, u.version[1]);
	CHECK_INT_EQ(1, u.version[2]);
	free(u.download_url); free(u.release_notes); free(u.loc_url);
}

TEST(parse_update_into_null_buf)
{
	RUFUS_UPDATE u = { 0 };
	BOOL r = parse_update_into(NULL, 0, &u);
	CHECK(r == FALSE);
}

TEST(parse_update_into_does_not_touch_global)
{
	char buf[256];
	snprintf(buf, sizeof(buf), "version = 99.99.99\n");
	RUFUS_UPDATE u = { 0 };
	uint16_t saved[3] = {
		update.version[0], update.version[1], update.version[2]
	};
	parse_update_into(buf, strlen(buf) + 1, &u);
	CHECK_INT_EQ(saved[0], update.version[0]);
	CHECK_INT_EQ(saved[1], update.version[1]);
	CHECK_INT_EQ(saved[2], update.version[2]);
	free(u.download_url); free(u.release_notes); free(u.loc_url);
}

TEST(parse_update_into_beta_has_higher_major_minor)
{
	char beta_buf[256];
	snprintf(beta_buf, sizeof(beta_buf), "version = 4.6.0\n");
	RUFUS_UPDATE beta = { 0 };
	parse_update_into(beta_buf, strlen(beta_buf) + 1, &beta);
	CHECK_INT_EQ(4, beta.version[0]);
	CHECK_INT_EQ(6, beta.version[1]);
	CHECK_INT_EQ(0, beta.version[2]);
	free(beta.download_url); free(beta.release_notes); free(beta.loc_url);
}

TEST(parse_update_into_stable_version_parsed_correctly)
{
	char stable_buf[256];
	snprintf(stable_buf, sizeof(stable_buf), "version = 4.5.1234\n");
	RUFUS_UPDATE stable = { 0 };
	parse_update_into(stable_buf, strlen(stable_buf) + 1, &stable);
	CHECK_INT_EQ(4, stable.version[0]);
	CHECK_INT_EQ(5, stable.version[1]);
	CHECK_INT_EQ(1234, stable.version[2]);
	free(stable.download_url); free(stable.release_notes); free(stable.loc_url);
}

int main(void)
{
	printf("=== parser common ===\n\n");

	printf("--- replace_char ---\n");
	RUN(replace_char_basic);
	RUN(replace_char_multi_char_rep);
	RUN(replace_char_no_match);
	RUN(replace_char_empty_src);
	RUN(replace_char_null_src);
	RUN(replace_char_null_rep);
	RUN(replace_char_all_match);

	printf("\n--- filter_chars ---\n");
	RUN(filter_chars_basic);
	RUN(filter_chars_no_match);
	RUN(filter_chars_null_str);
	RUN(filter_chars_null_rem);

	printf("\n--- remove_substr ---\n");
	RUN(remove_substr_basic);
	RUN(remove_substr_multiple);
	RUN(remove_substr_no_match);
	RUN(remove_substr_null_src);
	RUN(remove_substr_null_sub);
	RUN(remove_substr_sub_longer_than_src);

	printf("\n--- sanitize_label ---\n");
	RUN(sanitize_label_basic_lowercase);
	RUN(sanitize_label_strip_known_suffixes);
	RUN(sanitize_label_leading_dashes_removed);
	RUN(sanitize_label_double_dash_collapsed);
	RUN(sanitize_label_special_chars_replaced);

	printf("\n--- get_data_from_asn1 ---\n");
	RUN(get_data_from_asn1_find_by_oid);
	RUN(get_data_from_asn1_no_oid_match);
	RUN(get_data_from_asn1_null_buf);
	RUN(get_data_from_asn1_too_large);

	printf("\n--- GetSbatEntries ---\n");
	RUN(GetSbatEntries_basic);
	RUN(GetSbatEntries_comment_skipped);
	RUN(GetSbatEntries_null_input);
	RUN(GetSbatEntries_hex_version);
	RUN(GetSbatEntries_extra_fields_ignored);

	printf("\n--- GetThumbprintEntries ---\n");
	RUN(GetThumbprintEntries_basic);
	RUN(GetThumbprintEntries_null_input);
	RUN(GetThumbprintEntries_invalid_skipped);
	RUN(GetThumbprintEntries_multiple);

	printf("\n--- open_loc_file ---\n");
	RUN(open_loc_file_null);
	RUN(open_loc_file_nonexistent);
	RUN(open_loc_file_real_file);

	printf("\n--- get_supported_locales / get_loc_data_file ---\n");
	RUN(get_supported_locales_null);
	RUN(get_supported_locales_nonexistent);
	RUN(get_supported_locales_real_file);
	RUN(get_supported_locales_contains_en_us);
	RUN(get_loc_data_file_null_locale);
	RUN(get_loc_data_file_en_us);
	RUN(get_loc_data_file_populates_msg_table);

	printf("\n--- get_token_data_file_indexed ---\n");
	RUN(get_token_data_file_indexed_basic);
	RUN(get_token_data_file_indexed_second_occurrence);
	RUN(get_token_data_file_indexed_not_found);
	RUN(get_token_data_file_indexed_null_file);
	RUN(get_token_data_file_indexed_null_token);
	RUN(get_token_data_file_indexed_xml_style);
	RUN(get_token_data_file_indexed_quoted_value);

	printf("\n--- set_token_data_file ---\n");
	RUN(set_token_data_file_replace_existing);
	RUN(set_token_data_file_append_new);
	RUN(set_token_data_file_null_args);
	RUN(set_token_data_file_preserves_comments);

	printf("\n--- get_token_data_buffer ---\n");
	RUN(get_token_data_buffer_basic);
	RUN(get_token_data_buffer_nth_occurrence);
	RUN(get_token_data_buffer_not_found);
	RUN(get_token_data_buffer_null_token);
	RUN(get_token_data_buffer_too_small);
	RUN(get_token_data_buffer_no_nul_terminator);

	printf("\n--- insert_section_data ---\n");
	RUN(insert_section_data_basic);
	RUN(insert_section_data_null_args);
	RUN(insert_section_data_section_not_found);

	printf("\n--- replace_in_token_data ---\n");
	RUN(replace_in_token_data_basic);
	RUN(replace_in_token_data_no_match);
	RUN(replace_in_token_data_same_src_rep);
	RUN(replace_in_token_data_null_args);

	printf("\n--- parse_update_into ---\n");
	RUN(parse_update_into_basic_version);
	RUN(parse_update_into_null_buf);
	RUN(parse_update_into_does_not_touch_global);
	RUN(parse_update_into_beta_has_higher_major_minor);
	RUN(parse_update_into_stable_version_parsed_correctly);

	TEST_RESULTS();
}
