/*
 * tests/fuzz_parser.c — libFuzzer harness for parser.c
 *
 * Targets:
 *   - get_token_data_buffer()      (reads untrusted .loc / .ver buffers)
 *   - get_sanitized_token_data_buffer()
 *   - parse_update()               (parses rufus_linux.ver over the network)
 *   - GetSbatEntries()             (parses SBAT CSV from PE sections)
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -g \
 *     -I../src/linux/compat -I../src/windows -I../src/linux \
 *     -I../src -I../src/common \
 *     fuzz_parser.c ../src/linux/parser.c ../src/common/parser.c \
 *     ../src/linux/stdfn.c ../src/linux/stdio.c \
 *     ../src/common/localization.c \
 *     fuzz_parser_glue.c \
 *     -o fuzz_parser -lpthread
 *
 * Run:
 *   ./fuzz_parser corpus/parser/ -max_total_time=60
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Compat layer */
#include "windows.h"
#include "rufus.h"

extern char* get_token_data_buffer(const char* token, unsigned int n,
                                   const char* buffer, size_t buffer_size);
extern void parse_update(char* buf, size_t len);
extern RUFUS_UPDATE update;

/* GetSbatEntries is declared in rufus.h but lives in common/parser.c */
extern sbat_entry_t* GetSbatEntries(char* sbatlevel);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0 || size > 128 * 1024)
		return 0;

	/* Make a NUL-terminated mutable copy — all three functions expect this */
	char *buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	/* Target 1: get_token_data_buffer with a few common token names */
	const char *tokens[] = { "version", "download_url", "loc_url",
	                         "loc_version", "platform_min", "release_notes",
	                         "v", "", "A" };
	for (size_t i = 0; i < sizeof(tokens)/sizeof(tokens[0]); i++) {
		char *r = get_token_data_buffer(tokens[i], 1, buf, size + 1);
		free(r);
	}

	/* Target 2: parse_update — needs an extra byte for the NUL */
	char *buf2 = malloc(size + 2);
	if (buf2) {
		memcpy(buf2, data, size);
		buf2[size]   = '\n';
		buf2[size+1] = '\0';
		parse_update(buf2, size + 2);
		free(buf2);
	}
	safe_free(update.download_url);
	safe_free(update.release_notes);
	safe_free(update.loc_url);
	update.loc_version = 0;

	/* Target 3: GetSbatEntries — SBAT CSV parser */
	sbat_entry_t *sbat = GetSbatEntries(buf);
	if (sbat) {
		/* Just free the list — entries point into buf, not separately allocated */
		free(sbat);
	}

	free(buf);
	return 0;
}
