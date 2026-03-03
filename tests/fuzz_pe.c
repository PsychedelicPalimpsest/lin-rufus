/*
 * tests/fuzz_pe.c — libFuzzer harness for PE parser functions
 *
 * Targets:
 *   - GetPeArch()           (parses machine field from PE header)
 *   - GetPeSection()        (finds named sections: .sbat, .text, etc.)
 *   - GetPeSignatureData()  (finds WIN_CERTIFICATE in security directory)
 *   - FindResourceRva()     (walks IMAGE_RESOURCE_DIRECTORY)
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -g \
 *     -I../src/linux/compat -I../src/windows -I../src/linux \
 *     -I../src -I../src/common \
 *     fuzz_pe.c ../src/windows/parser.c ../src/linux/stdfn.c \
 *     fuzz_pe_glue.c \
 *     -o fuzz_pe
 *
 * Run:
 *   mkdir -p corpus/pe && ./fuzz_pe corpus/pe/ -max_total_time=60
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Compat layer */
#include "windows.h"
#include "rufus.h"

extern uint16_t GetPeArch(uint8_t* buf);
extern uint8_t* GetPeSection(uint8_t* buf, const char* name, uint32_t* len);
extern uint8_t* GetPeSignatureData(uint8_t* buf);
extern uint32_t FindResourceRva(const uint16_t* name, uint8_t* root,
                                uint8_t* root_end, uint8_t* dir, uint32_t* len);

/* Section names to probe (common PE sections + attack surface names) */
static const char * const section_names[] = {
	".text", ".data", ".rdata", ".rsrc", ".reloc",
	".sbat", ".sdmp", ".edata", ".idata",
	"", "\x00", "AAAAAAAAAA",
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 4 || size > 16 * 1024 * 1024)
		return 0;

	uint8_t *buf = malloc(size);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);

	/* Target 1: GetPeArch — just reads machine field, should never crash */
	(void)GetPeArch(buf);

	/* Target 2: GetPeSection — walk all section names */
	for (size_t i = 0; i < sizeof(section_names)/sizeof(section_names[0]); i++) {
		uint32_t len = 0;
		(void)GetPeSection(buf, section_names[i], &len);
		/* do NOT free result: it points into buf */
	}

	/* Target 3: GetPeSignatureData — reads security directory */
	(void)GetPeSignatureData(buf);

	/* Target 4: FindResourceRva — pass buf as root and dir, with proper root_end */
	if (size >= sizeof(uint16_t)) {
		uint32_t rsrc_len = 0;
		const uint16_t name = 0x0001; /* RT_CURSOR */
		(void)FindResourceRva(&name, buf, buf + size, buf, &rsrc_len);
	}

	free(buf);
	return 0;
}
