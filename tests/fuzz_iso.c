/*
 * tests/fuzz_iso.c — libFuzzer harness for iso.c
 *
 * Writes the fuzz input to a temporary file on disk (libfuzzer inputs are
 * byte arrays; iso.c functions operate on file paths), then calls:
 *   - ReadISOFileToBuffer()  — reads a named file from inside an ISO image
 *   - ExtractISO()           — full extraction + scan of an ISO image
 *
 * Build:
 *   make -C tests fuzz-iso
 *
 *   (see Makefile FUZZ_ISO_* variables for the full clang invocation;
 *    requires system libcdio, libiso9660, libudf)
 *
 * Run:
 *   mkdir -p corpus/iso && ./fuzz_iso corpus/iso/ -max_total_time=60
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Compat layer */
#include "windows.h"
#include "rufus.h"

extern uint32_t ReadISOFileToBuffer(const char* iso, const char* iso_file,
                                    uint8_t** buf);
extern BOOL ExtractISO(const char* src_iso, const char* dest_dir, BOOL scan);

/* File paths to probe inside the ISO (common boot files) */
static const char * const iso_files[] = {
	"/boot/grub/grub.cfg",
	"/EFI/BOOT/bootx64.efi",
	"/isolinux/isolinux.bin",
	"/autorun.inf",
	"/bootmgr",
	"/sources/install.wim",
	"",
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char tmp_iso[] = "/tmp/fuzz_iso_XXXXXX";
	char tmp_dir[] = "/tmp/fuzz_iso_dir_XXXXXX";
	int fd;
	uint8_t *buf = NULL;

	if (size == 0 || size > 4 * 1024 * 1024)
		return 0;

	/* Write fuzz data to a temp ISO file */
	fd = mkstemp(tmp_iso);
	if (fd < 0)
		return 0;
	if ((size_t)write(fd, data, size) != size) {
		close(fd);
		unlink(tmp_iso);
		return 0;
	}
	close(fd);

	/* Target 1: ReadISOFileToBuffer — try to read various well-known paths */
	for (size_t i = 0; i < sizeof(iso_files)/sizeof(iso_files[0]); i++) {
		buf = NULL;
		uint32_t r = ReadISOFileToBuffer(tmp_iso, iso_files[i], &buf);
		(void)r;
		free(buf);
	}

	/* Target 2: ExtractISO in scan-only mode (BOOL scan = TRUE) — do not
	 * actually extract files, just walk the ISO directory tree */
	if (mkdtemp(tmp_dir) != NULL) {
		(void)ExtractISO(tmp_iso, tmp_dir, TRUE);
		/* tmp_dir may be empty or contain a few bytes; remove it */
		rmdir(tmp_dir);
	}

	unlink(tmp_iso);
	return 0;
}
