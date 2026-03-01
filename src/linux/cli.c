/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: cli.c — non-GTK command-line interface
 * Copyright © 2015-2025 Pete Batard <pete@akeo.ie>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <errno.h>

#include "rufus.h"
#include "missing.h"
#include "version.h"
#include "drive.h"
#include "compat/winioctl.h"
#include "cli.h"

/* Globals set by cli_apply_options(); extern'd in format.c and globals.c */
extern int    fs_type;
extern int    boot_type;
extern int    partition_type;
extern int    target_type;
extern BOOL   quick_format;
extern BOOL   enable_verify_write;
extern char  *image_path;
extern char   app_dir[];

/* Drive registration — drive.c */
extern void drive_linux_reset_drives(void);
extern void drive_linux_add_drive(const char *id, const char *name,
                                   const char *display_name, uint64_t size);
extern DWORD ErrorStatus;
extern DWORD FormatThread(void *param);

/* ---- helpers ---- */

static int parse_fs(const char *s)
{
	if (strcasecmp(s, "fat16")  == 0) return FS_FAT16;
	if (strcasecmp(s, "fat32")  == 0) return FS_FAT32;
	if (strcasecmp(s, "ntfs")   == 0) return FS_NTFS;
	if (strcasecmp(s, "udf")    == 0) return FS_UDF;
	if (strcasecmp(s, "exfat")  == 0) return FS_EXFAT;
	if (strcasecmp(s, "ext2")   == 0) return FS_EXT2;
	if (strcasecmp(s, "ext3")   == 0) return FS_EXT3;
	if (strcasecmp(s, "ext4")   == 0) return FS_EXT4;
	return -1;
}

static int parse_part_scheme(const char *s)
{
	if (strcasecmp(s, "mbr") == 0) return PARTITION_STYLE_MBR;
	if (strcasecmp(s, "gpt") == 0) return PARTITION_STYLE_GPT;
	return -1;
}

static int parse_target(const char *s)
{
	if (strcasecmp(s, "bios") == 0) return TT_BIOS;
	if (strcasecmp(s, "uefi") == 0) return TT_UEFI;
	return -1;
}

/* ---- public API ---- */

void cli_options_init(cli_options_t *opts)
{
	memset(opts, 0, sizeof(*opts));
	opts->fs          = -1;
	opts->part_scheme = -1;
	opts->target      = -1;
	opts->quick       = -1; /* means "use default" (quick format on) */
}

void cli_print_usage(const char *prog)
{
	printf("Usage: %s --device /dev/sdX [OPTIONS]\n\n"
	       "Mandatory:\n"
	       "  -d, --device PATH         Target device (e.g. /dev/sdb)\n\n"
	       "Options:\n"
	       "  -i, --image PATH          Image file to write as-is\n"
	       "  -f, --fs FS               Filesystem: fat16 fat32 ntfs udf exfat ext2 ext3 ext4\n"
	       "  -p, --partition-scheme S  Partition scheme: mbr gpt\n"
	       "  -t, --target T            Boot target: bios uefi\n"
	       "  -l, --label LABEL         Volume label\n"
	       "      --quick               Quick format (default)\n"
	       "      --no-quick            Full format (zero-fill)\n"
	       "      --verify              Verify write after image write\n"
	       "  -h, --help                Show this help\n",
	       prog ? prog : "rufus");
}

int cli_parse_args(int argc, char *argv[], cli_options_t *opts)
{
	static const struct option long_opts[] = {
		{ "device",           required_argument, NULL, 'd' },
		{ "image",            required_argument, NULL, 'i' },
		{ "fs",               required_argument, NULL, 'f' },
		{ "partition-scheme", required_argument, NULL, 'p' },
		{ "target",           required_argument, NULL, 't' },
		{ "label",            required_argument, NULL, 'l' },
		{ "quick",            no_argument,       NULL, 'q' },
		{ "no-quick",         no_argument,       NULL, 'Q' },
		{ "verify",           no_argument,       NULL, 'V' },
		{ "help",             no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int c;
	int tmp;

	/* Reset getopt state for re-entrant tests */
	optind = 1;
	opterr = 0; /* suppress default error messages — we print our own */

	while ((c = getopt_long(argc, argv, "d:i:f:p:t:l:hqQV",
	                        long_opts, NULL)) != -1) {
		switch (c) {
		case 'd':
			if (!optarg || !*optarg) {
				fprintf(stderr, "rufus: --device requires a path\n");
				return CLI_PARSE_ERROR;
			}
			snprintf(opts->device, sizeof(opts->device), "%s", optarg);
			break;

		case 'i':
			if (!optarg || !*optarg) {
				fprintf(stderr, "rufus: --image requires a path\n");
				return CLI_PARSE_ERROR;
			}
			snprintf(opts->image, sizeof(opts->image), "%s", optarg);
			break;

		case 'f':
			tmp = parse_fs(optarg ? optarg : "");
			if (tmp < 0) {
				fprintf(stderr, "rufus: unknown filesystem '%s'\n", optarg);
				return CLI_PARSE_ERROR;
			}
			opts->fs = tmp;
			break;

		case 'p':
			tmp = parse_part_scheme(optarg ? optarg : "");
			if (tmp < 0) {
				fprintf(stderr, "rufus: unknown partition scheme '%s'\n", optarg);
				return CLI_PARSE_ERROR;
			}
			opts->part_scheme = tmp;
			break;

		case 't':
			tmp = parse_target(optarg ? optarg : "");
			if (tmp < 0) {
				fprintf(stderr, "rufus: unknown target '%s'\n", optarg);
				return CLI_PARSE_ERROR;
			}
			opts->target = tmp;
			break;

		case 'l':
			if (!optarg || !*optarg) {
				fprintf(stderr, "rufus: --label requires a name\n");
				return CLI_PARSE_ERROR;
			}
			snprintf(opts->label, sizeof(opts->label), "%s", optarg);
			break;

		case 'q':
			opts->quick = 1;
			break;

		case 'Q':
			opts->quick = 0;
			break;

		case 'V':
			opts->verify = 1;
			break;

		case 'h':
			cli_print_usage(argv[0]);
			return CLI_PARSE_HELP;

		case '?':
		default:
			fprintf(stderr, "rufus: unknown option '%s'\n",
			        (optind > 0 && optind <= argc) ? argv[optind - 1] : "?");
			return CLI_PARSE_ERROR;
		}
	}

	/* --device is mandatory */
	if (opts->device[0] == '\0') {
		fprintf(stderr, "rufus: --device is required\n");
		cli_print_usage(argv[0]);
		return CLI_PARSE_ERROR;
	}

	return CLI_PARSE_OK;
}

void cli_apply_options(const cli_options_t *opts)
{
	/* Filesystem */
	if (opts->fs >= 0)
		fs_type = opts->fs;

	/* Partition scheme */
	if (opts->part_scheme >= 0)
		partition_type = opts->part_scheme;

	/* Target */
	if (opts->target >= 0)
		target_type = opts->target;

	/* Quick format (default on if not specified) */
	quick_format = (opts->quick == 0) ? FALSE : TRUE;

	/* Write verification */
	enable_verify_write = (opts->verify == 1) ? TRUE : FALSE;

	/* Image path */
	if (opts->image[0] != '\0') {
		/* image_path is a char* global — point it at a static buffer */
		static char _image_path[512];
		snprintf(_image_path, sizeof(_image_path), "%s", opts->image);
		image_path = _image_path;
		boot_type  = BT_IMAGE;
	}
}

int cli_run(const cli_options_t *opts)
{
	int fd;
	uint64_t device_size = 0;
	uint32_t sector_size = 512;
	struct stat st;
	HANDLE thread;

	/* Open device to measure it */
	fd = open(opts->device, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "rufus: cannot open '%s': %s\n",
		        opts->device, strerror(errno));
		return 1;
	}

	if (fstat(fd, &st) == 0) {
		if (S_ISBLK(st.st_mode)) {
			ioctl(fd, BLKGETSIZE64, &device_size);
			ioctl(fd, BLKSSZGET,    &sector_size);
		} else {
			device_size = (uint64_t)st.st_size;
		}
	}
	close(fd);

	if (device_size == 0) {
		fprintf(stderr, "rufus: cannot determine size of '%s'\n", opts->device);
		return 1;
	}

	/* Register the device so GetPhysicalHandle() can open it */
	drive_linux_reset_drives();
	drive_linux_add_drive(opts->device, opts->device, opts->device, device_size);

	/* Populate SelectedDrive so format.c knows drive geometry */
	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	SelectedDrive.DiskSize   = (LONGLONG)device_size;
	SelectedDrive.SectorSize = sector_size;

	/* Propagate CLI options into Rufus globals */
	cli_apply_options(opts);

	/* Launch FormatThread and wait for it */
	ErrorStatus = 0;
	thread = CreateThread(NULL, 0, FormatThread,
	                      (void *)(uintptr_t)DRIVE_INDEX_MIN, 0, NULL);
	if (thread == NULL) {
		fprintf(stderr, "rufus: failed to start format thread\n");
		return 1;
	}
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);

	if (ErrorStatus != 0) {
		fprintf(stderr, "rufus: format failed (status 0x%08X)\n", ErrorStatus);
		return 1;
	}

	printf("Format completed successfully.\n");
	return 0;
}
