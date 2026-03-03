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
#include <stdint.h>
#include <inttypes.h>
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
#include "ui_combo_logic.h"

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
extern DWORD selected_cluster_size;
extern uint64_t persistence_size;
extern BOOL enable_bad_blocks;
extern int  nb_passes_sel;

/* Alert hook — stdlg.c (item 131) */
extern void alert_set_hook(BOOL (*hook)(int type));
extern void alert_clear_hook(void);

/* Auto-accept hook used by --no-prompt */
static BOOL cli_no_prompt_hook(int type) { (void)type; return TRUE; }

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

static int parse_boot_type(const char *s)
{
	if (strcasecmp(s, "non-bootable") == 0) return BT_NON_BOOTABLE;
	if (strcasecmp(s, "msdos")        == 0) return BT_MSDOS;
	if (strcasecmp(s, "freedos")      == 0) return BT_FREEDOS;
	if (strcasecmp(s, "image")        == 0) return BT_IMAGE;
	return -1;
}

/* Valid cluster sizes: powers of 2 from 512 to 2 MB */
#define CLUSTER_SIZE_MAX (2 * 1024 * 1024U)

static int parse_cluster_size(const char *s, DWORD *out)
{
	if (!s || !*s) return -1;
	char *end;
	unsigned long v = strtoul(s, &end, 10);
	if (*end != '\0' || v == 0 || v > CLUSTER_SIZE_MAX) return -1;
	/* Must be a power of two */
	if ((v & (v - 1)) != 0) return -1;
	*out = (DWORD)v;
	return 0;
}

/* ---- public API ---- */

void cli_options_init(cli_options_t *opts)
{
	memset(opts, 0, sizeof(*opts));
	opts->fs          = -1;
	opts->part_scheme = -1;
	opts->target      = -1;
	opts->quick       = -1; /* means "use default" (quick format on) */
	opts->boot_type   = -1; /* auto: BT_IMAGE if image set, else BT_NON_BOOTABLE */
	opts->cluster_size = 0; /* 0 = default cluster size */
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
	       "  -b, --boot-type TYPE      Boot type: non-bootable image freedos msdos\n"
	       "  -c, --cluster-size N      Cluster size in bytes (must be power of 2, e.g. 4096)\n"
	       "  -P, --persistence N       Persistence partition size in MiB (live-USB images only)\n"
	       "  -B, --bad-blocks          Scan device for bad blocks before formatting\n"
	       "  -N, --nb-passes N         Number of bad-block scan passes: 1-4 (requires -B)\n"
	       "  -l, --label LABEL         Volume label\n"
	       "  -L, --list-devices        List available removable drives and exit\n"
	       "      --quick               Quick format (default)\n"
	       "      --no-quick            Full format (zero-fill)\n"
	       "      --verify              Verify write after image write\n"
	       "      --no-prompt           Auto-accept all confirmation dialogs\n"
	       "      --version             Print version and exit\n"
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
		{ "boot-type",        required_argument, NULL, 'b' },
		{ "cluster-size",     required_argument, NULL, 'c' },
		{ "label",            required_argument, NULL, 'l' },
		{ "quick",            no_argument,       NULL, 'q' },
		{ "no-quick",         no_argument,       NULL, 'Q' },
		{ "verify",           no_argument,       NULL, 'V' },
		{ "no-prompt",        no_argument,       NULL, 'y' },
		{ "version",          no_argument,       NULL,  0  },
		{ "persistence",      required_argument, NULL, 'P' },
		{ "bad-blocks",       no_argument,       NULL, 'B' },
		{ "nb-passes",        required_argument, NULL, 'N' },
		{ "list-devices",     no_argument,       NULL, 'L' },
		{ "help",             no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int c;
	int tmp;
	int opt_index;

	/* Reset getopt state for re-entrant tests.
	 * On glibc, optind=0 forces full reinitialization (resets nextchar). */
	optind = 0;
	opterr = 0; /* suppress default error messages — we print our own */

	while ((c = getopt_long(argc, argv, "d:i:f:p:t:b:c:l:hqQVyP:BN:L",
	                        long_opts, &opt_index)) != -1) {
		switch (c) {
		case 0:
			/* Long-only option: check which one by name */
			if (strcmp(long_opts[opt_index].name, "version") == 0) {
				printf("rufus %s\n", RUFUS_VERSION_STR);
				return CLI_PARSE_VERSION;
			}
			break;

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

		case 'b':
			tmp = parse_boot_type(optarg ? optarg : "");
			if (tmp < 0) {
				fprintf(stderr, "rufus: unknown boot type '%s'\n", optarg);
				return CLI_PARSE_ERROR;
			}
			opts->boot_type = tmp;
			break;

		case 'c': {
			DWORD cs = 0;
			if (parse_cluster_size(optarg ? optarg : "", &cs) < 0) {
				fprintf(stderr, "rufus: invalid cluster size '%s' "
				        "(must be a power of 2 between 512 and 2097152)\n",
				        optarg ? optarg : "");
				return CLI_PARSE_ERROR;
			}
			opts->cluster_size = cs;
			break;
		}

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

		case 'y':
			opts->no_prompt = 1;
			break;

		case 'P': {
			/* --persistence N : N is in MiB */
			char *end = NULL;
			unsigned long val;
			if (!optarg || !*optarg) {
				fprintf(stderr, "rufus: --persistence requires a size in MiB\n");
				return CLI_PARSE_ERROR;
			}
			val = strtoul(optarg, &end, 10);
			if (!end || *end != '\0') {
				fprintf(stderr, "rufus: invalid persistence size '%s'\n", optarg);
				return CLI_PARSE_ERROR;
			}
			opts->persistence_size = (uint64_t)val * 1024 * 1024;
			break;
		}

		case 'B':
			opts->bad_blocks = 1;
			break;

		case 'N': {
			/* --nb-passes 1-4 */
			char *end = NULL;
			long val;
			if (!optarg || !*optarg) {
				fprintf(stderr, "rufus: --nb-passes requires a value (1-4)\n");
				return CLI_PARSE_ERROR;
			}
			val = strtol(optarg, &end, 10);
			if (!end || *end != '\0' || val < 1 || val > 4) {
				fprintf(stderr, "rufus: --nb-passes must be 1-4, got '%s'\n", optarg);
				return CLI_PARSE_ERROR;
			}
			opts->nb_passes = (int)val;
			break;
		}

		case 'L':
			return CLI_PARSE_LIST;

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

	/* --nb-passes requires --bad-blocks */
	if (opts->nb_passes > 0 && !opts->bad_blocks) {
		fprintf(stderr, "rufus: --nb-passes requires --bad-blocks\n");
		return CLI_PARSE_ERROR;
	}

	return CLI_PARSE_OK;
}

void cli_apply_options(const cli_options_t *opts)
{
	/* Filesystem */
	if (opts->fs >= 0) {
		fs_type = opts->fs;
		set_preselected_fs(opts->fs);
	}

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

	/* Explicit boot type (takes precedence over BT_IMAGE set above when both are
	 * set, which callers should avoid; override only when opts->boot_type >= 0) */
	if (opts->boot_type >= 0)
		boot_type = opts->boot_type;

	/* Cluster size (0 = default) */
	selected_cluster_size = opts->cluster_size;

	/* Persistence partition size (0 = no persistence) */
	persistence_size = opts->persistence_size;

	/* Bad blocks scan */
	if (opts->bad_blocks)
		enable_bad_blocks = TRUE;

	/* Number of bad-block scan passes (0 = not set, use default) */
	if (opts->nb_passes > 0)
		nb_passes_sel = opts->nb_passes - 1; /* 0-based index used by format.c */
}

/*
 * cli_print_devices — scan available removable drives and print each one.
 *
 * Output format (one drive per line, tab-separated):
 *   <device_path>\t<display_name>\t<size_bytes>
 *
 * Calls GetDevices(0) to populate rufus_drive[], then iterates the list.
 * Returns 0 if at least one drive was found, 1 if none were found.
 */
int cli_print_devices(void)
{
	extern RUFUS_DRIVE rufus_drive[MAX_DRIVES];
	GetDevices(0);
	int found = 0;
	for (int i = 0; i < MAX_DRIVES && rufus_drive[i].id != NULL; i++) {
		printf("%s\t%s\t%" PRIu64 "\n",
		       rufus_drive[i].id,
		       rufus_drive[i].display_name ? rufus_drive[i].display_name : "",
		       (uint64_t)rufus_drive[i].size);
		found++;
	}
	return found > 0 ? 0 : 1;
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

	/* Non-interactive mode: auto-accept all confirmation dialogs */
	if (opts->no_prompt)
		alert_set_hook(cli_no_prompt_hook);

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

	/* Remove the no-prompt hook now that the operation is complete */
	if (opts->no_prompt)
		alert_clear_hook();

	if (ErrorStatus != 0) {
		fprintf(stderr, "rufus: format failed (status 0x%08X)\n", ErrorStatus);
		return 1;
	}

	printf("Format completed successfully.\n");
	return 0;
}
