/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: cli.h — non-GTK command-line interface header
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

/*
 * cli.h — Non-GTK command-line interface for Rufus Linux.
 *
 * Activated when compiled without USE_GTK.  Provides argument parsing
 * and a minimal format-run harness for scripting / headless servers.
 */
#pragma once
#ifdef __linux__

#include <stddef.h>
#include <stdint.h>
#include "compat/windows.h"

/* Return codes from cli_parse_args() */
#define CLI_PARSE_OK       0   /* parsed successfully */
#define CLI_PARSE_HELP     1   /* --help requested (printed, do not run) */
#define CLI_PARSE_VERSION  2   /* --version requested (printed, do not run) */
#define CLI_PARSE_LIST     3   /* --list-devices requested (printed, do not run) */
#define CLI_PARSE_ERROR   -1   /* bad argument (message printed to stderr) */
/*
 * cli_options_t — collects all user-supplied format options.
 *
 * Fields left at their default (see cli_options_init) mean "auto/infer".
 * -1 for integer fields means "not specified".
 */
typedef struct {
    char device[512];       /* --device /dev/sdX (required) */
    char image[512];        /* --image  /path/to/image.iso  (optional) */
    char label[64];         /* --label  "LABEL"             (optional) */
    int  fs;                /* --fs fat32|ntfs|... → FS_* constant, or -1 */
    int  part_scheme;       /* --partition-scheme mbr|gpt  → PARTITION_STYLE_* or -1 */
    int  target;            /* --target bios|uefi          → TT_* or -1 */
    int  quick;             /* --quick / --no-quick: 1=yes, 0=no, -1=default(yes) */
    int  verify;            /* --verify: 1=yes, 0=no(default) */
    int  no_prompt;         /* --no-prompt: 1=auto-accept all dialogs, 0=interactive */
    int  boot_type;         /* BT_* constant; -1 = auto (BT_IMAGE if image set, else BT_NON_BOOTABLE) */
    DWORD cluster_size;     /* --cluster-size N bytes; 0 = default (auto) */
    uint64_t persistence_size; /* --persistence N MiB; 0 = no persistence partition */
    int  bad_blocks;        /* --bad-blocks: 1=run bad block scan, 0=skip */
    int  nb_passes;         /* --nb-passes 1-4: scan passes (requires bad_blocks); 0 = not set */
    char unattend_xml[512]; /* --unattend-xml PATH: pre-built unattend.xml to inject */
    int  include_hdds;      /* --include-hdds: 1=list/allow HDDs, 0=removable only (default) */
    int  zero_drive;        /* --zero-drive: 1=wipe entire drive with zeros and exit */
    int  force_large_fat32; /* --force-large-fat32: bypass size limit for FAT32 on large drives */
    int  ntfs_compression;  /* --ntfs-compression: enable NTFS file compression */
    int  json;              /* --json: use JSON output format (for --list-devices) */
    int  win_to_go;         /* --win-to-go/-W: write Windows To Go (WTG) image */
    int  write_as_image;    /* --write-as-image/-w: write image as raw DD (no extraction) */
    int  fast_zeroing;      /* --fast-zeroing/-Z: with --zero-drive: 0xFF-fill and readback */
    int  old_bios_fixes;    /* --old-bios-fixes/-o: add boot fixups for old/buggy BIOSes */
    int  allow_dual_uefi_bios; /* --allow-dual-uefi-bios/-A: allow both UEFI and legacy BIOS boot */
    int  preserve_timestamps; /* --preserve-timestamps/-e: keep file timestamps during ISO extraction */
    int  validate_md5sum;   /* --validate-md5sum/-m: enable UEFI media MD5 validation */
    int  no_rufus_mbr;      /* --no-rufus-mbr/-R: use standard MBR instead of Rufus's custom MBR */
    int  no_extended_label; /* --no-extended-label/-x: disable extended volume label on FAT */
    int  no_size_check;     /* --no-size-check/-s: skip image-larger-than-drive check */
    int  ignore_boot_marker; /* --ignore-boot-marker/-I: skip boot signature validation in VHD/image */
    int  file_indexing;     /* --file-indexing/-n: enable NTFS file indexing (Windows: avoid NOT_CONTENT_INDEXED) */
    int  detect_fakes;      /* --detect-fakes/-D: detect fake/cloned drives during bad-block scan */
    int  expert_mode;       /* --expert-mode/-E: unlock expert-level features (advanced hash, SBAT) */
    int  usb_debug;         /* --usb-debug/-g: enable verbose USB/SMART debug logging */
    int  enable_vmdk;       /* --enable-vmdk/-G: enable VMDK disk-image detection */
    int  advanced_format;   /* --advanced-format/-a: unlock ext2/3/4 and advanced format options */
} cli_options_t;

/* Initialise opts to default values (empty device/image, -1 for enums). */
void cli_options_init(cli_options_t *opts);

/*
 * cli_parse_args — parse argc/argv into opts.
 *
 * Returns CLI_PARSE_OK, CLI_PARSE_HELP, or CLI_PARSE_ERROR.
 * On CLI_PARSE_ERROR an error message is printed to stderr.
 * On CLI_PARSE_HELP usage is printed to stdout.
 */
int cli_parse_args(int argc, char *argv[], cli_options_t *opts);

/* Print usage to stdout. */
void cli_print_usage(const char *prog);

/*
 * cli_apply_options — propagate parsed options into Rufus globals.
 *
 * Must be called after cli_parse_args returns CLI_PARSE_OK and before
 * launching FormatThread.
 */
void cli_apply_options(const cli_options_t *opts);

/*
 * cli_print_devices — enumerate available removable drives (calls GetDevices).
 *
 * With json=0 prints one drive per line to stdout in tab-separated format:
 *   <device_path>\t<display_name>\t<size_bytes>
 *
 * With json=1 prints a JSON array of drive objects.
 *
 * Returns 0 if drives were found, 1 if none.
 */
int cli_print_devices(int json);

/*
 * cli_run — register the target device, apply options, launch FormatThread,
 * wait for completion, and return an exit code (0 = success, 1 = failure).
 *
 * Requires polkit/root privileges to open block devices for writing.
 */
int cli_run(const cli_options_t *opts);

#endif /* __linux__ */
