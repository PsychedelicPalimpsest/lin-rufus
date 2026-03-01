/*
 * cli.h — Non-GTK command-line interface for Rufus Linux.
 *
 * Activated when compiled without USE_GTK.  Provides argument parsing
 * and a minimal format-run harness for scripting / headless servers.
 */
#pragma once
#ifdef __linux__

#include <stddef.h>
#include "compat/windows.h"

/* Return codes from cli_parse_args() */
#define CLI_PARSE_OK      0   /* parsed successfully */
#define CLI_PARSE_HELP    1   /* --help requested (printed, do not run) */
#define CLI_PARSE_ERROR  -1   /* bad argument (message printed to stderr) */
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
 * cli_run — register the target device, apply options, launch FormatThread,
 * wait for completion, and return an exit code (0 = success, 1 = failure).
 *
 * Requires polkit/root privileges to open block devices for writing.
 */
int cli_run(const cli_options_t *opts);

#endif /* __linux__ */
