/*
 * test_cli_linux.c — TDD tests for the non-GTK CLI argument parser.
 *
 * Tests cli_parse_args() and cli_options_init() in isolation.
 * No network, no device access, no format thread — pure arg parsing.
 *
 * Build: see tests/Makefile entry for test_cli_linux.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "framework.h"
#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/winioctl.h"
#include "../src/windows/rufus.h"
#include "../src/linux/cli.h"

/* ---- helpers ---- */

/*
 * Build a fake argv from a string of space-separated tokens.
 * Caller must free() the returned array and each element.
 * Returns NULL on allocation failure.
 */
static char **build_argv(const char *args_str, int *argc_out)
{
    /* Copy the string so we can tokenise it */
    char *copy = strdup(args_str);
    if (!copy) return NULL;

    /* Count tokens */
    int count = 0;
    char *p = copy;
    while (*p) {
        while (*p == ' ') p++;
        if (*p) { count++; while (*p && *p != ' ') p++; }
    }

    char **argv = (char **)malloc((size_t)(count + 1) * sizeof(char *));
    if (!argv) { free(copy); return NULL; }

    /* Fill argv */
    int i = 0;
    p = copy;
    while (*p && i < count) {
        while (*p == ' ') p++;
        if (!*p) break;
        char *start = p;
        while (*p && *p != ' ') p++;
        size_t len = (size_t)(p - start);
        argv[i] = (char *)malloc(len + 1);
        if (!argv[i]) { /* leak on alloc failure (test only) */ break; }
        memcpy(argv[i], start, len);
        argv[i][len] = '\0';
        i++;
    }
    argv[i] = NULL;
    *argc_out = i;
    free(copy);
    return argv;
}

static void free_argv(char **argv, int argc)
{
    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);
}

/* Convenience: parse a string of args, return parse result, fill opts. */
static int parse(const char *args_str, cli_options_t *opts)
{
    cli_options_init(opts);
    int argc;
    char **argv = build_argv(args_str, &argc);
    if (!argv) return CLI_PARSE_ERROR;
    int r = cli_parse_args(argc, argv, opts);
    free_argv(argv, argc);
    return r;
}

/* ---- cli_options_init tests ---- */

static void test_init_clears_device(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.device[0] == '\0');
}

static void test_init_clears_image(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.image[0] == '\0');
}

static void test_init_fs_is_minus1(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.fs == -1);
}

static void test_init_part_scheme_is_minus1(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.part_scheme == -1);
}

static void test_init_target_is_minus1(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.target == -1);
}

static void test_init_quick_is_minus1(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.quick == -1); /* -1 means "use default" */
}

static void test_init_verify_is_zero(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.verify == 0);
}

/* ---- --device tests ---- */

static void test_device_is_parsed(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(strcmp(opts.device, "/dev/sda") == 0);
}

static void test_device_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus -d /dev/sdb", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(strcmp(opts.device, "/dev/sdb") == 0);
}

static void test_missing_device_arg_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

/* ---- --image tests ---- */

static void test_image_is_parsed(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --image /tmp/ubuntu.iso", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(strcmp(opts.image, "/tmp/ubuntu.iso") == 0);
}

static void test_image_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -i /tmp/test.img", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(strcmp(opts.image, "/tmp/test.img") == 0);
}

/* ---- --fs tests ---- */

static void test_fs_fat32(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fs fat32", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fs == FS_FAT32);
}

static void test_fs_ntfs(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fs ntfs", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fs == FS_NTFS);
}

static void test_fs_ext4(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fs ext4", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fs == FS_EXT4);
}

static void test_fs_ext3(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fs ext3", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fs == FS_EXT3);
}

static void test_fs_ext2(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fs ext2", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fs == FS_EXT2);
}

static void test_fs_exfat(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fs exfat", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fs == FS_EXFAT);
}

static void test_fs_udf(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fs udf", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fs == FS_UDF);
}

static void test_fs_fat16(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fs fat16", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fs == FS_FAT16);
}

static void test_fs_unknown_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fs zfs", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

/* ---- --partition-scheme tests ---- */

static void test_part_scheme_mbr(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --partition-scheme mbr", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.part_scheme == PARTITION_STYLE_MBR);
}

static void test_part_scheme_gpt(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --partition-scheme gpt", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.part_scheme == PARTITION_STYLE_GPT);
}

static void test_part_scheme_unknown_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --partition-scheme xfs", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

/* ---- --target tests ---- */

static void test_target_bios(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --target bios", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.target == TT_BIOS);
}

static void test_target_uefi(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --target uefi", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.target == TT_UEFI);
}

static void test_target_unknown_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --target legacy", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

/* ---- --quick / --no-quick tests ---- */

static void test_quick_sets_quick_true(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --quick", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.quick == 1);
}

static void test_no_quick_sets_quick_false(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --no-quick", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.quick == 0);
}

/* ---- --verify tests ---- */

static void test_verify_sets_verify_true(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --image /tmp/x.iso --verify", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.verify == 1);
}

/* ---- --label tests ---- */

static void test_label_is_parsed(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --label MYUSB", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(strcmp(opts.label, "MYUSB") == 0);
}

/* ---- --help tests ---- */

static void test_help_returns_help_code(void)
{
    cli_options_t opts;
    int r = parse("rufus --help", &opts);
    CHECK(r == CLI_PARSE_HELP);
}

static void test_help_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus -h", &opts);
    CHECK(r == CLI_PARSE_HELP);
}

/* ---- unknown option tests ---- */

static void test_unknown_option_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --frobnicate", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

/* ---- combination tests ---- */

static void test_all_options_combined(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sdc --image /tmp/ubuntu.iso "
                  "--fs fat32 --partition-scheme gpt --target uefi "
                  "--quick --verify --label UBUNTU", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(strcmp(opts.device, "/dev/sdc") == 0);
    CHECK(strcmp(opts.image, "/tmp/ubuntu.iso") == 0);
    CHECK(opts.fs == FS_FAT32);
    CHECK(opts.part_scheme == PARTITION_STYLE_GPT);
    CHECK(opts.target == TT_UEFI);
    CHECK(opts.quick == 1);
    CHECK(opts.verify == 1);
    CHECK(strcmp(opts.label, "UBUNTU") == 0);
}

static void test_no_args_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

/* ---- test suite ---- */

int main(void)
{
    printf("=== CLI argument parser tests ===\n");

    RUN_TEST(test_init_clears_device);
    RUN_TEST(test_init_clears_image);
    RUN_TEST(test_init_fs_is_minus1);
    RUN_TEST(test_init_part_scheme_is_minus1);
    RUN_TEST(test_init_target_is_minus1);
    RUN_TEST(test_init_quick_is_minus1);
    RUN_TEST(test_init_verify_is_zero);

    RUN_TEST(test_device_is_parsed);
    RUN_TEST(test_device_short_form);
    RUN_TEST(test_missing_device_arg_is_error);

    RUN_TEST(test_image_is_parsed);
    RUN_TEST(test_image_short_form);

    RUN_TEST(test_fs_fat32);
    RUN_TEST(test_fs_ntfs);
    RUN_TEST(test_fs_ext4);
    RUN_TEST(test_fs_ext3);
    RUN_TEST(test_fs_ext2);
    RUN_TEST(test_fs_exfat);
    RUN_TEST(test_fs_udf);
    RUN_TEST(test_fs_fat16);
    RUN_TEST(test_fs_unknown_is_error);

    RUN_TEST(test_part_scheme_mbr);
    RUN_TEST(test_part_scheme_gpt);
    RUN_TEST(test_part_scheme_unknown_is_error);

    RUN_TEST(test_target_bios);
    RUN_TEST(test_target_uefi);
    RUN_TEST(test_target_unknown_is_error);

    RUN_TEST(test_quick_sets_quick_true);
    RUN_TEST(test_no_quick_sets_quick_false);

    RUN_TEST(test_verify_sets_verify_true);

    RUN_TEST(test_label_is_parsed);

    RUN_TEST(test_help_returns_help_code);
    RUN_TEST(test_help_short_form);

    RUN_TEST(test_unknown_option_is_error);

    RUN_TEST(test_all_options_combined);
    RUN_TEST(test_no_args_is_error);

    TEST_RESULTS();
}
