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

/* ---- --no-prompt tests (item 131) ---- */

static void test_no_prompt_sets_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --no-prompt", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_prompt == 1);
}

static void test_no_prompt_default_is_zero(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.no_prompt == 0);
}

static void test_no_prompt_combined_with_other_opts(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --quick --no-prompt", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_prompt == 1);
    CHECK(opts.quick == 1);
}



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

/* ---- --version tests ---- */

static void test_version_returns_version_code(void)
{
    cli_options_t opts;
    int r = parse("rufus --version", &opts);
    CHECK(r == CLI_PARSE_VERSION);
}

/* ---- --boot-type tests ---- */

static void test_init_boot_type_is_minus1(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.boot_type == -1);
}

static void test_boot_type_non_bootable(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --boot-type non-bootable", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.boot_type == BT_NON_BOOTABLE);
}

static void test_boot_type_image(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --boot-type image", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.boot_type == BT_IMAGE);
}

static void test_boot_type_freedos(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --boot-type freedos", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.boot_type == BT_FREEDOS);
}

static void test_boot_type_msdos(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --boot-type msdos", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.boot_type == BT_MSDOS);
}

static void test_boot_type_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus -d /dev/sda -b freedos", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.boot_type == BT_FREEDOS);
}

static void test_boot_type_unknown_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --boot-type foobar", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

static void test_boot_type_case_insensitive(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --boot-type FreeDOS", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.boot_type == BT_FREEDOS);
}

/* ---- --cluster-size tests ---- */

static void test_init_cluster_size_is_zero(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.cluster_size == 0);
}

static void test_cluster_size_512(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --cluster-size 512", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.cluster_size == 512);
}

static void test_cluster_size_4096(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --cluster-size 4096", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.cluster_size == 4096);
}

static void test_cluster_size_65536(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --cluster-size 65536", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.cluster_size == 65536);
}

static void test_cluster_size_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus -d /dev/sda -c 4096", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.cluster_size == 4096);
}

static void test_cluster_size_zero_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --cluster-size 0", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

static void test_cluster_size_not_power_of_two_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --cluster-size 1000", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

static void test_cluster_size_alpha_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --cluster-size abc", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

static void test_cluster_size_too_large_is_error(void)
{
    /* Cluster sizes > 2MB are not valid */
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --cluster-size 4194304", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

/* ---- --persistence tests ---- */

static void test_init_persistence_is_zero(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.persistence_size == 0);
}

static void test_persistence_zero(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --persistence 0", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.persistence_size == 0);
}

static void test_persistence_megabytes(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --persistence 512", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.persistence_size == (uint64_t)512 * 1024 * 1024);
}

static void test_persistence_gigabyte(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --persistence 4096", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.persistence_size == (uint64_t)4096 * 1024 * 1024);
}

static void test_persistence_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -P 256", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.persistence_size == (uint64_t)256 * 1024 * 1024);
}

static void test_persistence_alpha_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --persistence foo", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

/* ---- --bad-blocks tests ---- */

static void test_init_bad_blocks_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.bad_blocks == 0);
}

static void test_bad_blocks_sets_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --bad-blocks", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.bad_blocks != 0);
}

static void test_bad_blocks_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -B", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.bad_blocks != 0);
}

static void test_bad_blocks_default_is_false(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.bad_blocks == 0);
}

/* ---- --nb-passes tests ---- */

static void test_init_nb_passes_is_zero(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.nb_passes == 0);
}

static void test_nb_passes_one(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --bad-blocks --nb-passes 1", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.nb_passes == 1);
}

static void test_nb_passes_four(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --bad-blocks --nb-passes 4", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.nb_passes == 4);
}

static void test_nb_passes_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -B -N 2", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.nb_passes == 2);
}

static void test_nb_passes_zero_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --nb-passes 0", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

static void test_nb_passes_five_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --nb-passes 5", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

static void test_nb_passes_alpha_is_error(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --nb-passes abc", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

static void test_nb_passes_requires_bad_blocks(void)
{
    /* --nb-passes without --bad-blocks should be an error */
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --nb-passes 2", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

static void test_nb_passes_with_bad_blocks(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --bad-blocks --nb-passes 2", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.nb_passes == 2);
    CHECK(opts.bad_blocks != 0);
}

/* ---- --list-devices tests ---- */

static void test_list_devices_returns_list_code(void)
{
    cli_options_t opts;
    int r = parse("rufus --list-devices", &opts);
    CHECK(r == CLI_PARSE_LIST);
}

static void test_list_devices_does_not_require_device(void)
{
    /* --list-devices is valid without --device */
    cli_options_t opts;
    int r = parse("rufus --list-devices", &opts);
    CHECK(r == CLI_PARSE_LIST);
}

static void test_list_devices_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus -L", &opts);
    CHECK(r == CLI_PARSE_LIST);
}

static void test_list_devices_ignores_other_options(void)
{
    /* --list-devices should still work if combined with --device */
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --list-devices", &opts);
    CHECK(r == CLI_PARSE_LIST);
}

/* ---- --json tests ---- */

static void test_init_json_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.json == 0);
}

static void test_json_sets_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --list-devices --json", &opts);
    CHECK(r == CLI_PARSE_LIST);
    CHECK(opts.json != 0);
}

static void test_json_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus --list-devices -j", &opts);
    CHECK(r == CLI_PARSE_LIST);
    CHECK(opts.json != 0);
}

static void test_json_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --list-devices", &opts);
    CHECK(r == CLI_PARSE_LIST);
    CHECK(opts.json == 0);
}

/* ---- --unattend-xml tests ---- */

static void test_init_unattend_xml_is_empty(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.unattend_xml[0] == '\0');
}

static void test_unattend_xml_sets_path(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --unattend-xml /tmp/unattend.xml", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(strcmp(opts.unattend_xml, "/tmp/unattend.xml") == 0);
}

static void test_unattend_xml_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -u /tmp/unattend.xml", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(strcmp(opts.unattend_xml, "/tmp/unattend.xml") == 0);
}

static void test_unattend_xml_requires_argument(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --unattend-xml", &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

static void test_unattend_xml_empty_path_is_error(void)
{
    /* Pass an empty string argument directly (can't do via parse() which doesn't handle quotes) */
    cli_options_t opts;
    cli_options_init(&opts);
    char *argv[] = { "rufus", "--device", "/dev/sda", "--unattend-xml", "", NULL };
    int r = cli_parse_args(5, argv, &opts);
    CHECK(r == CLI_PARSE_ERROR);
}

/* ---- --include-hdds tests ---- */

static void test_init_include_hdds_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.include_hdds == 0);
}

static void test_include_hdds_sets_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --include-hdds", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.include_hdds != 0);
}

static void test_include_hdds_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -H", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.include_hdds != 0);
}

static void test_include_hdds_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.include_hdds == 0);
}

/* ---- --zero-drive tests ---- */

static void test_init_zero_drive_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.zero_drive == 0);
}

static void test_zero_drive_sets_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --zero-drive", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.zero_drive != 0);
}

static void test_zero_drive_short_form(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -z", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.zero_drive != 0);
}

static void test_zero_drive_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.zero_drive == 0);
}

/* ---- --force-large-fat32 tests ---- */

static void test_init_force_large_fat32_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.force_large_fat32 == 0);
}

static void test_force_large_fat32_sets_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --force-large-fat32", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.force_large_fat32 != 0);
}

static void test_force_large_fat32_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.force_large_fat32 == 0);
}

/* ---- --ntfs-compression tests ---- */

static void test_init_ntfs_compression_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.ntfs_compression == 0);
}

static void test_ntfs_compression_sets_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --ntfs-compression", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.ntfs_compression != 0);
}

static void test_ntfs_compression_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.ntfs_compression == 0);
}

/* ---- --win-to-go tests ---- */

static void test_init_win_to_go_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.win_to_go == 0);
}

static void test_win_to_go_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --win-to-go", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.win_to_go != 0);
}

static void test_win_to_go_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -W", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.win_to_go != 0);
}

static void test_win_to_go_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.win_to_go == 0);
}

static void test_win_to_go_combined_with_device_and_image(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --image /tmp/win.iso --win-to-go", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.win_to_go != 0);
    CHECK(strcmp(opts.device, "/dev/sda") == 0);
    CHECK(strcmp(opts.image, "/tmp/win.iso") == 0);
}

/* ---- --write-as-image tests ---- */

static void test_init_write_as_image_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.write_as_image == 0);
}

static void test_write_as_image_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --write-as-image", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.write_as_image != 0);
}

static void test_write_as_image_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -w", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.write_as_image != 0);
}

static void test_write_as_image_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.write_as_image == 0);
}

/* ---- --fast-zeroing tests ---- */

static void test_init_fast_zeroing_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.fast_zeroing == 0);
}

static void test_fast_zeroing_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --fast-zeroing", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fast_zeroing != 0);
}

static void test_fast_zeroing_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -Z", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fast_zeroing != 0);
}

static void test_fast_zeroing_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.fast_zeroing == 0);
}

static void test_fast_zeroing_combined_with_zero_drive(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --zero-drive --fast-zeroing", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.zero_drive != 0);
    CHECK(opts.fast_zeroing != 0);
}

/* ---- --old-bios-fixes tests ---- */

static void test_init_old_bios_fixes_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.old_bios_fixes == 0);
}

static void test_old_bios_fixes_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --old-bios-fixes", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.old_bios_fixes != 0);
}

static void test_old_bios_fixes_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -o", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.old_bios_fixes != 0);
}

static void test_old_bios_fixes_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.old_bios_fixes == 0);
}

/* ---- --allow-dual-uefi-bios tests ---- */

static void test_init_allow_dual_uefi_bios_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.allow_dual_uefi_bios == 0);
}

static void test_allow_dual_uefi_bios_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --allow-dual-uefi-bios", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.allow_dual_uefi_bios != 0);
}

static void test_allow_dual_uefi_bios_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -A", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.allow_dual_uefi_bios != 0);
}

static void test_allow_dual_uefi_bios_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.allow_dual_uefi_bios == 0);
}

/* ---- --preserve-timestamps tests ---- */

static void test_init_preserve_timestamps_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.preserve_timestamps == 0);
}

static void test_preserve_timestamps_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --preserve-timestamps", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.preserve_timestamps != 0);
}

static void test_preserve_timestamps_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -e", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.preserve_timestamps != 0);
}

static void test_preserve_timestamps_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.preserve_timestamps == 0);
}

/* ---- --validate-md5sum tests ---- */

static void test_init_validate_md5sum_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.validate_md5sum == 0);
}

static void test_validate_md5sum_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --validate-md5sum", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.validate_md5sum != 0);
}

static void test_validate_md5sum_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -m", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.validate_md5sum != 0);
}

static void test_validate_md5sum_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.validate_md5sum == 0);
}

/* ---- --no-rufus-mbr tests ---- */

static void test_init_no_rufus_mbr_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.no_rufus_mbr == 0);
}

static void test_no_rufus_mbr_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --no-rufus-mbr", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_rufus_mbr != 0);
}

static void test_no_rufus_mbr_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -R", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_rufus_mbr != 0);
}

static void test_no_rufus_mbr_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_rufus_mbr == 0);
}

/* ---- --no-extended-label tests ---- */

static void test_init_no_extended_label_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.no_extended_label == 0);
}

static void test_no_extended_label_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --no-extended-label", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_extended_label != 0);
}

static void test_no_extended_label_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -x", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_extended_label != 0);
}

static void test_no_extended_label_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_extended_label == 0);
}

/* ---- --no-size-check tests ---- */

static void test_init_no_size_check_is_false(void)
{
    cli_options_t opts;
    cli_options_init(&opts);
    CHECK(opts.no_size_check == 0);
}

static void test_no_size_check_long_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda --no-size-check", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_size_check != 0);
}

static void test_no_size_check_short_flag(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda -s", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_size_check != 0);
}

static void test_no_size_check_default_is_off(void)
{
    cli_options_t opts;
    int r = parse("rufus --device /dev/sda", &opts);
    CHECK(r == CLI_PARSE_OK);
    CHECK(opts.no_size_check == 0);
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

    RUN_TEST(test_no_prompt_sets_flag);
    RUN_TEST(test_no_prompt_default_is_zero);
    RUN_TEST(test_no_prompt_combined_with_other_opts);

    RUN_TEST(test_label_is_parsed);

    RUN_TEST(test_help_returns_help_code);
    RUN_TEST(test_help_short_form);

    RUN_TEST(test_unknown_option_is_error);

    RUN_TEST(test_all_options_combined);
    RUN_TEST(test_no_args_is_error);

    /* --version tests */
    RUN_TEST(test_version_returns_version_code);

    /* --boot-type tests */
    RUN_TEST(test_init_boot_type_is_minus1);
    RUN_TEST(test_boot_type_non_bootable);
    RUN_TEST(test_boot_type_image);
    RUN_TEST(test_boot_type_freedos);
    RUN_TEST(test_boot_type_msdos);
    RUN_TEST(test_boot_type_short_form);
    RUN_TEST(test_boot_type_unknown_is_error);
    RUN_TEST(test_boot_type_case_insensitive);

    /* --cluster-size tests */
    RUN_TEST(test_init_cluster_size_is_zero);
    RUN_TEST(test_cluster_size_512);
    RUN_TEST(test_cluster_size_4096);
    RUN_TEST(test_cluster_size_65536);
    RUN_TEST(test_cluster_size_short_form);
    RUN_TEST(test_cluster_size_zero_is_error);
    RUN_TEST(test_cluster_size_not_power_of_two_is_error);
    RUN_TEST(test_cluster_size_alpha_is_error);
    RUN_TEST(test_cluster_size_too_large_is_error);

    /* --persistence tests */
    RUN_TEST(test_init_persistence_is_zero);
    RUN_TEST(test_persistence_zero);
    RUN_TEST(test_persistence_megabytes);
    RUN_TEST(test_persistence_gigabyte);
    RUN_TEST(test_persistence_short_form);
    RUN_TEST(test_persistence_alpha_is_error);

    /* --bad-blocks tests */
    RUN_TEST(test_init_bad_blocks_is_false);
    RUN_TEST(test_bad_blocks_sets_flag);
    RUN_TEST(test_bad_blocks_short_form);
    RUN_TEST(test_bad_blocks_default_is_false);

    /* --nb-passes tests */
    RUN_TEST(test_init_nb_passes_is_zero);
    RUN_TEST(test_nb_passes_one);
    RUN_TEST(test_nb_passes_four);
    RUN_TEST(test_nb_passes_short_form);
    RUN_TEST(test_nb_passes_zero_is_error);
    RUN_TEST(test_nb_passes_five_is_error);
    RUN_TEST(test_nb_passes_alpha_is_error);
    RUN_TEST(test_nb_passes_requires_bad_blocks);
    RUN_TEST(test_nb_passes_with_bad_blocks);

    /* --list-devices tests */
    RUN_TEST(test_list_devices_returns_list_code);
    RUN_TEST(test_list_devices_does_not_require_device);
    RUN_TEST(test_list_devices_short_form);
    RUN_TEST(test_list_devices_ignores_other_options);

    /* --json tests */
    RUN_TEST(test_init_json_is_false);
    RUN_TEST(test_json_sets_flag);
    RUN_TEST(test_json_short_form);
    RUN_TEST(test_json_default_is_off);

    /* --unattend-xml tests */
    RUN_TEST(test_init_unattend_xml_is_empty);
    RUN_TEST(test_unattend_xml_sets_path);
    RUN_TEST(test_unattend_xml_short_form);
    RUN_TEST(test_unattend_xml_requires_argument);
    RUN_TEST(test_unattend_xml_empty_path_is_error);

    /* --include-hdds tests */
    RUN_TEST(test_init_include_hdds_is_false);
    RUN_TEST(test_include_hdds_sets_flag);
    RUN_TEST(test_include_hdds_short_form);
    RUN_TEST(test_include_hdds_default_is_off);

    /* --zero-drive tests */
    RUN_TEST(test_init_zero_drive_is_false);
    RUN_TEST(test_zero_drive_sets_flag);
    RUN_TEST(test_zero_drive_short_form);
    RUN_TEST(test_zero_drive_default_is_off);

    /* --force-large-fat32 tests */
    RUN_TEST(test_init_force_large_fat32_is_false);
    RUN_TEST(test_force_large_fat32_sets_flag);
    RUN_TEST(test_force_large_fat32_default_is_off);

    /* --ntfs-compression tests */
    RUN_TEST(test_init_ntfs_compression_is_false);
    RUN_TEST(test_ntfs_compression_sets_flag);
    RUN_TEST(test_ntfs_compression_default_is_off);

    /* --win-to-go tests */
    RUN_TEST(test_init_win_to_go_is_false);
    RUN_TEST(test_win_to_go_long_flag);
    RUN_TEST(test_win_to_go_short_flag);
    RUN_TEST(test_win_to_go_default_is_off);
    RUN_TEST(test_win_to_go_combined_with_device_and_image);

    /* --write-as-image tests */
    RUN_TEST(test_init_write_as_image_is_false);
    RUN_TEST(test_write_as_image_long_flag);
    RUN_TEST(test_write_as_image_short_flag);
    RUN_TEST(test_write_as_image_default_is_off);

    /* --fast-zeroing tests */
    RUN_TEST(test_init_fast_zeroing_is_false);
    RUN_TEST(test_fast_zeroing_long_flag);
    RUN_TEST(test_fast_zeroing_short_flag);
    RUN_TEST(test_fast_zeroing_default_is_off);
    RUN_TEST(test_fast_zeroing_combined_with_zero_drive);

    /* --old-bios-fixes tests */
    RUN_TEST(test_init_old_bios_fixes_is_false);
    RUN_TEST(test_old_bios_fixes_long_flag);
    RUN_TEST(test_old_bios_fixes_short_flag);
    RUN_TEST(test_old_bios_fixes_default_is_off);

    /* --allow-dual-uefi-bios tests */
    RUN_TEST(test_init_allow_dual_uefi_bios_is_false);
    RUN_TEST(test_allow_dual_uefi_bios_long_flag);
    RUN_TEST(test_allow_dual_uefi_bios_short_flag);
    RUN_TEST(test_allow_dual_uefi_bios_default_is_off);

    /* --preserve-timestamps tests */
    RUN_TEST(test_init_preserve_timestamps_is_false);
    RUN_TEST(test_preserve_timestamps_long_flag);
    RUN_TEST(test_preserve_timestamps_short_flag);
    RUN_TEST(test_preserve_timestamps_default_is_off);

    /* --validate-md5sum tests */
    RUN_TEST(test_init_validate_md5sum_is_false);
    RUN_TEST(test_validate_md5sum_long_flag);
    RUN_TEST(test_validate_md5sum_short_flag);
    RUN_TEST(test_validate_md5sum_default_is_off);

    /* --no-rufus-mbr tests */
    RUN_TEST(test_init_no_rufus_mbr_is_false);
    RUN_TEST(test_no_rufus_mbr_long_flag);
    RUN_TEST(test_no_rufus_mbr_short_flag);
    RUN_TEST(test_no_rufus_mbr_default_is_off);

    /* --no-extended-label tests */
    RUN_TEST(test_init_no_extended_label_is_false);
    RUN_TEST(test_no_extended_label_long_flag);
    RUN_TEST(test_no_extended_label_short_flag);
    RUN_TEST(test_no_extended_label_default_is_off);

    /* --no-size-check tests */
    RUN_TEST(test_init_no_size_check_is_false);
    RUN_TEST(test_no_size_check_long_flag);
    RUN_TEST(test_no_size_check_short_flag);
    RUN_TEST(test_no_size_check_default_is_off);

    TEST_RESULTS();
}
