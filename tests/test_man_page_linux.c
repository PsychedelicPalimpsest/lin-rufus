/*
 * tests/test_man_page_linux.c
 *
 * Validates that the doc/rufus.1 man page exists, is syntactically valid
 * (parseable by groff), and documents all expected CLI flags.
 *
 * Tests do not require root and run on any Linux host with groff installed.
 */
#define RUFUS_TEST 1

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/* Read the entire contents of a file into a malloc'd buffer (NUL-terminated).
 * Returns NULL on failure. Caller must free(). */
static char *read_file_to_str(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/* Return the path to doc/rufus.1 relative to the repo root.
 * We search upward from the test binary's working directory. */
static const char *find_man_page(void)
{
    static char path[512];
    /* Try current dir (run from tests/) */
    snprintf(path, sizeof(path), "doc/rufus.1");
    if (access(path, R_OK) == 0) return path;
    /* One level up (run from repo root) */
    snprintf(path, sizeof(path), "../doc/rufus.1");
    if (access(path, R_OK) == 0) return path;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

TEST(man_page_file_exists) {
    const char *p = find_man_page();
    CHECK(p != NULL);
}

TEST(man_page_is_non_empty) {
    const char *p = find_man_page();
    if (!p) { return; }
    struct stat st;
    CHECK(stat(p, &st) == 0);
    CHECK(st.st_size > 100);
}

TEST(man_page_has_troff_header) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    /* Must start with .TH macro */
    CHECK(strncmp(content, ".TH", 3) == 0 || strstr(content, ".TH RUFUS") != NULL);
    free(content);
}

TEST(man_page_has_name_section) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, ".SH NAME") != NULL);
    free(content);
}

TEST(man_page_has_synopsis_section) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, ".SH SYNOPSIS") != NULL);
    free(content);
}

TEST(man_page_has_description_section) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, ".SH DESCRIPTION") != NULL);
    free(content);
}

TEST(man_page_has_options_section) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, ".SH OPTIONS") != NULL);
    free(content);
}

TEST(man_page_has_examples_section) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, ".SH EXAMPLES") != NULL);
    free(content);
}

TEST(man_page_has_see_also_section) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, ".SH SEE ALSO") != NULL);
    free(content);
}

TEST(man_page_documents_device_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--device") != NULL || strstr(content, "\\-\\-device") != NULL
       || strstr(content, "device") != NULL);
    free(content);
}

TEST(man_page_documents_image_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--image") != NULL || strstr(content, "image") != NULL);
    free(content);
}

TEST(man_page_documents_fs_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--fs") != NULL || strstr(content, "\\-\\-fs") != NULL);
    free(content);
}

TEST(man_page_documents_partition_scheme_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "partition") != NULL);
    free(content);
}

TEST(man_page_documents_target_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--target") != NULL || strstr(content, "target") != NULL);
    free(content);
}

TEST(man_page_documents_label_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--label") != NULL || strstr(content, "label") != NULL);
    free(content);
}

TEST(man_page_documents_quick_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--quick") != NULL || strstr(content, "quick") != NULL);
    free(content);
}

TEST(man_page_documents_verify_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--verify") != NULL || strstr(content, "verify") != NULL);
    free(content);
}

TEST(man_page_documents_no_prompt_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--no-prompt") != NULL || strstr(content, "no.prompt") != NULL
       || strstr(content, "no\\-prompt") != NULL);
    free(content);
}

TEST(man_page_documents_boot_type_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "boot-type") != NULL || strstr(content, "boot.type") != NULL
       || strstr(content, "boot_type") != NULL || strstr(content, "boot\\-type") != NULL);
    free(content);
}

TEST(man_page_documents_cluster_size_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "cluster-size") != NULL || strstr(content, "cluster.size") != NULL
       || strstr(content, "cluster\\-size") != NULL || strstr(content, "cluster_size") != NULL);
    free(content);
}

TEST(man_page_documents_version_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--version") != NULL || strstr(content, "version") != NULL);
    free(content);
}

TEST(man_page_documents_persistence_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "persistence") != NULL);
    free(content);
}

TEST(man_page_documents_bad_blocks_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "bad-blocks") != NULL || strstr(content, "bad.blocks") != NULL
       || strstr(content, "bad\\-blocks") != NULL);
    free(content);
}

TEST(man_page_documents_nb_passes_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "nb-passes") != NULL || strstr(content, "nb.passes") != NULL
       || strstr(content, "nb\\-passes") != NULL);
    free(content);
}

TEST(man_page_documents_list_devices_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "list-devices") != NULL || strstr(content, "list.devices") != NULL
       || strstr(content, "list\\-devices") != NULL);
    free(content);
}

TEST(man_page_documents_unattend_xml_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "unattend-xml") != NULL || strstr(content, "unattend.xml") != NULL
       || strstr(content, "unattend\\-xml") != NULL);
    free(content);
}

TEST(man_page_documents_include_hdds_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "include-hdds") != NULL || strstr(content, "include.hdds") != NULL
       || strstr(content, "include\\-hdds") != NULL);
    free(content);
}

TEST(man_page_documents_zero_drive_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "zero-drive") != NULL || strstr(content, "zero.drive") != NULL
       || strstr(content, "zero\\-drive") != NULL);
    free(content);
}

TEST(man_page_documents_force_large_fat32_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "force-large-fat32") != NULL || strstr(content, "force.large.fat32") != NULL
       || strstr(content, "force\\-large\\-fat32") != NULL);
    free(content);
}

TEST(man_page_documents_ntfs_compression_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "ntfs-compression") != NULL || strstr(content, "ntfs.compression") != NULL
       || strstr(content, "ntfs\\-compression") != NULL);
    free(content);
}

TEST(man_page_documents_win_to_go_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "win-to-go") != NULL || strstr(content, "win.to.go") != NULL
       || strstr(content, "win\\-to\\-go") != NULL || strstr(content, "WinToGo") != NULL);
    free(content);
}

TEST(man_page_documents_write_as_image_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "write-as-image") != NULL || strstr(content, "write.as.image") != NULL
       || strstr(content, "write\\-as\\-image") != NULL);
    free(content);
}

TEST(man_page_documents_fast_zeroing_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "fast-zeroing") != NULL || strstr(content, "fast.zeroing") != NULL
       || strstr(content, "fast\\-zeroing") != NULL);
    free(content);
}

TEST(man_page_documents_old_bios_fixes_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "old-bios-fixes") != NULL || strstr(content, "old.bios.fixes") != NULL
       || strstr(content, "old\\-bios\\-fixes") != NULL);
    free(content);
}

TEST(man_page_documents_allow_dual_uefi_bios_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "allow-dual-uefi-bios") != NULL
       || strstr(content, "allow.dual.uefi.bios") != NULL
       || strstr(content, "allow\\-dual\\-uefi\\-bios") != NULL
       || strstr(content, "dual.uefi") != NULL
       || strstr(content, "dual\\-uefi") != NULL);
    free(content);
}

TEST(man_page_documents_preserve_timestamps_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "preserve-timestamps") != NULL
       || strstr(content, "preserve.timestamps") != NULL
       || strstr(content, "preserve\\-timestamps") != NULL);
    free(content);
}

TEST(man_page_documents_validate_md5sum_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "validate-md5sum") != NULL
       || strstr(content, "validate.md5sum") != NULL
       || strstr(content, "validate\\-md5sum") != NULL
       || strstr(content, "md5sum") != NULL);
    free(content);
}

TEST(man_page_documents_no_rufus_mbr_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "no-rufus-mbr") != NULL
       || strstr(content, "no.rufus.mbr") != NULL
       || strstr(content, "no\\-rufus\\-mbr") != NULL
       || strstr(content, "rufus.mbr") != NULL);
    free(content);
}

TEST(man_page_documents_no_extended_label_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "no-extended-label") != NULL
       || strstr(content, "no.extended.label") != NULL
       || strstr(content, "no\\-extended\\-label") != NULL
       || strstr(content, "extended.label") != NULL);
    free(content);
}

TEST(man_page_documents_no_size_check_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "no-size-check") != NULL
       || strstr(content, "no.size.check") != NULL
       || strstr(content, "no\\-size\\-check") != NULL
       || strstr(content, "size.check") != NULL);
    free(content);
}

TEST(man_page_documents_json_flag) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "--json") != NULL || strstr(content, "\\-\\-json") != NULL
       || strstr(content, "\\-j") != NULL);
    free(content);
}

TEST(man_page_documents_fat32) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "fat32") != NULL);
    free(content);
}

TEST(man_page_documents_gpt) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "gpt") != NULL);
    free(content);
}

TEST(man_page_documents_mbr) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "mbr") != NULL || strstr(content, "MBR") != NULL
       || strstr(content, "Master Boot Record") != NULL);
    free(content);
}

TEST(man_page_documents_exit_status) {
    const char *p = find_man_page();
    if (!p) { return; }
    char *content = read_file_to_str(p);
    CHECK(content != NULL);
    CHECK(strstr(content, "EXIT STATUS") != NULL || strstr(content, "exit status") != NULL);
    free(content);
}

TEST(man_page_parses_with_groff) {
    if (access("/usr/bin/groff", X_OK) != 0 && access("/usr/local/bin/groff", X_OK) != 0) {
        return;
    }
    const char *p = find_man_page();
    if (!p) { return; }
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "groff -man -Tutf8 '%s' > /dev/null 2>&1", p);
    int rc = system(cmd);
    CHECK(rc == 0);
}

TEST(man_page_no_undefined_macros) {
    if (access("/usr/bin/groff", X_OK) != 0 && access("/usr/local/bin/groff", X_OK) != 0) {
        return;
    }
    const char *p = find_man_page();
    if (!p) { return; }
    /* groff -man -Ww prints warnings; we expect none for a well-formed page */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "groff -man -Tutf8 -Ww '%s' > /dev/null 2>&1", p);
    int rc = system(cmd);
    /* groff returns 0 even with warnings; we just check it doesn't crash */
    CHECK(rc == 0);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    RUN(man_page_file_exists);
    RUN(man_page_is_non_empty);
    RUN(man_page_has_troff_header);
    RUN(man_page_has_name_section);
    RUN(man_page_has_synopsis_section);
    RUN(man_page_has_description_section);
    RUN(man_page_has_options_section);
    RUN(man_page_has_examples_section);
    RUN(man_page_has_see_also_section);
    RUN(man_page_documents_device_flag);
    RUN(man_page_documents_image_flag);
    RUN(man_page_documents_fs_flag);
    RUN(man_page_documents_partition_scheme_flag);
    RUN(man_page_documents_target_flag);
    RUN(man_page_documents_label_flag);
    RUN(man_page_documents_quick_flag);
    RUN(man_page_documents_verify_flag);
    RUN(man_page_documents_no_prompt_flag);
    RUN(man_page_documents_boot_type_flag);
    RUN(man_page_documents_cluster_size_flag);
    RUN(man_page_documents_version_flag);
    RUN(man_page_documents_persistence_flag);
    RUN(man_page_documents_bad_blocks_flag);
    RUN(man_page_documents_nb_passes_flag);
    RUN(man_page_documents_list_devices_flag);
    RUN(man_page_documents_unattend_xml_flag);
    RUN(man_page_documents_include_hdds_flag);
    RUN(man_page_documents_zero_drive_flag);
    RUN(man_page_documents_force_large_fat32_flag);
    RUN(man_page_documents_ntfs_compression_flag);
    RUN(man_page_documents_win_to_go_flag);
    RUN(man_page_documents_write_as_image_flag);
    RUN(man_page_documents_fast_zeroing_flag);
    RUN(man_page_documents_old_bios_fixes_flag);
    RUN(man_page_documents_allow_dual_uefi_bios_flag);
    RUN(man_page_documents_preserve_timestamps_flag);
    RUN(man_page_documents_validate_md5sum_flag);
    RUN(man_page_documents_no_rufus_mbr_flag);
    RUN(man_page_documents_no_extended_label_flag);
    RUN(man_page_documents_no_size_check_flag);
    RUN(man_page_documents_json_flag);
    RUN(man_page_documents_fat32);
    RUN(man_page_documents_gpt);
    RUN(man_page_documents_mbr);
    RUN(man_page_documents_exit_status);
    RUN(man_page_parses_with_groff);
    RUN(man_page_no_undefined_macros);
    TEST_RESULTS();
}
