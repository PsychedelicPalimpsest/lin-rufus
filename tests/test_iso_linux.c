/*
 * test_iso_linux.c — Tests for ISO extraction functions (Linux only)
 *
 * Tests GetGrubVersion, GetGrubFs, GetEfiBootInfo (pure buffer scans),
 * and ReadISOFileToBuffer / ExtractISOFile / ExtractISO (using libcdio).
 *
 * A minimal ISO image is generated at test start via a Python/pycdlib script.
 * If the script is unavailable the ISO tests are skipped gracefully.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>

/* ---- test framework ---- */
#include "framework.h"

/* ---- compat layer ---- */
#include "windows.h"
#include "commctrl.h"

/* ---- rufus headers ---- */
#include "rufus.h"
#include "resource.h"
#include "localization.h"

/* ================================================================
 * Minimal globals required by linux/iso.c and its dependencies.
 *
 * NOTE: enable_iso / enable_joliet / enable_rockridge / has_ldlinux_c32
 * / img_report / md5sum_name / old_c32_name / efi_dirname / efi_bootname
 * / efi_archname / config_path / isolinux_path / grub_filesystems are
 * all DEFINED in linux/iso.c (which is compiled into this test binary).
 * This file only defines the remaining globals that iso.c `extern`s in.
 * ================================================================ */

HWND hMainDialog   = NULL;
HWND hDeviceList   = NULL;
HWND hProgress     = NULL;
HWND hStatus       = NULL;
HWND hInfo         = NULL;
HWND hLog          = NULL;

BOOL op_in_progress        = FALSE;
BOOL enable_HDDs           = FALSE;
BOOL enable_VHDs           = TRUE;
BOOL right_to_left_mode    = FALSE;

DWORD ErrorStatus          = 0;
DWORD LastWriteError       = 0;
DWORD MainThreadId         = 0;
DWORD DownloadStatus       = 0;

int fs_type                = 0;
int boot_type              = 0;
int partition_type         = 0;
int target_type            = 0;
uint8_t image_options      = 0;

char szFolderPath[MAX_PATH]   = "";
char app_dir[MAX_PATH]        = "";
char temp_dir[MAX_PATH]       = "/tmp";
char app_data_dir[MAX_PATH]   = "/tmp";
char system_dir[MAX_PATH]     = "/tmp";
char sysnative_dir[MAX_PATH]  = "/tmp";
char user_dir[MAX_PATH]       = "/tmp";
char* image_path               = NULL;
char* fido_url                 = NULL;
uint64_t persistence_size     = 0;

BOOL large_drive               = FALSE;
BOOL write_as_esp              = FALSE;
BOOL write_as_image            = FALSE;
BOOL lock_drive                = FALSE;
BOOL zero_drive                = FALSE;
BOOL fast_zeroing              = FALSE;
BOOL force_large_fat32         = FALSE;
BOOL enable_ntfs_compression   = FALSE;
BOOL enable_file_indexing      = FALSE;
BOOL preserve_timestamps       = FALSE;
BOOL validate_md5sum           = FALSE;
BOOL cpu_has_sha1_accel        = FALSE;
BOOL cpu_has_sha256_accel      = FALSE;

uint64_t md5sum_totalbytes     = 0;
HANDLE format_thread           = NULL;
StrArray modified_files;       /* extern'd by iso.c */
RUFUS_DRIVE rufus_drive[MAX_DRIVES];

/* grub_filesystems, config_path, isolinux_path are defined in iso.c */
extern StrArray grub_filesystems;

/* PrintStatusInfo and uprintfs are provided by localization.c and stdio.c respectively */

/* enable_iso / enable_joliet / enable_rockridge are defined in linux/iso.c */
extern BOOL enable_iso, enable_joliet, enable_rockridge;

/* ================================================================
 * ISO test image setup
 * ================================================================ */

#define TEST_ISO_PATH   "/tmp/test_rufus_iso.iso"
#define TEST_EXTRACT_DIR "/tmp/test_rufus_extract"
static int test_iso_available = 0;

static void setup_test_iso(void)
{
    /* Generate test ISO using Python/pycdlib */
    const char* script =
        "python3 -c \""
        "import pycdlib, io, sys\n"
        "iso = pycdlib.PyCdlib()\n"
        "iso.new(interchange_level=1, joliet=3, rock_ridge='1.09', vol_ident='TESTISO')\n"
        "c1 = b'Hello, world!\\n'\n"
        "iso.add_fp(io.BytesIO(c1), len(c1), '/HELLO.TXT;1', joliet_path='/hello.txt', rr_name='hello.txt')\n"
        "gc = b'\\x00'*64 + b'GRUB  version 2.06\\x00' + b'\\x00'*200\n"
        "iso.add_fp(io.BytesIO(gc), len(gc), '/CORE.IMG;1', joliet_path='/core.img', rr_name='core.img')\n"
        "ec = b'\\x00'*128 + b'UEFI SHIM\\n\$Version: 15.7\\x00' + b'\\x00'*64\n"
        "iso.add_fp(io.BytesIO(ec), len(ec), '/SHIMX64.EFI;1', joliet_path='/shimx64.efi', rr_name='shimx64.efi')\n"
        "iso.add_directory('/BOOT', joliet_path='/boot', rr_name='boot')\n"
        "c3 = b'nested file content\\n'\n"
        "iso.add_fp(io.BytesIO(c3), len(c3), '/BOOT/GRUB.CFG;1', joliet_path='/boot/grub.cfg', rr_name='grub.cfg')\n"
        "big = b'A'*8192 + b'B'*4096\n"
        "iso.add_fp(io.BytesIO(big), len(big), '/BIGFILE.BIN;1', joliet_path='/bigfile.bin', rr_name='bigfile.bin')\n"
        "iso.write('/tmp/test_rufus_iso.iso')\n"
        "iso.close()\n"
        "\"";

    int rc = system(script);
    struct stat st;
    if (rc == 0 && stat(TEST_ISO_PATH, &st) == 0 && st.st_size > 0)
        test_iso_available = 1;
}

static void cleanup_test_iso(void)
{
    unlink(TEST_ISO_PATH);
    /* Remove extract dir recursively if it exists */
    system("rm -rf " TEST_EXTRACT_DIR);
}

/* ================================================================
 * GetGrubVersion tests (pure buffer scan — no ISO needed)
 * ================================================================ */

TEST(grubver_empty_buf)
{
    /* Buffer smaller than max_string_size (32) — function should not scan */
    char buf[16] = "GRUB  version 2";
    memset(&img_report, 0, sizeof(img_report));
    GetGrubVersion(buf, sizeof(buf), "test");
    /* No version should have been detected */
    CHECK(img_report.grub2_version[0] == '\0');
}

TEST(grubver_exact_version)
{
    /* Buffer containing "GRUB  version 2.06\0" (two-space variant) */
    char buf[256];
    memset(buf, 0, sizeof(buf));
    memset(&img_report, 0, sizeof(img_report));
    const char* token = "GRUB  version 2.06";
    memcpy(buf + 32, token, strlen(token));
    /* The function reads <token>\0<version> where the char after the format
     * string is a space, and the version follows immediately.
     * Layout: "GRUB  version " + "2.06\0" so after the format + 1 char => "2.06" */
    GetGrubVersion(buf, sizeof(buf), "test");
    CHECK_STR_EQ(img_report.grub2_version, "2.06");
}

TEST(grubver_single_space_variant)
{
    /* Some distros use single-space "GRUB version X.Y" */
    char buf[256];
    memset(buf, 0, sizeof(buf));
    memset(&img_report, 0, sizeof(img_report));
    const char* token = "GRUB version 2.12";
    memcpy(buf + 40, token, strlen(token));
    GetGrubVersion(buf, sizeof(buf), "test");
    CHECK_STR_EQ(img_report.grub2_version, "2.12");
}

TEST(grubver_already_set_not_overwritten)
{
    /* If img_report.grub2_version is already set, it must not be overwritten */
    char buf[256];
    memset(buf, 0, sizeof(buf));
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.grub2_version, "2.02");
    const char* token = "GRUB  version 2.06";
    memcpy(buf + 32, token, strlen(token));
    GetGrubVersion(buf, sizeof(buf), "test");
    CHECK_STR_EQ(img_report.grub2_version, "2.02");
}

TEST(grubver_not_in_buf)
{
    char buf[256];
    memset(buf, 'x', sizeof(buf));
    buf[255] = 0;
    memset(&img_report, 0, sizeof(img_report));
    GetGrubVersion(buf, sizeof(buf), "test");
    CHECK(img_report.grub2_version[0] == '\0');
}

/* ================================================================
 * GetGrubFs tests
 * ================================================================ */

TEST(grubfs_finds_fshelp_entry)
{
    /* Buffer contains "fshelp\0fat\0" at some offset */
    char buf[256];
    memset(buf, 0, sizeof(buf));
    const char* entry = "fshelp\0fat";
    memcpy(buf + 50, entry, 11);
    StrArrayCreate(&grub_filesystems, 8);
    GetGrubFs(buf, sizeof(buf));
    CHECK(grub_filesystems.Index >= 1);
    /* The filesystem name 'fat' should be in the array */
    BOOL found = FALSE;
    for (size_t i = 0; i < grub_filesystems.Index; i++) {
        if (strcmp(grub_filesystems.String[i], "fat") == 0) { found = TRUE; break; }
    }
    CHECK(found);
    StrArrayDestroy(&grub_filesystems);
}

TEST(grubfs_no_entry)
{
    char buf[256];
    memset(buf, 'z', sizeof(buf));
    buf[255] = 0;
    StrArrayCreate(&grub_filesystems, 8);
    GetGrubFs(buf, sizeof(buf));
    CHECK(grub_filesystems.Index == 0);
    StrArrayDestroy(&grub_filesystems);
}

TEST(grubfs_multiple_entries)
{
    char buf[256];
    memset(buf, 0, sizeof(buf));
    /* Two filesystem entries */
    const char* e1 = "fshelp\0ext2";
    const char* e2 = "fshelp\0ntfs";
    memcpy(buf + 20, e1, 12);
    memcpy(buf + 50, e2, 12);
    StrArrayCreate(&grub_filesystems, 8);
    GetGrubFs(buf, sizeof(buf));
    CHECK(grub_filesystems.Index >= 2);
    StrArrayDestroy(&grub_filesystems);
}

/* ================================================================
 * GetEfiBootInfo tests
 * ================================================================ */

TEST(efiinfo_shim_found)
{
    char buf[512];
    memset(buf, 0, sizeof(buf));
    const char* shim = "UEFI SHIM\n$Version: 15.7";
    memcpy(buf + 100, shim, strlen(shim) + 1);
    /* Should not crash and should log the version */
    GetEfiBootInfo(buf, sizeof(buf), "test.efi");
    CHECK(1); /* just testing no crash */
}

TEST(efiinfo_systemd_boot)
{
    char buf[512];
    memset(buf, 0, sizeof(buf));
    const char* sb = "#### LoaderInfo: systemd-boot 255.5-3";
    memcpy(buf + 80, sb, strlen(sb) + 1);
    GetEfiBootInfo(buf, sizeof(buf), "systemd-bootx64.efi");
    CHECK(1);
}

TEST(efiinfo_empty_buf)
{
    char buf[16];
    memset(buf, 0, sizeof(buf));
    GetEfiBootInfo(buf, sizeof(buf), "test");
    CHECK(1);
}

/* ================================================================
 * ReadISOFileToBuffer tests (require test ISO)
 * ================================================================ */

TEST(read_iso_file_no_iso)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    /* Reading from non-existent ISO */
    uint8_t* buf = NULL;
    uint32_t r = ReadISOFileToBuffer("/tmp/does_not_exist.iso", "/hello.txt", &buf);
    CHECK(r == 0);
    CHECK(buf == NULL);
}

TEST(read_iso_file_not_found)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    uint8_t* buf = NULL;
    uint32_t r = ReadISOFileToBuffer(TEST_ISO_PATH, "/no_such_file.txt", &buf);
    CHECK(r == 0);
    if (buf) free(buf);
}

TEST(read_iso_file_hello)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    uint8_t* buf = NULL;
    uint32_t r = ReadISOFileToBuffer(TEST_ISO_PATH, "/hello.txt", &buf);
    CHECK(r > 0);
    if (r > 0) {
        CHECK(buf != NULL);
        CHECK(r == 14); /* "Hello, world!\n" */
        CHECK(memcmp(buf, "Hello, world!\n", 14) == 0);
        free(buf);
    }
}

TEST(read_iso_file_nested)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    uint8_t* buf = NULL;
    uint32_t r = ReadISOFileToBuffer(TEST_ISO_PATH, "/boot/grub.cfg", &buf);
    CHECK(r > 0);
    if (r > 0) {
        CHECK(buf != NULL);
        CHECK(memcmp(buf, "nested file content\n", 20) == 0);
        free(buf);
    }
}

TEST(read_iso_file_big)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    uint8_t* buf = NULL;
    uint32_t r = ReadISOFileToBuffer(TEST_ISO_PATH, "/bigfile.bin", &buf);
    CHECK(r == 8192 + 4096);
    if (r > 0) {
        for (uint32_t i = 0; i < 8192; i++) CHECK(buf[i] == 'A');
        for (uint32_t i = 8192; i < 8192+4096; i++) CHECK(buf[i] == 'B');
        free(buf);
    }
}

TEST(read_iso_null_args)
{
    uint8_t* buf = NULL;
    uint32_t r;
    r = ReadISOFileToBuffer(NULL, "/hello.txt", &buf);
    CHECK(r == 0);
    r = ReadISOFileToBuffer(TEST_ISO_PATH, NULL, &buf);
    CHECK(r == 0);
    r = ReadISOFileToBuffer(TEST_ISO_PATH, "/hello.txt", NULL);
    CHECK(r == 0);
}

/* ================================================================
 * ExtractISOFile tests (require test ISO)
 * ================================================================ */

#define EXTRACT_TMP_FILE "/tmp/test_iso_extract_out.txt"

TEST(extract_iso_file_hello)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    unlink(EXTRACT_TMP_FILE);
    int64_t r = ExtractISOFile(TEST_ISO_PATH, "/hello.txt", EXTRACT_TMP_FILE, 0);
    CHECK(r == 14);
    /* Verify content */
    int fd = open(EXTRACT_TMP_FILE, O_RDONLY);
    if (fd >= 0) {
        char buf[32] = {0};
        ssize_t nr = read(fd, buf, sizeof(buf)-1);
        close(fd);
        CHECK(nr == 14);
        CHECK(strcmp(buf, "Hello, world!\n") == 0);
    } else {
        CHECK(0); /* file not created */
    }
    unlink(EXTRACT_TMP_FILE);
}

TEST(extract_iso_file_nested)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    unlink(EXTRACT_TMP_FILE);
    int64_t r = ExtractISOFile(TEST_ISO_PATH, "/boot/grub.cfg", EXTRACT_TMP_FILE, 0);
    CHECK(r == 20);
    int fd = open(EXTRACT_TMP_FILE, O_RDONLY);
    if (fd >= 0) {
        char buf[64] = {0};
        ssize_t nr = read(fd, buf, sizeof(buf)-1);
        close(fd);
        CHECK(nr == 20);
        CHECK(strcmp(buf, "nested file content\n") == 0);
    } else {
        CHECK(0);
    }
    unlink(EXTRACT_TMP_FILE);
}

TEST(extract_iso_file_not_found)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    int64_t r = ExtractISOFile(TEST_ISO_PATH, "/does_not_exist.txt", EXTRACT_TMP_FILE, 0);
    CHECK(r == 0);
    /* Ensure failed extract doesn't leave a partial file */
    struct stat st;
    CHECK(stat(EXTRACT_TMP_FILE, &st) != 0); /* file should not exist */
}

TEST(extract_iso_file_null_args)
{
    int64_t r;
    r = ExtractISOFile(NULL, "/hello.txt", EXTRACT_TMP_FILE, 0);
    CHECK(r == 0);
    r = ExtractISOFile(TEST_ISO_PATH, NULL, EXTRACT_TMP_FILE, 0);
    CHECK(r == 0);
    r = ExtractISOFile(TEST_ISO_PATH, "/hello.txt", NULL, 0);
    CHECK(r == 0);
}

TEST(extract_iso_file_big)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    unlink(EXTRACT_TMP_FILE);
    int64_t r = ExtractISOFile(TEST_ISO_PATH, "/bigfile.bin", EXTRACT_TMP_FILE, 0);
    CHECK(r == 8192 + 4096);
    struct stat st;
    if (stat(EXTRACT_TMP_FILE, &st) == 0) {
        CHECK(st.st_size == 8192 + 4096);
    }
    unlink(EXTRACT_TMP_FILE);
}

/* ================================================================
 * ExtractISO scan tests (require test ISO)
 * ================================================================ */

TEST(extract_iso_scan_label)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    BOOL r = ExtractISO(TEST_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK(r == TRUE);
    /* Label should be "TESTISO" */
    CHECK(strncmp(img_report.label, "TESTISO", 7) == 0);
}

TEST(extract_iso_scan_counts_blocks)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    BOOL r = ExtractISO(TEST_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK(r == TRUE);
    /* Projected size should be > 0 */
    CHECK(img_report.projected_size > 0);
}

TEST(extract_iso_disabled)
{
    /* When enable_iso is FALSE, ExtractISO should return FALSE immediately */
    enable_iso = FALSE;
    BOOL r = ExtractISO(TEST_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK(r == FALSE);
    enable_iso = TRUE;
}

TEST(extract_iso_null_args)
{
    BOOL r;
    r = ExtractISO(NULL, TEST_EXTRACT_DIR, TRUE);
    CHECK(r == FALSE);
    r = ExtractISO(TEST_ISO_PATH, NULL, TRUE);
    CHECK(r == FALSE);
}

TEST(extract_iso_nonexistent)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    BOOL r = ExtractISO("/tmp/does_not_exist.iso", TEST_EXTRACT_DIR, TRUE);
    CHECK(r == FALSE);
}

TEST(extract_iso_full_extract)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    /* First scan, then extract */
    memset(&img_report, 0, sizeof(img_report));
    system("rm -rf " TEST_EXTRACT_DIR);
    mkdir(TEST_EXTRACT_DIR, 0755);

    enable_iso = TRUE;
    /* Scan phase */
    BOOL r = ExtractISO(TEST_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK(r == TRUE);

    /* Extract phase */
    r = ExtractISO(TEST_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    CHECK(r == TRUE);

    /* Check that files were extracted */
    struct stat st;
    char path[256];
    snprintf(path, sizeof(path), "%s/hello.txt", TEST_EXTRACT_DIR);
    CHECK(stat(path, &st) == 0);
    CHECK(st.st_size == 14);

    snprintf(path, sizeof(path), "%s/bigfile.bin", TEST_EXTRACT_DIR);
    CHECK(stat(path, &st) == 0);
    CHECK(st.st_size == 8192 + 4096);

    snprintf(path, sizeof(path), "%s/boot/grub.cfg", TEST_EXTRACT_DIR);
    CHECK(stat(path, &st) == 0);
    CHECK(st.st_size == 20);

    system("rm -rf " TEST_EXTRACT_DIR);
}

/* ================================================================
 * HasEfiImgBootLoaders test
 * ================================================================ */

TEST(has_efi_img_false)
{
    memset(&img_report, 0, sizeof(img_report));
    CHECK(HasEfiImgBootLoaders() == FALSE);
}

TEST(has_efi_img_true)
{
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi/boot/bootx64.img");
    CHECK(HasEfiImgBootLoaders() == TRUE);
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
    printf("=== ISO extraction tests (Linux) ===\n\n");

    /* Setup: generate test ISO */
    setup_test_iso();
    if (!test_iso_available)
        printf("  NOTE: test ISO not available (pycdlib not installed?); ISO I/O tests skipped\n\n");

    StrArrayCreate(&modified_files, 8);

    printf("  GetGrubVersion\n");
    RUN(grubver_empty_buf);
    RUN(grubver_exact_version);
    RUN(grubver_single_space_variant);
    RUN(grubver_already_set_not_overwritten);
    RUN(grubver_not_in_buf);

    printf("\n  GetGrubFs\n");
    RUN(grubfs_finds_fshelp_entry);
    RUN(grubfs_no_entry);
    RUN(grubfs_multiple_entries);

    printf("\n  GetEfiBootInfo\n");
    RUN(efiinfo_shim_found);
    RUN(efiinfo_systemd_boot);
    RUN(efiinfo_empty_buf);

    printf("\n  ReadISOFileToBuffer\n");
    RUN(read_iso_null_args);
    RUN(read_iso_file_no_iso);
    RUN(read_iso_file_not_found);
    RUN(read_iso_file_hello);
    RUN(read_iso_file_nested);
    RUN(read_iso_file_big);

    printf("\n  ExtractISOFile\n");
    RUN(extract_iso_file_null_args);
    RUN(extract_iso_file_hello);
    RUN(extract_iso_file_nested);
    RUN(extract_iso_file_not_found);
    RUN(extract_iso_file_big);

    printf("\n  ExtractISO\n");
    RUN(extract_iso_null_args);
    RUN(extract_iso_disabled);
    RUN(extract_iso_nonexistent);
    RUN(extract_iso_scan_label);
    RUN(extract_iso_scan_counts_blocks);
    RUN(extract_iso_full_extract);

    printf("\n  HasEfiImgBootLoaders\n");
    RUN(has_efi_img_false);
    RUN(has_efi_img_true);

    StrArrayDestroy(&modified_files);
    cleanup_test_iso();

    TEST_RESULTS();
}

#endif /* __linux__ */
