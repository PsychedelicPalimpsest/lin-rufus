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

/* ---- iso private types (for iso9660_readfat tests) ---- */
#include "../src/linux/iso_private.h"
/* iso9660_readfat is implemented in linux/iso.c (compiled into this binary) */
extern int iso9660_readfat(intptr_t pp, void *buf, size_t secsize, libfat_sector_t sec);

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

/* Stubs for OpticalDiscSaveImage() — ui.c / msg_dispatch symbols */
BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return TRUE; }
LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return 0; }
void EnableControls(BOOL e, BOOL r) { (void)e; (void)r; }

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
 * Syslinux ISO test (isolinux.bin with embedded version string)
 * ================================================================ */

#define SYSLINUX_ISO_PATH "/tmp/test_rufus_syslinux.iso"
static int syslinux_iso_available = 0;

static void setup_syslinux_iso(void)
{
    /*
     * Create an ISO9660 image containing:
     *   /isolinux/isolinux.bin   — fake binary with "ISOLINUX 6.03" at offset 64
     *   /isolinux/isolinux.cfg   — triggers config_path detection (syslinux_cfg[])
     *
     * The "ISOLINUX 6.03" pattern matches GetSyslinuxVersion:
     *   searches for "LINUX " preceded by "ISO" from offset 64 onward.
     *
     * The binary is 512 bytes: 64 zero-bytes, then the version string, then zeros.
     */
    const char *script =
        "python3 -c \""
        "import pycdlib, io\n"
        "iso = pycdlib.PyCdlib()\n"
        "iso.new(interchange_level=1, joliet=3, rock_ridge='1.09', vol_ident='SYSLINUX')\n"
        "iso.add_directory('/ISOLINUX', joliet_path='/isolinux', rr_name='isolinux')\n"
        "ver = b'\\x00'*64 + b'ISOLINUX 6.03 extra\\x00' + b'\\x00'*(512-64-20)\n"
        "iso.add_fp(io.BytesIO(ver), len(ver), '/ISOLINUX/ISOLINUX.BIN;1', joliet_path='/isolinux/isolinux.bin', rr_name='isolinux.bin')\n"
        "cfg = b'default linux\\n'\n"
        "iso.add_fp(io.BytesIO(cfg), len(cfg), '/ISOLINUX/ISOLINUX.CFG;1', joliet_path='/isolinux/isolinux.cfg', rr_name='isolinux.cfg')\n"
        "iso.write('" SYSLINUX_ISO_PATH "')\n"
        "iso.close()\n"
        "\"";
    struct stat st;
    if (system(script) == 0 && stat(SYSLINUX_ISO_PATH, &st) == 0 && st.st_size > 0)
        syslinux_iso_available = 1;
}

static void cleanup_syslinux_iso(void)
{
    unlink(SYSLINUX_ISO_PATH);
}

/* ================================================================
 * GRUB2 ISO test (normal.mod with embedded GRUB version string)
 * ================================================================ */

#define GRUB2_ISO_PATH "/tmp/test_rufus_grub2.iso"
static int grub2_iso_available = 0;

static void setup_grub2_iso(void)
{
    /*
     * Create an ISO9660 image containing:
     *   /boot/grub/i386-pc/normal.mod  — fake module with "GRUB  version 2.06\0"
     *       This triggers:
     *         (a) has_grub2 = 1 (directory match for "/boot/grub/i386-pc")
     *         (b) post-scan ReadISOFileToBuffer + GetGrubVersion sets grub2_version
     *
     * GetGrubVersion searches for "GRUB  version " (two spaces) in the buffer.
     * The buffer must be > 32 bytes (max_string_size check).
     */
    const char *script =
        "python3 -c \""
        "import pycdlib, io\n"
        "iso = pycdlib.PyCdlib()\n"
        "iso.new(interchange_level=1, joliet=3, rock_ridge='1.09', vol_ident='GRUB2TEST')\n"
        "iso.add_directory('/BOOT', joliet_path='/boot', rr_name='boot')\n"
        "iso.add_directory('/BOOT/GRUB', joliet_path='/boot/grub', rr_name='grub')\n"
        "iso.add_directory('/BOOT/GRUB/I386_PC', joliet_path='/boot/grub/i386-pc', rr_name='i386-pc')\n"
        "content = b'A' * 64 + b'GRUB  version 2.06\\x00' + b'B' * 64\n"
        "iso.add_fp(io.BytesIO(content), len(content), '/BOOT/GRUB/I386_PC/NORMAL.MOD;1', "
            "joliet_path='/boot/grub/i386-pc/normal.mod', rr_name='normal.mod')\n"
        "iso.write('" GRUB2_ISO_PATH "')\n"
        "iso.close()\n"
        "\"";
    struct stat st;
    if (system(script) == 0 && stat(GRUB2_ISO_PATH, &st) == 0 && st.st_size > 0)
        grub2_iso_available = 1;
}

static void cleanup_grub2_iso(void)
{
    unlink(GRUB2_ISO_PATH);
}

/* ================================================================
 * OpenSUSE ISO (tests config_path OpenSUSE priority + syslinux.cfg creation)
 * ================================================================ */

#define OPENSUSE_ISO_PATH "/tmp/test_rufus_opensuse.iso"
static int opensuse_iso_available = 0;

static void setup_opensuse_iso(void)
{
    /*
     * Creates an ISO with:
     *   /isolinux/isolinux.cfg          — standard path (shorter)
     *   /isolinux/isolinux.bin          — so HAS_SYSLINUX is TRUE
     *   /boot/i386/loader/isolinux.cfg  — OpenSUSE-priority path (longer)
     *
     * When scanned, Linux iso.c should:
     *   1. Select /boot/i386/loader/isolinux.cfg as cfg_path (overrides shortest)
     *   2. Set needs_syslinux_overwrite = TRUE
     */
    const char *script =
        "python3 -c \""
        "import pycdlib, io\n"
        "iso = pycdlib.PyCdlib()\n"
        "iso.new(interchange_level=1, joliet=3, rock_ridge='1.09', vol_ident='OPENSUSE')\n"
        "iso.add_directory('/ISOLINUX', joliet_path='/isolinux', rr_name='isolinux')\n"
        "iso.add_directory('/BOOT', joliet_path='/boot', rr_name='boot')\n"
        "iso.add_directory('/BOOT/I386', joliet_path='/boot/i386', rr_name='i386')\n"
        "iso.add_directory('/BOOT/I386/LOADER', joliet_path='/boot/i386/loader', rr_name='loader')\n"
        "cfg1 = b'default linux\\n'\n"
        "iso.add_fp(io.BytesIO(cfg1), len(cfg1), '/ISOLINUX/ISOLINUX.CFG;1', joliet_path='/isolinux/isolinux.cfg', rr_name='isolinux.cfg')\n"
        "ver = b'\\x00'*64 + b'ISOLINUX 6.03 extra\\x00' + b'\\x00'*(512-64-20)\n"
        "iso.add_fp(io.BytesIO(ver), len(ver), '/ISOLINUX/ISOLINUX.BIN;1', joliet_path='/isolinux/isolinux.bin', rr_name='isolinux.bin')\n"
        "cfg2 = b'default opensuse\\n'\n"
        "iso.add_fp(io.BytesIO(cfg2), len(cfg2), '/BOOT/I386/LOADER/ISOLINUX.CFG;1', joliet_path='/boot/i386/loader/isolinux.cfg', rr_name='isolinux.cfg')\n"
        "iso.write('" OPENSUSE_ISO_PATH "')\n"
        "iso.close()\n"
        "\"";
    struct stat st;
    if (system(script) == 0 && stat(OPENSUSE_ISO_PATH, &st) == 0 && st.st_size > 0)
        opensuse_iso_available = 1;
}

static void cleanup_opensuse_iso(void)
{
    unlink(OPENSUSE_ISO_PATH);
}

/* ================================================================
 * Broken UEFI bootloader ISO (tests has_efi & 0xc000 → DumpFatDir call)
 * ================================================================ */

#define BROKEN_EFI_ISO_PATH "/tmp/test_rufus_broken_efi.iso"
static int broken_efi_iso_available = 0;

static void setup_broken_efi_iso(void)
{
    /*
     * Creates a minimal Syslinux ISO so ExtractISO extraction mode runs
     * through the HAS_SYSLINUX branch.  No actual EFI img is needed since
     * we set has_efi manually and DumpFatDir is intercepted via --wrap.
     */
    const char *script =
        "python3 -c \""
        "import pycdlib, io\n"
        "iso = pycdlib.PyCdlib()\n"
        "iso.new(interchange_level=1, joliet=3, rock_ridge='1.09', vol_ident='BROKENEFI')\n"
        "iso.add_directory('/ISOLINUX', joliet_path='/isolinux', rr_name='isolinux')\n"
        "ver = b'\\x00'*64 + b'ISOLINUX 6.03 extra\\x00' + b'\\x00'*(512-64-20)\n"
        "iso.add_fp(io.BytesIO(ver), len(ver), '/ISOLINUX/ISOLINUX.BIN;1', joliet_path='/isolinux/isolinux.bin', rr_name='isolinux.bin')\n"
        "cfg = b'default linux\\n'\n"
        "iso.add_fp(io.BytesIO(cfg), len(cfg), '/ISOLINUX/ISOLINUX.CFG;1', joliet_path='/isolinux/isolinux.cfg', rr_name='isolinux.cfg')\n"
        "iso.write('" BROKEN_EFI_ISO_PATH "')\n"
        "iso.close()\n"
        "\"";
    struct stat st;
    if (system(script) == 0 && stat(BROKEN_EFI_ISO_PATH, &st) == 0 && st.st_size > 0)
        broken_efi_iso_available = 1;
}

static void cleanup_broken_efi_iso(void)
{
    unlink(BROKEN_EFI_ISO_PATH);
}

/* ================================================================
 * Knoppix ISO (tests symlinked_syslinux → real directory + syslnx cfg)
 * ================================================================ */

#define KNOPPIX_ISO_PATH "/tmp/test_rufus_knoppix.iso"
static int knoppix_iso_available = 0;

static void setup_knoppix_iso(void)
{
    /*
     * Creates an ISO with:
     *   /boot/isolinux/isolinux.bin     — so HAS_SYSLINUX is TRUE
     *   /boot/isolinux/isolinux.cfg     — triggers config_path
     *   /boot/isolinux/syslnx32.cfg     — Knoppix EFI syslinux config files
     *   /boot/isolinux/syslnx64.cfg
     *   /boot/syslinux → "isolinux"     — Rock Ridge symlink (the Knoppix case)
     *
     * When extracted, iso.c should:
     *   1. Detect the syslinux → isolinux symlink and set symlinked_syslinux
     *   2. After extraction, replace the symlink with a real directory
     *   3. Create syslnx32.cfg and syslnx64.cfg in the new directory
     */
    const char *script =
        "python3 -c \""
        "import pycdlib, io\n"
        "iso = pycdlib.PyCdlib()\n"
        "iso.new(interchange_level=1, joliet=3, rock_ridge='1.09', vol_ident='KNOPPIX')\n"
        "iso.add_directory('/BOOT', joliet_path='/boot', rr_name='boot')\n"
        "iso.add_directory('/BOOT/ISOLINUX', joliet_path='/boot/isolinux', rr_name='isolinux')\n"
        "ver = b'\\x00'*64 + b'ISOLINUX 6.03 extra\\x00' + b'\\x00'*(512-64-20)\n"
        "iso.add_fp(io.BytesIO(ver), len(ver), '/BOOT/ISOLINUX/ISOLINUX.BIN;1', joliet_path='/boot/isolinux/isolinux.bin', rr_name='isolinux.bin')\n"
        "cfg = b'default linux\\n'\n"
        "iso.add_fp(io.BytesIO(cfg), len(cfg), '/BOOT/ISOLINUX/ISOLINUX.CFG;1', joliet_path='/boot/isolinux/isolinux.cfg', rr_name='isolinux.cfg')\n"
        "s32 = b'default linux32\\n'\n"
        "iso.add_fp(io.BytesIO(s32), len(s32), '/BOOT/ISOLINUX/SYSLNX32.CFG;1', joliet_path='/boot/isolinux/syslnx32.cfg', rr_name='syslnx32.cfg')\n"
        "s64 = b'default linux64\\n'\n"
        "iso.add_fp(io.BytesIO(s64), len(s64), '/BOOT/ISOLINUX/SYSLNX64.CFG;1', joliet_path='/boot/isolinux/syslnx64.cfg', rr_name='syslnx64.cfg')\n"
        "iso.add_symlink(symlink_path='/BOOT/SYSLINUX;1', rr_symlink_name='syslinux', rr_path='isolinux', joliet_path='/boot/syslinux')\n"
        "iso.write('" KNOPPIX_ISO_PATH "')\n"
        "iso.close()\n"
        "\"";
    struct stat st;
    if (system(script) == 0 && stat(KNOPPIX_ISO_PATH, &st) == 0 && st.st_size > 0)
        knoppix_iso_available = 1;
}

static void cleanup_knoppix_iso(void)
{
    unlink(KNOPPIX_ISO_PATH);
}



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
    GetGrubFs(buf, sizeof(buf), &grub_filesystems);
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
    GetGrubFs(buf, sizeof(buf), &grub_filesystems);
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
    GetGrubFs(buf, sizeof(buf), &grub_filesystems);
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
 * Syslinux version detection tests
 * ================================================================ */

TEST(extract_iso_scan_detects_syslinux_version)
{
    /*
     * When scanning an ISO that contains isolinux/isolinux.bin with a
     * version string "ISOLINUX 6.03", ExtractISO (scan mode) must call
     * GetSyslinuxVersion and set img_report.sl_version = 0x0603.
     *
     * This test exercises the Linux iso.c Syslinux version detection
     * code path that was previously missing (sl_version was always 0).
     */
    if (!syslinux_iso_available) { printf("  (skipped: no syslinux test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    BOOL r = ExtractISO(SYSLINUX_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK(r == TRUE);
    /* Version 6.03 → 0x0603 */
    CHECK_MSG(img_report.sl_version == 0x0603,
              "sl_version must be 0x0603 after scanning Syslinux 6.03 ISO");
}

TEST(extract_iso_scan_detects_syslinux_version_str)
{
    /* After Syslinux version detection, sl_version_str should be "6.03" */
    if (!syslinux_iso_available) { printf("  (skipped: no syslinux test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    ExtractISO(SYSLINUX_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK_MSG(strcmp(img_report.sl_version_str, "6.03") == 0,
              "sl_version_str must be '6.03'");
}

TEST(extract_iso_no_syslinux_version_is_zero)
{
    /* A non-syslinux ISO must have sl_version == 0 */
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    ExtractISO(TEST_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK_MSG(img_report.sl_version == 0,
              "sl_version must remain 0 for non-Syslinux ISO");
}

/* ================================================================
 * GRUB2 version detection tests
 * ================================================================ */

TEST(extract_iso_scan_detects_grub2_version)
{
    /*
     * When scanning an ISO containing /boot/grub/i386-pc/normal.mod with
     * "GRUB  version 2.06" embedded, ExtractISO must:
     *   1. Set has_grub2 = 1 (from directory scan)
     *   2. Read normal.mod post-scan and call GetGrubVersion
     *   3. Set img_report.grub2_version = "2.06" (or "2.06-<label>")
     *
     * This was previously broken on Linux — grub2_version was always empty.
     */
    if (!grub2_iso_available) { printf("  (skipped: no GRUB2 test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    BOOL r = ExtractISO(GRUB2_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK(r == TRUE);
    CHECK_MSG(img_report.has_grub2 != 0,
              "has_grub2 must be non-zero for GRUB2 ISO");
    /* grub2_version must start with "2.06" (may have label suffix) */
    CHECK_MSG(strncmp(img_report.grub2_version, "2.06", 4) == 0,
              "grub2_version must start with '2.06'");
}

TEST(extract_iso_scan_grub2_version_non_grub_iso_stays_empty)
{
    /* A non-GRUB2 ISO must have grub2_version[0] == 0 */
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    ExtractISO(TEST_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK_MSG(img_report.grub2_version[0] == 0,
              "grub2_version must remain empty for non-GRUB2 ISO");
}

TEST(extract_iso_scan_grub2_has_grub2_set)
{
    /* has_grub2 must be set to 1 for the grub-boot ISO */
    if (!grub2_iso_available) { printf("  (skipped: no GRUB2 test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    ExtractISO(GRUB2_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    /* has_grub2 = 1 means "/boot/grub/i386-pc" (index 0 + 1) */
    CHECK_MSG(img_report.has_grub2 == 1,
              "has_grub2 must be 1 for /boot/grub/i386-pc");
}


/* ================================================================
 * OpenSUSE config_path selection + syslinux.cfg creation tests
 * ================================================================ */

TEST(extract_iso_scan_opensuse_sets_needs_syslinux_overwrite)
{
    /*
     * For OpenSUSE Live ISOs that have both /isolinux/isolinux.cfg (shorter)
     * and /boot/i386/loader/isolinux.cfg (longer, but OpenSUSE-priority),
     * iso.c must select the OpenSUSE path and set needs_syslinux_overwrite=TRUE.
     *
     * This mirrors Windows iso.c lines 990-994.
     */
    if (!opensuse_iso_available) { printf("  (skipped: no OpenSUSE test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    BOOL r = ExtractISO(OPENSUSE_ISO_PATH, "", TRUE);
    CHECK(r == TRUE);
    CHECK_MSG(strcmp(img_report.cfg_path, "/boot/i386/loader/isolinux.cfg") == 0,
              "cfg_path must be /boot/i386/loader/isolinux.cfg for OpenSUSE");
    CHECK_MSG(img_report.needs_syslinux_overwrite == TRUE,
              "needs_syslinux_overwrite must be TRUE for OpenSUSE");
}

TEST(extract_iso_scan_standard_syslinux_no_overwrite)
{
    /* Standard Syslinux ISO (no OpenSUSE path) must NOT set needs_syslinux_overwrite */
    if (!syslinux_iso_available) { printf("  (skipped: no syslinux test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    ExtractISO(SYSLINUX_ISO_PATH, "", TRUE);
    CHECK_MSG(img_report.needs_syslinux_overwrite == FALSE,
              "needs_syslinux_overwrite must be FALSE for standard syslinux");
    CHECK_MSG(strcmp(img_report.cfg_path, "/isolinux/isolinux.cfg") == 0,
              "cfg_path must be /isolinux/isolinux.cfg for standard syslinux");
}

TEST(extract_iso_extract_creates_syslinux_cfg)
{
    /*
     * After extracting a Syslinux-based ISO, iso.c must create
     * <dest_dir>/syslinux.cfg that points to img_report.cfg_path.
     *
     * This is required for Syslinux-based distros to boot from USB.
     * Windows iso.c lines 1141-1169 implement this; Linux was missing it.
     */
    if (!syslinux_iso_available) { printf("  (skipped: no syslinux test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    system("rm -rf " TEST_EXTRACT_DIR);
    system("mkdir -p " TEST_EXTRACT_DIR);
    /* Scan with empty dest_dir to populate img_report.cfg_path correctly */
    ExtractISO(SYSLINUX_ISO_PATH, "", TRUE);
    /* Extract to disk */
    BOOL r = ExtractISO(SYSLINUX_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    CHECK(r == TRUE);
    /* syslinux.cfg must have been created */
    struct stat st;
    char sysl_cfg[256];
    snprintf(sysl_cfg, sizeof(sysl_cfg), "%s/syslinux.cfg", TEST_EXTRACT_DIR);
    CHECK_MSG(stat(sysl_cfg, &st) == 0, "syslinux.cfg must be created after extraction");
    system("rm -rf " TEST_EXTRACT_DIR);
}

TEST(extract_iso_extract_syslinux_cfg_contents)
{
    /* syslinux.cfg must contain "CONFIG <cfg_path>" and "APPEND <dir>/" */
    if (!syslinux_iso_available) { printf("  (skipped: no syslinux test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    system("rm -rf " TEST_EXTRACT_DIR);
    system("mkdir -p " TEST_EXTRACT_DIR);
    ExtractISO(SYSLINUX_ISO_PATH, "", TRUE);
    ExtractISO(SYSLINUX_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    /* Read syslinux.cfg */
    char sysl_cfg[256];
    snprintf(sysl_cfg, sizeof(sysl_cfg), "%s/syslinux.cfg", TEST_EXTRACT_DIR);
    FILE *f = fopen(sysl_cfg, "r");
    if (f == NULL) { printf("  (syslinux.cfg not found)\n"); return; }
    char contents[512];
    size_t n = fread(contents, 1, sizeof(contents) - 1, f);
    fclose(f);
    contents[n] = '\0';
    CHECK_MSG(strstr(contents, "CONFIG /isolinux/isolinux.cfg") != NULL,
              "syslinux.cfg must contain 'CONFIG /isolinux/isolinux.cfg'");
    CHECK_MSG(strstr(contents, "APPEND /isolinux/") != NULL,
              "syslinux.cfg must contain 'APPEND /isolinux/'");
    system("rm -rf " TEST_EXTRACT_DIR);
}

TEST(extract_iso_extract_opensuse_renames_existing_syslinux_cfg)
{
    /*
     * For OpenSUSE (needs_syslinux_overwrite=TRUE), if syslinux.cfg already
     * exists in dest_dir, it must be renamed to syslinux.org before creating
     * the new syslinux.cfg. Mirrors Windows iso.c lines 1145-1150.
     */
    if (!opensuse_iso_available) { printf("  (skipped: no OpenSUSE test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    system("rm -rf " TEST_EXTRACT_DIR);
    system("mkdir -p " TEST_EXTRACT_DIR);
    /* Scan to set needs_syslinux_overwrite */
    ExtractISO(OPENSUSE_ISO_PATH, "", TRUE);
    /* Pre-create syslinux.cfg with sentinel content */
    char sysl_cfg[256], sysl_org[256];
    snprintf(sysl_cfg, sizeof(sysl_cfg), "%s/syslinux.cfg", TEST_EXTRACT_DIR);
    snprintf(sysl_org, sizeof(sysl_org), "%s/syslinux.org", TEST_EXTRACT_DIR);
    FILE *f = fopen(sysl_cfg, "w");
    CHECK(f != NULL);
    fprintf(f, "OLD_SYSLINUX_CFG\n");
    fclose(f);
    /* Extract — should rename old syslinux.cfg → syslinux.org */
    ExtractISO(OPENSUSE_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    /* syslinux.org must exist (renamed from old syslinux.cfg) */
    struct stat st;
    CHECK_MSG(stat(sysl_org, &st) == 0, "syslinux.org must exist after overwrite rename");
    /* Read syslinux.org — must contain the sentinel */
    f = fopen(sysl_org, "r");
    char buf[64];
    if (f) { fgets(buf, sizeof(buf), f); fclose(f); }
    CHECK_MSG(strstr(buf, "OLD_SYSLINUX_CFG") != NULL,
              "syslinux.org must contain original syslinux.cfg content");
    /* New syslinux.cfg must exist and point to the OpenSUSE cfg */
    f = fopen(sysl_cfg, "r");
    char contents[512];
    size_t n = fread(contents, 1, sizeof(contents) - 1, f);
    fclose(f);
    contents[n] = '\0';
    CHECK_MSG(strstr(contents, "CONFIG /boot/i386/loader/isolinux.cfg") != NULL,
              "new syslinux.cfg must reference the OpenSUSE cfg path");
    system("rm -rf " TEST_EXTRACT_DIR);
}

/* tracking vars defined in iso_linux_glue.c */
extern int g_dumpfatdir_call_count;
extern const char *g_dumpfatdir_last_path;

TEST(extract_iso_extract_efi_img_calls_dumpfatdir)
{
    /*
     * When has_efi & 0x8000 (Solus-style: EFI only in FAT efi.img),
     * ExtractISO extraction mode must call DumpFatDir(dest_dir, 0).
     * Mirrors Windows iso.c lines 1133-1140.
     */
    if (!broken_efi_iso_available) { printf("  (skipped: no broken_efi test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    system("rm -rf " TEST_EXTRACT_DIR);
    system("mkdir -p " TEST_EXTRACT_DIR);
    /* Scan first to populate img_report */
    ExtractISO(BROKEN_EFI_ISO_PATH, "", TRUE);
    /* Force-set the Solus EFI flag */
    img_report.has_efi = 0x8000;
    g_dumpfatdir_call_count = 0;
    ExtractISO(BROKEN_EFI_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    CHECK_MSG(g_dumpfatdir_call_count > 0,
              "DumpFatDir must be called when has_efi & 0x8000");
    system("rm -rf " TEST_EXTRACT_DIR);
}

TEST(extract_iso_extract_broken_efi_deletes_bootx64)
{
    /*
     * When has_efi & 0x4000 (broken bootx64.efi symlink, e.g. Mint),
     * ExtractISO extraction mode must:
     *   1. Delete <dest_dir>/EFI/boot/bootx64.efi
     *   2. Call DumpFatDir(dest_dir, 0)
     * Mirrors Windows iso.c lines 1134-1139.
     */
    if (!broken_efi_iso_available) { printf("  (skipped: no broken_efi test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    system("rm -rf " TEST_EXTRACT_DIR);
    system("mkdir -p " TEST_EXTRACT_DIR "/EFI/boot");
    /* Pre-create the broken bootx64.efi */
    char bootx64[256];
    snprintf(bootx64, sizeof(bootx64), "%s/EFI/boot/bootx64.efi", TEST_EXTRACT_DIR);
    FILE *f = fopen(bootx64, "w");
    if (f) { fprintf(f, "broken\n"); fclose(f); }
    /* Scan first */
    ExtractISO(BROKEN_EFI_ISO_PATH, "", TRUE);
    /* Force-set the broken-bootx64 EFI flag (0x4000 also implies DumpFatDir) */
    img_report.has_efi = 0xc000;
    g_dumpfatdir_call_count = 0;
    ExtractISO(BROKEN_EFI_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    /* bootx64.efi must have been deleted */
    struct stat st;
    CHECK_MSG(stat(bootx64, &st) != 0,
              "bootx64.efi must be deleted when has_efi & 0x4000");
    CHECK_MSG(g_dumpfatdir_call_count > 0,
              "DumpFatDir must be called when has_efi & 0x4000");
    system("rm -rf " TEST_EXTRACT_DIR);
}

TEST(extract_iso_extract_no_efi_img_skips_dumpfatdir)
{
    /*
     * When has_efi has no 0xc000 bits, DumpFatDir must NOT be called.
     */
    if (!broken_efi_iso_available) { printf("  (skipped: no broken_efi test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    system("rm -rf " TEST_EXTRACT_DIR);
    system("mkdir -p " TEST_EXTRACT_DIR);
    ExtractISO(BROKEN_EFI_ISO_PATH, "", TRUE);
    /* has_efi stays as-is from scan (likely 0) */
    g_dumpfatdir_call_count = 0;
    ExtractISO(BROKEN_EFI_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    CHECK_MSG(g_dumpfatdir_call_count == 0,
              "DumpFatDir must NOT be called when has_efi has no 0xc000 bits");
    system("rm -rf " TEST_EXTRACT_DIR);
}

TEST(extract_iso_knoppix_symlink_replaced_by_dir)
{
    /*
     * Knoppix ISOs have a Rock Ridge symlink /boot/syslinux → isolinux.
     * After extraction, the symlink must be replaced by a real directory.
     * Mirrors Windows iso.c lines 1183-1184.
     */
    if (!knoppix_iso_available) { printf("  (skipped: no Knoppix test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    system("rm -rf " TEST_EXTRACT_DIR);
    system("mkdir -p " TEST_EXTRACT_DIR);
    ExtractISO(KNOPPIX_ISO_PATH, "", TRUE);
    ExtractISO(KNOPPIX_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    char syslinux_dir[256];
    snprintf(syslinux_dir, sizeof(syslinux_dir), "%s/boot/syslinux", TEST_EXTRACT_DIR);
    struct stat st;
    CHECK_MSG(lstat(syslinux_dir, &st) == 0,
              "boot/syslinux must exist after Knoppix extraction");
    CHECK_MSG(S_ISDIR(st.st_mode),
              "boot/syslinux must be a real directory (not a symlink)");
    system("rm -rf " TEST_EXTRACT_DIR);
}

TEST(extract_iso_knoppix_creates_syslnx32_cfg)
{
    /*
     * After replacing the syslinux symlink, iso.c must create
     * boot/syslinux/syslnx32.cfg pointing to boot/isolinux/syslnx32.cfg.
     * Mirrors Windows iso.c lines 1186-1201.
     */
    if (!knoppix_iso_available) { printf("  (skipped: no Knoppix test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    system("rm -rf " TEST_EXTRACT_DIR);
    system("mkdir -p " TEST_EXTRACT_DIR);
    ExtractISO(KNOPPIX_ISO_PATH, "", TRUE);
    ExtractISO(KNOPPIX_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    char syslnx32[256];
    snprintf(syslnx32, sizeof(syslnx32), "%s/boot/syslinux/syslnx32.cfg", TEST_EXTRACT_DIR);
    struct stat st;
    CHECK_MSG(stat(syslnx32, &st) == 0,
              "boot/syslinux/syslnx32.cfg must be created after Knoppix extraction");
    /* Must contain CONFIG pointing to isolinux/syslnx32.cfg */
    FILE *f = fopen(syslnx32, "r");
    if (f) {
        char contents[512];
        size_t n = fread(contents, 1, sizeof(contents) - 1, f);
        fclose(f);
        contents[n] = '\0';
        CHECK_MSG(strstr(contents, "syslnx32.cfg") != NULL,
                  "syslnx32.cfg must reference syslnx32.cfg path");
    }
    system("rm -rf " TEST_EXTRACT_DIR);
}

TEST(extract_iso_knoppix_creates_syslnx64_cfg)
{
    /*
     * Same as above, but for syslnx64.cfg.
     */
    if (!knoppix_iso_available) { printf("  (skipped: no Knoppix test ISO)\n"); return; }
    memset(&img_report, 0, sizeof(img_report));
    enable_iso = TRUE;
    system("rm -rf " TEST_EXTRACT_DIR);
    system("mkdir -p " TEST_EXTRACT_DIR);
    ExtractISO(KNOPPIX_ISO_PATH, "", TRUE);
    ExtractISO(KNOPPIX_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    char syslnx64[256];
    snprintf(syslnx64, sizeof(syslnx64), "%s/boot/syslinux/syslnx64.cfg", TEST_EXTRACT_DIR);
    struct stat st;
    CHECK_MSG(stat(syslnx64, &st) == 0,
              "boot/syslinux/syslnx64.cfg must be created after Knoppix extraction");
    system("rm -rf " TEST_EXTRACT_DIR);
}

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
 * iso9660_readfat tests
 *
 * Tests the sector-reader callback used by libfat to read the FAT
 * filesystem embedded inside an EFI .img file on an ISO-9660 disc.
 * We use pre-filled buffers to avoid needing a real ISO image.
 * ================================================================ */

/* Helper: fill a fake private struct with a known pattern */
static void fill_private(iso9660_readfat_private *p, uint8_t pattern)
{
    memset(p, 0, sizeof(*p));
    p->p_iso     = NULL;    /* NULL => out-of-range reads will fail safely */
    p->lsn       = 0;
    p->sec_start = 0;
    memset(p->buf, pattern, sizeof(p->buf));
}

/* in-range read returns correct data */
TEST(readfat_inrange_sector_zero)
{
    iso9660_readfat_private priv;
    fill_private(&priv, 0xAB);
    uint8_t out[512] = {0};
    int r = iso9660_readfat((intptr_t)(void *)&priv, out, 512, 0);
    CHECK(r == 512);
    CHECK(out[0] == 0xAB);
    CHECK(out[511] == 0xAB);
}

/* in-range read at last slot returns correct data */
TEST(readfat_inrange_last_slot)
{
    iso9660_readfat_private priv;
    fill_private(&priv, 0xCD);
    /* buffer holds 32768 bytes / 512 = 64 sectors; last slot = 63 */
    uint8_t out[512] = {0};
    int r = iso9660_readfat((intptr_t)(void *)&priv, out, 512, 63);
    CHECK(r == 512);
    CHECK(out[0] == 0xCD);
}

/* sector size that is not a divisor of the buffer → returns 0 */
TEST(readfat_bad_secsize)
{
    iso9660_readfat_private priv;
    fill_private(&priv, 0x12);
    uint8_t out[300] = {0};
    /* 300 does not divide 32768 */
    int r = iso9660_readfat((intptr_t)(void *)&priv, out, 300, 0);
    CHECK(r == 0);
}

/* in-range read at sector 1 returns data at byte offset 512 */
TEST(readfat_inrange_sector_1_offset)
{
    iso9660_readfat_private priv;
    fill_private(&priv, 0x00);
    /* Write distinct sentinel at byte 512 */
    priv.buf[512] = 0x77;
    uint8_t out[512] = {0};
    int r = iso9660_readfat((intptr_t)(void *)&priv, out, 512, 1);
    CHECK(r == 512);
    CHECK(out[0] == 0x77);
}

/* out-of-range sector → p_iso is NULL → read fails → returns 0 */
TEST(readfat_outofrange_null_iso_fails)
{
    iso9660_readfat_private priv;
    fill_private(&priv, 0x55);
    uint8_t out[512] = {0};
    /* Sector 64 is outside [0, 64) → tries to seek (p_iso == NULL) → 0 */
    int r = iso9660_readfat((intptr_t)(void *)&priv, out, 512, 64);
    CHECK(r == 0);
}

/* ================================================================
 * is_in_md5sum / md5sum_totalbytes tests
 *
 * Create an ISO containing a data file and a matching md5sum.txt.
 * Verify that ExtractISO correctly accumulates md5sum_totalbytes for
 * every file that appears in md5sum.txt.
 * ================================================================ */

#define TEST_MD5_ISO_PATH    "/tmp/test_rufus_md5_iso.iso"
#define TEST_MD5_EXTRACT_DIR "/tmp/test_rufus_md5_extract"

static int md5_iso_available = 0;

static void setup_md5_iso(void)
{
    /*
     * Build an ISO containing:
     *   hello.txt   (14 bytes: "Hello, world!\n")
     *   listed.bin  (8 bytes:  "LISTED!!")       — listed in md5sum.txt
     *   unlisted.bin(6 bytes:  "NOPE!!")         — NOT listed in md5sum.txt
     *   md5sum.txt  — lists hello.txt and listed.bin only
     *
     * md5sum.txt format uses the standard "hash  ./path" layout.
     * The hash values are intentionally dummy (the test only verifies
     * that md5sum_totalbytes accumulates file sizes for listed files).
     */
    const char *script =
        "python3 -c \""
        "import pycdlib, io\n"
        "iso = pycdlib.PyCdlib()\n"
        "iso.new(interchange_level=1, joliet=3, rock_ridge='1.09', vol_ident='MD5TEST')\n"
        "c1 = b'Hello, world!\\n'\n"
        "iso.add_fp(io.BytesIO(c1), len(c1), '/HELLO.TXT;1', joliet_path='/hello.txt', rr_name='hello.txt')\n"
        "c2 = b'LISTED!!'\n"
        "iso.add_fp(io.BytesIO(c2), len(c2), '/LISTED.BIN;1', joliet_path='/listed.bin', rr_name='listed.bin')\n"
        "c3 = b'NOPE!!'\n"
        "iso.add_fp(io.BytesIO(c3), len(c3), '/UNLISTED.BIN;1', joliet_path='/unlisted.bin', rr_name='unlisted.bin')\n"
        "# md5sum.txt lists hello.txt and listed.bin but NOT unlisted.bin\n"
        "md5 = b'aabbcc0000000000000000000000000000  ./hello.txt\\n'\n"
        "md5 += b'ddeeff0000000000000000000000000000  ./listed.bin\\n'\n"
        "iso.add_fp(io.BytesIO(md5), len(md5), '/MD5SUM.TXT;1', joliet_path='/md5sum.txt', rr_name='md5sum.txt')\n"
        "iso.write('" TEST_MD5_ISO_PATH "')\n"
        "iso.close()\n"
        "\"";

    struct stat st;
    system(script);
    if (stat(TEST_MD5_ISO_PATH, &st) == 0 && st.st_size > 0)
        md5_iso_available = 1;
}

static void cleanup_md5_iso(void)
{
    unlink(TEST_MD5_ISO_PATH);
    system("rm -rf " TEST_MD5_EXTRACT_DIR);
}

/* md5sum_totalbytes should equal the sum of listed files (14 + 8 = 22) */
TEST(md5sum_totalbytes_counts_listed_files)
{
    if (!md5_iso_available) { printf("  (skipped: no md5 test ISO)\n"); return; }
    system("rm -rf " TEST_MD5_EXTRACT_DIR);
    mkdir(TEST_MD5_EXTRACT_DIR, 0755);

    memset(&img_report, 0, sizeof(img_report));
    md5sum_totalbytes = 0;
    enable_iso = TRUE;
    validate_md5sum = TRUE;

    /* Scan phase sets img_report.has_md5sum and total_blocks */
    BOOL r = ExtractISO(TEST_MD5_ISO_PATH, TEST_MD5_EXTRACT_DIR, TRUE);
    CHECK(r == TRUE);
    CHECK(img_report.has_md5sum == 1);

    /* Extract phase uses is_in_md5sum to accumulate md5sum_totalbytes */
    r = ExtractISO(TEST_MD5_ISO_PATH, TEST_MD5_EXTRACT_DIR, FALSE);
    CHECK(r == TRUE);

    /* hello.txt (14) + listed.bin (8) = 22, unlisted.bin excluded */
    CHECK_INT_EQ((int)md5sum_totalbytes, 22);

    validate_md5sum = FALSE;
    system("rm -rf " TEST_MD5_EXTRACT_DIR);
}

/* When validate_md5sum is FALSE, md5sum_totalbytes stays 0 */
TEST(md5sum_totalbytes_zero_when_disabled)
{
    if (!md5_iso_available) { printf("  (skipped: no md5 test ISO)\n"); return; }
    system("rm -rf " TEST_MD5_EXTRACT_DIR);
    mkdir(TEST_MD5_EXTRACT_DIR, 0755);

    memset(&img_report, 0, sizeof(img_report));
    md5sum_totalbytes = 0;
    enable_iso = TRUE;
    validate_md5sum = FALSE;

    BOOL r = ExtractISO(TEST_MD5_ISO_PATH, TEST_MD5_EXTRACT_DIR, TRUE);
    CHECK(r == TRUE);
    r = ExtractISO(TEST_MD5_ISO_PATH, TEST_MD5_EXTRACT_DIR, FALSE);
    CHECK(r == TRUE);

    CHECK_INT_EQ((int)md5sum_totalbytes, 0);

    system("rm -rf " TEST_MD5_EXTRACT_DIR);
}

/* When no md5sum.txt exists in the ISO, md5sum_totalbytes stays 0 */
TEST(md5sum_totalbytes_zero_when_no_md5sum_file)
{
    if (!test_iso_available) { printf("  (skipped: no test ISO)\n"); return; }
    system("rm -rf " TEST_EXTRACT_DIR);
    mkdir(TEST_EXTRACT_DIR, 0755);

    memset(&img_report, 0, sizeof(img_report));
    md5sum_totalbytes = 0;
    enable_iso = TRUE;
    validate_md5sum = TRUE;

    BOOL r = ExtractISO(TEST_ISO_PATH, TEST_EXTRACT_DIR, TRUE);
    CHECK(r == TRUE);
    CHECK(img_report.has_md5sum == 0);  /* no md5sum.txt in test ISO */

    r = ExtractISO(TEST_ISO_PATH, TEST_EXTRACT_DIR, FALSE);
    CHECK(r == TRUE);

    CHECK_INT_EQ((int)md5sum_totalbytes, 0);

    validate_md5sum = FALSE;
    system("rm -rf " TEST_EXTRACT_DIR);
}

/* ================================================================
 * DumpFatDir tests
 *
 * Create a FAT filesystem image with a few files and one sub-directory,
 * embed it inside an ISO-9660 image, then verify that DumpFatDir()
 * correctly extracts every entry.
 * ================================================================ */

#define TEST_FAT_ISO_PATH    "/tmp/test_rufus_fat_iso.iso"
#define TEST_FAT_EXTRACT_DIR "/tmp/test_rufus_fat_extract"
static int fat_iso_available = 0;

/* Helper: run a shell command; return 0 on success */
static int run_cmd(const char *cmd) { return system(cmd); }

static void setup_fat_iso(void)
{
    /* Build a small FAT image with: BOOTX64.EFI, BOOTIA32.EFI, BOOT/GRUB.CFG */
    const char *setup =
        "set -e\n"
        "T=$(mktemp -d)\n"
        /* 2 MiB FAT12 image */
        "dd if=/dev/zero of=$T/efi.img bs=512 count=4096 2>/dev/null\n"
        "mkfs.fat -F 12 $T/efi.img >/dev/null 2>&1\n"
        /* Seed files */
        "printf 'EFI-x64-content' > $T/bootx64.efi\n"
        "printf 'EFI-ia32-content' > $T/bootia32.efi\n"
        "printf 'grub-cfg-content' > $T/grub.cfg\n"
        /* Populate FAT image */
        "MTOOLS_SKIP_CHECK=1 mcopy -i $T/efi.img $T/bootx64.efi   ::/BOOTX64.EFI\n"
        "MTOOLS_SKIP_CHECK=1 mcopy -i $T/efi.img $T/bootia32.efi  ::/BOOTIA32.EFI\n"
        "MTOOLS_SKIP_CHECK=1 mmd   -i $T/efi.img                  ::/BOOT\n"
        "MTOOLS_SKIP_CHECK=1 mcopy -i $T/efi.img $T/grub.cfg      ::/BOOT/GRUB.CFG\n"
        /* Embed FAT image into ISO */
        "mkdir -p $T/isoroot\n"
        "cp $T/efi.img $T/isoroot/efi.img\n"
        "genisoimage -quiet -o " TEST_FAT_ISO_PATH " -J -R $T/isoroot 2>/dev/null\n"
        "rm -rf $T\n";

    struct stat st;
    run_cmd(setup);
    if (stat(TEST_FAT_ISO_PATH, &st) == 0 && st.st_size > 0)
        fat_iso_available = 1;
}

static void cleanup_fat_iso(void)
{
    unlink(TEST_FAT_ISO_PATH);
    run_cmd("rm -rf " TEST_FAT_EXTRACT_DIR);
}

/* Helper: prepare a fresh extraction directory */
static void prepare_extract_dir(void)
{
    run_cmd("rm -rf " TEST_FAT_EXTRACT_DIR);
    mkdir(TEST_FAT_EXTRACT_DIR, 0755);
}

/* ---- unit tests ---- */

TEST(dumpfatdir_null_path_returns_false)
{
    CHECK(DumpFatDir(NULL, 0) == FALSE);
}

TEST(dumpfatdir_null_image_path_returns_false)
{
    /* cluster == 0 triggers init path; image_path NULL → FALSE */
    char *saved = image_path;
    image_path = NULL;
    CHECK(DumpFatDir("/tmp", 0) == FALSE);
    image_path = saved;
}

TEST(dumpfatdir_invalid_iso_returns_false)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    char *saved = image_path;
    image_path = (char *)"/nonexistent/no.iso";
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    CHECK(DumpFatDir("/tmp", 0) == FALSE);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));
}

TEST(dumpfatdir_missing_efi_img_returns_false)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/no_such_file.img");
    CHECK(DumpFatDir("/tmp", 0) == FALSE);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));
}

TEST(dumpfatdir_returns_true_on_success)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    prepare_extract_dir();
    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    BOOL r = DumpFatDir(TEST_FAT_EXTRACT_DIR, 0);
    CHECK(r == TRUE);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));
}

TEST(dumpfatdir_extracts_first_file)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    prepare_extract_dir();
    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    DumpFatDir(TEST_FAT_EXTRACT_DIR, 0);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));

    /* At least one of the EFI files must be present */
    struct stat st;
    int found = (stat(TEST_FAT_EXTRACT_DIR "/BOOTX64.EFI", &st) == 0) ||
                (stat(TEST_FAT_EXTRACT_DIR "/bootx64.efi", &st) == 0);
    CHECK(found);
}

TEST(dumpfatdir_extracts_second_file)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    prepare_extract_dir();
    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    DumpFatDir(TEST_FAT_EXTRACT_DIR, 0);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));

    struct stat st;
    int found = (stat(TEST_FAT_EXTRACT_DIR "/BOOTIA32.EFI", &st) == 0) ||
                (stat(TEST_FAT_EXTRACT_DIR "/bootia32.efi", &st) == 0);
    CHECK(found);
}

TEST(dumpfatdir_file_content_correct)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    prepare_extract_dir();
    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    DumpFatDir(TEST_FAT_EXTRACT_DIR, 0);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));

    /* Verify file content of BOOTX64.EFI */
    const char *path64 = NULL;
    struct stat st;
    if (stat(TEST_FAT_EXTRACT_DIR "/BOOTX64.EFI", &st) == 0)
        path64 = TEST_FAT_EXTRACT_DIR "/BOOTX64.EFI";
    else if (stat(TEST_FAT_EXTRACT_DIR "/bootx64.efi", &st) == 0)
        path64 = TEST_FAT_EXTRACT_DIR "/bootx64.efi";
    if (path64 == NULL) { CHECK(0); return; }

    FILE *f = fopen(path64, "rb");
    CHECK(f != NULL);
    if (!f) return;
    char buf[64] = {0};
    fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    CHECK(strncmp(buf, "EFI-x64-content", 15) == 0);
}

TEST(dumpfatdir_creates_subdirectory)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    prepare_extract_dir();
    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    DumpFatDir(TEST_FAT_EXTRACT_DIR, 0);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));

    struct stat st;
    int found = (stat(TEST_FAT_EXTRACT_DIR "/BOOT", &st) == 0 && S_ISDIR(st.st_mode)) ||
                (stat(TEST_FAT_EXTRACT_DIR "/boot", &st) == 0 && S_ISDIR(st.st_mode));
    CHECK(found);
}

TEST(dumpfatdir_extracts_nested_file)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    prepare_extract_dir();
    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    DumpFatDir(TEST_FAT_EXTRACT_DIR, 0);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));

    struct stat st;
    int found = (stat(TEST_FAT_EXTRACT_DIR "/BOOT/GRUB.CFG", &st) == 0) ||
                (stat(TEST_FAT_EXTRACT_DIR "/BOOT/grub.cfg", &st) == 0) ||
                (stat(TEST_FAT_EXTRACT_DIR "/boot/GRUB.CFG", &st) == 0) ||
                (stat(TEST_FAT_EXTRACT_DIR "/boot/grub.cfg", &st) == 0);
    CHECK(found);
}

TEST(dumpfatdir_nested_file_content_correct)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    prepare_extract_dir();
    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    DumpFatDir(TEST_FAT_EXTRACT_DIR, 0);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));

    /* Find the grub.cfg file regardless of case */
    const char *candidates[] = {
        TEST_FAT_EXTRACT_DIR "/BOOT/GRUB.CFG",
        TEST_FAT_EXTRACT_DIR "/BOOT/grub.cfg",
        TEST_FAT_EXTRACT_DIR "/boot/GRUB.CFG",
        TEST_FAT_EXTRACT_DIR "/boot/grub.cfg",
        NULL
    };
    const char *found = NULL;
    struct stat st;
    for (int i = 0; candidates[i]; i++) {
        if (stat(candidates[i], &st) == 0) { found = candidates[i]; break; }
    }
    CHECK(found != NULL);
    if (!found) return;
    FILE *f = fopen(found, "rb");
    CHECK(f != NULL);
    if (!f) return;
    char buf[64] = {0};
    fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    CHECK(strncmp(buf, "grub-cfg-content", 16) == 0);
}

TEST(dumpfatdir_skips_existing_file)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    prepare_extract_dir();

    /* Pre-create a file to verify it is NOT overwritten */
    FILE *f = fopen(TEST_FAT_EXTRACT_DIR "/BOOTX64.EFI", "wb");
    if (f) { fwrite("ORIGINAL", 8, 1, f); fclose(f); }
    /* Also create lower-case variant to handle both cases */
    f = fopen(TEST_FAT_EXTRACT_DIR "/bootx64.efi", "wb");
    if (f) { fwrite("ORIGINAL", 8, 1, f); fclose(f); }

    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    DumpFatDir(TEST_FAT_EXTRACT_DIR, 0);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));

    /* The pre-existing file should not have been changed */
    char buf[64] = {0};
    const char *path64 = NULL;
    struct stat st;
    if (stat(TEST_FAT_EXTRACT_DIR "/BOOTX64.EFI", &st) == 0)
        path64 = TEST_FAT_EXTRACT_DIR "/BOOTX64.EFI";
    else if (stat(TEST_FAT_EXTRACT_DIR "/bootx64.efi", &st) == 0)
        path64 = TEST_FAT_EXTRACT_DIR "/bootx64.efi";
    if (path64 == NULL) { CHECK(0); return; }
    f = fopen(path64, "rb");
    CHECK(f != NULL);
    if (!f) return;
    fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    CHECK(strncmp(buf, "ORIGINAL", 8) == 0);
}

/* wchar16_to_utf8 is a static function in iso.c; we test it indirectly
 * by verifying that DumpFatDir produces correct filenames even for
 * characters outside ASCII (here we probe basic ASCII correctness via
 * the fixture files whose names contain only A-Z digits and dots). */
TEST(dumpfatdir_filenames_are_valid_utf8)
{
    if (!fat_iso_available) { printf("  (skipped: no FAT ISO)\n"); return; }
    prepare_extract_dir();
    char *saved = image_path;
    image_path = (char *)TEST_FAT_ISO_PATH;
    memset(&img_report, 0, sizeof(img_report));
    strcpy(img_report.efi_img_path, "/efi.img");
    DumpFatDir(TEST_FAT_EXTRACT_DIR, 0);
    image_path = saved;
    memset(&img_report, 0, sizeof(img_report));

    /* Every byte in every extracted filename must be valid ASCII (< 0x80)
     * which is a subset of valid UTF-8. */
    DIR *d = opendir(TEST_FAT_EXTRACT_DIR);
    CHECK(d != NULL);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        for (const char *p = de->d_name; *p; p++) {
            CHECK((unsigned char)*p < 0x80);
        }
    }
    closedir(d);
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
    printf("=== ISO extraction tests (Linux) ===\n\n");

    /* Setup: generate test ISOs */
    setup_test_iso();
    if (!test_iso_available)
        printf("  NOTE: test ISO not available (pycdlib not installed?); ISO I/O tests skipped\n\n");

    setup_fat_iso();
    if (!fat_iso_available)
        printf("  NOTE: FAT-in-ISO not available (mkfs.fat/mcopy/genisoimage missing?); DumpFatDir tests skipped\n\n");

    setup_md5_iso();
    if (!md5_iso_available)
        printf("  NOTE: md5sum test ISO not available (pycdlib not installed?); md5sum tracking tests skipped\n\n");

    setup_syslinux_iso();
    if (!syslinux_iso_available)
        printf("  NOTE: syslinux test ISO not available (pycdlib not installed?); Syslinux version tests skipped\n\n");

    setup_grub2_iso();
    if (!grub2_iso_available)
        printf("  NOTE: GRUB2 test ISO not available (pycdlib not installed?); GRUB2 version tests skipped\n\n");

    setup_opensuse_iso();
    if (!opensuse_iso_available)
        printf("  NOTE: OpenSUSE test ISO not available (pycdlib not installed?); OpenSUSE cfg tests skipped\n\n");

    setup_broken_efi_iso();
    if (!broken_efi_iso_available)
        printf("  NOTE: broken_efi test ISO not available; EFI workaround tests skipped\n\n");

    setup_knoppix_iso();
    if (!knoppix_iso_available)
        printf("  NOTE: Knoppix test ISO not available; Knoppix symlink tests skipped\n\n");

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

    printf("\n  Syslinux version detection\n");
    RUN(extract_iso_scan_detects_syslinux_version);
    RUN(extract_iso_scan_detects_syslinux_version_str);
    RUN(extract_iso_no_syslinux_version_is_zero);

    printf("\n  GRUB2 version detection\n");
    RUN(extract_iso_scan_detects_grub2_version);
    RUN(extract_iso_scan_grub2_version_non_grub_iso_stays_empty);
    RUN(extract_iso_scan_grub2_has_grub2_set);

    printf("\n  OpenSUSE config_path + syslinux.cfg creation\n");
    RUN(extract_iso_scan_opensuse_sets_needs_syslinux_overwrite);
    RUN(extract_iso_scan_standard_syslinux_no_overwrite);
    RUN(extract_iso_extract_creates_syslinux_cfg);
    RUN(extract_iso_extract_syslinux_cfg_contents);
    RUN(extract_iso_extract_opensuse_renames_existing_syslinux_cfg);

    printf("\n  Broken UEFI bootloader workaround (Solus/Mint)\n");
    RUN(extract_iso_extract_efi_img_calls_dumpfatdir);
    RUN(extract_iso_extract_broken_efi_deletes_bootx64);
    RUN(extract_iso_extract_no_efi_img_skips_dumpfatdir);

    printf("\n  Knoppix symlinked_syslinux workaround\n");
    RUN(extract_iso_knoppix_symlink_replaced_by_dir);
    RUN(extract_iso_knoppix_creates_syslnx32_cfg);
    RUN(extract_iso_knoppix_creates_syslnx64_cfg);

    printf("\n  HasEfiImgBootLoaders\n");
    RUN(has_efi_img_false);
    RUN(has_efi_img_true);

    printf("\n  iso9660_readfat\n");
    RUN(readfat_inrange_sector_zero);
    RUN(readfat_inrange_last_slot);
    RUN(readfat_bad_secsize);
    RUN(readfat_inrange_sector_1_offset);
    RUN(readfat_outofrange_null_iso_fails);

    printf("\n  DumpFatDir\n");
    RUN(dumpfatdir_null_path_returns_false);
    RUN(dumpfatdir_null_image_path_returns_false);
    RUN(dumpfatdir_invalid_iso_returns_false);
    RUN(dumpfatdir_missing_efi_img_returns_false);
    RUN(dumpfatdir_returns_true_on_success);
    RUN(dumpfatdir_extracts_first_file);
    RUN(dumpfatdir_extracts_second_file);
    RUN(dumpfatdir_file_content_correct);
    RUN(dumpfatdir_creates_subdirectory);
    RUN(dumpfatdir_extracts_nested_file);
    RUN(dumpfatdir_nested_file_content_correct);
    RUN(dumpfatdir_skips_existing_file);
    RUN(dumpfatdir_filenames_are_valid_utf8);

    printf("\n  is_in_md5sum / md5sum_totalbytes\n");
    RUN(md5sum_totalbytes_zero_when_no_md5sum_file);
    RUN(md5sum_totalbytes_zero_when_disabled);
    RUN(md5sum_totalbytes_counts_listed_files);

    StrArrayDestroy(&modified_files);
    cleanup_test_iso();
    cleanup_fat_iso();
    cleanup_md5_iso();
    cleanup_syslinux_iso();
    cleanup_grub2_iso();
    cleanup_opensuse_iso();
    cleanup_broken_efi_iso();
    cleanup_knoppix_iso();

    TEST_RESULTS();
}

#endif /* __linux__ */
