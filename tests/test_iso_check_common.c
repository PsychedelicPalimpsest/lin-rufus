/*
 * test_iso_check_common.c — Tests for common check_iso_props() ISO classifier
 *
 * check_iso_props() lives in src/common/iso_check.c, which is an "include trick"
 * file: it is #included (not compiled standalone) into linux/iso.c and
 * windows/iso.c, where it accesses the file-local statics and constants of the
 * enclosing translation unit.
 *
 * Here we replicate that environment — defining all the required statics,
 * constants, and globals — and then #include the common file directly so that
 * check_iso_props() becomes part of this test TU.
 */
#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ */
/* Headers (same include path as the iso_scan_common test)            */
/* ------------------------------------------------------------------ */
#include "rufus.h"                        /* BOOL, NB_OLD_C32, ... */
#include "../src/common/iso_config.h"     /* EXTRACT_PROPS typedef */

/* ISO_BLOCKSIZE is normally from <cdio/iso9660.h>; define it here */
#ifndef ISO_BLOCKSIZE
#define ISO_BLOCKSIZE 2048
#endif

/* ------------------------------------------------------------------ */
/* Stubs for functions called by check_iso_props()                     */
/* ------------------------------------------------------------------ */

void uprintf(const char* fmt, ...) { (void)fmt; }

/* Simple StrArray backed by a fixed pool */
#define SA_MAX 64
static char* sa_pool[SA_MAX];
static uint32_t sa_used = 0;

void StrArrayCreate(StrArray* arr, uint32_t initial_size)
{
	(void)initial_size;
	arr->String = calloc(SA_MAX, sizeof(char*));
	arr->Index  = 0;
	arr->Max    = SA_MAX;
}

int32_t StrArrayAdd(StrArray* arr, const char* str, BOOL duplicate)
{
	if (!arr || arr->Index >= arr->Max) return -1;
	arr->String[arr->Index] = duplicate ? strdup(str) : (char*)str;
	if (duplicate) sa_pool[sa_used++ % SA_MAX] = arr->String[arr->Index];
	return (int32_t)arr->Index++;
}

void StrArrayDestroy(StrArray* arr)
{
	if (!arr) return;
	for (uint32_t i = 0; i < arr->Index; i++)
		free(arr->String[i]);
	free(arr->String);
	arr->String = NULL;
	arr->Index = arr->Max = 0;
}

/* ------------------------------------------------------------------ */
/* String constants (must mirror platform iso.c)                       */
/* ------------------------------------------------------------------ */

static const char* bootmgr_name     = "bootmgr";
static const char* grldr_name       = "grldr";
static const char* ldlinux_name     = "ldlinux.sys";
static const char* ldlinux_c32      = "ldlinux.c32";
static const char* casper_dirname   = "/casper";
static const char* proxmox_dirname  = "/proxmox";
static const char* sources_str      = "/sources";
static const char* wininst_name[]   = { "install.wim", "install.esd", "install.swm" };
static const char* grub_dirname[]   = { "/boot/grub/i386-pc", "/boot/grub2/i386-pc" };
static const char* grub_cfg[]       = { "grub.cfg", "loopback.cfg" };
static const char* menu_cfg         = "menu.cfg";
/* NB: Do not alter the order without validating hardcoded indexes */
static const char* syslinux_cfg[]   = { "isolinux.cfg", "syslinux.cfg", "extlinux.conf",
                                        "txt.cfg", "live.cfg" };
static const char* isolinux_bin[]   = { "isolinux.bin", "boot.bin" };
static const char* pe_dirname[]     = { "/i386", "/amd64", "/minint" };
static const char* pe_file[]        = { "ntdetect.com", "setupldr.bin", "txtsetup.sif" };
static const char* reactos_name[]   = { "setupldr.sys", "freeldr.sys" };
static const char* kolibri_name     = "kolibri.img";
static const char* manjaro_marker   = ".miso";
static const char* pop_os_name      = "pop-os";
static const int64_t old_c32_threshold[NB_OLD_C32] = OLD_C32_THRESHOLD;

/* Non-static globals (exported by platform iso.c) */
const char* bootmgr_efi_name        = "bootmgr.efi";
const char* efi_dirname             = "/efi/boot";
const char* efi_bootname[3]         = { "boot", "grub", "mm" };
const char* efi_archname[ARCH_MAX]  = {
	"", "ia32", "x64", "arm", "aa64", "ia64", "riscv64", "loongarch64", "ebc"
};
const char* md5sum_name[2]          = { "md5sum.txt", "MD5SUMS" };
const char* old_c32_name[NB_OLD_C32] = OLD_C32_NAMES;

/* ------------------------------------------------------------------ */
/* State variables (statics in platform iso.c)                         */
/* ------------------------------------------------------------------ */

static BOOL scan_only = FALSE;
static StrArray config_path, isolinux_path;

/* Globals modified by check_iso_props */
RUFUS_IMG_REPORT img_report;
uint64_t total_blocks = 0;
BOOL has_ldlinux_c32 = FALSE;

/* Stubs needed by iso_check.c for WIM-splitting code (both Windows and Linux) */

int fs_type = 0;
char *image_path = NULL;
#define print_split_file(p, l) ((void)0)
BOOL WimSplitFile(const char* src, const char* dst) { (void)src; (void)dst; return FALSE; }

/* ------------------------------------------------------------------ */
/* Pull in the common implementation                                    */
/* ------------------------------------------------------------------ */

#include "../src/common/iso_check.c"

/* ------------------------------------------------------------------ */
/* Test helpers                                                         */
/* ------------------------------------------------------------------ */

static void reset(void)
{
	memset(&img_report, 0, sizeof(img_report));
	total_blocks     = 0;
	has_ldlinux_c32  = FALSE;
	scan_only        = TRUE;  /* most tests use scan_only mode */
	StrArrayCreate(&config_path, 16);
	StrArrayCreate(&isolinux_path, 16);
}

static void teardown(void)
{
	StrArrayDestroy(&config_path);
	StrArrayDestroy(&isolinux_path);
}

/* ================================================================
 * Scan-only tests
 * ================================================================ */

/* syslinux cfg detection sets is_cfg + is_syslinux_cfg */
TEST(scan_syslinux_cfg_isolinux)
{
	reset();
	EXTRACT_PROPS p;
	BOOL r = check_iso_props("", 1024, "isolinux.cfg", "/isolinux.cfg", &p);
	CHECK(r == TRUE);
	CHECK(p.is_cfg == TRUE);
	CHECK(p.is_syslinux_cfg == TRUE);
	/* config_path should have received the entry (index < 3) */
	CHECK(config_path.Index == 1);
	CHECK(strcmp(config_path.String[0], "/isolinux.cfg") == 0);
	teardown();
}

TEST(scan_syslinux_cfg_syslinux)
{
	reset();
	EXTRACT_PROPS p;
	BOOL r = check_iso_props("", 1024, "syslinux.cfg", "/syslinux.cfg", &p);
	CHECK(r == TRUE);
	CHECK(p.is_syslinux_cfg == TRUE);
	/* syslinux.cfg is index 1 — added to config_path */
	CHECK(config_path.Index == 1);
	teardown();
}

TEST(scan_syslinux_cfg_extlinux)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 512, "extlinux.conf", "/extlinux.conf", &p);
	CHECK(p.is_syslinux_cfg == TRUE);
	/* extlinux.conf is index 2 — added to config_path */
	CHECK(config_path.Index == 1);
	teardown();
}

/* txt.cfg and live.cfg are index >= 3 — NOT added to config_path */
TEST(scan_syslinux_cfg_txt_cfg)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 512, "txt.cfg", "/txt.cfg", &p);
	CHECK(p.is_syslinux_cfg == TRUE);
	CHECK(config_path.Index == 0); /* index 3, not added */
	teardown();
}

/* EFI syslinux detection: syslinux.cfg in /efi/boot */
TEST(scan_efi_syslinux)
{
	reset();
	EXTRACT_PROPS p;
	img_report.has_efi_syslinux = FALSE;
	check_iso_props("/efi/boot", 512, "syslinux.cfg", "/efi/boot/syslinux.cfg", &p);
	CHECK(img_report.has_efi_syslinux == TRUE);
	teardown();
}

/* archiso loader/entries conf detection */
TEST(scan_loader_entries_conf)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/loader/entries", 256, "arch.conf", "/loader/entries/arch.conf", &p);
	CHECK(p.is_conf == TRUE);
	teardown();
}

TEST(scan_loader_entries_non_conf)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/loader/entries", 256, "arch.txt", "/loader/entries/arch.txt", &p);
	CHECK(p.is_conf == FALSE);
	teardown();
}

/* GRUB2 directory detection */
TEST(scan_grub2_boot_dir)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/boot/grub/i386-pc", 4096, "core.img", "/boot/grub/i386-pc/core.img", &p);
	CHECK(img_report.has_grub2 == 1);
	teardown();
}

TEST(scan_grub2_boot2_dir)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/boot/grub2/i386-pc", 4096, "core.img", "/boot/grub2/i386-pc/core.img", &p);
	CHECK(img_report.has_grub2 == 2);
	teardown();
}

/* ldlinux.c32 sets has_ldlinux_c32 */
TEST(scan_ldlinux_c32)
{
	reset();
	has_ldlinux_c32 = FALSE;
	EXTRACT_PROPS p;
	check_iso_props("", 65536, "ldlinux.c32", "/ldlinux.c32", &p);
	CHECK(has_ldlinux_c32 == TRUE);
	teardown();
}

/* casper directory sets uses_casper */
TEST(scan_casper)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/casper", 1024, "filesystem.squashfs",
	                "/casper/filesystem.squashfs", &p);
	CHECK(img_report.uses_casper == TRUE);
	CHECK(img_report.disable_iso == FALSE);
	teardown();
}

/* pop-os subdirectory of casper sets disable_iso */
TEST(scan_pop_os)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/casper/pop-os", 1024, "filesystem.squashfs",
	                "/casper/pop-os/filesystem.squashfs", &p);
	CHECK(img_report.uses_casper == TRUE);
	CHECK(img_report.disable_iso == TRUE);
	teardown();
}

/* proxmox directory sets disable_iso */
TEST(scan_proxmox)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/proxmox", 1024, "pve.squashfs", "/proxmox/pve.squashfs", &p);
	CHECK(img_report.disable_iso == TRUE);
	teardown();
}

/* Root-level: bootmgr */
TEST(scan_root_bootmgr)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 1024, "bootmgr", "/bootmgr", &p);
	CHECK(img_report.has_bootmgr == TRUE);
	teardown();
}

/* Root-level: bootmgr.efi sets has_efi and has_bootmgr_efi */
TEST(scan_root_bootmgr_efi)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 65536, "bootmgr.efi", "/bootmgr.efi", &p);
	CHECK(img_report.has_bootmgr_efi == TRUE);
	CHECK(img_report.has_efi & 1);
	CHECK(img_report.efi_boot_entry[0].type == EBT_BOOTMGR);
	CHECK(strcmp(img_report.efi_boot_entry[0].path, "/bootmgr.efi") == 0);
	teardown();
}

/* Root-level: grldr sets has_grub4dos */
TEST(scan_root_grldr)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 512, "grldr", "/grldr", &p);
	CHECK(img_report.has_grub4dos == TRUE);
	teardown();
}

/* Root-level: kolibri.img sets has_kolibrios */
TEST(scan_root_kolibri)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 1024, "kolibri.img", "/kolibri.img", &p);
	CHECK(img_report.has_kolibrios == TRUE);
	teardown();
}

/* Root-level: .miso sets disable_iso (Manjaro) */
TEST(scan_root_manjaro)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 0, ".miso", "/.miso", &p);
	CHECK(img_report.disable_iso == TRUE);
	teardown();
}

/* Root-level: md5sum.txt sets has_md5sum = 1 */
TEST(scan_root_md5sum)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 512, "md5sum.txt", "/md5sum.txt", &p);
	CHECK(img_report.has_md5sum == 1);
	teardown();
}

/* Root-level: MD5SUMS sets has_md5sum = 2 */
TEST(scan_root_MD5SUMS)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 512, "MD5SUMS", "/MD5SUMS", &p);
	CHECK(img_report.has_md5sum == 2);
	teardown();
}

/* ReactOS detection */
TEST(scan_reactos)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/loader", 65536, "setupldr.sys", "/loader/setupldr.sys", &p);
	CHECK(img_report.reactos_path[0] != '\0');
	CHECK(strcmp(img_report.reactos_path, "/loader/setupldr.sys") == 0);
	teardown();
}

/* efi*.img path */
TEST(scan_efi_img)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/boot", 1024*1024, "efiboot.img", "/boot/efiboot.img", &p);
	CHECK(HAS_EFI_IMG(img_report));
	CHECK(strcmp(img_report.efi_img_path, "/boot/efiboot.img") == 0);
	teardown();
}

/* Short bootx64.efi in /efi/boot triggers broken-link logic */
TEST(scan_tiny_bootx64)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/efi/boot", 128, "bootx64.efi", "/efi/boot/bootx64.efi", &p);
	CHECK(img_report.has_efi & 0x4000);
	CHECK(strcmp(img_report.efi_img_path, "[BOOT]/1-Boot-NoEmul.img") == 0);
	teardown();
}

/* EFI boot entry: boot.efi → has_efi bit 2, type 0 */
TEST(scan_efi_boot_entry)
{
	reset();
	EXTRACT_PROPS p;
	/* "boot" + "" + ".efi" = "boot.efi" (archname[0] == "") */
	check_iso_props("/efi/boot", 65536, "boot.efi", "/efi/boot/boot.efi", &p);
	CHECK(img_report.has_efi & (uint16_t)(2 << 0)); /* i=0 → bit 1 */
	CHECK(img_report.efi_boot_entry[0].type == 0);
	teardown();
}

/* Windows installer sources/ detection */
TEST(scan_wininst_path)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/sources", 1024*1024*1024LL, "install.wim",
	                "/sources/install.wim", &p);
	CHECK(img_report.wininst_index == 1);
	/* On Linux the path is stored as-is; on Windows it has a "?:" prefix */
#ifdef _WIN32
	CHECK(strcmp(img_report.wininst_path[0], "?:/sources/install.wim") == 0);
#else
	CHECK(strcmp(img_report.wininst_path[0], "/sources/install.wim") == 0);
#endif
	teardown();
}

/* File >= 4 GB sets has_4GB_file wininst bit */
TEST(scan_wininst_4gb)
{
	reset();
	EXTRACT_PROPS p;
	int64_t big = (int64_t)4 * 1024 * 1024 * 1024LL + 1;
	check_iso_props("/sources", big, "install.wim", "/sources/install.wim", &p);
	CHECK(img_report.wininst_index == 1);
	CHECK(img_report.has_4GB_file & 0x10u);
	teardown();
}

/* Panther unattend detection */
TEST(scan_panther_unattend)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/sources/$OEM$/$$/Panther", 512, "unattend.xml",
	                "/sources/$OEM$/$$/Panther/unattend.xml", &p);
	CHECK(img_report.has_panther_unattend == TRUE);
	teardown();
}

/* WinPE /i386/ntdetect.com → winpe bit 0 */
TEST(scan_winpe_ntdetect)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("/i386", 4096, "ntdetect.com", "/i386/ntdetect.com", &p);
	/* pe_file[0] in pe_dirname[0]: bit = (1<<0)<<(3*0) = 1 */
	CHECK(img_report.winpe & 1u);
	teardown();
}

/* isolinux.bin added to isolinux_path */
TEST(scan_isolinux_bin)
{
	reset();
	EXTRACT_PROPS p;
	check_iso_props("", 32768, "isolinux.bin", "/isolinux.bin", &p);
	CHECK(isolinux_path.Index == 1);
	CHECK(strcmp(isolinux_path.String[0], "/isolinux.bin") == 0);
	teardown();
}

/* total_blocks accumulation */
TEST(scan_total_blocks)
{
	reset();
	total_blocks = 0;
	EXTRACT_PROPS p;
	/* file_length = 4096 = 2 * ISO_BLOCKSIZE → adds 2 blocks */
	check_iso_props("/data", 4096, "file.dat", "/data/file.dat", &p);
	CHECK(total_blocks == 2);
	teardown();
}

/* Non-zero file_length < ISO_BLOCKSIZE → 1 block */
TEST(scan_total_blocks_small_file)
{
	reset();
	total_blocks = 0;
	EXTRACT_PROPS p;
	check_iso_props("/data", 1, "tiny.dat", "/data/tiny.dat", &p);
	CHECK(total_blocks == 1);
	teardown();
}

/* Zero-length file adds nothing to total_blocks */
TEST(scan_total_blocks_zero_file)
{
	reset();
	total_blocks = 0;
	EXTRACT_PROPS p;
	check_iso_props("", 0, "empty", "/empty", &p);
	CHECK(total_blocks == 0);
	teardown();
}

/* ================================================================
 * Write-time (scan_only == FALSE) tests
 * ================================================================ */

/* ldlinux.sys at root returns TRUE (skip) at write time */
TEST(write_ldlinux_sys_skip)
{
	reset();
	scan_only = FALSE;
	EXTRACT_PROPS p;
	BOOL r = check_iso_props("", 65536, "ldlinux.sys", "/ldlinux.sys", &p);
	CHECK(r == TRUE);
	teardown();
}

/* ldlinux.sys NOT at root is not skipped */
TEST(write_ldlinux_sys_not_root)
{
	reset();
	scan_only = FALSE;
	EXTRACT_PROPS p;
	BOOL r = check_iso_props("/boot", 65536, "ldlinux.sys", "/boot/ldlinux.sys", &p);
	CHECK(r == FALSE);
	teardown();
}

/* .cfg extension sets is_cfg at write time */
TEST(write_cfg_extension)
{
	reset();
	scan_only = FALSE;
	EXTRACT_PROPS p;
	BOOL r = check_iso_props("/some/dir", 512, "custom.cfg", "/some/dir/custom.cfg", &p);
	CHECK(r == FALSE);
	CHECK(p.is_cfg == TRUE);
	teardown();
}

/* grub.cfg sets is_grub_cfg */
TEST(write_grub_cfg)
{
	reset();
	scan_only = FALSE;
	EXTRACT_PROPS p;
	BOOL r = check_iso_props("/boot/grub", 1024, "grub.cfg", "/boot/grub/grub.cfg", &p);
	CHECK(r == FALSE);
	CHECK(p.is_grub_cfg == TRUE);
	teardown();
}

/* menu.cfg sets is_menu_cfg */
TEST(write_menu_cfg)
{
	reset();
	scan_only = FALSE;
	EXTRACT_PROPS p;
	BOOL r = check_iso_props("/boot", 512, "menu.cfg", "/boot/menu.cfg", &p);
	CHECK(r == FALSE);
	CHECK(p.is_menu_cfg == TRUE);
	teardown();
}

/* Normal file at write time returns FALSE */
TEST(write_normal_file)
{
	reset();
	scan_only = FALSE;
	EXTRACT_PROPS p;
	BOOL r = check_iso_props("/data", 1024, "readme.txt", "/data/readme.txt", &p);
	CHECK(r == FALSE);
	teardown();
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void)
{
	/* scan-only tests */
	RUN(scan_syslinux_cfg_isolinux);
	RUN(scan_syslinux_cfg_syslinux);
	RUN(scan_syslinux_cfg_extlinux);
	RUN(scan_syslinux_cfg_txt_cfg);
	RUN(scan_efi_syslinux);
	RUN(scan_loader_entries_conf);
	RUN(scan_loader_entries_non_conf);
	RUN(scan_grub2_boot_dir);
	RUN(scan_grub2_boot2_dir);
	RUN(scan_ldlinux_c32);
	RUN(scan_casper);
	RUN(scan_pop_os);
	RUN(scan_proxmox);
	RUN(scan_root_bootmgr);
	RUN(scan_root_bootmgr_efi);
	RUN(scan_root_grldr);
	RUN(scan_root_kolibri);
	RUN(scan_root_manjaro);
	RUN(scan_root_md5sum);
	RUN(scan_root_MD5SUMS);
	RUN(scan_reactos);
	RUN(scan_efi_img);
	RUN(scan_tiny_bootx64);
	RUN(scan_efi_boot_entry);
	RUN(scan_wininst_path);
	RUN(scan_wininst_4gb);
	RUN(scan_panther_unattend);
	RUN(scan_winpe_ntdetect);
	RUN(scan_isolinux_bin);
	RUN(scan_total_blocks);
	RUN(scan_total_blocks_small_file);
	RUN(scan_total_blocks_zero_file);
	/* write-time tests */
	RUN(write_ldlinux_sys_skip);
	RUN(write_ldlinux_sys_not_root);
	RUN(write_cfg_extension);
	RUN(write_grub_cfg);
	RUN(write_menu_cfg);
	RUN(write_normal_file);

	TEST_RESULTS();
	return _fail > 0 ? 1 : 0;
}
