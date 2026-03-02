/*
 * test_combo_logic_linux.c — Tests for SetFSFromISO and
 * SetPartitionSchemeAndTargetSystem (ui_combo_logic.c).
 *
 * These functions smarten up the Partition Scheme / Target System / File
 * System combos based on the currently scanned image report and the selected
 * boot type.  All tests run without GTK: they use the combo_bridge in its
 * GTK-free mode.
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "framework.h"

#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/windowsx.h"    /* ComboBox_GetCurSel */
#include "../src/linux/compat/winioctl.h"    /* PARTITION_STYLE_MBR/GPT/RAW */
#include "../src/linux/compat/msg_dispatch.h"
#include "../src/windows/rufus.h"
#include "../src/windows/drive.h"            /* RUFUS_DRIVE_INFO */
#include "../src/linux/combo_bridge.h"
#include "../src/linux/ui_combo_logic.h"

#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Globals referenced by ui_combo_logic.c that must be provided by the test.
 * In the real binary these live in globals.c / ui_gtk.c.
 * --------------------------------------------------------------------- */
HWND hDeviceList      = NULL;
HWND hPartitionScheme = NULL;
HWND hTargetSystem    = NULL;
HWND hFileSystem      = NULL;
HWND hBootType        = NULL;
HWND hImageOption     = NULL;
HWND hClusterSize     = NULL;
HWND hLabel           = NULL;

/* Globals referenced by the logic */
int   boot_type     = BT_IMAGE;
int   partition_type = PARTITION_STYLE_MBR;
int   target_type   = TT_BIOS;
int   fs_type       = FS_FAT32;
BOOL  allow_dual_uefi_bios = FALSE;
BOOL  has_uefi_csm  = FALSE;
char *image_path    = NULL;
RUFUS_IMG_REPORT img_report;
RUFUS_DRIVE_INFO SelectedDrive;
const char *sfd_name = "Large-Flash (SFD)";

/* Additional globals referenced by SetPartitionSchemeAndTargetSystem */
uint8_t image_options = IMOP_WINTOGO;

/* FileSystemLabel — defined in globals.c in the real build */
const char *FileSystemLabel[FS_MAX] = {
	"FAT", "FAT32", "NTFS", "UDF", "exFAT", "ReFS", "ext2", "ext3", "ext4"
};

/* stubs for things combo_logic.c may call */
void SetComboEntry(HWND hDlg, int data)
{
	combo_state_t *cs = (combo_state_t *)hDlg;
	if (!cs) return;
	/* Find the item whose data matches `data` and select it */
	for (int i = 0; i < cs->count; i++) {
		if ((int)(intptr_t)cs->data[i] == data) {
			cs->cur_sel = i;
			return;
		}
	}
	/* If not found, select first item */
	if (cs->count > 0)
		cs->cur_sel = 0;
}

/* needed by populate_fs_combo path */
int access(const char *path, int mode);   /* real libc, just declare */

/* -------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

/* Create a combo state registered with msg_dispatch, assign to *out_hwnd */
static combo_state_t *make_combo(HWND *out_hwnd)
{
	combo_state_t *cs = combo_state_alloc(NULL);
	msg_dispatch_register((HWND)cs, combo_msg_handler);
	if (out_hwnd)
		*out_hwnd = (HWND)cs;
	return cs;
}

static void free_combo(combo_state_t *cs, HWND *out_hwnd)
{
	if (!cs) return;
	msg_dispatch_unregister((HWND)cs);
	combo_state_free(cs);
	if (out_hwnd)
		*out_hwnd = NULL;
}

/* Return the integer item-data value at combo position idx */
static int combo_data_at(HWND h, int idx)
{
	return (int)(intptr_t)ComboBox_GetItemData(h, idx);
}

/* Setup helper: pre-populate FS combo with FAT32, NTFS, ext4 */
static void setup_fs_combo(void)
{
	ComboBox_ResetContent(hFileSystem);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "FAT32"), FS_FAT32);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "NTFS"),  FS_NTFS);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "ext4"),  FS_EXT4);
	ComboBox_SetCurSel(hFileSystem, 0);
	fs_type = FS_FAT32;
}
static int combo_cur_data(HWND h)
{
	int sel = ComboBox_GetCurSel(h);
	if (sel < 0) return -9999;
	return combo_data_at(h, sel);
}

/* Return whether any item in the combo has the given data value */
static BOOL combo_has_data(HWND h, int data)
{
	int n = ComboBox_GetCount(h);
	for (int i = 0; i < n; i++) {
		if (combo_data_at(h, i) == data)
			return TRUE;
	}
	return FALSE;
}

/* Reset img_report and image_path to "no image" state */
static void clear_image(void)
{
	free(image_path);
	image_path = NULL;
	memset(&img_report, 0, sizeof(img_report));
	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
}

/* Set up a minimal device in the device combo so SetPartitionScheme...
 * doesn't bail out early on "no device selected". */
static combo_state_t *cs_device;
static combo_state_t *cs_pt;
static combo_state_t *cs_ts;
static combo_state_t *cs_fs;
static combo_state_t *cs_bt;
static combo_state_t *cs_imgopt;

static void setup_combos(void)
{
	msg_dispatch_init();

	cs_device  = make_combo(&hDeviceList);
	cs_pt      = make_combo(&hPartitionScheme);
	cs_ts      = make_combo(&hTargetSystem);
	cs_fs      = make_combo(&hFileSystem);
	cs_bt      = make_combo(&hBootType);
	cs_imgopt  = make_combo(&hImageOption);

	/* Add a fake device so the device list is not empty */
	ComboBox_AddString(hDeviceList, "USB Drive (fake)");
	ComboBox_SetItemData(hDeviceList, 0, (DWORD_PTR)0);
	ComboBox_SetCurSel(hDeviceList, 0);

	/* Add boot types */
	ComboBox_SetItemData(hBootType, ComboBox_AddString(hBootType, "Non-bootable"), BT_NON_BOOTABLE);
	ComboBox_SetItemData(hBootType, ComboBox_AddString(hBootType, "ISO Image"), BT_IMAGE);
	ComboBox_SetItemData(hBootType, ComboBox_AddString(hBootType, "FreeDOS"), BT_FREEDOS);
}

static void teardown_combos(void)
{
	free_combo(cs_device, &hDeviceList);
	free_combo(cs_pt, &hPartitionScheme);
	free_combo(cs_ts, &hTargetSystem);
	free_combo(cs_fs, &hFileSystem);
	free_combo(cs_bt, &hBootType);
	free_combo(cs_imgopt, &hImageOption);
	clear_image();
	boot_type = BT_IMAGE;
	allow_dual_uefi_bios = FALSE;
}

/* =========================================================================
 * SetPartitionSchemeAndTargetSystem tests
 * ======================================================================= */

/*
 * BT_NON_BOOTABLE: partition scheme combo must contain SFD; target system
 * combo must contain the "BIOS+UEFI" dual entry and nothing BIOS-only.
 */
TEST(non_bootable_allows_sfd)
{
	setup_combos();
	boot_type = BT_NON_BOOTABLE;
	clear_image();

	SetPartitionSchemeAndTargetSystem(FALSE);

	CHECK(combo_has_data(hPartitionScheme, PARTITION_STYLE_MBR));
	CHECK(combo_has_data(hPartitionScheme, PARTITION_STYLE_GPT));
	/* SFD entry must appear for non-bootable */
	CHECK(combo_has_data(hPartitionScheme, PARTITION_STYLE_SFD));

	/* Non-bootable: BIOS+UEFI (TT_BIOS) must be present, but no UEFI-only */
	CHECK(!combo_has_data(hTargetSystem, TT_UEFI));

	teardown_combos();
}

/*
 * BT_IMAGE + BIOS-only image (no EFI): GPT must be disabled, UEFI target
 * must not be shown.
 */
TEST(image_bios_only_disables_gpt_and_uefi)
{
	setup_combos();
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/fake.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso = TRUE;
	/* No EFI, has BIOS bootable syslinux */
	img_report.sl_version = (5 << 8) | 1;   /* SL 5.1 */

	SetPartitionSchemeAndTargetSystem(FALSE);

	/* GPT must NOT appear for BIOS-only images */
	CHECK(!combo_has_data(hPartitionScheme, PARTITION_STYLE_GPT));
	CHECK(combo_has_data(hPartitionScheme, PARTITION_STYLE_MBR));

	/* UEFI target must NOT appear */
	CHECK(!combo_has_data(hTargetSystem, TT_UEFI));
	CHECK(combo_has_data(hTargetSystem, TT_BIOS));

	teardown_combos();
}

/*
 * BT_IMAGE + EFI-only image: BIOS target must not appear.
 */
TEST(image_efi_only_disables_bios_target)
{
	setup_combos();
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/fake.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso = TRUE;
	/* EFI-only (no BIOS syslinux/bootmgr) */
	img_report.has_efi = 0x2;   /* x86_64 EFI bit set */

	SetPartitionSchemeAndTargetSystem(FALSE);

	/* BIOS target must NOT appear (image is EFI-only) */
	CHECK(!combo_has_data(hTargetSystem, TT_BIOS));
	CHECK(combo_has_data(hTargetSystem, TT_UEFI));

	teardown_combos();
}

/*
 * BT_IMAGE + BIOS+EFI dual-boot image (non-Windows): both targets must appear.
 */
TEST(image_dual_boot_allows_both_targets)
{
	setup_combos();
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/ubuntu.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso = TRUE;
	/* EFI + BIOS (syslinux) dual-boot Linux ISO */
	img_report.has_efi = 0x2;
	img_report.sl_version = (5 << 8) | 1;  /* Syslinux 5.1 */

	SetPartitionSchemeAndTargetSystem(FALSE);

	/* Both BIOS and UEFI should be available */
	CHECK(combo_has_data(hTargetSystem, TT_BIOS));
	CHECK(combo_has_data(hTargetSystem, TT_UEFI));

	teardown_combos();
}

/*
 * BT_FREEDOS: GPT must be disabled, UEFI target must not appear.
 */
TEST(freedos_forces_mbr_and_bios)
{
	setup_combos();
	boot_type = BT_FREEDOS;
	clear_image();

	SetPartitionSchemeAndTargetSystem(FALSE);

	CHECK(!combo_has_data(hPartitionScheme, PARTITION_STYLE_GPT));
	CHECK(combo_has_data(hPartitionScheme, PARTITION_STYLE_MBR));
	CHECK(!combo_has_data(hTargetSystem, TT_UEFI));
	CHECK(combo_has_data(hTargetSystem, TT_BIOS));

	teardown_combos();
}

/*
 * BT_SYSLINUX_V4: same restrictions as FreeDOS.
 */
TEST(syslinux_v4_forces_mbr_and_bios)
{
	setup_combos();
	boot_type = BT_SYSLINUX_V4;
	clear_image();

	SetPartitionSchemeAndTargetSystem(FALSE);

	CHECK(!combo_has_data(hPartitionScheme, PARTITION_STYLE_GPT));
	CHECK(combo_has_data(hPartitionScheme, PARTITION_STYLE_MBR));
	CHECK(!combo_has_data(hTargetSystem, TT_UEFI));

	teardown_combos();
}

/*
 * BT_UEFI_NTFS: BIOS target must not appear.
 */
TEST(uefi_ntfs_disables_bios_target)
{
	setup_combos();
	boot_type = BT_UEFI_NTFS;
	clear_image();

	SetPartitionSchemeAndTargetSystem(FALSE);

	CHECK(!combo_has_data(hTargetSystem, TT_BIOS));
	CHECK(combo_has_data(hTargetSystem, TT_UEFI));

	teardown_combos();
}

/*
 * BT_IMAGE with no device selected: combos must remain empty.
 */
TEST(no_device_leaves_combos_empty)
{
	setup_combos();
	/* Remove the fake device */
	ComboBox_ResetContent(hDeviceList);
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/fake.iso");

	SetPartitionSchemeAndTargetSystem(FALSE);

	/* With no device, nothing should be added */
	CHECK_INT_EQ(ComboBox_GetCount(hPartitionScheme), 0);
	CHECK_INT_EQ(ComboBox_GetCount(hTargetSystem), 0);

	teardown_combos();
}

/*
 * only_target=TRUE: partition scheme combo must NOT be touched.
 */
TEST(only_target_leaves_partition_unchanged)
{
	setup_combos();
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/ubuntu.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso = TRUE;
	img_report.has_efi = 0x2;

	/* Populate partition scheme with a known entry first */
	ComboBox_SetItemData(hPartitionScheme,
	    ComboBox_AddString(hPartitionScheme, "MBR"), PARTITION_STYLE_MBR);
	ComboBox_SetCurSel(hPartitionScheme, 0);
	int pt_count_before = ComboBox_GetCount(hPartitionScheme);

	SetPartitionSchemeAndTargetSystem(TRUE);   /* only_target = TRUE */

	/* Partition scheme count must not change */
	CHECK_INT_EQ(ComboBox_GetCount(hPartitionScheme), pt_count_before);

	teardown_combos();
}

/*
 * BT_IMAGE + Windows ISO (has_bootmgr + has_efi): GPT + UEFI should be
 * the preferred/default choices.
 */
TEST(windows_iso_prefers_gpt_uefi)
{
	setup_combos();
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/windows11.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso = TRUE;
	img_report.has_bootmgr = TRUE;
	img_report.has_efi     = 0x2;   /* UEFI bootable */

	SetPartitionSchemeAndTargetSystem(FALSE);

	/* Both MBR and GPT must be available */
	CHECK(combo_has_data(hPartitionScheme, PARTITION_STYLE_MBR));
	CHECK(combo_has_data(hPartitionScheme, PARTITION_STYLE_GPT));

	/* The default selection must be GPT (since has_efi && !allow_dual_uefi_bios) */
	CHECK_INT_EQ(combo_cur_data(hPartitionScheme), PARTITION_STYLE_GPT);

	/* UEFI must be the selected target */
	CHECK_INT_EQ(combo_cur_data(hTargetSystem), TT_UEFI);

	teardown_combos();
}

/*
 * Grub2 boot type: same restrictions as syslinux/freedos
 * (MBR only, BIOS only).
 */
TEST(grub2_forces_mbr_and_bios)
{
	setup_combos();
	boot_type = BT_GRUB2;
	clear_image();

	SetPartitionSchemeAndTargetSystem(FALSE);

	CHECK(!combo_has_data(hPartitionScheme, PARTITION_STYLE_GPT));
	CHECK(combo_has_data(hPartitionScheme, PARTITION_STYLE_MBR));
	CHECK(!combo_has_data(hTargetSystem, TT_UEFI));

	teardown_combos();
}

/* =========================================================================
 * SetFSFromISO tests
 * ======================================================================= */

/*
 * No image path → SetFSFromISO should return immediately without changing
 * the combo selection.
 */
TEST(set_fs_no_image_noop)
{
	setup_combos();
	boot_type  = BT_IMAGE;
	clear_image();   /* image_path = NULL */

	/* Pre-populate FS combo with FAT32 and NTFS */
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "FAT32"),  FS_FAT32);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "NTFS"),   FS_NTFS);
	ComboBox_SetCurSel(hFileSystem, 1);   /* select NTFS */

	SetFSFromISO();

	/* Selection must not have changed from NTFS */
	CHECK_INT_EQ(combo_cur_data(hFileSystem), FS_NTFS);

	teardown_combos();
}

/*
 * Syslinux image (no 4 GB file, BIOS bootable): FAT32 must be preferred.
 */
TEST(set_fs_syslinux_prefers_fat32)
{
	setup_combos();
	setup_fs_combo();
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/linux.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso      = TRUE;
	img_report.sl_version  = (5 << 8) | 1;  /* Syslinux 5.1 */
	img_report.has_efi     = 0x2;
	/* No 4 GB file */

	SetFSFromISO();

	CHECK_INT_EQ(combo_cur_data(hFileSystem), FS_FAT32);

	teardown_combos();
}

/*
 * Windows ISO (has_bootmgr, no 4 GB file, UEFI): FAT32 must be preferred
 * when allow_dual_uefi_bios is TRUE (Windows install on MBR/BIOS).
 */
TEST(set_fs_windows_dual_bios_uefi_prefers_fat32)
{
	setup_combos();
	setup_fs_combo();
	boot_type             = BT_IMAGE;
	image_path            = strdup("/tmp/win.iso");
	allow_dual_uefi_bios  = TRUE;
	target_type           = TT_UEFI;
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso       = TRUE;
	img_report.has_bootmgr  = TRUE;
	img_report.has_efi      = 0x2;
	/* No 4 GB file */

	SetFSFromISO();

	/* With dual BIOS+UEFI and no 4 GB file, FAT32 is preferred */
	CHECK_INT_EQ(combo_cur_data(hFileSystem), FS_FAT32);

	allow_dual_uefi_bios = FALSE;
	teardown_combos();
}

/*
 * Windows ISO (has_bootmgr, HAS 4 GB file, UEFI target): NTFS is preferred.
 * The 4GB file blocks the EFI-prefers-FAT32 path; bootmgr falls back to NTFS.
 */
TEST(set_fs_windows_standard_prefers_ntfs)
{
	setup_combos();
	boot_type             = BT_IMAGE;
	image_path            = strdup("/tmp/win.iso");
	allow_dual_uefi_bios  = FALSE;
	target_type           = TT_UEFI;
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso        = TRUE;
	img_report.has_bootmgr   = TRUE;
	img_report.has_efi       = 0x2;
	img_report.has_4GB_file  = TRUE;   /* Windows 11-style: install.wim > 4 GB */

	/* Populate combo with FAT32 + NTFS */
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "FAT32"), FS_FAT32);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "NTFS"),  FS_NTFS);
	ComboBox_SetCurSel(hFileSystem, 0);

	SetFSFromISO();

	/* NTFS should be selected (4GB file blocks FAT32 on EFI path; bootmgr selects NTFS) */
	CHECK_INT_EQ(combo_cur_data(hFileSystem), FS_NTFS);

	teardown_combos();
}

/*
 * EFI-only image (no BIOS bootable, UEFI target, no 4 GB file): FAT32.
 */
TEST(set_fs_efi_only_uefi_target_prefers_fat32)
{
	setup_combos();
	setup_fs_combo();
	boot_type   = BT_IMAGE;
	image_path  = strdup("/tmp/arch.iso");
	target_type = TT_UEFI;
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso  = TRUE;
	img_report.has_efi = 0x2;
	/* No syslinux / bootmgr / winpe / grub */

	SetFSFromISO();

	CHECK_INT_EQ(combo_cur_data(hFileSystem), FS_FAT32);

	teardown_combos();
}

/*
 * Windows ISO with a 4 GB file: FAT32 must NOT be selected even for UEFI;
 * NTFS should be chosen instead via the bootmgr fallback.
 */
TEST(set_fs_4gb_file_blocks_fat32)
{
	setup_combos();
	boot_type   = BT_IMAGE;
	image_path  = strdup("/tmp/big_windows.iso");
	target_type = TT_UEFI;
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso       = TRUE;
	img_report.has_bootmgr  = TRUE;   /* Windows image */
	img_report.has_efi      = 0x2;
	img_report.has_4GB_file = TRUE;

	/* Populate combo with FAT32 + NTFS */
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "FAT32"), FS_FAT32);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "NTFS"),  FS_NTFS);
	ComboBox_SetCurSel(hFileSystem, 0);

	SetFSFromISO();

	/* With a 4 GB file, FAT32 is blocked; NTFS must be selected */
	int cur = combo_cur_data(hFileSystem);
	CHECK(cur != FS_FAT32);
	CHECK_INT_EQ(cur, FS_NTFS);

	teardown_combos();
}

/* =========================================================================
 * Round-trip / integration tests
 * ======================================================================= */

/*
 * Switching from a Windows ISO to a Linux ISO should update the FS
 * preference accordingly.
 */
TEST(roundtrip_windows_then_linux_iso)
{
	setup_combos();
	boot_type = BT_IMAGE;

	/* --- Phase 1: Windows ISO (Win11 style, has 4GB file → NTFS) --- */
	image_path = strdup("/tmp/win11.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso       = TRUE;
	img_report.has_bootmgr  = TRUE;
	img_report.has_efi      = 0x2;
	img_report.has_4GB_file = TRUE;   /* install.wim > 4 GB blocks FAT32 */

	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "FAT32"), FS_FAT32);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "NTFS"),  FS_NTFS);
	ComboBox_SetCurSel(hFileSystem, 0);

	SetFSFromISO();
	int win_fs = combo_cur_data(hFileSystem);
	CHECK_INT_EQ(win_fs, FS_NTFS);

	/* --- Phase 2: Linux ISO (syslinux + EFI) --- */
	free(image_path);
	image_path = strdup("/tmp/debian.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso     = TRUE;
	img_report.sl_version = (5 << 8) | 1;
	img_report.has_efi    = 0x2;

	SetFSFromISO();
	int linux_fs = combo_cur_data(hFileSystem);
	CHECK_INT_EQ(linux_fs, FS_FAT32);

	teardown_combos();
}

/*
 * SetPartitionSchemeAndTargetSystem + SetFSFromISO called in the same order
 * as UM_IMAGE_SCANNED handler: results should be internally consistent.
 */
TEST(image_scanned_handler_order)
{
	setup_combos();
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/ubuntu.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso     = TRUE;
	img_report.sl_version = (5 << 8) | 1;  /* Syslinux 5.1 */
	img_report.has_efi    = 0x2;

	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "FAT32"), FS_FAT32);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "NTFS"),  FS_NTFS);

	/* This is the order used in UM_IMAGE_SCANNED */
	SetFSFromISO();
	SetPartitionSchemeAndTargetSystem(FALSE);

	/* A dual-boot Linux ISO should allow both targets */
	CHECK(combo_has_data(hTargetSystem, TT_BIOS));
	CHECK(combo_has_data(hTargetSystem, TT_UEFI));

	/* FAT32 should be selected for syslinux */
	CHECK_INT_EQ(combo_cur_data(hFileSystem), FS_FAT32);

	teardown_combos();
}

/* =========================================================================
 * set_preselected_fs tests
 * ======================================================================= */

/*
 * After set_preselected_fs(FS_NTFS), SetFSFromISO should prefer NTFS even for
 * a Syslinux image that would normally prefer FAT32.
 */
TEST(preselected_fs_overrides_syslinux_default)
{
	setup_combos();
	setup_fs_combo();
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/linux.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso     = TRUE;
	img_report.sl_version = (5 << 8) | 1;   /* Syslinux 5.1 */
	img_report.has_efi    = 0x2;

	set_preselected_fs(FS_NTFS);
	SetFSFromISO();

	/* User-requested NTFS must win */
	CHECK_INT_EQ(combo_cur_data(hFileSystem), FS_NTFS);

	/* Reset for subsequent tests */
	set_preselected_fs(FS_UNKNOWN);
	teardown_combos();
}

/*
 * set_preselected_fs(FS_UNKNOWN) reverts to automatic selection so that the
 * next call uses normal image-based heuristics.
 */
TEST(preselected_fs_unknown_reverts_to_auto)
{
	setup_combos();
	setup_fs_combo();
	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/linux.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso     = TRUE;
	img_report.sl_version = (5 << 8) | 1;   /* Syslinux 5.1 */
	img_report.has_efi    = 0x2;

	/* Set then immediately clear the preselection */
	set_preselected_fs(FS_NTFS);
	set_preselected_fs(FS_UNKNOWN);
	SetFSFromISO();

	/* Without a preselection, Syslinux heuristic should win → FAT32 */
	CHECK_INT_EQ(combo_cur_data(hFileSystem), FS_FAT32);

	teardown_combos();
}

/*
 * Preselected FS must be honoured only when that FS is actually present in
 * the combo.  If the FS is absent, automatic selection falls through as
 * normal.
 */
TEST(preselected_fs_absent_from_combo_falls_through)
{
	setup_combos();
	/* Only FAT32 and NTFS in combo — no ext4 */
	ComboBox_ResetContent(hFileSystem);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "FAT32"), FS_FAT32);
	ComboBox_SetItemData(hFileSystem, ComboBox_AddString(hFileSystem, "NTFS"),  FS_NTFS);
	ComboBox_SetCurSel(hFileSystem, 0);
	fs_type = FS_FAT32;

	boot_type  = BT_IMAGE;
	image_path = strdup("/tmp/linux.iso");
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_iso     = TRUE;
	img_report.sl_version = (5 << 8) | 1;

	/* ext4 is not in the combo; preselection should be ignored */
	set_preselected_fs(FS_EXT4);
	SetFSFromISO();

	/* Syslinux heuristic: FAT32 */
	CHECK_INT_EQ(combo_cur_data(hFileSystem), FS_FAT32);

	set_preselected_fs(FS_UNKNOWN);
	teardown_combos();
}

/* =========================================================================
 * main
 * ======================================================================= */
int main(void)
{
	printf("=== combo_logic tests ===\n");

	RUN(non_bootable_allows_sfd);
	RUN(image_bios_only_disables_gpt_and_uefi);
	RUN(image_efi_only_disables_bios_target);
	RUN(image_dual_boot_allows_both_targets);
	RUN(freedos_forces_mbr_and_bios);
	RUN(syslinux_v4_forces_mbr_and_bios);
	RUN(uefi_ntfs_disables_bios_target);
	RUN(no_device_leaves_combos_empty);
	RUN(only_target_leaves_partition_unchanged);
	RUN(windows_iso_prefers_gpt_uefi);
	RUN(grub2_forces_mbr_and_bios);
	RUN(set_fs_no_image_noop);
	RUN(set_fs_syslinux_prefers_fat32);
	RUN(set_fs_windows_dual_bios_uefi_prefers_fat32);
	RUN(set_fs_windows_standard_prefers_ntfs);
	RUN(set_fs_efi_only_uefi_target_prefers_fat32);
	RUN(set_fs_4gb_file_blocks_fat32);
	RUN(roundtrip_windows_then_linux_iso);
	RUN(image_scanned_handler_order);
	RUN(preselected_fs_overrides_syslinux_default);
	RUN(preselected_fs_unknown_reverts_to_auto);
	RUN(preselected_fs_absent_from_combo_falls_through);

	TEST_RESULTS();
	return (_fail > 0) ? 1 : 0;
}
