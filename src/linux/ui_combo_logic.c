/*
 * ui_combo_logic.c — Smart combo-box population for Partition Scheme,
 * Target System, and File System dropdowns.
 *
 * This file has no GTK dependency: it uses only the combo_bridge message
 * API (CB_* messages via SendMessageA) so it can be unit-tested without
 * a display.
 *
 * Ported from the Windows rufus.c SetFSFromISO / SetPartitionSchemeAnd-
 * TargetSystem implementation (Copyright © Pete Batard 2011-2024).
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <unistd.h>   /* access() */

#include "compat/windows.h"
#include "compat/windowsx.h"   /* ComboBox_GetCurSel */
#include "compat/winioctl.h"   /* PARTITION_STYLE_MBR/GPT/RAW */
#include "../windows/rufus.h"
#include "../windows/drive.h"  /* RUFUS_DRIVE_INFO */
#include "ui_combo_logic.h"

/* -------------------------------------------------------------------------
 * Externally-defined globals (globals.c / ui_gtk.c)
 * --------------------------------------------------------------------- */
extern HWND hDeviceList;
extern HWND hPartitionScheme;
extern HWND hTargetSystem;
extern HWND hFileSystem;
extern HWND hBootType;
extern HWND hImageOption;
extern HWND hClusterSize;

extern int   boot_type;
extern int   partition_type;
extern int   target_type;
extern int   fs_type;
extern BOOL  allow_dual_uefi_bios;
extern BOOL  has_uefi_csm;
extern char *image_path;
extern RUFUS_IMG_REPORT img_report;
extern RUFUS_DRIVE_INFO SelectedDrive;
extern const char *sfd_name;
extern uint8_t image_options;
extern const char *FileSystemLabel[FS_MAX];

/* Scan-local preferred selection state (mirrors Windows static locals) */
static int selected_pt  = -1;   /* user-overridden partition type, -1 = auto */
static int selected_fs  = FS_UNKNOWN;
static int preselected_fs = FS_UNKNOWN;

/*
 * set_preselected_fs  —  record a filesystem requested on the command line.
 * Pass FS_UNKNOWN (-1) to clear the preselection and restore automatic choice.
 * SetFSFromISO() will honour this value when the corresponding FS entry is
 * present in hFileSystem.
 */
void set_preselected_fs(int fs)
{
	preselected_fs = fs;
}

void set_user_selected_fs(int fs)
{
	selected_fs = (fs > 0) ? fs : FS_UNKNOWN;
}


/* -------------------------------------------------------------------------
 * populate_fs_combo
 *
 * Fills hFileSystem with all filesystems available on this machine.
 * FAT32 is always present; NTFS/exFAT/UDF are conditional on tool presence.
 * ext2/3/4 are always offered (kernel-supported).
 * Defaults the selection to FAT32.
 * --------------------------------------------------------------------- */
void populate_fs_combo(void)
{
	IGNORE_RETVAL(ComboBox_ResetContent(hFileSystem));

	/* FAT16 — only if mkfs.fat or mkdosfs is available */
	{
		static const char * const fat16_candidates[] = {
			"/sbin/mkfs.fat", "/usr/sbin/mkfs.fat", "/bin/mkfs.fat", "/usr/bin/mkfs.fat",
			"/usr/local/sbin/mkfs.fat", "/usr/local/bin/mkfs.fat",
			"/sbin/mkdosfs", "/usr/sbin/mkdosfs", NULL
		};
		for (int i = 0; fat16_candidates[i]; i++) {
			if (access(fat16_candidates[i], X_OK) == 0) {
				IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
				    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_FAT16]), FS_FAT16));
				break;
			}
		}
	}

	IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
	    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_FAT32]), FS_FAT32));

	/* NTFS — only if mkntfs is available */
	{
		static const char * const ntfs_candidates[] = {
			"/sbin/mkntfs", "/usr/sbin/mkntfs", "/bin/mkntfs", "/usr/bin/mkntfs",
			"/usr/local/sbin/mkntfs", "/usr/local/bin/mkntfs",
			"/sbin/mkfs.ntfs", "/usr/sbin/mkfs.ntfs", NULL
		};
		for (int i = 0; ntfs_candidates[i]; i++) {
			if (access(ntfs_candidates[i], X_OK) == 0) {
				IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
				    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_NTFS]), FS_NTFS));
				break;
			}
		}
	}

	/* exFAT — only if mkfs.exfat or mkexfatfs is available */
	{
		static const char * const exfat_candidates[] = {
			"/sbin/mkfs.exfat", "/usr/sbin/mkfs.exfat", "/bin/mkfs.exfat", "/usr/bin/mkfs.exfat",
			"/usr/local/sbin/mkfs.exfat", "/usr/local/bin/mkfs.exfat",
			"/sbin/mkexfatfs", "/usr/sbin/mkexfatfs", NULL
		};
		for (int i = 0; exfat_candidates[i]; i++) {
			if (access(exfat_candidates[i], X_OK) == 0) {
				IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
				    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_EXFAT]), FS_EXFAT));
				break;
			}
		}
	}

	/* UDF — only if mkudffs is available */
	{
		static const char * const udf_candidates[] = {
			"/sbin/mkudffs", "/usr/sbin/mkudffs", "/bin/mkudffs", "/usr/bin/mkudffs",
			"/usr/local/sbin/mkudffs", "/usr/local/bin/mkudffs", NULL
		};
		for (int i = 0; udf_candidates[i]; i++) {
			if (access(udf_candidates[i], X_OK) == 0) {
				IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
				    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_UDF]), FS_UDF));
				break;
			}
		}
	}

	IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
	    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_EXT2]), FS_EXT2));
	IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
	    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_EXT3]), FS_EXT3));
	IGNORE_RETVAL(ComboBox_SetItemData(hFileSystem,
	    ComboBox_AddString(hFileSystem, FileSystemLabel[FS_EXT4]), FS_EXT4));

	/* Default to FAT32 */
	IGNORE_RETVAL(ComboBox_SetCurSel(hFileSystem, 0));
	fs_type = FS_FAT32;

	populate_cluster_combo(FS_FAT32);
}

/* -------------------------------------------------------------------------
 * populate_cluster_combo
 *
 * Fills hClusterSize for the given filesystem.  For ext* and exFAT a
 * single "default" entry is offered.  For FAT32 and NTFS a full list of
 * standard cluster sizes is provided.
 * --------------------------------------------------------------------- */
void populate_cluster_combo(int fs)
{
	IGNORE_RETVAL(ComboBox_ResetContent(hClusterSize));

	if (IS_EXT(fs) || fs == FS_EXFAT) {
		IGNORE_RETVAL(ComboBox_SetItemData(hClusterSize,
		    ComboBox_AddString(hClusterSize, "4096 bytes (Default)"), 4096));
		IGNORE_RETVAL(ComboBox_SetCurSel(hClusterSize, 0));
		return;
	}

	static const struct { const char *label; DWORD size; } clusters[] = {
		{ "512 bytes",   512   },
		{ "1024 bytes",  1024  },
		{ "2048 bytes",  2048  },
		{ "4096 bytes",  4096  },
		{ "8192 bytes",  8192  },
		{ "16384 bytes", 16384 },
		{ "32768 bytes", 32768 },
		{ "65536 bytes", 65536 },
		{ NULL, 0 }
	};
	int def = 3; /* 4096 bytes default */
	for (int i = 0; clusters[i].label; i++) {
		IGNORE_RETVAL(ComboBox_SetItemData(hClusterSize,
		    ComboBox_AddString(hClusterSize, clusters[i].label), clusters[i].size));
	}
	IGNORE_RETVAL(ComboBox_SetCurSel(hClusterSize, def));
}

/* -------------------------------------------------------------------------
 * SetFSFromISO
 *
 * Selects the most appropriate filesystem from the *existing* hFileSystem
 * combo entries based on the current image report.  The FS combo must
 * already be populated (e.g. by populate_fs_combo) before this is called.
 * Returns immediately without change if image_path is NULL.
 *
 * Logic mirrors Windows rufus.c SetFSFromISO().
 * --------------------------------------------------------------------- */
void SetFSFromISO(void)
{
	int i, fs_tmp, preferred_fs = FS_UNKNOWN;
	uint32_t fs_mask;
	BOOL windows_to_go;

	if (image_path == NULL)
		return;

	windows_to_go = (image_options & IMOP_WINTOGO) && (boot_type == BT_IMAGE) &&
		HAS_WINTOGO(img_report) &&
		(ComboBox_GetCurItemData(hImageOption) == IMOP_WIN_TO_GO);

	/* Build a mask of all FSes currently in the combo */
	fs_mask = FS_NTFS | (img_report.has_4GB_file ? 0 : (1 << FS_FAT32));
	for (i = 0; i < ComboBox_GetCount(hFileSystem); i++) {
		fs_tmp = (int)ComboBox_GetItemData(hFileSystem, i);
		if (fs_tmp >= 0 && fs_tmp < FS_MAX)
			fs_mask |= 1 << fs_tmp;
	}

	/* If the user explicitly selected an FS in the GUI, honour it (highest priority) */
	if ((selected_fs > FS_UNKNOWN && selected_fs < FS_MAX) && (fs_mask & (1 << selected_fs))) {
		preferred_fs = selected_fs;
	}
	/* If a filesystem was preselected from the command line, honour it */
	else if ((preselected_fs >= 0 && preselected_fs < FS_MAX) && (fs_mask & (1 << preselected_fs))) {
		preferred_fs = preselected_fs;
	} else {
		/*
		 * Images that require NTFS (e.g. Mint LMDE — live→casper symlink) must
		 * use NTFS regardless of other image properties.  Mirrors Windows
		 * rufus.c IS_FAT32_COMPAT check (lines 193-209).
		 */
		if (img_report.needs_ntfs) {
			if (fs_mask & (1 << FS_NTFS))
				preferred_fs = FS_NTFS;
		} else if (HAS_SYSLINUX(img_report) || HAS_REACTOS(img_report) || HAS_KOLIBRIOS(img_report) ||
		    (IS_EFI_BOOTABLE(img_report) && (target_type == TT_UEFI) &&
		     (!windows_to_go) && (!img_report.has_4GB_file))) {
			/*
			 * Syslinux, ReactOS, KolibriOS, and EFI-only images (when targeting
			 * UEFI and the image has no 4 GB file) prefer FAT32.
			 */
			if (fs_mask & (1 << FS_FAT32))
				preferred_fs = FS_FAT32;
			else if ((fs_mask & (1 << FS_FAT16)) && !HAS_KOLIBRIOS(img_report))
				preferred_fs = FS_FAT16;
		} else if (windows_to_go || HAS_BOOTMGR(img_report) || HAS_WINPE(img_report)) {
			/*
			 * Windows images: FAT32 when dual BIOS+UEFI and no 4 GB file,
			 * otherwise NTFS.
			 */
			if ((fs_mask & (1 << FS_FAT32)) && (!img_report.has_4GB_file) &&
			    allow_dual_uefi_bios)
				preferred_fs = FS_FAT32;
			else if (fs_mask & (1 << FS_NTFS))
				preferred_fs = FS_NTFS;
		}
	}
	if (preferred_fs != FS_UNKNOWN) {
		for (i = 0; i < ComboBox_GetCount(hFileSystem); i++) {
			fs_tmp = (int)ComboBox_GetItemData(hFileSystem, i);
			if (fs_tmp == preferred_fs) {
				IGNORE_RETVAL(ComboBox_SetCurSel(hFileSystem, i));
				fs_type = preferred_fs;
				populate_cluster_combo(fs_type);
				break;
			}
		}
	}
}

/* -------------------------------------------------------------------------
 * SetPartitionSchemeAndTargetSystem
 *
 * Repopulates the Partition Scheme (unless only_target is TRUE) and the
 * Target System combos based on the current boot_type and img_report.
 *
 * Logic mirrors Windows rufus.c SetPartitionSchemeAndTargetSystem().
 * --------------------------------------------------------------------- */
void SetPartitionSchemeAndTargetSystem(BOOL only_target)
{
	/*
	 * allowed_partition_scheme[0] = MBR, [1] = GPT, [2] = SFD
	 * allowed_target_system[0]    = BIOS, [1] = UEFI, [2] = BIOS+UEFI dual
	 */
	BOOL allowed_partition_scheme[3] = { TRUE, TRUE, FALSE };
	BOOL allowed_target_system[3]    = { TRUE, TRUE, FALSE };
	BOOL is_windows_to_go_selected;
	int preferred_pt;

	if (!only_target)
		IGNORE_RETVAL(ComboBox_ResetContent(hPartitionScheme));
	IGNORE_RETVAL(ComboBox_ResetContent(hTargetSystem));

	/* boot_type is maintained by the caller (updated in on_boot_changed /
	 * on_device_changed callbacks).  We don't re-read it from the combo here
	 * so that unit tests can set it directly without a live GTK widget. */
	is_windows_to_go_selected = (boot_type == BT_IMAGE) && (image_path != NULL) &&
		HAS_WINTOGO(img_report) &&
		(ComboBox_GetCurItemData(hImageOption) == IMOP_WIN_TO_GO);

	/* If no device is selected, don't populate anything */
	if (ComboBox_GetCurSel(hDeviceList) < 0)
		return;

	switch (boot_type) {
	case BT_NON_BOOTABLE:
		allowed_partition_scheme[PARTITION_STYLE_SFD] = TRUE;
		allowed_target_system[0] = FALSE;
		allowed_target_system[1] = FALSE;
		allowed_target_system[2] = TRUE;
		break;
	case BT_IMAGE:
		if (image_path == NULL)
			break;
		/* Check if image is EFI bootable */
		if (!IS_EFI_BOOTABLE(img_report)) {
			allowed_partition_scheme[PARTITION_STYLE_GPT] = FALSE;
			allowed_target_system[1] = FALSE;
			break;
		}
		/* Image is EFI bootable */
		if (IS_BIOS_BOOTABLE(img_report)) {
			if (!HAS_WINDOWS(img_report) || allow_dual_uefi_bios ||
			    is_windows_to_go_selected) {
				allowed_target_system[0] = FALSE;
				allowed_target_system[1] = TRUE;
				allowed_target_system[2] = TRUE;
			}
			/*
			 * Syslinux 4.x has no NTFS support.  If the image uses Syslinux ≤4
			 * and has a 4 GB file (forcing NTFS), disable MBR entirely.
			 */
			if (HAS_SYSLINUX(img_report) &&
			    (SL_MAJOR(img_report.sl_version) < 5) &&
			    img_report.has_4GB_file &&
			    !HAS_BOOTMGR(img_report) && !HAS_WINPE(img_report) &&
			    !HAS_GRUB(img_report))
				allowed_partition_scheme[PARTITION_STYLE_MBR] = FALSE;
		} else {
			/* EFI-only image: no BIOS target */
			allowed_target_system[0] = FALSE;
		}
		break;
	case BT_MSDOS:
	case BT_FREEDOS:
	case BT_SYSLINUX_V4:
	case BT_SYSLINUX_V6:
	case BT_REACTOS:
	case BT_GRUB4DOS:
	case BT_GRUB2:
		allowed_partition_scheme[PARTITION_STYLE_GPT] = FALSE;
		allowed_target_system[1] = FALSE;
		break;
	case BT_UEFI_NTFS:
		allowed_target_system[0] = FALSE;
		break;
	default:
		break;
	}

	if (!only_target) {
		/* For drives > 2 TB, force GPT */
		if (SelectedDrive.DiskSize > 2 * TB)
			selected_pt = PARTITION_STYLE_GPT;

		/* Start with the drive's current partition scheme as the preference */
		preferred_pt = SelectedDrive.PartitionStyle;

		if (allowed_partition_scheme[PARTITION_STYLE_MBR])
			IGNORE_RETVAL(ComboBox_SetItemData(hPartitionScheme,
			    ComboBox_AddString(hPartitionScheme, "MBR"), PARTITION_STYLE_MBR));
		if (allowed_partition_scheme[PARTITION_STYLE_GPT])
			IGNORE_RETVAL(ComboBox_SetItemData(hPartitionScheme,
			    ComboBox_AddString(hPartitionScheme, "GPT"), PARTITION_STYLE_GPT));
		if (allowed_partition_scheme[PARTITION_STYLE_SFD] && sfd_name)
			IGNORE_RETVAL(ComboBox_SetItemData(hPartitionScheme,
			    ComboBox_AddString(hPartitionScheme, sfd_name), PARTITION_STYLE_SFD));

		/* Override preferred partition type */
		if (boot_type == BT_NON_BOOTABLE) {
			preferred_pt = (selected_pt >= 0) ? selected_pt : PARTITION_STYLE_MBR;
		} else if (boot_type == BT_UEFI_NTFS) {
			preferred_pt = (selected_pt >= 0) ? selected_pt : PARTITION_STYLE_GPT;
		} else if ((boot_type == BT_IMAGE) && (image_path != NULL) &&
		           (img_report.is_iso || img_report.is_windows_img)) {
			if (HAS_WINDOWS(img_report) && img_report.has_efi) {
				preferred_pt = allow_dual_uefi_bios ? PARTITION_STYLE_MBR :
				               ((selected_pt >= 0) ? selected_pt : PARTITION_STYLE_GPT);
			}
			if (IS_DD_BOOTABLE(img_report))
				preferred_pt = (selected_pt >= 0) ? selected_pt : PARTITION_STYLE_MBR;
		}

		SetComboEntry(hPartitionScheme, preferred_pt);
		partition_type = (int)ComboBox_GetCurItemData(hPartitionScheme);
	}

	/* Populate Target System combo */
	has_uefi_csm = FALSE;
	if (allowed_target_system[0] && (partition_type != PARTITION_STYLE_GPT)) {
		IGNORE_RETVAL(ComboBox_SetItemData(hTargetSystem,
		    ComboBox_AddString(hTargetSystem, "BIOS (or UEFI-CSM)"), TT_BIOS));
		has_uefi_csm = TRUE;
	}
	if (allowed_target_system[1]) {
		IGNORE_RETVAL(ComboBox_SetItemData(hTargetSystem,
		    ComboBox_AddString(hTargetSystem, "UEFI (non-CSM)"), TT_UEFI));
	}
	if (allowed_target_system[2] &&
	    ((partition_type != PARTITION_STYLE_GPT) || (boot_type == BT_NON_BOOTABLE))) {
		/* "BIOS+UEFI" uses TT_BIOS value (as in the Windows implementation) */
		IGNORE_RETVAL(ComboBox_SetItemData(hTargetSystem,
		    ComboBox_AddString(hTargetSystem, "BIOS+UEFI"), TT_BIOS));
	}

	/* Try to reselect the previously-chosen target type */
	{
		int found = -1;
		for (int i = 0; i < ComboBox_GetCount(hTargetSystem); i++) {
			if ((int)ComboBox_GetItemData(hTargetSystem, i) == target_type) {
				found = i;
				break;
			}
		}
		if (found >= 0)
			IGNORE_RETVAL(ComboBox_SetCurSel(hTargetSystem, found));
		else if (ComboBox_GetCount(hTargetSystem) > 0)
			IGNORE_RETVAL(ComboBox_SetCurSel(hTargetSystem, 0));
	}
	target_type = (int)ComboBox_GetCurItemData(hTargetSystem);
}
