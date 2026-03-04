/*
 * Rufus: The Reliable USB Formatting Utility
 * ISO file-property classifier — portable implementation
 * Copyright © 2011-2024 Pete Batard <pete@akeo.ie>
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
 * NOTE: This file is intentionally NOT compiled as a standalone translation unit.
 * It must be #included by src/linux/iso.c and src/windows/iso.c after they have
 * defined all the file-local statics and constants that this function requires:
 *
 *   scan_only, config_path, isolinux_path         (statics in platform iso.c)
 *   total_blocks, has_ldlinux_c32, img_report      (globals in platform iso.c)
 *   bootmgr_name, grldr_name, ldlinux_name,       \
 *   ldlinux_c32, casper_dirname, proxmox_dirname,  |  string constants in
 *   sources_str, wininst_name[], grub_dirname[],   |  platform iso.c
 *   grub_cfg[], menu_cfg, syslinux_cfg[],          |
 *   isolinux_bin[], pe_dirname[], pe_file[],        |
 *   reactos_name[], kolibri_name, manjaro_marker,  |
 *   pop_os_name, old_c32_threshold[]               /
 *   bootmgr_efi_name, efi_dirname, efi_bootname[], \  non-static globals in
 *   efi_archname[], md5sum_name[], old_c32_name[]   /  platform iso.c
 *
 * Platform differences handled with #ifdef _WIN32:
 *   - wininst_path storage format: "?:%s" (Windows) vs "%s" (Linux)
 *   - WIM file splitting for FAT32 targets (Windows only)
 */

/*
 * Classify a single ISO entry and accumulate global scan state.
 *
 * Returns TRUE when the caller should skip actual file extraction:
 *   - always during scan_only mode
 *   - when the file is ldlinux.sys at root (syslinux will write it)
 *   - (Windows only) when the file needs to be split into .swm pieces
 * Returns FALSE otherwise (write the file normally).
 */
static BOOL check_iso_props(const char* psz_dirname, int64_t file_length,
                             const char* psz_basename, const char* psz_fullpath,
                             EXTRACT_PROPS* props)
{
	size_t i, j, k, len;
	char   bootloader_name[32];

	memset(props, 0, sizeof(EXTRACT_PROPS));

	/* Check for an isolinux/syslinux config file anywhere */
	for (i = 0; i < ARRAYSIZE(syslinux_cfg); i++) {
		if (safe_stricmp(psz_basename, syslinux_cfg[i]) == 0) {
			props->is_cfg = TRUE;
			props->is_syslinux_cfg = TRUE;
			/* Maintain a list of all the isolinux/syslinux config files identified so far */
			if (scan_only && i < 3)
				StrArrayAdd(&config_path, psz_fullpath, TRUE);
			if (scan_only && i == 1 &&
			    safe_stricmp(psz_dirname, efi_dirname) == 0)
				img_report.has_efi_syslinux = TRUE;
		}
	}

	/* Check for archiso loader/entries conf files */
	if (safe_stricmp(psz_dirname, "/loader/entries") == 0) {
		len = safe_strlen(psz_basename);
		props->is_conf = (len > 4 && safe_stricmp(&psz_basename[len - 5], ".conf") == 0);
	}

	/* Check for an old incompatible c32 file anywhere */
	for (i = 0; i < NB_OLD_C32; i++) {
		if (safe_stricmp(psz_basename, old_c32_name[i]) == 0 &&
		    file_length <= old_c32_threshold[i])
			props->is_old_c32[i] = TRUE;
	}

	if (!scan_only) {
		/* Write-time: check for config files that may need patching */
		len = safe_strlen(psz_basename);
		if (len >= 4 && safe_stricmp(&psz_basename[len - 4], ".cfg") == 0) {
			props->is_cfg = TRUE;
			for (i = 0; i < ARRAYSIZE(grub_cfg); i++) {
				if (safe_stricmp(psz_basename, grub_cfg[i]) == 0)
					props->is_grub_cfg = TRUE;
			}
			if (safe_stricmp(psz_basename, menu_cfg) == 0)
				props->is_menu_cfg = TRUE;
		}

		/* In case there's an ldlinux.sys on the ISO, prevent it from overwriting ours */
		if (psz_dirname != NULL && psz_dirname[0] == 0 &&
		    safe_stricmp(psz_basename, ldlinux_name) == 0) {
			uprintf("Skipping '%s' from ISO (will be written by syslinux)", psz_basename);
			return TRUE;
		}

		/* Split a >4GB install.wim if the target filesystem is FAT.
		 * Works on both Windows and Linux: our custom wimlib supports
		 * the "iso_path|/internal/path" format for reading WIM files
		 * directly out of ISO images on both platforms. */
		if (file_length >= 4 * GB && psz_dirname != NULL && IS_FAT(fs_type) &&
		    img_report.has_4GB_file == 0x11) {
			if (safe_stricmp(&psz_dirname[max(0, ((int)safe_strlen(psz_dirname)) -
			    ((int)strlen(sources_str)))], sources_str) == 0) {
				char wim_path[4 * MAX_PATH];
				for (i = 0; i < ARRAYSIZE(wininst_name) - 1; i++) {
					if (safe_stricmp(psz_basename, wininst_name[i]) == 0 &&
					    file_length >= 4 * GB) {
						print_split_file((char*)psz_fullpath, file_length);
						char* dst = safe_strdup(psz_fullpath);
						if (dst == NULL) return FALSE;
						dst[strlen(dst) - 3] = 's';
						dst[strlen(dst) - 2] = 'w';
						dst[strlen(dst) - 1] = 'm';
						assert(safe_strlen(image_path) + safe_strlen(psz_dirname) +
						       safe_strlen(psz_basename) + 2 < ARRAYSIZE(wim_path));
						static_sprintf(wim_path, "%s|%s/%s",
						               image_path, psz_dirname, psz_basename);
						WimSplitFile(wim_path, dst);
						free(dst);
						return TRUE;
					}
				}
			}
		}

		return FALSE;
	}

	/* ---- scan-time only ---- */

	/* Check for GRUB artifacts */
	for (i = 0; i < ARRAYSIZE(grub_dirname); i++) {
		if (safe_stricmp(psz_dirname, grub_dirname[i]) == 0)
			img_report.has_grub2 = (uint8_t)i + 1;
	}

	/* Check for a syslinux v5.0+ file anywhere */
	if (safe_stricmp(psz_basename, ldlinux_c32) == 0)
		has_ldlinux_c32 = TRUE;

	/* Check for a '/casper#####' directory (non-empty) */
	if (safe_strnicmp(psz_dirname, casper_dirname, strlen(casper_dirname)) == 0) {
		img_report.uses_casper = TRUE;
		if (safe_strstr(psz_dirname, pop_os_name) != NULL)
			img_report.disable_iso = TRUE;
	}

	/* Check for a '/proxmox' directory */
	if (safe_stricmp(psz_dirname, proxmox_dirname) == 0)
		img_report.disable_iso = TRUE;

	/* Check for various files and directories in root (psz_dirname == "") */
	if (psz_dirname != NULL && psz_dirname[0] == '\0') {
		if (safe_stricmp(psz_basename, bootmgr_name) == 0)
			img_report.has_bootmgr = TRUE;
		if (safe_stricmp(psz_basename, bootmgr_efi_name) == 0) {
			/*
			 * We may extract the bootloaders for revocation validation later but
			 * to do so, since we're working with case sensitive file systems, we
			 * must store all found UEFI bootloader paths with the right case.
			 */
			for (j = 0; j < ARRAYSIZE(img_report.efi_boot_entry); j++) {
				if (img_report.efi_boot_entry[j].path[0] == 0) {
					img_report.efi_boot_entry[j].type = EBT_BOOTMGR;
					static_strcpy(img_report.efi_boot_entry[j].path, psz_fullpath);
					break;
				}
			}
			img_report.has_efi |= 1;
			img_report.has_bootmgr_efi = TRUE;
		}
		if (safe_stricmp(psz_basename, grldr_name) == 0)
			img_report.has_grub4dos = TRUE;
		if (safe_stricmp(psz_basename, kolibri_name) == 0)
			img_report.has_kolibrios = TRUE;
		if (safe_stricmp(psz_basename, manjaro_marker) == 0)
			img_report.disable_iso = TRUE;
		for (i = 0; i < ARRAYSIZE(md5sum_name); i++) {
			if (safe_stricmp(psz_basename, md5sum_name[i]) == 0)
				img_report.has_md5sum = (uint8_t)(i + 1);
		}
	}

	/* Check for ReactOS presence anywhere */
	if (img_report.reactos_path[0] == 0) {
		for (i = 0; i < ARRAYSIZE(reactos_name); i++) {
			if (safe_stricmp(psz_basename, reactos_name[i]) == 0)
				static_strcpy(img_report.reactos_path, psz_fullpath);
		}
	}

	/* Check for the first 'efi*.img' we can find (that hopefully contains EFI boot files) */
	if (!HAS_EFI_IMG(img_report) && safe_strlen(psz_basename) >= 7 &&
	    safe_strnicmp(psz_basename, "efi", 3) == 0 &&
	    safe_stricmp(&psz_basename[strlen(psz_basename) - 4], ".img") == 0)
		static_strcpy(img_report.efi_img_path, psz_fullpath);

	/* Check for the EFI boot entries */
	if (safe_stricmp(psz_dirname, efi_dirname) == 0) {
		for (k = 0; k < ARRAYSIZE(efi_bootname); k++) {
			for (i = 0; i < ARRAYSIZE(efi_archname); i++) {
				static_sprintf(bootloader_name, "%s%s.efi", efi_bootname[k], efi_archname[i]);
				if (safe_stricmp(psz_basename, bootloader_name) == 0) {
					if (k == 0)
						img_report.has_efi |= (uint16_t)(2 << i);
					for (j = 0; j < ARRAYSIZE(img_report.efi_boot_entry); j++) {
						if (img_report.efi_boot_entry[j].path[0] == 0) {
							img_report.efi_boot_entry[j].type = (uint8_t)k;
							static_strcpy(img_report.efi_boot_entry[j].path, psz_fullpath);
							break;
						}
					}
				}
			}
		}
		/*
		 * Linux Mint Edge 21.2/Mint 21.3 have an invalid /EFI/boot/bootx64.efi
		 * because it's a symbolic link to a file that does not exist on the media.
		 * This is originally due to a Debian bug fixed in:
		 * https://salsa.debian.org/live-team/live-build/-/commit/5bff71fea2dd54adcd6c428d3f1981734079a2f7
		 * If we detect a tiny bootx64.efi file, assert it's a broken link and try
		 * to extract a "good" version from the El-Torito image.
		 */
		if (safe_stricmp(psz_basename, "bootx64.efi") == 0 && file_length < 256) {
			img_report.has_efi |= 0x4000;
			static_strcpy(img_report.efi_img_path, "[BOOT]/1-Boot-NoEmul.img");
		}
	}

	/* Check for "install.###" in "###/sources/" */
	if (psz_dirname != NULL) {
		int dlen = (int)safe_strlen(psz_dirname);
		int slen = (int)strlen(sources_str);
		int soff = (dlen > slen) ? (dlen - slen) : 0;
		if (safe_stricmp(&psz_dirname[soff], sources_str) == 0) {
			for (i = 0; i < ARRAYSIZE(wininst_name); i++) {
				if (safe_stricmp(psz_basename, wininst_name[i]) == 0 &&
				    img_report.wininst_index < MAX_WININST) {
#ifdef _WIN32
					static_sprintf(img_report.wininst_path[img_report.wininst_index],
					               "?:%s", psz_fullpath);
#else
					static_sprintf(img_report.wininst_path[img_report.wininst_index],
					               "%s", psz_fullpath);
#endif
					img_report.wininst_index++;
					if (file_length >= 4 * GB)
						img_report.has_4GB_file |= (0x10u << i);
				}
			}
		}
	}

	/* Check for "\sources\$OEM$\$$\Panther\unattend.xml" */
	if (safe_stricmp(psz_dirname, "/sources/$OEM$/$$/Panther") == 0 &&
	    safe_stricmp(psz_basename, "unattend.xml") == 0)
		img_report.has_panther_unattend = TRUE;

	/* Check for PE (XP) specific files in "/i386", "/amd64" or "/minint" */
	for (i = 0; i < ARRAYSIZE(pe_dirname); i++)
		if (safe_stricmp(psz_dirname, pe_dirname[i]) == 0)
			for (j = 0; j < ARRAYSIZE(pe_file); j++)
				if (safe_stricmp(psz_basename, pe_file[j]) == 0)
					img_report.winpe |= (1u << j) << (ARRAYSIZE(pe_dirname) * i);

	/* Maintain a list of all the isolinux.bin files found */
	for (i = 0; i < ARRAYSIZE(isolinux_bin); i++) {
		if (safe_stricmp(psz_basename, isolinux_bin[i]) == 0)
			StrArrayAdd(&isolinux_path, psz_fullpath, TRUE);
	}

	/* Propagate old c32 flags to img_report */
	for (i = 0; i < NB_OLD_C32; i++)
		if (props->is_old_c32[i])
			img_report.has_old_c32[i] = TRUE;

	/* Track any file >= 4 GB */
	if (file_length >= 4 * GB && (img_report.has_4GB_file & 0x0f) != 0x0f)
		img_report.has_4GB_file++;

	/* Compute projected size needed (NB: ISO_BLOCKSIZE = UDF_BLOCKSIZE) */
	if (file_length != 0)
		total_blocks += (uint64_t)(file_length + ISO_BLOCKSIZE - 1) / ISO_BLOCKSIZE;

	return TRUE; /* scan_only: caller skips actual extraction */
}
