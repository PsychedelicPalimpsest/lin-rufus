/*
 * Rufus: The Reliable USB Formatting Utility
 * ISO config-file patching — portable implementation
 * Copyright © 2012-2025 Pete Batard <pete@akeo.ie>
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
 * iso_patch_config_file() is the portable heart of the "fix_config" routine
 * that both Linux and Windows iso.c call after extracting each config file
 * from an ISO.  All platform-specific operations (path-separator conversion,
 * file copy) are handled by the callers or via the `copy_fn` callback.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iso_config.h"
#include "../rufus.h"

/* Declared in platform parser.c (linux or windows) */
extern char* replace_in_token_data(const char* filename, const char* token,
	const char* src, const char* rep, BOOL dos2unix);
/* Declared in common/parser.c */
extern char* replace_char(const char* src, const char c, const char* rep);
/* Declared in common/stdfn.c */
extern int32_t StrArrayAdd(StrArray* arr, const char* str, BOOL duplicate);

/* Compile-time constants duplicated here to avoid including iso.c internals.
 * These match the values used in both linux/iso.c and windows/iso.c. */
#define ISO_EFI_DIRNAME   "/efi/boot"
#define ISO_ISOLINUX_CFG  "isolinux.cfg"

BOOL iso_patch_config_file(
	const char   *file_path,
	const char   *psz_path,
	const char   *psz_basename,
	EXTRACT_PROPS *props,
	int           boot_type,
	uint64_t      persistence_size,
	BOOL          has_persistence,
	BOOL          rh8_derivative,
	BOOL          has_efi_syslinux,
	const char   *iso_label_raw,
	const char   *usb_label_raw,
	const char   *image_path,
	StrArray     *modified_files,
	iso_copy_fn   copy_fn)
{
	BOOL  modified = FALSE, patched;
	char *iso_lbl = NULL, *usb_lbl = NULL, *dst = NULL;
	size_t nul_pos;

	if (!file_path || !file_path[0] || !props)
		return FALSE;

	nul_pos = strlen(file_path);

	/* ----------------------------------------------------------------
	 * 1. Persistence injection
	 * ----------------------------------------------------------------
	 * Add the distro-specific persistence keyword to the kernel command
	 * line.  We try several patterns because each major distro family
	 * uses a different one.
	 */
	if ((boot_type == BT_IMAGE) && has_persistence && persistence_size > 0) {
		if (props->is_grub_cfg || props->is_menu_cfg || props->is_syslinux_cfg) {
			const char *kw = props->is_grub_cfg ? "linux" : "append";

			/* Ubuntu & derivatives — "file=/cdrom/preseed" token */
			if (replace_in_token_data(file_path, kw,
				"file=/cdrom/preseed", "persistent file=/cdrom/preseed", TRUE) != NULL) {
				uprintf("  Added 'persistent' kernel option");
				modified = TRUE;
				/* Remove Ubuntu's "maybe-ubiquity" splash workaround */
				if (props->is_grub_cfg)
					replace_in_token_data(file_path, "linux", "maybe-ubiquity", "", TRUE);
			} else if (replace_in_token_data(file_path, kw,
				"boot=casper", "boot=casper persistent", TRUE) != NULL) {
				/* Linux Mint */
				uprintf("  Added 'persistent' kernel option");
				modified = TRUE;
			} else if (replace_in_token_data(file_path, "linux",
				"/casper/vmlinuz", "/casper/vmlinuz persistent", TRUE) != NULL) {
				/* Ubuntu 23.04 / 24.04 GRUB-only */
				uprintf("  Added 'persistent' kernel option");
				modified = TRUE;
			} else if (replace_in_token_data(file_path, "kernel",
				"/casper/vmlinuz", "/casper/vmlinuz persistent", TRUE) != NULL) {
				uprintf("  Added 'persistent' kernel option");
				modified = TRUE;
			} else if (replace_in_token_data(file_path, kw,
				"boot=live", "boot=live persistence", TRUE) != NULL) {
				/* Debian & derivatives */
				uprintf("  Added 'persistence' kernel option");
				modified = TRUE;
			}
		}
	}

	/* ----------------------------------------------------------------
	 * 2. Label replacement + Red Hat inst.stage2 fix
	 * ----------------------------------------------------------------
	 * Replace the ISO volume label with the USB volume label wherever it
	 * appears in kernel command-line options.  Spaces in labels are
	 * represented as "\\x20" in boot config files.
	 */
	if ((props->is_cfg || props->is_conf) &&
	    iso_label_raw != NULL && usb_label_raw != NULL) {
		static const char* cfg_token[] = {
			"options", "append", "linux", "linuxefi", "$linux", "search", "for"
		};

		iso_lbl = replace_char(iso_label_raw, ' ', "\\x20");
		usb_lbl = replace_char(usb_label_raw, ' ', "\\x20");

		if (iso_lbl != NULL && usb_lbl != NULL) {
			patched = FALSE;
			for (int i = 0; i < (int)(sizeof(cfg_token) / sizeof(cfg_token[0])); i++) {
				if (replace_in_token_data(file_path, cfg_token[i],
					iso_lbl, usb_lbl, TRUE) != NULL) {
					modified = TRUE;
					patched  = TRUE;
				}
			}
			if (patched)
				uprintf("  Patched %s: '%s' ➔ '%s'", file_path, iso_lbl, usb_lbl);

			/* Red Hat 8+ inst.stage2 → inst.repo
			 * Skip netinst ISOs (they use stage2 legitimately). */
			patched = FALSE;
			if (rh8_derivative && (image_path == NULL ||
			    strstr(image_path, "netinst") == NULL)) {
				for (int i = 0; i < (int)(sizeof(cfg_token) / sizeof(cfg_token[0])); i++) {
					if (replace_in_token_data(file_path, cfg_token[i],
						"inst.stage2", "inst.repo", TRUE) != NULL) {
						modified = TRUE;
						patched  = TRUE;
					}
				}
				if (patched)
					uprintf("  Patched %s: '%s' ➔ '%s'",
					        file_path, "inst.stage2", "inst.repo");
			}
		}

		free(iso_lbl);
		free(usb_lbl);
		iso_lbl = usb_lbl = NULL;
	}

	/* ----------------------------------------------------------------
	 * 3. Tails dual BIOS+EFI workaround
	 * ----------------------------------------------------------------
	 * When an ISO has /EFI/syslinux/isolinux.cfg but no native EFI
	 * syslinux config, duplicate it to /EFI/syslinux/syslinux.cfg.
	 */
	if (props->is_syslinux_cfg &&
	    safe_stricmp(psz_path,     ISO_EFI_DIRNAME) == 0 &&
	    safe_stricmp(psz_basename, ISO_ISOLINUX_CFG) == 0 &&
	    !has_efi_syslinux &&
	    copy_fn != NULL &&
	    nul_pos >= 12) {
		dst = safe_strdup(file_path);
		if (dst != NULL) {
			/* Change the trailing "isolinux.cfg" → "syslinux.cfg".
			 * "isolinux.cfg" is 12 characters; overwrite first 3
			 * letters "iso" → "sys". */
			dst[nul_pos - 12] = 's';
			dst[nul_pos - 11] = 'y';
			dst[nul_pos - 10] = 's';
			if (copy_fn(file_path, dst))
				uprintf("Duplicated %s to %s", file_path, dst);
			free(dst);
			dst = NULL;
		}
	}

	/* ----------------------------------------------------------------
	 * 4. FreeNAS cd9660 path fix
	 * ----------------------------------------------------------------
	 * FreeNAS GRUB configs use "cd9660:/dev/iso9660/<LABEL>"; rewrite
	 * to the equivalent FAT/msdosfs path for USB boot.
	 */
	if (props->is_grub_cfg &&
	    iso_label_raw != NULL && usb_label_raw != NULL) {
		iso_lbl = malloc(MAX_PATH);
		usb_lbl = malloc(MAX_PATH);
		if (iso_lbl != NULL && usb_lbl != NULL) {
			snprintf(iso_lbl, MAX_PATH,
			         "cd9660:/dev/iso9660/%s", iso_label_raw);
			snprintf(usb_lbl, MAX_PATH,
			         "msdosfs:/dev/msdosfs/%s", usb_label_raw);
			if (replace_in_token_data(file_path, "set",
				iso_lbl, usb_lbl, TRUE) != NULL) {
				uprintf("  Patched %s: '%s' ➔ '%s'",
				        file_path, iso_lbl, usb_lbl);
				modified = TRUE;
			}
		}
		free(iso_lbl);
		free(usb_lbl);
		iso_lbl = usb_lbl = NULL;
	}

	/* Record this file as modified so UpdateMD5Sum can refresh its hash */
	if (modified && modified_files != NULL)
		StrArrayAdd(modified_files, file_path, TRUE);

	return modified;
}
