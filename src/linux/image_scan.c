/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: image_scan.c – ImageScanThread
 * Copyright © 2011-2025 Pete Batard <pete@akeo.ie>
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
 * ImageScanThread — scans an image file and populates img_report.
 *
 * On Windows this logic lives in rufus.c.  On Linux we keep it in its own
 * translation unit so it can be compiled and tested independently.
 *
 * Flow:
 *   1. Validate image_path (early exit if NULL).
 *   2. Zero img_report.
 *   3. Call ExtractISO(…, TRUE)  – scan mode: populate img_report.is_iso,
 *      img_report.label, img_report.image_size, bootloader flags, etc.
 *   4. Call IsBootableImage() to detect dd-writable disk images.
 *   5. If it is a Windows image, call PopulateWindowsVersion().
 *   6. Post UM_IMAGE_SCANNED so the GTK main thread can refresh the UI.
 */

#include <string.h>

#include "rufus.h"
#include "missing.h"

/* ---- externs provided by other translation units ---- */
extern char             *image_path;
extern RUFUS_IMG_REPORT  img_report;
extern HWND              hMainDialog;

/* ---- forward declarations ---- */
BOOL   ExtractISO(const char* src_iso, const char* dest_dir, BOOL scan);
int8_t IsBootableImage(const char* path);
BOOL   PopulateWindowsVersion(void);

/* -----------------------------------------------------------------------
 * ImageScanThread
 *
 * Runs as a background thread started by on_select_clicked() (ui_gtk.c)
 * whenever the user selects a new image file.  Posts UM_IMAGE_SCANNED
 * when done so the GTK idle loop can refresh the UI safely.
 * ----------------------------------------------------------------------- */
DWORD WINAPI ImageScanThread(LPVOID param)
{
	(void)param;

	if (image_path == NULL)
		goto out_no_msg;

	memset(&img_report, 0, sizeof(img_report));

	/* Scan the image — this populates img_report fields: is_iso, label,
	 * image_size, has_grub2, has_syslinux, has_efi, is_windows_img, … */
	img_report.is_iso          = (BOOLEAN)ExtractISO(image_path, "", TRUE);
	img_report.is_bootable_img = IsBootableImage(image_path);

	/* If a Windows installation image was detected, gather version info */
	if (img_report.wininst_index > 0 || img_report.is_windows_img)
		PopulateWindowsVersion();

	/* Notify the GTK main thread; it will refresh all dependent combos. */
	PostMessage(hMainDialog, UM_IMAGE_SCANNED, 0, 0);

out_no_msg:
	ExitThread(0);
}
