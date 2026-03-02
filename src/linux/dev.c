/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: dev.c — device enumeration via sysfs
 * Copyright © 2014-2026 Pete Batard <pete@akeo.ie>
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

/* Linux implementation: dev.c - device enumeration via sysfs */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/usbdevice_fs.h>
#include <limits.h>
#include <assert.h>

#include "rufus.h"
#include "dev.h"
#include "drive.h"
#include "resource.h"

extern RUFUS_DRIVE rufus_drive[MAX_DRIVES];
extern HWND hDeviceList;
extern HWND hMainDialog;
extern BOOL enable_HDDs;

/* Read a sysfs attribute for a block device, trim trailing whitespace.
 * Returns TRUE on success. */
static BOOL sysfs_read_attr(const char* sysfs_root, const char* devname,
                             const char* attr, char* buf, size_t bufsz)
{
	char path[512];
	snprintf(path, sizeof(path), "%s/block/%s/%s", sysfs_root, devname, attr);
	FILE* f = fopen(path, "r");
	if (!f) return FALSE;
	BOOL ok = (fgets(buf, (int)bufsz, f) != NULL);
	fclose(f);
	if (ok) {
		char* p = buf + strlen(buf);
		while (p > buf && (p[-1] == '\n' || p[-1] == '\r' || p[-1] == ' ' || p[-1] == '\t'))
			*--p = '\0';
	}
	return ok;
}

/* Check if a path exists on disk */
static BOOL path_exists(const char* path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

/* Return TRUE if the block device name is a well-known virtual device */
static BOOL is_virtual_device(const char* name)
{
	return (strncmp(name, "loop", 4) == 0 ||
	        strncmp(name, "ram",  3) == 0 ||
	        strncmp(name, "zram", 4) == 0);
}

/* Walk up the resolved sysfs device path to find the USB device node —
 * the first ancestor directory that contains a 'busnum' file.
 * Returns TRUE and fills usb_path_out on success. */
BOOL find_usb_sysfs_device(const char* sysfs_root, const char* blk_name,
                            char* usb_path_out, size_t usb_path_sz)
{
	char dev_link[PATH_MAX];
	char resolved[PATH_MAX];

	snprintf(dev_link, sizeof(dev_link), "%s/block/%s/device",
	         sysfs_root, blk_name);
	if (realpath(dev_link, resolved) == NULL)
		return FALSE;

	/* Walk up the resolved path looking for a 'busnum' attribute */
	size_t len = strlen(resolved);
	while (len > 1) {
		char busnum_path[PATH_MAX];
		snprintf(busnum_path, sizeof(busnum_path), "%s/busnum", resolved);
		if (access(busnum_path, F_OK) == 0) {
			snprintf(usb_path_out, usb_path_sz, "%s", resolved);
			return TRUE;
		}
		/* Strip last path component */
		while (len > 0 && resolved[len - 1] != '/')
			len--;
		if (len > 0 && resolved[len - 1] == '/')
			len--;
		resolved[len] = '\0';
	}
	return FALSE;
}

/* Read an integer attribute from a sysfs path (absolute, not block-relative) */
static int sysfs_read_int(const char* path)
{
	FILE* f = fopen(path, "r");
	if (!f) return -1;
	int val = -1;
	fscanf(f, "%d", &val);
	fclose(f);
	return val;
}

void ClearDrives(void)
{
	for (int i = 0; i < MAX_DRIVES && rufus_drive[i].size != 0; i++) {
		safe_free(rufus_drive[i].id);
		safe_free(rufus_drive[i].name);
		safe_free(rufus_drive[i].display_name);
		safe_free(rufus_drive[i].label);
		safe_free(rufus_drive[i].hub);
	}
	memset(rufus_drive, 0, sizeof(rufus_drive));
}

/*
 * Enumerate block devices using the provided sysfs and dev roots.
 * This variant is used for testing (inject fake roots) and by GetDevices().
 */
BOOL GetDevicesWithRoot(DWORD devnum, const char* sysfs_root, const char* dev_root)
{
	char block_dir[512], attr[128], vendor[128], model[128];
	int num_drives = 0;
	BOOL r = FALSE, found = FALSE;
	LONG maxwidth = 0;

	IGNORE_RETVAL(ComboBox_ResetContent(hDeviceList));
	ClearDrives();

	snprintf(block_dir, sizeof(block_dir), "%s/block", sysfs_root);
	DIR* dir = opendir(block_dir);
	if (!dir) return FALSE;

	struct dirent* ent;
	while ((ent = readdir(dir)) != NULL && num_drives < MAX_DRIVES) {
		const char* name = ent->d_name;

		if (name[0] == '.') continue;
		if (is_virtual_device(name)) continue;

		/* Only real hardware has a device/ subdirectory */
		char device_dir[640];
		snprintf(device_dir, sizeof(device_dir), "%s/block/%s/device", sysfs_root, name);
		if (!path_exists(device_dir)) continue;

		/* The device node must exist */
		char dev_node[512];
		snprintf(dev_node, sizeof(dev_node), "%s/%s", dev_root, name);
		if (!path_exists(dev_node)) continue;

		/* removable flag — skip non-removable unless HDDs are enabled */
		BOOL removable = FALSE;
		if (sysfs_read_attr(sysfs_root, name, "removable", attr, sizeof(attr)))
			removable = (attr[0] == '1');
		if (!removable && !enable_HDDs) continue;

		/* Size in 512-byte sectors → bytes */
		uint64_t size = 0;
		if (sysfs_read_attr(sysfs_root, name, "size", attr, sizeof(attr)))
			size = strtoull(attr, NULL, 10) * 512ULL;
		if (size < MIN_DRIVE_SIZE) continue;

		/* Vendor / model */
		vendor[0] = '\0';
		model[0] = '\0';
		sysfs_read_attr(sysfs_root, name, "device/vendor", vendor, sizeof(vendor));
		sysfs_read_attr(sysfs_root, name, "device/model",  model,  sizeof(model));

		/* Build short name */
		char dev_name[256];
		if (vendor[0] && model[0])
			snprintf(dev_name, sizeof(dev_name), "%s %s", vendor, model);
		else if (model[0])
			snprintf(dev_name, sizeof(dev_name), "%s", model);
		else if (vendor[0])
			snprintf(dev_name, sizeof(dev_name), "%s", vendor);
		else
			snprintf(dev_name, sizeof(dev_name), "%s", name);

		/* Build display name: "SIZE NAME" */
		char display_name[512];
		snprintf(display_name, sizeof(display_name), "%s %s",
		         SizeToHumanReadable(size, FALSE, FALSE), dev_name);

		/* Drive index will be assigned after sorting */
		rufus_drive[num_drives].id           = safe_strdup(dev_node);
		rufus_drive[num_drives].name         = safe_strdup(dev_name);
		rufus_drive[num_drives].display_name = safe_strdup(display_name);
		rufus_drive[num_drives].label        = safe_strdup("");
		rufus_drive[num_drives].index        = 0; /* assigned after sort */
		rufus_drive[num_drives].size         = size;

		/* Locate the parent USB device in sysfs for CyclePort/CycleDevice */
		char usb_path[PATH_MAX];
		if (find_usb_sysfs_device(sysfs_root, name, usb_path, sizeof(usb_path))) {
			rufus_drive[num_drives].hub  = safe_strdup(usb_path);
			/* Store devnum so CyclePort can build /dev/bus/usb/BBB/DDD */
			char devnum_path[PATH_MAX];
			snprintf(devnum_path, sizeof(devnum_path), "%s/devnum", usb_path);
			int dn = sysfs_read_int(devnum_path);
			rufus_drive[num_drives].port = (dn > 0) ? (uint32_t)dn : 0;
		} else {
			rufus_drive[num_drives].hub  = NULL;
			rufus_drive[num_drives].port = 0;
		}
		num_drives++;
	}
	closedir(dir);

	/* Sort by increasing size (selection sort, mirrors Windows behaviour) */
	for (int u = 0; u < num_drives - 1; u++) {
		uint64_t min_size = rufus_drive[u].size;
		int min_idx = u;
		for (int v = u + 1; v < num_drives; v++) {
			if (rufus_drive[v].size < min_size) {
				min_size  = rufus_drive[v].size;
				min_idx   = v;
			}
		}
		if (min_idx != u) {
			RUFUS_DRIVE tmp;
			memcpy(&tmp,               &rufus_drive[u],       sizeof(RUFUS_DRIVE));
			memcpy(&rufus_drive[u],    &rufus_drive[min_idx], sizeof(RUFUS_DRIVE));
			memcpy(&rufus_drive[min_idx], &tmp,               sizeof(RUFUS_DRIVE));
		}
	}

	/* Assign stable drive indices after sorting */
	for (int u = 0; u < num_drives; u++)
		rufus_drive[u].index = DRIVE_INDEX_MIN + (DWORD)u;

	/* Populate the device combo box */
	int i = 0;
	for (int u = 0; u < num_drives; u++) {
		IGNORE_RETVAL(ComboBox_SetItemData(hDeviceList,
		    ComboBox_AddString(hDeviceList, rufus_drive[u].display_name),
		    rufus_drive[u].index));
		maxwidth = max(maxwidth, GetEntryWidth(hDeviceList, rufus_drive[u].display_name));
	}
	SendMessage(hDeviceList, CB_SETDROPPEDWIDTH, (WPARAM)maxwidth, 0);

	if (devnum >= DRIVE_INDEX_MIN) {
		for (i = 0; i < ComboBox_GetCount(hDeviceList); i++) {
			if ((DWORD)ComboBox_GetItemData(hDeviceList, i) == devnum) {
				found = TRUE;
				break;
			}
		}
	}
	if (!found) i = 0;
	IGNORE_RETVAL(ComboBox_SetCurSel(hDeviceList, i));
	SendMessage(hMainDialog, WM_COMMAND, (CBN_SELCHANGE << 16) | IDC_DEVICE, 0);
	SendMessage(hMainDialog, WM_NEXTDLGCTL,
	            (WPARAM)GetDlgItem(hMainDialog, IDC_START), TRUE);
	r = TRUE;

	return r;
}

BOOL GetDevices(DWORD devnum)
{
	return GetDevicesWithRoot(devnum, "/sys", "/dev");
}

BOOL CyclePort(int index)
{
	static uint64_t last_reset = 0;
	if (index < 0 || index >= MAX_DRIVES) return FALSE;

	if (GetTickCount64() < last_reset + 10000ULL) {
		uprintf("You must wait at least 10 seconds before trying to reset a device");
		return FALSE;
	}

	const char* hub = rufus_drive[index].hub;
	if (hub == NULL) {
		uprintf("The device does not appear to be a USB device");
		return FALSE;
	}

	/* Read busnum and devnum from sysfs */
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/busnum", hub);
	int busnum = sysfs_read_int(path);
	snprintf(path, sizeof(path), "%s/devnum", hub);
	int devnum = sysfs_read_int(path);
	if (busnum <= 0 || devnum <= 0) {
		uprintf("Could not determine USB bus/device number for reset");
		return FALSE;
	}

	snprintf(path, sizeof(path), "/dev/bus/usb/%03d/%03d", busnum, devnum);
	uprintf("Resetting USB device %s", path);
	int fd = open(path, O_WRONLY);
	if (fd < 0) {
		uprintf_errno("Could not open %s", path);
		return FALSE;
	}
	BOOL r = (ioctl(fd, USBDEVFS_RESET, 0) == 0);
	if (!r)
		uprintf_errno("Failed to reset USB device");
	else
		uprintf("Please wait for the device to re-appear...");
	close(fd);
	last_reset = GetTickCount64();
	return r;
}

int CycleDevice(int index)
{
	if (index < 0 || index >= MAX_DRIVES) return ERROR_INVALID_PARAMETER;

	const char* hub = rufus_drive[index].hub;
	if (hub == NULL) {
		uprintf("The device does not appear to be a USB device");
		return ERROR_DEV_NOT_EXIST;
	}

	/* The USB device ID is the basename of the sysfs path (e.g. "4-1") */
	const char* dev_id = strrchr(hub, '/');
	if (dev_id == NULL || dev_id[1] == '\0') return ERROR_INVALID_PARAMETER;
	dev_id++; /* skip the '/' */

	/* Unbind */
	int fd = open("/sys/bus/usb/drivers/usb/unbind", O_WRONLY);
	if (fd < 0) {
		uprintf_errno("Could not open USB unbind");
		return (int)errno;
	}
	uprintf("Unbinding USB device %s", dev_id);
	write(fd, dev_id, strlen(dev_id));
	close(fd);

	/* Brief pause to let the device detach */
	usleep(500000);

	/* Rebind */
	fd = open("/sys/bus/usb/drivers/usb/bind", O_WRONLY);
	if (fd < 0) {
		uprintf_errno("Could not open USB bind");
		return (int)errno;
	}
	uprintf("Rebinding USB device %s", dev_id);
	write(fd, dev_id, strlen(dev_id));
	close(fd);

	return NO_ERROR;
}

/* ISO 9660 Primary Volume Descriptor: offset 0x8000, label at +0x28, 32 bytes */
#define ISO_VD_OFFSET   0x8000LL
#define ISO_LABEL_OFFSET (ISO_VD_OFFSET + 0x28)
#define ISO_LABEL_LEN   32
/* Skip blank/rewritable media that report <= 4096 bytes */
#define MIN_OPTICAL_SIZE 4097LL

BOOL GetOpticalMediaWithRoot(const char* dev_root, IMG_SAVE* img_save)
{
	static char dev_path[PATH_MAX];
	static char label_buf[ISO_LABEL_LEN + 1];
	DIR* d;
	struct dirent* ent;
	int fd;
	int64_t disk_size = 0;
	uint64_t blk_size = 0;
	uint8_t iso_buf[ISO_LABEL_LEN];
	int k;

	d = opendir(dev_root);
	if (d == NULL)
		return FALSE;

	while ((ent = readdir(d)) != NULL) {
		/* Only consider sr* (sr0, sr1, ...) */
		if (strncmp(ent->d_name, "sr", 2) != 0 || !isdigit((unsigned char)ent->d_name[2]))
			continue;

		snprintf(dev_path, sizeof(dev_path), "%s/%s", dev_root, ent->d_name);
		fd = open(dev_path, O_RDONLY | O_NONBLOCK);
		if (fd < 0)
			continue;

		/* Try ioctl first (real block device), fall back to seek for test files */
		if (ioctl(fd, BLKGETSIZE64, &blk_size) == 0) {
			disk_size = (int64_t)blk_size;
		} else {
			disk_size = lseek(fd, 0, SEEK_END);
			lseek(fd, 0, SEEK_SET);
		}

		if (disk_size <= MIN_OPTICAL_SIZE) {
			close(fd);
			continue;
		}

		/* Try to read ISO 9660 volume label */
		memset(label_buf, 0, sizeof(label_buf));
		if (lseek(fd, ISO_LABEL_OFFSET, SEEK_SET) == ISO_LABEL_OFFSET) {
			if (read(fd, iso_buf, ISO_LABEL_LEN) == ISO_LABEL_LEN) {
				memcpy(label_buf, iso_buf, ISO_LABEL_LEN);
				label_buf[ISO_LABEL_LEN] = '\0';
				/* Strip trailing spaces */
				for (k = ISO_LABEL_LEN - 1; k >= 0 && label_buf[k] == ' '; k--)
					label_buf[k] = '\0';
			}
		}
		close(fd);

		img_save->DevicePath = dev_path;
		img_save->DeviceSize = disk_size;
		img_save->Label = label_buf[0] ? label_buf : NULL;

		closedir(d);
		return TRUE;
	}

	closedir(d);
	return FALSE;
}

BOOL GetOpticalMedia(IMG_SAVE* img_save)
{
	return GetOpticalMediaWithRoot("/dev", img_save);
}
