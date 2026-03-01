/* Linux implementation: dev.c - device enumeration via sysfs */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
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
		rufus_drive[num_drives].hub          = NULL;
		rufus_drive[num_drives].index        = 0; /* assigned after sort */
		rufus_drive[num_drives].port         = 0;
		rufus_drive[num_drives].size         = size;
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

BOOL CyclePort(int index)                            { (void)index; return FALSE; }
int  CycleDevice(int index)                          { (void)index; return 0; }
BOOL GetOpticalMedia(IMG_SAVE* img_save)             { (void)img_save; return FALSE; }
