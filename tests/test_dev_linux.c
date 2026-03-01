/*
 * test_dev_linux.c — tests for Linux device enumeration (GetDevicesWithRoot)
 *
 * Strategy: build a fake sysfs tree under a tmpdir and verify that
 * GetDevicesWithRoot() populates rufus_drive[] correctly.
 *
 * Linux-only; no-op on other platforms.
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
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

/* ---- compat layer (provides BOOL, DWORD, HWND, etc.) ---- */
#include "windows.h"
#include "commctrl.h"
#include "rufus.h"
/* Declare GetDevicesWithRoot without pulling in dev.h (which has a non-extern GUID
 * that causes multiple-definition errors when included in more than one TU). */
extern BOOL GetDevicesWithRoot(DWORD devnum, const char* sysfs_root, const char* dev_root);
extern void ClearDrives(void);
#include "resource.h"

/* ===== Globals required by rufus.h externs ===== */
RUFUS_DRIVE rufus_drive[MAX_DRIVES];

HWND hDeviceList  = NULL;
HWND hMainDialog  = NULL;

BOOL enable_HDDs  = FALSE;
BOOL enable_VHDs  = TRUE;
BOOL right_to_left_mode = FALSE;

/* msg_dispatch stub — provide SendMessageA directly */
LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
{
	(void)h; (void)m; (void)w; (void)l;
	return 0;
}

/* ===== Stub functions required by dev.c ===== */
void uprintf(const char* fmt, ...) { (void)fmt; }
char* lmprintf(int id, ...) { (void)id; return ""; }

char* SizeToHumanReadable(uint64_t size, BOOL copy_to_log, BOOL fake_units)
{
	static char buf[32];
	static const char* suf[] = { "B", "KB", "MB", "GB", "TB" };
	double hr = (double)size;
	int s = 0;
	const double div = fake_units ? 1000.0 : 1024.0;
	(void)copy_to_log;
	while (s < 4 && hr >= div) { hr /= div; s++; }
	snprintf(buf, sizeof(buf), (hr - (int)hr < 0.05) ? "%.0f %s" : "%.1f %s", hr, suf[s]);
	return buf;
}

LONG GetEntryWidth(HWND h, const char* e) { (void)h; (void)e; return 0; }

/* ===== Helpers to build a fake sysfs tree ===== */

static void mkdirs(const char* path)
{
	char tmp[1024];
	snprintf(tmp, sizeof(tmp), "%s", path);
	for (char* p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(tmp, 0755);
			*p = '/';
		}
	}
	mkdir(tmp, 0755);
}

static void fake_write_file(const char* path, const char* content)
{
	FILE* f = fopen(path, "w");
	assert(f != NULL);
	fputs(content, f);
	fclose(f);
}

typedef struct {
	const char* name;     /* block device name, e.g. "sda" */
	int  removable;       /* 0 or 1 */
	uint64_t sectors;     /* 512-byte sector count */
	const char* vendor;   /* NULL to skip */
	const char* model;    /* NULL to skip */
	int  has_device_dir;  /* 0 = virtual (no device/ subdir) */
	int  has_node;        /* 0 = missing /dev node */
	/* USB detection: non-NULL means idVendor file present */
	const char* vid_str;
	const char* pid_str;
} FakeDev;

static void fake_sysfs_create(const char* sysfs_root, const char* dev_root,
                               const FakeDev* devs, int n)
{
	char path[1024];

	snprintf(path, sizeof(path), "%s/block", sysfs_root);
	mkdirs(path);

	for (int i = 0; i < n; i++) {
		const FakeDev* d = &devs[i];

		/* block/<name>/ */
		snprintf(path, sizeof(path), "%s/block/%s", sysfs_root, d->name);
		mkdirs(path);

		/* removable */
		snprintf(path, sizeof(path), "%s/block/%s/removable", sysfs_root, d->name);
		fake_write_file(path, d->removable ? "1\n" : "0\n");

		/* size */
		snprintf(path, sizeof(path), "%s/block/%s/size", sysfs_root, d->name);
		char sec[32]; snprintf(sec, sizeof(sec), "%llu\n", (unsigned long long)d->sectors);
		fake_write_file(path, sec);

		/* device/ subdirectory */
		if (d->has_device_dir) {
			snprintf(path, sizeof(path), "%s/block/%s/device", sysfs_root, d->name);
			mkdirs(path);

			if (d->vendor) {
				snprintf(path, sizeof(path), "%s/block/%s/device/vendor",
				         sysfs_root, d->name);
				fake_write_file(path, d->vendor);
			}
			if (d->model) {
				snprintf(path, sizeof(path), "%s/block/%s/device/model",
				         sysfs_root, d->name);
				fake_write_file(path, d->model);
			}
			if (d->vid_str) {
				snprintf(path, sizeof(path), "%s/block/%s/device/idVendor",
				         sysfs_root, d->name);
				fake_write_file(path, d->vid_str);
			}
			if (d->pid_str) {
				snprintf(path, sizeof(path), "%s/block/%s/device/idProduct",
				         sysfs_root, d->name);
				fake_write_file(path, d->pid_str);
			}
		}

		/* /dev/<name> node (empty file simulates presence) */
		if (d->has_node) {
			snprintf(path, sizeof(path), "%s/%s", dev_root, d->name);
			fake_write_file(path, "");
		}
	}
}

static void rmdir_recursive(const char* path)
{
	DIR* d = opendir(path);
	if (!d) { remove(path); return; }
	struct dirent* e;
	char sub[1024];
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
		snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
		struct stat st;
		if (stat(sub, &st) == 0 && S_ISDIR(st.st_mode))
			rmdir_recursive(sub);
		else
			remove(sub);
	}
	closedir(d);
	rmdir(path);
}

/* Create a pair of tmpdirs; caller must call cleanup */
static void make_tmpdirs(char* sysfs, char* dev)
{
	strcpy(sysfs, "/tmp/test_sysfs_XXXXXX");
	assert(mkdtemp(sysfs) != NULL);
	strcpy(dev, "/tmp/test_dev_XXXXXX");
	assert(mkdtemp(dev) != NULL);
}

/* ===== Mini test framework ===== */
static int g_pass = 0, g_fail = 0;

#define CHECK(expr) do { \
	if (expr) { g_pass++; } \
	else { g_fail++; fprintf(stderr, "FAIL [line %d]: %s\n", __LINE__, #expr); } \
} while(0)

#define CHECK_MSG(expr, msg) do { \
	if (expr) { g_pass++; } \
	else { g_fail++; fprintf(stderr, "FAIL [line %d]: %s  (%s)\n", __LINE__, msg, #expr); } \
} while(0)

/* Helper: count how many rufus_drive slots are filled */
static int count_drives(void)
{
	int n = 0;
	while (n < MAX_DRIVES && rufus_drive[n].size != 0) n++;
	return n;
}

/* Helper: find drive index by device name substring in .id */
static int find_drive_by_node_suffix(const char* suffix)
{
	for (int i = 0; i < MAX_DRIVES && rufus_drive[i].size != 0; i++) {
		if (rufus_drive[i].id && strstr(rufus_drive[i].id, suffix))
			return i;
	}
	return -1;
}

/* ===== Individual tests ===== */

/* 1. Empty /sys/block — returns TRUE but finds 0 drives */
static void test_empty_block_dir(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);
	char block[128]; snprintf(block, sizeof(block), "%s/block", sysfs);
	mkdirs(block);

	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 2. Missing /sys/block — returns FALSE */
static void test_no_block_dir(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);
	/* deliberately do NOT create /sys/block */

	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == FALSE);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 3. Single USB drive is discovered */
static void test_single_usb_drive(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	/* 8 GB removable USB drive */
	uint64_t sectors_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, sectors_8g, "Kingston  ", "DataTraveler\n", 1, 1, "0951\n", "1666\n" }
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 1);

	int idx = find_drive_by_node_suffix("sda");
	CHECK(idx >= 0);
	if (idx >= 0) {
		CHECK(rufus_drive[idx].size == sectors_8g * 512ULL);
		CHECK(rufus_drive[idx].name != NULL);
		CHECK(strstr(rufus_drive[idx].name, "Kingston") != NULL);
		CHECK(strstr(rufus_drive[idx].name, "DataTraveler") != NULL);
		CHECK(rufus_drive[idx].display_name != NULL);
		/* display_name must contain the size string */
		CHECK(strstr(rufus_drive[idx].display_name, "GB") != NULL);
		CHECK(rufus_drive[idx].index >= DRIVE_INDEX_MIN);
		CHECK(rufus_drive[idx].label != NULL);
	}

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 4. Two drives are sorted by increasing size */
static void test_two_drives_sorted_by_size(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t sectors_2g = (uint64_t)2 * 1024 * 1024 * 1024 / 512;
	uint64_t sectors_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;

	FakeDev devs[] = {
		/* sda — 8 GB (listed first in dir, but larger) */
		{ "sda", 1, sectors_8g, "Kingston  ", "DataTraveler\n", 1, 1, NULL, NULL },
		/* sdb — 2 GB (smaller; should end up at index 0 after sort) */
		{ "sdb", 1, sectors_2g, "SanDisk   ", "Cruzer Blade\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 2);

	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 2);

	/* Sorted: [0] is smaller (sdb), [1] is larger (sda) */
	CHECK(rufus_drive[0].size < rufus_drive[1].size);
	CHECK(rufus_drive[0].size == sectors_2g * 512ULL);
	CHECK(rufus_drive[1].size == sectors_8g * 512ULL);

	/* Indices assigned in sorted order */
	CHECK(rufus_drive[0].index == DRIVE_INDEX_MIN);
	CHECK(rufus_drive[1].index == DRIVE_INDEX_MIN + 1);

	/* Names match the correct drives */
	CHECK(strstr(rufus_drive[0].name, "SanDisk") != NULL);
	CHECK(strstr(rufus_drive[1].name, "Kingston") != NULL);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 5. Non-removable drive excluded when enable_HDDs is FALSE */
static void test_non_removable_excluded(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t sectors_500g = (uint64_t)500ULL * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 0, sectors_500g, "Seagate   ", "ST500DM002\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	enable_HDDs = FALSE;
	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 6. Non-removable drive included when enable_HDDs is TRUE */
static void test_non_removable_included_when_hdd_enabled(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t sectors_500g = (uint64_t)500ULL * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 0, sectors_500g, "Seagate   ", "ST500DM002\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	enable_HDDs = TRUE;
	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 1);
	enable_HDDs = FALSE; /* restore */

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 7. Drive smaller than MIN_DRIVE_SIZE is excluded */
static void test_too_small_excluded(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	/* 4 MB — below MIN_DRIVE_SIZE (8 MB) */
	uint64_t sectors_4m = (uint64_t)4 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, sectors_4m, "Test      ", "TinyDrive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 8. loop* devices are skipped */
static void test_loop_device_skipped(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t sectors_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "loop0", 1, sectors_8g, NULL, NULL, 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 9. ram* devices are skipped */
static void test_ram_device_skipped(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t sectors_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "ram0", 0, sectors_8g, NULL, NULL, 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 10. Device without a device/ subdir (virtual, e.g. dm-0) is skipped */
static void test_virtual_no_device_subdir_skipped(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t sectors_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "dm0", 1, sectors_8g, NULL, NULL, 0 /* no device/ dir */, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 11. Device without /dev node is skipped */
static void test_missing_dev_node_skipped(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t sectors_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, sectors_8g, "USB", "Drive\n", 1, 0 /* no /dev node */, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 12. Mixed bag: 2 valid, 1 loop, 1 non-removable, 1 too-small */
static void test_mixed_devices(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_2g  = (uint64_t)2  * 1024 * 1024 * 1024 / 512;
	uint64_t s_8g  = (uint64_t)8  * 1024 * 1024 * 1024 / 512;
	uint64_t s_4m  = (uint64_t)4  * 1024 * 1024 / 512;
	uint64_t s_500g = (uint64_t)500ULL * 1024 * 1024 * 1024 / 512;

	FakeDev devs[] = {
		{ "sda",   1, s_8g,   "Kingston  ", "DataTraveler\n", 1, 1, NULL, NULL },
		{ "sdb",   1, s_2g,   "SanDisk   ", "Cruzer\n",        1, 1, NULL, NULL },
		{ "loop0", 1, s_8g,   NULL, NULL,                      1, 1, NULL, NULL },
		{ "sdc",   0, s_500g, "Seagate   ", "HDD\n",           1, 1, NULL, NULL },
		{ "sdd",   1, s_4m,   "Tiny      ", "Drive\n",          1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 5);

	enable_HDDs = FALSE;
	BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 2);

	/* Sorted by size: sdb (2GB) then sda (8GB) */
	CHECK(rufus_drive[0].size == s_2g * 512ULL);
	CHECK(rufus_drive[1].size == s_8g * 512ULL);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 13. ClearDrives frees memory and zeros the array */
static void test_clear_drives(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g, "Test", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);

	ClearDrives();
	CHECK(count_drives() == 0);
	CHECK(rufus_drive[0].id == NULL);
	CHECK(rufus_drive[0].name == NULL);
	CHECK(rufus_drive[0].display_name == NULL);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 14. Drive index selection when devnum matches */
static void test_devnum_selection(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_2g = (uint64_t)2 * 1024 * 1024 * 1024 / 512;
	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g, "Big",   "Drive\n", 1, 1, NULL, NULL },
		{ "sdb", 1, s_2g, "Small", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 2);

	/* First call: populate and get drive indices */
	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 2);

	/* Second call: request the larger drive by its index */
	DWORD big_idx = rufus_drive[1].index; /* [1] is the 8GB (sorted) */
	BOOL ret = GetDevicesWithRoot(big_idx, sysfs, dev);
	CHECK(ret == TRUE);
	/* The requested drive must be in the array with matching index */
	int found = -1;
	for (int i = 0; i < MAX_DRIVES && rufus_drive[i].size != 0; i++) {
		if (rufus_drive[i].index == DRIVE_INDEX_MIN + 1)
			found = i;
	}
	CHECK(found >= 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 15. Drive name falls back to device name when vendor/model absent */
static void test_name_fallback_to_devname(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g, NULL, NULL, 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);
	CHECK(rufus_drive[0].name != NULL);
	CHECK(strcmp(rufus_drive[0].name, "sda") == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 16. Exactly MIN_DRIVE_SIZE is accepted */
static void test_exactly_min_drive_size(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	/* MIN_DRIVE_SIZE = 8 * MB = 8 * 1024 * 1024 */
	uint64_t sectors_8m = (uint64_t)8 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, sectors_8m, "Test", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 17. Display name includes human-readable size */
static void test_display_name_has_size(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_4g = (uint64_t)4 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_4g, "Test", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);
	CHECK(rufus_drive[0].display_name != NULL);
	CHECK(strstr(rufus_drive[0].display_name, "GB") != NULL);
	/* Must also contain device name */
	CHECK(strstr(rufus_drive[0].display_name, "Drive") != NULL);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 18. Multiple GetDevicesWithRoot calls don't leak memory */
static void test_repeated_calls_no_leak(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g, "Test", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	for (int i = 0; i < 5; i++) {
		BOOL ret = GetDevicesWithRoot(0, sysfs, dev);
		CHECK(ret == TRUE);
		CHECK(count_drives() == 1);
		CHECK(rufus_drive[0].name != NULL);
	}

	ClearDrives();
	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 19. zram* devices are skipped */
static void test_zram_device_skipped(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "zram0", 0, s_8g, NULL, NULL, 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 20. Three drives — all sorted correctly */
static void test_three_drives_sorted(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_1g  = (uint64_t)1  * 1024 * 1024 * 1024 / 512;
	uint64_t s_4g  = (uint64_t)4  * 1024 * 1024 * 1024 / 512;
	uint64_t s_16g = (uint64_t)16 * 1024 * 1024 * 1024 / 512;

	FakeDev devs[] = {
		{ "sdc", 1, s_16g, "Big",  "Drive\n",  1, 1, NULL, NULL },
		{ "sda", 1, s_1g,  "Tiny", "Drive\n",  1, 1, NULL, NULL },
		{ "sdb", 1, s_4g,  "Mid",  "Drive\n",  1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 3);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 3);
	CHECK(rufus_drive[0].size < rufus_drive[1].size);
	CHECK(rufus_drive[1].size < rufus_drive[2].size);
	CHECK(rufus_drive[0].index == DRIVE_INDEX_MIN);
	CHECK(rufus_drive[1].index == DRIVE_INDEX_MIN + 1);
	CHECK(rufus_drive[2].index == DRIVE_INDEX_MIN + 2);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* ===== main ===== */
int main(void)
{
	printf("=== test_dev_linux ===\n");

	test_empty_block_dir();
	test_no_block_dir();
	test_single_usb_drive();
	test_two_drives_sorted_by_size();
	test_non_removable_excluded();
	test_non_removable_included_when_hdd_enabled();
	test_too_small_excluded();
	test_loop_device_skipped();
	test_ram_device_skipped();
	test_virtual_no_device_subdir_skipped();
	test_missing_dev_node_skipped();
	test_mixed_devices();
	test_clear_drives();
	test_devnum_selection();
	test_name_fallback_to_devname();
	test_exactly_min_drive_size();
	test_display_name_has_size();
	test_repeated_calls_no_leak();
	test_zram_device_skipped();
	test_three_drives_sorted();

	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}

#endif /* __linux__ */
