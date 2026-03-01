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

/* ===== Additional tests ===== */

/* 21. One sector below MIN_DRIVE_SIZE is excluded */
static void test_one_sector_below_min_size_excluded(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	/* MIN_DRIVE_SIZE = 8 MB = 8*1024*1024 bytes; minus one sector (512 bytes) */
	uint64_t sectors = (uint64_t)8 * 1024 * 1024 / 512 - 1;
	FakeDev devs[] = {
		{ "sda", 1, sectors, "Test", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 22. Zero-sector drive is excluded */
static void test_zero_sector_excluded(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	FakeDev devs[] = {
		{ "sda", 1, 0, "Test", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 23. Vendor-only name (no model file) */
static void test_vendor_only_name(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g, "Corsair", NULL, 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);
	CHECK(rufus_drive[0].name != NULL);
	CHECK(strcmp(rufus_drive[0].name, "Corsair") == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 24. Model-only name (no vendor file) */
static void test_model_only_name(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g, NULL, "Ultra Flair\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);
	CHECK(rufus_drive[0].name != NULL);
	CHECK(strcmp(rufus_drive[0].name, "Ultra Flair") == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 25. Trailing whitespace / newlines in sysfs attrs are stripped */
static void test_whitespace_trimmed_from_attrs(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	/* sysfs writes vendor with trailing spaces and model with a newline */
	FakeDev devs[] = {
		{ "sda", 1, s_8g, "Kingston  \n", "DataTraveler   \n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);

	/* The name must not contain trailing spaces or newlines */
	const char* n = rufus_drive[0].name;
	CHECK(n != NULL);
	if (n) {
		size_t len = strlen(n);
		CHECK(len > 0);
		CHECK(n[len - 1] != ' ');
		CHECK(n[len - 1] != '\n');
		CHECK(n[len - 1] != '\r');
		/* Individual components must appear trimmed */
		CHECK(strstr(n, "Kingston") != NULL);
		CHECK(strstr(n, "DataTraveler") != NULL);
	}

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 26. devnum that matches no drive → first item selected (no crash) */
static void test_devnum_no_match_returns_true(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g, "Test", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	/* Pass an index that can't possibly match any discovered drive */
	BOOL ret = GetDevicesWithRoot(0xDEADBEEF, sysfs, dev);
	CHECK(ret == TRUE);
	CHECK(count_drives() == 1);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 27. id field is the full /dev/NAME path */
static void test_id_field_is_dev_path(void)
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

	/* id must end with "/sda" (relative to our fake dev root) */
	CHECK(rufus_drive[0].id != NULL);
	if (rufus_drive[0].id) {
		const char* p = strrchr(rufus_drive[0].id, '/');
		CHECK(p != NULL);
		if (p) CHECK(strcmp(p + 1, "sda") == 0);
	}

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 28. label field is an empty string (not NULL) */
static void test_label_field_empty_string(void)
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
	CHECK(rufus_drive[0].label != NULL);
	if (rufus_drive[0].label)
		CHECK(rufus_drive[0].label[0] == '\0');

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 29. hub field is NULL (not allocated) */
static void test_hub_field_is_null(void)
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
	CHECK(rufus_drive[0].hub == NULL);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 30. port field is 0 */
static void test_port_field_is_zero(void)
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
	CHECK(rufus_drive[0].port == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 31. sysfs entry after MAX_DRIVES valid drives is silently ignored */
static void test_max_drives_cap(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;

	/* Create MAX_DRIVES + 2 valid removable drives */
	int n = MAX_DRIVES + 2;
	for (int i = 0; i < n; i++) {
		char name[32], node[128], removable_path[256], size_path[256];
		char dev_dir[256], model_path[256], block_dir[256];

		snprintf(name, sizeof(name), "sd%c", 'a' + (i % 26));
		/* Unique names: after z, use two-char suffixes like "sda0".
		 * Keep it simple: just use indices encoded as hex in name. */
		snprintf(name, sizeof(name), "sd%04x", i);

		snprintf(block_dir, sizeof(block_dir), "%s/block/%s", sysfs, name);
		mkdirs(block_dir);

		snprintf(removable_path, sizeof(removable_path), "%s/removable", block_dir);
		fake_write_file(removable_path, "1\n");

		char sec[32]; snprintf(sec, sizeof(sec), "%llu\n",
		              (unsigned long long)(s_8g + (uint64_t)i));
		snprintf(size_path, sizeof(size_path), "%s/size", block_dir);
		fake_write_file(size_path, sec);

		snprintf(dev_dir, sizeof(dev_dir), "%s/device", block_dir);
		mkdirs(dev_dir);
		snprintf(model_path, sizeof(model_path), "%s/model", dev_dir);
		fake_write_file(model_path, "USB Drive\n");

		/* create /dev node */
		snprintf(node, sizeof(node), "%s/%s", dev, name);
		fake_write_file(node, "");
	}

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == MAX_DRIVES);

	ClearDrives();
	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 32. Calling GetDevices again after adding a drive updates the list */
static void test_list_updates_on_second_call(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	uint64_t s_4g = (uint64_t)4 * 1024 * 1024 * 1024 / 512;

	FakeDev first[] = {
		{ "sda", 1, s_8g, "First", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, first, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);

	/* Add a second drive to the fake sysfs and dev */
	FakeDev second[] = {
		{ "sdb", 1, s_4g, "Second", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, second, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 2);

	/* Sorted: sdb (4GB) first */
	CHECK(rufus_drive[0].size == s_4g * 512ULL);
	CHECK(rufus_drive[1].size == s_8g * 512ULL);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 33. NVMe-style device (nvme0n1) is discovered when enable_HDDs is TRUE */
static void test_nvme_style_device_with_hdd_enabled(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_512g = (uint64_t)512ULL * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		/* NVMe drives are typically non-removable */
		{ "nvme0n1", 0, s_512g, "Samsung", "SSD 980\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	enable_HDDs = TRUE;
	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);
	CHECK(strstr(rufus_drive[0].name, "Samsung") != NULL);
	enable_HDDs = FALSE;

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 34. NVMe device excluded when enable_HDDs is FALSE */
static void test_nvme_excluded_without_hdd_flag(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_512g = (uint64_t)512ULL * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "nvme0n1", 0, s_512g, "Samsung", "SSD 980\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	enable_HDDs = FALSE;
	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 0);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 35. SD-card style device (mmcblk0) is discovered when removable=1 */
static void test_mmcblk_device_discovered(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_32g = (uint64_t)32ULL * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "mmcblk0", 1, s_32g, "SanDisk", "SD Card\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);
	CHECK(strstr(rufus_drive[0].name, "SanDisk") != NULL);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 36. Display name contains both vendor and model */
static void test_display_name_has_vendor_and_model(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g, "Verbatim", "Store N Go\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 1);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 1);
	CHECK(rufus_drive[0].display_name != NULL);
	if (rufus_drive[0].display_name) {
		CHECK(strstr(rufus_drive[0].display_name, "Verbatim") != NULL);
		CHECK(strstr(rufus_drive[0].display_name, "Store N Go") != NULL);
		CHECK(strstr(rufus_drive[0].display_name, "GB") != NULL);
	}

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 37. Two drives with identical sizes: both discovered, order stable */
static void test_two_drives_same_size(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g = (uint64_t)8 * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g, "VendorA", "Model1\n", 1, 1, NULL, NULL },
		{ "sdb", 1, s_8g, "VendorB", "Model2\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 2);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 2);
	CHECK(rufus_drive[0].size == s_8g * 512ULL);
	CHECK(rufus_drive[1].size == s_8g * 512ULL);
	/* Both must have valid indices */
	CHECK(rufus_drive[0].index >= DRIVE_INDEX_MIN);
	CHECK(rufus_drive[1].index >= DRIVE_INDEX_MIN);
	CHECK(rufus_drive[0].index != rufus_drive[1].index);

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 38. drive_index values are contiguous from DRIVE_INDEX_MIN */
static void test_drive_indices_are_contiguous(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_1g = (uint64_t)1  * 1024 * 1024 * 1024 / 512;
	uint64_t s_2g = (uint64_t)2  * 1024 * 1024 * 1024 / 512;
	uint64_t s_4g = (uint64_t)4  * 1024 * 1024 * 1024 / 512;
	uint64_t s_8g = (uint64_t)8  * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sdd", 1, s_8g, "D", "Drive\n", 1, 1, NULL, NULL },
		{ "sdc", 1, s_4g, "C", "Drive\n", 1, 1, NULL, NULL },
		{ "sdb", 1, s_2g, "B", "Drive\n", 1, 1, NULL, NULL },
		{ "sda", 1, s_1g, "A", "Drive\n", 1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 4);

	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 4);
	for (int i = 0; i < 4; i++)
		CHECK(rufus_drive[i].index == (DWORD)(DRIVE_INDEX_MIN + i));

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 39. enable_HDDs=TRUE: both removable and non-removable drives found */
static void test_enable_hdds_includes_both_types(void)
{
	char sysfs[64], dev[64];
	make_tmpdirs(sysfs, dev);

	uint64_t s_8g   = (uint64_t)8   * 1024 * 1024 * 1024 / 512;
	uint64_t s_500g = (uint64_t)500ULL * 1024 * 1024 * 1024 / 512;
	FakeDev devs[] = {
		{ "sda", 1, s_8g,   "USB",  "Flash\n",    1, 1, NULL, NULL },
		{ "sdb", 0, s_500g, "WD",   "My Book\n",  1, 1, NULL, NULL },
	};
	fake_sysfs_create(sysfs, dev, devs, 2);

	enable_HDDs = TRUE;
	GetDevicesWithRoot(0, sysfs, dev);
	CHECK(count_drives() == 2);
	/* sorted: USB flash (8GB) before HDD (500GB) */
	CHECK(rufus_drive[0].size < rufus_drive[1].size);
	enable_HDDs = FALSE;

	rmdir_recursive(sysfs); rmdir_recursive(dev);
}

/* 40. ClearDrives on already-empty array is safe */
static void test_clear_drives_idempotent(void)
{
	ClearDrives();
	CHECK(count_drives() == 0);
	ClearDrives(); /* must not crash or double-free */
	CHECK(count_drives() == 0);
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
	test_one_sector_below_min_size_excluded();
	test_zero_sector_excluded();
	test_vendor_only_name();
	test_model_only_name();
	test_whitespace_trimmed_from_attrs();
	test_devnum_no_match_returns_true();
	test_id_field_is_dev_path();
	test_label_field_empty_string();
	test_hub_field_is_null();
	test_port_field_is_zero();
	test_max_drives_cap();
	test_list_updates_on_second_call();
	test_nvme_style_device_with_hdd_enabled();
	test_nvme_excluded_without_hdd_flag();
	test_mmcblk_device_discovered();
	test_display_name_has_vendor_and_model();
	test_two_drives_same_size();
	test_drive_indices_are_contiguous();
	test_enable_hdds_includes_both_types();
	test_clear_drives_idempotent();

	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}

#endif /* __linux__ */
