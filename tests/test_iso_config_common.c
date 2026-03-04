/*
 * test_iso_config_common.c — Cross-platform tests for iso_patch_config_file()
 *
 * Tests the portable config-file patching logic from src/common/iso_config.c.
 * These tests compile and run on both Linux (GCC) and Windows/Wine (MinGW).
 *
 * On Linux: uses linux/parser.c for replace_in_token_data.
 * On Windows/Wine: uses windows/parser.c for replace_in_token_data.
 * replace_char (from common/parser.c) is provided as an inline stub to
 * avoid conflicts with Windows PE-parsing headers in common/parser.c.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include "../src/windows/rufus.h"
#include "../src/windows/missing.h"
#include "../src/windows/msapi_utf8.h"
#include "../src/windows/localization.h"
#else
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#endif

#include "../src/common/iso_config.h"

/* Platform path separator string */
#ifdef _WIN32
#define PATH_SEP_STR "\\"
#else
#define PATH_SEP_STR "/"
#endif

/* ---- Minimal stubs ---------------------------------------------------- */

windows_version_t WindowsVersion;
RUFUS_UPDATE update;
RUFUS_IMG_REPORT img_report;
char szFolderPath[MAX_PATH], app_dir[MAX_PATH], temp_dir[MAX_PATH], system_dir[MAX_PATH];
BOOL right_to_left_mode = FALSE;
BOOL en_msg_mode = FALSE;
void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s) { (void)s; }
char *lmprintf(uint32_t id, ...) { (void)id; return ""; }

/*
 * replace_char — self-contained copy from common/parser.c.
 * On Wine/MinGW we cannot link common/parser.c because its PE-parsing
 * functions conflict with the Windows headers, so we inline it here.
 */
char *replace_char(const char *src, const char c, const char *rep)
{
	size_t i, j, k, count = 0;
	size_t str_len = src ? strlen(src) : 0;
	size_t rep_len = rep ? strlen(rep) : 0;
	char *res;

	if (!src || !rep)
		return NULL;
	for (i = 0; i < str_len; i++)
		if (src[i] == c) count++;
	res = (char *)malloc(str_len + count * rep_len + 1);
	if (!res) return NULL;
	for (i = 0, j = 0; i < str_len; i++) {
		if (src[i] == c) {
			for (k = 0; k < rep_len; k++) res[j++] = rep[k];
		} else {
			res[j++] = src[i];
		}
	}
	res[j] = '\0';
	return res;
}

/* ---- Cross-platform temp file helpers --------------------------------- */

#ifdef _WIN32
static char *make_tempfile(const char *content)
{
	char tmp_dir[MAX_PATH], tmp_path[MAX_PATH];
	GetTempPathA(MAX_PATH, tmp_dir);
	GetTempFileNameA(tmp_dir, "ruf", 0, tmp_path);
	FILE *f = fopen(tmp_path, "w");
	if (!f) return NULL;
	fputs(content, f);
	fclose(f);
	return strdup(tmp_path);
}
static void delete_tempfile(char *path)
{
	if (path) { DeleteFileA(path); free(path); }
}

static char *make_tempdir(void)
{
	char tmp_dir[MAX_PATH], dir_path[MAX_PATH];
	GetTempPathA(MAX_PATH, tmp_dir);
	/* Use GetTempFileName to get a unique name, then repurpose as dir */
	char tmp_name[MAX_PATH];
	GetTempFileNameA(tmp_dir, "ruf", 0, tmp_name);
	DeleteFileA(tmp_name);
	if (!CreateDirectoryA(tmp_name, NULL)) return NULL;
	strncpy(dir_path, tmp_name, MAX_PATH - 1);
	return strdup(dir_path);
}
static void delete_tempdir(char *dir)
{
	if (!dir) return;
	/* Remove all files then the dir */
	char pattern[MAX_PATH];
	snprintf(pattern, MAX_PATH, "%s\\*", dir);
	WIN32_FIND_DATAA fd;
	HANDLE h = FindFirstFileA(pattern, &fd);
	if (h != INVALID_HANDLE_VALUE) {
		do {
			if (strcmp(fd.cFileName, ".") && strcmp(fd.cFileName, "..")) {
				char full[MAX_PATH];
				snprintf(full, MAX_PATH, "%s\\%s", dir, fd.cFileName);
				DeleteFileA(full);
			}
		} while (FindNextFileA(h, &fd));
		FindClose(h);
	}
	RemoveDirectoryA(dir);
	free(dir);
}
static BOOL win32_copy_fn(const char *src, const char *dst)
{
	return CopyFileA(src, dst, FALSE);
}
#define platform_copy_fn win32_copy_fn

#else  /* Linux */
#include <unistd.h>
#include <fcntl.h>

static char *make_tempfile(const char *content)
{
	char *path = strdup("/tmp/rufus_cfg_test_XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) { free(path); return NULL; }
	size_t len = strlen(content);
	if (write(fd, content, len) != (ssize_t)len) {
		close(fd); unlink(path); free(path); return NULL;
	}
	close(fd);
	return path;
}
static void delete_tempfile(char *path)
{
	if (path) { unlink(path); free(path); }
}

static char *make_tempdir(void)
{
	char *dir = strdup("/tmp/rufus_tails_XXXXXX");
	if (!mkdtemp(dir)) { free(dir); return NULL; }
	return dir;
}
static void delete_tempdir(char *dir)
{
	if (!dir) return;
	/* Caller removes files before calling us */
	rmdir(dir);
	free(dir);
}
static BOOL posix_copy_fn(const char *src, const char *dst)
{
	FILE *in = fopen(src, "rb"), *out = fopen(dst, "wb");
	if (!in || !out) { if (in) fclose(in); if (out) fclose(out); return FALSE; }
	char buf[4096]; size_t n;
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) fwrite(buf, 1, n, out);
	fclose(in); fclose(out); return TRUE;
}
#define platform_copy_fn posix_copy_fn
#endif  /* _WIN32 */

/* Read an entire file into a malloc'd buffer. */
static char *read_file_str(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	rewind(f);
	char *buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	size_t n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[n] = '\0';
	return buf;
}

/* Convenience: build a zeroed EXTRACT_PROPS */
static EXTRACT_PROPS make_props(BOOL is_cfg, BOOL is_syslinux_cfg,
                                BOOL is_grub_cfg, BOOL is_conf,
                                BOOL is_menu_cfg)
{
	EXTRACT_PROPS p;
	memset(&p, 0, sizeof(p));
	p.is_cfg          = is_cfg;
	p.is_syslinux_cfg = is_syslinux_cfg;
	p.is_grub_cfg     = is_grub_cfg;
	p.is_conf         = is_conf;
	p.is_menu_cfg     = is_menu_cfg;
	return p;
}

/* ======================================================================
 * 1. NULL / empty-path guard
 * ====================================================================== */
TEST(null_path_is_noop)
{
	EXTRACT_PROPS p = make_props(TRUE, FALSE, FALSE, FALSE, FALSE);
	BOOL r = iso_patch_config_file(NULL, "/boot", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "ISO_LABEL", "USB_LABEL",
	                               "/image.iso", NULL, NULL);
	CHECK(!r);
}

TEST(empty_path_is_noop)
{
	EXTRACT_PROPS p = make_props(TRUE, FALSE, FALSE, FALSE, FALSE);
	BOOL r = iso_patch_config_file("", "/boot", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "ISO_LABEL", "USB_LABEL",
	                               "/image.iso", NULL, NULL);
	CHECK(!r);
}

TEST(null_props_is_noop)
{
	char *path = make_tempfile("linux /vmlinuz boot=live\n");
	CHECK(path != NULL);
	BOOL r = iso_patch_config_file(path, "/boot", "grub.cfg", NULL,
	                               BT_IMAGE, 1024*1024, TRUE, FALSE, FALSE,
	                               "ISO_LABEL", "USB_LABEL",
	                               "/image.iso", NULL, NULL);
	CHECK(!r);
	delete_tempfile(path);
}

/* ======================================================================
 * 2. No modification when labels are equal
 * ====================================================================== */
TEST(label_same_no_modification)
{
	const char *content = "linux /vmlinuz boot=MY_LABEL\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, FALSE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "MY_LABEL", "MY_LABEL",
	                               "/image.iso", &mf, NULL);
	CHECK(!r);
	CHECK_INT_EQ((int)mf.Index, 0);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 3. Label replacement — grub.cfg
 * ====================================================================== */
TEST(label_replace_grub_append)
{
	const char *content =
		"linux /vmlinuz root=live:CDLABEL=UBUNTU_20_04 quiet splash\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, FALSE, TRUE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "UBUNTU_20_04", "MY_USB",
	                               "/image.iso", &mf, NULL);
	CHECK(r);
	CHECK_INT_EQ((int)mf.Index, 1);

	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "MY_USB") != NULL);
	CHECK(strstr(result, "UBUNTU_20_04") == NULL);
	free(result);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

TEST(label_replace_with_spaces_as_x20)
{
	const char *content =
		"append root=live:CDLABEL=Ubuntu\\x2022.04 quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, TRUE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot", "syslinux.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "Ubuntu 22.04", "MY USB",
	                               "/image.iso", &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "MY\\x20USB") != NULL);
	CHECK(strstr(result, "Ubuntu\\x2022.04") == NULL);
	free(result);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 4. Persistence — Ubuntu grub
 * ====================================================================== */
TEST(persistence_ubuntu_grub)
{
	const char *content =
		"linux /vmlinuz file=/cdrom/preseed/ubuntu.seed maybe-ubiquity quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, FALSE, TRUE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_IMAGE, 4096ULL * 1024 * 1024,
	                               TRUE, FALSE, FALSE,
	                               "UBUNTU_ISO", "MY_USB",
	                               "/ubuntu.iso", &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "persistent") != NULL);
	free(result);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 5. Persistence — Linux Mint casper
 * ====================================================================== */
TEST(persistence_mint_casper)
{
	const char *content = "append boot=casper quiet splash\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, TRUE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/isolinux", "isolinux.cfg", &p,
	                               BT_IMAGE, 2ULL * 1024 * 1024 * 1024,
	                               TRUE, FALSE, FALSE,
	                               "LINUXMINT", "MY_USB",
	                               "/linuxmint.iso", &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "boot=casper persistent") != NULL);
	free(result);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 6. Persistence — Debian live
 * ====================================================================== */
TEST(persistence_debian_live)
{
	const char *content = "linux /vmlinuz boot=live quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, FALSE, TRUE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_IMAGE, 2ULL * 1024 * 1024 * 1024,
	                               TRUE, FALSE, FALSE,
	                               "DEBIAN", "MY_USB",
	                               "/debian.iso", &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "boot=live persistence") != NULL);
	free(result);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 7. No persistence when persistence_size == 0
 * ====================================================================== */
TEST(persistence_disabled_when_size_zero)
{
	const char *content = "linux /vmlinuz file=/cdrom/preseed/ubuntu.seed\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, FALSE, TRUE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "UBUNTU_ISO", "MY_USB",
	                               "/image.iso", &mf, NULL);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "persistent") == NULL);
	free(result);
	(void)r;

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 8. Red Hat inst.stage2 → inst.repo
 * ====================================================================== */
TEST(rh8_inst_stage2_replaced)
{
	const char *content = "append inst.stage2=cdrom quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, TRUE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/isolinux", "isolinux.cfg", &p,
	                               BT_IMAGE, 0, FALSE,
	                               TRUE, FALSE,
	                               "RHEL_ISO", "MY_USB",
	                               "/rhel.iso", &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "inst.repo") != NULL);
	CHECK(strstr(result, "inst.stage2") == NULL);
	free(result);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

TEST(rh8_netinst_not_replaced)
{
	const char *content = "append inst.stage2=cdrom quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, TRUE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/isolinux", "isolinux.cfg", &p,
	                               BT_IMAGE, 0, FALSE, TRUE, FALSE,
	                               "RHEL_ISO", "MY_USB",
	                               "/fedora-37-netinst.iso", &mf, NULL);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "inst.stage2") != NULL);
	free(result);
	(void)r;

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 9. FreeNAS cd9660 → msdosfs path fix
 * ====================================================================== */
TEST(freenas_cd9660_patched)
{
	const char *content = "set root='cd9660:/dev/iso9660/FREENAS'\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(FALSE, FALSE, TRUE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "FREENAS", "FREENAS_USB",
	                               "/freenas.iso", &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "msdosfs:/dev/msdosfs/FREENAS_USB") != NULL);
	CHECK(strstr(result, "cd9660:/dev/iso9660/FREENAS") == NULL);
	free(result);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 10. Tails dual BIOS+EFI workaround
 * ====================================================================== */
TEST(tails_isolinux_cfg_duplicated_to_syslinux_cfg)
{
	const char *content = "DEFAULT vesamenu.c32\nLABEL live\n";
	char *tmp_dir = make_tempdir();
	CHECK(tmp_dir != NULL);

	char iso_path[512], sys_path[512];
	snprintf(iso_path, sizeof(iso_path), "%s%sisolinux.cfg",
	         tmp_dir, PATH_SEP_STR);
	snprintf(sys_path, sizeof(sys_path), "%s%ssyslinux.cfg",
	         tmp_dir, PATH_SEP_STR);

	FILE *f = fopen(iso_path, "w");
	CHECK(f != NULL);
	fputs(content, f);
	fclose(f);

	EXTRACT_PROPS p = make_props(FALSE, TRUE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	iso_patch_config_file(iso_path, "/efi/boot", "isolinux.cfg", &p,
	                      BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                      "ISO_LBL", "USB_LBL",
	                      "/image.iso", &mf, platform_copy_fn);

	/* Verify the copy was made */
#ifdef _WIN32
	DWORD attr = GetFileAttributesA(sys_path);
	CHECK(attr != INVALID_FILE_ATTRIBUTES);
#else
	CHECK(access(sys_path, F_OK) == 0);
#endif

	char *sys_content = read_file_str(sys_path);
	CHECK(sys_content != NULL);
	CHECK(strstr(sys_content, "DEFAULT vesamenu.c32") != NULL);
	free(sys_content);

	/* Cleanup */
#ifdef _WIN32
	DeleteFileA(iso_path);
	DeleteFileA(sys_path);
	delete_tempdir(tmp_dir);
#else
	unlink(iso_path);
	unlink(sys_path);
	delete_tempdir(tmp_dir);
#endif
	StrArrayDestroy(&mf);
}

TEST(tails_copy_skipped_when_efi_syslinux_present)
{
	char *tmp_dir = make_tempdir();
	CHECK(tmp_dir != NULL);

	char iso_path[512], sys_path[512];
	snprintf(iso_path, sizeof(iso_path), "%s%sisolinux.cfg",
	         tmp_dir, PATH_SEP_STR);
	snprintf(sys_path, sizeof(sys_path), "%s%ssyslinux.cfg",
	         tmp_dir, PATH_SEP_STR);

	FILE *f = fopen(iso_path, "w");
	CHECK(f != NULL);
	fputs("DEFAULT vesamenu.c32\n", f);
	fclose(f);

	EXTRACT_PROPS p = make_props(FALSE, TRUE, FALSE, FALSE, FALSE);

	iso_patch_config_file(iso_path, "/efi/boot", "isolinux.cfg", &p,
	                      BT_IMAGE, 0, FALSE, FALSE,
	                      TRUE,  /* has_efi_syslinux — skip copy */
	                      "ISO", "USB",
	                      "/image.iso", NULL, platform_copy_fn);

	/* syslinux.cfg must NOT have been created */
#ifdef _WIN32
	DWORD attr = GetFileAttributesA(sys_path);
	CHECK(attr == INVALID_FILE_ATTRIBUTES);
#else
	CHECK(access(sys_path, F_OK) != 0);
#endif

#ifdef _WIN32
	DeleteFileA(iso_path);
	delete_tempdir(tmp_dir);
#else
	unlink(iso_path);
	delete_tempdir(tmp_dir);
#endif
}

/* ======================================================================
 * 11. modified_files list populated correctly
 * ====================================================================== */
TEST(modified_files_populated)
{
	const char *content = "linux /vmlinuz MYISO quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, FALSE, TRUE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "MYISO", "MYUSB",
	                               "/image.iso", &mf, NULL);
	CHECK(r);
	CHECK(mf.Index >= 1);
	int found = 0;
	for (uint32_t i = 0; i < mf.Index; i++)
		if (mf.String[i] && strcmp(mf.String[i], path) == 0)
			found = 1;
	CHECK(found);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

TEST(unmodified_file_not_in_modified_list)
{
	const char *content = "# just a comment\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, FALSE, TRUE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "SOMEISO", "SOMEUSB",
	                               "/image.iso", &mf, NULL);
	CHECK(!r);
	CHECK_INT_EQ((int)mf.Index, 0);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 12. is_cfg=FALSE means no label replacement
 * ====================================================================== */
TEST(no_label_replace_when_not_cfg)
{
	const char *content = "linux /vmlinuz root=CDLABEL=MY_ISO quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(FALSE, FALSE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot", "somefile", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "MY_ISO", "MY_USB",
	                               "/image.iso", &mf, NULL);
	CHECK(!r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "MY_ISO") != NULL);
	free(result);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 13. Persistence skipped when boot_type != BT_IMAGE
 * ====================================================================== */
TEST(persistence_skipped_when_not_bt_image)
{
	const char *content = "linux /vmlinuz file=/cdrom/preseed/ubuntu.seed\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, FALSE, TRUE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_SYSLINUX_V4, 2ULL * 1024 * 1024 * 1024,
	                               TRUE, FALSE, FALSE,
	                               "UBUNTU_ISO", "MY_USB",
	                               "/image.iso", &mf, NULL);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "persistent") == NULL);
	free(result);
	(void)r;

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

/* ======================================================================
 * 14. Multiple replacements in the same file
 * ====================================================================== */
TEST(multiple_label_occurrences_all_replaced)
{
	const char *content =
		"linux /vmlinuz root=live:CDLABEL=MYISO quiet\n"
		"search --no-floppy --label MYISO\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, FALSE, TRUE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "MYISO", "MYUSB",
	                               "/image.iso", &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "MYUSB") != NULL);
	CHECK(strstr(result, "MYISO") == NULL);
	free(result);

	StrArrayDestroy(&mf);
	delete_tempfile(path);
}

int main(void)
{
	printf("=== iso_config common ===\n\n");

	RUN(null_path_is_noop);
	RUN(empty_path_is_noop);
	RUN(null_props_is_noop);
	RUN(label_same_no_modification);
	RUN(label_replace_grub_append);
	RUN(label_replace_with_spaces_as_x20);
	RUN(persistence_ubuntu_grub);
	RUN(persistence_mint_casper);
	RUN(persistence_debian_live);
	RUN(persistence_disabled_when_size_zero);
	RUN(rh8_inst_stage2_replaced);
	RUN(rh8_netinst_not_replaced);
	RUN(freenas_cd9660_patched);
	RUN(tails_isolinux_cfg_duplicated_to_syslinux_cfg);
	RUN(tails_copy_skipped_when_efi_syslinux_present);
	RUN(modified_files_populated);
	RUN(unmodified_file_not_in_modified_list);
	RUN(no_label_replace_when_not_cfg);
	RUN(persistence_skipped_when_not_bt_image);
	RUN(multiple_label_occurrences_all_replaced);

	TEST_RESULTS();
}
