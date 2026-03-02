/*
 * test_iso_config_linux.c — Tests for iso_patch_config_file()
 *
 * Tests the portable config-file patching logic from src/common/iso_config.c.
 * We compile against src/linux/parser.c (for replace_in_token_data) and
 * src/common/parser.c (for replace_char), so these are Linux tests only.
 *
 * All tests create temporary files, call iso_patch_config_file, read the
 * result back and assert on the content.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/common/iso_config.h"

/* ---- Minimal stubs ---------------------------------------------------- */

void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s)       { (void)s; }

/* parser.c references these globals */
windows_version_t WindowsVersion = {0};
RUFUS_UPDATE update = {{0}, {0}, NULL, NULL};
BOOL en_msg_mode = FALSE;
BOOL right_to_left_mode = FALSE;

/* ---- Helpers ----------------------------------------------------------- */

/* Write content to a temp file and return a malloc'd path, or NULL on error. */
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

/* Read the entire content of a file into a malloc'd buffer. */
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
	p.is_cfg         = is_cfg;
	p.is_syslinux_cfg = is_syslinux_cfg;
	p.is_grub_cfg    = is_grub_cfg;
	p.is_conf        = is_conf;
	p.is_menu_cfg    = is_menu_cfg;
	return p;
}

/* Platform copy_fn for the tails test */
static BOOL posix_copy_fn(const char *src, const char *dst)
{
	FILE *in  = fopen(src, "rb");
	FILE *out = fopen(dst, "wb");
	if (!in || !out) { if (in) fclose(in); if (out) fclose(out); return FALSE; }
	char buf[4096];
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
		fwrite(buf, 1, n, out);
	fclose(in);
	fclose(out);
	return TRUE;
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
	unlink(path); free(path);
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
	                               "MY_LABEL", "MY_LABEL",  /* same label */
	                               "/image.iso", &mf, NULL);
	CHECK(!r);
	CHECK_INT_EQ((int)mf.Index, 0);

	StrArrayDestroy(&mf);
	unlink(path); free(path);
}

/* ======================================================================
 * 3. Label replacement — grub.cfg
 * ====================================================================== */
TEST(label_replace_grub_append)
{
	/* A grub.cfg where 'linux' token contains the ISO label */
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
	unlink(path); free(path);
}

TEST(label_replace_with_spaces_as_x20)
{
	/* Label with space: "Ubuntu 22.04" → "\\x20" separated */
	const char *content =
		"append root=live:CDLABEL=Ubuntu\\x2022.04 quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, TRUE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot", "syslinux.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "Ubuntu 22.04", "MY USB",  /* spaces */
	                               "/image.iso", &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	/* After replacement "\\x20" encoded USB label should appear */
	CHECK(strstr(result, "MY\\x20USB") != NULL);
	CHECK(strstr(result, "Ubuntu\\x2022.04") == NULL);
	free(result);

	StrArrayDestroy(&mf);
	unlink(path); free(path);
}

/* ======================================================================
 * 4. Persistence — Ubuntu grub (file=/cdrom/preseed)
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
	                               TRUE /* has_persistence */,
	                               FALSE, FALSE,
	                               "UBUNTU_ISO", "MY_USB",
	                               "/ubuntu.iso", &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "persistent") != NULL);
	free(result);

	StrArrayDestroy(&mf);
	unlink(path); free(path);
}

/* ======================================================================
 * 5. Persistence — Linux Mint (boot=casper)
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
	unlink(path); free(path);
}

/* ======================================================================
 * 6. Persistence — Debian (boot=live)
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
	unlink(path); free(path);
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

	/* persistence_size = 0 AND has_persistence = FALSE */
	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "UBUNTU_ISO", "MY_USB",
	                               "/image.iso", &mf, NULL);
	/* May or may not be modified due to label replacement, but 'persistent'
	 * keyword must NOT be injected. */
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "persistent") == NULL);
	free(result);

	StrArrayDestroy(&mf);
	unlink(path); free(path);
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
	                               TRUE  /* rh8_derivative */,
	                               FALSE,
	                               "RHEL_ISO", "MY_USB",
	                               "/rhel.iso" /* NOT a netinst */, &mf, NULL);
	CHECK(r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "inst.repo") != NULL);
	CHECK(strstr(result, "inst.stage2") == NULL);
	free(result);

	StrArrayDestroy(&mf);
	unlink(path); free(path);
}

TEST(rh8_netinst_not_replaced)
{
	const char *content = "append inst.stage2=cdrom quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	EXTRACT_PROPS p = make_props(TRUE, TRUE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	/* image_path contains "netinst" → skip the replacement */
	BOOL r = iso_patch_config_file(path, "/isolinux", "isolinux.cfg", &p,
	                               BT_IMAGE, 0, FALSE,
	                               TRUE /* rh8_derivative */,
	                               FALSE,
	                               "RHEL_ISO", "MY_USB",
	                               "/fedora-37-netinst.iso", &mf, NULL);

	char *result = read_file_str(path);
	CHECK(result != NULL);
	/* 'inst.stage2' must NOT be replaced for netinst */
	CHECK(strstr(result, "inst.stage2") != NULL);
	free(result);

	StrArrayDestroy(&mf);
	unlink(path); free(path);
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
	unlink(path); free(path);
}

/* ======================================================================
 * 10. Tails dual BIOS+EFI workaround
 * ====================================================================== */
TEST(tails_isolinux_cfg_duplicated_to_syslinux_cfg)
{
	/* Create a temp file whose path ends in "isolinux.cfg" (12 chars) */
	const char *content = "DEFAULT vesamenu.c32\nLABEL live\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	/* Rename the temp file so its basename is "isolinux.cfg" */
	size_t len = strlen(path);
	/* Replace last 6 chars with "is.cfg" — instead build a proper path */
	char iso_path[512], sys_path[512];
	/* Use a directory */
	char dir[] = "/tmp/rufus_tails_XXXXXX";
	char *tmp_dir = mkdtemp(dir);
	CHECK(tmp_dir != NULL);
	snprintf(iso_path, sizeof(iso_path), "%s/isolinux.cfg", tmp_dir);
	snprintf(sys_path, sizeof(sys_path), "%s/syslinux.cfg", tmp_dir);

	/* Write the config file */
	FILE *f = fopen(iso_path, "w");
	CHECK(f != NULL);
	fputs(content, f);
	fclose(f);

	EXTRACT_PROPS p = make_props(FALSE, TRUE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(iso_path, "/efi/boot", "isolinux.cfg", &p,
	                               BT_IMAGE, 0, FALSE, FALSE,
	                               FALSE /* has_efi_syslinux */,
	                               "ISO_LBL", "USB_LBL",
	                               "/image.iso", &mf, posix_copy_fn);
	/* The copy should have happened */
	CHECK(access(sys_path, F_OK) == 0);

	/* Verify content of the copy */
	char *sys_content = read_file_str(sys_path);
	CHECK(sys_content != NULL);
	CHECK(strstr(sys_content, "DEFAULT vesamenu.c32") != NULL);
	free(sys_content);

	unlink(iso_path);
	unlink(sys_path);
	rmdir(tmp_dir);
	StrArrayDestroy(&mf);
	free(path);
	(void)r;
}

TEST(tails_copy_skipped_when_efi_syslinux_present)
{
	char dir[] = "/tmp/rufus_tails2_XXXXXX";
	char *tmp_dir = mkdtemp(dir);
	CHECK(tmp_dir != NULL);

	char iso_path[512], sys_path[512];
	snprintf(iso_path, sizeof(iso_path), "%s/isolinux.cfg", tmp_dir);
	snprintf(sys_path, sizeof(sys_path), "%s/syslinux.cfg", tmp_dir);

	FILE *f = fopen(iso_path, "w"); CHECK(f != NULL);
	fputs("DEFAULT vesamenu.c32\n", f);
	fclose(f);

	EXTRACT_PROPS p = make_props(FALSE, TRUE, FALSE, FALSE, FALSE);

	iso_patch_config_file(iso_path, "/efi/boot", "isolinux.cfg", &p,
	                      BT_IMAGE, 0, FALSE, FALSE,
	                      TRUE /* has_efi_syslinux — skip the copy */,
	                      "ISO", "USB",
	                      "/image.iso", NULL, posix_copy_fn);

	/* syslinux.cfg must NOT have been created */
	CHECK(access(sys_path, F_OK) != 0);

	unlink(iso_path);
	rmdir(tmp_dir);
}

/* ======================================================================
 * 11. modified_files list is populated correctly
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
	/* The modified path should match what we passed */
	int found = 0;
	for (uint32_t i = 0; i < mf.Index; i++)
		if (mf.String[i] && strcmp(mf.String[i], path) == 0)
			found = 1;
	CHECK(found);

	StrArrayDestroy(&mf);
	unlink(path); free(path);
}

TEST(unmodified_file_not_in_modified_list)
{
	/* Content has no matching tokens for either the label or persistence */
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
	unlink(path); free(path);
}

/* ======================================================================
 * 12. is_cfg=FALSE means no label replacement
 * ====================================================================== */
TEST(no_label_replace_when_not_cfg)
{
	const char *content = "linux /vmlinuz root=CDLABEL=MY_ISO quiet\n";
	char *path = make_tempfile(content);
	CHECK(path != NULL);

	/* is_cfg = FALSE → label replacement skipped */
	EXTRACT_PROPS p = make_props(FALSE, FALSE, FALSE, FALSE, FALSE);
	StrArray mf; StrArrayCreate(&mf, 4);

	BOOL r = iso_patch_config_file(path, "/boot", "somefile", &p,
	                               BT_IMAGE, 0, FALSE, FALSE, FALSE,
	                               "MY_ISO", "MY_USB",
	                               "/image.iso", &mf, NULL);
	CHECK(!r);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "MY_ISO") != NULL);  /* unchanged */
	free(result);

	StrArrayDestroy(&mf);
	unlink(path); free(path);
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

	/* boot_type = BT_SYSLINUX_V4 (not BT_IMAGE) */
	BOOL r = iso_patch_config_file(path, "/boot/grub", "grub.cfg", &p,
	                               BT_SYSLINUX_V4, 2ULL * 1024 * 1024 * 1024,
	                               TRUE, FALSE, FALSE,
	                               "UBUNTU_ISO", "MY_USB",
	                               "/image.iso", &mf, NULL);
	char *result = read_file_str(path);
	CHECK(result != NULL);
	CHECK(strstr(result, "persistent") == NULL);
	free(result);

	StrArrayDestroy(&mf);
	unlink(path); free(path);
}

/* ======================================================================
 * 14. Multiple replacements in the same file
 * ====================================================================== */
TEST(multiple_label_occurrences_all_replaced)
{
	/* Two lines both containing the ISO label */
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
	unlink(path); free(path);
}

int main(void)
{
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
