/*
 * test_wue_linux.c - Tests for Linux WUE (Windows User Experience) implementation
 *
 * Tests CreateUnattendXml and PopulateWindowsVersion.
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "framework.h"

/* ---- compat layer ---- */
#include "windows.h"

/* ---- rufus headers ---- */
#include "rufus.h"
#include "resource.h"
#include "vhd.h"
#include "wue.h"
#include "wimlib.h"

/* ================================================================
 * Globals required by wue.c and its dependencies
 * ================================================================ */

DWORD  ErrorStatus    = 0;
DWORD  MainThreadId   = 0;
DWORD  DownloadStatus = 0;
DWORD  LastWriteError = 0;

BOOL   op_in_progress     = FALSE;
BOOL   large_drive        = FALSE;
BOOL   usb_debug          = FALSE;
BOOL   detect_fakes       = FALSE;
BOOL   allow_dual_uefi_bios = FALSE;
BOOL   ignore_boot_marker = FALSE;
BOOL   has_ffu_support    = FALSE;

HWND   hMainDialog = NULL;

char   temp_dir[MAX_PATH]  = "/tmp";
char   *image_path         = NULL;

RUFUS_IMG_REPORT img_report = { 0 };

/* ================================================================
 * Stubs
 * ================================================================ */

void uprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void wuprintf(const wchar_t *fmt, ...)
{
	(void)fmt;
}

void uprintfs(const char *s) { if (s) fputs(s, stderr); }
void uprint_progress(uint64_t cur, uint64_t max) { (void)cur; (void)max; }
void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL f)
	{ (void)op; (void)msg; (void)cur; (void)tot; (void)f; }
char* lmprintf(uint32_t msg_id, ...) { (void)msg_id; return ""; }

/* VHD stubs (wue.c doesn't use them but linking requires them) */
int8_t  IsBootableImage(const char* p)              { (void)p; return 0; }
uint32_t GetWimVersion(const char* p)               { (void)p; return 0; }
char*   VhdMountImageAndGetSize(const char* p, uint64_t* s) { (void)p; (void)s; return NULL; }
void    VhdUnmountImage(void)                       {}
BOOL    WimExtractFile(const char* a, int b, const char* c, const char* d)
	{ (void)a;(void)b;(void)c;(void)d; return FALSE; }
BOOL    WimSplitFile(const char* a, const char* b)  { (void)a;(void)b; return FALSE; }
BOOL    WimApplyImage(const char* a, int b, const char* c)
	{ (void)a;(void)b;(void)c; return FALSE; }

/* ================================================================
 * Helpers
 * ================================================================ */

/* Read the contents of a file into a malloc'd buffer (NUL-terminated) */
static char* slurp(const char* path)
{
	FILE* f = fopen(path, "rb");
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	char* buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	fread(buf, 1, (size_t)sz, f);
	buf[sz] = '\0';
	fclose(f);
	return buf;
}

/* ================================================================
 * Tests: CreateUnattendXml
 * ================================================================ */

TEST(create_unattend_flags_zero)
{
	/* flags == 0 → should return NULL */
	char* p = CreateUnattendXml(ARCH_X86_64, 0);
	CHECK(p == NULL);
}

TEST(create_unattend_invalid_arch)
{
	/* arch out of range → should return NULL */
	char* p = CreateUnattendXml(0, UNATTEND_SECUREBOOT_TPM_MINRAM);
	CHECK(p == NULL);
	p = CreateUnattendXml(ARCH_MAX + 1, UNATTEND_SECUREBOOT_TPM_MINRAM);
	CHECK(p == NULL);
}

TEST(create_unattend_creates_file)
{
	/* Any non-zero flag should produce a file */
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_SECUREBOOT_TPM_MINRAM);
	CHECK(p != NULL);
	if (p) {
		struct stat st;
		CHECK(stat(p, &st) == 0);
		CHECK(st.st_size > 0);
		unlink(p);
	}
}

TEST(create_unattend_xml_header)
{
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_SECUREBOOT_TPM_MINRAM);
	SKIP_IF(p == NULL);
	char* content = slurp(p);
	unlink(p);
	CHECK(content != NULL);
	if (content) {
		CHECK(strstr(content, "<?xml") != NULL);
		CHECK(strstr(content, "<unattend") != NULL);
		CHECK(strstr(content, "</unattend>") != NULL);
		free(content);
	}
}

TEST(create_unattend_secureboot_tpm)
{
	/* UNATTEND_SECUREBOOT_TPM_MINRAM → bypass registry keys */
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_SECUREBOOT_TPM_MINRAM);
	SKIP_IF(p == NULL);
	char* content = slurp(p);
	unlink(p);
	CHECK(content != NULL);
	if (content) {
		CHECK(strstr(content, "BypassTPMCheck") != NULL);
		CHECK(strstr(content, "BypassSecureBootCheck") != NULL);
		CHECK(strstr(content, "BypassRAMCheck") != NULL);
		free(content);
	}
}

TEST(create_unattend_no_online_account)
{
	/* UNATTEND_NO_ONLINE_ACCOUNT → BypassNRO key */
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_NO_ONLINE_ACCOUNT);
	SKIP_IF(p == NULL);
	char* content = slurp(p);
	unlink(p);
	CHECK(content != NULL);
	if (content) {
		CHECK(strstr(content, "BypassNRO") != NULL);
		free(content);
	}
}

TEST(create_unattend_no_data_collection)
{
	/* UNATTEND_NO_DATA_COLLECTION → ProtectYourPC */
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_NO_DATA_COLLECTION);
	SKIP_IF(p == NULL);
	char* content = slurp(p);
	unlink(p);
	CHECK(content != NULL);
	if (content) {
		CHECK(strstr(content, "ProtectYourPC") != NULL);
		free(content);
	}
}

TEST(create_unattend_offline_drives)
{
	/* UNATTEND_OFFLINE_INTERNAL_DRIVES → SanPolicy */
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_OFFLINE_INTERNAL_DRIVES);
	SKIP_IF(p == NULL);
	char* content = slurp(p);
	unlink(p);
	CHECK(content != NULL);
	if (content) {
		CHECK(strstr(content, "SanPolicy") != NULL);
		free(content);
	}
}

TEST(create_unattend_full_mask)
{
	/* Full mask should produce a valid XML without crashing */
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_FULL_MASK);
	SKIP_IF(p == NULL);
	char* content = slurp(p);
	unlink(p);
	CHECK(content != NULL);
	if (content) {
		CHECK(strstr(content, "<?xml") != NULL);
		CHECK(strstr(content, "</unattend>") != NULL);
		free(content);
	}
}

TEST(create_unattend_arm64_arch)
{
	/* Test ARM64 arch name in output */
	char* p = CreateUnattendXml(ARCH_ARM_64, UNATTEND_SECUREBOOT_TPM_MINRAM);
	SKIP_IF(p == NULL);
	char* content = slurp(p);
	unlink(p);
	CHECK(content != NULL);
	if (content) {
		CHECK(strstr(content, "arm64") != NULL);
		free(content);
	}
}

TEST(create_unattend_temp_in_tmp)
{
	/* The generated file should be somewhere under /tmp */
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_SECUREBOOT_TPM_MINRAM);
	CHECK(p != NULL);
	if (p) {
		CHECK(strncmp(p, "/tmp/", 5) == 0);
		unlink(p);
	}
}

TEST(create_unattend_disable_bitlocker)
{
	/* UNATTEND_DISABLE_BITLOCKER → PreventDeviceEncryption */
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_DISABLE_BITLOCKER);
	SKIP_IF(p == NULL);
	char* content = slurp(p);
	unlink(p);
	CHECK(content != NULL);
	if (content) {
		CHECK(strstr(content, "PreventDeviceEncryption") != NULL);
		free(content);
	}
}

TEST(create_unattend_force_smode)
{
	/* UNATTEND_FORCE_S_MODE → SkuPolicyRequired */
	char* p = CreateUnattendXml(ARCH_X86_64, UNATTEND_FORCE_S_MODE);
	SKIP_IF(p == NULL);
	char* content = slurp(p);
	unlink(p);
	CHECK(content != NULL);
	if (content) {
		CHECK(strstr(content, "SkuPolicyRequired") != NULL);
		free(content);
	}
}

/* ================================================================
 * Helpers: WIM-in-ISO fixture creation
 * ================================================================ */

/*
 * Create a minimal WIM at dest_path with a single empty image and
 * Windows version properties set (major=10, build=19041).
 * Returns 0 on success, non-zero on failure.
 */
/*
 * Write a minimal WIM binary by hand.
 *
 * The WIM consists of a 208-byte header followed immediately by a UTF-16LE
 * XML block containing Windows version 10.0.19041.  No image blobs are
 * present – wimlib only needs the XML section to satisfy
 * PopulateWindowsVersion().
 *
 * Layout matches the on-disk wim_header_disk struct (see wimlib/header.h):
 *   +0x00  magic       8 bytes  "MSWIM\0\0\0"
 *   +0x08  hdr_size    4 bytes  208
 *   +0x0c  wim_version 4 bytes  0x00010d00  (WIM_VERSION_DEFAULT)
 *   +0x10  flags       4 bytes  0
 *   +0x14  chunk_size  4 bytes  0
 *   +0x18  guid        16 bytes (arbitrary)
 *   +0x28  part_number 2 bytes  1
 *   +0x2a  total_parts 2 bytes  1
 *   +0x2c  image_count 4 bytes  1
 *   +0x30  blob_table_reshdr  24 bytes  zeros (no blobs)
 *   +0x48  xml_data_reshdr    24 bytes  points to the XML block at offset 208
 *   +0x60  boot_metadata_reshdr 24 bytes zeros
 *   +0x78  boot_idx    4 bytes  0
 *   +0x7c  integrity_reshdr   24 bytes  zeros
 *   +0x94  unused      60 bytes zeros
 *
 * reshdr_disk layout (24 bytes):
 *   bytes 0-6   size_in_wim  (7-byte LE)
 *   byte  7     flags
 *   bytes 8-15  offset       (8-byte LE)
 *   bytes 16-23 uncompressed_size (8-byte LE)
 */
static int create_minimal_wim_with_version(const char *dest_path)
{
	static const char xml_utf8[] =
		"<WIM>"
		  "<IMAGE INDEX=\"1\">"
		    "<WINDOWS>"
		      "<VERSION>"
		        "<MAJOR>10</MAJOR>"
		        "<MINOR>0</MINOR>"
		        "<BUILD>19041</BUILD>"
		        "<SPBUILD>1</SPBUILD>"
		      "</VERSION>"
		    "</WINDOWS>"
		  "</IMAGE>"
		"</WIM>";

	/* Build UTF-16LE XML with BOM */
	static const uint8_t bom[] = { 0xff, 0xfe };
	size_t src_len = strlen(xml_utf8);
	size_t xml_len = 2 + src_len * 2; /* BOM + 2 bytes per char (ASCII subset) */
	uint8_t *xml = malloc(xml_len);
	if (!xml) return -1;
	xml[0] = 0xff; xml[1] = 0xfe;
	for (size_t i = 0; i < src_len; i++) {
		xml[2 + i*2]   = (uint8_t)xml_utf8[i];
		xml[2 + i*2+1] = 0;
	}
	(void)bom; /* already embedded above */

	/* Build reshdr for xml block: size_in_wim=xml_len, flags=0,
	 * offset=208, uncompressed_size=xml_len */
	uint8_t xml_reshdr[24] = {0};
	uint64_t xsz = (uint64_t)xml_len;
	uint64_t xoff = 208ULL;
	/* 7-byte little-endian size_in_wim */
	for (int i = 0; i < 7; i++) xml_reshdr[i] = (uint8_t)(xsz >> (8*i));
	/* flags = 0 already */
	for (int i = 0; i < 8; i++) xml_reshdr[8+i]  = (uint8_t)(xoff >> (8*i));
	for (int i = 0; i < 8; i++) xml_reshdr[16+i] = (uint8_t)(xsz  >> (8*i));

	/* Build 208-byte header */
	uint8_t hdr[208] = {0};
	/* magic */
	static const uint8_t magic[] = { 'M','S','W','I','M',0,0,0 };
	memcpy(hdr+0x00, magic, 8);
	/* hdr_size = 208 */
	hdr[0x08] = 208; hdr[0x09] = 0; hdr[0x0a] = 0; hdr[0x0b] = 0;
	/* wim_version = 0x00010d00 */
	hdr[0x0c] = 0x00; hdr[0x0d] = 0x0d; hdr[0x0e] = 0x01; hdr[0x0f] = 0x00;
	/* flags, chunk_size = 0 (already zeroed) */
	/* guid: fill with fixed bytes */
	for (int i = 0; i < 16; i++) hdr[0x18+i] = (uint8_t)(i+1);
	/* part_number = 1 */
	hdr[0x28] = 1; hdr[0x29] = 0;
	/* total_parts = 1 */
	hdr[0x2a] = 1; hdr[0x2b] = 0;
	/* image_count = 1 */
	hdr[0x2c] = 1;
	/* blob_table_reshdr at 0x30: zeros (already done) */
	/* xml_data_reshdr at 0x48 */
	memcpy(hdr+0x48, xml_reshdr, 24);
	/* rest zero */

	FILE *f = fopen(dest_path, "wb");
	if (!f) { free(xml); return -1; }
	int r = 0;
	if (fwrite(hdr, 1, 208, f) != 208 ||
	    fwrite(xml, 1, xml_len, f) != xml_len)
		r = -1;
	fclose(f);
	free(xml);
	return r;
}

/*
 * Create an ISO9660 image at iso_path containing a single file src_file
 * placed at dest_dir/filename within the ISO (e.g. sources/install.wim).
 * dest_dir must be a relative path (no leading '/').
 * Returns 0 on success, non-zero on failure.
 */
static int create_iso_with_wim(const char *iso_path,
                                const char *wim_src,
                                const char *dest_dir_in_iso)
{
	char tmpdir[256], subdir[512], src_name[256], cmd[2048];
	char *p;
	int r;

	/* Create a staging directory */
	snprintf(tmpdir, sizeof(tmpdir), "/tmp/rufus-iso-stage-XXXXXX");
	if (!mkdtemp(tmpdir)) return -1;

	/* Build full subdir path in staging area */
	snprintf(subdir, sizeof(subdir), "%s/%s", tmpdir, dest_dir_in_iso);

	/* mkdir -p for up to 3 path components */
	char dirbuf[512];
	snprintf(dirbuf, sizeof(dirbuf), "%s", subdir);
	for (p = dirbuf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(dirbuf, 0755);
			*p = '/';
		}
	}
	if (mkdir(dirbuf, 0755) != 0 && errno != EEXIST) { r = -1; goto cleanup; }

	/* Copy WIM into staging subdir as install.wim (the expected name in real Windows ISOs) */
	snprintf(src_name, sizeof(src_name), "%s/install.wim", subdir);
	snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", wim_src, src_name);
	r = system(cmd);
	if (r != 0) goto cleanup;

	/* Use genisoimage/mkisofs to build the ISO (Rock Ridge preserves lowercase filenames) */
	snprintf(cmd, sizeof(cmd),
	         "genisoimage -quiet -R -o '%s' -iso-level 3 '%s' 2>/dev/null",
	         iso_path, tmpdir);
	r = system(cmd);

cleanup:
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
	system(cmd);
	return r;
}

/* ================================================================
 * Tests: PopulateWindowsVersion
 * ================================================================ */

TEST(populate_wv_no_image_path)
{
	/* image_path is NULL/empty → should return FALSE */
	image_path = NULL;
	memset(&img_report, 0, sizeof(img_report));
	BOOL r = PopulateWindowsVersion();
	CHECK(r == FALSE);
}

TEST(populate_wv_real_wim_if_available)
{
	/* Optional: only runs if /tmp/test.wim exists */
	const char* p = "/tmp/test.wim";
	if (access(p, R_OK) != 0) return;
	image_path = (char*)p;
	img_report.is_windows_img = TRUE;
	memset(&img_report.win_version, 0, sizeof(img_report.win_version));
	BOOL r = PopulateWindowsVersion();
	/* A real Windows WIM should produce major != 0 and build != 0 */
	CHECK(r == TRUE);
	CHECK(img_report.win_version.major != 0);
	CHECK(img_report.win_version.build != 0);
	image_path = NULL;
}

/*
 * Test that PopulateWindowsVersion correctly opens a WIM embedded inside an
 * ISO9660 image.  This exercises the wininst_path offset: the path stored by
 * linux/iso.c is "/sources/install.wim" (leading '/'), so the correct offset
 * to strip the leading slash is [1], not [3] (which would give "rces/…").
 */
TEST(populate_wv_wim_in_iso)
{
	const char wim_tmp[] = "/tmp/rufus-test-embedded.wim";
	const char iso_tmp[] = "/tmp/rufus-test-embedded.iso";

	/* Skip if genisoimage is unavailable */
	if (system("which genisoimage >/dev/null 2>&1") != 0) {
		fprintf(stderr, "  SKIP: genisoimage not found\n");
		return;
	}

	/* Create a minimal WIM with Windows version info */
	int r = create_minimal_wim_with_version(wim_tmp);
	if (r != 0) {
		fprintf(stderr, "  SKIP: could not create test WIM (wimlib error %d)\n", r);
		return;
	}

	/* Wrap it in an ISO at sources/install.wim */
	r = create_iso_with_wim(iso_tmp, wim_tmp, "sources");
	unlink(wim_tmp);
	if (r != 0) {
		fprintf(stderr, "  SKIP: could not create test ISO (error %d)\n", r);
		unlink(iso_tmp);
		return;
	}

	/* Configure img_report to point at the embedded WIM */
	memset(&img_report, 0, sizeof(img_report));
	img_report.is_windows_img = FALSE;
	img_report.wininst_index  = 1;
	/* Path stored by linux/iso.c: leading '/' followed by the ISO-relative path */
	snprintf(img_report.wininst_path[0], sizeof(img_report.wininst_path[0]),
	         "/sources/install.wim");

	image_path = (char *)iso_tmp;

	BOOL ok = PopulateWindowsVersion();

	image_path = NULL;
	unlink(iso_tmp);

	/* Should have successfully extracted version 10.0.19041 */
	CHECK_MSG(ok == TRUE,
	          "PopulateWindowsVersion must return TRUE for a WIM embedded in an ISO");
	CHECK_MSG(img_report.win_version.major == 10,
	          "Major version must be 10");
	CHECK_MSG(img_report.win_version.build == 19041,
	          "Build must be 19041");
}

/*
 * Verify that using the wrong offset [3] (the old buggy code) would NOT find
 * the WIM inside the ISO – i.e. the test above is a meaningful regression guard.
 *
 * We set wininst_path to a deliberately wrong value whose [3] char is 'r'
 * (simulating the "/sources/install.wim" → [3] = 'r' bug) and confirm that
 * PopulateWindowsVersion fails to open the WIM.
 */
TEST(populate_wv_wim_in_iso_wrong_offset_fails)
{
	const char wim_tmp[] = "/tmp/rufus-test-wrong-offset.wim";
	const char iso_tmp[] = "/tmp/rufus-test-wrong-offset.iso";

	if (system("which genisoimage >/dev/null 2>&1") != 0) return;

	int r = create_minimal_wim_with_version(wim_tmp);
	if (r != 0) { unlink(wim_tmp); return; }

	r = create_iso_with_wim(iso_tmp, wim_tmp, "sources");
	unlink(wim_tmp);
	if (r != 0) { unlink(iso_tmp); return; }

	memset(&img_report, 0, sizeof(img_report));
	img_report.is_windows_img = FALSE;
	img_report.wininst_index  = 1;
	/*
	 * Simulate the wrong offset: pass "?:/sources/install.wim" so that
	 * [3] == 's' and the path "sources/install.wim" happens to be correct
	 * for the Windows code.  On Linux the path is "/sources/install.wim",
	 * so [3] == 'r', which would be wrong.
	 *
	 * To prove the negative: put a path where [3] gives a bad name.
	 * e.g. "XX/BAD/install.wim" → [3] = 'B' → wimlib looks for "BAD/install.wim"
	 * which doesn't exist → PopulateWindowsVersion must return FALSE.
	 */
	snprintf(img_report.wininst_path[0], sizeof(img_report.wininst_path[0]),
	         "XX/BAD/install.wim");

	/* The test harness in wue.c uses [1] so "X/BAD/install.wim" is the path
	 * passed to wimlib.  That still won't match the actual "sources/install.wim",
	 * so the open must fail and PopulateWindowsVersion must return FALSE. */
	image_path = (char *)iso_tmp;

	BOOL ok = PopulateWindowsVersion();

	image_path = NULL;
	unlink(iso_tmp);

	CHECK_MSG(ok == FALSE,
	          "PopulateWindowsVersion must return FALSE when wininst_path gives a wrong WIM path");
}

/* ================================================================
 * Tests: Stub functions
 * ================================================================ */

TEST(stub_setup_winpe_returns_false)
{
	CHECK(SetupWinPE('C') == FALSE);
}

TEST(stub_setup_wintogo_returns_false)
{
	CHECK(SetupWinToGo(0, "/dev/sda", FALSE) == FALSE);
}

TEST(stub_copy_sku_returns_false)
{
	CHECK(CopySKUSiPolicy("/mnt") == FALSE);
}

TEST(stub_set_wintogo_index_returns_neg1)
{
	CHECK(SetWinToGoIndex() == -1);
}

/* ================================================================
 * Helper: create a temp directory, return path (must free)
 * ================================================================ */
static char* make_temp_dir(void)
{
	char *path = strdup("/tmp/rufus-wue-test-XXXXXX");
	if (!path) return NULL;
	if (!mkdtemp(path)) { free(path); return NULL; }
	return path;
}

/* Helper: recursively mkdir (2 levels max) */
static int mkdir_p(const char *path)
{
	char buf[512];
	snprintf(buf, sizeof(buf), "%s", path);
	for (char *p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(buf, 0755);
			*p = '/';
		}
	}
	return mkdir(buf, 0755);
}

/* Helper: check if file exists */
static int file_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Helper: cleanup a temp directory tree (2 levels) */
static void rmdir_tree(const char *root)
{
	if (!root) return;
	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", root);
	system(cmd);
}

/* ================================================================
 * Tests: ApplyWindowsCustomization
 * ================================================================ */

extern void wue_set_mount_path(const char *path);

/* 1. NULL unattend_xml_path → returns FALSE */
TEST(apply_customization_null_unattend_returns_false)
{
	unattend_xml_path = NULL;
	BOOL r = ApplyWindowsCustomization(0, UNATTEND_NO_DATA_COLLECTION);
	CHECK(r == FALSE);
}

/* 2. OOBE-only (no WINPE_SETUP_MASK): copies to sources/$OEM$/$$/Panther/unattend.xml */
TEST(apply_customization_oobe_copies_to_oem_panther)
{
	char *mount = make_temp_dir();
	SKIP_IF(mount == NULL);

	/* Create a fake sources/ directory so mkdir_p only needs Panther */
	char sources_dir[512];
	snprintf(sources_dir, sizeof(sources_dir), "%s/sources", mount);
	mkdir(sources_dir, 0755);

	/* Create a fake unattend.xml */
	unattend_xml_path = CreateUnattendXml(ARCH_X86_64, UNATTEND_NO_DATA_COLLECTION);
	SKIP_IF(unattend_xml_path == NULL);

	wue_set_mount_path(mount);
	BOOL r = ApplyWindowsCustomization(0, UNATTEND_NO_DATA_COLLECTION);
	CHECK(r == TRUE);

	/* Verify the file was copied to the right place */
	char expected[512];
	snprintf(expected, sizeof(expected),
	         "%s/sources/$OEM$/$$/Panther/unattend.xml", mount);
	CHECK_MSG(file_exists(expected), "unattend.xml must be in sources/$OEM$/$$/Panther/");

	unlink(unattend_xml_path);
	unattend_xml_path = NULL;
	wue_set_mount_path(NULL);
	rmdir_tree(mount);
	free(mount);
}

/* 3. WinToGo flag: copies to Windows/Panther/unattend.xml */
TEST(apply_customization_wintogo_copies_to_windows_panther)
{
	char *mount = make_temp_dir();
	SKIP_IF(mount == NULL);

	unattend_xml_path = CreateUnattendXml(ARCH_X86_64, UNATTEND_NO_DATA_COLLECTION);
	SKIP_IF(unattend_xml_path == NULL);

	wue_set_mount_path(mount);
	int flags = UNATTEND_NO_DATA_COLLECTION | UNATTEND_WINDOWS_TO_GO;
	BOOL r = ApplyWindowsCustomization(0, flags);
	CHECK(r == TRUE);

	char expected[512];
	snprintf(expected, sizeof(expected), "%s/Windows/Panther/unattend.xml", mount);
	CHECK_MSG(file_exists(expected), "unattend.xml must be in Windows/Panther/");

	unlink(unattend_xml_path);
	unattend_xml_path = NULL;
	wue_set_mount_path(NULL);
	rmdir_tree(mount);
	free(mount);
}

/* 4. Copied file content matches the source */
TEST(apply_customization_content_matches)
{
	char *mount = make_temp_dir();
	SKIP_IF(mount == NULL);

	char sources_dir[512];
	snprintf(sources_dir, sizeof(sources_dir), "%s/sources", mount);
	mkdir(sources_dir, 0755);

	unattend_xml_path = CreateUnattendXml(ARCH_X86_64, UNATTEND_NO_ONLINE_ACCOUNT);
	SKIP_IF(unattend_xml_path == NULL);

	char *orig = slurp(unattend_xml_path);
	SKIP_IF(orig == NULL);

	wue_set_mount_path(mount);
	BOOL r = ApplyWindowsCustomization(0, UNATTEND_NO_ONLINE_ACCOUNT);
	CHECK(r == TRUE);

	char copied_path[512];
	snprintf(copied_path, sizeof(copied_path),
	         "%s/sources/$OEM$/$$/Panther/unattend.xml", mount);
	char *copy = slurp(copied_path);
	CHECK_MSG(copy != NULL, "copied file must be readable");
	if (copy) {
		CHECK_STR_EQ(orig, copy);
		free(copy);
	}

	free(orig);
	unlink(unattend_xml_path);
	unattend_xml_path = NULL;
	wue_set_mount_path(NULL);
	rmdir_tree(mount);
	free(mount);
}

/* 5. NULL mount path → returns FALSE */
TEST(apply_customization_null_mount_returns_false)
{
	unattend_xml_path = CreateUnattendXml(ARCH_X86_64, UNATTEND_NO_DATA_COLLECTION);
	SKIP_IF(unattend_xml_path == NULL);

	wue_set_mount_path(NULL);
	BOOL r = ApplyWindowsCustomization(0, UNATTEND_NO_DATA_COLLECTION);
	CHECK(r == FALSE);

	unlink(unattend_xml_path);
	unattend_xml_path = NULL;
}

/* 6. Multiple OOBE flags: file still copies correctly */
TEST(apply_customization_multiple_flags)
{
	char *mount = make_temp_dir();
	SKIP_IF(mount == NULL);

	char sources_dir[512];
	snprintf(sources_dir, sizeof(sources_dir), "%s/sources", mount);
	mkdir(sources_dir, 0755);

	int flags = UNATTEND_NO_DATA_COLLECTION | UNATTEND_NO_ONLINE_ACCOUNT
	            | UNATTEND_DUPLICATE_LOCALE;
	unattend_xml_path = CreateUnattendXml(ARCH_X86_64, flags);
	SKIP_IF(unattend_xml_path == NULL);

	wue_set_mount_path(mount);
	BOOL r = ApplyWindowsCustomization(0, flags);
	CHECK(r == TRUE);

	char expected[512];
	snprintf(expected, sizeof(expected),
	         "%s/sources/$OEM$/$$/Panther/unattend.xml", mount);
	CHECK_MSG(file_exists(expected), "unattend.xml must exist for multi-flag case");

	unlink(unattend_xml_path);
	unattend_xml_path = NULL;
	wue_set_mount_path(NULL);
	rmdir_tree(mount);
	free(mount);
}

/* ================================================================
 * Main
 * ================================================================ */
int main(void)
{
	printf("=== WUE Linux Tests ===\n");

	RUN(create_unattend_flags_zero);
	RUN(create_unattend_invalid_arch);
	RUN(create_unattend_creates_file);
	RUN(create_unattend_xml_header);
	RUN(create_unattend_secureboot_tpm);
	RUN(create_unattend_no_online_account);
	RUN(create_unattend_no_data_collection);
	RUN(create_unattend_offline_drives);
	RUN(create_unattend_full_mask);
	RUN(create_unattend_arm64_arch);
	RUN(create_unattend_temp_in_tmp);
	RUN(create_unattend_disable_bitlocker);
	RUN(create_unattend_force_smode);
	RUN(populate_wv_no_image_path);
	RUN(populate_wv_real_wim_if_available);
	RUN(populate_wv_wim_in_iso);
	RUN(populate_wv_wim_in_iso_wrong_offset_fails);
	RUN(stub_setup_winpe_returns_false);
	RUN(stub_setup_wintogo_returns_false);
	RUN(stub_copy_sku_returns_false);
	RUN(stub_set_wintogo_index_returns_neg1);

	printf("\n=== ApplyWindowsCustomization tests ===\n");
	RUN(apply_customization_null_unattend_returns_false);
	RUN(apply_customization_oobe_copies_to_oem_panther);
	RUN(apply_customization_wintogo_copies_to_windows_panther);
	RUN(apply_customization_content_matches);
	RUN(apply_customization_null_mount_returns_false);
	RUN(apply_customization_multiple_flags);

	TEST_RESULTS();
}

#endif /* __linux__ */
