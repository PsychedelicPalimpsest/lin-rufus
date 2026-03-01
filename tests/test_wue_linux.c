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

TEST(stub_apply_customization_returns_false)
{
	CHECK(ApplyWindowsCustomization('C', 0) == FALSE);
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
	RUN(stub_setup_winpe_returns_false);
	RUN(stub_setup_wintogo_returns_false);
	RUN(stub_copy_sku_returns_false);
	RUN(stub_set_wintogo_index_returns_neg1);
	RUN(stub_apply_customization_returns_false);

	TEST_RESULTS();
}

#endif /* __linux__ */
