/*
 * test_wue_common.c — Cross-platform tests for wue_compute_option_flags()
 *
 * Tests the pure-logic flag computation from src/common/wue.c.
 * wue_compute_option_flags() has no platform-specific dependencies — it
 * only inspects RUFUS_IMG_REPORT fields and UNATTEND_* constants.
 *
 * Stubs are provided for all symbols used by CreateUnattendXml() (in the
 * same translation unit) that wue_compute_option_flags() itself never calls.
 *
 * Runs on Linux (native) and Windows (Wine / MinGW cross-compile).
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2025 Rufus contributors
 */

#include "framework.h"

#include <stdarg.h>
#include <string.h>

#ifdef _WIN32
#include "../src/windows/rufus.h"
#include "../src/common/oobe_locale.h"
#include "../src/windows/wue.h"
#else
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/common/oobe_locale.h"
#include "../src/windows/wue.h"
#endif

/* -----------------------------------------------------------------------
 * Stubs for symbols that CreateUnattendXml() references but
 * wue_compute_option_flags() does not call.
 * --------------------------------------------------------------------- */

const char* bypass_name[3] = { "BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck" };
char unattend_username[MAX_USERNAME_LENGTH];
int unattend_xml_flags, unattend_xml_mask;
char szFolderPath[MAX_PATH], app_dir[MAX_PATH], temp_dir[MAX_PATH], system_dir[MAX_PATH];
windows_version_t WindowsVersion;
RUFUS_UPDATE update;
RUFUS_IMG_REPORT img_report;

void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s)       { (void)s; }
char *lmprintf(uint32_t id, ...)   { (void)id; return ""; }
const char *GetLocalTimezone(void) { return "UTC"; }
void GetOobeLocale(OobeLocale *l)  { (void)l; }
void filter_chars(char *dst, const char *chars, char rep)
    { (void)dst; (void)chars; (void)rep; }

/* -----------------------------------------------------------------------
 * Helper: build a minimal RUFUS_IMG_REPORT for a given Windows version
 * --------------------------------------------------------------------- */
static RUFUS_IMG_REPORT make_report(int major, int build, BOOL has_bootmgr_efi)
{
	RUFUS_IMG_REPORT r;
	memset(&r, 0, sizeof(r));
	r.has_bootmgr_efi     = has_bootmgr_efi;
	r.win_version.major   = (uint8_t)major;
	r.win_version.build   = (uint32_t)build;
	return r;
}

/* -----------------------------------------------------------------------
 * Tests
 * --------------------------------------------------------------------- */

/* Base flags that must always be set for any Windows image */
TEST(base_flags_always_set_win10)
{
	RUFUS_IMG_REPORT ir = make_report(10, 19041, TRUE);
	int flags = wue_compute_option_flags(&ir, FALSE);
	CHECK(flags & UNATTEND_SET_USER);
	CHECK(flags & UNATTEND_DUPLICATE_LOCALE);
	CHECK(flags & UNATTEND_NO_DATA_COLLECTION);
	CHECK(flags & UNATTEND_DISABLE_BITLOCKER);
}

TEST(base_flags_always_set_win11)
{
	RUFUS_IMG_REPORT ir = make_report(11, 22000, TRUE);
	int flags = wue_compute_option_flags(&ir, FALSE);
	CHECK(flags & UNATTEND_SET_USER);
	CHECK(flags & UNATTEND_DUPLICATE_LOCALE);
	CHECK(flags & UNATTEND_NO_DATA_COLLECTION);
	CHECK(flags & UNATTEND_DISABLE_BITLOCKER);
}

/* Win11 should get the secureboot/TPM bypass option */
TEST(win11_adds_secureboot_tpm)
{
	RUFUS_IMG_REPORT ir = make_report(11, 22000, TRUE);
	int flags = wue_compute_option_flags(&ir, FALSE);
	CHECK(flags & UNATTEND_SECUREBOOT_TPM_MINRAM);
}

/* Win10 must NOT get the secureboot/TPM bypass */
TEST(win10_no_secureboot_tpm)
{
	RUFUS_IMG_REPORT ir = make_report(10, 19041, TRUE);
	int flags = wue_compute_option_flags(&ir, FALSE);
	CHECK(!(flags & UNATTEND_SECUREBOOT_TPM_MINRAM));
}

/* Win11 without bootmgr_efi is not classified as Win11 */
TEST(win11_no_bootmgr_efi_no_secureboot)
{
	RUFUS_IMG_REPORT ir = make_report(11, 22000, FALSE);
	int flags = wue_compute_option_flags(&ir, FALSE);
	CHECK(!(flags & UNATTEND_SECUREBOOT_TPM_MINRAM));
}

/* Build 22500+ adds no-online-account requirement */
TEST(build_22500_adds_no_online_account)
{
	RUFUS_IMG_REPORT ir = make_report(11, 22500, TRUE);
	int flags = wue_compute_option_flags(&ir, FALSE);
	CHECK(flags & UNATTEND_NO_ONLINE_ACCOUNT);
}

/* Build 22499 must NOT get the no-online-account flag */
TEST(build_22499_no_online_account)
{
	RUFUS_IMG_REPORT ir = make_report(11, 22499, TRUE);
	int flags = wue_compute_option_flags(&ir, FALSE);
	CHECK(!(flags & UNATTEND_NO_ONLINE_ACCOUNT));
}

/* Build 26200+ adds MS2023 bootloader flag */
TEST(build_26200_adds_ms2023_bootloaders)
{
	RUFUS_IMG_REPORT ir = make_report(11, 26200, TRUE);
	int flags = wue_compute_option_flags(&ir, FALSE);
	CHECK(flags & UNATTEND_USE_MS2023_BOOTLOADERS);
}

/* Build 26199 must NOT get MS2023 bootloader flag */
TEST(build_26199_no_ms2023_bootloaders)
{
	RUFUS_IMG_REPORT ir = make_report(11, 26199, TRUE);
	int flags = wue_compute_option_flags(&ir, FALSE);
	CHECK(!(flags & UNATTEND_USE_MS2023_BOOTLOADERS));
}

/* Expert mode adds FORCE_S_MODE */
TEST(expert_mode_adds_s_mode)
{
	RUFUS_IMG_REPORT ir = make_report(10, 19041, TRUE);
	int flags_normal = wue_compute_option_flags(&ir, FALSE);
	int flags_expert = wue_compute_option_flags(&ir, TRUE);
	CHECK(!(flags_normal & UNATTEND_FORCE_S_MODE));
	CHECK(flags_expert & UNATTEND_FORCE_S_MODE);
}

/* Expert mode does not remove base flags */
TEST(expert_mode_keeps_base_flags)
{
	RUFUS_IMG_REPORT ir = make_report(10, 19041, TRUE);
	int flags = wue_compute_option_flags(&ir, TRUE);
	CHECK(flags & UNATTEND_SET_USER);
	CHECK(flags & UNATTEND_DUPLICATE_LOCALE);
	CHECK(flags & UNATTEND_NO_DATA_COLLECTION);
	CHECK(flags & UNATTEND_DISABLE_BITLOCKER);
}

/* Exact build-gate boundaries: 26200 gets flag, 26199 does not */
TEST(ms2023_build_gate_exact_boundary)
{
	RUFUS_IMG_REPORT lo = make_report(11, 26199, TRUE);
	RUFUS_IMG_REPORT hi = make_report(11, 26200, TRUE);
	int flags_lo = wue_compute_option_flags(&lo, FALSE);
	int flags_hi = wue_compute_option_flags(&hi, FALSE);
	CHECK(!(flags_lo & UNATTEND_USE_MS2023_BOOTLOADERS));
	CHECK(flags_hi & UNATTEND_USE_MS2023_BOOTLOADERS);
}

/* Exact build-gate for no-online-account: 22500 gets, 22499 does not */
TEST(online_account_build_gate_exact_boundary)
{
	RUFUS_IMG_REPORT lo = make_report(11, 22499, TRUE);
	RUFUS_IMG_REPORT hi = make_report(11, 22500, TRUE);
	int flags_lo = wue_compute_option_flags(&lo, FALSE);
	int flags_hi = wue_compute_option_flags(&hi, FALSE);
	CHECK(!(flags_lo & UNATTEND_NO_ONLINE_ACCOUNT));
	CHECK(flags_hi & UNATTEND_NO_ONLINE_ACCOUNT);
}

/* All features combined: Win11 22H2 in expert mode */
TEST(win11_22h2_expert_all_flags)
{
	RUFUS_IMG_REPORT ir = make_report(11, 22621, TRUE);
	int flags = wue_compute_option_flags(&ir, TRUE);
	CHECK(flags & UNATTEND_SET_USER);
	CHECK(flags & UNATTEND_DUPLICATE_LOCALE);
	CHECK(flags & UNATTEND_NO_DATA_COLLECTION);
	CHECK(flags & UNATTEND_DISABLE_BITLOCKER);
	CHECK(flags & UNATTEND_SECUREBOOT_TPM_MINRAM);
	CHECK(flags & UNATTEND_NO_ONLINE_ACCOUNT);
	CHECK(flags & UNATTEND_FORCE_S_MODE);
	/* Build 22621 < 26200: no MS2023 bootloaders */
	CHECK(!(flags & UNATTEND_USE_MS2023_BOOTLOADERS));
}

/* Full-feature Win11 build >= 26200 in expert mode */
TEST(win11_26200_expert_all_flags_including_ms2023)
{
	RUFUS_IMG_REPORT ir = make_report(11, 26200, TRUE);
	int flags = wue_compute_option_flags(&ir, TRUE);
	CHECK(flags & UNATTEND_SET_USER);
	CHECK(flags & UNATTEND_SECUREBOOT_TPM_MINRAM);
	CHECK(flags & UNATTEND_NO_ONLINE_ACCOUNT);
	CHECK(flags & UNATTEND_USE_MS2023_BOOTLOADERS);
	CHECK(flags & UNATTEND_FORCE_S_MODE);
}

int main(void)
{
	printf("=== wue common (wue_compute_option_flags) ===\n\n");

	RUN(base_flags_always_set_win10);
	RUN(base_flags_always_set_win11);
	RUN(win11_adds_secureboot_tpm);
	RUN(win10_no_secureboot_tpm);
	RUN(win11_no_bootmgr_efi_no_secureboot);
	RUN(build_22500_adds_no_online_account);
	RUN(build_22499_no_online_account);
	RUN(build_26200_adds_ms2023_bootloaders);
	RUN(build_26199_no_ms2023_bootloaders);
	RUN(expert_mode_adds_s_mode);
	RUN(expert_mode_keeps_base_flags);
	RUN(ms2023_build_gate_exact_boundary);
	RUN(online_account_build_gate_exact_boundary);
	RUN(win11_22h2_expert_all_flags);
	RUN(win11_26200_expert_all_flags_including_ms2023);

	TEST_RESULTS();
}
