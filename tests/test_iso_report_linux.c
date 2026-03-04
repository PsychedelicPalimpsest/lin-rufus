/* tests/test_iso_report_linux.c
 * Tests for log_iso_report() — common ISO scan results logger.
 *
 * log_iso_report() reads the global img_report and calls uprintf() to
 * produce one log line per detected property.  These tests capture uprintf
 * output via rufus_set_log_handler() and verify the expected text.
 *
 * Tests:
 *  1.  label_is_logged                — ISO label appears in "ISO label: …" line
 *  2.  projected_size_logged          — Size line emitted for non-zero projected_size
 *  3.  no_size_when_zero              — No "Size:" line when projected_size == 0
 *  4.  windows_version_with_minor     — "Detected: Windows 10.0 ISO (Build …)"
 *  5.  windows_version_no_minor       — "Detected: Windows 11 ISO (Build …)" (no ".0")
 *  6.  mismatch_truncated_logged      — Truncation error logged for mismatch_size > 0
 *  7.  mismatch_truncated_shows_notification — Notification shown for truncated ISO
 *  8.  mismatch_larger_logged         — "larger than reported" note for mismatch_size < 0
 *  8.  has_4gb_file_logged            — ">4GB file" flag logged
 *  9.  has_long_filename_logged       — ">64 chars filename" logged
 * 10.  has_deep_directories_logged    — "Rock Ridge deep directory" logged
 * 11.  syslinux_version_logged        — Syslinux version string logged
 * 12.  old_c32_logged                 — Old c32 file names logged for syslinux v4
 * 13.  old_c32_not_logged_syslinux_v5 — c32 names NOT logged for syslinux v5+
 * 14.  kolibrios_logged               — KolibriOS logged
 * 15.  reactos_logged                 — ReactOS logged
 * 16.  grub4dos_logged                — Grub4DOS logged
 * 17.  grub2_version_logged           — GRUB2 with version string logged
 * 18.  efi_via_img_logged             — EFI through img path logged
 * 19.  efi_win7_x64_logged            — EFI win7_x64 logged
 * 20.  bootmgr_bios_only_logged       — Bootmgr "BIOS only" logged
 * 21.  bootmgr_efi_only_logged        — Bootmgr "UEFI only" logged
 * 22.  bootmgr_bios_and_efi_logged    — Bootmgr "BIOS and UEFI" logged
 * 23.  winpe_i386_logged              — WinPE logged for WINPE_I386
 * 24.  winpe_amd64_logged             — WinPE logged for WINPE_AMD64
 * 25.  winpe_minint_logged            — WinPE logged for WINPE_MININT
 * 26.  winpe_with_minint_suffix       — "with /minint" suffix when uses_minint is set
 * 27.  wininst_esd_logged             — Install.esd wininst path logged
 * 28.  wininst_wim_logged             — Install.wim wininst path logged
 * 29.  needs_ntfs_logged              — NTFS requirement note logged
 * 30.  symlinks_rr_logged             — Rock Ridge symlinks note logged
 * 31.  symlinks_udf_logged            — UDF symlinks note logged
 * 32.  no_winpe_line_when_not_set     — WinPE not logged when winpe==0
 * 33.  no_wininst_when_not_set        — wininst not logged when wininst_index==0
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "framework.h"

#include "windows.h"
#include "rufus.h"

/* ---- Function under test ---- */
void log_iso_report(void);

/* ---- Globals provided by iso_report_linux_glue.c ---- */
extern RUFUS_IMG_REPORT img_report;
void rufus_set_log_handler(void (*fn)(const char *msg));
int iso_report_get_notification_calls(void);
void iso_report_reset_notification_calls(void);

/* ---- Log capture infrastructure ---- */
#define CAP_BUF_SZ 8192

static char g_captured[CAP_BUF_SZ];
static int  g_call_count;

static void capture_handler(const char *msg)
{
    size_t used = strlen(g_captured);
    size_t avail = CAP_BUF_SZ - used - 2;
    if (avail > 0) {
        strncat(g_captured, msg, avail);
        g_captured[used + avail] = '\0';
        /* append a newline so we can search line-by-line */
        if (strlen(g_captured) < CAP_BUF_SZ - 1)
            strcat(g_captured, "\n");
    }
    g_call_count++;
}

static void reset_capture(void)
{
    g_captured[0] = '\0';
    g_call_count  = 0;
    rufus_set_log_handler(capture_handler);
}

static void stop_capture(void)
{
    rufus_set_log_handler(NULL);
}

static int has(const char *needle)
{
    return strstr(g_captured, needle) != NULL;
}

/* ---- Helpers ---- */
static RUFUS_IMG_REPORT make_empty(void)
{
    RUFUS_IMG_REPORT r;
    memset(&r, 0, sizeof(r));
    return r;
}

/* SL_MAJOR/SL_MINOR from rufus.h: sl_version is uint16_t encoded as (major<<8)|minor */
#define MAKE_SL_VERSION(major, minor) ((uint16_t)(((major) << 8) | (minor)))

/* ===========================================================================
 * Tests
 * =========================================================================*/

TEST(label_is_logged)
{
    img_report = make_empty();
    strncpy(img_report.label, "UBUNTU_22", sizeof(img_report.label) - 1);
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("ISO label: 'UBUNTU_22'"), "label must appear in output");
}

TEST(projected_size_logged)
{
    img_report = make_empty();
    img_report.projected_size = (uint64_t)128 * 1024 * 1024; /* 128 MiB */
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Size:"), "projected size must be logged");
    CHECK_MSG(has("128"), "128 MiB must appear in output");
}

TEST(no_size_when_zero)
{
    img_report = make_empty();
    img_report.projected_size = 0;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(!has("Size:"), "no Size: line when projected_size == 0");
}

TEST(windows_version_with_minor)
{
    img_report = make_empty();
    img_report.win_version.major    = 10;
    img_report.win_version.minor    = 0;
    img_report.win_version.build    = 19041;
    img_report.win_version.revision = 1;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Windows 10"), "Windows major version must appear");
    CHECK_MSG(has("19041"), "build number must appear");
}

TEST(windows_version_no_minor)
{
    img_report = make_empty();
    img_report.win_version.major    = 11;
    img_report.win_version.minor    = 0;
    img_report.win_version.build    = 22621;
    img_report.win_version.revision = 0;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Windows 11"), "Windows 11 must appear");
    CHECK_MSG(has("22621"), "build number must appear");
}

TEST(mismatch_truncated_logged)
{
    img_report = make_empty();
    img_report.mismatch_size = (int64_t)512 * 1024; /* +512 KiB truncated */
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("ERROR") || has("truncated"), "truncation error must be logged");
}

TEST(mismatch_truncated_shows_notification)
{
    img_report = make_empty();
    img_report.mismatch_size = (int64_t)512 * 1024;
    iso_report_reset_notification_calls();
    log_iso_report();
    CHECK_MSG(iso_report_get_notification_calls() > 0,
              "truncated ISO must trigger a Notification dialog");
}

TEST(mismatch_larger_logged)
{
    img_report = make_empty();
    img_report.mismatch_size = -(int64_t)(512 * 1024); /* file is larger */
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("larger"), "larger-than-ISO note must be logged");
}

TEST(has_4gb_file_logged)
{
    img_report = make_empty();
    img_report.has_4GB_file = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("4GB"), "4GB file flag must be logged");
}

TEST(has_long_filename_logged)
{
    img_report = make_empty();
    img_report.has_long_filename = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("64 chars"), "long filename flag must be logged");
}

TEST(has_deep_directories_logged)
{
    img_report = make_empty();
    img_report.has_deep_directories = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("deep directory") || has("Rock Ridge"), "deep directories flag must be logged");
}

TEST(syslinux_version_logged)
{
    img_report = make_empty();
    img_report.sl_version = MAKE_SL_VERSION(6, 3);
    strncpy(img_report.sl_version_str, "6.03", sizeof(img_report.sl_version_str) - 1);
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Syslinux") || has("Isolinux"), "Syslinux must be logged");
    CHECK_MSG(has("6.03"), "Syslinux version string must appear");
}

TEST(old_c32_logged)
{
    img_report = make_empty();
    /* Syslinux v4: SL_MAJOR < 5, so old c32 files are logged */
    img_report.sl_version = MAKE_SL_VERSION(4, 7);
    strncpy(img_report.sl_version_str, "4.07", sizeof(img_report.sl_version_str) - 1);
    img_report.has_old_c32[0] = TRUE;  /* menu.c32 */
    img_report.has_old_c32[1] = TRUE;  /* vesamenu.c32 */
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("menu.c32"), "old menu.c32 must be logged for syslinux v4");
    CHECK_MSG(has("vesamenu.c32"), "old vesamenu.c32 must be logged for syslinux v4");
}

TEST(old_c32_not_logged_syslinux_v5)
{
    img_report = make_empty();
    /* Syslinux v5+: old c32 NOT logged */
    img_report.sl_version = MAKE_SL_VERSION(5, 0);
    strncpy(img_report.sl_version_str, "5.00", sizeof(img_report.sl_version_str) - 1);
    img_report.has_old_c32[0] = TRUE;
    img_report.has_old_c32[1] = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(!has("menu.c32"), "old c32 NOT logged for syslinux v5+");
}

TEST(kolibrios_logged)
{
    img_report = make_empty();
    img_report.has_kolibrios = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("KolibriOS"), "KolibriOS must be logged");
}

TEST(reactos_logged)
{
    img_report = make_empty();
    strncpy(img_report.reactos_path, "/loader/setupldr.sys", sizeof(img_report.reactos_path) - 1);
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("ReactOS"), "ReactOS must be logged");
}

TEST(grub4dos_logged)
{
    img_report = make_empty();
    img_report.has_grub4dos = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Grub4DOS"), "Grub4DOS must be logged");
}

TEST(grub2_version_logged)
{
    img_report = make_empty();
    img_report.has_grub2 = TRUE;
    strncpy(img_report.grub2_version, "2.12", sizeof(img_report.grub2_version) - 1);
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("GRUB2"), "GRUB2 must be logged");
    CHECK_MSG(has("2.12"), "GRUB2 version must appear");
}

TEST(efi_via_img_logged)
{
    img_report = make_empty();
    img_report.has_efi = 0x80;
    strncpy(img_report.efi_img_path, "/efi/boot/bootx64.img", sizeof(img_report.efi_img_path) - 1);
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("EFI"), "EFI must be logged");
    CHECK_MSG(has("bootx64.img"), "EFI img path must appear");
}

TEST(efi_standard_logged)
{
    img_report = make_empty();
    img_report.has_efi = 1;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("EFI"), "EFI must be logged");
}

TEST(bootmgr_bios_only_logged)
{
    img_report = make_empty();
    img_report.has_bootmgr     = TRUE;
    img_report.has_bootmgr_efi = FALSE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Bootmgr"), "Bootmgr must be logged");
    CHECK_MSG(has("BIOS only"), "BIOS only must appear");
}

TEST(bootmgr_efi_only_logged)
{
    img_report = make_empty();
    img_report.has_bootmgr     = FALSE;
    img_report.has_bootmgr_efi = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Bootmgr"), "Bootmgr must be logged");
    CHECK_MSG(has("UEFI only"), "UEFI only must appear");
}

TEST(bootmgr_bios_and_efi_logged)
{
    img_report = make_empty();
    img_report.has_bootmgr     = TRUE;
    img_report.has_bootmgr_efi = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Bootmgr"), "Bootmgr must be logged");
    CHECK_MSG(has("BIOS and UEFI"), "BIOS and UEFI must appear");
}

TEST(winpe_i386_logged)
{
    img_report = make_empty();
    img_report.winpe = WINPE_I386;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("WinPE"), "WinPE must be logged");
}

TEST(winpe_amd64_logged)
{
    img_report = make_empty();
    img_report.winpe = WINPE_AMD64;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("WinPE"), "WinPE must be logged");
}

TEST(winpe_minint_logged)
{
    img_report = make_empty();
    img_report.winpe = WINPE_MININT;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("WinPE"), "WinPE must be logged");
}

TEST(winpe_with_minint_suffix)
{
    img_report = make_empty();
    img_report.winpe       = WINPE_I386;
    img_report.uses_minint = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("WinPE"), "WinPE must be logged");
    CHECK_MSG(has("/minint"), "uses_minint must produce /minint in output");
}

TEST(wininst_esd_logged)
{
    img_report = make_empty();
    img_report.wininst_index   = 1;
    img_report.wininst_version = (10 << 24) | (0 << 16) | (19041 << 8);
    strncpy(img_report.wininst_path[0], "/sources/install.esd",
            sizeof(img_report.wininst_path[0]) - 1);
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Install") || has("install"), "Install file must be logged");
    CHECK_MSG(has("esd"), "install.esd extension must appear");
}

TEST(wininst_wim_logged)
{
    img_report = make_empty();
    img_report.wininst_index   = 1;
    img_report.wininst_version = (10 << 24) | (0 << 16) | (19041 << 8);
    strncpy(img_report.wininst_path[0], "/sources/install.wim",
            sizeof(img_report.wininst_path[0]) - 1);
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("Install") || has("install"), "Install file must be logged");
    CHECK_MSG(has("wim"), "install.wim extension must appear");
}

TEST(needs_ntfs_logged)
{
    img_report = make_empty();
    img_report.needs_ntfs = TRUE;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("ntfs") || has("NTFS"), "NTFS requirement must be logged");
}

TEST(symlinks_rr_logged)
{
    img_report = make_empty();
    img_report.has_symlinks = SYMLINKS_RR;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("symbolic links") || has("symlink"), "symlink note must be logged");
}

TEST(symlinks_udf_logged)
{
    img_report = make_empty();
    img_report.has_symlinks = SYMLINKS_UDF;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(has("symbolic links") || has("symlink"), "UDF symlink note must be logged");
}

TEST(no_winpe_line_when_not_set)
{
    img_report = make_empty();
    img_report.winpe = 0;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(!has("WinPE"), "WinPE must NOT be logged when winpe==0");
}

TEST(no_wininst_when_not_set)
{
    img_report = make_empty();
    img_report.wininst_index = 0;
    reset_capture();
    log_iso_report();
    stop_capture();
    CHECK_MSG(!has("Install"), "wininst must NOT be logged when wininst_index==0");
}

/* ---- Main ---- */
int main(void)
{
    RUN_TEST(label_is_logged);
    RUN_TEST(projected_size_logged);
    RUN_TEST(no_size_when_zero);
    RUN_TEST(windows_version_with_minor);
    RUN_TEST(windows_version_no_minor);
    RUN_TEST(mismatch_truncated_logged);
    RUN_TEST(mismatch_truncated_shows_notification);
    RUN_TEST(mismatch_larger_logged);
    RUN_TEST(has_4gb_file_logged);
    RUN_TEST(has_long_filename_logged);
    RUN_TEST(has_deep_directories_logged);
    RUN_TEST(syslinux_version_logged);
    RUN_TEST(old_c32_logged);
    RUN_TEST(old_c32_not_logged_syslinux_v5);
    RUN_TEST(kolibrios_logged);
    RUN_TEST(reactos_logged);
    RUN_TEST(grub4dos_logged);
    RUN_TEST(grub2_version_logged);
    RUN_TEST(efi_via_img_logged);
    RUN_TEST(efi_standard_logged);
    RUN_TEST(bootmgr_bios_only_logged);
    RUN_TEST(bootmgr_efi_only_logged);
    RUN_TEST(bootmgr_bios_and_efi_logged);
    RUN_TEST(winpe_i386_logged);
    RUN_TEST(winpe_amd64_logged);
    RUN_TEST(winpe_minint_logged);
    RUN_TEST(winpe_with_minint_suffix);
    RUN_TEST(wininst_esd_logged);
    RUN_TEST(wininst_wim_logged);
    RUN_TEST(needs_ntfs_logged);
    RUN_TEST(symlinks_rr_logged);
    RUN_TEST(symlinks_udf_logged);
    RUN_TEST(no_winpe_line_when_not_set);
    RUN_TEST(no_wininst_when_not_set);
    PRINT_RESULTS();
    return g_failed > 0 ? 1 : 0;
}

#endif /* __linux__ */
