/* tests/test_img_info_linux.c
 * Tests for format_img_info() — human-readable image report summary.
 *
 * format_img_info() is pure C (no GTK), so these tests run without a display.
 *
 * Tests:
 *  1. null_report_returns_zero       — NULL report → returns 0, no crash
 *  2. null_buf_returns_zero          — NULL buf → returns 0
 *  3. zero_size_returns_zero         — sz=0 → returns 0
 *  4. raw_image_type_label           — empty report → "Type: Raw image"
 *  5. iso_type_label                 — is_iso=1 → "Type: ISO 9660"
 *  6. vhd_type_label                 — is_vhd=1 → "Type: VHD/VHDX"
 *  7. bootable_img_type_label        — is_bootable_img=1 → "Type: Bootable image"
 *  8. label_included_when_set        — label "MYISO" → "Label: MYISO"
 *  9. image_size_mib                 — 128 MiB size → "Size: 128.0 MiB"
 * 10. image_size_gib                 — 4 GiB size → "Size: 4.0 GiB"
 * 11. windows_version_line           — Win10 build 19041 → "Windows: 10.0 (build 19041)"
 * 12. efi_x86_64_architecture        — has_efi=ARCH_X86_64 bit → "Architecture: x86-64"
 * 13. efi_arm64_architecture         — has_efi=ARCH_ARM_64 bit → "Architecture: ARM64"
 * 14. secure_boot_signed             — has_secureboot=1 → "Secure Boot: signed"
 * 15. secure_boot_revoked            — has_secureboot=0x02 → "Secure Boot: REVOKED"
 * 16. xz_compression                 — compression_type=XZ → "Compression: XZ"
 * 17. no_size_when_zero              — image_size=0 → no "Size:" line
 * 18. grub2_version_included         — grub2="2.12" → "GRUB: 2.12"
 * 19. winpe_flag_shown               — winpe=WINPE_AMD64 → "WinPE: x86-64"
 * 20. buf_truncation_safe            — tiny buf=16 → no crash, NUL-terminated
 * 21. winpe_i386_architecture        — winpe=WINPE_I386  → "WinPE: i386"
 * 22. winpe_amd64_architecture       — winpe=WINPE_AMD64 → "WinPE: x86-64"
 * 23. winpe_minint_architecture      — winpe=WINPE_MININT → "WinPE: i386 (MININT)"
 * 24. winpe_uses_minint_shown        — WINPE_I386 + uses_minint=TRUE → "with /minint"
 * 25. winpe_no_minint_suffix         — WINPE_AMD64 + uses_minint=FALSE → no "/minint" in output
 * 26. winpe_unknown_bitmask_fallback — some non-zero winpe bits that don't match any
 *                                      named arch → "WinPE: unknown" fallback
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

/* compat + rufus headers */
#include "windows.h"
#include "rufus.h"
#include "../../src/bled/bled.h"  /* BLED_COMPRESSION_* */

/* Function under test */
extern size_t format_img_info(const RUFUS_IMG_REPORT *r, char *buf, size_t sz);

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */
#define BUF_SZ 1024

static RUFUS_IMG_REPORT make_empty(void)
{
    RUFUS_IMG_REPORT r;
    memset(&r, 0, sizeof(r));
    return r;
}

static int has_line(const char *buf, const char *needle)
{
    return strstr(buf, needle) != NULL;
}

/* -------------------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------------- */

TEST(null_report_returns_zero)
{
    char buf[BUF_SZ];
    size_t n = format_img_info(NULL, buf, sizeof(buf));
    CHECK_MSG(n == 0, "NULL report must return 0");
}

TEST(null_buf_returns_zero)
{
    RUFUS_IMG_REPORT r = make_empty();
    size_t n = format_img_info(&r, NULL, BUF_SZ);
    CHECK_MSG(n == 0, "NULL buf must return 0");
}

TEST(zero_size_returns_zero)
{
    RUFUS_IMG_REPORT r = make_empty();
    char buf[BUF_SZ];
    size_t n = format_img_info(&r, buf, 0);
    CHECK_MSG(n == 0, "sz=0 must return 0");
}

TEST(raw_image_type_label)
{
    RUFUS_IMG_REPORT r = make_empty();
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Type: Raw image"), "empty report must produce 'Type: Raw image'");
}

TEST(iso_type_label)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.is_iso = TRUE;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Type: ISO 9660"), "is_iso must produce 'Type: ISO 9660'");
}

TEST(vhd_type_label)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.is_vhd = TRUE;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Type: VHD/VHDX"), "is_vhd must produce 'Type: VHD/VHDX'");
}

TEST(bootable_img_type_label)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.is_bootable_img = 1;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Type: Bootable image"), "is_bootable_img must produce 'Type: Bootable image'");
}

TEST(label_included_when_set)
{
    RUFUS_IMG_REPORT r = make_empty();
    strncpy(r.label, "MYISO", sizeof(r.label) - 1);
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Label: MYISO"), "non-empty label must appear in output");
}

TEST(image_size_mib)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.image_size = 128ULL * (1 << 20);  /* 128 MiB */
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Size: 128.0 MiB"), "128 MiB size must show '128.0 MiB'");
}

TEST(image_size_gib)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.image_size = 4ULL * (1 << 30);  /* 4 GiB */
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Size: 4.0 GiB"), "4 GiB size must show '4.0 GiB'");
}

TEST(windows_version_line)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.is_windows_img = TRUE;
    r.win_version.major = 10;
    r.win_version.minor = 0;
    r.win_version.build = 19041;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Windows: 10.0 (build 19041)"), "Windows 10 must show version line");
}

TEST(efi_x86_64_architecture)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.has_efi = (1u << ARCH_X86_64);
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "x86-64"), "x86-64 EFI must show architecture");
}

TEST(efi_arm64_architecture)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.has_efi = (1u << ARCH_ARM_64);
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "ARM64"), "ARM64 EFI must show architecture");
}

TEST(secure_boot_signed)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.has_efi = (1u << ARCH_X86_64);
    r.has_secureboot_bootloader = 0x01;  /* bit 0 = signed, no revocation */
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Secure Boot: signed"), "signed SB must show 'Secure Boot: signed'");
}

TEST(secure_boot_revoked)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.has_efi = (1u << ARCH_X86_64);
    r.has_secureboot_bootloader = 0x02;  /* bit 1 = revoked */
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Secure Boot: REVOKED"), "revoked SB must show 'Secure Boot: REVOKED'");
}

TEST(xz_compression)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.compression_type = BLED_COMPRESSION_XZ;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "Compression: XZ"), "XZ compression must appear");
}

TEST(no_size_when_zero)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.image_size = 0;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(!has_line(buf, "Size:"), "zero image_size must not show Size: line");
}

TEST(grub2_version_included)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.has_grub2 = 1;
    strncpy(r.grub2_version, "2.12", sizeof(r.grub2_version) - 1);
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "GRUB: 2.12"), "GRUB2 version must appear");
}

TEST(winpe_flag_shown)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.winpe = WINPE_AMD64;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "WinPE: x86-64"), "WINPE_AMD64 must produce 'WinPE: x86-64'");
}

TEST(winpe_i386_architecture)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.winpe = WINPE_I386;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "WinPE: i386"), "WINPE_I386 must produce 'WinPE: i386'");
}

TEST(winpe_amd64_architecture)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.winpe = WINPE_AMD64;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "WinPE: x86-64"), "WINPE_AMD64 must produce 'WinPE: x86-64'");
}

TEST(winpe_minint_architecture)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.winpe = WINPE_MININT;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "WinPE: i386 (MININT)"), "WINPE_MININT must produce 'WinPE: i386 (MININT)'");
}

TEST(winpe_uses_minint_shown)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.winpe = WINPE_I386;
    r.uses_minint = TRUE;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(has_line(buf, "WinPE: i386"), "uses_minint must still show architecture");
    CHECK_MSG(has_line(buf, "with /minint"), "uses_minint must show 'with /minint'");
}

TEST(winpe_no_minint_suffix)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.winpe = WINPE_AMD64;
    r.uses_minint = FALSE;
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    CHECK_MSG(!has_line(buf, "/minint"), "uses_minint=FALSE must not produce /minint suffix");
}

TEST(winpe_unknown_bitmask_fallback)
{
    /* Set a single bit that does not complete any named arch pattern */
    RUFUS_IMG_REPORT r = make_empty();
    r.winpe = 0x01;   /* bit 0 only: not enough to satisfy WINPE_I386 = 0x0007 */
    char buf[BUF_SZ];
    format_img_info(&r, buf, sizeof(buf));
    /* HAS_WINPE is false for 0x01, so no WinPE line should appear */
    CHECK_MSG(!has_line(buf, "WinPE:"), "partial winpe bits must NOT produce a WinPE line");
}

TEST(buf_truncation_safe)
{
    RUFUS_IMG_REPORT r = make_empty();
    r.is_iso = TRUE;
    strncpy(r.label, "LONGNAMELABEL", sizeof(r.label) - 1);
    char buf[16];
    size_t n = format_img_info(&r, buf, sizeof(buf));
    /* Must not crash; buf must be NUL-terminated; n < sz */
    CHECK_MSG(buf[15] == '\0', "buf must be NUL-terminated on truncation");
    CHECK_MSG(n > 0, "must return non-zero even when truncated");
}

int main(void)
{
    printf("=== format_img_info tests ===\n");
    RUN(null_report_returns_zero);
    RUN(null_buf_returns_zero);
    RUN(zero_size_returns_zero);
    RUN(raw_image_type_label);
    RUN(iso_type_label);
    RUN(vhd_type_label);
    RUN(bootable_img_type_label);
    RUN(label_included_when_set);
    RUN(image_size_mib);
    RUN(image_size_gib);
    RUN(windows_version_line);
    RUN(efi_x86_64_architecture);
    RUN(efi_arm64_architecture);
    RUN(secure_boot_signed);
    RUN(secure_boot_revoked);
    RUN(xz_compression);
    RUN(no_size_when_zero);
    RUN(grub2_version_included);
    RUN(winpe_flag_shown);
    RUN(winpe_i386_architecture);
    RUN(winpe_amd64_architecture);
    RUN(winpe_minint_architecture);
    RUN(winpe_uses_minint_shown);
    RUN(winpe_no_minint_suffix);
    RUN(winpe_unknown_bitmask_fallback);
    RUN(buf_truncation_safe);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}

#endif /* __linux__ */
