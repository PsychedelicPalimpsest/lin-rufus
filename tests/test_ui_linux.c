/* tests/test_ui_linux.c - Tests for version initialization and UI logic */
#include "../src/windows/rufus.h"
#include "../src/linux/version.h"
#include "../src/linux/device_combo.h"
#include "../src/linux/hyperlink.h"
#include "../src/linux/proposed_label.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Minimal test harness */
static int _pass = 0, _fail = 0;
#define CHECK_MSG(cond, msg) do { \
    if (cond) { _pass++; } else { _fail++; printf("  FAIL: %s\n", msg); } \
} while(0)
#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s\n", #name); test_##name(); } while(0)
#define TEST_RESULTS() printf("\n%d passed, %d failed\n", _pass, _fail)

extern uint16_t rufus_version[3];
void init_rufus_version(void);

TEST(version_major_correct)
{
    init_rufus_version();
    CHECK_MSG(rufus_version[0] == RUFUS_LINUX_VERSION_MAJOR,
              "version[0] must match RUFUS_LINUX_VERSION_MAJOR");
}

TEST(version_minor_correct)
{
    init_rufus_version();
    CHECK_MSG(rufus_version[1] == RUFUS_LINUX_VERSION_MINOR,
              "version[1] must match RUFUS_LINUX_VERSION_MINOR");
}

TEST(version_patch_correct)
{
    init_rufus_version();
    CHECK_MSG(rufus_version[2] == RUFUS_LINUX_VERSION_PATCH,
              "version[2] must match RUFUS_LINUX_VERSION_PATCH");
}

TEST(version_nonzero)
{
    init_rufus_version();
    CHECK_MSG(rufus_version[0] > 0, "major version must be > 0");
}

TEST(version_format_string)
{
    init_rufus_version();
    char buf[16];
    snprintf(buf, sizeof(buf), "%d.%d", rufus_version[0], rufus_version[1]);
    CHECK_MSG(buf[0] != '\0', "formatted version must be non-empty");
    CHECK_MSG(strchr(buf, '.') != NULL, "formatted version must contain a dot");
}

/* ---- device_open_in_fm_build_cmd tests ---- */

TEST(device_open_in_fm_build_cmd_basic)
{
    char buf[128];
    int rc = device_open_in_fm_build_cmd("/dev/sdb", buf, sizeof(buf));
    CHECK_MSG(rc == 1, "should return 1 on success");
    CHECK_MSG(strcmp(buf, "xdg-open '/dev/sdb'") == 0,
              "should produce \"xdg-open '/dev/sdb'\": quoted path");
}

TEST(device_open_in_fm_build_cmd_sdc)
{
    char buf[128];
    int rc = device_open_in_fm_build_cmd("/dev/sdc", buf, sizeof(buf));
    CHECK_MSG(rc == 1, "should return 1 for /dev/sdc");
    CHECK_MSG(strcmp(buf, "xdg-open '/dev/sdc'") == 0,
              "should produce \"xdg-open '/dev/sdc'\": quoted path");
}

TEST(device_open_in_fm_build_cmd_null_path)
{
    char buf[128];
    int rc = device_open_in_fm_build_cmd(NULL, buf, sizeof(buf));
    CHECK_MSG(rc == 0, "should return 0 for NULL path");
}

TEST(device_open_in_fm_build_cmd_empty_path)
{
    char buf[128];
    int rc = device_open_in_fm_build_cmd("", buf, sizeof(buf));
    CHECK_MSG(rc == 0, "should return 0 for empty path");
}

TEST(device_open_in_fm_build_cmd_buffer_too_small)
{
    char buf[5];
    int rc = device_open_in_fm_build_cmd("/dev/sdb", buf, sizeof(buf));
    CHECK_MSG(rc == 0, "should return 0 when buffer is too small");
}

TEST(device_open_in_fm_build_cmd_null_out)
{
    int rc = device_open_in_fm_build_cmd("/dev/sdb", NULL, 128);
    CHECK_MSG(rc == 0, "should return 0 for NULL output buffer");
}

TEST(device_open_in_fm_build_cmd_nvme)
{
    char buf[128];
    int rc = device_open_in_fm_build_cmd("/dev/nvme0n1", buf, sizeof(buf));
    CHECK_MSG(rc == 1, "should return 1 for nvme path");
    CHECK_MSG(strcmp(buf, "xdg-open '/dev/nvme0n1'") == 0,
              "should produce correct quoted command for nvme path");
}

/* ---- hyperlink_build_markup tests ---- */

TEST(hyperlink_basic_url_and_text)
{
    char buf[256];
    int r = hyperlink_build_markup("https://example.com", "Click here", buf, sizeof(buf));
    CHECK_MSG(r > 0, "should return positive length");
    CHECK_MSG(strstr(buf, "<a href=\"https://example.com\">") != NULL,
              "markup must contain the href");
    CHECK_MSG(strstr(buf, "Click here") != NULL,
              "markup must contain the display text");
    CHECK_MSG(strstr(buf, "</a>") != NULL,
              "markup must contain closing tag");
}

TEST(hyperlink_null_text_uses_url)
{
    char buf[256];
    int r = hyperlink_build_markup("https://rufus.ie", NULL, buf, sizeof(buf));
    CHECK_MSG(r > 0, "should return positive length");
    /* When text is NULL the URL itself is used as display text */
    CHECK_MSG(strstr(buf, "https://rufus.ie") != NULL,
              "markup must contain the URL as display text");
    CHECK_MSG(strstr(buf, "<a href=") != NULL, "must have opening anchor tag");
    CHECK_MSG(strstr(buf, "</a>") != NULL, "must have closing anchor tag");
}

TEST(hyperlink_xml_special_chars_escaped)
{
    char buf[512];
    int r = hyperlink_build_markup("https://x.com/?a=1&b=2", "A&B <Test>", buf, sizeof(buf));
    CHECK_MSG(r > 0, "should return positive length");
    /* & in URL and text must be escaped */
    CHECK_MSG(strstr(buf, "&amp;") != NULL, "ampersand must be escaped to &amp;");
    /* < and > must be escaped */
    CHECK_MSG(strstr(buf, "&lt;") != NULL, "less-than must be escaped");
    CHECK_MSG(strstr(buf, "&gt;") != NULL, "greater-than must be escaped");
    /* Raw & must not appear outside of entity sequences */
    /* Count occurrences of bare & (not part of &xxx;) */
    int bare_amp = 0;
    const char *p = buf;
    while ((p = strchr(p, '&')) != NULL) {
        /* Look for at least 2 chars after & — if next 3 chars are not alpha it's bare */
        if (strncmp(p, "&amp;", 5) != 0 &&
            strncmp(p, "&lt;",  4) != 0 &&
            strncmp(p, "&gt;",  4) != 0 &&
            strncmp(p, "&quot;",6) != 0 &&
            strncmp(p, "&apos;",6) != 0)
            bare_amp++;
        p++;
    }
    CHECK_MSG(bare_amp == 0, "no bare ampersands should appear in markup");
}

TEST(hyperlink_null_url_returns_error)
{
    char buf[256] = "untouched";
    int r = hyperlink_build_markup(NULL, "text", buf, sizeof(buf));
    CHECK_MSG(r == -1, "null url must return -1");
}

TEST(hyperlink_null_buf_returns_error)
{
    int r = hyperlink_build_markup("https://x.com", "x", NULL, 128);
    CHECK_MSG(r == -1, "null buf must return -1");
}

TEST(hyperlink_zero_bufsz_returns_error)
{
    char buf[4] = "xxx";
    int r = hyperlink_build_markup("https://x.com", "x", buf, 0);
    CHECK_MSG(r == -1, "zero bufsz must return -1");
}

TEST(hyperlink_empty_text_uses_url)
{
    char buf[256];
    int r = hyperlink_build_markup("https://rufus.ie", "", buf, sizeof(buf));
    CHECK_MSG(r > 0, "should return positive length for empty text");
    /* Empty text → url used as display */
    char *second_rufus = strstr(buf, "rufus.ie");
    CHECK_MSG(second_rufus != NULL, "URL should appear as display text too");
}

/* ---- IS_DD_BOOTABLE / IS_DD_ONLY macro tests (ISOHybrid detection) ---- */

/*
 * Verifies that IS_DD_BOOTABLE returns TRUE when is_bootable_img > 0,
 * and IS_DD_ONLY returns TRUE only when the image is not an ISO or
 * disable_iso is set.  These macros drive the ISOHybrid dialog in
 * on_start_clicked().
 */

TEST(is_dd_bootable_positive_when_bootable)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    CHECK_MSG(IS_DD_BOOTABLE(r), "is_bootable_img=1 must make IS_DD_BOOTABLE true");
}

TEST(is_dd_bootable_false_when_zero)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 0;
    CHECK_MSG(!IS_DD_BOOTABLE(r), "is_bootable_img=0 must make IS_DD_BOOTABLE false");
}

TEST(is_dd_bootable_false_when_negative)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = -1;  /* error / undetected */
    CHECK_MSG(!IS_DD_BOOTABLE(r), "is_bootable_img=-1 must make IS_DD_BOOTABLE false");
}

TEST(is_dd_only_iso_not_disabled)
{
    /* Bootable ISO with disable_iso=FALSE → NOT DD-only (ISO mode available) */
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    r.is_iso = TRUE;
    r.disable_iso = FALSE;
    CHECK_MSG(!IS_DD_ONLY(r), "bootable ISO with disable_iso=FALSE must NOT be DD-only");
}

TEST(is_dd_only_iso_disabled)
{
    /* Bootable ISO with disable_iso=TRUE → DD-only */
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    r.is_iso = TRUE;
    r.disable_iso = TRUE;
    CHECK_MSG(IS_DD_ONLY(r), "bootable ISO with disable_iso=TRUE must be DD-only");
}

TEST(is_dd_only_raw_image)
{
    /* Bootable non-ISO image → DD-only (no ISO extraction possible) */
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    r.is_iso = FALSE;
    r.disable_iso = FALSE;
    CHECK_MSG(IS_DD_ONLY(r), "bootable non-ISO image must be DD-only");
}

TEST(isohybrid_dialog_condition)
{
    /* Simulate a typical ISOHybrid ISO: bootable + is_iso + not disabled */
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    r.is_iso = TRUE;
    r.disable_iso = FALSE;
    /* The ISOHybrid dialog appears when: IS_DD_BOOTABLE && is_iso && !IS_DD_ONLY */
    BOOL show_dialog = IS_DD_BOOTABLE(r) && r.is_iso && !IS_DD_ONLY(r);
    CHECK_MSG(show_dialog, "ISOHybrid dialog condition should be TRUE for hybrid ISO");
}

TEST(isohybrid_dialog_skipped_for_raw_img)
{
    /* Non-ISO image: dialog should not be shown (IS_DD_ONLY handles it directly) */
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = 1;
    r.is_iso = FALSE;
    r.disable_iso = FALSE;
    BOOL show_dialog = IS_DD_BOOTABLE(r) && r.is_iso && !IS_DD_ONLY(r);
    CHECK_MSG(!show_dialog, "ISOHybrid dialog must be skipped for non-ISO images");
}

/* ---- SetProposedLabel / get_iso_proposed_label tests ---- */

TEST(proposed_label_iso_label_returned)
{
    /* Normal case: ISO has a label → return it */
    const char *result = get_iso_proposed_label(FALSE, "/tmp/ubuntu.iso", "UBUNTU_JAMMY");
    CHECK_MSG(result != NULL, "should not return NULL when user has not changed label");
    CHECK_MSG(strcmp(result, "UBUNTU_JAMMY") == 0, "should return ISO label");
}

TEST(proposed_label_user_changed_returns_null)
{
    /* User manually edited the label → preserve it (return NULL) */
    const char *result = get_iso_proposed_label(TRUE, "/tmp/ubuntu.iso", "UBUNTU_JAMMY");
    CHECK_MSG(result == NULL, "should return NULL when user_changed=TRUE");
}

TEST(proposed_label_empty_img_label_returns_empty)
{
    /* ISO has no volume label → clear the entry */
    const char *result = get_iso_proposed_label(FALSE, "/tmp/nolabel.iso", "");
    CHECK_MSG(result != NULL, "should not return NULL");
    CHECK_MSG(result[0] == '\0', "should return empty string when img_label is empty");
}

TEST(proposed_label_null_img_label_returns_empty)
{
    /* img_label is NULL (shouldn't happen but be robust) */
    const char *result = get_iso_proposed_label(FALSE, "/tmp/nolabel.iso", NULL);
    CHECK_MSG(result != NULL, "should not return NULL for null img_label");
    CHECK_MSG(result[0] == '\0', "should return empty string when img_label is NULL");
}

TEST(proposed_label_null_image_path_returns_empty)
{
    /* No image is selected → clear */
    const char *result = get_iso_proposed_label(FALSE, NULL, "SOMEISO");
    CHECK_MSG(result != NULL, "should not return NULL when image_path is NULL");
    CHECK_MSG(result[0] == '\0', "should return empty string when image_path is NULL");
}

TEST(proposed_label_empty_image_path_returns_empty)
{
    /* Empty image_path → clear */
    const char *result = get_iso_proposed_label(FALSE, "", "SOMEISO");
    CHECK_MSG(result != NULL, "should not return NULL when image_path is empty");
    CHECK_MSG(result[0] == '\0', "should return empty string when image_path is empty");
}

TEST(proposed_label_not_user_changed_returns_label)
{
    /* user_changed=FALSE but was previously TRUE — now cleared: label is returned */
    const char *result = get_iso_proposed_label(FALSE, "/tmp/arch.iso", "ARCH_202401");
    CHECK_MSG(result != NULL, "must not return NULL");
    CHECK_MSG(strcmp(result, "ARCH_202401") == 0, "must return the ISO label");
}

TEST(proposed_label_user_changed_ignores_label_change)
{
    /* Even if the ISO label is different, user_changed prevents update */
    const char *result = get_iso_proposed_label(TRUE, "/tmp/mint.iso", "LMDE_6");
    CHECK_MSG(result == NULL, "user_changed must block any label update");
}

int main(void)
{
    printf("=== version tests ===\n");
    RUN(version_major_correct);
    RUN(version_minor_correct);
    RUN(version_patch_correct);
    RUN(version_nonzero);
    RUN(version_format_string);

    printf("\n=== device combo context menu tests ===\n");
    RUN(device_open_in_fm_build_cmd_basic);
    RUN(device_open_in_fm_build_cmd_sdc);
    RUN(device_open_in_fm_build_cmd_null_path);
    RUN(device_open_in_fm_build_cmd_empty_path);
    RUN(device_open_in_fm_build_cmd_buffer_too_small);
    RUN(device_open_in_fm_build_cmd_null_out);
    RUN(device_open_in_fm_build_cmd_nvme);

    printf("\n=== hyperlink_build_markup tests ===\n");
    RUN(hyperlink_basic_url_and_text);
    RUN(hyperlink_null_text_uses_url);
    RUN(hyperlink_xml_special_chars_escaped);
    RUN(hyperlink_null_url_returns_error);
    RUN(hyperlink_null_buf_returns_error);
    RUN(hyperlink_zero_bufsz_returns_error);
    RUN(hyperlink_empty_text_uses_url);

    printf("\n=== ISOHybrid detection / IS_DD_BOOTABLE macro tests ===\n");
    RUN(is_dd_bootable_positive_when_bootable);
    RUN(is_dd_bootable_false_when_zero);
    RUN(is_dd_bootable_false_when_negative);
    RUN(is_dd_only_iso_not_disabled);
    RUN(is_dd_only_iso_disabled);
    RUN(is_dd_only_raw_image);
    RUN(isohybrid_dialog_condition);
    RUN(isohybrid_dialog_skipped_for_raw_img);

    printf("\n=== SetProposedLabel / get_iso_proposed_label tests ===\n");
    RUN(proposed_label_iso_label_returned);
    RUN(proposed_label_user_changed_returns_null);
    RUN(proposed_label_empty_img_label_returns_empty);
    RUN(proposed_label_null_img_label_returns_empty);
    RUN(proposed_label_null_image_path_returns_empty);
    RUN(proposed_label_empty_image_path_returns_empty);
    RUN(proposed_label_not_user_changed_returns_label);
    RUN(proposed_label_user_changed_ignores_label_change);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
