/*
 * test_dos_linux.c — Tests for dos.c Linux implementation
 *
 * Tests cover:
 *   • ExtractFreeDOS() — copies FreeDOS boot files to a target directory
 *   • SetDOSLocale()   — creates AUTOEXEC.BAT with basic locale settings
 *   • ExtractDOS()     — dispatches to ExtractFreeDOS based on boot_type
 *
 * The tests work by pointing app_dir at the project root so that
 * get_freedos_source_dir() can locate res/freedos/.
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include "framework.h"
#include "windows.h"
#include "rufus.h"
#include "localization.h"

/* Pull in the declarations */
#include "dos.h"

/* ================================================================
 * Globals — defined in globals.c, declared extern here
 * ================================================================ */

extern DWORD ErrorStatus;
extern char app_dir[MAX_PATH];
extern char app_data_dir[MAX_PATH];
extern char user_dir[MAX_PATH];
extern char *ini_file;
extern BOOL op_in_progress;
extern BOOL right_to_left_mode;
extern int  dialog_showing;
extern BOOL en_msg_mode;
extern RUFUS_UPDATE update;
extern windows_version_t WindowsVersion;
extern loc_cmd* selected_locale;
extern BOOL cpu_has_sha1_accel;
extern BOOL cpu_has_sha256_accel;
extern int  boot_type;
extern HWND hBootType;

/* ================================================================
 * Helpers
 * ================================================================ */

/* Create a temporary directory and return its path (caller must free).
 * The directory is created as /tmp/rufus_test_XXXXXX */
static char* make_tmpdir(void)
{
    char tmpl[] = "/tmp/rufus_dos_XXXXXX";
    char* p = mkdtemp(tmpl);
    if (!p) return NULL;
    return strdup(p);
}

/* Recursively remove a directory tree (simple, no symlink follow) */
static void rm_rf(const char* path)
{
    DIR *d = opendir(path);
    if (!d) { remove(path); return; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char sub[2048];
        snprintf(sub, sizeof(sub), "%s/%s", path, de->d_name);
        struct stat st;
        if (lstat(sub, &st) == 0 && S_ISDIR(st.st_mode))
            rm_rf(sub);
        else
            remove(sub);
    }
    closedir(d);
    rmdir(path);
}

/* Check whether a file exists and is non-empty */
static int file_exists_nonempty(const char* path)
{
    struct stat st;
    return (stat(path, &st) == 0 && st.st_size > 0) ? 1 : 0;
}

/* Find the project root by walking up from the executable path stored in
 * app_dir until we find a directory containing res/freedos/. */
static void set_app_dir_to_project_root(void)
{
    /* The test binary is built in tests/, whose parent is the project root. */
    char candidate[MAX_PATH];
    /* app_dir is already set to the binary directory; try parent directories */
    /* First, try app_dir itself */
    snprintf(candidate, sizeof(candidate), "%sres/freedos/COMMAND.COM", app_dir);
    if (access(candidate, F_OK) == 0)
        return; /* already correct */
    /* Try parent: app_dir/../res/freedos/COMMAND.COM */
    snprintf(candidate, sizeof(candidate), "%s../res/freedos/COMMAND.COM", app_dir);
    if (access(candidate, F_OK) == 0) {
        /* Set app_dir to the parent */
        char parent[MAX_PATH];
        snprintf(parent, sizeof(parent), "%s../", app_dir);
        strncpy(app_dir, parent, sizeof(app_dir) - 1);
        app_dir[sizeof(app_dir) - 1] = '\0';
        return;
    }
    /* Fallback: use cwd */
}

/* ================================================================
 * Tests
 * ================================================================ */

TEST(extract_freedos_null_path)
{
    CHECK(ExtractFreeDOS(NULL) == FALSE);
}

TEST(extract_freedos_nonexistent_path)
{
    CHECK(ExtractFreeDOS("/tmp/__no_such_dir_rufus_test_freedos__/") == FALSE);
}

TEST(extract_freedos_returns_true_on_success)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    BOOL result = ExtractFreeDOS(target_with_sep);
    rm_rf(target);
    free(target);

    CHECK_INT_EQ(TRUE, result);
}

TEST(extract_freedos_command_com_present)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    BOOL ok = ExtractFreeDOS(target_with_sep);
    if (!ok) { rm_rf(target); free(target); CHECK(ok); return; }

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/COMMAND.COM", target);
    int found = file_exists_nonempty(path);

    rm_rf(target);
    free(target);

    CHECK(found);
}

TEST(extract_freedos_kernel_sys_present)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    BOOL ok = ExtractFreeDOS(target_with_sep);
    if (!ok) { rm_rf(target); free(target); CHECK(ok); return; }

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/KERNEL.SYS", target);
    int found = file_exists_nonempty(path);

    rm_rf(target);
    free(target);

    CHECK(found);
}

TEST(extract_freedos_locale_dir_created)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    BOOL ok = ExtractFreeDOS(target_with_sep);
    if (!ok) { rm_rf(target); free(target); CHECK(ok); return; }

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/LOCALE", target);
    struct stat st;
    int found = (stat(path, &st) == 0 && S_ISDIR(st.st_mode));

    rm_rf(target);
    free(target);

    CHECK(found);
}

TEST(extract_freedos_ega_cpx_in_locale)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    BOOL ok = ExtractFreeDOS(target_with_sep);
    if (!ok) { rm_rf(target); free(target); CHECK(ok); return; }

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/LOCALE/EGA.CPX", target);
    int found = file_exists_nonempty(path);

    rm_rf(target);
    free(target);

    CHECK(found);
}

TEST(extract_freedos_display_exe_in_locale)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    BOOL ok = ExtractFreeDOS(target_with_sep);
    if (!ok) { rm_rf(target); free(target); CHECK(ok); return; }

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/LOCALE/DISPLAY.EXE", target);
    int found = file_exists_nonempty(path);

    rm_rf(target);
    free(target);

    CHECK(found);
}

TEST(extract_freedos_autoexec_bat_created)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    BOOL ok = ExtractFreeDOS(target_with_sep);
    if (!ok) { rm_rf(target); free(target); CHECK(ok); return; }

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/AUTOEXEC.BAT", target);
    int found = (access(path, F_OK) == 0);

    rm_rf(target);
    free(target);

    CHECK(found);
}

TEST(extract_dos_freedos_boot_type)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    boot_type = BT_FREEDOS;
    BOOL ok = ExtractDOS(target_with_sep);

    rm_rf(target);
    free(target);

    CHECK_INT_EQ(TRUE, ok);
}

TEST(extract_dos_unknown_boot_type_returns_false)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    boot_type = BT_MSDOS; /* MS-DOS not supported on Linux — returns FALSE */
    BOOL ok = ExtractDOS(target_with_sep);

    rm_rf(target);
    free(target);

    CHECK_INT_EQ(FALSE, ok);
}

TEST(set_dos_locale_creates_autoexec)
{
    char *target = make_tmpdir();
    CHECK(target != NULL);

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    BOOL ok = SetDOSLocale(target_with_sep, TRUE);
    if (!ok) { rm_rf(target); free(target); CHECK(ok); return; }

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/AUTOEXEC.BAT", target);
    int found = (access(path, F_OK) == 0);

    rm_rf(target);
    free(target);

    CHECK(found);
}

TEST(set_dos_locale_null_returns_false)
{
    CHECK(SetDOSLocale(NULL, TRUE) == FALSE);
}

/* ================================================================
 * SetDOSLocale keyboard detection tests (TDD — require injection hooks)
 * ================================================================ */

#ifdef RUFUS_TEST
/* Injection hooks provided by dos_locale.c when built with -DRUFUS_TEST */
extern void dos_locale_set_xkb_layout(const char* layout);
extern void dos_locale_set_etc_default_keyboard_path(const char* p);
extern void dos_locale_set_vconsole_path(const char* p);
#endif

TEST(set_dos_locale_detects_german_keyboard)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
    return;
#else
    dos_locale_set_xkb_layout("de");

    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);

    BOOL ok = SetDOSLocale(sep, TRUE);

    /* Read AUTOEXEC.BAT and look for "GR" (German DOS keyboard code in keyb command) */
    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(cfg, "r");
    int found_gr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " GR,") || strstr(line, " gr,"))
                found_gr = 1;
        }
        fclose(f);
    }

    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);

    CHECK(ok);
    CHECK_MSG(found_gr, "German XKB layout → AUTOEXEC.BAT should reference 'GR' keyboard");
#endif
}

TEST(set_dos_locale_detects_french_keyboard)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
    return;
#else
    dos_locale_set_xkb_layout("fr");

    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);

    BOOL ok = SetDOSLocale(sep, TRUE);

    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(cfg, "r");
    int found_fr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " FR,") || strstr(line, " fr,"))
                found_fr = 1;
        }
        fclose(f);
    }

    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);

    CHECK(ok);
    CHECK_MSG(found_fr, "French XKB layout → AUTOEXEC.BAT should reference 'FR' keyboard");
#endif
}

TEST(set_dos_locale_unknown_falls_back_to_us)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
    return;
#else
    dos_locale_set_xkb_layout("xx");  /* unknown layout */

    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);

    BOOL ok = SetDOSLocale(sep, TRUE);

    char bat[MAX_PATH];
    snprintf(bat, sizeof(bat), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(bat, "r");
    int found_us = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "US") || strstr(line, "us") || strstr(line, "437"))
                found_us = 1;
        }
        fclose(f);
    }

    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);

    CHECK(ok);
    CHECK_MSG(found_us, "Unknown XKB layout → AUTOEXEC.BAT should reference US/437");
#endif
}

TEST(set_dos_locale_british_maps_to_uk)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
    return;
#else
    dos_locale_set_xkb_layout("gb");

    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);

    BOOL ok = SetDOSLocale(sep, TRUE);

    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(cfg, "r");
    int found_uk = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " UK,") || strstr(line, " uk,"))
                found_uk = 1;
        }
        fclose(f);
    }

    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);

    CHECK(ok);
    CHECK_MSG(found_uk, "GB (British) XKB layout → AUTOEXEC.BAT should reference 'UK' keyboard");
#endif
}

TEST(set_dos_locale_us_no_fdconfig_menu)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
    return;
#else
    /* When US keyboard is in use, there's no need for a multi-language menu;
     * AUTOEXEC.BAT should mention 437 and US */
    dos_locale_set_xkb_layout("us");

    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);

    BOOL ok = SetDOSLocale(sep, TRUE);

    char bat[MAX_PATH];
    snprintf(bat, sizeof(bat), "%s/AUTOEXEC.BAT", target);
    int bat_exists = (access(bat, F_OK) == 0);

    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);

    CHECK(ok);
    CHECK_MSG(bat_exists, "US keyboard → AUTOEXEC.BAT should be created");
#endif
}

/* Helper: inject an XKB layout, call SetDOSLocale, scan AUTOEXEC.BAT for
 * a given uppercase keyboard code string (e.g. "SP", "NL", "SV") in the
 * keyb command, and clean up.  Returns 1 if found, 0 if not.
 * Windows parity: keyboard codes appear in AUTOEXEC.BAT (keyb XX,,\locale\...) */
#ifdef RUFUS_TEST
static int check_kb_in_fdconfig(const char* xkb, const char* expected_dos_upper)
{
    dos_locale_set_xkb_layout(xkb);
    char *target = make_tmpdir();
    if (!target) { dos_locale_set_xkb_layout(NULL); return -1; }
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);
    /* Check AUTOEXEC.BAT for the keyb XX,, command */
    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(cfg, "r");
    int found = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char upper[256];
            size_t i;
            for (i = 0; i < sizeof(upper)-1 && line[i]; i++)
                upper[i] = (char)toupper((unsigned char)line[i]);
            upper[i] = '\0';
            /* Match "keyb XX,," or "keyb XX\r\n" */
            char needle[32];
            snprintf(needle, sizeof(needle), " %s,", expected_dos_upper);
            if (strstr(upper, needle))
                found = 1;
        }
        fclose(f);
    }
    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);
    return found;
}

/* Helper: write a temporary keyboard config file and return its path (caller frees). */
static char* write_kb_config_file(const char* contents)
{
    char tmpl[] = "/tmp/rufus_kbcfg_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return NULL;
    write(fd, contents, strlen(contents));
    close(fd);
    return strdup(tmpl);
}
#endif /* RUFUS_TEST */

TEST(vconsole_keymap_de_maps_to_gr)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* Simulate /etc/vconsole.conf with KEYMAP=de on a Fedora/RHEL system */
    char *vcfg = write_kb_config_file("KEYMAP=\"de\"\nFONT=eurlatgr\n");
    CHECK(vcfg != NULL);
    dos_locale_set_etc_default_keyboard_path("/nonexistent/keyboard.cfg");
    dos_locale_set_vconsole_path(vcfg);

    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    BOOL ok = SetDOSLocale(sep, TRUE);

    /* keyboard code appears in AUTOEXEC.BAT keyb command (Windows parity) */
    char cfg_path[MAX_PATH];
    snprintf(cfg_path, sizeof(cfg_path), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(cfg_path, "r");
    int found_gr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " GR,") || strstr(line, " gr,"))
                found_gr = 1;
        }
        fclose(f);
    }

    dos_locale_set_etc_default_keyboard_path(NULL);
    dos_locale_set_vconsole_path(NULL);
    rm_rf(target); free(target);
    unlink(vcfg); free(vcfg);

    CHECK(ok);
    CHECK_MSG(found_gr, "vconsole KEYMAP=de -> AUTOEXEC.BAT should reference 'GR' keyboard");
#endif
}

TEST(vconsole_keymap_with_variant_strips_suffix)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* Some systems use KEYMAP=de-latin1 -- the variant should be stripped */
    char *vcfg = write_kb_config_file("KEYMAP=de-latin1\n");
    CHECK(vcfg != NULL);
    dos_locale_set_etc_default_keyboard_path("/nonexistent/keyboard.cfg");
    dos_locale_set_vconsole_path(vcfg);

    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    BOOL ok = SetDOSLocale(sep, TRUE);

    char cfg_path[MAX_PATH];
    snprintf(cfg_path, sizeof(cfg_path), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(cfg_path, "r");
    int found_gr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " GR,") || strstr(line, " gr,"))
                found_gr = 1;
        }
        fclose(f);
    }

    dos_locale_set_etc_default_keyboard_path(NULL);
    dos_locale_set_vconsole_path(NULL);
    rm_rf(target); free(target);
    unlink(vcfg); free(vcfg);

    CHECK(ok);
    CHECK_MSG(found_gr, "KEYMAP=de-latin1 should map to 'GR' (variant suffix stripped)");
#endif
}

TEST(etc_default_keyboard_takes_priority_over_vconsole)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* /etc/default/keyboard says fr, vconsole says de -- fr should win */
    char *kbcfg = write_kb_config_file("XKBLAYOUT=fr\n");
    char *vcfg  = write_kb_config_file("KEYMAP=de\n");
    CHECK(kbcfg != NULL && vcfg != NULL);
    dos_locale_set_etc_default_keyboard_path(kbcfg);
    dos_locale_set_vconsole_path(vcfg);

    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);

    /* keyboard code appears in AUTOEXEC.BAT keyb command (Windows parity) */
    char cfg_path[MAX_PATH];
    snprintf(cfg_path, sizeof(cfg_path), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(cfg_path, "r");
    int found_fr = 0, found_gr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " FR,") || strstr(line, " fr,")) found_fr = 1;
            if (strstr(line, " GR,") || strstr(line, " gr,")) found_gr = 1;
        }
        fclose(f);
    }

    dos_locale_set_etc_default_keyboard_path(NULL);
    dos_locale_set_vconsole_path(NULL);
    rm_rf(target); free(target);
    unlink(kbcfg); free(kbcfg);
    unlink(vcfg);  free(vcfg);

    CHECK_MSG(found_fr, "/etc/default/keyboard (fr) takes priority over vconsole (de): should find FR");
    CHECK_MSG(!found_gr, "/etc/default/keyboard (fr) takes priority over vconsole (de): should NOT find GR");
#endif
}

/* Helper: run SetDOSLocale with /etc/default/keyboard content, return keyb XX code found in AUTOEXEC.BAT */
#ifdef RUFUS_TEST
static int autoexec_keyb_code_from_keyboard_file(const char* keyboard_file_contents, char* code_out, size_t code_sz)
{
    char *kbcfg = write_kb_config_file(keyboard_file_contents);
    if (!kbcfg) return 0;
    dos_locale_set_etc_default_keyboard_path(kbcfg);
    dos_locale_set_vconsole_path("/nonexistent/vconsole.conf");

    char *target = make_tmpdir();
    if (!target) { unlink(kbcfg); free(kbcfg); return 0; }
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);

    char bat[MAX_PATH];
    snprintf(bat, sizeof(bat), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(bat, "r");
    int found = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            /* Look for "keyb XX,," pattern */
            char *p = strstr(line, "keyb ");
            if (!p) p = strstr(line, "KEYB ");
            if (p) {
                p += 5;
                size_t i = 0;
                while (*p && *p != ',' && !isspace((unsigned char)*p) && i < code_sz - 1)
                    code_out[i++] = (char)toupper((unsigned char)*p++);
                code_out[i] = '\0';
                found = 1;
                break;
            }
        }
        fclose(f);
    }

    dos_locale_set_etc_default_keyboard_path(NULL);
    dos_locale_set_vconsole_path(NULL);
    rm_rf(target); free(target);
    unlink(kbcfg); free(kbcfg);
    return found;
}
#endif /* RUFUS_TEST */

TEST(swiss_french_variant_uses_sf_keyboard)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    char code[16] = {0};
    int found = autoexec_keyb_code_from_keyboard_file(
        "XKBLAYOUT=\"ch\"\nXKBVARIANT=\"fr\"\n", code, sizeof(code));
    CHECK_MSG(found, "Should find keyb command in AUTOEXEC.BAT");
    CHECK_MSG(strcmp(code, "SF") == 0,
              "Swiss French (ch + fr variant) -> DOS keyboard 'SF'");
#endif
}

TEST(swiss_german_no_variant_uses_sg_keyboard)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    char code[16] = {0};
    int found = autoexec_keyb_code_from_keyboard_file(
        "XKBLAYOUT=\"ch\"\n", code, sizeof(code));
    CHECK_MSG(found, "Should find keyb command in AUTOEXEC.BAT");
    CHECK_MSG(strcmp(code, "SG") == 0,
              "Swiss German (ch, no variant) -> DOS keyboard 'SG'");
#endif
}

TEST(serbian_latin_variant_uses_yu_keyboard)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    char code[16] = {0};
    int found = autoexec_keyb_code_from_keyboard_file(
        "XKBLAYOUT=\"rs\"\nXKBVARIANT=\"latin\"\n", code, sizeof(code));
    CHECK_MSG(found, "Should find keyb command in AUTOEXEC.BAT");
    CHECK_MSG(strcmp(code, "YU") == 0,
              "Serbian Latin (rs + latin variant) -> DOS keyboard 'YU'");
#endif
}

TEST(serbian_cyrillic_default_rs_uses_yc_keyboard)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* Serbia XKB without variant defaults to Cyrillic -> DOS 'YC' */
    char code[16] = {0};
    int found = autoexec_keyb_code_from_keyboard_file(
        "XKBLAYOUT=\"rs\"\n", code, sizeof(code));
    CHECK_MSG(found, "Should find keyb command in AUTOEXEC.BAT");
    CHECK_MSG(strcmp(code, "YC") == 0,
              "Serbian Cyrillic default (rs, no variant) -> DOS keyboard 'YC'");
#endif
}

TEST(set_dos_locale_spanish_maps_to_sp)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_kb_in_fdconfig("es", "SP") == 1,
              "Spanish XKB 'es' -> DOS 'SP'");
#endif
}

TEST(set_dos_locale_dutch_maps_to_nl)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_kb_in_fdconfig("nl", "NL") == 1,
              "Dutch XKB 'nl' -> DOS 'NL'");
#endif
}

TEST(set_dos_locale_italian_maps_to_it)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_kb_in_fdconfig("it", "IT") == 1,
              "Italian XKB 'it' -> DOS 'IT'");
#endif
}

TEST(set_dos_locale_swedish_maps_to_sv)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_kb_in_fdconfig("se", "SV") == 1,
              "Swedish XKB 'se' -> DOS 'SV'");
#endif
}

TEST(set_dos_locale_norwegian_maps_to_no)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_kb_in_fdconfig("no", "NO") == 1,
              "Norwegian XKB 'no' -> DOS 'NO'");
#endif
}

TEST(set_dos_locale_russian_maps_to_ru)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_kb_in_fdconfig("ru", "RU") == 1,
              "Russian XKB 'ru' -> DOS 'RU'");
#endif
}

TEST(set_dos_locale_polish_maps_to_pl)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_kb_in_fdconfig("pl", "PL") == 1,
              "Polish XKB 'pl' -> DOS 'PL'");
#endif
}

TEST(latam_xkb_maps_to_la_keyboard)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* 'latam' is the correct XKB layout code for Latin American Spanish */
    CHECK_MSG(check_kb_in_fdconfig("latam", "LA") == 1,
              "Latin American Spanish XKB 'latam' -> DOS 'LA'");
#endif
}

TEST(la_xkb_laos_does_not_map_to_la_keyboard)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* 'la' is Laos in XKB — should NOT produce Latin American DOS keyboard */
    CHECK_MSG(check_kb_in_fdconfig("la", "LA") == 0,
              "Laos XKB 'la' should NOT map to DOS Latin American 'LA' keyboard");
#endif
}
/* ================================================================
 * Keyboard driver file selection tests (keybrd2.sys parity)
 * Windows SetDOSLocale selects keyboard.sys vs keybrd2.sys based on
 * which fd_kb* list the keyboard code appears in.  The Linux port
 * must do the same.
 *
 * fd_kb1 (keyboard.sys): be br cf co cz dk dv fr gr hu it jp la lh
 *                         nl no pl po rh sf sg sk sp su sv uk us yu
 * fd_kb2 (keybrd2.sys) : bg ce gk is ro ru rx tr tt yc
 * ================================================================ */
#ifdef RUFUS_TEST
/* Helper: check that AUTOEXEC.BAT references the expected keyboard driver.
 * Returns 1 if found, 0 if not found, -1 on error.
 * Windows parity: KEYB.EXE is loaded from AUTOEXEC.BAT, not FDCONFIG.SYS. */
static int check_driver_in_fdconfig(const char* xkb, const char* expected_driver)
{
    dos_locale_set_xkb_layout(xkb);
    char *target = make_tmpdir();
    if (!target) { dos_locale_set_xkb_layout(NULL); return -1; }
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);
    /* Windows puts keyboard driver in AUTOEXEC.BAT, not CONFIG.SYS */
    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(cfg, "r");
    int found = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            /* Case-insensitive search for the driver filename */
            char *p = line;
            while (*p) { *p = (char)toupper((unsigned char)*p); p++; }
            if (strstr(line, expected_driver))
                found = 1;
        }
        fclose(f);
    }
    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);
    return found;
}

/* Helper: returns 1 if FDCONFIG.SYS contains any DEVICE= or !DEVICE= line
 * referencing KEYB.EXE. Windows parity: KEYB.EXE should only be in AUTOEXEC.BAT. */
static int fdconfig_has_keyb_device_line(const char* xkb)
{
    dos_locale_set_xkb_layout(xkb);
    char *target = make_tmpdir();
    if (!target) { dos_locale_set_xkb_layout(NULL); return -1; }
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);
    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg, "r");
    int found = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char upper[256];
            size_t i;
            for (i = 0; i < sizeof(upper)-1 && line[i]; i++)
                upper[i] = (char)toupper((unsigned char)line[i]);
            upper[i] = '\0';
            if (strstr(upper, "KEYB.EXE"))
                found = 1;
        }
        fclose(f);
    }
    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);
    return found;
}
#endif /* RUFUS_TEST */

TEST(keyboard_sys_used_for_german)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* de -> GR -> fd_kb1 -> keyboard.sys */
    CHECK_MSG(check_driver_in_fdconfig("de", "KEYBOARD.SYS") == 1,
              "German (de) should use KEYBOARD.SYS");
#endif
}

TEST(keyboard_sys_used_for_french)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* fr -> FR -> fd_kb1 -> keyboard.sys */
    CHECK_MSG(check_driver_in_fdconfig("fr", "KEYBOARD.SYS") == 1,
              "French (fr) should use KEYBOARD.SYS");
#endif
}

TEST(keybrd2_sys_used_for_russian)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* ru -> RU -> fd_kb2 -> keybrd2.sys */
    CHECK_MSG(check_driver_in_fdconfig("ru", "KEYBRD2.SYS") == 1,
              "Russian (ru) should use KEYBRD2.SYS");
#endif
}

TEST(keybrd2_sys_used_for_greek)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* gr -> GK -> fd_kb2 -> keybrd2.sys */
    CHECK_MSG(check_driver_in_fdconfig("gr", "KEYBRD2.SYS") == 1,
              "Greek (gr) should use KEYBRD2.SYS");
#endif
}

TEST(keybrd2_sys_used_for_turkish)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* tr -> TR -> fd_kb2 -> keybrd2.sys */
    CHECK_MSG(check_driver_in_fdconfig("tr", "KEYBRD2.SYS") == 1,
              "Turkish (tr) should use KEYBRD2.SYS");
#endif
}

TEST(keyboard_sys_used_for_us)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* Windows parity: US/437 AUTOEXEC.BAT has echo line with human-readable names,
     * no keyb command (US English is the DOS default — no driver needed). */
    dos_locale_set_xkb_layout("us");
    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);
    char bat[MAX_PATH];
    snprintf(bat, sizeof(bat), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(bat, "r");
    int found_us = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char *p = line;
            while (*p) { *p = (char)toupper((unsigned char)*p); p++; }
            if (strstr(line, "US-ENGLISH")) found_us = 1;
        }
        fclose(f);
    }
    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);
    CHECK_MSG(found_us == 1,
              "US locale AUTOEXEC.BAT should show 'US-English' (human-readable name)");
#endif
}

TEST(us_locale_no_fdconfig_sys)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* Windows parity: US/437 creates only AUTOEXEC.BAT, no FDCONFIG.SYS */
    dos_locale_set_xkb_layout("us");
    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);
    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/FDCONFIG.SYS", target);
    int fdconfig_exists = (access(cfg, F_OK) == 0);
    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);
    CHECK_MSG(!fdconfig_exists,
              "US locale should NOT create FDCONFIG.SYS (Windows parity)");
#endif
}

TEST(fdconfig_has_no_keyb_device_line_german)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* Windows parity: FDCONFIG.SYS should have only menu items, no DEVICE=KEYB lines */
    CHECK_MSG(fdconfig_has_keyb_device_line("de") == 0,
              "FDCONFIG.SYS should NOT have DEVICE=KEYB.EXE lines (Windows parity)");
#endif
}

/* ================================================================
 * FreeDOS codepage upgrade tests (CP850 -> CP858 parity)
 * Windows fd_upgrade_cp() upgrades CP850 to CP858 (adds Euro symbol).
 * The Linux port must do the same for FreeDOS targets.
 * ================================================================ */
#ifdef RUFUS_TEST
/* Helper: return the first codepage number found in FDCONFIG.SYS MENU line [NNN] */
static int get_fdconfig_cp(const char* xkb)
{
    dos_locale_set_xkb_layout(xkb);
    char *target = make_tmpdir();
    if (!target) { dos_locale_set_xkb_layout(NULL); return -1; }
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);
    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg, "r");
    int cp = -1;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            /* Lines like: "MENU 1) Use German keyboard with ... codepage [858]" */
            char *bracket = strrchr(line, '[');
            if (!bracket) continue;
            int parsed = atoi(bracket + 1);
            if (parsed > 0) { cp = parsed; break; }
        }
        fclose(f);
    }
    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);
    return cp;
}
#endif /* RUFUS_TEST */

TEST(freedos_upgrades_cp850_to_cp858_for_german)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* de -> GR, CP850 -> should be upgraded to CP858 for FreeDOS */
    int cp = get_fdconfig_cp("de");
    CHECK_MSG(cp == 858, "German FreeDOS should use CP858 (upgraded from CP850)");
#endif
}

TEST(freedos_upgrades_cp850_to_cp858_for_french)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* fr -> FR, CP850 -> should be upgraded to CP858 for FreeDOS */
    int cp = get_fdconfig_cp("fr");
    CHECK_MSG(cp == 858, "French FreeDOS should use CP858 (upgraded from CP850)");
#endif
}

TEST(freedos_keeps_cp866_for_russian)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* ru -> RU, CP866 -> should NOT be upgraded (only CP850 is upgraded) */
    int cp = get_fdconfig_cp("ru");
    CHECK_MSG(cp == 866, "Russian FreeDOS should keep CP866");
#endif
}

TEST(freedos_keeps_cp737_for_greek)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* gr -> GK, CP737 -> should NOT be upgraded */
    int cp = get_fdconfig_cp("gr");
    CHECK_MSG(cp == 737, "Greek FreeDOS should keep CP737");
#endif
}

/* ================================================================
 * AUTOEXEC.BAT parity tests
 * Windows writes a full keyboard+codepage setup in AUTOEXEC.BAT:
 *   GOTO %CONFIG%
 *   :1
 *   mode con codepage prepare=((cp) \locale\ega.cpx)
 *   mode con codepage select=cp
 *   keyb XX,,\locale\keyboard.sys
 *   :2
 * The Linux port should write the same structure.
 * ================================================================ */
#ifdef RUFUS_TEST
/* Helper: check AUTOEXEC.BAT contains a specific needle string. */
static int check_autoexec_contains(const char* xkb, const char* needle)
{
    dos_locale_set_xkb_layout(xkb);
    char *target = make_tmpdir();
    if (!target) { dos_locale_set_xkb_layout(NULL); return -1; }
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);
    char bat[MAX_PATH];
    snprintf(bat, sizeof(bat), "%s/AUTOEXEC.BAT", target);
    FILE *f = fopen(bat, "r");
    int found = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            /* Case-insensitive search */
            char upper_line[256], upper_needle[256];
            size_t i;
            for (i = 0; i < sizeof(upper_line)-1 && line[i]; i++)
                upper_line[i] = (char)toupper((unsigned char)line[i]);
            upper_line[i] = '\0';
            for (i = 0; i < sizeof(upper_needle)-1 && needle[i]; i++)
                upper_needle[i] = (char)toupper((unsigned char)needle[i]);
            upper_needle[i] = '\0';
            if (strstr(upper_line, upper_needle))
                found = 1;
        }
        fclose(f);
    }
    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);
    return found;
}
#endif /* RUFUS_TEST */

TEST(autoexec_has_goto_config_for_german)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_autoexec_contains("de", "GOTO") == 1,
              "German AUTOEXEC.BAT should have GOTO %%CONFIG%%");
#endif
}

TEST(autoexec_has_label_1_for_german)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_autoexec_contains("de", ":1") == 1,
              "German AUTOEXEC.BAT should have :1 label");
#endif
}

TEST(autoexec_has_keyb_command_for_german)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_autoexec_contains("de", "keyb") == 1,
              "German AUTOEXEC.BAT should have keyb command");
#endif
}

TEST(autoexec_has_mode_codepage_for_german)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_autoexec_contains("de", "codepage") == 1,
              "German AUTOEXEC.BAT should have mode codepage command");
#endif
}

TEST(autoexec_has_ega_cpx_for_german)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_autoexec_contains("de", "ega.cpx") == 1,
              "German AUTOEXEC.BAT should reference ega.cpx");
#endif
}

TEST(autoexec_has_label_2_for_german)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    CHECK_MSG(check_autoexec_contains("de", ":2") == 1,
              "German AUTOEXEC.BAT should have :2 (US fallback) label");
#endif
}

TEST(autoexec_uses_ega3_for_russian)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* Russian CP866 -> ega3.cpx (Cyrillic) */
    CHECK_MSG(check_autoexec_contains("ru", "ega3.cpx") == 1,
              "Russian AUTOEXEC.BAT should reference ega3.cpx");
#endif
}

TEST(autoexec_uses_ega5_for_greek)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* Greek CP737 -> ega5.cpx (Greek) */
    CHECK_MSG(check_autoexec_contains("gr", "ega5.cpx") == 1,
              "Greek AUTOEXEC.BAT should reference ega5.cpx");
#endif
}

/* ================================================================
 * Human-readable menu description tests
 * Windows uses kb_to_hr() / cp_to_hr() to show names like
 * "German keyboard with Western-European (Euro) codepage [858]".
 * The Linux port should show similar descriptions.
 * ================================================================ */
#ifdef RUFUS_TEST
/* Helper: check that FDCONFIG.SYS contains a needle (case-insensitive). */
static int fdconfig_contains(const char* xkb, const char* needle)
{
    dos_locale_set_xkb_layout(xkb);
    char *target = make_tmpdir();
    if (!target) { dos_locale_set_xkb_layout(NULL); return -1; }
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);
    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg, "r");
    int found = 0;
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            char upper_line[512], upper_needle[512];
            size_t i;
            for (i = 0; i < sizeof(upper_line)-1 && line[i]; i++)
                upper_line[i] = (char)toupper((unsigned char)line[i]);
            upper_line[i] = '\0';
            for (i = 0; i < sizeof(upper_needle)-1 && needle[i]; i++)
                upper_needle[i] = (char)toupper((unsigned char)needle[i]);
            upper_needle[i] = '\0';
            if (strstr(upper_line, upper_needle))
                found = 1;
        }
        fclose(f);
    }
    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);
    return found;
}
#endif /* RUFUS_TEST */

TEST(fdconfig_menu_shows_german_name)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* de -> GR -> menu should show "German" not just "GR" */
    CHECK_MSG(fdconfig_contains("de", "German") == 1,
              "German FDCONFIG.SYS menu should show 'German' keyboard name");
#endif
}

TEST(fdconfig_menu_shows_cp858_name)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* de -> CP858 -> menu should show Euro codepage description */
    CHECK_MSG(fdconfig_contains("de", "Euro") == 1,
              "German FDCONFIG.SYS menu should show 'Euro' in codepage name");
#endif
}

TEST(fdconfig_menu_shows_russian_name)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* ru -> RU -> menu should show "Russian" */
    CHECK_MSG(fdconfig_contains("ru", "Russian") == 1,
              "Russian FDCONFIG.SYS menu should show 'Russian' keyboard name");
#endif
}

TEST(fdconfig_menu_shows_french_name)
{
#ifndef RUFUS_TEST
    printf("SKIP (needs RUFUS_TEST)\n");
#else
    /* fr -> FR -> menu should show "French" */
    CHECK_MSG(fdconfig_contains("fr", "French") == 1,
              "French FDCONFIG.SYS menu should show 'French' keyboard name");
#endif
}

/* GetResource is provided by stdfn.c */
#include "resource.h"
extern uint8_t* GetResource(void *m, char *n, char *t, const char *d, DWORD *l, BOOL dup);
extern DWORD    GetResourceSize(void *m, char *n, char *t, const char *d);

TEST(getresource_command_com_not_null)
{
    DWORD size = 0;
    uint8_t *data = GetResource(NULL, MAKEINTRESOURCEA(IDR_FD_COMMAND_COM),
                                MAKEINTRESOURCEA(10), "COMMAND.COM", &size, FALSE);
    CHECK(data != NULL);
}

TEST(getresource_command_com_size_correct)
{
    DWORD size = 0;
    uint8_t *data = GetResource(NULL, MAKEINTRESOURCEA(IDR_FD_COMMAND_COM),
                                MAKEINTRESOURCEA(10), "COMMAND.COM", &size, FALSE);
    CHECK(data != NULL);
    CHECK_INT_EQ(87772, (int)size);
}

TEST(getresource_kernel_sys_not_null)
{
    DWORD size = 0;
    uint8_t *data = GetResource(NULL, MAKEINTRESOURCEA(IDR_FD_KERNEL_SYS),
                                MAKEINTRESOURCEA(10), "KERNEL.SYS", &size, FALSE);
    CHECK(data != NULL);
    CHECK_INT_EQ(46256, (int)size);
}

TEST(getresource_unknown_id_returns_null)
{
    DWORD size = 0;
    /* ID 9999 is not a FreeDOS resource */
    uint8_t *data = GetResource(NULL, MAKEINTRESOURCEA(9999),
                                MAKEINTRESOURCEA(10), "unknown", &size, FALSE);
    CHECK(data == NULL);
}

TEST(getresource_dup_allocates_copy)
{
    DWORD size1 = 0, size2 = 0;
    uint8_t *orig = GetResource(NULL, MAKEINTRESOURCEA(IDR_FD_COMMAND_COM),
                                MAKEINTRESOURCEA(10), "COMMAND.COM", &size1, FALSE);
    uint8_t *copy = GetResource(NULL, MAKEINTRESOURCEA(IDR_FD_COMMAND_COM),
                                MAKEINTRESOURCEA(10), "COMMAND.COM", &size2, TRUE);
    CHECK(orig != NULL);
    CHECK(copy != NULL);
    CHECK(orig != copy);         /* dup must return a different pointer */
    CHECK_INT_EQ((int)size1, (int)size2);
    CHECK(memcmp(orig, copy, size1) == 0);
    free(copy);
}

TEST(getresource_ega_cpx_not_null)
{
    DWORD size = 0;
    uint8_t *data = GetResource(NULL, MAKEINTRESOURCEA(IDR_FD_EGA1_CPX),
                                MAKEINTRESOURCEA(10), "EGA.CPX", &size, FALSE);
    CHECK(data != NULL);
    CHECK(size > 0);
}

TEST(extract_freedos_embedded_no_disk)
{
    /* ExtractFreeDOS must succeed using embedded data even when app_dir
     * points to a directory that has no res/freedos/ underneath it. */
    char saved_app_dir[MAX_PATH];
    strncpy(saved_app_dir, app_dir, sizeof(saved_app_dir) - 1);
    saved_app_dir[sizeof(saved_app_dir) - 1] = '\0';

    strncpy(app_dir, "/nonexistent_rufus_test/", sizeof(app_dir) - 1);

    char *target = make_tmpdir();
    if (!target) {
        strncpy(app_dir, saved_app_dir, sizeof(app_dir) - 1);
        CHECK(target != NULL);
        return;
    }

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);

    BOOL result = ExtractFreeDOS(target_with_sep);

    /* Verify COMMAND.COM was written from embedded data */
    char cmd_path[MAX_PATH];
    snprintf(cmd_path, sizeof(cmd_path), "%s/COMMAND.COM", target);
    int cmd_ok = file_exists_nonempty(cmd_path);

    rm_rf(target);
    free(target);

    strncpy(app_dir, saved_app_dir, sizeof(app_dir) - 1);

    CHECK_INT_EQ(TRUE, result);
    CHECK_INT_EQ(1, cmd_ok);
}

TEST(extract_freedos_embedded_content_correct_size)
{
    /* Embedded COMMAND.COM should be exactly 87772 bytes */
    char saved_app_dir[MAX_PATH];
    strncpy(saved_app_dir, app_dir, sizeof(saved_app_dir) - 1);
    saved_app_dir[sizeof(saved_app_dir) - 1] = '\0';

    strncpy(app_dir, "/nonexistent_rufus_test/", sizeof(app_dir) - 1);

    char *target = make_tmpdir();
    if (!target) {
        strncpy(app_dir, saved_app_dir, sizeof(app_dir) - 1);
        CHECK(target != NULL);
        return;
    }

    char target_with_sep[MAX_PATH];
    snprintf(target_with_sep, sizeof(target_with_sep), "%s/", target);
    ExtractFreeDOS(target_with_sep);

    char cmd_path[MAX_PATH];
    snprintf(cmd_path, sizeof(cmd_path), "%s/COMMAND.COM", target);
    struct stat st;
    long sz = (stat(cmd_path, &st) == 0) ? (long)st.st_size : -1;

    rm_rf(target);
    free(target);

    strncpy(app_dir, saved_app_dir, sizeof(app_dir) - 1);

    CHECK_INT_EQ(87772, (int)sz);
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
    printf("=== DOS Linux tests ===\n");

    /* Point app_dir at the project root so res/freedos/ is reachable */
    set_app_dir_to_project_root();

    RUN(extract_freedos_null_path);
    RUN(extract_freedos_nonexistent_path);
    RUN(extract_freedos_returns_true_on_success);
    RUN(extract_freedos_command_com_present);
    RUN(extract_freedos_kernel_sys_present);
    RUN(extract_freedos_locale_dir_created);
    RUN(extract_freedos_ega_cpx_in_locale);
    RUN(extract_freedos_display_exe_in_locale);
    RUN(extract_freedos_autoexec_bat_created);
    RUN(extract_dos_freedos_boot_type);
    RUN(extract_dos_unknown_boot_type_returns_false);
    RUN(set_dos_locale_creates_autoexec);
    RUN(set_dos_locale_null_returns_false);
    RUN(set_dos_locale_detects_german_keyboard);
    RUN(set_dos_locale_detects_french_keyboard);
    RUN(set_dos_locale_unknown_falls_back_to_us);
    RUN(set_dos_locale_british_maps_to_uk);
    RUN(set_dos_locale_us_no_fdconfig_menu);
    RUN(set_dos_locale_spanish_maps_to_sp);
    RUN(set_dos_locale_dutch_maps_to_nl);
    RUN(set_dos_locale_italian_maps_to_it);
    RUN(set_dos_locale_swedish_maps_to_sv);
    RUN(set_dos_locale_norwegian_maps_to_no);
    RUN(set_dos_locale_russian_maps_to_ru);
    RUN(set_dos_locale_polish_maps_to_pl);
    RUN(latam_xkb_maps_to_la_keyboard);
    RUN(la_xkb_laos_does_not_map_to_la_keyboard);
    RUN(vconsole_keymap_de_maps_to_gr);
    RUN(vconsole_keymap_with_variant_strips_suffix);
    RUN(etc_default_keyboard_takes_priority_over_vconsole);
    RUN(swiss_french_variant_uses_sf_keyboard);
    RUN(swiss_german_no_variant_uses_sg_keyboard);
    RUN(serbian_latin_variant_uses_yu_keyboard);
    RUN(serbian_cyrillic_default_rs_uses_yc_keyboard);

    RUN(keyboard_sys_used_for_german);
    RUN(keyboard_sys_used_for_french);
    RUN(keybrd2_sys_used_for_russian);
    RUN(keybrd2_sys_used_for_greek);
    RUN(keybrd2_sys_used_for_turkish);
    RUN(keyboard_sys_used_for_us);
    RUN(us_locale_no_fdconfig_sys);
    RUN(fdconfig_has_no_keyb_device_line_german);

    RUN(freedos_upgrades_cp850_to_cp858_for_german);
    RUN(freedos_upgrades_cp850_to_cp858_for_french);
    RUN(freedos_keeps_cp866_for_russian);
    RUN(freedos_keeps_cp737_for_greek);

    RUN(autoexec_has_goto_config_for_german);
    RUN(autoexec_has_label_1_for_german);
    RUN(autoexec_has_keyb_command_for_german);
    RUN(autoexec_has_mode_codepage_for_german);
    RUN(autoexec_has_ega_cpx_for_german);
    RUN(autoexec_has_label_2_for_german);
    RUN(autoexec_uses_ega3_for_russian);
    RUN(autoexec_uses_ega5_for_greek);

    RUN(fdconfig_menu_shows_german_name);
    RUN(fdconfig_menu_shows_cp858_name);
    RUN(fdconfig_menu_shows_russian_name);
    RUN(fdconfig_menu_shows_french_name);

    RUN(getresource_command_com_not_null);
    RUN(getresource_command_com_size_correct);
    RUN(getresource_kernel_sys_not_null);
    RUN(getresource_unknown_id_returns_null);
    RUN(getresource_dup_allocates_copy);
    RUN(getresource_ega_cpx_not_null);
    RUN(extract_freedos_embedded_no_disk);
    RUN(extract_freedos_embedded_content_correct_size);

    TEST_RESULTS();
}
#endif /* __linux__ */
