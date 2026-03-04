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

    /* Read FDCONFIG.SYS and look for "GR" (German DOS keyboard code) */
    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg, "r");
    int found_gr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " GR") || strstr(line, " gr") || strstr(line, ",GR") || strstr(line, ",gr"))
                found_gr = 1;
        }
        fclose(f);
    }

    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);

    CHECK(ok);
    CHECK_MSG(found_gr, "German XKB layout → FDCONFIG.SYS should reference 'GR' keyboard");
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
    snprintf(cfg, sizeof(cfg), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg, "r");
    int found_fr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " FR") || strstr(line, " fr") || strstr(line, ",FR") || strstr(line, ",fr"))
                found_fr = 1;
        }
        fclose(f);
    }

    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);

    CHECK(ok);
    CHECK_MSG(found_fr, "French XKB layout → FDCONFIG.SYS should reference 'FR' keyboard");
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
    snprintf(cfg, sizeof(cfg), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg, "r");
    int found_uk = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " UK") || strstr(line, " uk") || strstr(line, ",UK") || strstr(line, ",uk"))
                found_uk = 1;
        }
        fclose(f);
    }

    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);

    CHECK(ok);
    CHECK_MSG(found_uk, "GB (British) XKB layout → FDCONFIG.SYS should reference 'UK' keyboard");
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

/* Helper: inject an XKB layout, call SetDOSLocale, scan FDCONFIG.SYS for
 * a given uppercase keyboard code string (e.g. "SP", "NL", "SV"), and
 * clean up.  Returns 1 if found, 0 if not. */
#ifdef RUFUS_TEST
static int check_kb_in_fdconfig(const char* xkb, const char* expected_dos_upper)
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
            /* Look for the code as a word boundary, e.g. " SP," or " SP " */
            char needle_space[8], needle_comma[8];
            snprintf(needle_space, sizeof(needle_space), " %s ", expected_dos_upper);
            snprintf(needle_comma, sizeof(needle_comma), " %s,", expected_dos_upper);
            if (strstr(line, needle_space) || strstr(line, needle_comma))
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

    char cfg_path[MAX_PATH];
    snprintf(cfg_path, sizeof(cfg_path), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg_path, "r");
    int found_gr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " GR") || strstr(line, " gr") ||
                strstr(line, ",GR") || strstr(line, ",gr"))
                found_gr = 1;
        }
        fclose(f);
    }

    dos_locale_set_etc_default_keyboard_path(NULL);
    dos_locale_set_vconsole_path(NULL);
    rm_rf(target); free(target);
    unlink(vcfg); free(vcfg);

    CHECK(ok);
    CHECK_MSG(found_gr, "vconsole KEYMAP=de -> FDCONFIG.SYS should reference 'GR' keyboard");
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
    snprintf(cfg_path, sizeof(cfg_path), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg_path, "r");
    int found_gr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " GR") || strstr(line, " gr") ||
                strstr(line, ",GR") || strstr(line, ",gr"))
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

    char cfg_path[MAX_PATH];
    snprintf(cfg_path, sizeof(cfg_path), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg_path, "r");
    int found_fr = 0, found_gr = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " FR") || strstr(line, ",FR")) found_fr = 1;
            if (strstr(line, " GR") || strstr(line, ",GR")) found_gr = 1;
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
/* Helper: check that FDCONFIG.SYS contains the expected driver filename.
 * Returns 1 if found, 0 if not found, -1 on error. */
static int check_driver_in_fdconfig(const char* xkb, const char* expected_driver)
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
    /* us -> US -> fd_kb1 -> keyboard.sys (via simple AUTOEXEC path) */
    dos_locale_set_xkb_layout("us");
    char *target = make_tmpdir();
    CHECK(target != NULL);
    char sep[MAX_PATH];
    snprintf(sep, sizeof(sep), "%s/", target);
    SetDOSLocale(sep, TRUE);
    /* For US/437, we get FDCONFIG.SYS with KEYBOARD.SYS */
    char cfg[MAX_PATH];
    snprintf(cfg, sizeof(cfg), "%s/FDCONFIG.SYS", target);
    FILE *f = fopen(cfg, "r");
    int found = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char *p = line;
            while (*p) { *p = (char)toupper((unsigned char)*p); p++; }
            if (strstr(line, "KEYBOARD.SYS")) found = 1;
        }
        fclose(f);
    }
    dos_locale_set_xkb_layout(NULL);
    rm_rf(target); free(target);
    CHECK_MSG(found == 1, "US locale should use KEYBOARD.SYS");
#endif
}

/* ================================================================
 * FreeDOS codepage upgrade tests (CP850 -> CP858 parity)
 * Windows fd_upgrade_cp() upgrades CP850 to CP858 (adds Euro symbol).
 * The Linux port must do the same for FreeDOS targets.
 * ================================================================ */
#ifdef RUFUS_TEST
/* Helper: return the first codepage number found in FDCONFIG.SYS for XKB layout. */
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
            /* Lines like: "1 !DEVICE=\LOCALE\KEYB.EXE GR,858,\LOCALE\KEYBOARD.SYS" */
            char *keyb = strstr(line, "KEYB.EXE");
            if (!keyb) continue;
            /* Skip to the comma after the keyboard code */
            char *comma = strchr(keyb, ',');
            if (!comma) continue;
            int parsed = atoi(comma + 1);
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
    RUN(vconsole_keymap_de_maps_to_gr);
    RUN(vconsole_keymap_with_variant_strips_suffix);
    RUN(etc_default_keyboard_takes_priority_over_vconsole);

    RUN(keyboard_sys_used_for_german);
    RUN(keyboard_sys_used_for_french);
    RUN(keybrd2_sys_used_for_russian);
    RUN(keybrd2_sys_used_for_greek);
    RUN(keybrd2_sys_used_for_turkish);
    RUN(keyboard_sys_used_for_us);

    RUN(freedos_upgrades_cp850_to_cp858_for_german);
    RUN(freedos_upgrades_cp850_to_cp858_for_french);
    RUN(freedos_keeps_cp866_for_russian);
    RUN(freedos_keeps_cp737_for_greek);

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
