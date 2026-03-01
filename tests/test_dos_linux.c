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
 * Embedded resource tests (item 31)
 * ================================================================ */

#include "resource.h"
/* GetResource is provided by stdfn.c */
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
