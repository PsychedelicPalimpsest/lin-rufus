/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: rufus.c — main entry point
 * Copyright © 2011-2026 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Linux main entry point and rufus.c function stubs */
#include "rufus.h"
#include "missing.h"
#include "version.h"
#include "polkit.h"
#include "paths.h"
#include "crash_handler.h"
#ifndef USE_GTK
#include "cli.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

/* ---- Function stubs ---- */
/* EnableControls is provided by ui_gtk.c when using the GTK UI */
#ifndef USE_GTK
void EnableControls(BOOL enable, BOOL remove_checkboxes)  { (void)enable;(void)remove_checkboxes; }
#endif

BOOL CALLBACK LogCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
    { (void)hDlg;(void)message;(void)wParam;(void)lParam; return FALSE; }

enum ArchType MachineToArch(WORD machine) {
    switch(machine) {
    case IMAGE_FILE_MACHINE_I386:  return ARCH_X86_32;
    case IMAGE_FILE_MACHINE_AMD64: return ARCH_X86_64;
    case IMAGE_FILE_MACHINE_ARM:   return ARCH_ARM_32;
    case IMAGE_FILE_MACHINE_ARMNT: return ARCH_ARM_32;
    case IMAGE_FILE_MACHINE_ARM64: return ARCH_ARM_64;
    default:                       return ARCH_UNKNOWN;
    }
}

void ClrAlertPromptHook(void) {}
/* SetFSFromISO / SetPartitionSchemeAndTargetSystem are always provided by
 * ui_combo_logic.c for all builds. */
HANDLE CreatePreallocatedFile(const char* path, DWORD access, DWORD share,
    LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, LONGLONG size)
    { (void)path;(void)access;(void)share;(void)sa;(void)disp;(void)flags;(void)size; return INVALID_HANDLE_VALUE; }

/* ---- Path / settings initialization ---- */

/*
 * Declared in globals.c — the paths used throughout the application.
 */
extern char app_dir[MAX_PATH];
extern char app_data_dir[MAX_PATH];
extern char user_dir[MAX_PATH];
extern char* ini_file;

/* Static storage for the ini_file path (must outlive the program). */
static char s_ini_path[MAX_PATH];

/*
 * rufus_init_paths() — initialise XDG-compliant application paths and the
 * settings INI file.
 *
 * app_dir      directory of the running executable (via /proc/self/exe)
 * app_data_dir $XDG_DATA_HOME/rufus  (or ~/.local/share/rufus)
 * user_dir     home directory (SUDO_USER-aware; see rufus_effective_home())
 * ini_file     $XDG_CONFIG_HOME/rufus/rufus.ini  (or ~/.config/rufus/rufus.ini)
 *
 * The INI directory and an empty INI file are created if they do not exist.
 */
void rufus_init_paths(void)
{
    char exe_path[PATH_MAX];
    ssize_t len;
    const char* xdg_data;
    const char* xdg_config;
    char home_buf[PATH_MAX];
    const char* home;
    char ini_dir[MAX_PATH];
    FILE* f;

    /* --- app_dir: directory containing the executable --- */
    len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        /* Strip the filename to get the directory */
        char* slash = strrchr(exe_path, '/');
        if (slash != NULL) {
            *slash = '\0';
            snprintf(app_dir, sizeof(app_dir), "%s/", exe_path);
        } else {
            snprintf(app_dir, sizeof(app_dir), "./");
        }
    } else {
        snprintf(app_dir, sizeof(app_dir), "./");
    }

    /* --- home directory: SUDO_USER-aware ---
     * When running as root via 'sudo rufus', use the original user's home
     * directory so that settings are stored in their profile, not root's.
     * This mirrors the Windows UAC behaviour. */
    home = rufus_effective_home(home_buf, sizeof(home_buf));
    snprintf(user_dir, sizeof(user_dir), "%s", home);

    /* --- app_data_dir: $XDG_DATA_HOME/rufus or ~/.local/share/rufus ---
     * If we resolved SUDO_USER's home, skip $XDG_DATA_HOME (which would be
     * root's XDG path) and build from the effective home directory. */
    xdg_data = (geteuid() == 0 && getenv("SUDO_USER") && getenv("SUDO_USER")[0])
               ? NULL : getenv("XDG_DATA_HOME");
    if (xdg_data != NULL && xdg_data[0] != '\0')
        snprintf(app_data_dir, sizeof(app_data_dir), "%s/rufus", xdg_data);
    else
        snprintf(app_data_dir, sizeof(app_data_dir), "%s/.local/share/rufus", home);

    /* Create app_data_dir if it doesn't exist */
    {
        char* p = app_data_dir + 1;  /* skip leading / */
        while (*p) {
            if (*p == '/') {
                *p = '\0';
                mkdir(app_data_dir, 0755);
                *p = '/';
            }
            p++;
        }
        mkdir(app_data_dir, 0755);
    }

    /* --- ini_file: $XDG_CONFIG_HOME/rufus/rufus.ini or ~/.config/rufus/rufus.ini ---
     * Same SUDO_USER logic: skip root's XDG_CONFIG_HOME when acting on behalf
     * of a sudo-invoking user. */
    xdg_config = (geteuid() == 0 && getenv("SUDO_USER") && getenv("SUDO_USER")[0])
                 ? NULL : getenv("XDG_CONFIG_HOME");
    if (xdg_config != NULL && xdg_config[0] != '\0')
        snprintf(ini_dir, sizeof(ini_dir), "%s/rufus", xdg_config);
    else
        snprintf(ini_dir, sizeof(ini_dir), "%s/.config/rufus", home);

    /* Create ini directory if it doesn't exist */
    {
        char* p = ini_dir + 1;
        while (*p) {
            if (*p == '/') {
                *p = '\0';
                mkdir(ini_dir, 0755);
                *p = '/';
            }
            p++;
        }
        mkdir(ini_dir, 0755);
    }

    snprintf(s_ini_path, sizeof(s_ini_path), "%s/rufus.ini", ini_dir);

    /* Create the INI file if it doesn't exist (so set_token_data_file can open it) */
    f = fopen(s_ini_path, "a");
    if (f != NULL) {
        fclose(f);
        ini_file = s_ini_path;
    } else {
        /* If we can't create the file, leave ini_file NULL */
        ini_file = NULL;
    }

    /* temp_dir — use TMPDIR if set, otherwise /tmp */
    const char *tmpenv = getenv("TMPDIR");
    if (tmpenv != NULL && tmpenv[0] != '\0')
        snprintf(temp_dir, sizeof(temp_dir), "%s", tmpenv);
    else
        snprintf(temp_dir, sizeof(temp_dir), "/tmp");

    uprintf("app_dir:      %s", app_dir);
    uprintf("app_data_dir: %s", app_data_dir);
    uprintf("user_dir:     %s", user_dir);
    uprintf("ini_file:     %s", ini_file ? ini_file : "(none)");
    uprintf("temp_dir:     %s", temp_dir);
}

/*
 * find_loc_file() — locate the embedded.loc localization file.
 *
 * Searches in order:
 *   1. <app_dir>/res/loc/embedded.loc   (development / running from build root)
 *   2. <app_dir>/embedded.loc           (same dir as binary, e.g. after install)
 *   3. RUFUS_DATADIR "/embedded.loc"    (compile-time installed path)
 *
 * Returns a pointer to a static buffer with the path on success, or NULL if
 * the file cannot be found.  The returned pointer is valid until the next
 * call to find_loc_file().
 */
const char *find_loc_file(void)
{
    static char loc_path[PATH_MAX];
    struct stat st;

    /* 1. Development: <app_dir>/res/loc/embedded.loc */
    snprintf(loc_path, sizeof(loc_path), "%sres/loc/embedded.loc", app_dir);
    if (stat(loc_path, &st) == 0 && S_ISREG(st.st_mode))
        return loc_path;

    /* 1b. Development (binary in src/ subdir): <app_dir>/../res/loc/embedded.loc */
    snprintf(loc_path, sizeof(loc_path), "%s../res/loc/embedded.loc", app_dir);
    if (stat(loc_path, &st) == 0 && S_ISREG(st.st_mode))
        return loc_path;

    /* 2. Installed alongside binary: <app_dir>/embedded.loc */
    snprintf(loc_path, sizeof(loc_path), "%sembedded.loc", app_dir);
    if (stat(loc_path, &st) == 0 && S_ISREG(st.st_mode))
        return loc_path;

#ifdef RUFUS_DATADIR
    /* 3. Compile-time data directory */
    snprintf(loc_path, sizeof(loc_path), "%s/embedded.loc", RUFUS_DATADIR);
    if (stat(loc_path, &st) == 0 && S_ISREG(st.st_mode))
        return loc_path;
#endif

    return NULL;
}

/* ---- Linux main entry point ---- */
#ifndef USE_GTK

/* Progress output for CLI mode — report to stdout */
void UpdateProgress(int op, float percent)
{
	(void)op;
	printf("[%3d%%]\r", (int)percent);
	fflush(stdout);
}

void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL f)
{
	(void)msg; (void)f;
	if (tot == 0) return;
	UpdateProgress(op, (float)((double)cur / (double)tot * 100.0));
}

int main(int argc, char *argv[])
{
	cli_options_t opts;
	int r;

	install_crash_handlers();

	/* Initialize paths (app_dir, app_data_dir, ini_file) before parsing args
	 * so settings can be read and locale data can be found. */
	rufus_init_paths();

	r = cli_parse_args(argc, argv, &opts);
	if (r == CLI_PARSE_HELP)
		return 0;
	if (r == CLI_PARSE_VERSION)
		return 0;
	if (r == CLI_PARSE_LIST) {
		cli_apply_options(&opts);
		return cli_print_devices(opts.json);
	}
	if (r != CLI_PARSE_OK)
		return 1;

	return cli_run(&opts);
}
#endif /* !USE_GTK */
