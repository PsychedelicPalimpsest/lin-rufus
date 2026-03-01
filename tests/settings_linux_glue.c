/*
 * settings_linux_glue.c — build shim for test_settings_linux
 *
 * Provides:
 *  1. Minimal globals needed by stdio.c + rufus_init_paths()
 *     (localization-owned globals come from common/localization.c in EXTRA_SRC)
 *  2. rufus_init_paths() — from src/linux/rufus.c, compiled without GTK main()
 */
#include "rufus.h"

/* Globals used by stdio.c */
DWORD ErrorStatus = 0;

/* Globals used by rufus_init_paths() — declared extern in rufus.c */
char app_dir[MAX_PATH]      = { 0 };
char app_data_dir[MAX_PATH] = { 0 };
char user_dir[MAX_PATH]     = { 0 };
char *ini_file              = NULL;

/* Globals used by localization / lmprintf */
BOOL right_to_left_mode = FALSE;

/* Globals used by iso.c-related paths (pulled in transitively) */
BOOL op_in_progress      = FALSE;
int  dialog_showing      = 0;

/* Hash accel flags (referenced by hash_algos.c if pulled in) */
BOOL cpu_has_sha1_accel   = FALSE;
BOOL cpu_has_sha256_accel = FALSE;

/* Globals used by parser.c */
RUFUS_UPDATE update = { {0,0,0}, {0,0}, NULL, NULL };
windows_version_t WindowsVersion = { 0 };

/* bled stubs (needed by stdio.c's ExtractZip) */
void bled_init(void *a, void *b, void *c, void *d, void *e, void *f, void *g) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; }
int  bled_uncompress_to_dir(const char *a, const char *b, int c) { (void)a;(void)b;(void)c; return -1; }
void bled_exit(void) {}

/* Pull in rufus_init_paths() without GTK's main() */
#define USE_GTK
#include "../src/linux/rufus.c"
#undef USE_GTK
