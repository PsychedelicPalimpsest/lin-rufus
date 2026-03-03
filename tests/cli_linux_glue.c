/*
 * cli_linux_glue.c — minimal stubs for the test_cli_linux build.
 *
 * cli.c calls cli_apply_options() which touches Rufus globals.
 * The tests only exercise cli_parse_args() and cli_options_init(),
 * so we only need the globals that cli_apply_options() externs.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

/* compat layer */
#include "windows.h"
#include "compat/winioctl.h"
#include "rufus.h"
#include "drive.h"

/* Rufus globals used by cli_apply_options() / cli_run() */
int    fs_type           = FS_FAT32;
int    boot_type         = BT_NON_BOOTABLE;
int    partition_type    = 0; /* PARTITION_STYLE_MBR == 0 */
int    target_type       = 0; /* TT_BIOS == 0 */
BOOL   quick_format      = TRUE;
BOOL   enable_verify_write = FALSE;
DWORD  selected_cluster_size = 0;
uint64_t persistence_size = 0;
BOOL   enable_bad_blocks = FALSE;
int    nb_passes_sel     = 0;
char  *unattend_xml_path = NULL;
BOOL   enable_HDDs       = FALSE;
char  *image_path        = NULL;
char   app_dir[MAX_PATH] = "/tmp";
DWORD  ErrorStatus       = 0;
RUFUS_DRIVE_INFO SelectedDrive;

/* drive stubs — cli tests only call cli_parse_args, not cli_run */
RUFUS_DRIVE rufus_drive[MAX_DRIVES];
void drive_linux_reset_drives(void) { }
void drive_linux_add_drive(const char *id, const char *name,
                           const char *display_name, uint64_t size)
{ (void)id; (void)name; (void)display_name; (void)size; }
BOOL GetDevices(DWORD devnum) { (void)devnum; return FALSE; }

/* FormatThread stub */
DWORD FormatThread(void *param) { (void)param; return 0; }

/* uprintf stub */
void uprintf(const char *fmt, ...) { (void)fmt; }

/* alert hook stubs — cli.c calls these when --no-prompt is set */
void alert_set_hook(BOOL (*hook)(int type)) { (void)hook; }
void alert_clear_hook(void) { }

void set_preselected_fs(int fs) { (void)fs; }
