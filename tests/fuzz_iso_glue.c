/*
 * fuzz_iso_glue.c — stub globals and functions for the fuzz_iso build.
 *
 * iso.c has many dependencies on the rest of the Rufus binary (globals,
 * UI helpers, bled, wimlib, syslinux).  For fuzzing purposes we only need
 * ReadISOFileToBuffer() and ExtractISO() to work correctly; everything else
 * can be a no-op stub.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "windows.h"
#include "rufus.h"
#include "drive.h"

/* ── Logging ────────────────────────────────────────────────────────── */
/* uprintf / uprintfs are defined in linux/stdio.c which we include */

/* ── Globals expected by iso.c / iso_scan.c ─────────────────────────── */
RUFUS_IMG_REPORT      img_report          = { 0 };
RUFUS_UPDATE          update              = { {0,0,0}, {0,0}, NULL, NULL, NULL, 0 };
windows_version_t     WindowsVersion      = { 0 };
BOOL                  right_to_left_mode  = FALSE;
char                 *ini_file            = NULL;
char                 *save_image_type     = NULL;
uint64_t              md5sum_totalbytes   = 0;
BOOL                  preserve_timestamps = FALSE;
BOOL                  validate_md5sum     = FALSE;
BOOL                  op_in_progress      = FALSE;
HANDLE                format_thread       = NULL;
StrArray              modified_files      = { 0 };
uint16_t              embedded_sl_version[2] = { 0, 0 };
RUFUS_DRIVE_INFO      SelectedDrive       = { 0 };
HWND                  hDeviceList         = NULL;
HWND                  hMainDialog         = NULL;
DWORD                 ErrorStatus         = 0;
int                   boot_type           = 0;
int                   fs_type             = 0;
uint64_t              persistence_size    = 0;
char                 *image_path          = NULL;

/* Syslinux libfat sector constants (normally defined in syslinux.c) */
uint32_t LIBFAT_SECTOR_SHIFT = 9;
uint32_t LIBFAT_SECTOR_SIZE  = 512;
uint32_t LIBFAT_SECTOR_MASK  = 511;

/* ── UI stubs ────────────────────────────────────────────────────────── */
void     EnableControls(BOOL e, BOOL r)              { (void)e; (void)r; }
void     InitProgress(BOOL b)                        { (void)b; }
void     _UpdateProgressWithInfo(int op, int msg, uint64_t n, uint64_t total, BOOL force)
                                                     { (void)op; (void)msg; (void)n; (void)total; (void)force; }
LRESULT  SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
                                                     { (void)h; (void)m; (void)w; (void)l; return 0; }
BOOL     PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l)
                                                     { (void)h; (void)m; (void)w; (void)l; return TRUE; }
char    *FileDialog(BOOL s, char *p, const ext_t *e, UINT *sel)
                                                     { (void)s; (void)p; (void)e; (void)sel; return NULL; }

/* ── Device stubs ────────────────────────────────────────────────────── */
BOOL     GetOpticalMedia(IMG_SAVE *s)                { (void)s; return FALSE; }
char    *GetPhysicalName(DWORD idx)                  { (void)idx; return NULL; }

/* ── Syslinux / bootloader version stubs ─────────────────────────────── */
/* GetGrubVersion, GetGrubFs, GetEfiBootInfo are defined in iso_scan.c */
uint16_t GetSyslinuxVersion(char *buf, size_t sz, char **ext)
                                                     { (void)buf; (void)sz; (void)ext; return 0; }

/* ── Wimlib stubs ────────────────────────────────────────────────────── */
uint32_t GetWimVersion(const char *p)                { (void)p; return 0; }
BOOL     WimSplitFile(const char *s, const char *d)  { (void)s; (void)d; return FALSE; }

/* ── FAT dump stub (DumpFatDir is called from iso.c for EFI images) ───── */
BOOL     DumpFatDir(const char *path, int32_t cluster) { (void)path; (void)cluster; return FALSE; }

/* ── bled (decompressor) stubs ───────────────────────────────────────── */
void     bled_init(uint64_t *src_sz, uint64_t *dst_sz,
                   void (*upd)(int, int, uint64_t, uint64_t),
                   void (*msg)(const char *, ...),
                   void (*err)(const char *, ...),
                   BOOL *abort_flag)
                                                     { (void)src_sz; (void)dst_sz; (void)upd;
                                                       (void)msg; (void)err; (void)abort_flag; }
void     bled_exit(void)                             { }
int      bled_uncompress_to_dir(const char *src, const char *dst, int type)
                                                     { (void)src; (void)dst; (void)type; return -1; }

/* ── VHD stub ─────────────────────────────────────────────────────────── */
BOOL     vhd_write_fixed_footer(int fd, uint64_t disk_sz)
                                                     { (void)fd; (void)disk_sz; return FALSE; }
