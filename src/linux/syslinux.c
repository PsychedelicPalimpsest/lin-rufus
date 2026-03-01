/*
 * Rufus: The Reliable USB Formatting Utility
 * Syslinux bootloader installation — Linux port
 * Copyright © 2003 Lars Munch Christensen
 * Copyright © 1998-2008 H. Peter Anvin
 * Copyright © 2012-2024 Pete Batard
 * Copyright © 2025 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include "rufus.h"
#include "resource.h"
#include "drive.h"
#include "syslinux.h"      /* syslinux_make_bootsect, syslinux_patch, syslinux_check_bootsect */
#include "syslxfs.h"       /* VFAT */
#include "libfat.h"        /* libfat_open / close / searchdir / etc. */
#include "setadv.h"        /* syslinux_adv, syslinux_reset_adv, ADV_SIZE */

/* embedded_sl_version_ext is defined in globals.c; declare here */
extern char embedded_sl_version_ext[2][32];

/* ------------------------------------------------------------------
 * Global sector-size variables required by libinstaller and libfat.
 * These mirror the Windows version's per-call initialisation.
 * ------------------------------------------------------------------ */
unsigned char* syslinux_ldlinux[2]       = { NULL, NULL };
const int      syslinux_ldlinux_mtime[2] = { 0, 0 };

uint32_t SECTOR_SHIFT       = 9;
uint32_t SECTOR_SIZE        = 512;
uint32_t LIBFAT_SECTOR_SHIFT = 9;
uint32_t LIBFAT_SECTOR_SIZE  = 512;
uint32_t LIBFAT_SECTOR_MASK  = 511;

/* ------------------------------------------------------------------
 * libfat_readfile — pread-based sector reader used by libfat_open().
 * pp is the POSIX file descriptor (cast to intptr_t).
 * ------------------------------------------------------------------ */
int libfat_readfile(intptr_t pp, void *buf, size_t secsize,
                    libfat_sector_t sector)
{
    int fd = (int)(intptr_t)pp;
    if (fd < 0) return 0;
    ssize_t n = pread(fd, buf, secsize, (off_t)sector * (off_t)secsize);
    if (n <= 0) return 0;
    return (int)n;
}

/* ------------------------------------------------------------------
 * GetSyslinuxVersion — scan a buffer for a syslinux/isolinux version
 * string of the form "SYSLINUX x.yy" or "ISOLINUX x.yy".
 *
 * Ported verbatim from src/windows/syslinux.c.
 * ------------------------------------------------------------------ */
uint16_t GetSyslinuxVersion(char *buf, size_t buf_size, char **ext)
{
    size_t i, j, k;
    char *p = NULL;
    unsigned long version_ul[2];
    uint16_t version = 0;
    const char LINUX[] = { 'L', 'I', 'N', 'U', 'X', ' ' };
    static char *nullstr = "";
    char unauthorized[] = { '<', '>', ':', '|', '*', '?', '\\', '/' };

    *ext = nullstr;
    if (buf_size < 256)
        return 0;

    /* Start at 64 to skip the short incomplete version at the top of ldlinux.sys */
    for (i = 64; i < buf_size - 64; i++) {
        if (memcmp(&buf[i], LINUX, sizeof(LINUX)) == 0) {
            /* Require "SYS" or "ISO" prefix immediately before "LINUX " */
            if (!( ((buf[i - 3] == 'I') && (buf[i - 2] == 'S') && (buf[i - 1] == 'O'))
                || ((buf[i - 3] == 'S') && (buf[i - 2] == 'Y') && (buf[i - 1] == 'S')) ))
                continue;
            i += sizeof(LINUX);
            version_ul[0] = strtoul(&buf[i], &p, 10);
            if (version_ul[0] >= 256) continue;
            version_ul[1] = strtoul(&p[1], &p, 10);
            if (version_ul[1] >= 256) continue;
            version = (uint16_t)((version_ul[0] << 8) + version_ul[1]);
            if (version == 0) continue;

            /* Force a '/' separator before any extra version suffix */
            *p = '/';
            /* Remove the x.yz- duplicate if present */
            for (j = 0; (buf[i + j] == p[1 + j]) && (buf[i + j] != ' '); j++);
            if (p[j + 1] == '-') j++;
            if (j > 0) {
                for (k = 1; p[k + j] != ' ' && p[k + j] != '\0'; k++)
                    p[k] = p[k + j];
                p[k] = '\0';
            }

            /* Drop characters that are invalid in directory names */
            for (j = 1; p[j] != '\0'; j++) {
                for (k = 0; k < sizeof(unauthorized); k++) {
                    if (p[j] == unauthorized[k]) {
                        p[j] = '_';
                        break;
                    }
                }
            }
            *ext = p;
            return version;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------
 * load_ldlinux_data — load ldlinux.sys and ldlinux.bss for the given
 * syslinux version.  Tries the following locations in order:
 *   1. app_data_dir/Rufus/syslinux-<ver><ext>/ldlinux.{sys,bss}
 *   2. app_dir/../res/syslinux/ldlinux_v{4,6}.{sys,bss}
 *   3. <exe_dir>/res/syslinux/ldlinux_v{4,6}.{sys,bss}
 * Returns TRUE on success; caller must free() syslinux_ldlinux[0/1].
 * ------------------------------------------------------------------ */
static uint8_t *load_binary_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    if (out_len) *out_len = (size_t)sz;
    return buf;
}

static BOOL load_ldlinux_data(BOOL use_v6)
{
    int v = use_v6 ? 6 : 4;
    char path[MAX_PATH];
    static const char *exts[2] = { "sys", "bss" };

    /* First: try versioned directory in app_data_dir */
    for (int i = 0; i < 2; i++) {
        static_sprintf(path, "%s/Rufus/syslinux-%s%s/ldlinux.%s",
                       app_data_dir,
                       use_v6 ? embedded_sl_version_str[1] : embedded_sl_version_str[0],
                       use_v6 ? embedded_sl_version_ext[1] : embedded_sl_version_ext[0],
                       exts[i]);
        syslinux_ldlinux[i] = load_binary_file(path, &syslinux_ldlinux_len[i]);
        if (!syslinux_ldlinux[i]) break;
    }
    if (syslinux_ldlinux[0] && syslinux_ldlinux[1]) {
        uprintf("Loaded syslinux V%d from %s", v, path);
        return TRUE;
    }
    /* Clean up partial load */
    for (int i = 0; i < 2; i++) {
        free(syslinux_ldlinux[i]);
        syslinux_ldlinux[i] = NULL;
        syslinux_ldlinux_len[i] = 0;
    }

    /* Second: bundled res/syslinux/ldlinux_v{4,6}.{sys,bss} */
    /* Try relative to app_dir and also the build res/ directory */
    const char *search_dirs[] = { app_dir, "../../", "../res/..", NULL };
    for (int d = 0; search_dirs[d]; d++) {
        for (int i = 0; i < 2; i++) {
            snprintf(path, sizeof(path), "%s/res/syslinux/ldlinux_v%d.%s",
                     search_dirs[d], v, exts[i]);
            syslinux_ldlinux[i] = load_binary_file(path, &syslinux_ldlinux_len[i]);
            if (!syslinux_ldlinux[i]) break;
        }
        if (syslinux_ldlinux[0] && syslinux_ldlinux[1]) {
            uprintf("Loaded bundled syslinux V%d from %s", v, path);
            return TRUE;
        }
        /* Clean up partial */
        for (int i = 0; i < 2; i++) {
            free(syslinux_ldlinux[i]);
            syslinux_ldlinux[i] = NULL;
            syslinux_ldlinux_len[i] = 0;
        }
    }

    uprintf("Error: Could not find ldlinux_v%d.sys/bss", v);
    return FALSE;
}

/* ------------------------------------------------------------------
 * write_ldlinux_via_mcopy — write ldlinux.sys + ADV to a FAT partition
 * using mcopy from mtools (avoids needing root for image-file tests;
 * also works on block devices when already not mounted elsewhere).
 * ------------------------------------------------------------------ */
static BOOL write_ldlinux_via_mcopy(const char *part_path, int ldlinux_idx)
{
    char tmpfile[] = "/tmp/rufus_ldlinux_XXXXXX";
    int  fd = mkstemp(tmpfile);
    if (fd < 0) {
        uprintf("Could not create temp file for ldlinux.sys: %s", strerror(errno));
        return FALSE;
    }

    /* Write ldlinux.sys followed by the Auxiliary Data Vector */
    ssize_t w1 = write(fd, syslinux_ldlinux[ldlinux_idx],
                       syslinux_ldlinux_len[ldlinux_idx]);
    ssize_t w2 = write(fd, syslinux_adv, 2 * ADV_SIZE);
    fsync(fd);
    close(fd);

    if (w1 != (ssize_t)syslinux_ldlinux_len[ldlinux_idx] ||
        w2 != (ssize_t)(2 * ADV_SIZE)) {
        uprintf("Could not write temp ldlinux.sys");
        unlink(tmpfile);
        return FALSE;
    }

    /* mcopy: -i device  source  ::destination (the :: prefix = device root) */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "MTOOLS_SKIP_CHECK=1 mcopy -o -i '%s' '%s' '::ldlinux.sys' 2>/dev/null",
             part_path, tmpfile);
    int rc = system(cmd);
    unlink(tmpfile);

    if (rc != 0) {
        uprintf("mcopy failed for ldlinux.sys (rc=%d)", rc);
        return FALSE;
    }
    return TRUE;
}

/* ------------------------------------------------------------------
 * InstallSyslinux — write syslinux boot files and boot sector to a
 * FAT-formatted Linux partition / image file.
 *
 * Steps:
 *  1. Determine V4 vs V6 and set sector-size globals.
 *  2. Load ldlinux.sys and ldlinux.bss data.
 *  3. Reset the Auxiliary Data Vector.
 *  4. Write ldlinux.sys (+ADV) to the FAT partition using mcopy.
 *  5. Open the partition fd for libfat and direct I/O.
 *  6. Use libfat to walk the FAT chain and collect ldlinux.sys sectors.
 *  7. Call syslinux_patch() to embed the sector map in ldlinux.sys.
 *  8. Write the patched ldlinux.sys back to each sector directly.
 *  9. Read the VBR, apply syslinux_make_bootsect(), write VBR back.
 * 10. For V6, also copy ldlinux.c32.
 * ------------------------------------------------------------------ */
BOOL InstallSyslinux(DWORD drive_index, char drive_letter, int file_system)
{
    (void)drive_letter; (void)file_system;

    BOOL use_v6 = (boot_type == BT_SYSLINUX_V6) ||
                  ((boot_type == BT_IMAGE) && (SL_MAJOR(img_report.sl_version) >= 5));

    PrintInfoDebug(0, MSG_234,
                   (boot_type == BT_IMAGE) ? img_report.sl_version_str
                                           : embedded_sl_version_str[use_v6 ? 1 : 0]);

    /* ---- 1. Sector-size setup ---- */
    SECTOR_SHIFT = 0;
    SECTOR_SIZE  = SelectedDrive.SectorSize ? SelectedDrive.SectorSize : 512;
    {
        uint32_t tmp = SECTOR_SIZE;
        while (tmp >>= 1)
            SECTOR_SHIFT++;
    }
    LIBFAT_SECTOR_SHIFT = SECTOR_SHIFT;
    LIBFAT_SECTOR_SIZE  = SECTOR_SIZE;
    LIBFAT_SECTOR_MASK  = SECTOR_SIZE - 1;

    BOOL r = FALSE;

    /* ---- 2. Load ldlinux data ---- */
    if (!load_ldlinux_data(use_v6)) {
        uprintf("InstallSyslinux: could not load ldlinux files");
        return FALSE;
    }

    /* ---- 3. Reset ADV ---- */
    syslinux_reset_adv(syslinux_adv);

    /* ---- 4. Get partition path ---- */
    char *part_path = GetLogicalName(drive_index, 0, FALSE, TRUE);
    if (!part_path)
        part_path = GetPhysicalName(drive_index);
    if (!part_path) {
        uprintf("InstallSyslinux: could not get partition path");
        goto out_data;
    }

    /* ---- 5. Write ldlinux.sys to FAT via mcopy ---- */
    if (!write_ldlinux_via_mcopy(part_path, 0)) {
        uprintf("InstallSyslinux: failed to write ldlinux.sys");
        goto out_path;
    }
    uprintf("Successfully wrote 'ldlinux.sys' to partition");
    if (boot_type != BT_IMAGE)
        UpdateProgress(OP_FILE_COPY, -1.0f);

    /* ---- 6. Open partition fd ---- */
    int d_fd = open(part_path, O_RDWR | O_CLOEXEC);
    if (d_fd < 0) {
        uprintf("InstallSyslinux: could not open %s: %s", part_path, strerror(errno));
        goto out_path;
    }

    /* ---- 7. Map ldlinux.sys sectors with libfat ---- */
    /* NOTE: libfat determines FAT type by cluster count. Images with >65524
     * clusters are treated as FAT28 (FAT32). Use at least a 34 MB image with
     * 1-sector clusters when testing, or the FAT chain will be misread. */
    int ldlinux_sectors = (int)((syslinux_ldlinux_len[0] + 2 * ADV_SIZE +
                                 SECTOR_SIZE - 1) >> SECTOR_SHIFT);
    libfat_sector_t *sectors = (libfat_sector_t *)calloc(
        (size_t)ldlinux_sectors, sizeof(libfat_sector_t));
    if (!sectors) {
        uprintf("InstallSyslinux: out of memory");
        goto out_fd;
    }

    struct libfat_filesystem *lf_fs = libfat_open(libfat_readfile,
                                                   (intptr_t)d_fd);
    if (!lf_fs) {
        uprintf("InstallSyslinux: libfat could not open FAT filesystem");
        goto out_sectors;
    }

    int32_t ldlinux_cluster = libfat_searchdir(lf_fs, 0, "LDLINUX SYS", NULL);
    if (ldlinux_cluster < 0) {
        uprintf("InstallSyslinux: ldlinux.sys not found in FAT directory");
        libfat_close(lf_fs);
        goto out_sectors;
    }

    int nsectors = 0;
    libfat_sector_t s = libfat_clustertosector(lf_fs, ldlinux_cluster);
    while (s && nsectors < ldlinux_sectors) {
        sectors[nsectors++] = s;
        s = libfat_nextsector(lf_fs, s);
    }
    libfat_close(lf_fs);

    if (nsectors < ldlinux_sectors) {
        uprintf("InstallSyslinux: only mapped %d/%d sectors", nsectors, ldlinux_sectors);
        goto out_sectors;
    }

    /* ---- 8. Patch ldlinux.sys with sector map ---- */
    {
        /* Temporarily strip the trailing '/' from cfg_path to get directory */
        size_t cfg_len = strlen(img_report.cfg_path);
        int slash_pos = (int)cfg_len;
        while (slash_pos > 0 && img_report.cfg_path[slash_pos] != '/')
            slash_pos--;
        if (slash_pos > 0) img_report.cfg_path[slash_pos] = '\0';

        int w = syslinux_patch((const sector_t *)sectors, nsectors,
                               0, 0, img_report.cfg_path, NULL);
        if (slash_pos > 0) img_report.cfg_path[slash_pos] = '/';

        if (w < 0) {
            uprintf("WARNING: Could not patch syslinux files (sector map).");
            goto out_sectors;
        }
    }

    /* ---- 9. Write patched ldlinux.sys back sector by sector ---- */
    {
        const uint8_t *src = syslinux_ldlinux[0];
        unsigned long  remaining = syslinux_ldlinux_len[0];
        for (int si = 0; si < nsectors && remaining > 0; si++) {
            size_t chunk = (remaining > SECTOR_SIZE) ? SECTOR_SIZE : remaining;
            if (pwrite(d_fd, src, chunk, (off_t)sectors[si] * SECTOR_SIZE)
                    != (ssize_t)chunk) {
                uprintf("InstallSyslinux: pwrite sector %d failed: %s",
                        si, strerror(errno));
                goto out_sectors;
            }
            src       += chunk;
            remaining -= chunk;
        }
    }
    uprintf("Successfully patched ldlinux.sys");

    /* ---- 10. Read VBR, apply syslinux bootsect, write back ---- */
    {
        uint8_t vbr[512];
        if (pread(d_fd, vbr, sizeof(vbr), 0) != (ssize_t)sizeof(vbr)) {
            uprintf("InstallSyslinux: could not read VBR: %s", strerror(errno));
            goto out_sectors;
        }

        const char *errmsg;
        int sl_fs_type;
        errmsg = syslinux_check_bootsect(vbr, &sl_fs_type);
        if (errmsg) {
            uprintf("InstallSyslinux: boot sector check: %s", errmsg);
            /* Not fatal — proceed with patching anyway */
        }

        syslinux_make_bootsect(vbr, VFAT);

        if (pwrite(d_fd, vbr, sizeof(vbr), 0) != (ssize_t)sizeof(vbr)) {
            uprintf("InstallSyslinux: could not write syslinux boot record: %s",
                    strerror(errno));
            goto out_sectors;
        }
        uprintf("Successfully wrote Syslinux boot record");
    }

    /* ---- 11. Copy ldlinux.c32 for V6 ---- */
    if (use_v6) {
        char c32_src[MAX_PATH], c32_dst[MAX_PATH];
        snprintf(c32_src, sizeof(c32_src),
                 "%s/Rufus/syslinux-%s/ldlinux.c32",
                 app_data_dir, embedded_sl_version_str[1]);
        snprintf(c32_dst, sizeof(c32_dst),
                 "MTOOLS_SKIP_CHECK=1 mcopy -i '%s' '%s' '::ldlinux.c32' 2>/dev/null",
                 part_path, c32_src);
        if (access(c32_src, R_OK) == 0 && system(c32_dst) == 0)
            uprintf("Installed ldlinux.c32");
        else
            uprintf("Caution: No ldlinux.c32 available; target may need it.");
    }

    if (boot_type != BT_IMAGE)
        UpdateProgress(OP_FILE_COPY, -1.0f);

    r = TRUE;

out_sectors:
    free(sectors);
out_fd:
    fsync(d_fd);
    close(d_fd);
out_path:
    free(part_path);
out_data:
    free(syslinux_ldlinux[0]); syslinux_ldlinux[0] = NULL;
    free(syslinux_ldlinux[1]); syslinux_ldlinux[1] = NULL;
    syslinux_ldlinux_len[0] = syslinux_ldlinux_len[1] = 0;
    return r;
}

