/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux drive access implementation
 * Copyright © 2024-2025 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/* Tell windows.h to skip its weak stubs; we provide the real implementations */
#define LINUX_DRIVE_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>   /* BLKGETSIZE64, BLKRRPART, BLKSSZGET, BLKFLSBUF */
#include <time.h>

#include "rufus.h"
#include "drive.h"
#include "drive_linux.h"

/* rufus_drive[] is defined in globals.c (production) or inline by tests */
extern RUFUS_DRIVE rufus_drive[MAX_DRIVES];

/* -------------------------------------------------------------------------
 * Partition fd offset table — strong implementations for linux_get_fd_base_offset
 * etc., declared as weak no-ops in compat/windows.h.
 * Maps open fds to (base_offset, partition_size) for raw image file partitions.
 * --------------------------------------------------------------------- */
#define MAX_PART_FDS 32
static int      _pfd[MAX_PART_FDS];
static uint64_t _pbase[MAX_PART_FDS];
static uint64_t _psize[MAX_PART_FDS];
static int      _pfd_count = 0;

void linux_register_fd_offset(int fd, uint64_t base, uint64_t size)
{
    for (int i = 0; i < _pfd_count; i++) {
        if (_pfd[i] == fd) { _pbase[i] = base; _psize[i] = size; return; }
    }
    if (_pfd_count < MAX_PART_FDS) {
        _pfd  [_pfd_count] = fd;
        _pbase[_pfd_count] = base;
        _psize[_pfd_count] = size;
        _pfd_count++;
    }
}

void linux_unregister_fd_offset(int fd)
{
    for (int i = 0; i < _pfd_count; i++) {
        if (_pfd[i] == fd) {
            _pfd_count--;
            _pfd  [i] = _pfd  [_pfd_count];
            _pbase[i] = _pbase[_pfd_count];
            _psize[i] = _psize[_pfd_count];
            return;
        }
    }
}

uint64_t linux_get_fd_base_offset(int fd)
{
    for (int i = 0; i < _pfd_count; i++)
        if (_pfd[i] == fd) return _pbase[i];
    return 0;
}

uint64_t linux_get_fd_part_size(int fd)
{
    for (int i = 0; i < _pfd_count; i++)
        if (_pfd[i] == fd) return _psize[i];
    return 0;
}


int partition_index[PI_MAX]    = { 0 };
RUFUS_DRIVE_INFO SelectedDrive = { 0 };

/* -------------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------- */

/* Count of live entries in rufus_drive[] (size==0 is sentinel) */
static int drive_count(void)
{
    int n = 0;
    while (n < MAX_DRIVES && rufus_drive[n].id != NULL) n++;
    return n;
}

/* Return the rufus_drive entry whose index matches DriveIndex, or NULL */
static RUFUS_DRIVE *get_entry(DWORD DriveIndex)
{
    for (int i = 0; i < MAX_DRIVES; i++) {
        if (rufus_drive[i].id == NULL) break;
        if (rufus_drive[i].index == DriveIndex) return &rufus_drive[i];
    }
    return NULL;
}

/* Read uint32_t LE from a byte array */
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Read uint64_t LE from a byte array */
static uint64_t le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

/* Minimal CRC-32 (IEEE polynomial, same as GPT spec) */
static uint32_t crc32_ieee(const uint8_t *buf, size_t len)
{
    static uint32_t table[256];
    static int init = 0;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int j = 0; j < 8; j++)
                c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = 1;
    }
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++)
        crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFU;
}

/* -------------------------------------------------------------------------
 * Test-support helpers (exposed via drive_linux.h)
 * --------------------------------------------------------------------- */

void drive_linux_reset_drives(void)
{
    for (int i = 0; i < MAX_DRIVES; i++) {
        if (rufus_drive[i].id == NULL) break;
        /* Free only if it looks like it was malloc'd (non-const pointer).
         * In test_format_linux.c the pointer is a local string — don't free. */
        rufus_drive[i].id = NULL;
        rufus_drive[i].name = NULL;
        rufus_drive[i].display_name = NULL;
        rufus_drive[i].label = NULL;
    }
    memset(rufus_drive, 0, sizeof(rufus_drive));
}

void drive_linux_add_drive(const char *id, const char *name,
                           const char *display_name, uint64_t size)
{
    int n = drive_count();
    if (n >= MAX_DRIVES) return;

    /* Use strdup so test code can freely modify / unlink the path */
    rufus_drive[n].id           = strdup(id);
    rufus_drive[n].name         = strdup(name);
    rufus_drive[n].display_name = strdup(display_name);
    rufus_drive[n].label        = strdup("");
    rufus_drive[n].hub          = NULL;
    rufus_drive[n].index        = (DWORD)(DRIVE_INDEX_MIN + n);
    rufus_drive[n].port         = 0;
    rufus_drive[n].size         = size;
}

/* -------------------------------------------------------------------------
 * MBR/GPT parsers (exposed via drive_linux.h for white-box testing)
 * --------------------------------------------------------------------- */

int drive_linux_parse_mbr(const uint8_t sector[512],
                          parsed_partition_t parts[4], int *nparts)
{
    *nparts = 0;

    if (sector[510] != 0x55 || sector[511] != 0xAA)
        return PARTITION_STYLE_RAW;

    for (int i = 0; i < 4; i++) {
        const uint8_t *e = sector + 446 + i * 16;
        uint8_t  type      = e[4];
        uint32_t lba_start = le32(e + 8);
        uint32_t lba_size  = le32(e + 12);

        if (type == 0 || lba_size == 0) continue;

        parsed_partition_t *p = &parts[(*nparts)++];
        memset(p, 0, sizeof(*p));
        p->offset   = (uint64_t)lba_start * 512;
        p->size     = (uint64_t)lba_size  * 512;
        p->mbr_type = type;
    }
    return PARTITION_STYLE_MBR;
}

int drive_linux_parse_gpt(const uint8_t *header_buf,
                          const uint8_t *entries_buf, size_t entries_sz,
                          parsed_partition_t *parts, int *nparts)
{
    *nparts = 0;

    if (memcmp(header_buf, "EFI PART", 8) != 0)
        return PARTITION_STYLE_RAW;

    uint32_t hdr_size       = le32(header_buf + 12);
    uint32_t hdr_crc_stored = le32(header_buf + 16);
    uint32_t num_entries    = le32(header_buf + 80);
    uint32_t entry_size     = le32(header_buf + 84);

    if (hdr_size < 92 || entry_size < 128) return PARTITION_STYLE_RAW;

    /* Verify header CRC */
    uint8_t tmp[512];
    size_t check_size = (hdr_size < 512) ? hdr_size : 512;
    memcpy(tmp, header_buf, check_size);
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    if (crc32_ieee(tmp, check_size) != hdr_crc_stored)
        return PARTITION_STYLE_RAW;

    for (uint32_t i = 0; i < num_entries; i++) {
        size_t off = (size_t)i * entry_size;
        if (off + entry_size > entries_sz) break;

        const uint8_t *e = entries_buf + off;
        int empty = 1;
        for (int b = 0; b < 16; b++) { if (e[b] != 0) { empty = 0; break; } }
        if (empty) continue;

        uint64_t first_lba = le64(e + 32);
        uint64_t last_lba  = le64(e + 40);
        if (last_lba < first_lba) continue;

        parsed_partition_t *p = &parts[(*nparts)++];
        memset(p, 0, sizeof(*p));
        p->offset = first_lba * 512;
        p->size   = (last_lba - first_lba + 1) * 512;
        memcpy(p->type_guid, e,      16);
        memcpy(p->part_guid, e + 16, 16);
    }
    return PARTITION_STYLE_GPT;
}

/* -------------------------------------------------------------------------
 * Public drive API
 * --------------------------------------------------------------------- */

char *GetPhysicalName(DWORD DriveIndex)
{
    RUFUS_DRIVE *e = get_entry(DriveIndex);
    if (!e || !e->id) return NULL;
    return strdup(e->id);
}

HANDLE GetPhysicalHandle(DWORD DriveIndex, BOOL bLockDrive,
                         BOOL bWriteAccess, BOOL bWriteShare)
{
    (void)bLockDrive; (void)bWriteShare;
    RUFUS_DRIVE *e = get_entry(DriveIndex);
    if (!e || !e->id) return INVALID_HANDLE_VALUE;

    int flags = bWriteAccess ? O_RDWR : O_RDONLY;
    flags |= O_CLOEXEC;
    int fd = open(e->id, flags);
    return (fd >= 0) ? (HANDLE)(intptr_t)fd : INVALID_HANDLE_VALUE;
}

uint64_t GetDriveSize(DWORD DriveIndex)
{
    RUFUS_DRIVE *e = get_entry(DriveIndex);
    if (!e || !e->id) return 0;

    int fd = open(e->id, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;

    uint64_t size = 0;
    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (S_ISBLK(st.st_mode))
            ioctl(fd, BLKGETSIZE64, &size);
        else
            size = (uint64_t)st.st_size;
    }
    close(fd);
    return size;
}

BOOL IsMediaPresent(DWORD DriveIndex)
{
    RUFUS_DRIVE *e = get_entry(DriveIndex);
    if (!e || !e->id) return FALSE;
    return (access(e->id, F_OK) == 0) ? TRUE : FALSE;
}

BOOL GetDrivePartitionData(DWORD DriveIndex, char *FileSystemName,
                           DWORD FileSystemNameSize, BOOL bSilent)
{
    (void)bSilent;
    RUFUS_DRIVE *e = get_entry(DriveIndex);
    if (!e || !e->id) return FALSE;

    int fd = open(e->id, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FALSE;

    uint64_t disk_size  = 0;
    uint32_t sector_size = 512;
    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (S_ISBLK(st.st_mode)) {
            ioctl(fd, BLKGETSIZE64, &disk_size);
            ioctl(fd, BLKSSZGET, &sector_size);
        } else {
            disk_size = (uint64_t)st.st_size;
        }
    }

    SelectedDrive.DiskSize      = (LONGLONG)disk_size;
    SelectedDrive.SectorSize    = sector_size;
    SelectedDrive.DeviceNumber  = DriveIndex;
    SelectedDrive.nPartitions   = 0;
    SelectedDrive.PartitionStyle = PARTITION_STYLE_RAW;

    if (FileSystemName && FileSystemNameSize > 0)
        FileSystemName[0] = '\0';

    if (disk_size < 512) { close(fd); return TRUE; }

    uint8_t sector0[512] = { 0 };
    if (pread(fd, sector0, 512, 0) != 512) { close(fd); return TRUE; }

    /* Check for GPT (protective MBR with type 0xEE) */
    int is_gpt = 0;
    if (sector0[510] == 0x55 && sector0[511] == 0xAA) {
        for (int i = 0; i < 4; i++) {
            if (sector0[446 + i * 16 + 4] == 0xEE) { is_gpt = 1; break; }
        }
    }

    if (is_gpt) {
        uint8_t  hdr[512] = { 0 };
        size_t   entries_sz = 128 * 128;
        uint8_t *entries = (uint8_t *)calloc(1, entries_sz);
        if (!entries) { close(fd); return FALSE; }

        if (pread(fd, hdr, 512, 512) == 512 &&
            pread(fd, entries, entries_sz, 1024) == (ssize_t)entries_sz) {
            parsed_partition_t pp[128];
            int np = 0;
            if (drive_linux_parse_gpt(hdr, entries, entries_sz, pp, &np) == PARTITION_STYLE_GPT) {
                SelectedDrive.PartitionStyle = PARTITION_STYLE_GPT;
                int count = (np > MAX_PARTITIONS) ? MAX_PARTITIONS : np;
                SelectedDrive.nPartitions = count;
                for (int i = 0; i < count; i++) {
                    SelectedDrive.Partition[i].Offset = pp[i].offset;
                    SelectedDrive.Partition[i].Size   = pp[i].size;
                }
            }
        }
        free(entries);
    } else {
        parsed_partition_t pp[4];
        int np = 0;
        if (drive_linux_parse_mbr(sector0, pp, &np) == PARTITION_STYLE_MBR) {
            SelectedDrive.PartitionStyle = PARTITION_STYLE_MBR;
            int count = (np > MAX_PARTITIONS) ? MAX_PARTITIONS : np;
            SelectedDrive.nPartitions = count;
            for (int i = 0; i < count; i++) {
                SelectedDrive.Partition[i].Offset = pp[i].offset;
                SelectedDrive.Partition[i].Size   = pp[i].size;
            }
        }
    }

    close(fd);
    return TRUE;
}

BOOL InitializeDisk(HANDLE hDrive)
{
    if (!hDrive || hDrive == INVALID_HANDLE_VALUE) return FALSE;
    int fd = (int)(intptr_t)hDrive;
    uint8_t zeros[512] = { 0 };
    return (pwrite(fd, zeros, 512, 0) == 512) ? TRUE : FALSE;
}

BOOL RefreshDriveLayout(HANDLE hDrive)
{
    if (!hDrive || hDrive == INVALID_HANDLE_VALUE) return FALSE;
    int fd = (int)(intptr_t)hDrive;
    ioctl(fd, BLKRRPART);  /* non-fatal on regular files */
    return TRUE;
}

BOOL CreatePartition(HANDLE hDrive, int PartitionStyle, int FileSystem,
                     BOOL bMBRIsBootable, uint8_t extra_partitions)
{
    (void)FileSystem; (void)extra_partitions;
    if (!hDrive || hDrive == INVALID_HANDLE_VALUE) return FALSE;
    int fd = (int)(intptr_t)hDrive;

    uint64_t disk_size   = (uint64_t)SelectedDrive.DiskSize;
    uint32_t sector_size = SelectedDrive.SectorSize ? SelectedDrive.SectorSize : 512;
    uint64_t total_sects = disk_size / sector_size;

    if (PartitionStyle == PARTITION_STYLE_MBR) {
        uint8_t mbr[512] = { 0 };
        mbr[510] = 0x55; mbr[511] = 0xAA;

        uint32_t lba_start = 2048;
        uint32_t lba_size  = (uint32_t)(total_sects > lba_start + 1
                                        ? total_sects - lba_start : 1);
        uint8_t *e = mbr + 446;
        e[0] = bMBRIsBootable ? 0x80 : 0x00;
        e[1] = 0xFE; e[2] = 0xFF; e[3] = 0xFF;
        e[4] = 0x0C;
        e[5] = 0xFE; e[6] = 0xFF; e[7] = 0xFF;
        e[8]  = (lba_start)       & 0xFF;
        e[9]  = (lba_start >>  8) & 0xFF;
        e[10] = (lba_start >> 16) & 0xFF;
        e[11] = (lba_start >> 24) & 0xFF;
        e[12] = (lba_size)        & 0xFF;
        e[13] = (lba_size >>  8)  & 0xFF;
        e[14] = (lba_size >> 16)  & 0xFF;
        e[15] = (lba_size >> 24)  & 0xFF;

        return (pwrite(fd, mbr, 512, 0) == 512) ? TRUE : FALSE;

    } else if (PartitionStyle == PARTITION_STYLE_GPT) {
        uint8_t  mbr[512]   = { 0 };
        uint8_t  hdr[512]   = { 0 };
        uint8_t *entries    = NULL;
        size_t   entries_sz = 128 * 128;
        BOOL     ok         = FALSE;

        entries = (uint8_t *)calloc(1, entries_sz);
        if (!entries) return FALSE;

        /* Protective MBR */
        mbr[450] = 0xEE;
        uint32_t prot_size = (total_sects - 1 > 0xFFFFFFFFU) ?
                              0xFFFFFFFFU : (uint32_t)(total_sects - 1);
        mbr[454] = 1;
        mbr[458] = prot_size & 0xFF;
        mbr[459] = (prot_size >> 8) & 0xFF;
        mbr[460] = (prot_size >> 16) & 0xFF;
        mbr[461] = (prot_size >> 24) & 0xFF;
        mbr[510] = 0x55; mbr[511] = 0xAA;

        uint64_t first_usable = 34;
        uint64_t last_usable  = (total_sects > 68) ? total_sects - 34 : first_usable;

        /* Build partition entry 0 */
        static const uint8_t bd_type[16] = {
            0xA2,0xA0,0xD0,0xEB, 0xE5,0xB9, 0x33,0x44,
            0x87,0xC0, 0x68,0xB6,0xB7,0x26,0x99,0xC7
        };
        uint8_t part_guid[16] = { 0 };
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            uint64_t t = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
            memcpy(part_guid, &t, 8);
            part_guid[8] = 0x80;
        }

        uint8_t *pe = entries;
        memcpy(pe + 0,  bd_type,   16);
        memcpy(pe + 16, part_guid, 16);
        for (int i = 0; i < 8; i++) pe[32 + i] = (first_usable >> (8*i)) & 0xFF;
        for (int i = 0; i < 8; i++) pe[40 + i] = (last_usable  >> (8*i)) & 0xFF;

        uint32_t entries_crc = crc32_ieee(entries, entries_sz);

        /* Build GPT header */
        memcpy(hdr, "EFI PART", 8);
        hdr[8] = 0x00; hdr[9] = 0x00; hdr[10] = 0x01; hdr[11] = 0x00;
        hdr[12] = 92;
        hdr[24] = 1;
        uint64_t alt = total_sects - 1;
        for (int i = 0; i < 8; i++) hdr[32 + i] = (alt          >> (8*i)) & 0xFF;
        for (int i = 0; i < 8; i++) hdr[40 + i] = (first_usable >> (8*i)) & 0xFF;
        for (int i = 0; i < 8; i++) hdr[48 + i] = (last_usable  >> (8*i)) & 0xFF;
        for (int i = 0; i < 16; i++) hdr[56 + i] = part_guid[(i + 1) % 16];
        hdr[72] = 2;
        hdr[80] = 128; hdr[84] = 128;
        hdr[88] = entries_crc & 0xFF;
        hdr[89] = (entries_crc >>  8) & 0xFF;
        hdr[90] = (entries_crc >> 16) & 0xFF;
        hdr[91] = (entries_crc >> 24) & 0xFF;

        uint8_t hcrc_tmp[92];
        memcpy(hcrc_tmp, hdr, 92);
        hcrc_tmp[16] = hcrc_tmp[17] = hcrc_tmp[18] = hcrc_tmp[19] = 0;
        uint32_t hcrc = crc32_ieee(hcrc_tmp, 92);
        hdr[16] = hcrc & 0xFF;
        hdr[17] = (hcrc >>  8) & 0xFF;
        hdr[18] = (hcrc >> 16) & 0xFF;
        hdr[19] = (hcrc >> 24) & 0xFF;

        ok = (pwrite(fd, mbr,     512,         0)    == 512         &&
              pwrite(fd, hdr,     512,         512)   == 512         &&
              pwrite(fd, entries, entries_sz,  1024)  == (ssize_t)entries_sz)
             ? TRUE : FALSE;

        free(entries);
        return ok;
    }

    return FALSE;
}

/* -------------------------------------------------------------------------
 * GetLogicalName: scan sysfs to find partition path
 * --------------------------------------------------------------------- */

char *GetLogicalNameWithRoot(DWORD DriveIndex, uint64_t PartitionOffset,
                             BOOL bKeepTrailingSlash, BOOL bSilent,
                             const char *sysfs_root, const char *dev_root)
{
    (void)bKeepTrailingSlash; (void)bSilent;
    RUFUS_DRIVE *e = get_entry(DriveIndex);
    if (!e || !e->id) return NULL;

    const char *base = strrchr(e->id, '/');
    base = base ? base + 1 : e->id;

    char block_dir[512];
    snprintf(block_dir, sizeof(block_dir), "%s/block/%s", sysfs_root, base);

    DIR *d = opendir(block_dir);
    if (!d) return NULL;

    char *result = NULL;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strncmp(ent->d_name, base, strlen(base)) != 0) continue;
        if (strcmp(ent->d_name, base) == 0) continue;

        char start_path[640];
        snprintf(start_path, sizeof(start_path), "%s/block/%s/%s/start",
                 sysfs_root, base, ent->d_name);
        FILE *f = fopen(start_path, "r");
        if (!f) continue;
        uint64_t start_sector = 0;
        fscanf(f, "%llu", (unsigned long long *)&start_sector);
        fclose(f);

        if (start_sector * 512 != PartitionOffset) continue;

        char dev_path[512];
        snprintf(dev_path, sizeof(dev_path), "%s/%s", dev_root, ent->d_name);
        if (access(dev_path, F_OK) != 0) continue;

        result = strdup(dev_path);
        break;
    }
    closedir(d);
    return result;
}

char *GetLogicalName(DWORD DriveIndex, uint64_t PartitionOffset,
                     BOOL bKeepTrailingSlash, BOOL bSilent)
{
    return GetLogicalNameWithRoot(DriveIndex, PartitionOffset,
                                  bKeepTrailingSlash, bSilent,
                                  "/sys", "/dev");
}

char *AltGetLogicalName(DWORD DriveIndex, uint64_t PartitionOffset,
                        BOOL bKeepTrailingSlash, BOOL bSilent)
{
    return GetLogicalName(DriveIndex, PartitionOffset,
                          bKeepTrailingSlash, bSilent);
}

char *GetExtPartitionName(DWORD DriveIndex, uint64_t PartitionOffset)
{
    char *name = GetLogicalName(DriveIndex, PartitionOffset, FALSE, TRUE);
    if (name) return name;

    /* Fall back to physical path when no sysfs partition node exists. */
    name = GetPhysicalName(DriveIndex);
    if (!name) return NULL;

    /* For non-zero offsets on image files, append "@offset:size" so
     * posix_io.c can locate the partition region within the raw file. */
    if (PartitionOffset > 0) {
        struct stat st;
        if (stat(name, &st) == 0 && !S_ISBLK(st.st_mode)) {
            uint64_t part_size = (uint64_t)st.st_size > PartitionOffset
                                 ? (uint64_t)st.st_size - PartitionOffset : 0;
            /* Build "path@offset:size" */
            size_t len = strlen(name) + 64;
            char *tagged = (char*)malloc(len);
            if (tagged) {
                snprintf(tagged, len, "%s@%" PRIu64 ":%" PRIu64,
                         name, (uint64_t)PartitionOffset, part_size);
                free(name);
                return tagged;
            }
        }
    }
    return name;
}

BOOL WaitForLogical(DWORD DriveIndex, uint64_t PartitionOffset)
{
    char *name = GetLogicalName(DriveIndex, PartitionOffset, FALSE, TRUE);
    if (!name) return FALSE;
    free(name);
    return TRUE;
}

HANDLE GetLogicalHandle(DWORD DriveIndex, uint64_t PartitionOffset,
                        BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare)
{
    (void)bLockDrive; (void)bWriteShare;
    char *name = GetLogicalName(DriveIndex, PartitionOffset, FALSE, TRUE);
    /* Fall back to the physical path when no sysfs partition node exists
     * (e.g. temp image files in tests, or raw disk images). */
    if (!name)
        name = GetPhysicalName(DriveIndex);
    if (!name) return INVALID_HANDLE_VALUE;

    int flags = bWriteAccess ? O_RDWR : O_RDONLY;
    flags |= O_CLOEXEC;
    int fd = open(name, flags);
    free(name);
    if (fd < 0) return INVALID_HANDLE_VALUE;

    /* For image files with a non-zero partition offset, register the offset
     * so that SetFilePointerEx(FILE_BEGIN) transparently adds it. */
    if (PartitionOffset > 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && !S_ISBLK(st.st_mode)) {
            uint64_t disk_size = (uint64_t)st.st_size;
            uint64_t part_size = (disk_size > PartitionOffset)
                                 ? (disk_size - PartitionOffset) : 0;
            linux_register_fd_offset(fd, PartitionOffset, part_size);
        }
    }

    return (HANDLE)(intptr_t)fd;
}

HANDLE AltGetLogicalHandle(DWORD DriveIndex, uint64_t PartitionOffset,
                           BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare)
{
    return GetLogicalHandle(DriveIndex, PartitionOffset,
                            bLockDrive, bWriteAccess, bWriteShare);
}

int GetDriveNumber(HANDLE hDrive, char *path)
{
    (void)path;
    if (!hDrive || hDrive == INVALID_HANDLE_VALUE) return -1;
    int fd = (int)(intptr_t)hDrive;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISBLK(st.st_mode)) return -1;
    return (int)((st.st_rdev >> 20) & 0xFF);
}

BOOL UnmountVolume(HANDLE hDrive)
{
    if (!hDrive || hDrive == INVALID_HANDLE_VALUE) return FALSE;
    int fd = (int)(intptr_t)hDrive;
    ioctl(fd, BLKFLSBUF);  /* flush buffers; non-fatal */
    return TRUE;
}

BOOL AltUnmountVolume(const char *dn, BOOL bSilent)
{
    (void)bSilent;
    if (!dn) return FALSE;
    return (access(dn, F_OK) == 0) ? TRUE : FALSE;
}

/* -------------------------------------------------------------------------
 * Stubs for not-yet-implemented functions
 * --------------------------------------------------------------------- */

BOOL SetAutoMount(BOOL enable)                        { (void)enable; return FALSE; }
BOOL GetAutoMount(BOOL* enabled)                      { (void)enabled; return FALSE; }
BOOL DeletePartition(DWORD di, ULONGLONG off, BOOL s) { (void)di;(void)off;(void)s; return FALSE; }
BOOL IsVdsAvailable(BOOL bSilent)                     { (void)bSilent; return FALSE; }
BOOL ListVdsVolumes(BOOL bSilent)                     { (void)bSilent; return FALSE; }
BOOL VdsRescan(DWORD rt, DWORD st, BOOL s)            { (void)rt;(void)st;(void)s; return FALSE; }
BOOL GetDriveLetters(DWORD di, char* dl)              { (void)di;(void)dl; return FALSE; }
UINT GetDriveTypeFromIndex(DWORD di)                  { (void)di; return 0; }
char GetUnusedDriveLetter(void)                       { return 0; }
BOOL IsDriveLetterInUse(const char dl)                { (void)dl; return FALSE; }
char RemoveDriveLetters(DWORD di, BOOL last, BOOL s)  { (void)di;(void)last;(void)s; return 0; }
BOOL GetDriveLabel(DWORD di, char* letters, char** label, BOOL s) { (void)di;(void)letters;(void)label;(void)s; return FALSE; }
BOOL AnalyzeMBR(HANDLE h, const char* name, BOOL s)   { (void)h;(void)name;(void)s; return FALSE; }
BOOL AnalyzePBR(HANDLE h)                             { (void)h; return FALSE; }
BOOL MountVolume(char* dn, char* dg)                  { (void)dn;(void)dg; return FALSE; }
char* AltMountVolume(DWORD di, uint64_t off, BOOL s)  { (void)di;(void)off;(void)s; return NULL; }
BOOL RemountVolume(char* dn, BOOL s)                  { (void)dn;(void)s; return FALSE; }
const char* GetMBRPartitionType(const uint8_t type)   { (void)type; return ""; }
const char* GetGPTPartitionType(const GUID* guid)     { (void)guid; return ""; }
BOOL RefreshLayout(DWORD di)                          { (void)di; return FALSE; }
uint64_t GetEspOffset(DWORD di)                       { (void)di; return 0; }
BOOL ToggleEsp(DWORD di, uint64_t off)                { (void)di;(void)off; return FALSE; }
BOOL IsMsDevDrive(DWORD di)                           { (void)di; return FALSE; }
BOOL IsFilteredDrive(DWORD di)                        { (void)di; return FALSE; }
int  IsHDD(DWORD di, uint16_t vid, uint16_t pid, const char* strid) { (void)di;(void)vid;(void)pid;(void)strid; return 0; }
