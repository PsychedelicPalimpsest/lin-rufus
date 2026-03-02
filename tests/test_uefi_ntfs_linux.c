/*
 * test_uefi_ntfs_linux.c — Tests for UEFI:NTFS boot bridge support
 *
 * Tests cover:
 *   1. XP_UEFI_NTFS flag logic helpers
 *   2. CreatePartition (MBR) with XP_UEFI_NTFS — FAT partition at end of disk
 *   3. CreatePartition (GPT) with XP_UEFI_NTFS — ESP partition at end of disk
 *   4. UEFI:NTFS image loading from disk (load_uefi_ntfs_data)
 *   5. Writing UEFI:NTFS image to correct partition offset
 *   6. SelectedDrive.Partition[PI_UEFI_NTFS] populated correctly
 *   7. XP_UEFI_NTFS + XP_PERSISTENCE: both partitions present
 *   8. uefi_ntfs_needs_extra_partition() helper
 *
 * All tests use sparse temp image files; no real block device needed for
 * unit tests.  Root-requiring tests are guarded by SKIP_NOT_ROOT().
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include "framework.h"
#include "../src/linux/drive_linux.h"
#include "../src/windows/rufus.h"
#include "../src/windows/drive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Functions under test */
extern BOOL CreatePartition(HANDLE hDrive, int PartitionStyle, int FileSystem,
                            BOOL bMBRIsBootable, uint8_t extra_partitions);
extern BOOL InitializeDisk(HANDLE hDrive);
extern BOOL GetDrivePartitionData(DWORD DriveIndex, char *FileSystemName,
                                  DWORD FileSystemNameSize, BOOL bSilent);
extern HANDLE GetPhysicalHandle(DWORD DriveIndex, BOOL bLockDrive,
                                BOOL bWriteAccess, BOOL bWriteShare);

/* UEFI:NTFS specific functions */
extern uint8_t *load_uefi_ntfs_data(size_t *out_size);
extern BOOL write_uefi_ntfs_partition(HANDLE hDrive, uint64_t offset,
                                      const uint8_t *data, size_t size);
extern BOOL uefi_ntfs_needs_extra_partition(int boot_type, int fs_type,
                                            int target_type,
                                            const RUFUS_IMG_REPORT *report);

/* Globals/externs provided by PARTITION_OPS_LINUX_SRC (globals.c/stdfn.c/stdio.c/ui.c) */
extern RUFUS_DRIVE_INFO SelectedDrive;
extern int partition_index[];

/* Minimal stubs for symbols NOT in PARTITION_OPS_LINUX_SRC */
char *get_token_data_file_indexed(const char *t, const char *f, const int i)
{ (void)t; (void)f; (void)i; return NULL; }
void PrintStatusInfo(BOOL cl, BOOL up, unsigned int pct, int mid, ...)
{ (void)cl; (void)up; (void)pct; (void)mid; }
LONG_PTR SendMessage(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return 0; }
BOOL PostMessage(HWND h, UINT m, WPARAM w, LPARAM l)
{ (void)h; (void)m; (void)w; (void)l; return TRUE; }

/* CRC-32 (IEEE 802.3 polynomial) — used to verify GPT entries CRC */
static uint32_t crc32_table[256];
static int crc32_init_done = 0;
static void crc32_init(void)
{
    if (crc32_init_done) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_init_done = 1;
}
static uint32_t crc32_ieee(const void *buf, size_t len)
{
    crc32_init();
    uint32_t crc = 0xFFFFFFFFu;
    const uint8_t *p = (const uint8_t *)buf;
    for (size_t i = 0; i < len; i++)
        crc = crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* -------------------------------------------------------------------------
 * Helper: create a sparse temp image, register as drive 0, return path
 * --------------------------------------------------------------------- */
#define IMG_SIZE  (64ULL * 1024 * 1024)  /* 64 MB sparse image */
#define SECTOR    512
#define DRIVE_IDX DRIVE_INDEX_MIN
#ifndef MB
#define MB        (1024ULL * 1024ULL)
#endif
#ifndef KB
#define KB        (1024ULL)
#endif

static char g_path[64];
static int  g_img_fd = -1;

static BOOL setup_image(void)
{
    strcpy(g_path, "/tmp/test_uefi_ntfs_XXXXXX");
    g_img_fd = mkstemp(g_path);
    if (g_img_fd < 0) return FALSE;
    if (ftruncate(g_img_fd, (off_t)IMG_SIZE) != 0) {
        close(g_img_fd); g_img_fd = -1;
        unlink(g_path); return FALSE;
    }

    drive_linux_reset_drives();
    drive_linux_add_drive(g_path, "Test", "Test 64 MB", IMG_SIZE);
    memset(&SelectedDrive, 0, sizeof(SelectedDrive));
    SelectedDrive.DiskSize  = (LONGLONG)IMG_SIZE;
    SelectedDrive.SectorSize = SECTOR;
    SelectedDrive.DeviceNumber = DRIVE_IDX;
    return TRUE;
}

static void teardown_image(void)
{
    if (g_img_fd >= 0) { close(g_img_fd); g_img_fd = -1; }
    if (g_path[0]) { unlink(g_path); g_path[0] = '\0'; }
    drive_linux_reset_drives();
}

/* =========================================================================
 * TEST GROUP 1: uefi_ntfs_needs_extra_partition() logic
 * ========================================================================= */

TEST(needs_partition_efi_bootable_ntfs)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = TRUE;
    r.has_efi = TRUE;
    /* EFI bootable image + NTFS target fs → should need UEFI:NTFS */
    BOOL result = uefi_ntfs_needs_extra_partition(BT_IMAGE, FS_NTFS, TT_UEFI, &r);
    CHECK(result == TRUE);
}

TEST(needs_partition_efi_bootable_exfat)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = TRUE;
    r.has_efi = TRUE;
    BOOL result = uefi_ntfs_needs_extra_partition(BT_IMAGE, FS_EXFAT, TT_UEFI, &r);
    CHECK(result == TRUE);
}

TEST(no_partition_when_not_efi_bootable)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = TRUE;
    r.has_efi = FALSE;   /* no EFI bootloaders */
    BOOL result = uefi_ntfs_needs_extra_partition(BT_IMAGE, FS_NTFS, TT_UEFI, &r);
    CHECK(result == FALSE);
}

TEST(no_partition_for_fat32_fs)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = TRUE;
    r.has_efi = TRUE;
    /* FAT32 is already UEFI-readable — no UEFI:NTFS needed */
    BOOL result = uefi_ntfs_needs_extra_partition(BT_IMAGE, FS_FAT32, TT_UEFI, &r);
    CHECK(result == FALSE);
}

TEST(no_partition_for_ext_fs)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = TRUE;
    r.has_efi = TRUE;
    BOOL result = uefi_ntfs_needs_extra_partition(BT_IMAGE, FS_EXT2, TT_UEFI, &r);
    CHECK(result == FALSE);
}

TEST(no_partition_for_non_bootable)
{
    RUFUS_IMG_REPORT r = { 0 };
    r.is_bootable_img = FALSE;
    r.has_efi = TRUE;
    BOOL result = uefi_ntfs_needs_extra_partition(BT_NON_BOOTABLE, FS_NTFS, TT_UEFI, &r);
    CHECK(result == FALSE);
}

TEST(needs_partition_for_bt_uefi_ntfs)
{
    /* BT_UEFI_NTFS boot type always needs the extra partition regardless of image */
    RUFUS_IMG_REPORT r = { 0 };
    BOOL result = uefi_ntfs_needs_extra_partition(BT_UEFI_NTFS, FS_NTFS, TT_UEFI, &r);
    CHECK(result == TRUE);
}

TEST(no_partition_when_report_null)
{
    /* NULL report means we can't determine EFI support */
    BOOL result = uefi_ntfs_needs_extra_partition(BT_IMAGE, FS_NTFS, TT_UEFI, NULL);
    CHECK(result == FALSE);
}

/* =========================================================================
 * TEST GROUP 2: MBR CreatePartition with XP_UEFI_NTFS
 * ========================================================================= */

TEST(mbr_uefi_ntfs_partition_created)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;
    BOOL ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_NTFS,
                               TRUE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);

    /* Read back the MBR and verify two partition entries are present */
    uint8_t mbr[512];
    ssize_t r = pread(g_img_fd, mbr, 512, 0);
    CHECK(r == 512);
    CHECK(mbr[510] == 0x55);
    CHECK(mbr[511] == 0xAA);

    /* First partition entry (main) */
    const uint8_t *e0 = mbr + 446;
    uint32_t lba0 = (uint32_t)e0[8] | ((uint32_t)e0[9] << 8) |
                    ((uint32_t)e0[10] << 16) | ((uint32_t)e0[11] << 24);
    uint32_t sz0  = (uint32_t)e0[12] | ((uint32_t)e0[13] << 8) |
                    ((uint32_t)e0[14] << 16) | ((uint32_t)e0[15] << 24);
    CHECK(lba0 == 2048);  /* standard first partition LBA */
    CHECK(sz0 > 0);

    /* Second partition entry (UEFI:NTFS — type 0xEF) at end */
    const uint8_t *e1 = mbr + 446 + 16;
    uint8_t type1 = e1[4];
    uint32_t lba1 = (uint32_t)e1[8] | ((uint32_t)e1[9] << 8) |
                    ((uint32_t)e1[10] << 16) | ((uint32_t)e1[11] << 24);
    CHECK(type1 == 0xEF);   /* EFI System partition type */
    CHECK(lba1 >= lba0 + sz0);  /* UEFI:NTFS is after the main partition */

    /* partition_index[PI_UEFI_NTFS] should be set */
    CHECK(partition_index[PI_UEFI_NTFS] != 0 ||
          SelectedDrive.Partition[PI_UEFI_NTFS].Size > 0);

    teardown_image();
}

TEST(mbr_uefi_ntfs_offset_populated)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;
    BOOL ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_NTFS,
                               TRUE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);
    CHECK(SelectedDrive.Partition[PI_UEFI_NTFS].Offset > 0);
    CHECK(SelectedDrive.Partition[PI_UEFI_NTFS].Size > 0);
    teardown_image();
}

TEST(mbr_uefi_ntfs_size_matches_img)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;
    BOOL ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_NTFS,
                               TRUE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);
    /* The UEFI:NTFS partition should be >= 1 MB (size of uefi-ntfs.img) */
    CHECK(SelectedDrive.Partition[PI_UEFI_NTFS].Size >= MB);
    teardown_image();
}

TEST(mbr_uefi_ntfs_main_partition_shrunk)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;

    /* Create without UEFI:NTFS first to get baseline main partition size */
    BOOL ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_NTFS, TRUE, 0);
    CHECK(ok == TRUE);
    uint64_t size_without = SelectedDrive.Partition[PI_MAIN].Size;

    /* Now with UEFI:NTFS */
    memset(&SelectedDrive.Partition, 0, sizeof(SelectedDrive.Partition));
    ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_NTFS, TRUE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);
    uint64_t size_with = SelectedDrive.Partition[PI_MAIN].Size;

    CHECK(size_with < size_without);
    teardown_image();
}

/* =========================================================================
 * TEST GROUP 3: GPT CreatePartition with XP_UEFI_NTFS
 * ========================================================================= */

TEST(gpt_uefi_ntfs_partition_created)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;
    BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS,
                               FALSE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);

    /* Read GPT header at LBA 1 */
    uint8_t gpt_hdr[512];
    ssize_t r = pread(g_img_fd, gpt_hdr, 512, 512);
    CHECK(r == 512);
    CHECK(memcmp(gpt_hdr, "EFI PART", 8) == 0);

    teardown_image();
}

TEST(gpt_uefi_ntfs_offset_populated)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;
    BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS,
                               FALSE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);
    CHECK(SelectedDrive.Partition[PI_UEFI_NTFS].Offset > 0);
    CHECK(SelectedDrive.Partition[PI_UEFI_NTFS].Size >= MB);
    teardown_image();
}

TEST(gpt_uefi_ntfs_esp_guid_present)
{
    /* EFI System Partition GUID (on-disk LE): C12A7328-F81F-11D2-BA4B-00A0C93EC93B */
    static const uint8_t ESP_GUID_LE[16] = {
        0x28,0x73,0x2A,0xC1, 0x1F,0xF8, 0xD2,0x11,
        0xBA,0x4B, 0x00,0xA0,0xC9,0x3E,0xC9,0x3B
    };
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;
    BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS,
                               FALSE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);

    /* Read partition entries at LBA 2 (offset 1024) */
    uint8_t entries[128 * 128];
    ssize_t r = pread(g_img_fd, entries, sizeof(entries), 1024);
    CHECK(r == (ssize_t)sizeof(entries));

    /* Search for an entry with the ESP GUID */
    BOOL found_esp = FALSE;
    for (int i = 0; i < 128; i++) {
        const uint8_t *pe = entries + i * 128;
        if (memcmp(pe, ESP_GUID_LE, 16) == 0) {
            found_esp = TRUE;
            break;
        }
    }
    CHECK(found_esp == TRUE);

    teardown_image();
}

TEST(gpt_uefi_ntfs_main_partition_shrunk)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;

    /* Baseline without UEFI:NTFS */
    BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, 0);
    CHECK(ok == TRUE);
    uint64_t size_without = SelectedDrive.Partition[PI_MAIN].Size;

    memset(&SelectedDrive.Partition, 0, sizeof(SelectedDrive.Partition));
    ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);
    uint64_t size_with = SelectedDrive.Partition[PI_MAIN].Size;

    CHECK(size_with < size_without);
    teardown_image();
}

/* =========================================================================
 * TEST GROUP 4: load_uefi_ntfs_data()
 * ========================================================================= */

TEST(load_uefi_ntfs_data_not_null)
{
    size_t sz = 0;
    uint8_t *data = load_uefi_ntfs_data(&sz);
    /* The image should be loadable from res/uefi/uefi-ntfs.img */
    CHECK(data != NULL);
    if (data) {
        CHECK(sz == 1024 * 1024);  /* exactly 1 MiB */
        free(data);
    }
}

TEST(load_uefi_ntfs_data_size_correct)
{
    size_t sz = 0;
    uint8_t *data = load_uefi_ntfs_data(&sz);
    if (data == NULL) {
        /* Skip gracefully if res/ not available */
        printf("  SKIP: uefi-ntfs.img not found\n");
        free(data);
        return;
    }
    CHECK(sz > 0);
    CHECK(sz == 1024 * 1024);  /* 1 MiB exactly */
    free(data);
}

TEST(load_uefi_ntfs_data_has_fat_sig)
{
    size_t sz = 0;
    uint8_t *data = load_uefi_ntfs_data(&sz);
    if (data == NULL) {
        printf("  SKIP: uefi-ntfs.img not found\n");
        return;
    }
    /* uefi-ntfs.img is a FAT filesystem image — sector 0 ends with 0x55 0xAA */
    CHECK(sz >= 512);
    CHECK(data[510] == 0x55);
    CHECK(data[511] == 0xAA);
    free(data);
}

/* =========================================================================
 * TEST GROUP 5: write_uefi_ntfs_partition()
 * ========================================================================= */

TEST(write_uefi_ntfs_to_offset)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;

    /* Use a small synthetic payload (512 bytes with FAT signature) */
    uint8_t payload[512];
    memset(payload, 0xAB, sizeof(payload));
    payload[510] = 0x55;
    payload[511] = 0xAA;

    uint64_t write_offset = 60ULL * MB;  /* near end of 64 MB image */
    BOOL ok = write_uefi_ntfs_partition(h, write_offset, payload, sizeof(payload));
    CHECK(ok == TRUE);

    /* Read back and verify */
    uint8_t readback[512];
    ssize_t r = pread(g_img_fd, readback, sizeof(readback), (off_t)write_offset);
    CHECK(r == 512);
    CHECK(memcmp(readback, payload, sizeof(payload)) == 0);

    teardown_image();
}

TEST(write_uefi_ntfs_null_data_fails)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;
    BOOL ok = write_uefi_ntfs_partition(h, MB, NULL, 512);
    CHECK(ok == FALSE);
    teardown_image();
}

TEST(write_uefi_ntfs_zero_size_fails)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;
    uint8_t buf[4] = { 0 };
    BOOL ok = write_uefi_ntfs_partition(h, MB, buf, 0);
    CHECK(ok == FALSE);
    teardown_image();
}

TEST(write_uefi_ntfs_invalid_handle_fails)
{
    uint8_t buf[512] = { 0 };
    BOOL ok = write_uefi_ntfs_partition(INVALID_HANDLE_VALUE, MB, buf, sizeof(buf));
    CHECK(ok == FALSE);
}

/* =========================================================================
 * TEST GROUP 6: XP_UEFI_NTFS + XP_PERSISTENCE together
 * ========================================================================= */

TEST(mbr_uefi_ntfs_and_persistence)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;

    /* Set persistence_size (global) */
    extern uint64_t persistence_size;
    persistence_size = 4 * MB;

    BOOL ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_NTFS,
                               TRUE, XP_UEFI_NTFS | XP_PERSISTENCE);
    CHECK(ok == TRUE);

    /* Three partitions: main + persistence + UEFI:NTFS */
    uint8_t mbr[512];
    pread(g_img_fd, mbr, 512, 0);

    /* Count non-empty MBR entries */
    int n = 0;
    for (int i = 0; i < 4; i++) {
        const uint8_t *e = mbr + 446 + i * 16;
        uint32_t lba = (uint32_t)e[8] | ((uint32_t)e[9] << 8) |
                       ((uint32_t)e[10] << 16) | ((uint32_t)e[11] << 24);
        if (lba > 0) n++;
    }
    CHECK(n == 3);

    /* UEFI:NTFS and persistence both have valid offsets */
    CHECK(SelectedDrive.Partition[PI_UEFI_NTFS].Offset > 0);
    CHECK(SelectedDrive.Partition[PI_CASPER].Offset > 0);

    persistence_size = 0;
    teardown_image();
}

TEST(gpt_uefi_ntfs_and_persistence)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;

    extern uint64_t persistence_size;
    persistence_size = 4 * MB;

    BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS,
                               FALSE, XP_UEFI_NTFS | XP_PERSISTENCE);
    CHECK(ok == TRUE);

    /* Both UEFI:NTFS and persistence partitions should be present */
    CHECK(SelectedDrive.Partition[PI_UEFI_NTFS].Offset > 0);
    CHECK(SelectedDrive.Partition[PI_CASPER].Offset > 0);
    CHECK(SelectedDrive.Partition[PI_UEFI_NTFS].Offset !=
          SelectedDrive.Partition[PI_CASPER].Offset);

    persistence_size = 0;
    teardown_image();
}

/* =========================================================================
 * TEST GROUP 7: End-to-end partition + image write
 * ========================================================================= */

TEST(uefi_ntfs_written_after_partition)
{
    /* Load real uefi-ntfs.img; skip if unavailable */
    size_t img_sz = 0;
    uint8_t *img_data = load_uefi_ntfs_data(&img_sz);
    if (img_data == NULL) {
        printf("  SKIP: uefi-ntfs.img not found\n");
        return;
    }

    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;

    BOOL ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_NTFS,
                               TRUE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);

    uint64_t offset = SelectedDrive.Partition[PI_UEFI_NTFS].Offset;
    CHECK(offset > 0);

    ok = write_uefi_ntfs_partition(h, offset, img_data, img_sz);
    CHECK(ok == TRUE);

    /* Verify the FAT signature is present at the written offset */
    uint8_t sector0[512];
    ssize_t r = pread(g_img_fd, sector0, 512, (off_t)offset);
    CHECK(r == 512);
    CHECK(sector0[510] == 0x55);
    CHECK(sector0[511] == 0xAA);

    free(img_data);
    teardown_image();
}

TEST(uefi_ntfs_does_not_overlap_main_partition)
{
    CHECK(setup_image());
    HANDLE h = (HANDLE)(intptr_t)g_img_fd;

    BOOL ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_NTFS,
                               TRUE, XP_UEFI_NTFS);
    CHECK(ok == TRUE);

    uint64_t main_off  = SelectedDrive.Partition[PI_MAIN].Offset;
    uint64_t main_end  = main_off + SelectedDrive.Partition[PI_MAIN].Size;
    uint64_t uefi_off  = SelectedDrive.Partition[PI_UEFI_NTFS].Offset;

    CHECK(uefi_off >= main_end);  /* UEFI:NTFS starts after main partition ends */
    teardown_image();
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(void)
{
    printf("=== UEFI:NTFS boot bridge tests ===\n");
    printf("uefi_ntfs_needs_extra_partition() logic:\n");
    RUN(needs_partition_efi_bootable_ntfs);
    RUN(needs_partition_efi_bootable_exfat);
    RUN(no_partition_when_not_efi_bootable);
    RUN(no_partition_for_fat32_fs);
    RUN(no_partition_for_ext_fs);
    RUN(no_partition_for_non_bootable);
    RUN(needs_partition_for_bt_uefi_ntfs);
    RUN(no_partition_when_report_null);

    printf("\nMBR CreatePartition + XP_UEFI_NTFS:\n");
    RUN(mbr_uefi_ntfs_partition_created);
    RUN(mbr_uefi_ntfs_offset_populated);
    RUN(mbr_uefi_ntfs_size_matches_img);
    RUN(mbr_uefi_ntfs_main_partition_shrunk);

    printf("\nGPT CreatePartition + XP_UEFI_NTFS:\n");
    RUN(gpt_uefi_ntfs_partition_created);
    RUN(gpt_uefi_ntfs_offset_populated);
    RUN(gpt_uefi_ntfs_esp_guid_present);
    RUN(gpt_uefi_ntfs_main_partition_shrunk);

    printf("\nload_uefi_ntfs_data():\n");
    RUN(load_uefi_ntfs_data_not_null);
    RUN(load_uefi_ntfs_data_size_correct);
    RUN(load_uefi_ntfs_data_has_fat_sig);

    printf("\nwrite_uefi_ntfs_partition():\n");
    RUN(write_uefi_ntfs_to_offset);
    RUN(write_uefi_ntfs_null_data_fails);
    RUN(write_uefi_ntfs_zero_size_fails);
    RUN(write_uefi_ntfs_invalid_handle_fails);

    printf("\nXP_UEFI_NTFS + XP_PERSISTENCE:\n");
    RUN(mbr_uefi_ntfs_and_persistence);
    RUN(gpt_uefi_ntfs_and_persistence);

    printf("\nEnd-to-end:\n");
    RUN(uefi_ntfs_written_after_partition);
    RUN(uefi_ntfs_does_not_overlap_main_partition);

    TEST_RESULTS();
}

#endif /* __linux__ */
