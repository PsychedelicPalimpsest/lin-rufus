/*
 * test_partition_ops_linux.c — Tests for DeletePartition, GetEspOffset, ToggleEsp
 *
 * Tests cover:
 *   1. DeletePartition on MBR images
 *   2. DeletePartition on GPT images
 *   3. DeletePartition with invalid inputs
 *   4. GetEspOffset on MBR images (with and without EFI partition)
 *   5. GetEspOffset on GPT images (with and without ESP)
 *   6. ToggleEsp on GPT images (toggle MS Basic Data ↔ EFI System)
 *   7. ToggleEsp on MBR images (toggle FAT32 ↔ EFI System type)
 *   8. ToggleEsp on non-existent partition
 *
 * All tests use temp image files; no real block device is touched.
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

/* Re-use the externs from the test-support API */
extern RUFUS_DRIVE_INFO SelectedDrive;
extern int partition_index[];

/* Functions under test (declared in drive.h) */
extern BOOL DeletePartition(DWORD DriveIndex, ULONGLONG PartitionOffset, BOOL bSilent);
extern uint64_t GetEspOffset(DWORD DriveIndex);
extern BOOL ToggleEsp(DWORD DriveIndex, uint64_t PartitionOffset);

/* Functions used to set up test state */
extern BOOL InitializeDisk(HANDLE hDrive);
extern BOOL CreatePartition(HANDLE hDrive, int PartitionStyle, int FileSystem,
                            BOOL bMBRIsBootable, uint8_t extra_partitions);
extern BOOL GetDrivePartitionData(DWORD DriveIndex, char *FileSystemName,
                                  DWORD FileSystemNameSize, BOOL bSilent);
extern HANDLE GetPhysicalHandle(DWORD DriveIndex, BOOL bLockDrive,
                                BOOL bWriteAccess, BOOL bWriteShare);
extern void linux_register_fd_offset(int fd, uint64_t base, uint64_t size);

/* GPT type GUIDs in on-disk little-endian byte form */
/* EFI System: {C12A7328-F81F-11D2-BA4B-00A0C93EC93B} */
static const uint8_t ESP_GUID_LE[16] = {
	0x28,0x73,0x2A,0xC1, 0x1F,0xF8, 0xD2,0x11,
	0xBA,0x4B, 0x00,0xA0,0xC9,0x3E,0xC9,0x3B
};
/* Microsoft Basic Data: {EBD0A0A2-B9E5-4433-87C0-68B6B72699C7} */
static const uint8_t MSBD_GUID_LE[16] = {
	0xA2,0xA0,0xD0,0xEB, 0xE5,0xB9, 0x33,0x44,
	0x87,0xC0, 0x68,0xB6,0xB7,0x26,0x99,0xC7
};
/* Microsoft Reserved Partition: {E3C9E316-0B5C-4DB8-817D-F92DF00215AE} */
static const uint8_t MSR_GUID_LE[16] = {
	0x16,0xE3,0xC9,0xE3, 0x5C,0x0B, 0xB8,0x4D,
	0x81,0x7D, 0xF9,0x2D,0xF0,0x02,0x15,0xAE
};

/* CRC-32 (IEEE 802.3 polynomial) used by GPT */
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
#define IMG_SIZE (64ULL * 1024 * 1024)  /* 64 MB sparse image */
/* Windows To Go requires ESP (260 MB) + MSR (128 MB), use 1 GB for those tests */
#define IMG_SIZE_LARGE (1ULL * 1024 * 1024 * 1024)
#define SECTOR   512
#define DRIVE_IDX DRIVE_INDEX_MIN

static char g_path[64];
static int  g_img_fd = -1;

static void setup_image(void)
{
	strcpy(g_path, "/tmp/rufus_partops_XXXXXX");
	g_img_fd = mkstemp(g_path);
	if (g_img_fd < 0) { perror("mkstemp"); abort(); }
	if (ftruncate(g_img_fd, (off_t)IMG_SIZE) != 0) { perror("ftruncate"); abort(); }

	/* Write MBR signature so AnalyzeMBR won't think it's totally raw */
	uint8_t sig[2] = { 0x55, 0xAA };
	pwrite(g_img_fd, sig, 2, 510);

	drive_linux_reset_drives();
	drive_linux_add_drive(g_path, "T", "TestDisk", IMG_SIZE);
	SelectedDrive.DiskSize   = (LONGLONG)IMG_SIZE;
	SelectedDrive.SectorSize = SECTOR;
}

static void setup_large_image(void)
{
	strcpy(g_path, "/tmp/rufus_partops_XXXXXX");
	g_img_fd = mkstemp(g_path);
	if (g_img_fd < 0) { perror("mkstemp"); abort(); }
	if (ftruncate(g_img_fd, (off_t)IMG_SIZE_LARGE) != 0) { perror("ftruncate"); abort(); }

	uint8_t sig[2] = { 0x55, 0xAA };
	pwrite(g_img_fd, sig, 2, 510);

	drive_linux_reset_drives();
	drive_linux_add_drive(g_path, "T", "TestDisk", IMG_SIZE_LARGE);
	SelectedDrive.DiskSize   = (LONGLONG)IMG_SIZE_LARGE;
	SelectedDrive.SectorSize = SECTOR;
}

static void teardown_image(void)
{
	if (g_img_fd >= 0) { close(g_img_fd); g_img_fd = -1; }
	unlink(g_path);
}

/* -------------------------------------------------------------------------
 * Build an MBR partition table in the temp image.
 * Creates one partition at LBA 2048, size = (total_sectors - 2048) sectors.
 * type_byte: e.g. 0x0C for FAT32, 0xEF for EFI System.
 * --------------------------------------------------------------------- */
static void write_mbr_partition(uint8_t type_byte, uint64_t *out_offset_bytes)
{
	uint8_t mbr[512] = { 0 };
	/* Signature */
	mbr[510] = 0x55; mbr[511] = 0xAA;

	uint32_t lba_start = 2048;
	uint32_t lba_size  = (uint32_t)((IMG_SIZE / SECTOR) - lba_start);

	uint8_t *e = mbr + 446;
	e[0]  = 0x80;               /* bootable */
	e[4]  = type_byte;
	e[5]  = 0xFE; e[6] = 0xFF; e[7] = 0xFF;
	e[8]  = (lba_start)       & 0xFF;
	e[9]  = (lba_start >>  8) & 0xFF;
	e[10] = (lba_start >> 16) & 0xFF;
	e[11] = (lba_start >> 24) & 0xFF;
	e[12] = (lba_size)        & 0xFF;
	e[13] = (lba_size >>  8)  & 0xFF;
	e[14] = (lba_size >> 16)  & 0xFF;
	e[15] = (lba_size >> 24)  & 0xFF;

	pwrite(g_img_fd, mbr, 512, 0);
	if (out_offset_bytes)
		*out_offset_bytes = (uint64_t)lba_start * SECTOR;
}

/* -------------------------------------------------------------------------
 * Build a GPT image in the temp image using CreatePartition.
 * The partition type GUID depends on what CreatePartition writes (MS Basic Data).
 * Returns the partition byte offset.
 * --------------------------------------------------------------------- */
static uint64_t write_gpt_partition(void)
{
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	if (h == INVALID_HANDLE_VALUE) abort();
	CreatePartition(h, PARTITION_STYLE_GPT, FS_FAT32, FALSE, 0);
	CloseHandle(h);

	/* Now use GetDrivePartitionData to find the partition offset */
	char fsname[32] = "";
	GetDrivePartitionData(DRIVE_IDX, fsname, sizeof(fsname), TRUE);
	if (SelectedDrive.nPartitions < 1) return 0;
	return SelectedDrive.Partition[0].Offset;
}

/* -------------------------------------------------------------------------
 * Build a GPT image with an ESP type GUID (instead of MS Basic Data).
 * We use CreatePartition then patch the type GUID in the entries.
 * --------------------------------------------------------------------- */
static uint64_t write_gpt_esp_partition(void)
{
	/* First create with default (MS Basic Data) */
	uint64_t off = write_gpt_partition();

	/* Now read the entries (sector 2 = LBA 2, 128 * 128 bytes) */
	size_t entries_sz = 128 * 128;
	uint8_t *entries = calloc(1, entries_sz);
	if (!entries) abort();
	pread(g_img_fd, entries, entries_sz, 1024);

	/* Patch first entry's type GUID to ESP */
	memcpy(entries, ESP_GUID_LE, 16);

	/* Recompute entries CRC */
	uint32_t ecrc = crc32_ieee(entries, entries_sz);
	pwrite(g_img_fd, entries, entries_sz, 1024);

	/* Update header's entries CRC field (offset 88 in GPT header = sector 1) */
	uint8_t hdr[512];
	pread(g_img_fd, hdr, 512, 512);
	hdr[88] = ecrc & 0xFF;
	hdr[89] = (ecrc >>  8) & 0xFF;
	hdr[90] = (ecrc >> 16) & 0xFF;
	hdr[91] = (ecrc >> 24) & 0xFF;
	/* Recompute header CRC (first 92 bytes, field at offset 16 = 0) */
	uint8_t tmp[92];
	memcpy(tmp, hdr, 92);
	tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
	uint32_t hcrc = crc32_ieee(tmp, 92);
	hdr[16] = hcrc & 0xFF;
	hdr[17] = (hcrc >>  8) & 0xFF;
	hdr[18] = (hcrc >> 16) & 0xFF;
	hdr[19] = (hcrc >> 24) & 0xFF;
	pwrite(g_img_fd, hdr, 512, 512);

	free(entries);
	return off;
}

/* ============================================================
 * 1. DeletePartition — invalid inputs
 * ============================================================ */

TEST(delete_part_invalid_drive_index)
{
	setup_image();
	/* Out-of-range index: should return FALSE */
	BOOL r = DeletePartition(DRIVE_INDEX_MIN - 1, 2048 * SECTOR, TRUE);
	CHECK(r == FALSE);
	teardown_image();
}

TEST(delete_part_no_drives)
{
	drive_linux_reset_drives();
	BOOL r = DeletePartition(DRIVE_INDEX_MIN, 2048 * SECTOR, TRUE);
	CHECK(r == FALSE);
}

TEST(delete_part_offset_not_found_mbr)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0x0C, &off);
	/* Try to delete at a wrong offset */
	BOOL r = DeletePartition(DRIVE_IDX, off + 512, TRUE);
	CHECK(r == FALSE);
	teardown_image();
}

TEST(delete_part_offset_not_found_gpt)
{
	setup_image();
	uint64_t off = write_gpt_partition();
	/* Try to delete at a wrong offset */
	BOOL r = DeletePartition(DRIVE_IDX, off + 512, TRUE);
	CHECK(r == FALSE);
	teardown_image();
}

/* ============================================================
 * 2. DeletePartition — MBR
 * ============================================================ */

TEST(delete_part_mbr_removes_entry)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0x0C, &off);

	BOOL r = DeletePartition(DRIVE_IDX, off, TRUE);
	CHECK(r == TRUE);

	/* Read back the MBR and verify the partition entry at bytes 446..461 is zeroed */
	uint8_t mbr[512];
	pread(g_img_fd, mbr, 512, 0);
	uint8_t *e = mbr + 446;
	int zeroed = 1;
	for (int i = 0; i < 16; i++) {
		if (e[i] != 0) { zeroed = 0; break; }
	}
	CHECK(zeroed == 1);
	teardown_image();
}

TEST(delete_part_mbr_signature_preserved)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0x0C, &off);

	DeletePartition(DRIVE_IDX, off, TRUE);

	/* MBR signature must be preserved */
	uint8_t mbr[512];
	pread(g_img_fd, mbr, 512, 0);
	CHECK(mbr[510] == 0x55);
	CHECK(mbr[511] == 0xAA);
	teardown_image();
}

TEST(delete_part_mbr_returns_true)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0x83, &off);  /* Linux type */
	BOOL r = DeletePartition(DRIVE_IDX, off, TRUE);
	CHECK(r == TRUE);
	teardown_image();
}

/* ============================================================
 * 3. DeletePartition — GPT
 * ============================================================ */

TEST(delete_part_gpt_zeroes_entry)
{
	setup_image();
	uint64_t off = write_gpt_partition();
	CHECK(off > 0);

	BOOL r = DeletePartition(DRIVE_IDX, off, TRUE);
	CHECK(r == TRUE);

	/* Read back GPT entries (LBA 2 = byte offset 1024) */
	uint8_t entry[128];
	pread(g_img_fd, entry, 128, 1024);
	/* Type GUID should be all zeros */
	int all_zero = 1;
	for (int i = 0; i < 16; i++) {
		if (entry[i] != 0) { all_zero = 0; break; }
	}
	CHECK(all_zero == 1);
	teardown_image();
}

TEST(delete_part_gpt_header_crc_updated)
{
	setup_image();
	uint64_t off = write_gpt_partition();

	DeletePartition(DRIVE_IDX, off, TRUE);

	/* Read back GPT header and verify header CRC is non-zero (was updated) */
	uint8_t hdr[512];
	pread(g_img_fd, hdr, 512, 512);
	uint32_t stored_crc = hdr[16] | ((uint32_t)hdr[17] << 8) |
	                      ((uint32_t)hdr[18] << 16) | ((uint32_t)hdr[19] << 24);
	CHECK(stored_crc != 0);

	/* Verify the CRC is correct */
	uint8_t tmp[92];
	memcpy(tmp, hdr, 92);
	tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
	uint32_t expected = crc32_ieee(tmp, 92);
	CHECK(stored_crc == expected);

	teardown_image();
}

TEST(delete_part_gpt_returns_true)
{
	setup_image();
	uint64_t off = write_gpt_partition();
	BOOL r = DeletePartition(DRIVE_IDX, off, TRUE);
	CHECK(r == TRUE);
	teardown_image();
}

/* ============================================================
 * 4. GetEspOffset — no ESP
 * ============================================================ */

TEST(get_esp_offset_invalid_drive)
{
	drive_linux_reset_drives();
	uint64_t r = GetEspOffset(DRIVE_INDEX_MIN - 1);
	CHECK(r == 0);
}

TEST(get_esp_offset_no_drives)
{
	drive_linux_reset_drives();
	uint64_t r = GetEspOffset(DRIVE_INDEX_MIN);
	CHECK(r == 0);
}

TEST(get_esp_offset_unpartitioned_disk)
{
	setup_image();
	/* No valid partition table → offset 0 */
	uint64_t r = GetEspOffset(DRIVE_IDX);
	CHECK(r == 0);
	teardown_image();
}

TEST(get_esp_offset_mbr_fat32_not_esp)
{
	setup_image();
	write_mbr_partition(0x0C, NULL);  /* FAT32 LBA, not EFI */
	uint64_t r = GetEspOffset(DRIVE_IDX);
	CHECK(r == 0);
	teardown_image();
}

TEST(get_esp_offset_gpt_ms_basic_not_esp)
{
	setup_image();
	write_gpt_partition();  /* creates MS Basic Data partition */
	uint64_t r = GetEspOffset(DRIVE_IDX);
	CHECK(r == 0);
	teardown_image();
}

/* ============================================================
 * 5. GetEspOffset — with ESP
 * ============================================================ */

TEST(get_esp_offset_mbr_efi_type)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0xEF, &off);  /* EFI System partition type */
	uint64_t r = GetEspOffset(DRIVE_IDX);
	CHECK(r == off);
	teardown_image();
}

TEST(get_esp_offset_gpt_esp_type)
{
	setup_image();
	uint64_t off = write_gpt_esp_partition();
	CHECK(off > 0);
	uint64_t r = GetEspOffset(DRIVE_IDX);
	CHECK(r == off);
	teardown_image();
}

/* ============================================================
 * 6. ToggleEsp — invalid inputs
 * ============================================================ */

TEST(toggle_esp_invalid_drive)
{
	drive_linux_reset_drives();
	BOOL r = ToggleEsp(DRIVE_INDEX_MIN - 1, 2048 * SECTOR);
	CHECK(r == FALSE);
}

TEST(toggle_esp_no_drives)
{
	drive_linux_reset_drives();
	BOOL r = ToggleEsp(DRIVE_INDEX_MIN, 2048 * SECTOR);
	CHECK(r == FALSE);
}

TEST(toggle_esp_gpt_offset_not_found)
{
	setup_image();
	uint64_t off = write_gpt_partition();
	/* Use wrong offset */
	BOOL r = ToggleEsp(DRIVE_IDX, off + 512);
	CHECK(r == FALSE);
	teardown_image();
}

TEST(toggle_esp_mbr_offset_not_found)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0x0C, &off);
	BOOL r = ToggleEsp(DRIVE_IDX, off + 512);
	CHECK(r == FALSE);
	teardown_image();
}

/* ============================================================
 * 7. ToggleEsp — GPT (MS Basic Data ↔ EFI System)
 * ============================================================ */

TEST(toggle_esp_gpt_basic_data_to_esp)
{
	setup_image();
	uint64_t off = write_gpt_partition();
	CHECK(off > 0);

	/* Initially MS Basic Data — ToggleEsp → should become ESP */
	BOOL r = ToggleEsp(DRIVE_IDX, off);
	CHECK(r == TRUE);

	/* Read back first entry's type GUID */
	uint8_t type[16];
	pread(g_img_fd, type, 16, 1024);
	CHECK(memcmp(type, ESP_GUID_LE, 16) == 0);

	teardown_image();
}

TEST(toggle_esp_gpt_esp_to_basic_data)
{
	setup_image();
	uint64_t off = write_gpt_esp_partition();
	CHECK(off > 0);

	/* Initially ESP — ToggleEsp → should become MS Basic Data */
	BOOL r = ToggleEsp(DRIVE_IDX, off);
	CHECK(r == TRUE);

	uint8_t type[16];
	pread(g_img_fd, type, 16, 1024);
	CHECK(memcmp(type, MSBD_GUID_LE, 16) == 0);

	teardown_image();
}

TEST(toggle_esp_gpt_roundtrip)
{
	setup_image();
	uint64_t off = write_gpt_partition();

	/* Toggle twice → back to original */
	ToggleEsp(DRIVE_IDX, off);
	ToggleEsp(DRIVE_IDX, off);

	uint8_t type[16];
	pread(g_img_fd, type, 16, 1024);
	CHECK(memcmp(type, MSBD_GUID_LE, 16) == 0);

	teardown_image();
}

TEST(toggle_esp_gpt_updates_crc)
{
	setup_image();
	uint64_t off = write_gpt_partition();
	ToggleEsp(DRIVE_IDX, off);

	/* Verify header CRC is correct after toggle */
	uint8_t hdr[512];
	pread(g_img_fd, hdr, 512, 512);
	uint32_t stored_hcrc = hdr[16] | ((uint32_t)hdr[17] << 8) |
	                       ((uint32_t)hdr[18] << 16) | ((uint32_t)hdr[19] << 24);
	uint8_t tmp[92];
	memcpy(tmp, hdr, 92);
	tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
	CHECK(stored_hcrc == crc32_ieee(tmp, 92));

	teardown_image();
}

/* ============================================================
 * 8. ToggleEsp — MBR (FAT32/0x0C ↔ EFI System/0xEF)
 * ============================================================ */

TEST(toggle_esp_mbr_fat32_becomes_efi)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0x0C, &off);  /* FAT32 LBA */

	BOOL r = ToggleEsp(DRIVE_IDX, off);
	CHECK(r == TRUE);

	uint8_t mbr[512];
	pread(g_img_fd, mbr, 512, 0);
	/* Type byte is at mbr[446 + 4] */
	CHECK(mbr[446 + 4] == 0xEF);

	teardown_image();
}

TEST(toggle_esp_mbr_efi_becomes_fat32)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0xEF, &off);

	BOOL r = ToggleEsp(DRIVE_IDX, off);
	CHECK(r == TRUE);

	uint8_t mbr[512];
	pread(g_img_fd, mbr, 512, 0);
	CHECK(mbr[446 + 4] == 0x0C);  /* FAT32 LBA */

	teardown_image();
}

TEST(toggle_esp_mbr_roundtrip)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0x0C, &off);

	ToggleEsp(DRIVE_IDX, off);
	ToggleEsp(DRIVE_IDX, off);

	uint8_t mbr[512];
	pread(g_img_fd, mbr, 512, 0);
	CHECK(mbr[446 + 4] == 0x0C);

	teardown_image();
}

TEST(toggle_esp_mbr_signature_preserved)
{
	setup_image();
	uint64_t off;
	write_mbr_partition(0x0C, &off);

	ToggleEsp(DRIVE_IDX, off);

	uint8_t mbr[512];
	pread(g_img_fd, mbr, 512, 0);
	CHECK(mbr[510] == 0x55);
	CHECK(mbr[511] == 0xAA);

	teardown_image();
}

/* ============================================================
 * 8. CreatePartition — XP_ESP / XP_MSR extra partitions
 * ============================================================ */

/* Helper: read a GPT entry from the entries array (128 bytes each, starts at LBA 2) */
static void read_gpt_entry(int entry_idx, uint8_t out_type[16],
                           uint64_t *out_start, uint64_t *out_end)
{
	uint8_t entry[128] = {0};
	pread(g_img_fd, entry, 128, 1024 + (off_t)(entry_idx * 128));
	if (out_type)  memcpy(out_type, entry, 16);
	if (out_start) {
		uint64_t v = 0;
		for (int i = 0; i < 8; i++) v |= (uint64_t)entry[32+i] << (8*i);
		*out_start = v;
	}
	if (out_end) {
		uint64_t v = 0;
		for (int i = 0; i < 8; i++) v |= (uint64_t)entry[40+i] << (8*i);
		*out_end = v;
	}
}

TEST(create_partition_gpt_with_esp_creates_two_partitions)
{
	setup_large_image();
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_ESP);
	CloseHandle(h);
	CHECK(ok == TRUE);

	GetDrivePartitionData(DRIVE_IDX, NULL, 0, TRUE);
	/* Should have 2 partitions: ESP + main */
	CHECK_INT_EQ(2, (int)SelectedDrive.nPartitions);

	teardown_image();
}

TEST(create_partition_gpt_with_esp_correct_type_guid)
{
	setup_large_image();
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_ESP);
	CloseHandle(h);

	/* First GPT entry should be ESP type GUID */
	uint8_t type[16];
	read_gpt_entry(0, type, NULL, NULL);
	CHECK_MSG(memcmp(type, ESP_GUID_LE, 16) == 0, "First partition must be ESP type GUID");

	teardown_image();
}

TEST(create_partition_gpt_with_esp_correct_size)
{
	/* ESP must be 260 MB = 260 * 1024 * 1024 bytes */
	setup_large_image();
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_ESP);
	CloseHandle(h);

	uint64_t esp_start, esp_end;
	read_gpt_entry(0, NULL, &esp_start, &esp_end);
	uint64_t esp_sectors = esp_end - esp_start + 1;
	uint64_t esp_bytes   = esp_sectors * 512;
	uint64_t expected    = 260ULL * 1024 * 1024;
	CHECK_MSG(esp_bytes == expected, "ESP must be exactly 260 MB");

	teardown_image();
}

TEST(create_partition_gpt_with_msr_creates_two_partitions)
{
	setup_large_image();
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_MSR);
	CloseHandle(h);
	CHECK(ok == TRUE);

	GetDrivePartitionData(DRIVE_IDX, NULL, 0, TRUE);
	CHECK_INT_EQ(2, (int)SelectedDrive.nPartitions);

	teardown_image();
}

TEST(create_partition_gpt_with_msr_correct_type_guid)
{
	setup_large_image();
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_MSR);
	CloseHandle(h);

	uint8_t type[16];
	read_gpt_entry(0, type, NULL, NULL);
	CHECK_MSG(memcmp(type, MSR_GUID_LE, 16) == 0, "First partition must be MSR type GUID");

	teardown_image();
}

TEST(create_partition_gpt_with_msr_correct_size)
{
	/* MSR must be 128 MB */
	setup_large_image();
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_MSR);
	CloseHandle(h);

	uint64_t msr_start, msr_end;
	read_gpt_entry(0, NULL, &msr_start, &msr_end);
	uint64_t msr_sectors = msr_end - msr_start + 1;
	uint64_t msr_bytes   = msr_sectors * 512;
	uint64_t expected    = 128ULL * 1024 * 1024;
	CHECK_MSG(msr_bytes == expected, "MSR must be exactly 128 MB");

	teardown_image();
}

TEST(create_partition_gpt_with_esp_and_msr_creates_three_partitions)
{
	setup_large_image();
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_ESP | XP_MSR);
	CloseHandle(h);
	CHECK(ok == TRUE);

	GetDrivePartitionData(DRIVE_IDX, NULL, 0, TRUE);
	/* Should have 3 partitions: ESP + MSR + main */
	CHECK_INT_EQ(3, (int)SelectedDrive.nPartitions);

	teardown_image();
}

TEST(create_partition_gpt_with_esp_and_msr_layout_order)
{
	/* ESP must come first, then MSR, then main data partition */
	setup_large_image();
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_ESP | XP_MSR);
	CloseHandle(h);

	uint8_t type0[16], type1[16], type2[16];
	uint64_t start0, end0, start1, end1, start2;
	read_gpt_entry(0, type0, &start0, &end0);
	read_gpt_entry(1, type1, &start1, &end1);
	read_gpt_entry(2, type2, &start2, NULL);

	CHECK_MSG(memcmp(type0, ESP_GUID_LE,  16) == 0, "Entry 0 must be ESP");
	CHECK_MSG(memcmp(type1, MSR_GUID_LE,  16) == 0, "Entry 1 must be MSR");
	CHECK_MSG(memcmp(type2, MSBD_GUID_LE, 16) == 0, "Entry 2 must be Main Data");

	/* Partitions must be contiguous and non-overlapping */
	CHECK_MSG(start1 > end0, "MSR must start after ESP ends");
	CHECK_MSG(start2 > end1, "Main must start after MSR ends");

	teardown_image();
}

TEST(create_partition_gpt_with_esp_and_msr_main_partition_index)
{
	/* PI_MAIN must point to the main data partition (index 2 when ESP+MSR present) */
	setup_large_image();
	HANDLE h = GetPhysicalHandle(DRIVE_IDX, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, XP_ESP | XP_MSR);
	CloseHandle(h);

	/* PI_MAIN should point to offset that is AFTER ESP and MSR */
	uint64_t esp_size = 260ULL * 1024 * 1024;
	uint64_t msr_size = 128ULL * 1024 * 1024;
	uint64_t expected_min_offset = 2048 * 512 + esp_size + msr_size;
	CHECK_MSG(SelectedDrive.Partition[partition_index[PI_MAIN]].Offset >= expected_min_offset,
	          "Main partition offset must be after ESP+MSR");

	teardown_image();
}

/* ============================================================
 * main
 * ============================================================ */

int main(void)
{
	printf("=== partition ops Linux tests ===\n");

	printf("--- DeletePartition (invalid inputs) ---\n");
	RUN_TEST(delete_part_invalid_drive_index);
	RUN_TEST(delete_part_no_drives);
	RUN_TEST(delete_part_offset_not_found_mbr);
	RUN_TEST(delete_part_offset_not_found_gpt);

	printf("--- DeletePartition (MBR) ---\n");
	RUN_TEST(delete_part_mbr_removes_entry);
	RUN_TEST(delete_part_mbr_signature_preserved);
	RUN_TEST(delete_part_mbr_returns_true);

	printf("--- DeletePartition (GPT) ---\n");
	RUN_TEST(delete_part_gpt_zeroes_entry);
	RUN_TEST(delete_part_gpt_header_crc_updated);
	RUN_TEST(delete_part_gpt_returns_true);

	printf("--- GetEspOffset (no ESP) ---\n");
	RUN_TEST(get_esp_offset_invalid_drive);
	RUN_TEST(get_esp_offset_no_drives);
	RUN_TEST(get_esp_offset_unpartitioned_disk);
	RUN_TEST(get_esp_offset_mbr_fat32_not_esp);
	RUN_TEST(get_esp_offset_gpt_ms_basic_not_esp);

	printf("--- GetEspOffset (with ESP) ---\n");
	RUN_TEST(get_esp_offset_mbr_efi_type);
	RUN_TEST(get_esp_offset_gpt_esp_type);

	printf("--- ToggleEsp (invalid inputs) ---\n");
	RUN_TEST(toggle_esp_invalid_drive);
	RUN_TEST(toggle_esp_no_drives);
	RUN_TEST(toggle_esp_gpt_offset_not_found);
	RUN_TEST(toggle_esp_mbr_offset_not_found);

	printf("--- ToggleEsp (GPT) ---\n");
	RUN_TEST(toggle_esp_gpt_basic_data_to_esp);
	RUN_TEST(toggle_esp_gpt_esp_to_basic_data);
	RUN_TEST(toggle_esp_gpt_roundtrip);
	RUN_TEST(toggle_esp_gpt_updates_crc);

	printf("--- ToggleEsp (MBR) ---\n");
	RUN_TEST(toggle_esp_mbr_fat32_becomes_efi);
	RUN_TEST(toggle_esp_mbr_efi_becomes_fat32);
	RUN_TEST(toggle_esp_mbr_roundtrip);
	RUN_TEST(toggle_esp_mbr_signature_preserved);

	printf("--- CreatePartition (XP_ESP / XP_MSR) ---\n");
	RUN_TEST(create_partition_gpt_with_esp_creates_two_partitions);
	RUN_TEST(create_partition_gpt_with_esp_correct_type_guid);
	RUN_TEST(create_partition_gpt_with_esp_correct_size);
	RUN_TEST(create_partition_gpt_with_msr_creates_two_partitions);
	RUN_TEST(create_partition_gpt_with_msr_correct_type_guid);
	RUN_TEST(create_partition_gpt_with_msr_correct_size);
	RUN_TEST(create_partition_gpt_with_esp_and_msr_creates_three_partitions);
	RUN_TEST(create_partition_gpt_with_esp_and_msr_layout_order);
	RUN_TEST(create_partition_gpt_with_esp_and_msr_main_partition_index);

	PRINT_RESULTS();
	drive_linux_reset_drives();
	return (g_failed == 0) ? 0 : 1;
}

#endif /* __linux__ */
