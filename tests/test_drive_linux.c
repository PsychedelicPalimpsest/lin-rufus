/*
 * test_drive_linux.c — Extensive unit tests for src/linux/drive.c
 *
 * Tests cover:
 *  1. GetPhysicalName       — drive-index → device path lookup
 *  2. GetPhysicalHandle     — open a device / file for I/O
 *  3. GetDriveSize          — size query (fstat fallback for regular files)
 *  4. IsMediaPresent        — accessibility check
 *  5. MBR parsing           — parse_mbr_partitions (internal, white-box)
 *  6. GPT parsing           — parse_gpt_partitions (internal, white-box)
 *  7. GetDrivePartitionData — end-to-end partition info population
 *  8. InitializeDisk        — zeroes partition area on disk image
 *  9. CreatePartition MBR   — writes correct MBR partition table
 * 10. CreatePartition GPT   — writes correct GPT partition table
 * 11. RefreshDriveLayout    — succeeds/fails gracefully
 * 12. GetLogicalName        — partition path lookup via fake sysfs
 * 13. UnmountVolume         — graceful handling (no actual unmount in tests)
 * 14. AltUnmountVolume      — graceful handling
 */

#include "framework.h"

/* Pull in the Linux drive.c internal API */
#include "../src/linux/drive_linux.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

/* -------------------------------------------------------------------------
 * Portable mkstemp wrapper: create + immediately remove from dir so the
 * file is cleaned up on close, but keep the fd open.
 * Returns fd >= 0 on success.  path[] is filled in.
 * --------------------------------------------------------------------- */
static int make_temp_file(char path[64], uint64_t size)
{
	strcpy(path, "/tmp/rufus_test_XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) return -1;

	/* Extend to requested size */
	if (size > 0 && ftruncate(fd, (off_t)size) != 0) {
		close(fd);
		unlink(path);
		return -1;
	}
	return fd;
}

/* -------------------------------------------------------------------------
 * Minimal CRC-32 used to construct/verify GPT headers in tests.
 * Uses the standard IEEE polynomial (same as GPT spec).
 * --------------------------------------------------------------------- */
static uint32_t crc32_update(uint32_t crc, const uint8_t *buf, size_t len)
{
	static uint32_t table[256];
	static int init = 0;
	if (!init) {
		for (uint32_t i = 0; i < 256; i++) {
			uint32_t c = i;
			for (int j = 0; j < 8; j++)
				c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
			table[i] = c;
		}
		init = 1;
	}
	crc = ~crc;
	for (size_t i = 0; i < len; i++)
		crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
	return ~crc;
}
static uint32_t crc32(const uint8_t *buf, size_t len) { return crc32_update(0, buf, len); }

/* -------------------------------------------------------------------------
 * Build a minimal MBR in a 512-byte buffer.
 * Writes up to 4 partition entries at the standard MBR offsets.
 * --------------------------------------------------------------------- */
typedef struct {
	uint8_t  status;       /* 0x80 = active, 0x00 = inactive */
	uint8_t  type;         /* partition type byte */
	uint32_t lba_start;    /* first sector (LE) */
	uint32_t lba_size;     /* number of sectors (LE) */
} mbr_part_spec_t;

static void build_mbr(uint8_t buf[512], const mbr_part_spec_t *parts, int nparts)
{
	memset(buf, 0, 512);
	buf[510] = 0x55;
	buf[511] = 0xAA;
	for (int i = 0; i < nparts && i < 4; i++) {
		uint8_t *e = buf + 446 + i * 16;
		e[0] = parts[i].status;
		/* CHS start — pack dummy values (not important for LBA) */
		e[1] = 0xFE; e[2] = 0xFF; e[3] = 0xFF;
		e[4] = parts[i].type;
		/* CHS end */
		e[5] = 0xFE; e[6] = 0xFF; e[7] = 0xFF;
		/* LBA start (LE32) */
		e[8]  = (parts[i].lba_start)       & 0xFF;
		e[9]  = (parts[i].lba_start >>  8) & 0xFF;
		e[10] = (parts[i].lba_start >> 16) & 0xFF;
		e[11] = (parts[i].lba_start >> 24) & 0xFF;
		/* LBA size (LE32) */
		e[12] = (parts[i].lba_size)        & 0xFF;
		e[13] = (parts[i].lba_size  >>  8) & 0xFF;
		e[14] = (parts[i].lba_size  >> 16) & 0xFF;
		e[15] = (parts[i].lba_size  >> 24) & 0xFF;
	}
}

/* -------------------------------------------------------------------------
 * Build a minimal GPT header + one partition entry in the provided buffers.
 * header_buf must be >= 512 bytes (sector 1).
 * entries_buf must be >= 128*128 = 16384 bytes (sectors 2-33).
 * total_sectors: total number of 512-byte sectors on the disk.
 * --------------------------------------------------------------------- */
static void build_gpt(uint8_t *header_buf, uint8_t *entries_buf,
                      uint64_t total_sectors,
                      uint64_t part_start_lba, uint64_t part_end_lba,
                      const uint8_t type_guid[16], const uint8_t part_guid[16])
{
	memset(header_buf, 0, 512);
	memset(entries_buf, 0, 128 * 128);

	/* Build one partition entry (128 bytes) */
	uint8_t *pe = entries_buf;
	memcpy(pe + 0,  type_guid, 16);
	memcpy(pe + 16, part_guid, 16);
	/* First LBA */
	for (int i = 0; i < 8; i++) pe[32 + i] = (part_start_lba >> (8*i)) & 0xFF;
	/* Last LBA */
	for (int i = 0; i < 8; i++) pe[40 + i] = (part_end_lba  >> (8*i)) & 0xFF;
	/* Attributes: 0 */
	/* Name: empty (all zero UTF-16) */

	uint32_t entries_crc = crc32(entries_buf, 128 * 128);

	/* Build GPT header */
	uint8_t *h = header_buf;
	memcpy(h, "EFI PART", 8);                  /* signature */
	h[8]  = 0x00; h[9]  = 0x00;               /* revision: 1.0 */
	h[10] = 0x01; h[11] = 0x00;
	/* Header size = 92 (LE32) */
	h[12] = 92; h[13] = 0; h[14] = 0; h[15] = 0;
	/* Header CRC32 — filled in below */
	/* Reserved: 0 */
	/* MyLBA = 1 */
	h[24] = 1;
	/* AlternateLBA = total_sectors - 1 */
	uint64_t alt = total_sectors - 1;
	for (int i = 0; i < 8; i++) h[32 + i] = (alt >> (8*i)) & 0xFF;
	/* FirstUsableLBA = 34 */
	h[40] = 34;
	/* LastUsableLBA = total_sectors - 34 */
	uint64_t last_usable = total_sectors - 34;
	for (int i = 0; i < 8; i++) h[48 + i] = (last_usable >> (8*i)) & 0xFF;
	/* Disk GUID — use a fixed test value */
	for (int i = 0; i < 16; i++) h[56 + i] = (uint8_t)(0xAB + i);
	/* StartingLBAOfPartitionEntries = 2 */
	h[72] = 2;
	/* NumberOfPartitionEntries = 128 (LE32) */
	h[80] = 128; h[81] = 0; h[82] = 0; h[83] = 0;
	/* SizeOfPartitionEntry = 128 (LE32) */
	h[84] = 128; h[85] = 0; h[86] = 0; h[87] = 0;
	/* PartitionEntryArrayCRC32 */
	h[88] = (entries_crc)       & 0xFF;
	h[89] = (entries_crc >>  8) & 0xFF;
	h[90] = (entries_crc >> 16) & 0xFF;
	h[91] = (entries_crc >> 24) & 0xFF;

	/* Now compute header CRC (over first 92 bytes, CRC field zeroed) */
	uint8_t hcrc_tmp[92];
	memcpy(hcrc_tmp, h, 92);
	hcrc_tmp[16] = hcrc_tmp[17] = hcrc_tmp[18] = hcrc_tmp[19] = 0;
	uint32_t hcrc = crc32(hcrc_tmp, 92);
	h[16] = (hcrc)       & 0xFF;
	h[17] = (hcrc >>  8) & 0xFF;
	h[18] = (hcrc >> 16) & 0xFF;
	h[19] = (hcrc >> 24) & 0xFF;
}

/* =========================================================================
 * 1. GetPhysicalName
 * ====================================================================== */

TEST(get_physical_name_valid)
{
	/* Inject a fake drive into the global table */
	drive_linux_reset_drives();
	drive_linux_add_drive("/dev/sdb", "Test Drive", "1.0 GB Test Drive", 1024*1024*1024ULL);

	char *name = GetPhysicalName(DRIVE_INDEX_MIN);
	CHECK(name != NULL);
	if (name) CHECK(strcmp(name, "/dev/sdb") == 0);
	safe_free(name);
}

TEST(get_physical_name_out_of_range)
{
	drive_linux_reset_drives();
	char *name = GetPhysicalName(DRIVE_INDEX_MIN + 99);
	CHECK(name == NULL);
}

TEST(get_physical_name_second_drive)
{
	drive_linux_reset_drives();
	drive_linux_add_drive("/dev/sdb", "Drive A", "512 MB Drive A", 512*1024*1024ULL);
	drive_linux_add_drive("/dev/sdc", "Drive B", "2.0 GB Drive B", 2048*1024*1024ULL);

	char *name0 = GetPhysicalName(DRIVE_INDEX_MIN);
	char *name1 = GetPhysicalName(DRIVE_INDEX_MIN + 1);
	CHECK(name0 != NULL);
	CHECK(name1 != NULL);
	if (name0) { CHECK(strcmp(name0, "/dev/sdb") == 0); safe_free(name0); }
	if (name1) { CHECK(strcmp(name1, "/dev/sdc") == 0); safe_free(name1); }
}

/* =========================================================================
 * 2. GetPhysicalHandle
 * ====================================================================== */

TEST(get_physical_handle_valid_file)
{
	char path[64];
	int tfd = make_temp_file(path, 1024 * 1024);
	CHECK(tfd >= 0);
	close(tfd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "Test", "1 MB Test", 1024*1024ULL);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	CHECK(h != NULL);
	CloseHandle(h);
	unlink(path);
}

TEST(get_physical_handle_nonexistent)
{
	drive_linux_reset_drives();
	drive_linux_add_drive("/nonexistent/path/xyz", "Fake", "Fake", 1024ULL);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h == INVALID_HANDLE_VALUE);
}

TEST(get_physical_handle_invalid_index)
{
	drive_linux_reset_drives();
	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN + 50, FALSE, TRUE, FALSE);
	CHECK(h == INVALID_HANDLE_VALUE);
}

TEST(get_physical_handle_readonly)
{
	char path[64];
	int tfd = make_temp_file(path, 64 * 1024);
	CHECK(tfd >= 0);
	close(tfd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "Test", "64KB Test", 64*1024ULL);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, FALSE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);
	CloseHandle(h);
	unlink(path);
}

/* =========================================================================
 * 3. GetDriveSize
 * ====================================================================== */

TEST(get_drive_size_regular_file)
{
	char path[64];
	int tfd = make_temp_file(path, 4 * 1024 * 1024ULL);  /* 4 MB */
	CHECK(tfd >= 0);
	close(tfd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "Test", "4 MB Test", 4*1024*1024ULL);

	uint64_t sz = GetDriveSize(DRIVE_INDEX_MIN);
	CHECK_INT_EQ((int)(sz / (1024*1024)), 4);
	unlink(path);
}

TEST(get_drive_size_zero_for_missing)
{
	drive_linux_reset_drives();
	drive_linux_add_drive("/nonexistent/dev/xyz", "X", "X", 0);
	uint64_t sz = GetDriveSize(DRIVE_INDEX_MIN);
	CHECK(sz == 0);
}

TEST(get_drive_size_invalid_index)
{
	drive_linux_reset_drives();
	uint64_t sz = GetDriveSize(DRIVE_INDEX_MIN + 99);
	CHECK(sz == 0);
}

/* =========================================================================
 * 4. IsMediaPresent
 * ====================================================================== */

TEST(is_media_present_existing_file)
{
	char path[64];
	int tfd = make_temp_file(path, 64 * 1024);
	CHECK(tfd >= 0);
	close(tfd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "Test", "64KB", 64*1024ULL);
	CHECK(IsMediaPresent(DRIVE_INDEX_MIN) != FALSE);
	unlink(path);
}

TEST(is_media_present_missing_file)
{
	drive_linux_reset_drives();
	drive_linux_add_drive("/no/such/device/xyz99", "X", "X", 0);
	CHECK(IsMediaPresent(DRIVE_INDEX_MIN) == FALSE);
}

TEST(is_media_present_invalid_index)
{
	drive_linux_reset_drives();
	CHECK(IsMediaPresent(DRIVE_INDEX_MIN + 99) == FALSE);
}

/* =========================================================================
 * 5. MBR parsing (white-box test of internal parse_mbr helper)
 * ====================================================================== */

TEST(parse_mbr_single_partition)
{
	uint8_t sector[512];
	mbr_part_spec_t p = { 0x80, 0x0C, 2048, 204800 };   /* FAT32 */
	build_mbr(sector, &p, 1);

	parsed_partition_t parts[4];
	int nparts;
	int style = drive_linux_parse_mbr(sector, parts, &nparts);

	CHECK_INT_EQ(style, PARTITION_STYLE_MBR);
	CHECK_INT_EQ(nparts, 1);
	CHECK(parts[0].offset == (uint64_t)2048 * 512);
	CHECK(parts[0].size   == (uint64_t)204800 * 512);
	CHECK_INT_EQ(parts[0].mbr_type, 0x0C);
}

TEST(parse_mbr_four_partitions)
{
	uint8_t sector[512];
	mbr_part_spec_t p[4] = {
		{ 0x80, 0x0C, 2048,   204800 },
		{ 0x00, 0x83, 206848, 409600 },
		{ 0x00, 0x82, 616448, 16384  },
		{ 0x00, 0x8E, 632832, 819200 },
	};
	build_mbr(sector, p, 4);

	parsed_partition_t parts[4];
	int nparts;
	int style = drive_linux_parse_mbr(sector, parts, &nparts);

	CHECK_INT_EQ(style, PARTITION_STYLE_MBR);
	CHECK_INT_EQ(nparts, 4);
	CHECK(parts[0].offset == (uint64_t)2048   * 512);
	CHECK(parts[1].offset == (uint64_t)206848 * 512);
	CHECK(parts[2].offset == (uint64_t)616448 * 512);
	CHECK(parts[3].offset == (uint64_t)632832 * 512);
	CHECK_INT_EQ(parts[1].mbr_type, 0x83);
	CHECK_INT_EQ(parts[2].mbr_type, 0x82);
}

TEST(parse_mbr_empty_table)
{
	uint8_t sector[512];
	memset(sector, 0, 512);
	sector[510] = 0x55;
	sector[511] = 0xAA;

	parsed_partition_t parts[4];
	int nparts;
	int style = drive_linux_parse_mbr(sector, parts, &nparts);

	CHECK_INT_EQ(style, PARTITION_STYLE_MBR);
	CHECK_INT_EQ(nparts, 0);
}

TEST(parse_mbr_bad_signature_is_raw)
{
	uint8_t sector[512];
	memset(sector, 0, 512);
	/* No 0x55AA signature */

	parsed_partition_t parts[4];
	int nparts;
	int style = drive_linux_parse_mbr(sector, parts, &nparts);

	CHECK_INT_EQ(style, PARTITION_STYLE_RAW);
}

TEST(parse_mbr_skips_zero_type_entries)
{
	uint8_t sector[512];
	mbr_part_spec_t p[4] = {
		{ 0x80, 0x0C, 2048,   204800 },
		{ 0x00, 0x00, 0,      0      },  /* empty */
		{ 0x00, 0x83, 206848, 409600 },
		{ 0x00, 0x00, 0,      0      },  /* empty */
	};
	build_mbr(sector, p, 4);

	parsed_partition_t parts[4];
	int nparts;
	drive_linux_parse_mbr(sector, parts, &nparts);

	CHECK_INT_EQ(nparts, 2);
}

/* =========================================================================
 * 6. GPT parsing
 * ====================================================================== */

/* Type GUID for Microsoft Basic Data: {EBD0A0A2-B9E5-4433-87C0-68B6B72699C7} */
static const uint8_t GUID_BASIC_DATA[16] = {
	0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
	0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
};
static const uint8_t TEST_PART_GUID[16] = {
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
	0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
};

TEST(parse_gpt_single_partition)
{
	uint64_t total_sectors = 2048 * 1024;  /* ~1 GB disk */
	uint8_t header[512];
	uint8_t entries[128 * 128];
	build_gpt(header, entries, total_sectors,
	          2048, 2048 + 204799, GUID_BASIC_DATA, TEST_PART_GUID);

	parsed_partition_t parts[128];
	int nparts;
	int style = drive_linux_parse_gpt(header, entries, 128 * 128, parts, &nparts);

	CHECK_INT_EQ(style, PARTITION_STYLE_GPT);
	CHECK_INT_EQ(nparts, 1);
	CHECK(parts[0].offset == (uint64_t)2048 * 512);
	CHECK(parts[0].size   == (uint64_t)204800 * 512);
	/* Type GUID should be copied */
	CHECK(memcmp(parts[0].type_guid, GUID_BASIC_DATA, 16) == 0);
}

TEST(parse_gpt_bad_signature)
{
	uint64_t total_sectors = 2048;
	uint8_t header[512];
	uint8_t entries[128 * 128];
	build_gpt(header, entries, total_sectors, 34, 100, GUID_BASIC_DATA, TEST_PART_GUID);
	/* Corrupt signature */
	header[0] = 0xFF;

	parsed_partition_t parts[128];
	int nparts;
	int style = drive_linux_parse_gpt(header, entries, 128 * 128, parts, &nparts);

	CHECK(style != PARTITION_STYLE_GPT);
}

TEST(parse_gpt_empty_entries)
{
	uint64_t total_sectors = 4096;
	uint8_t header[512];
	uint8_t entries[128 * 128];
	memset(entries, 0, sizeof(entries));

	/* Build header without any partitions */
	build_gpt(header, entries, total_sectors, 0, 0, GUID_BASIC_DATA, TEST_PART_GUID);
	/* Override the one entry with zeros — type GUID = 0 means empty */
	memset(entries, 0, 128);
	/* Recompute entries CRC */
	uint32_t ec = crc32(entries, 128 * 128);
	header[88] = ec & 0xFF;
	header[89] = (ec >> 8) & 0xFF;
	header[90] = (ec >> 16) & 0xFF;
	header[91] = (ec >> 24) & 0xFF;
	/* Recompute header CRC */
	uint8_t tmp[92];
	memcpy(tmp, header, 92);
	tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
	uint32_t hc = crc32(tmp, 92);
	header[16] = hc & 0xFF;
	header[17] = (hc >> 8) & 0xFF;
	header[18] = (hc >> 16) & 0xFF;
	header[19] = (hc >> 24) & 0xFF;

	parsed_partition_t parts[128];
	int nparts;
	int style = drive_linux_parse_gpt(header, entries, 128 * 128, parts, &nparts);

	CHECK_INT_EQ(style, PARTITION_STYLE_GPT);
	CHECK_INT_EQ(nparts, 0);
}

/* =========================================================================
 * 7. GetDrivePartitionData (end-to-end)
 * ====================================================================== */

TEST(get_drive_partition_data_mbr)
{
	/* Create a 64 MB temp image with an MBR partition table */
	char path[64];
	int fd = make_temp_file(path, 64 * 1024 * 1024ULL);
	CHECK(fd >= 0);

	/* Write a valid MBR with one partition */
	uint8_t sector[512];
	mbr_part_spec_t p = { 0x80, 0x0C, 2048, 65536 };
	build_mbr(sector, &p, 1);
	pwrite(fd, sector, 512, 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "Test", "64 MB", 64*1024*1024ULL);

	/* Reset SelectedDrive */
	memset(&SelectedDrive, 0, sizeof(SelectedDrive));

	char fs_name[64] = "";
	BOOL ok = GetDrivePartitionData(DRIVE_INDEX_MIN, fs_name, sizeof(fs_name), TRUE);
	CHECK(ok != FALSE);
	CHECK_INT_EQ(SelectedDrive.PartitionStyle, PARTITION_STYLE_MBR);
	CHECK(SelectedDrive.nPartitions >= 1);
	CHECK(SelectedDrive.Partition[0].Offset == (uint64_t)2048 * 512);
	CHECK(SelectedDrive.DiskSize > 0);

	unlink(path);
}

TEST(get_drive_partition_data_gpt)
{
	char path[64];
	uint64_t total_sectors = 2 * 1024 * 2;  /* 2 MB = 4096 sectors */
	int fd = make_temp_file(path, total_sectors * 512);
	CHECK(fd >= 0);

	/* Write protective MBR */
	uint8_t mbr[512];
	mbr_part_spec_t pm = { 0x00, 0xEE, 1, (uint32_t)(total_sectors - 1) };
	build_mbr(mbr, &pm, 1);
	pwrite(fd, mbr, 512, 0);

	/* Write GPT header + entries */
	uint8_t header[512];
	uint8_t entries[128 * 128];
	build_gpt(header, entries, total_sectors,
	          34, total_sectors - 34, GUID_BASIC_DATA, TEST_PART_GUID);
	pwrite(fd, header,  512,     512);       /* sector 1 */
	pwrite(fd, entries, 128*128, 1024);      /* sectors 2-33 */
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "GPT Test", "2 MB GPT", total_sectors * 512);

	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	char fs_name[64] = "";
	BOOL ok = GetDrivePartitionData(DRIVE_INDEX_MIN, fs_name, sizeof(fs_name), TRUE);
	CHECK(ok != FALSE);
	CHECK_INT_EQ(SelectedDrive.PartitionStyle, PARTITION_STYLE_GPT);
	CHECK(SelectedDrive.nPartitions >= 1);
	CHECK(SelectedDrive.DiskSize > 0);

	unlink(path);
}

TEST(get_drive_partition_data_raw)
{
	char path[64];
	int fd = make_temp_file(path, 1024 * 1024);
	CHECK(fd >= 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "RAW", "1 MB RAW", 1024*1024ULL);

	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	char fs_name[64] = "";
	/* Should succeed but report 0 partitions and RAW style */
	GetDrivePartitionData(DRIVE_INDEX_MIN, fs_name, sizeof(fs_name), TRUE);
	CHECK_INT_EQ(SelectedDrive.PartitionStyle, PARTITION_STYLE_RAW);
	CHECK_INT_EQ(SelectedDrive.nPartitions, 0);

	unlink(path);
}

/* =========================================================================
 * 8. InitializeDisk
 * ====================================================================== */

TEST(initialize_disk_zeroes_first_sector)
{
	char path[64];
	int fd = make_temp_file(path, 64 * 1024);
	CHECK(fd >= 0);

	/* Write a valid MBR first */
	uint8_t sector[512];
	mbr_part_spec_t p = { 0x80, 0x0C, 2048, 65536 };
	build_mbr(sector, &p, 1);
	pwrite(fd, sector, 512, 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "T", "T", 64*1024ULL);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);

	BOOL ok = InitializeDisk(h);
	CHECK(ok != FALSE);

	/* First sector should now be zeroed at the MBR signature offset */
	uint8_t readback[512];
	int rfd = open(path, O_RDONLY);
	pread(rfd, readback, 512, 0);
	close(rfd);

	/* The 0x55AA signature must be gone */
	CHECK(!(readback[510] == 0x55 && readback[511] == 0xAA));

	CloseHandle(h);
	unlink(path);
}

TEST(initialize_disk_invalid_handle)
{
	BOOL ok = InitializeDisk(INVALID_HANDLE_VALUE);
	CHECK(ok == FALSE);
}

/* =========================================================================
 * 9. CreatePartition — MBR
 * ====================================================================== */

TEST(create_partition_mbr_fat32)
{
	char path[64];
	uint64_t disk_size = 64 * 1024 * 1024ULL;
	int fd = make_temp_file(path, disk_size);
	CHECK(fd >= 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "T", "T", disk_size);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);

	/* Set up SelectedDrive */
	SelectedDrive.DiskSize   = (LONGLONG)disk_size;
	SelectedDrive.SectorSize = 512;
	SelectedDrive.DeviceNumber = DRIVE_INDEX_MIN;

	BOOL ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_FAT32, FALSE, 0);
	CHECK(ok != FALSE);

	/* Read back and verify MBR signature */
	uint8_t sector[512];
	int rfd = open(path, O_RDONLY);
	pread(rfd, sector, 512, 0);
	close(rfd);

	CHECK_INT_EQ(sector[510], 0x55);
	CHECK_INT_EQ(sector[511], 0xAA);

	/* At least one non-empty partition entry */
	int found = 0;
	for (int i = 0; i < 4; i++) {
		const uint8_t *e = sector + 446 + i * 16;
		uint32_t lba_size = e[12] | (e[13]<<8) | (e[14]<<16) | (e[15]<<24);
		if (lba_size > 0) found = 1;
	}
	CHECK(found);

	CloseHandle(h);
	unlink(path);
}

TEST(create_partition_mbr_with_uefi_marker)
{
	char path[64];
	uint64_t disk_size = 64 * 1024 * 1024ULL;
	int fd = make_temp_file(path, disk_size);
	CHECK(fd >= 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "T", "T", disk_size);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);

	SelectedDrive.DiskSize   = (LONGLONG)disk_size;
	SelectedDrive.SectorSize = 512;
	SelectedDrive.DeviceNumber = DRIVE_INDEX_MIN;

	BOOL ok = CreatePartition(h, PARTITION_STYLE_MBR, FS_FAT32, TRUE, 0);
	CHECK(ok != FALSE);

	CloseHandle(h);
	unlink(path);
}

TEST(create_partition_invalid_handle)
{
	SelectedDrive.DiskSize   = 64 * 1024 * 1024LL;
	SelectedDrive.SectorSize = 512;
	BOOL ok = CreatePartition(INVALID_HANDLE_VALUE, PARTITION_STYLE_MBR, FS_FAT32, FALSE, 0);
	CHECK(ok == FALSE);
}

/* =========================================================================
 * 10. CreatePartition — GPT
 * ====================================================================== */

TEST(create_partition_gpt)
{
	char path[64];
	uint64_t disk_size = 64 * 1024 * 1024ULL;
	int fd = make_temp_file(path, disk_size);
	CHECK(fd >= 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "T", "T", disk_size);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);

	SelectedDrive.DiskSize   = (LONGLONG)disk_size;
	SelectedDrive.SectorSize = 512;
	SelectedDrive.DeviceNumber = DRIVE_INDEX_MIN;

	BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_NTFS, FALSE, 0);
	CHECK(ok != FALSE);

	/* Read back GPT header at sector 1 (byte 512) */
	uint8_t header[512];
	int rfd = open(path, O_RDONLY);
	pread(rfd, header, 512, 512);
	close(rfd);

	/* Verify GPT signature */
	CHECK(memcmp(header, "EFI PART", 8) == 0);

	CloseHandle(h);
	unlink(path);
}

TEST(create_partition_gpt_verifies_crc)
{
	char path[64];
	uint64_t disk_size = 64 * 1024 * 1024ULL;
	int fd = make_temp_file(path, disk_size);
	CHECK(fd >= 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "T", "T", disk_size);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);

	SelectedDrive.DiskSize   = (LONGLONG)disk_size;
	SelectedDrive.SectorSize = 512;
	SelectedDrive.DeviceNumber = DRIVE_INDEX_MIN;

	BOOL ok = CreatePartition(h, PARTITION_STYLE_GPT, FS_FAT32, FALSE, 0);
	CHECK(ok != FALSE);

	/* Read back and verify header CRC ourselves */
	uint8_t header[512];
	int rfd = open(path, O_RDONLY);
	pread(rfd, header, 512, 512);
	close(rfd);

	uint8_t tmp[92];
	memcpy(tmp, header, 92);
	uint32_t stored_crc = tmp[16] | (tmp[17]<<8) | (tmp[18]<<16) | (tmp[19]<<24);
	tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
	uint32_t computed_crc = crc32(tmp, 92);
	CHECK_INT_EQ((int)stored_crc, (int)computed_crc);

	CloseHandle(h);
	unlink(path);
}

/* =========================================================================
 * 11. RefreshDriveLayout
 * ====================================================================== */

TEST(refresh_drive_layout_regular_file)
{
	/* On a regular file, BLKRRPART ioctl will fail; RefreshDriveLayout
	 * should return gracefully (either TRUE or FALSE — not crash). */
	char path[64];
	int fd = make_temp_file(path, 4096);
	CHECK(fd >= 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "T", "T", 4096);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);

	/* Must not crash */
	RefreshDriveLayout(h);

	CloseHandle(h);
	unlink(path);
}

TEST(refresh_drive_layout_invalid_handle)
{
	/* Must not crash or assert */
	BOOL r = RefreshDriveLayout(INVALID_HANDLE_VALUE);
	CHECK(r == FALSE);
}

/* =========================================================================
 * 12. GetLogicalName (fake sysfs)
 * ====================================================================== */

TEST(get_logical_name_finds_partition)
{
	/* Build a fake sysfs tree:
	 *   /tmp/rufus_sysfs_test/block/sdb/sdb1/
	 *     start  => "2048\n"
	 *     size   => "204800\n"
	 *   /tmp/rufus_devfs_test/sdb1  (exists) */
	char sysfs[64], devfs[64];
	snprintf(sysfs, sizeof(sysfs), "/tmp/rufus_sysfs_%d", (int)getpid());
	snprintf(devfs, sizeof(devfs), "/tmp/rufus_devfs_%d", (int)getpid());

	char block_sdb[128], sdb1[128], dev_node[128];
	snprintf(block_sdb, sizeof(block_sdb), "%s/block/sdb",      sysfs);
	snprintf(sdb1,      sizeof(sdb1),      "%s/block/sdb/sdb1", sysfs);

	/* Create directories */
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "mkdir -p '%s' '%s'", sdb1, devfs);
	system(cmd);

	/* Write start and size */
	FILE *f;
	char attr[256];
	snprintf(attr, sizeof(attr), "%s/start", sdb1);
	f = fopen(attr, "w"); fputs("2048\n", f); fclose(f);
	snprintf(attr, sizeof(attr), "%s/size", sdb1);
	f = fopen(attr, "w"); fputs("204800\n", f); fclose(f);

	/* Create the device node as a regular file */
	snprintf(dev_node, sizeof(dev_node), "%s/sdb1", devfs);
	f = fopen(dev_node, "w"); fclose(f);

	/* Fake the drive entry */
	char drv_path[128];
	snprintf(drv_path, sizeof(drv_path), "%s/sdb", devfs);
	f = fopen(drv_path, "w"); fclose(f);

	drive_linux_reset_drives();
	drive_linux_add_drive(drv_path, "Test", "200 MB Test", 200*1024*1024ULL);

	char *name = GetLogicalNameWithRoot(DRIVE_INDEX_MIN,
	                                    (uint64_t)2048 * 512, /* offset */
	                                    FALSE, TRUE,
	                                    sysfs, devfs);
	CHECK(name != NULL);
	if (name) {
		/* Should contain "sdb1" */
		CHECK(strstr(name, "sdb1") != NULL);
		safe_free(name);
	}

	/* Cleanup */
	snprintf(cmd, sizeof(cmd), "rm -rf '%s' '%s'", sysfs, devfs);
	system(cmd);
}

TEST(get_logical_name_no_match)
{
	char sysfs[64], devfs[64];
	snprintf(sysfs, sizeof(sysfs), "/tmp/rufus_sysfs2_%d", (int)getpid());
	snprintf(devfs, sizeof(devfs), "/tmp/rufus_devfs2_%d", (int)getpid());

	char sdb1[128];
	snprintf(sdb1, sizeof(sdb1), "%s/block/sdb/sdb1", sysfs);
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "mkdir -p '%s' '%s'", sdb1, devfs);
	system(cmd);

	FILE *f;
	char attr[256];
	snprintf(attr, sizeof(attr), "%s/start", sdb1);
	f = fopen(attr, "w"); fputs("2048\n", f); fclose(f);
	snprintf(attr, sizeof(attr), "%s/size", sdb1);
	f = fopen(attr, "w"); fputs("204800\n", f); fclose(f);

	/* No device node */
	char drv_path[128];
	snprintf(drv_path, sizeof(drv_path), "%s/sdb", devfs);
	f = fopen(drv_path, "w"); fclose(f);

	drive_linux_reset_drives();
	drive_linux_add_drive(drv_path, "Test", "200 MB", 200*1024*1024ULL);

	/* Ask for an offset that doesn't match */
	char *name = GetLogicalNameWithRoot(DRIVE_INDEX_MIN,
	                                    (uint64_t)99999 * 512,
	                                    FALSE, TRUE,
	                                    sysfs, devfs);
	CHECK(name == NULL);

	snprintf(cmd, sizeof(cmd), "rm -rf '%s' '%s'", sysfs, devfs);
	system(cmd);
}

/* =========================================================================
 * 13. UnmountVolume — graceful on non-block handles
 * ====================================================================== */

TEST(unmount_volume_invalid_handle)
{
	/* Must not crash */
	BOOL r = UnmountVolume(INVALID_HANDLE_VALUE);
	/* May return FALSE on a regular file; must not crash */
	(void)r;
}

TEST(unmount_volume_regular_file)
{
	char path[64];
	int fd = make_temp_file(path, 4096);
	CHECK(fd >= 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "T", "T", 4096);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);

	/* Must not crash; expected FALSE because not a block device */
	UnmountVolume(h);

	CloseHandle(h);
	unlink(path);
}

/* =========================================================================
 * 14. AltUnmountVolume
 * ====================================================================== */

TEST(alt_unmount_volume_null_path)
{
	/* Must not crash */
	AltUnmountVolume(NULL, TRUE);
}

TEST(alt_unmount_volume_nonexistent_path)
{
	/* Must not crash */
	AltUnmountVolume("/no/such/device/xyz99", TRUE);
}

/* =========================================================================
 * 15. GetDriveNumber
 * ====================================================================== */

TEST(get_drive_number_from_handle)
{
	char path[64];
	int fd = make_temp_file(path, 4096);
	CHECK(fd >= 0);
	close(fd);

	drive_linux_reset_drives();
	drive_linux_add_drive(path, "T", "T", 4096);

	HANDLE h = GetPhysicalHandle(DRIVE_INDEX_MIN, FALSE, TRUE, FALSE);
	CHECK(h != INVALID_HANDLE_VALUE);

	int n = GetDriveNumber(h, path);
	/* For a non-block-device file, may return -1; must not crash */
	(void)n;

	CloseHandle(h);
	unlink(path);
}

/* =========================================================================
 * Main
 * ====================================================================== */

int main(void)
{
	printf("=== drive_linux tests ===\n");

	/* GetPhysicalName */
	RUN_TEST(get_physical_name_valid);
	RUN_TEST(get_physical_name_out_of_range);
	RUN_TEST(get_physical_name_second_drive);

	/* GetPhysicalHandle */
	RUN_TEST(get_physical_handle_valid_file);
	RUN_TEST(get_physical_handle_nonexistent);
	RUN_TEST(get_physical_handle_invalid_index);
	RUN_TEST(get_physical_handle_readonly);

	/* GetDriveSize */
	RUN_TEST(get_drive_size_regular_file);
	RUN_TEST(get_drive_size_zero_for_missing);
	RUN_TEST(get_drive_size_invalid_index);

	/* IsMediaPresent */
	RUN_TEST(is_media_present_existing_file);
	RUN_TEST(is_media_present_missing_file);
	RUN_TEST(is_media_present_invalid_index);

	/* MBR parsing */
	RUN_TEST(parse_mbr_single_partition);
	RUN_TEST(parse_mbr_four_partitions);
	RUN_TEST(parse_mbr_empty_table);
	RUN_TEST(parse_mbr_bad_signature_is_raw);
	RUN_TEST(parse_mbr_skips_zero_type_entries);

	/* GPT parsing */
	RUN_TEST(parse_gpt_single_partition);
	RUN_TEST(parse_gpt_bad_signature);
	RUN_TEST(parse_gpt_empty_entries);

	/* GetDrivePartitionData */
	RUN_TEST(get_drive_partition_data_mbr);
	RUN_TEST(get_drive_partition_data_gpt);
	RUN_TEST(get_drive_partition_data_raw);

	/* InitializeDisk */
	RUN_TEST(initialize_disk_zeroes_first_sector);
	RUN_TEST(initialize_disk_invalid_handle);

	/* CreatePartition MBR */
	RUN_TEST(create_partition_mbr_fat32);
	RUN_TEST(create_partition_mbr_with_uefi_marker);
	RUN_TEST(create_partition_invalid_handle);

	/* CreatePartition GPT */
	RUN_TEST(create_partition_gpt);
	RUN_TEST(create_partition_gpt_verifies_crc);

	/* RefreshDriveLayout */
	RUN_TEST(refresh_drive_layout_regular_file);
	RUN_TEST(refresh_drive_layout_invalid_handle);

	/* GetLogicalName */
	RUN_TEST(get_logical_name_finds_partition);
	RUN_TEST(get_logical_name_no_match);

	/* UnmountVolume */
	RUN_TEST(unmount_volume_invalid_handle);
	RUN_TEST(unmount_volume_regular_file);

	/* AltUnmountVolume */
	RUN_TEST(alt_unmount_volume_null_path);
	RUN_TEST(alt_unmount_volume_nonexistent_path);

	/* GetDriveNumber */
	RUN_TEST(get_drive_number_from_handle);

	PRINT_RESULTS();
	return (g_failed == 0) ? 0 : 1;
}
