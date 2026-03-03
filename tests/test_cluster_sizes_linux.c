/*
 * test_cluster_sizes_linux.c — Unit tests for ComputeClusterSizes()
 * and SetClusterSizeLabels() on Linux.
 *
 * Tests cover:
 *  1. ComputeClusterSizes — FAT16 allowed/default per disk size
 *  2. ComputeClusterSizes — FAT32 allowed/default per disk size
 *  3. ComputeClusterSizes — NTFS allowed/default per disk size
 *  4. ComputeClusterSizes — exFAT allowed/default per disk size
 *  5. ComputeClusterSizes — UDF and ext2/3 with advanced_mode_format
 *  6. ComputeClusterSizes — clears previous data
 *  7. SetClusterSizeLabels — initialises ClusterSizeLabel[]
 */

#include "framework.h"

#include "../src/linux/drive_linux.h"
#include "../src/windows/rufus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── globals needed by the compilation units ─────────────────────────── */
extern RUFUS_DRIVE_INFO SelectedDrive;
extern int advanced_mode_format;
extern char ClusterSizeLabel[MAX_CLUSTER_SIZES][64];

/* ── helper: set disk size and call ComputeClusterSizes ─────────────────*/
static void setup(uint64_t disk_size)
{
	memset(&SelectedDrive, 0, sizeof(SelectedDrive));
	SelectedDrive.DiskSize   = (LONGLONG)disk_size;
	SelectedDrive.SectorSize = 512;
	ComputeClusterSizes();
}

/* ═══════════════════════════════════════════════════════════════════════
 * Group 1: FAT16
 * ═══════════════════════════════════════════════════════════════════════ */

/* A 128 MB drive is within the FAT16 range (< 4 GB) */
TEST(fat16_128mb_allowed_nonzero)
{
	setup(128 * MB);
	CHECK(SelectedDrive.ClusterSize[FS_FAT16].Allowed != 0);
}

TEST(fat16_128mb_default_nonzero)
{
	setup(128 * MB);
	CHECK(SelectedDrive.ClusterSize[FS_FAT16].Default != 0);
}

/* A 3.9 GB drive is still within the FAT16 range */
TEST(fat16_3_9gb_allowed_nonzero)
{
	setup((uint64_t)(3.9 * GB));
	CHECK(SelectedDrive.ClusterSize[FS_FAT16].Allowed != 0);
}

/* A 5 GB drive is above the 4 GB FAT16 ceiling — not allowed */
TEST(fat16_5gb_not_allowed)
{
	setup(5ULL * GB);
	CHECK_INT_EQ(0, (int)SelectedDrive.ClusterSize[FS_FAT16].Allowed);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Group 2: FAT32
 * ═══════════════════════════════════════════════════════════════════════ */

/* 64 MB is well above the threshold where FAT32 cluster sizes are valid
 * (exactly 32 MB hits the FAT32_CLUSTER_THRESHOLD and gives Allowed=0 after masking) */
TEST(fat32_32mb_allowed_nonzero)
{
	setup(64 * MB);
	CHECK(SelectedDrive.ClusterSize[FS_FAT32].Allowed != 0);
}

/* Below 32 MB — FAT32 not allowed */
TEST(fat32_16mb_not_allowed)
{
	setup(16 * MB);
	CHECK_INT_EQ(0, (int)SelectedDrive.ClusterSize[FS_FAT32].Allowed);
}

/* A 512 MB drive — FAT32 allowed and default set */
TEST(fat32_512mb_allowed_and_default)
{
	setup(512 * MB);
	CHECK(SelectedDrive.ClusterSize[FS_FAT32].Allowed != 0);
	CHECK(SelectedDrive.ClusterSize[FS_FAT32].Default != 0);
}

/* A 2.1 TB drive is beyond MAX_FAT32_SIZE (2 TB) — FAT32 not allowed */
TEST(fat32_2_1tb_not_allowed)
{
	setup((uint64_t)(2.1 * TB));
	CHECK_INT_EQ(0, (int)SelectedDrive.ClusterSize[FS_FAT32].Allowed);
}

/* A 1 GB drive — default should be 4 KB (per MS spec: 256 MB–8 GB → 4 KB) */
TEST(fat32_1gb_default_4kb)
{
	setup(1 * GB);
	CHECK_INT_EQ(4096, (int)SelectedDrive.ClusterSize[FS_FAT32].Default);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Group 3: NTFS
 * ═══════════════════════════════════════════════════════════════════════ */

/* NTFS is supported for drives < 256 TB */
TEST(ntfs_512mb_allowed_nonzero)
{
	setup(512 * MB);
	CHECK(SelectedDrive.ClusterSize[FS_NTFS].Allowed != 0);
}

TEST(ntfs_512mb_default_nonzero)
{
	setup(512 * MB);
	CHECK(SelectedDrive.ClusterSize[FS_NTFS].Default != 0);
}

/* For a 512 MB drive, NTFS default should be 4 KB (< 16 TB range) */
TEST(ntfs_512mb_default_4kb)
{
	setup(512 * MB);
	CHECK_INT_EQ(4096, (int)SelectedDrive.ClusterSize[FS_NTFS].Default);
}

/* An 8 TB drive — NTFS default is larger */
TEST(ntfs_8tb_default_nonzero)
{
	setup(8ULL * TB);
	CHECK(SelectedDrive.ClusterSize[FS_NTFS].Default != 0);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Group 4: exFAT
 * ═══════════════════════════════════════════════════════════════════════ */

/* exFAT allowed for < 256 TB drives */
TEST(exfat_allowed_nonzero)
{
	setup(512 * MB);
	CHECK(SelectedDrive.ClusterSize[FS_EXFAT].Allowed != 0);
}

/* < 256 MB → exFAT default = 4 KB */
TEST(exfat_128mb_default_4kb)
{
	setup(128 * MB);
	CHECK_INT_EQ(4 * 1024, (int)SelectedDrive.ClusterSize[FS_EXFAT].Default);
}

/* 256 MB – 32 GB → exFAT default = 32 KB */
TEST(exfat_8gb_default_32kb)
{
	setup(8ULL * GB);
	CHECK_INT_EQ(32 * 1024, (int)SelectedDrive.ClusterSize[FS_EXFAT].Default);
}

/* >= 32 GB → exFAT default = 128 KB */
TEST(exfat_64gb_default_128kb)
{
	setup(64ULL * GB);
	CHECK_INT_EQ(128 * 1024, (int)SelectedDrive.ClusterSize[FS_EXFAT].Default);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Group 5: UDF and ext2/3
 * ═══════════════════════════════════════════════════════════════════════ */

/* UDF is always allowed for drives < 256 TB */
TEST(udf_allowed_single_default)
{
	setup(512 * MB);
	CHECK_INT_EQ(SINGLE_CLUSTERSIZE_DEFAULT,
	             (int)SelectedDrive.ClusterSize[FS_UDF].Allowed);
	CHECK_INT_EQ(1, (int)SelectedDrive.ClusterSize[FS_UDF].Default);
}

/* ext2 not allowed without advanced_mode_format */
TEST(ext2_requires_advanced_mode)
{
	advanced_mode_format = FALSE;
	setup(512 * MB);
	CHECK_INT_EQ(0, (int)SelectedDrive.ClusterSize[FS_EXT2].Allowed);
}

/* ext2 allowed when advanced_mode_format is set and size >= MIN_EXT_SIZE */
TEST(ext2_allowed_with_advanced_mode)
{
	advanced_mode_format = TRUE;
	setup(512 * MB); /* 512 MB >= 256 MB (MIN_EXT_SIZE) */
	CHECK(SelectedDrive.ClusterSize[FS_EXT2].Allowed != 0);
	advanced_mode_format = FALSE;
}

/* ext2 not allowed even with advanced_mode_format if size < MIN_EXT_SIZE */
TEST(ext2_too_small_with_advanced_mode)
{
	advanced_mode_format = TRUE;
	setup(64 * MB); /* 64 MB < 256 MB */
	CHECK_INT_EQ(0, (int)SelectedDrive.ClusterSize[FS_EXT2].Allowed);
	advanced_mode_format = FALSE;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Group 6: Clears previous data
 * ═══════════════════════════════════════════════════════════════════════ */

/* Calling ComputeClusterSizes twice gives fresh results, not accumulation */
TEST(compute_clears_previous_data)
{
	/* First call: 5 GB — FAT16 not allowed */
	setup(5ULL * GB);
	CHECK_INT_EQ(0, (int)SelectedDrive.ClusterSize[FS_FAT16].Allowed);

	/* Second call: 1 GB — FAT16 should now be allowed */
	setup(1 * GB);
	CHECK(SelectedDrive.ClusterSize[FS_FAT16].Allowed != 0);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Group 7: SetClusterSizeLabels
 * ═══════════════════════════════════════════════════════════════════════ */

TEST(set_cluster_size_labels_slot0_default)
{
	SetClusterSizeLabels();
	/* slot 0 is the "Default" label — must be non-empty */
	CHECK(ClusterSizeLabel[0][0] != '\0');
}

TEST(set_cluster_size_labels_slot1_512bytes)
{
	SetClusterSizeLabels();
	/* slot 1 = "512 bytes" (MSG_026 = "bytes", i=512) */
	CHECK(strstr(ClusterSizeLabel[1], "512") != NULL);
}

TEST(set_cluster_size_labels_has_kb_entry)
{
	SetClusterSizeLabels();
	/*
	 * At index 6 the byte counter crosses 8192 and is divided by 1024,
	 * so the label starts with "16 " rather than "16384 ".
	 * This verifies that the i /= 1024 branch in SetClusterSizeLabels ran.
	 */
	CHECK(strstr(ClusterSizeLabel[6], "16384") == NULL);
	CHECK(strncmp(ClusterSizeLabel[6], "16 ", 3) == 0);
}

int main(void)
{
	/* FAT16 */
	RUN(fat16_128mb_allowed_nonzero);
	RUN(fat16_128mb_default_nonzero);
	RUN(fat16_3_9gb_allowed_nonzero);
	RUN(fat16_5gb_not_allowed);
	/* FAT32 */
	RUN(fat32_32mb_allowed_nonzero);
	RUN(fat32_16mb_not_allowed);
	RUN(fat32_512mb_allowed_and_default);
	RUN(fat32_2_1tb_not_allowed);
	RUN(fat32_1gb_default_4kb);
	/* NTFS */
	RUN(ntfs_512mb_allowed_nonzero);
	RUN(ntfs_512mb_default_nonzero);
	RUN(ntfs_512mb_default_4kb);
	RUN(ntfs_8tb_default_nonzero);
	/* exFAT */
	RUN(exfat_allowed_nonzero);
	RUN(exfat_128mb_default_4kb);
	RUN(exfat_8gb_default_32kb);
	RUN(exfat_64gb_default_128kb);
	/* UDF + ext */
	RUN(udf_allowed_single_default);
	RUN(ext2_requires_advanced_mode);
	RUN(ext2_allowed_with_advanced_mode);
	RUN(ext2_too_small_with_advanced_mode);
	/* Clears previous */
	RUN(compute_clears_previous_data);
	/* SetClusterSizeLabels */
	RUN(set_cluster_size_labels_slot0_default);
	RUN(set_cluster_size_labels_slot1_512bytes);
	RUN(set_cluster_size_labels_has_kb_entry);
	TEST_RESULTS();
}
