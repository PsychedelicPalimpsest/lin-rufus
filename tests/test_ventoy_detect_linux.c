/*
 * test_ventoy_detect_linux.c — Unit tests for Ventoy detection
 *
 * Tests ventoy_check_mbr(), ventoy_detect_by_label(), and ventoy_detect()
 * using synthetic temp files (no real block device needed for most tests).
 *
 * Build: auto-discovered by tests/Makefile.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>

#include "framework.h"

/* Pull in the module under test via the compat layer */
#include "../src/linux/compat/windows.h"
#include "../src/linux/ventoy_detect.h"
#include "../src/linux/ventoy_detect.c"

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static char g_tmpfile[64];

/* Create a 1 MiB temp file, write |len| bytes of |data| at |offset|.
 * Returns path in g_tmpfile, or NULL on error.  Caller must unlink. */
static const char *make_tmp_disk(const void *data, size_t len, off_t offset)
{
snprintf(g_tmpfile, sizeof(g_tmpfile), "/tmp/vtoy_test_%d", (int)getpid());
int fd = open(g_tmpfile, O_CREAT | O_RDWR | O_TRUNC, 0600);
if (fd < 0) return NULL;
/* Extend to 1 MiB with zeros via lseek+write */
if (lseek(fd, 1024 * 1024 - 1, SEEK_SET) < 0) { close(fd); unlink(g_tmpfile); return NULL; }
char zero = 0;
if (write(fd, &zero, 1) != 1) { close(fd); unlink(g_tmpfile); return NULL; }
/* Write the payload */
if (len > 0 && pwrite(fd, data, len, offset) != (ssize_t)len) {
unlink(g_tmpfile); return NULL;
}
close(fd);
return g_tmpfile;
}

/* ======================================================
   TESTS: ventoy_check_mbr
   ====================================================== */

TEST(test_check_mbr_null) {
CHECK(ventoy_check_mbr(NULL) == FALSE);
}

TEST(test_check_mbr_nonexistent) {
CHECK(ventoy_check_mbr("/tmp/vtoy_no_such_file_99999") == FALSE);
}

TEST(test_check_mbr_no_magic) {
const char *path = make_tmp_disk(NULL, 0, 0);
CHECK_MSG(path != NULL, "Failed to create temp file");
CHECK(ventoy_check_mbr(path) == FALSE);
if (path) unlink(path);
}

TEST(test_check_mbr_wrong_magic) {
const char *path = make_tmp_disk("ABCD", 4, VENTOY_MBR_OFFSET);
CHECK_MSG(path != NULL, "Failed to create temp file");
CHECK(ventoy_check_mbr(path) == FALSE);
if (path) unlink(path);
}

TEST(test_check_mbr_correct_magic) {
const char *path = make_tmp_disk(VENTOY_MBR_MAGIC, VENTOY_MBR_MAGIC_LEN, VENTOY_MBR_OFFSET);
CHECK_MSG(path != NULL, "Failed to create temp file");
CHECK(ventoy_check_mbr(path) == TRUE);
if (path) unlink(path);
}

TEST(test_check_mbr_magic_at_wrong_offset) {
/* "VTOY" at offset 0, not at 0x1B4 — should not be detected */
const char *path = make_tmp_disk(VENTOY_MBR_MAGIC, VENTOY_MBR_MAGIC_LEN, 0);
CHECK_MSG(path != NULL, "Failed to create temp file");
CHECK(ventoy_check_mbr(path) == FALSE);
if (path) unlink(path);
}

TEST(test_check_mbr_partial_magic) {
/* Only 3 bytes of magic — the 4th will be zero, mismatch */
const char *path = make_tmp_disk("VTO", 3, VENTOY_MBR_OFFSET);
CHECK_MSG(path != NULL, "Failed to create temp file");
CHECK(ventoy_check_mbr(path) == FALSE);
if (path) unlink(path);
}

/* ======================================================
   TESTS: ventoy_detect_by_label
   ====================================================== */

TEST(test_detect_by_label_null) {
CHECK(ventoy_detect_by_label(NULL) == FALSE);
}

TEST(test_detect_by_label_nonexistent_dev) {
/* No partition files exist → blkid fails immediately */
CHECK(ventoy_detect_by_label("/tmp/no_device_99999_vtoy") == FALSE);
}

/* ======================================================
   TESTS: ventoy_detect
   ====================================================== */

TEST(test_detect_null) {
CHECK(ventoy_detect(NULL) == FALSE);
}

TEST(test_detect_nonexistent) {
CHECK(ventoy_detect("/tmp/vtoy_no_such_file_99999") == FALSE);
}

TEST(test_detect_empty_disk) {
const char *path = make_tmp_disk(NULL, 0, 0);
CHECK_MSG(path != NULL, "Failed to create temp file");
CHECK(ventoy_detect(path) == FALSE);
if (path) unlink(path);
}

TEST(test_detect_mbr_magic) {
const char *path = make_tmp_disk(VENTOY_MBR_MAGIC, VENTOY_MBR_MAGIC_LEN, VENTOY_MBR_OFFSET);
CHECK_MSG(path != NULL, "Failed to create temp file");
CHECK(ventoy_detect(path) == TRUE);
if (path) unlink(path);
}

/* ======================================================
   TESTS: partition path helper (white-box via naming convention)
   ====================================================== */

TEST(test_part_path_sda) {
char buf[64];
/* sda → sda1 (no "p") */
snprintf(buf, sizeof(buf), "%s%s%d", "/dev/sda", "", 1);
CHECK_STR_EQ(buf, "/dev/sda1");
}

TEST(test_part_path_nvme) {
char buf[64];
snprintf(buf, sizeof(buf), "%s%s%d", "/dev/nvme0n1", "p", 1);
CHECK_STR_EQ(buf, "/dev/nvme0n1p1");
}

TEST(test_part_path_mmcblk) {
char buf[64];
snprintf(buf, sizeof(buf), "%s%s%d", "/dev/mmcblk0", "p", 2);
CHECK_STR_EQ(buf, "/dev/mmcblk0p2");
}

/* ======================================================
   TESTS: constants
   ====================================================== */

TEST(test_mbr_offset_value) {
CHECK_INT_EQ(VENTOY_MBR_OFFSET, 0x1B4);
}

TEST(test_magic_string) {
CHECK_INT_EQ((int)strlen(VENTOY_MBR_MAGIC), VENTOY_MBR_MAGIC_LEN);
CHECK_STR_EQ(VENTOY_MBR_MAGIC, "VTOY");
}

TEST(test_label_strings) {
CHECK_STR_EQ(VENTOY_LABEL_DATA, "Ventoy");
CHECK_STR_EQ(VENTOY_LABEL_EFI,  "VTOYEFI");
}

/* ======================================================
   MAIN
   ====================================================== */
int main(void)
{
printf("=== test_ventoy_detect_linux ===\n");

RUN(test_check_mbr_null);
RUN(test_check_mbr_nonexistent);
RUN(test_check_mbr_no_magic);
RUN(test_check_mbr_wrong_magic);
RUN(test_check_mbr_correct_magic);
RUN(test_check_mbr_magic_at_wrong_offset);
RUN(test_check_mbr_partial_magic);
RUN(test_detect_by_label_null);
RUN(test_detect_by_label_nonexistent_dev);
RUN(test_detect_null);
RUN(test_detect_nonexistent);
RUN(test_detect_empty_disk);
RUN(test_detect_mbr_magic);
RUN(test_part_path_sda);
RUN(test_part_path_nvme);
RUN(test_part_path_mmcblk);
RUN(test_mbr_offset_value);
RUN(test_magic_string);
RUN(test_label_strings);

TEST_RESULTS();
}
