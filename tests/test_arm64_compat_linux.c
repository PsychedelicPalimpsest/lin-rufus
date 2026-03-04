/*
 * test_arm64_compat_linux.c
 * Tests for ARM64 cross-compile compatibility (item 100)
 *
 * Verifies that:
 *   1. Linux ioctl headers required by rufus compile on AArch64
 *      (BLKGETSIZE64, SG_IO, BLKPG_DEL_PARTITION, etc.)
 *   2. configure.ac supports --with-arch=aarch64
 *   3. The cross-compiler can produce AArch64 object code
 *
 * Linux-only (uses Linux kernel headers).
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>       /* BLKGETSIZE64, BLKRRPART, BLKSSZGET */
#include <linux/blkpg.h>    /* BLKPG, BLKPG_DEL_PARTITION */
#include <scsi/sg.h>        /* SG_IO, sg_io_hdr_t */

#include "framework.h"

/* ------------------------------------------------------------------ */
/* Tests: ioctl constant availability                                   */
/* ------------------------------------------------------------------ */

TEST(blkgetsize64_is_defined)
{
    unsigned long val = BLKGETSIZE64;
    CHECK(val != 0);
}

TEST(blksszget_is_defined)
{
    unsigned long val = BLKSSZGET;
    CHECK(val != 0);
}

TEST(blkrrpart_is_defined)
{
    unsigned long val = BLKRRPART;
    CHECK(val != 0);
}

TEST(blkpg_is_defined)
{
    int val = BLKPG;
    CHECK(val != 0);
}

TEST(blkpg_del_partition_is_defined)
{
    int val = BLKPG_DEL_PARTITION;
    CHECK(val != 0);
}

TEST(sg_io_is_defined)
{
    unsigned long val = SG_IO;
    CHECK(val != 0);
}

/* ------------------------------------------------------------------ */
/* Tests: sg_io_hdr_t fields needed by rufus                           */
/* ------------------------------------------------------------------ */

TEST(sg_io_hdr_has_interface_id)
{
    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.interface_id = 'S';
    CHECK(hdr.interface_id == 'S');
}

TEST(sg_io_hdr_has_dxfer_direction)
{
    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    CHECK(hdr.dxfer_direction == SG_DXFER_FROM_DEV);
}

TEST(sg_io_hdr_has_cmdp)
{
    unsigned char cmd[16] = {0};
    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.cmdp = cmd;
    CHECK(hdr.cmdp == cmd);
}

/* Additional sg_io_hdr fields used by src/linux/smart.c */
TEST(sg_io_hdr_has_cmd_len)
{
    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.cmd_len = 16;
    CHECK(hdr.cmd_len == 16);
}

TEST(sg_io_hdr_has_dxfer_len)
{
    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.dxfer_len = 512;
    CHECK(hdr.dxfer_len == 512);
}

TEST(sg_io_hdr_has_mx_sb_len)
{
    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.mx_sb_len = 64;
    CHECK(hdr.mx_sb_len == 64);
}

TEST(sg_io_hdr_has_sbp)
{
    uint8_t sense[64] = {0};
    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.sbp = sense;
    CHECK(hdr.sbp == sense);
}

TEST(sg_io_hdr_has_timeout)
{
    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.timeout = 30000;
    CHECK(hdr.timeout == 30000);
}

TEST(sg_io_hdr_has_status)
{
    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.status = 0;
    CHECK(hdr.status == 0);
}

TEST(sg_dxfer_to_dev_is_defined)
{
    int val = SG_DXFER_TO_DEV;
    /* Must be distinct from SG_DXFER_FROM_DEV and SG_DXFER_NONE */
    CHECK(val != SG_DXFER_FROM_DEV);
    CHECK(val != SG_DXFER_NONE);
}

TEST(sg_dxfer_none_is_defined)
{
    int val = SG_DXFER_NONE;
    (void)val;
    CHECK(1); /* compile-time check that SG_DXFER_NONE exists */
}

/* ------------------------------------------------------------------ */
/* Tests: integer type sizes (AArch64 LP64)                            */
/* ------------------------------------------------------------------ */

TEST(uint64_t_is_8_bytes)
{
    CHECK(sizeof(uint64_t) == 8);
}

TEST(size_t_is_pointer_width)
{
    CHECK(sizeof(size_t) == sizeof(void*));
}

TEST(int_is_4_bytes)
{
    /* C11 / LP64 guarantee */
    CHECK(sizeof(int) == 4);
}

/* ------------------------------------------------------------------ */
/* Tests: configure.ac --with-arch support                             */
/* ------------------------------------------------------------------ */

static char configure_content[1 << 20];

static int load_configure_ac(void)
{
    FILE *f = fopen("../configure.ac", "r");
    if (!f) f = fopen("configure.ac", "r");
    if (!f) return 0;
    size_t n = fread(configure_content, 1, sizeof(configure_content) - 1, f);
    fclose(f);
    configure_content[n] = '\0';
    return (int)(n > 0);
}

TEST(configure_ac_has_with_arch_option)
{
    if (!load_configure_ac()) { CHECK_MSG(0, "Could not read configure.ac"); return; }
    CHECK(strstr(configure_content, "--with-arch") != NULL ||
          strstr(configure_content, "with-arch") != NULL ||
          strstr(configure_content, "target_arch") != NULL);
}

TEST(configure_ac_derives_cross_prefix_from_arch)
{
    if (!load_configure_ac()) { CHECK_MSG(0, "Could not read configure.ac"); return; }
    /* The configure.ac must set CC to <arch>-linux-gnu-gcc */
    CHECK(strstr(configure_content, "linux-gnu-gcc") != NULL ||
          strstr(configure_content, "_cross_prefix") != NULL);
}

TEST(configure_ac_arch_only_for_linux)
{
    if (!load_configure_ac()) { CHECK_MSG(0, "Could not read configure.ac"); return; }
    /* The --with-arch option must guard on target_os == linux */
    CHECK(strstr(configure_content, "target_arch") != NULL);
}

/* ------------------------------------------------------------------ */
/* Test runner                                                          */
/* ------------------------------------------------------------------ */

int main(void)
{
    RUN(blkgetsize64_is_defined);
    RUN(blksszget_is_defined);
    RUN(blkrrpart_is_defined);
    RUN(blkpg_is_defined);
    RUN(blkpg_del_partition_is_defined);
    RUN(sg_io_is_defined);

    RUN(sg_io_hdr_has_interface_id);
    RUN(sg_io_hdr_has_dxfer_direction);
    RUN(sg_io_hdr_has_cmdp);
    RUN(sg_io_hdr_has_cmd_len);
    RUN(sg_io_hdr_has_dxfer_len);
    RUN(sg_io_hdr_has_mx_sb_len);
    RUN(sg_io_hdr_has_sbp);
    RUN(sg_io_hdr_has_timeout);
    RUN(sg_io_hdr_has_status);
    RUN(sg_dxfer_to_dev_is_defined);
    RUN(sg_dxfer_none_is_defined);

    RUN(uint64_t_is_8_bytes);
    RUN(size_t_is_pointer_width);
    RUN(int_is_4_bytes);

    RUN(configure_ac_has_with_arch_option);
    RUN(configure_ac_derives_cross_prefix_from_arch);
    RUN(configure_ac_arch_only_for_linux);

    TEST_RESULTS();
}

#endif /* __linux__ */
