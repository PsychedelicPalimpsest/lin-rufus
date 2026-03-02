/*
 * Minimal glue translation unit for test_partition_types_common.
 *
 * Provides CompareGUID() and GuidToString() by including the common
 * implementations directly.  Both common/*.c files are #include-pattern
 * files (not compiled as standalone TUs) so this glue TU instantiates them.
 *
 * Cross-platform: works for both Linux native and MinGW/Wine builds.
 */

#ifdef _WIN32
/* Windows path: crtdbg triggers #include chain that needs _WIN32 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* rufus.h must be found via the per-platform include path:
 *   Linux: -I$(SRC_DIR)/linux
 *   Windows: -I$(SRC_DIR)/windows  */
#include "rufus.h"
/* common/drive.h defines RUFUS_DRIVE_INFO used by common/drive.c */
#include "../src/common/drive.h"

/* uprintf stub: common/stdfn.c calls uprintf for hash-table diagnostics */
void uprintf(const char *format, ...) { (void)format; }

/* Instantiate CompareGUID */
#include "../src/common/stdfn.c"

/* Instantiate GuidToString */
#include "../src/common/stdio.c"

/*
 * common/drive.c also contains AnalyzeMBR() / AnalyzePBR() which reference
 * ms-sys boot-record helpers and SelectedDrive.  test_partition_types_common
 * does NOT exercise those functions — only GetMBRPartitionType() and
 * GetGPTPartitionType() are tested.  Provide stub definitions so the linker
 * is satisfied without pulling in the entire ms-sys library.
 */
RUFUS_DRIVE_INFO SelectedDrive = { 0 };
void set_bytes_per_sector(unsigned long v)          { (void)v; }
int  is_br(FILE *fp)                               { (void)fp; return 0; }
int  is_dos_mbr(FILE *fp)                          { (void)fp; return 0; }
int  is_dos_f2_mbr(FILE *fp)                       { (void)fp; return 0; }
int  is_95b_mbr(FILE *fp)                          { (void)fp; return 0; }
int  is_2000_mbr(FILE *fp)                         { (void)fp; return 0; }
int  is_vista_mbr(FILE *fp)                        { (void)fp; return 0; }
int  is_win7_mbr(FILE *fp)                         { (void)fp; return 0; }
int  is_rufus_mbr(FILE *fp)                        { (void)fp; return 0; }
int  is_syslinux_mbr(FILE *fp)                     { (void)fp; return 0; }
int  is_reactos_mbr(FILE *fp)                      { (void)fp; return 0; }
int  is_kolibrios_mbr(FILE *fp)                    { (void)fp; return 0; }
int  is_grub4dos_mbr(FILE *fp)                     { (void)fp; return 0; }
int  is_grub2_mbr(FILE *fp)                        { (void)fp; return 0; }
int  is_zero_mbr_not_including_disk_signature_or_copy_protect(FILE *fp) { (void)fp; return 0; }
int  is_fat_16_br(FILE *fp)                        { (void)fp; return 0; }
int  is_fat_32_br(FILE *fp)                        { (void)fp; return 0; }
int  entire_fat_16_br_matches(FILE *fp)            { (void)fp; return 0; }
int  entire_fat_16_fd_br_matches(FILE *fp)         { (void)fp; return 0; }
int  entire_fat_16_ros_br_matches(FILE *fp)        { (void)fp; return 0; }
int  entire_fat_32_br_matches(FILE *fp)            { (void)fp; return 0; }
int  entire_fat_32_nt_br_matches(FILE *fp)         { (void)fp; return 0; }
int  entire_fat_32_fd_br_matches(FILE *fp)         { (void)fp; return 0; }
int  entire_fat_32_ros_br_matches(FILE *fp)        { (void)fp; return 0; }
int  entire_fat_32_kos_br_matches(FILE *fp)        { (void)fp; return 0; }
