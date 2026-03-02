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

/* uprintf stub: common/stdfn.c calls uprintf for hash-table diagnostics */
void uprintf(const char *format, ...) { (void)format; }

/* Instantiate CompareGUID */
#include "../src/common/stdfn.c"

/* Instantiate GuidToString */
#include "../src/common/stdio.c"
