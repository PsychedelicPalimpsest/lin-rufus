/* tests/test_ui_linux.c - Tests for version initialization and UI logic */
#include "../src/windows/rufus.h"
#include "../src/linux/version.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Minimal test harness */
static int _pass = 0, _fail = 0;
#define CHECK_MSG(cond, msg) do { \
    if (cond) { _pass++; } else { _fail++; printf("  FAIL: %s\n", msg); } \
} while(0)
#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s\n", #name); test_##name(); } while(0)
#define TEST_RESULTS() printf("\n%d passed, %d failed\n", _pass, _fail)

extern uint16_t rufus_version[3];
void init_rufus_version(void);

TEST(version_major_correct)
{
    init_rufus_version();
    CHECK_MSG(rufus_version[0] == RUFUS_LINUX_VERSION_MAJOR,
              "version[0] must match RUFUS_LINUX_VERSION_MAJOR");
}

TEST(version_minor_correct)
{
    init_rufus_version();
    CHECK_MSG(rufus_version[1] == RUFUS_LINUX_VERSION_MINOR,
              "version[1] must match RUFUS_LINUX_VERSION_MINOR");
}

TEST(version_patch_correct)
{
    init_rufus_version();
    CHECK_MSG(rufus_version[2] == RUFUS_LINUX_VERSION_PATCH,
              "version[2] must match RUFUS_LINUX_VERSION_PATCH");
}

TEST(version_nonzero)
{
    init_rufus_version();
    CHECK_MSG(rufus_version[0] > 0, "major version must be > 0");
}

TEST(version_format_string)
{
    init_rufus_version();
    char buf[16];
    snprintf(buf, sizeof(buf), "%d.%d", rufus_version[0], rufus_version[1]);
    CHECK_MSG(buf[0] != '\0', "formatted version must be non-empty");
    CHECK_MSG(strchr(buf, '.') != NULL, "formatted version must contain a dot");
}

int main(void)
{
    printf("=== version tests ===\n");
    RUN(version_major_correct);
    RUN(version_minor_correct);
    RUN(version_patch_correct);
    RUN(version_nonzero);
    RUN(version_format_string);
    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
