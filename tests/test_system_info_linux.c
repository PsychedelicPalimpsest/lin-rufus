/*
 * tests/test_system_info_linux.c
 *
 * Tests for src/linux/system_info.c:
 *   GetTPMVersion()        – detects host TPM version from /sys/class/tpm/
 *   IsSecureBootEnabled()  – reads EFI variable SecureBoot-*
 *   IsSetupModeEnabled()   – reads EFI variable SetupMode-*
 *
 * All tests use fake /sys and /sys/firmware trees via the injectable paths
 * provided by the RUFUS_TEST build of system_info.c.
 */
#define RUFUS_TEST 1

#include "framework.h"
#include "../src/linux/system_info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

/* ---------- helpers to build a minimal fake sysfs / EFI tree ----------- */

static char g_tmpdir[256];

static void cleanup_tmpdir(void)
{
    if (g_tmpdir[0])
        system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
}

/* mkdtemp-based temp tree */
static const char *make_tmpdir(void)
{
    strncpy(g_tmpdir, "/tmp/test_sysinfo_XXXXXX", sizeof(g_tmpdir) - 1);
    if (!mkdtemp(g_tmpdir)) {
        perror("mkdtemp");
        exit(1);
    }
    return g_tmpdir;
}

static void rmkdir(const char *path)
{
    /* mkdir -p equivalent: iterate and create each component */
    char buf[512];
    strncpy(buf, path, sizeof(buf) - 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(buf, 0755);
            *p = '/';
        }
    }
    mkdir(buf, 0755);
}

static void write_bytes(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    if (data && len > 0) fwrite(data, 1, len, f);
    fclose(f);
}

static void write_str(const char *path, const char *str)
{
    write_bytes(path, str, strlen(str));
}

/*
 * EFI variable layout:
 *   bytes 0-3:  UINT32 attributes (little-endian)
 *   bytes 4+:   variable data
 *
 * For SecureBoot / SetupMode, the data is a single byte:
 *   1 = enabled/active, 0 = disabled/inactive.
 */
static void write_efi_var(const char *path, uint8_t value)
{
    uint8_t buf[5];
    /* attributes: EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS */
    buf[0] = 0x06; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00;
    buf[4] = value;
    write_bytes(path, buf, sizeof(buf));
}

/* GUID used for global EFI variables (SecureBoot, SetupMode, etc.) */
#define EFI_GLOBAL_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"

#define SECUREBOOT_VAR "SecureBoot-" EFI_GLOBAL_GUID
#define SETUPMODE_VAR  "SetupMode-"  EFI_GLOBAL_GUID

/* ========================= GetTPMVersion tests ========================= */

TEST(tpm_no_sysfs_returns_0)
{
    const char *root = make_tmpdir();
    /* Don't create any TPM directory — sysfs root is just the temp dir */
    sysinfo_set_sysfs_root(root);

    int ver = GetTPMVersion();
    CHECK_INT_EQ(0, ver);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(tpm_version_file_absent_returns_0)
{
    const char *root = make_tmpdir();
    char tpmdir[512];
    snprintf(tpmdir, sizeof(tpmdir), "%s/class/tpm/tpm0", root);
    rmkdir(tpmdir);
    /* Directory exists but tpm_version_major file is absent */
    sysinfo_set_sysfs_root(root);

    int ver = GetTPMVersion();
    CHECK_INT_EQ(0, ver);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(tpm_version_1_returns_1)
{
    const char *root = make_tmpdir();
    char tpmdir[512];
    snprintf(tpmdir, sizeof(tpmdir), "%s/class/tpm/tpm0", root);
    rmkdir(tpmdir);
    char file[600];
    snprintf(file, sizeof(file), "%s/tpm_version_major", tpmdir);
    write_str(file, "1\n");
    sysinfo_set_sysfs_root(root);

    int ver = GetTPMVersion();
    CHECK_INT_EQ(1, ver);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(tpm_version_2_returns_2)
{
    const char *root = make_tmpdir();
    char tpmdir[512];
    snprintf(tpmdir, sizeof(tpmdir), "%s/class/tpm/tpm0", root);
    rmkdir(tpmdir);
    char file[600];
    snprintf(file, sizeof(file), "%s/tpm_version_major", tpmdir);
    write_str(file, "2\n");
    sysinfo_set_sysfs_root(root);

    int ver = GetTPMVersion();
    CHECK_INT_EQ(2, ver);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(tpm_garbage_in_version_file_returns_0)
{
    const char *root = make_tmpdir();
    char tpmdir[512];
    snprintf(tpmdir, sizeof(tpmdir), "%s/class/tpm/tpm0", root);
    rmkdir(tpmdir);
    char file[600];
    snprintf(file, sizeof(file), "%s/tpm_version_major", tpmdir);
    write_str(file, "garbage\n");
    sysinfo_set_sysfs_root(root);

    int ver = GetTPMVersion();
    /* atoi("garbage") == 0, so version_not_recognised → 0 */
    CHECK_INT_EQ(0, ver);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(tpm_empty_version_file_returns_0)
{
    const char *root = make_tmpdir();
    char tpmdir[512];
    snprintf(tpmdir, sizeof(tpmdir), "%s/class/tpm/tpm0", root);
    rmkdir(tpmdir);
    char file[600];
    snprintf(file, sizeof(file), "%s/tpm_version_major", tpmdir);
    write_str(file, "");
    sysinfo_set_sysfs_root(root);

    int ver = GetTPMVersion();
    CHECK_INT_EQ(0, ver);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(tpm_version_2_no_newline)
{
    /* Version file without trailing newline should still work */
    const char *root = make_tmpdir();
    char tpmdir[512];
    snprintf(tpmdir, sizeof(tpmdir), "%s/class/tpm/tpm0", root);
    rmkdir(tpmdir);
    char file[600];
    snprintf(file, sizeof(file), "%s/tpm_version_major", tpmdir);
    write_str(file, "2");
    sysinfo_set_sysfs_root(root);

    int ver = GetTPMVersion();
    CHECK_INT_EQ(2, ver);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

/* =================== IsSecureBootEnabled tests =================== */

TEST(secureboot_no_efi_dir_returns_false)
{
    const char *root = make_tmpdir();
    sysinfo_set_efi_root(root);

    /* No efivars directory at all */
    int result = IsSecureBootEnabled();
    CHECK_INT_EQ(0, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(secureboot_var_absent_returns_false)
{
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);
    /* Directory exists but SecureBoot variable file is absent */
    sysinfo_set_efi_root(root);

    int result = IsSecureBootEnabled();
    CHECK_INT_EQ(0, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(secureboot_enabled_returns_true)
{
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);
    char var_path[600];
    snprintf(var_path, sizeof(var_path), "%s/" SECUREBOOT_VAR, efivars);
    write_efi_var(var_path, 1);
    sysinfo_set_efi_root(root);

    int result = IsSecureBootEnabled();
    CHECK_INT_EQ(1, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(secureboot_disabled_returns_false)
{
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);
    char var_path[600];
    snprintf(var_path, sizeof(var_path), "%s/" SECUREBOOT_VAR, efivars);
    write_efi_var(var_path, 0);
    sysinfo_set_efi_root(root);

    int result = IsSecureBootEnabled();
    CHECK_INT_EQ(0, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(secureboot_short_file_returns_false)
{
    /* A file shorter than 5 bytes cannot contain a valid EFI variable */
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);
    char var_path[600];
    snprintf(var_path, sizeof(var_path), "%s/" SECUREBOOT_VAR, efivars);
    uint8_t short_data[3] = { 0x06, 0x00, 0x01 };
    write_bytes(var_path, short_data, sizeof(short_data));
    sysinfo_set_efi_root(root);

    int result = IsSecureBootEnabled();
    CHECK_INT_EQ(0, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(secureboot_empty_file_returns_false)
{
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);
    char var_path[600];
    snprintf(var_path, sizeof(var_path), "%s/" SECUREBOOT_VAR, efivars);
    write_bytes(var_path, NULL, 0);
    sysinfo_set_efi_root(root);

    int result = IsSecureBootEnabled();
    CHECK_INT_EQ(0, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

/* =================== IsSetupModeEnabled tests =================== */

TEST(setupmode_no_efi_dir_returns_false)
{
    const char *root = make_tmpdir();
    sysinfo_set_efi_root(root);

    int result = IsSetupModeEnabled();
    CHECK_INT_EQ(0, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(setupmode_var_absent_returns_false)
{
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);
    sysinfo_set_efi_root(root);

    int result = IsSetupModeEnabled();
    CHECK_INT_EQ(0, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(setupmode_enabled_returns_true)
{
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);
    char var_path[600];
    snprintf(var_path, sizeof(var_path), "%s/" SETUPMODE_VAR, efivars);
    write_efi_var(var_path, 1);
    sysinfo_set_efi_root(root);

    int result = IsSetupModeEnabled();
    CHECK_INT_EQ(1, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

TEST(setupmode_disabled_returns_false)
{
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);
    char var_path[600];
    snprintf(var_path, sizeof(var_path), "%s/" SETUPMODE_VAR, efivars);
    write_efi_var(var_path, 0);
    sysinfo_set_efi_root(root);

    int result = IsSetupModeEnabled();
    CHECK_INT_EQ(0, result);

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

/* ========== Combined scenario: SB enabled, SetupMode off ========== */
TEST(sb_enabled_setup_mode_off)
{
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);

    char var_sb[600], var_sm[600];
    snprintf(var_sb, sizeof(var_sb), "%s/" SECUREBOOT_VAR, efivars);
    snprintf(var_sm, sizeof(var_sm), "%s/" SETUPMODE_VAR,  efivars);
    write_efi_var(var_sb, 1);
    write_efi_var(var_sm, 0);
    sysinfo_set_efi_root(root);

    CHECK_INT_EQ(1, IsSecureBootEnabled());
    CHECK_INT_EQ(0, IsSetupModeEnabled());

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

/* SB reported as enabled but SetupMode also on — firmware quirk / setup phase */
TEST(sb_enabled_setup_mode_on)
{
    const char *root = make_tmpdir();
    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", root);
    rmkdir(efivars);

    char var_sb[600], var_sm[600];
    snprintf(var_sb, sizeof(var_sb), "%s/" SECUREBOOT_VAR, efivars);
    snprintf(var_sm, sizeof(var_sm), "%s/" SETUPMODE_VAR,  efivars);
    write_efi_var(var_sb, 1);
    write_efi_var(var_sm, 1);
    sysinfo_set_efi_root(root);

    CHECK_INT_EQ(1, IsSecureBootEnabled());
    CHECK_INT_EQ(1, IsSetupModeEnabled());

    system("rm -rf /tmp/test_sysinfo_XXXXXX 2>/dev/null");
    rmdir(root);
}

/* ========== TPM + Secure Boot combined scenario ========== */
TEST(tpm2_and_secureboot_enabled)
{
    /* Use separate char arrays so the two tmpdirs don't alias g_tmpdir */
    char sys_root[256], efi_root_buf[256];

    strncpy(g_tmpdir, "/tmp/test_sysinfo_XXXXXX", sizeof(g_tmpdir) - 1);
    if (!mkdtemp(g_tmpdir)) { perror("mkdtemp"); exit(1); }
    strncpy(sys_root, g_tmpdir, sizeof(sys_root) - 1);

    char tpmdir[512];
    snprintf(tpmdir, sizeof(tpmdir), "%s/class/tpm/tpm0", sys_root);
    rmkdir(tpmdir);
    char tpmfile[600];
    snprintf(tpmfile, sizeof(tpmfile), "%s/tpm_version_major", tpmdir);
    write_str(tpmfile, "2\n");
    sysinfo_set_sysfs_root(sys_root);

    /* Second temp dir for EFI vars */
    strncpy(g_tmpdir, "/tmp/test_sysinfo_XXXXXX", sizeof(g_tmpdir) - 1);
    if (!mkdtemp(g_tmpdir)) { perror("mkdtemp"); exit(1); }
    strncpy(efi_root_buf, g_tmpdir, sizeof(efi_root_buf) - 1);

    char efivars[512];
    snprintf(efivars, sizeof(efivars), "%s/efivars", efi_root_buf);
    rmkdir(efivars);
    char var_sb[600];
    snprintf(var_sb, sizeof(var_sb), "%s/" SECUREBOOT_VAR, efivars);
    write_efi_var(var_sb, 1);
    sysinfo_set_efi_root(efi_root_buf);

    CHECK_INT_EQ(2, GetTPMVersion());
    CHECK_INT_EQ(1, IsSecureBootEnabled());

    /* cleanup */
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf %s %s", sys_root, efi_root_buf);
    system(cmd);
}

/* ====================== main ====================== */

int main(void)
{
    printf("  tpm_no_sysfs_returns_0\n");          tpm_no_sysfs_returns_0();
    printf("  tpm_version_file_absent_returns_0\n"); tpm_version_file_absent_returns_0();
    printf("  tpm_version_1_returns_1\n");           tpm_version_1_returns_1();
    printf("  tpm_version_2_returns_2\n");           tpm_version_2_returns_2();
    printf("  tpm_garbage_in_version_file_returns_0\n"); tpm_garbage_in_version_file_returns_0();
    printf("  tpm_empty_version_file_returns_0\n");  tpm_empty_version_file_returns_0();
    printf("  tpm_version_2_no_newline\n");          tpm_version_2_no_newline();

    printf("  secureboot_no_efi_dir_returns_false\n"); secureboot_no_efi_dir_returns_false();
    printf("  secureboot_var_absent_returns_false\n");  secureboot_var_absent_returns_false();
    printf("  secureboot_enabled_returns_true\n");      secureboot_enabled_returns_true();
    printf("  secureboot_disabled_returns_false\n");    secureboot_disabled_returns_false();
    printf("  secureboot_short_file_returns_false\n");  secureboot_short_file_returns_false();
    printf("  secureboot_empty_file_returns_false\n");  secureboot_empty_file_returns_false();

    printf("  setupmode_no_efi_dir_returns_false\n"); setupmode_no_efi_dir_returns_false();
    printf("  setupmode_var_absent_returns_false\n");  setupmode_var_absent_returns_false();
    printf("  setupmode_enabled_returns_true\n");      setupmode_enabled_returns_true();
    printf("  setupmode_disabled_returns_false\n");    setupmode_disabled_returns_false();

    printf("  sb_enabled_setup_mode_off\n");  sb_enabled_setup_mode_off();
    printf("  sb_enabled_setup_mode_on\n");   sb_enabled_setup_mode_on();
    printf("  tpm2_and_secureboot_enabled\n"); tpm2_and_secureboot_enabled();

    TEST_RESULTS();
}
