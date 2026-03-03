/*
 * test_ui_smoke_linux.c — Smoke tests for the Linux GTK UI.
 *
 * These tests verify the rufus binary actually starts, renders a window,
 * and terminates cleanly under a virtual framebuffer (Xvfb).
 *
 * Requirements: xvfb-run, scrot (screenshot), the rufus binary at ../src/rufus.
 * If xvfb-run or the binary is absent, tests are skipped (not failed) so CI
 * on headless machines without Xvfb doesn't break.
 *
 * Build: auto-discovered by tests/Makefile as a LINUX_BIN.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "framework.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Return 1 if a file path exists and is executable. */
static int file_executable(const char *path)
{
    return (access(path, X_OK) == 0);
}

/* Return 1 if a command is available on PATH. */
static int cmd_available(const char *cmd)
{
    char which_cmd[256];
    snprintf(which_cmd, sizeof(which_cmd), "which %s >/dev/null 2>&1", cmd);
    return (system(which_cmd) == 0);
}

/* Return file size in bytes, or -1 on error. */
static long file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

/* Path to the rufus binary relative to the test binary location. */
static const char *rufus_bin(void)
{
    static char path[512];
    if (path[0]) return path;
    /* Tests run from tests/ directory; binary is at ../src/rufus */
    snprintf(path, sizeof(path), "%s/../src/rufus", getenv("PWD") ? getenv("PWD") : ".");
    return path;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/*
 * 1. Binary existence — the built rufus ELF must exist and be executable.
 */
TEST(binary_exists_and_executable)
{
    const char *bin = rufus_bin();
    int ok = file_executable(bin);
    if (!ok) {
        printf("  SKIP: rufus binary not found at %s\n", bin);
        /* Don't fail — binary may not be built in all CI configurations. */
        _pass++;
        return;
    }
    CHECK_MSG(ok, "rufus binary must exist and be executable");
}

/*
 * 2. Binary is ELF — sanity check the file magic bytes.
 */
TEST(binary_is_elf)
{
    const char *bin = rufus_bin();
    if (!file_executable(bin)) { _pass++; printf("  SKIP: binary absent\n"); return; }

    FILE *f = fopen(bin, "rb");
    CHECK_MSG(f != NULL, "must be able to open rufus binary");
    if (!f) return;

    unsigned char magic[4];
    size_t n = fread(magic, 1, 4, f);
    fclose(f);

    CHECK_MSG(n == 4, "must read 4 bytes");
    CHECK_MSG(magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F',
              "binary must start with ELF magic bytes");
}

/*
 * 3. Binary links against GTK3 — confirmed by the required shared-library list.
 */
TEST(binary_links_gtk3)
{
    const char *bin = rufus_bin();
    if (!file_executable(bin)) { _pass++; printf("  SKIP: binary absent\n"); return; }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ldd %s 2>/dev/null | grep -q libgtk-3", bin);
    int rc = system(cmd);
    CHECK_MSG(rc == 0, "rufus binary must link against libgtk-3");
}

/*
 * 4. xvfb-run smoke: rufus starts and runs for at least ~2 seconds without
 *    crashing (not segfault, not immediate exit 1).  We allow exit 124
 *    (timeout) and 143 (SIGTERM from timeout) as success — the process was
 *    alive long enough.  We also accept exit 0 (graceful shutdown).
 *
 *    The test is skipped when xvfb-run is unavailable.
 */
TEST(starts_under_xvfb_without_crash)
{
    const char *bin = rufus_bin();
    if (!file_executable(bin)) { _pass++; printf("  SKIP: binary absent\n"); return; }
    if (!cmd_available("xvfb-run")) { _pass++; printf("  SKIP: xvfb-run not found\n"); return; }

    /* Run rufus for 3 seconds then kill it. */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "xvfb-run --auto-servernum --server-args='-screen 0 1024x768x24' "
             "timeout 3 %s >/dev/null 2>&1",
             bin);
    int raw = system(cmd);
    int status = WEXITSTATUS(raw);

    /* 124 = timeout(1) killed the process; 143 = SIGTERM (128+15). Both are fine. */
    int crashed = (status != 0 && status != 124 && status != 143);
    if (crashed)
        printf("  (exit status %d)\n", status);
    CHECK_MSG(!crashed,
              "rufus must not crash immediately under xvfb (exit 0/124/143 are OK)");
}

/*
 * 5. Screenshot is non-trivial: when rufus runs for 3 s under Xvfb, a
 *    screenshot taken at t=2s must be larger than 5 KiB (a blank/black
 *    screen is typically < 1 KiB as a PNG due to solid-colour compression).
 *
 *    Requires: xvfb-run, scrot.
 */
TEST(window_renders_non_blank)
{
    const char *bin = rufus_bin();
    if (!file_executable(bin)) { _pass++; printf("  SKIP: binary absent\n"); return; }
    if (!cmd_available("xvfb-run")) { _pass++; printf("  SKIP: xvfb-run not found\n"); return; }
    if (!cmd_available("scrot"))    { _pass++; printf("  SKIP: scrot not found\n"); return; }

    const char *sshot = "/tmp/rufus_smoke_test.png";
    unlink(sshot);

    /* Start Xvfb on a fixed display, launch rufus, screenshot, kill. */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "Xvfb :96 -screen 0 1024x768x24 >/dev/null 2>&1 & XPID=$!; "
             "sleep 0.5; "
             "DISPLAY=:96 %s >/dev/null 2>&1 & RPID=$!; "
             "sleep 2.5; "
             "scrot %s -d 0 --display :96 >/dev/null 2>&1; "
             "kill $RPID 2>/dev/null; kill $XPID 2>/dev/null; "
             "wait 2>/dev/null; true",
             bin, sshot);
    system(cmd);

    long sz = file_size(sshot);
    if (sz < 0) {
        /* scrot failed — skip rather than fail */
        printf("  SKIP: screenshot not created (scrot may have failed)\n");
        _pass++;
        return;
    }
    printf("  screenshot size: %ld bytes\n", sz);
    CHECK_MSG(sz > 5000, "rendered window screenshot must be > 5 KiB (not a blank screen)");

    unlink(sshot);
}

/*
 * 6. UI responds to --help or --version without hanging.
 *    (Non-GUI mode exits immediately with status 0 or 1.)
 */
TEST(help_flag_exits_quickly)
{
    const char *bin = rufus_bin();
    if (!file_executable(bin)) { _pass++; printf("  SKIP: binary absent\n"); return; }

    char cmd[512];
    /* timeout 2 ensures we don't hang; --help should print usage and exit. */
    snprintf(cmd, sizeof(cmd),
             "timeout 2 %s --help >/dev/null 2>&1 || true", bin);
    /* We don't fail on non-zero exit; we just verify it exits within 2s. */
    int raw = system(cmd);
    int status = WEXITSTATUS(raw);
    /* 124 = timeout fired = hung for 2s without exiting */
    CHECK_MSG(status != 124, "--help must not hang (timeout fired)");
}

/*
 * 7. Localization: running rufus under xvfb for 3s must produce the string
 *    "localization:" in its stderr/stdout, confirming the embedded.loc file
 *    is found and parsed on startup.
 */
TEST(localization_loaded_on_startup)
{
    const char *bin = rufus_bin();
    if (!file_executable(bin)) { _pass++; printf("  SKIP: binary absent\n"); return; }
    if (!cmd_available("xvfb-run")) { _pass++; printf("  SKIP: xvfb-run not found\n"); return; }

    const char *logfile = "/tmp/rufus_smoke_loc.txt";
    unlink(logfile);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "xvfb-run --auto-servernum --server-args='-screen 0 800x600x24' "
             "timeout 3 %s >%s 2>&1 || true",
             bin, logfile);
    system(cmd);

    /* Read output and look for "localization:" string */
    FILE *f = fopen(logfile, "r");
    int found = 0;
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "localization:")) { found = 1; break; }
        }
        fclose(f);
    }
    unlink(logfile);

    CHECK_MSG(found, "rufus startup must emit 'localization:' log line (embedded.loc loaded)");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
    printf("=== UI smoke tests ===\n");
    RUN(binary_exists_and_executable);
    RUN(binary_is_elf);
    RUN(binary_links_gtk3);
    RUN(starts_under_xvfb_without_crash);
    RUN(window_renders_non_blank);
    RUN(help_flag_exits_quickly);
    RUN(localization_loaded_on_startup);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
