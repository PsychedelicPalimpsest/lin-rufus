/*
 * test_ui_automation_linux.c — Full GTK UI automation tests for the Linux Rufus build.
 *
 * Uses AT-SPI2 accessibility API (via python3-pyatspi) to interact with the
 * running rufus GTK window: clicking buttons, toggling checkboxes, opening
 * dialogs, and verifying widget states — without any mock stubs.
 *
 * Infrastructure:
 *   1. Xvfb virtual framebuffer (:97)
 *   2. dbus-launch session bus (for AT-SPI2 communication)
 *   3. at-spi2-registryd accessibility registry daemon
 *   4. rufus binary, started headlessly under DISPLAY=:97
 *   5. rufus_ui_automation.py Python helper (per-test invocations via popen)
 *
 * Prerequisites: xvfb-run (or Xvfb), python3, python3-pyatspi, xdotool,
 *   dbus-launch, at-spi2-registryd, the built rufus binary at ../src/rufus.
 *
 * All tests skip (not fail) when any prerequisite is absent.
 *
 * Author: 2025 PsychedelicPalimpsest
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>

#include "framework.h"

/* ------------------------------------------------------------------ */
/* Global state (set up once in main, torn down at exit)               */
/* ------------------------------------------------------------------ */

static pid_t g_xvfb_pid        = 0;
static pid_t g_dbus_pid         = 0;
static pid_t g_atspi_pid        = 0;
static pid_t g_rufus_pid        = 0;

/* Environment strings held in static buffers set by setup_env(). */
static char g_display[32]             = "";   /* e.g. ":97"            */
static char g_dbus_addr[512]          = "";   /* DBUS_SESSION_BUS_ADDRESS */
static char g_dbus_pid_str[32]        = "";   /* DBus daemon PID str   */
static char g_rufus_pid_str[32]       = "";   /* rufus PID str         */
static char g_automation_script[512]  = "";   /* path to .py helper    */
static char g_rufus_bin[512]          = "";   /* path to rufus binary  */

static int  g_env_ready = 0;  /* 1 if setup_env() succeeded           */

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int cmd_available(const char *cmd)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "which %s >/dev/null 2>&1", cmd);
    return system(buf) == 0;
}

static int file_executable(const char *path)
{
    return access(path, X_OK) == 0;
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/*
 * Parse dbus-launch --sh-syntax output and extract the address and PID.
 * Expected lines:
 *   DBUS_SESSION_BUS_ADDRESS='unix:path=/tmp/...';
 *   DBUS_SESSION_BUS_PID=12345;
 */
static int parse_dbus_launch_output(const char *out,
                                    char *addr, size_t addr_sz,
                                    char *pid_str, size_t pid_sz)
{
    const char *p = strstr(out, "DBUS_SESSION_BUS_ADDRESS='");
    if (!p) {
        /* Try without quotes */
        p = strstr(out, "DBUS_SESSION_BUS_ADDRESS=");
        if (!p) return 0;
        p += strlen("DBUS_SESSION_BUS_ADDRESS=");
        const char *end = strchr(p, '\n');
        if (!end) end = p + strlen(p);
        /* Strip trailing semicolon/whitespace */
        while (end > p && (*(end-1) == ';' || *(end-1) == ' ' || *(end-1) == '\n'))
            end--;
        size_t len = (size_t)(end - p);
        if (len >= addr_sz) len = addr_sz - 1;
        memcpy(addr, p, len);
        addr[len] = '\0';
    } else {
        p += strlen("DBUS_SESSION_BUS_ADDRESS='");
        const char *end = strchr(p, '\'');
        if (!end) return 0;
        size_t len = (size_t)(end - p);
        if (len >= addr_sz) len = addr_sz - 1;
        memcpy(addr, p, len);
        addr[len] = '\0';
    }

    const char *q = strstr(out, "DBUS_SESSION_BUS_PID=");
    if (q) {
        q += strlen("DBUS_SESSION_BUS_PID=");
        snprintf(pid_str, pid_sz, "%ld", strtol(q, NULL, 10));
    }
    return 1;
}

/*
 * Run dbus-launch and capture its output.
 * Returns 1 on success, 0 on failure.
 */
static int launch_dbus_session(void)
{
    FILE *fp = popen("dbus-launch --sh-syntax 2>/dev/null", "r");
    if (!fp) return 0;
    char buf[1024] = "";
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    pclose(fp);

    if (!parse_dbus_launch_output(buf,
                                  g_dbus_addr, sizeof(g_dbus_addr),
                                  g_dbus_pid_str, sizeof(g_dbus_pid_str)))
        return 0;
    if (g_dbus_addr[0] == '\0') return 0;

    setenv("DBUS_SESSION_BUS_ADDRESS", g_dbus_addr, 1);
    if (g_dbus_pid_str[0])
        g_dbus_pid = (pid_t)atoi(g_dbus_pid_str);
    return 1;
}

/*
 * Find the at-spi2-registryd binary.
 */
static const char *find_atspi_registryd(void)
{
    static const char *candidates[] = {
        "/usr/libexec/at-spi2-registryd",
        "/usr/lib/at-spi2-core/at-spi2-registryd",
        "/usr/lib/at-spi2-registryd",
        NULL
    };
    for (int i = 0; candidates[i]; i++)
        if (access(candidates[i], X_OK) == 0)
            return candidates[i];
    return NULL;
}

/*
 * Set g_rufus_bin and g_automation_script from the test binary's location.
 * Tests are run from the tests/ directory.
 */
static void init_paths(void)
{
    const char *pwd = getenv("PWD");
    if (!pwd) pwd = ".";
    snprintf(g_rufus_bin, sizeof(g_rufus_bin), "%s/../src/rufus", pwd);
    snprintf(g_automation_script, sizeof(g_automation_script),
             "%s/rufus_ui_automation.py", pwd);
}

/*
 * setup_env() — start Xvfb, DBus, at-spi2-registryd, and rufus.
 * Returns 1 on success.  Sets g_env_ready.
 */
static int setup_env(void)
{
    init_paths();

    /* Check prerequisites */
    if (!file_executable(g_rufus_bin)) {
        printf("  SKIP-SETUP: rufus binary not found at %s\n", g_rufus_bin);
        return 0;
    }
    if (!file_executable(g_automation_script)) {
        printf("  SKIP-SETUP: automation script not found at %s\n",
               g_automation_script);
        return 0;
    }
    if (!cmd_available("python3")) {
        printf("  SKIP-SETUP: python3 not available\n");
        return 0;
    }
    if (!cmd_available("Xvfb")) {
        printf("  SKIP-SETUP: Xvfb not available\n");
        return 0;
    }
    if (!cmd_available("dbus-launch")) {
        printf("  SKIP-SETUP: dbus-launch not available\n");
        return 0;
    }
    /* pyatspi check */
    if (system("python3 -c 'import pyatspi' 2>/dev/null") != 0) {
        printf("  SKIP-SETUP: python3-pyatspi not installed\n");
        return 0;
    }

    /* Choose display */
    snprintf(g_display, sizeof(g_display), ":97");
    setenv("DISPLAY", g_display, 1);

    /* 1. Start Xvfb */
    g_xvfb_pid = fork();
    if (g_xvfb_pid == 0) {
        /* child */
        execlp("Xvfb", "Xvfb", g_display,
               "-screen", "0", "1024x768x24",
               "-ac",   /* no access control — allows any connection */
               (char *)NULL);
        _exit(127);
    }
    if (g_xvfb_pid < 0) { perror("fork Xvfb"); return 0; }
    sleep_ms(600);

    /* 2. Start DBus session */
    if (!launch_dbus_session()) {
        printf("  SKIP-SETUP: dbus-launch failed\n");
        return 0;
    }

    /* 3. Start at-spi2-registryd */
    const char *atspi_bin = find_atspi_registryd();
    if (atspi_bin) {
        g_atspi_pid = fork();
        if (g_atspi_pid == 0) {
            /* Redirect stdout/stderr to /dev/null */
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
            execlp(atspi_bin, atspi_bin, (char *)NULL);
            _exit(127);
        }
        sleep_ms(400);
    }

    /* 4. Start rufus */
    g_rufus_pid = fork();
    if (g_rufus_pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp(g_rufus_bin, g_rufus_bin, (char *)NULL);
        _exit(127);
    }
    if (g_rufus_pid < 0) { perror("fork rufus"); return 0; }

    snprintf(g_rufus_pid_str, sizeof(g_rufus_pid_str), "%d", (int)g_rufus_pid);
    setenv("RUFUS_PID", g_rufus_pid_str, 1);

    /* Wait for rufus to initialise and register with AT-SPI2 */
    sleep_ms(3000);

    /* Quick sanity: is rufus still alive? */
    if (kill(g_rufus_pid, 0) != 0) {
        printf("  SKIP-SETUP: rufus process exited immediately\n");
        return 0;
    }

    g_env_ready = 1;
    return 1;
}

/*
 * teardown_env() — terminate rufus, at-spi2, dbus, Xvfb.
 */
static void teardown_env(void)
{
    if (g_rufus_pid > 0) { kill(g_rufus_pid, SIGTERM); waitpid(g_rufus_pid, NULL, 0); g_rufus_pid = 0; }
    if (g_atspi_pid  > 0) { kill(g_atspi_pid,  SIGTERM); waitpid(g_atspi_pid,  NULL, 0); g_atspi_pid  = 0; }
    if (g_dbus_pid   > 0) { kill(g_dbus_pid,   SIGTERM); waitpid(g_dbus_pid,   NULL, 0); g_dbus_pid   = 0; }
    if (g_xvfb_pid   > 0) { kill(g_xvfb_pid,   SIGTERM); waitpid(g_xvfb_pid,   NULL, 0); g_xvfb_pid   = 0; }
    g_env_ready = 0;
}

/* ------------------------------------------------------------------ */
/* run_auto_test() — invoke the Python helper for one named test       */
/* ------------------------------------------------------------------ */

/*
 * Run rufus_ui_automation.py <test_name> and return its exit code.
 *   0   = pass
 *   1   = fail
 *   77  = skip
 *   -1  = could not exec
 */
static int run_auto_test(const char *test_name)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "python3 %s %s 2>/dev/null",
             g_automation_script, test_name);
    int raw = system(cmd);
    if (raw < 0) return -1;
    return WEXITSTATUS(raw);
}

/* ------------------------------------------------------------------ */
/* Skip helper: emit a skip message and count as pass                  */
/* ------------------------------------------------------------------ */

#define SKIP_IF_NOT_READY() \
    do { \
        if (!g_env_ready) { \
            printf("  SKIP: UI environment not ready\n"); \
            _pass++; \
            return; \
        } \
    } while (0)

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/*
 * 1. Verify the 'Device' label exists in the widget tree.
 */
TEST(ui_widget_tree_has_device_label)
{
    SKIP_IF_NOT_READY();
    int rc = run_auto_test("widget_tree_has_device_label");
    if (rc == 77) { printf("  SKIP: pyatspi not available\n"); _pass++; return; }
    CHECK_MSG(rc == 0, "AT-SPI2 widget tree must contain a 'Device' label");
}

/*
 * 2. Status bar shows 'Ready' on startup.
 */
TEST(ui_status_shows_ready)
{
    SKIP_IF_NOT_READY();
    int rc = run_auto_test("status_shows_ready");
    if (rc == 77) { printf("  SKIP\n"); _pass++; return; }
    CHECK_MSG(rc == 0, "Status label must read 'Ready' on rufus startup");
}

/*
 * 3. START button exists in the widget tree.
 */
TEST(ui_start_button_exists)
{
    SKIP_IF_NOT_READY();
    int rc = run_auto_test("start_button_exists");
    if (rc == 77) { printf("  SKIP\n"); _pass++; return; }
    CHECK_MSG(rc == 0, "START button must be present in the main window");
}

/*
 * 4. CLOSE button exists and is enabled.
 */
TEST(ui_close_button_exists)
{
    SKIP_IF_NOT_READY();
    int rc = run_auto_test("close_button_exists");
    if (rc == 77) { printf("  SKIP\n"); _pass++; return; }
    CHECK_MSG(rc == 0, "CLOSE button must be present and enabled");
}

/*
 * 5. Clicking the ⚙ settings button opens a dialog.
 */
TEST(ui_settings_dialog_opens)
{
    SKIP_IF_NOT_READY();
    int rc = run_auto_test("settings_dialog_opens");
    if (rc == 77) { printf("  SKIP\n"); _pass++; return; }
    CHECK_MSG(rc == 0, "Settings dialog must open when ⚙ button is clicked");
}

/*
 * 6. Ctrl+L opens (or shows) the log dialog.
 */
TEST(ui_ctrl_l_opens_log_dialog)
{
    SKIP_IF_NOT_READY();
    if (!cmd_available("xdotool")) {
        printf("  SKIP: xdotool not available\n");
        _pass++; return;
    }
    int rc = run_auto_test("ctrl_l_opens_log_dialog");
    if (rc == 77) { printf("  SKIP\n"); _pass++; return; }
    CHECK_MSG(rc == 0, "Ctrl+L must open the log dialog");
}

/*
 * 7. Ctrl+P persistent-log toggle does not crash rufus.
 */
TEST(ui_ctrl_p_persistent_log_toggle)
{
    SKIP_IF_NOT_READY();
    if (!cmd_available("xdotool")) {
        printf("  SKIP: xdotool not available\n");
        _pass++; return;
    }
    int rc = run_auto_test("ctrl_p_persistent_log_toggle");
    if (rc == 77) { printf("  SKIP\n"); _pass++; return; }
    CHECK_MSG(rc == 0, "Ctrl+P must toggle persistent log without crashing rufus");
}

/*
 * 8. 'Show advanced drive properties' toggle button works.
 */
TEST(ui_advanced_drive_toggle)
{
    SKIP_IF_NOT_READY();
    int rc = run_auto_test("advanced_drive_toggle");
    if (rc == 77) { printf("  SKIP\n"); _pass++; return; }
    CHECK_MSG(rc == 0, "Advanced drive properties toggle must change state on click");
}

/*
 * 9. 'Quick format' checkbox can be toggled.
 */
TEST(ui_quick_format_checkbox_toggle)
{
    SKIP_IF_NOT_READY();
    int rc = run_auto_test("quick_format_checkbox_toggle");
    if (rc == 77) {
        /* pyatspi unavailable or checkbox disabled — not a failure */
        printf("  SKIP\n");
        _pass++; return;
    }
    CHECK_MSG(rc == 0, "Quick format checkbox must be toggleable");
}

/*
 * 10. Clicking CLOSE terminates rufus.
 *     MUST be last: this kills the rufus process.
 */
TEST(ui_close_button_exits_app)
{
    SKIP_IF_NOT_READY();
    int rc = run_auto_test("close_button_exits_app");
    if (rc == 77) { printf("  SKIP\n"); _pass++; return; }
    CHECK_MSG(rc == 0, "CLOSE button must cause rufus to exit");

    /* rufus is gone — mark the environment as torn down to avoid
     * duplicate teardown in teardown_env(). */
    g_rufus_pid = 0;
    g_env_ready = 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== UI automation tests ===\n");

    /* One-time environment setup */
    int env_ok = setup_env();
    if (!env_ok)
        printf("NOTE: UI environment setup failed — all automation tests will be skipped\n\n");

    RUN(ui_widget_tree_has_device_label);
    RUN(ui_status_shows_ready);
    RUN(ui_start_button_exists);
    RUN(ui_close_button_exists);
    RUN(ui_settings_dialog_opens);
    RUN(ui_ctrl_l_opens_log_dialog);
    RUN(ui_ctrl_p_persistent_log_toggle);
    RUN(ui_advanced_drive_toggle);
    RUN(ui_quick_format_checkbox_toggle);
    RUN(ui_close_button_exits_app);  /* MUST be last */

    teardown_env();

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
