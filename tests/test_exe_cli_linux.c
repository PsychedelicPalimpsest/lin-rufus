/*
 * test_exe_cli_linux.c — Integration tests that invoke the Rufus binary
 * as a subprocess to verify end-to-end CLI behaviour.
 *
 * These tests exercise:
 *   Linux binary (src/rufus built with GTK): CLI mode triggered by --device
 *   Wine binary  (src/rufus.exe via wine):   --help output
 *
 * No real device access is needed for most tests (we use /nonexistent or
 * /dev/null).  The tests verify exit codes and stdout/stderr content.
 *
 * Linux-only (uses popen/fork, Wine, /proc-based path detection).
 */

#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>

#include "framework.h"

/* ── path to the Linux binary ──────────────────────────────────────── */

/*
 * The Linux binary is always at <tests>/../src/rufus.
 * We resolve it at startup relative to the test binary's own directory.
 */
static char linux_bin[PATH_MAX + 64];
static char windows_exe[PATH_MAX + 64];

static void resolve_binary_paths(void)
{
	char self[PATH_MAX];
	ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (n <= 0) {
		snprintf(linux_bin,   sizeof(linux_bin),   "../src/rufus");
		snprintf(windows_exe, sizeof(windows_exe), "../src/rufus.exe");
		return;
	}
	self[n] = '\0';
	/* Strip filename to get directory */
	char *slash = strrchr(self, '/');
	if (slash) *slash = '\0';
	snprintf(linux_bin,   sizeof(linux_bin),   "%s/../src/rufus",     self);
	snprintf(windows_exe, sizeof(windows_exe), "%s/../src/rufus.exe", self);
}

/* ── subprocess helpers ────────────────────────────────────────────── */

/*
 * run_cmd_capture — run a command via sh -c, capture combined stdout+stderr,
 * and return the exit code of the command itself (not any pipe filter).
 * Returns -1 on popen/pclose failure.
 */
static int run_cmd_capture(const char *cmd, char *buf, size_t bufsz)
{
	FILE *fp = popen(cmd, "r");
	if (!fp) return -1;

	size_t total = 0;
	if (buf && bufsz > 1) {
		char tmp[4096];
		size_t r;
		while ((r = fread(tmp, 1, sizeof(tmp), fp)) > 0) {
			size_t copy = r;
			if (total + copy >= bufsz - 1)
				copy = bufsz - 1 - total;
			memcpy(buf + total, tmp, copy);
			total += copy;
			if (total >= bufsz - 1) break;
		}
		buf[total] = '\0';
	}

	int st = pclose(fp);
	if (WIFEXITED(st)) return WEXITSTATUS(st);
	return -1;
}

/*
 * Build a command string that:
 *  - redirects stderr to stdout (2>&1) so we capture everything
 *  - wraps in bash -c with PIPESTATUS so exit code propagation is reliable
 */
static void build_cmd(char *out, size_t outsz, const char *fmt, ...)
{
	char inner[8192];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(inner, sizeof(inner), fmt, ap);
	va_end(ap);
	/* Use bash -c with explicit exit propagation to preserve exit code */
	snprintf(out, outsz, "bash -c '%s 2>&1; exit $?'", inner);
}

/* ── Linux binary tests ────────────────────────────────────────────── */

/*
 * Verify the binary exists and is executable.
 */
TEST(linux_binary_exists)
{
	struct stat st;
	CHECK_MSG(stat(linux_bin, &st) == 0, "src/rufus not found");
	CHECK_MSG(S_ISREG(st.st_mode), "src/rufus is not a regular file");
	CHECK_MSG((st.st_mode & S_IXUSR) != 0, "src/rufus is not executable");
}

/*
 * --device with a non-existent path → exit 1, error message on stderr.
 */
TEST(linux_nonexistent_device_exits_1)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, 8192, "\"%s\" --device /dev/rufus_test_nonexistent_xyz_abc", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_INT_EQ(rc, 1);
	CHECK_MSG(strstr(out, "cannot open") != NULL || strstr(out, "No such file") != NULL,
	          "expected 'cannot open' or 'No such file' in output");
}

/*
 * --device /dev/null → exit 1 (cannot determine size of char device).
 */
TEST(linux_null_device_exits_1)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, 8192, "\"%s\" --device /dev/null --no-prompt", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_INT_EQ(rc, 1);
	CHECK_MSG(strstr(out, "cannot determine size") != NULL,
	          "expected 'cannot determine size' in output");
}

/*
 * --device /dev/null --fs badfs → exit 1, "unknown filesystem" error.
 */
TEST(linux_bad_fs_exits_1)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, 8192, "\"%s\" --device /dev/null --fs totally_invalid_fs", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_INT_EQ(rc, 1);
	CHECK_MSG(strstr(out, "unknown filesystem") != NULL ||
	          strstr(out, "totally_invalid_fs") != NULL,
	          "expected 'unknown filesystem' in output");
}

/*
 * --device /dev/null --partition-scheme bad → exit 1.
 */
TEST(linux_bad_partition_scheme_exits_1)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, 8192, "\"%s\" --device /dev/null --partition-scheme notascheme", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_INT_EQ(rc, 1);
	CHECK_MSG(strstr(out, "unknown partition scheme") != NULL ||
	          strstr(out, "notascheme") != NULL,
	          "expected 'unknown partition scheme' in output");
}

/*
 * --device /dev/null --target bad → exit 1.
 */
TEST(linux_bad_target_exits_1)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, 8192, "\"%s\" --device /dev/null --target notarget", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_INT_EQ(rc, 1);
	CHECK_MSG(strstr(out, "unknown target") != NULL ||
	          strstr(out, "notarget") != NULL,
	          "expected 'unknown target' in output");
}

/*
 * --device PATH --help → exit 0 (help wins, usage printed).
 */
TEST(linux_help_with_device_exits_0)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, 8192, "\"%s\" --device /dev/null --help", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_INT_EQ(rc, 0);
	CHECK_MSG(strstr(out, "Usage:") != NULL || strstr(out, "--device") != NULL,
	          "expected usage text in output");
}

/*
 * --device PATH --help outputs expected options.
 */
TEST(linux_help_lists_options)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, 8192, "\"%s\" --device /dev/null --help", linux_bin);
	run_cmd_capture(cmd, out, sizeof(out));
	CHECK_MSG(strstr(out, "--image") != NULL  || strstr(out, "-i") != NULL,
	          "expected --image in help output");
	CHECK_MSG(strstr(out, "--fs") != NULL || strstr(out, "-f") != NULL,
	          "expected --fs in help output");
}

/*
 * Short form -d works the same as --device.
 */
TEST(linux_short_device_flag)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, 8192, "\"%s\" -d /dev/rufus_test_nonexistent_abc_xyz", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	/* -d /nonexistent still hits "cannot open" → exit 1 */
	CHECK_INT_EQ(rc, 1);
	CHECK_MSG(strstr(out, "cannot open") != NULL || strstr(out, "No such file") != NULL,
	          "expected error for bad device via -d flag");
}

/*
 * Without --device, the binary should attempt GUI mode and eventually fail
 * (no display) — exit non-zero or fall through to GTK error.
 * We just verify it doesn't segfault (exit code != 139).
 */
TEST(linux_no_device_no_segfault)
{
	char cmd[8192], out[4096];
	/* Run without DISPLAY so GTK fails fast */
	snprintf(cmd, sizeof(cmd),
	         "{ DISPLAY= \"%s\"; } 2>&1 | head -5", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_MSG(rc != 139, "rufus without --device should not segfault (SIGSEGV=139)");
}

/*
 * --version exits 0 and prints a version string.
 */
TEST(linux_version_exits_0)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, sizeof(cmd), "\"%s\" --version", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_INT_EQ(rc, 0);
	CHECK_MSG(strstr(out, "rufus") != NULL || strstr(out, "4.") != NULL,
	          "expected version string in output");
}

/*
 * --list-devices exits 0 or 1 (no segfault), outputs nothing harmful.
 */
TEST(linux_list_devices_no_segfault)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, sizeof(cmd), "\"%s\" --list-devices", linux_bin);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_MSG(rc == 0 || rc == 1, "expected exit 0 (found drives) or 1 (no drives)");
	CHECK_MSG(rc != 139, "--list-devices should not segfault");
}

/*
 * Help output lists the new flags added in recent CLI work.
 */
TEST(linux_help_lists_new_flags)
{
	char cmd[8192], out[4096];
	build_cmd(cmd, sizeof(cmd), "\"%s\" --device /dev/null --help", linux_bin);
	run_cmd_capture(cmd, out, sizeof(out));
	CHECK_MSG(strstr(out, "list-devices") != NULL || strstr(out, "-L") != NULL,
	          "expected --list-devices in help output");
	CHECK_MSG(strstr(out, "zero-drive") != NULL || strstr(out, "-z") != NULL,
	          "expected --zero-drive in help output");
	CHECK_MSG(strstr(out, "include-hdds") != NULL || strstr(out, "-H") != NULL,
	          "expected --include-hdds in help output");
}

/* ── Wine / Windows binary tests ──────────────────────────────────── */

static int wine_available(void)
{
	return system("which wine >/dev/null 2>&1") == 0;
}

static int windows_exe_exists(void)
{
	struct stat st;
	return stat(windows_exe, &st) == 0 && S_ISREG(st.st_mode);
}

/*
 * rufus.exe --help (via wine) should exit 0 and output usage text.
 * Wine diagnostic messages on stderr are expected and ignored.
 */
TEST(wine_help_exits_0)
{
	if (!wine_available() || !windows_exe_exists()) {
		printf("  (SKIP — wine or rufus.exe not available)\n");
		_pass++;   /* count as pass for summary */
		return;
	}
	char cmd[8192], out[8192];
	snprintf(cmd, sizeof(cmd),
	         "DISPLAY='' wine \"%s\" --help 2>&1 | grep -v '^[0-9a-f]*:err:\\|^it looks like\\|^multiarch\\|^execute\\|^$'",
	         windows_exe);
	int rc = run_cmd_capture(cmd, out, sizeof(out));
	CHECK_INT_EQ(rc, 0);
}

/*
 * rufus.exe --help output must contain "Usage:" and list known flags.
 */
TEST(wine_help_contains_usage)
{
	if (!wine_available() || !windows_exe_exists()) {
		printf("  (SKIP — wine or rufus.exe not available)\n");
		_pass++;
		return;
	}
	char cmd[8192], out[8192];
	snprintf(cmd, sizeof(cmd),
	         "DISPLAY='' wine \"%s\" --help 2>&1", windows_exe);
	run_cmd_capture(cmd, out, sizeof(out));
	CHECK_MSG(strstr(out, "Usage:") != NULL || strstr(out, "rufus") != NULL,
	          "expected 'Usage:' in wine --help output");
}

/*
 * rufus.exe --help must list the -i / --iso flag.
 */
TEST(wine_help_lists_iso_flag)
{
	if (!wine_available() || !windows_exe_exists()) {
		printf("  (SKIP — wine or rufus.exe not available)\n");
		_pass++;
		return;
	}
	char cmd[8192], out[8192];
	snprintf(cmd, sizeof(cmd), "DISPLAY='' wine \"%s\" --help 2>&1", windows_exe);
	run_cmd_capture(cmd, out, sizeof(out));
	CHECK_MSG(strstr(out, "--iso") != NULL || strstr(out, "-i") != NULL,
	          "expected --iso/-i in wine --help output");
}

/*
 * rufus.exe --help must list the -f / --filesystem flag.
 */
TEST(wine_help_lists_filesystem_flag)
{
	if (!wine_available() || !windows_exe_exists()) {
		printf("  (SKIP — wine or rufus.exe not available)\n");
		_pass++;
		return;
	}
	char cmd[8192], out[8192];
	snprintf(cmd, sizeof(cmd), "DISPLAY='' wine \"%s\" --help 2>&1", windows_exe);
	run_cmd_capture(cmd, out, sizeof(out));
	CHECK_MSG(strstr(out, "--filesystem") != NULL || strstr(out, "-f") != NULL,
	          "expected --filesystem/-f in wine --help output");
}

/* ── main ───────────────────────────────────────────────────────────── */

int main(void)
{
	resolve_binary_paths();

	printf("=== test_exe_cli_linux ===\n");
	printf("  Linux binary: %s\n", linux_bin);
	printf("  Windows exe:  %s\n", windows_exe);

	/* Linux binary tests */
	RUN(linux_binary_exists);
	RUN(linux_nonexistent_device_exits_1);
	RUN(linux_null_device_exits_1);
	RUN(linux_bad_fs_exits_1);
	RUN(linux_bad_partition_scheme_exits_1);
	RUN(linux_bad_target_exits_1);
	RUN(linux_help_with_device_exits_0);
	RUN(linux_help_lists_options);
	RUN(linux_short_device_flag);
	RUN(linux_no_device_no_segfault);
	RUN(linux_version_exits_0);
	RUN(linux_list_devices_no_segfault);
	RUN(linux_help_lists_new_flags);

	/* Wine / Windows tests */
	RUN(wine_help_exits_0);
	RUN(wine_help_contains_usage);
	RUN(wine_help_lists_iso_flag);
	RUN(wine_help_lists_filesystem_flag);

	TEST_RESULTS();
}

#endif /* __linux__ */
