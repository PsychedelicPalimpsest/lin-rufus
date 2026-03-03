/*
 * test_ntfsfix_linux.c — TDD unit tests for src/linux/ntfsfix.c
 *
 * Tests cover RunNtfsFix() in isolation using a mock hook for system()
 * so no ntfsfix binary needs to be present and nothing is actually executed.
 *
 * Test categories:
 *   1. Input validation — NULL/empty path returns FALSE before any command runs
 *   2. Command format   — command string is correctly constructed
 *   3. Return value     — always TRUE for non-empty paths regardless of exit code
 *   4. Hook reset       — passing NULL to set_hook restores real system()
 *   5. Path quoting     — paths with spaces are correctly quoted
 *   6. Overflow safety  — very long paths are truncated, not overflowed
 *
 * Linux-only (ntfsfix is a Linux tool).
 */

#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "framework.h"

#include <windows.h>          /* linux/compat */
#include "../src/windows/rufus.h"
#include "../src/linux/format_linux.h"

/* ── globals required by ntfsfix.c / uprintf ──────────────────────── */
DWORD  ErrorStatus = 0;
BOOL   op_in_progress = FALSE;

void uprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/* ── mock infrastructure ──────────────────────────────────────────── */

/* Last command string seen by the mock, and the return value to fake. */
static char  mock_last_cmd[1024];
static int   mock_return_value = 0;
static int   mock_call_count   = 0;

static int mock_system(const char *cmd)
{
	mock_call_count++;
	if (cmd)
		snprintf(mock_last_cmd, sizeof(mock_last_cmd), "%s", cmd);
	else
		mock_last_cmd[0] = '\0';
	return mock_return_value;
}

/* Reset mock state and install the hook before each test. */
static void mock_reset(void)
{
	mock_last_cmd[0] = '\0';
	mock_return_value = 0;
	mock_call_count   = 0;
	ntfsfix_set_system_hook(mock_system);
}

/* ================================================================
 * 1. Input validation
 * ================================================================ */

TEST(null_path_returns_false)
{
	mock_reset();
	BOOL r = RunNtfsFix(NULL);
	CHECK(r == FALSE);
	/* system() must NOT have been called */
	CHECK_INT_EQ(mock_call_count, 0);
}

TEST(empty_path_returns_false)
{
	mock_reset();
	BOOL r = RunNtfsFix("");
	CHECK(r == FALSE);
	CHECK_INT_EQ(mock_call_count, 0);
}

/* ================================================================
 * 2. Command format
 * ================================================================ */

TEST(command_starts_with_ntfsfix)
{
	mock_reset();
	RunNtfsFix("/dev/sdb1");
	CHECK(strncmp(mock_last_cmd, "ntfsfix ", 8) == 0);
}

TEST(command_includes_partition_path)
{
	mock_reset();
	RunNtfsFix("/dev/sdb1");
	CHECK(strstr(mock_last_cmd, "/dev/sdb1") != NULL);
}

TEST(command_quotes_partition_path)
{
	mock_reset();
	RunNtfsFix("/dev/sdb1");
	/* Path must be enclosed in double-quotes: ntfsfix "/dev/sdb1" */
	CHECK(strstr(mock_last_cmd, "\"/dev/sdb1\"") != NULL);
}

TEST(command_for_nvme_partition)
{
	mock_reset();
	RunNtfsFix("/dev/nvme0n1p1");
	CHECK(strstr(mock_last_cmd, "\"/dev/nvme0n1p1\"") != NULL);
}

TEST(command_for_loop_device)
{
	mock_reset();
	RunNtfsFix("/dev/loop0p1");
	CHECK(strstr(mock_last_cmd, "\"/dev/loop0p1\"") != NULL);
}

TEST(command_for_path_with_spaces)
{
	mock_reset();
	/*
	 * Realistic example: partition device path with a space.
	 * The quotes must wrap the entire path so the shell treats it as one arg.
	 */
	RunNtfsFix("/dev/disk with space/p1");
	CHECK(strstr(mock_last_cmd, "\"/dev/disk with space/p1\"") != NULL);
}

/* ================================================================
 * 3. Return value
 * ================================================================ */

TEST(returns_true_when_system_returns_zero)
{
	mock_reset();
	mock_return_value = 0;
	BOOL r = RunNtfsFix("/dev/sdb1");
	CHECK(r == TRUE);
}

TEST(returns_true_when_system_returns_nonzero)
{
	mock_reset();
	mock_return_value = 1;
	BOOL r = RunNtfsFix("/dev/sdb1");
	/* RunNtfsFix returns TRUE even if ntfsfix reports an error */
	CHECK(r == TRUE);
}

TEST(returns_true_when_system_returns_negative)
{
	mock_reset();
	mock_return_value = -1;
	BOOL r = RunNtfsFix("/dev/sdb1");
	CHECK(r == TRUE);
}

/* ================================================================
 * 4. Mock call count
 * ================================================================ */

TEST(system_called_exactly_once_per_valid_invocation)
{
	mock_reset();
	RunNtfsFix("/dev/sda1");
	CHECK_INT_EQ(mock_call_count, 1);
}

TEST(system_not_called_for_null)
{
	mock_reset();
	RunNtfsFix(NULL);
	CHECK_INT_EQ(mock_call_count, 0);
}

TEST(system_not_called_for_empty)
{
	mock_reset();
	RunNtfsFix("");
	CHECK_INT_EQ(mock_call_count, 0);
}

/* ================================================================
 * 5. Hook management
 * ================================================================ */

TEST(set_hook_null_restores_no_crash)
{
	/*
	 * Passing NULL to ntfsfix_set_system_hook() must not crash and must
	 * restore the real system() (or at least a safe default).
	 * We just verify the call doesn't segfault; we do not actually invoke
	 * the real system() in unit tests.
	 */
	ntfsfix_set_system_hook(NULL);
	/* Re-install the mock for subsequent tests */
	ntfsfix_set_system_hook(mock_system);
	CHECK(1); /* reached here without crash */
}

/* Two file-scope hook variants for the replacement test */
static int hook_a_call_count = 0;
static int hook_b_call_count = 0;

static int hook_a_fn(const char *c) { (void)c; hook_a_call_count++; return 0; }
static int hook_b_fn(const char *c) { (void)c; hook_b_call_count++; return 0; }

TEST(hook_can_be_replaced_multiple_times)
{
	hook_a_call_count = hook_b_call_count = 0;

	ntfsfix_set_system_hook(hook_a_fn);
	RunNtfsFix("/dev/sda1");
	CHECK_INT_EQ(hook_a_call_count, 1);
	CHECK_INT_EQ(hook_b_call_count, 0);

	ntfsfix_set_system_hook(hook_b_fn);
	RunNtfsFix("/dev/sda2");
	CHECK_INT_EQ(hook_a_call_count, 1);
	CHECK_INT_EQ(hook_b_call_count, 1);

	/* Restore mock for remaining tests */
	ntfsfix_set_system_hook(mock_system);
}

/* ================================================================
 * 6. Overflow safety
 * ================================================================ */

TEST(very_long_path_does_not_crash)
{
	mock_reset();
	/* Generate a 600-char path — longer than the cmd[512] buffer. */
	char long_path[601];
	memset(long_path, 'a', 600);
	long_path[0] = '/';
	long_path[600] = '\0';

	/*
	 * snprintf(cmd, 512, "ntfsfix \"%s\"", path) will truncate silently.
	 * The command sent to mock_system will be at most 511 chars + NUL.
	 * The function must not crash and must still return TRUE.
	 */
	BOOL r = RunNtfsFix(long_path);
	CHECK(r == TRUE);
	CHECK_INT_EQ(mock_call_count, 1);
	/* Verify the cmd was actually truncated (≤ 511 bytes) */
	CHECK(strlen(mock_last_cmd) <= 511);
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
	/* Install mock so every test starts clean */
	ntfsfix_set_system_hook(mock_system);

	printf("=== test_ntfsfix_linux ===\n");

	/* 1. Input validation */
	RUN(null_path_returns_false);
	RUN(empty_path_returns_false);

	/* 2. Command format */
	RUN(command_starts_with_ntfsfix);
	RUN(command_includes_partition_path);
	RUN(command_quotes_partition_path);
	RUN(command_for_nvme_partition);
	RUN(command_for_loop_device);
	RUN(command_for_path_with_spaces);

	/* 3. Return value */
	RUN(returns_true_when_system_returns_zero);
	RUN(returns_true_when_system_returns_nonzero);
	RUN(returns_true_when_system_returns_negative);

	/* 4. Mock call count */
	RUN(system_called_exactly_once_per_valid_invocation);
	RUN(system_not_called_for_null);
	RUN(system_not_called_for_empty);

	/* 5. Hook management */
	RUN(set_hook_null_restores_no_crash);
	RUN(hook_can_be_replaced_multiple_times);

	/* 6. Overflow safety */
	RUN(very_long_path_does_not_crash);

	TEST_RESULTS();
}

#endif /* __linux__ */
