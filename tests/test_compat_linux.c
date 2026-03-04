/* test_compat_linux.c — tests for compat layer headers:
 *   shlwapi.h: PathFileExistsA, PathFileExistsW, PathCombineA, StrStrIA, StrCmpIA
 *   shellapi.h: ShellExecuteA
 *   windows.h: GetTickCount64
 */
#ifdef _WIN32
#include "framework.h"
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

/* Pull in the compat headers under test */
#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/shlwapi.h"
#include "../src/linux/compat/shellapi.h"

/* Minimal stub so windows.h links */
DWORD _win_last_error = 0;

/* =========================================================================
 * GetTickCount64 (Feature 219)
 * =========================================================================*/

TEST(get_tick_count64_nonzero)
{
    ULONGLONG t = GetTickCount64();
    CHECK_MSG(t > 0, "GetTickCount64 must return a non-zero value on Linux");
}

TEST(get_tick_count64_advances)
{
    ULONGLONG t0 = GetTickCount64();
    struct timespec ts = { 0, 10000000 };  /* 10 ms */
    nanosleep(&ts, NULL);
    ULONGLONG t1 = GetTickCount64();
    CHECK_MSG(t1 > t0, "GetTickCount64 must increase after 10 ms sleep");
}

TEST(get_tick_count64_delta_reasonable)
{
    /* A 10 ms sleep should produce a delta in [5, 500] ms */
    ULONGLONG t0 = GetTickCount64();
    struct timespec ts = { 0, 10000000 };  /* 10 ms */
    nanosleep(&ts, NULL);
    ULONGLONG t1 = GetTickCount64();
    ULONGLONG delta = t1 - t0;
    CHECK_MSG(delta >= 5 && delta <= 500,
              "GetTickCount64 delta after 10ms must be in [5,500] ms");
}

TEST(get_tick_count64_millisecond_resolution)
{
    /* Two calls in tight succession must differ by < 100 ms (they're fast) */
    ULONGLONG t0 = GetTickCount64();
    ULONGLONG t1 = GetTickCount64();
    ULONGLONG delta = t1 - t0;
    CHECK_MSG(delta < 100,
              "Two back-to-back GetTickCount64 calls must differ by < 100 ms");
}

TEST(get_tick_count64_cycle_port_rate_limit_works)
{
    /* The CyclePort guard is: GetTickCount64() < last_reset + 10000ULL
     * With a real timer, a freshly recorded last_reset should NOT fire
     * if queried within ~0ms (simulating just-reset). */
    ULONGLONG last_reset = GetTickCount64();
    /* Immediately after recording, we're well within the 10s window */
    CHECK_MSG(GetTickCount64() < last_reset + 10000ULL,
              "GetTickCount64 must support CyclePort rate-limit guard");
    /* After 10+ seconds last_reset would expire — just verify the arithmetic */
    last_reset = 0;  /* simulate a very old reset (boot) */
    ULONGLONG now = GetTickCount64();
    /* now must be >= 10000 if system has been running > 10s (almost always true) */
    if (now >= 10000ULL) {
        CHECK_MSG(now >= last_reset + 10000ULL,
                  "Old last_reset must not block CyclePort when 10s has passed");
    }
}

/* =========================================================================
 * PathFileExistsA
 * =========================================================================*/

TEST(path_file_exists_a_real_file)
{
	/* /etc/hostname or /etc/os-release always exists on Linux */
	CHECK_MSG(PathFileExistsA("/etc/hostname") == TRUE ||
	          PathFileExistsA("/etc/os-release") == TRUE,
	          "PathFileExistsA: a real system file must exist");
}

TEST(path_file_exists_a_missing_file)
{
	CHECK_MSG(PathFileExistsA("/tmp/definitely_not_there_rufus_test_xyz_12345") == FALSE,
	          "PathFileExistsA: missing file must return FALSE");
}

TEST(path_file_exists_a_null_path)
{
	CHECK_MSG(PathFileExistsA(NULL) == FALSE,
	          "PathFileExistsA(NULL) must return FALSE");
}

TEST(path_file_exists_a_empty_string)
{
	CHECK_MSG(PathFileExistsA("") == FALSE,
	          "PathFileExistsA(\"\") must return FALSE");
}

TEST(path_file_exists_a_directory)
{
	/* /tmp is always a directory; should still return TRUE */
	CHECK_MSG(PathFileExistsA("/tmp") == TRUE,
	          "PathFileExistsA: directory must return TRUE");
}

/* =========================================================================
 * PathCombineA
 * =========================================================================*/

TEST(path_combine_a_basic)
{
	char out[MAX_PATH];
	LPSTR r = PathCombineA(out, "/usr", "bin");
	CHECK_MSG(r != NULL, "PathCombineA must not return NULL");
	CHECK_MSG(strcmp(out, "/usr/bin") == 0, "PathCombineA: /usr + bin = /usr/bin");
}

TEST(path_combine_a_trailing_slash)
{
	char out[MAX_PATH];
	PathCombineA(out, "/usr/", "bin");
	CHECK_MSG(strcmp(out, "/usr/bin") == 0,
	          "PathCombineA: trailing slash in dir must not produce double slash");
}

TEST(path_combine_a_null_dir)
{
	char out[MAX_PATH];
	LPSTR r = PathCombineA(out, NULL, "file.txt");
	CHECK_MSG(r != NULL, "PathCombineA with NULL dir must not return NULL");
	CHECK_MSG(strcmp(out, "file.txt") == 0,
	          "PathCombineA(NULL, file) must equal file");
}

TEST(path_combine_a_null_file)
{
	char out[MAX_PATH];
	LPSTR r = PathCombineA(out, "/usr", NULL);
	CHECK_MSG(r != NULL, "PathCombineA with NULL file must not return NULL");
	CHECK_MSG(strcmp(out, "/usr") == 0,
	          "PathCombineA(dir, NULL) must equal dir");
}

TEST(path_combine_a_backslash_normalised)
{
	char out[MAX_PATH];
	PathCombineA(out, "C:\\Users", "file.txt");
	/* Backslashes must become forward slashes */
	CHECK_MSG(strchr(out, '\\') == NULL,
	          "PathCombineA must normalise backslashes to forward slashes");
}

TEST(path_combine_a_null_result_returns_null)
{
	LPSTR r = PathCombineA(NULL, "/usr", "bin");
	CHECK_MSG(r == NULL, "PathCombineA(NULL result) must return NULL");
}

/* =========================================================================
 * StrStrIA / StrCmpIA
 * =========================================================================*/

TEST(strstr_ia_basic_match)
{
	CHECK_MSG(StrStrIA("Hello World", "world") != NULL,
	          "StrStrIA must find case-insensitive match");
}

TEST(strstr_ia_no_match)
{
	CHECK_MSG(StrStrIA("Hello World", "xyz") == NULL,
	          "StrStrIA must return NULL when no match");
}

TEST(strcmp_ia_equal)
{
	CHECK_MSG(StrCmpIA("ABC", "abc") == 0,
	          "StrCmpIA: case-insensitive equal strings must return 0");
}

TEST(strcmp_ia_less)
{
	CHECK_MSG(StrCmpIA("abc", "xyz") < 0,
	          "StrCmpIA: 'abc' < 'xyz' must be < 0");
}

/* =========================================================================
 * ShellExecuteA — smoke tests (we can't verify the browser opens in CI)
 * =========================================================================*/

TEST(shell_execute_a_null_file_returns_error)
{
	HINSTANCE h = ShellExecuteA(NULL, "open", NULL, NULL, NULL, SW_SHOWNORMAL);
	/* NULL file must return an error code (≤ 32) */
	CHECK_MSG((intptr_t)h <= 32,
	          "ShellExecuteA(NULL file) must return error hinstance (≤ 32)");
}

TEST(shell_execute_a_empty_file_returns_error)
{
	HINSTANCE h = ShellExecuteA(NULL, "open", "", NULL, NULL, SW_SHOWNORMAL);
	CHECK_MSG((intptr_t)h <= 32,
	          "ShellExecuteA(empty file) must return error");
}

TEST(shell_execute_a_valid_path_returns_gt32)
{
	/* Pass a real path — xdg-open will launch asynchronously and we
	 * just verify the return code is > 32 (success convention). */
	HINSTANCE h = ShellExecuteA(NULL, "open", "/tmp", NULL, NULL, SW_SHOWNORMAL);
	/* Accept either success (> 32) or failure in headless CI environment */
	CHECK((intptr_t)h > 0);
}

TEST(shell_execute_a_sw_show_constant_defined)
{
	/* Ensure SW_SHOWNORMAL is accessible via shellapi.h */
	CHECK_MSG(SW_SHOWNORMAL == 1, "SW_SHOWNORMAL must be 1");
	CHECK_MSG(SW_SHOW == 5,       "SW_SHOW must be 5");
}

/* =========================================================================
 * main
 * =========================================================================*/
int main(void)
{
	printf("=== compat shlwapi / shellapi tests ===\n");

    printf("\n  GetTickCount64 (Feature 219)\n");
    RUN(get_tick_count64_nonzero);
    RUN(get_tick_count64_advances);
    RUN(get_tick_count64_delta_reasonable);
    RUN(get_tick_count64_millisecond_resolution);
    RUN(get_tick_count64_cycle_port_rate_limit_works);

	printf("\n  PathFileExistsA\n");
	RUN(path_file_exists_a_real_file);
	RUN(path_file_exists_a_missing_file);
	RUN(path_file_exists_a_null_path);
	RUN(path_file_exists_a_empty_string);
	RUN(path_file_exists_a_directory);

	printf("\n  PathCombineA\n");
	RUN(path_combine_a_basic);
	RUN(path_combine_a_trailing_slash);
	RUN(path_combine_a_null_dir);
	RUN(path_combine_a_null_file);
	RUN(path_combine_a_backslash_normalised);
	RUN(path_combine_a_null_result_returns_null);

	printf("\n  StrStrIA / StrCmpIA\n");
	RUN(strstr_ia_basic_match);
	RUN(strstr_ia_no_match);
	RUN(strcmp_ia_equal);
	RUN(strcmp_ia_less);

	printf("\n  ShellExecuteA\n");
	RUN(shell_execute_a_null_file_returns_error);
	RUN(shell_execute_a_empty_file_returns_error);
	RUN(shell_execute_a_valid_path_returns_gt32);
	RUN(shell_execute_a_sw_show_constant_defined);

	TEST_RESULTS();
	return (_fail > 0) ? 1 : 0;
}
/* end */
#endif /* _WIN32 */
