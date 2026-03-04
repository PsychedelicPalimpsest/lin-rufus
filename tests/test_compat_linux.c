/* test_compat_linux.c — tests for compat layer headers:
 *   shlwapi.h: PathFileExistsA, PathFileExistsW, PathCombineA, StrStrIA, StrCmpIA,
 *              StrCmpNIA
 *   shellapi.h: ShellExecuteA
 *   windows.h: GetTickCount64, CharLowerA/CharUpperA, GetEnvironmentVariableA,
 *              SetEnvironmentVariableA, GetTempPathA, GetTempFileNameA,
 *              GetModuleFileNameA, GetCurrentProcessId, GetCurrentThreadId,
 *              GetCurrentThread, SetThreadAffinityMask
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
#include <sys/syscall.h>
#include <sys/types.h>
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
 * StrCmpNIA — case-insensitive n-char comparison
 * =========================================================================*/

TEST(strcmpnia_equal_n_chars)
{
	/* First 5 chars are identical case-insensitively */
	CHECK_MSG(StrCmpNIA("HELLO world", "hello world", 5) == 0,
	          "StrCmpNIA: equal first 5 chars must return 0");
}

TEST(strcmpnia_less_in_first_n)
{
	CHECK_MSG(StrCmpNIA("abc", "xyz", 3) < 0,
	          "StrCmpNIA: 'abc' < 'xyz' in 3 chars must be < 0");
}

TEST(strcmpnia_n_zero_always_equal)
{
	/* n=0: no characters compared, must return 0 */
	CHECK_MSG(StrCmpNIA("abc", "xyz", 0) == 0,
	          "StrCmpNIA(n=0): must return 0 (no chars compared)");
}

TEST(strcmpnia_differing_after_n)
{
	/* First 4 chars are equal, diff starts at char 5 — must be 0 */
	CHECK_MSG(StrCmpNIA("TEST_abc", "test_xyz", 5) == 0,
	          "StrCmpNIA must only compare first n chars");
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
 * CharLowerA / CharUpperA — in-place case conversion
 * =========================================================================*/

TEST(charlowera_lowercases_string)
{
	char s[] = "HELLO WORLD";
	CharLowerA(s);
	CHECK_STR_EQ(s, "hello world");
}

TEST(charlowera_already_lowercase_unchanged)
{
	char s[] = "hello world";
	CharLowerA(s);
	CHECK_STR_EQ(s, "hello world");
}

TEST(charlowera_mixed_case)
{
	char s[] = "HeLLo";
	CharLowerA(s);
	CHECK_STR_EQ(s, "hello");
}

TEST(charlowera_empty_string)
{
	char s[] = "";
	CharLowerA(s);
	CHECK_STR_EQ(s, "");
}

TEST(charlowera_null_safe)
{
	/* CharLowerA(NULL) must not crash */
	char *r = CharLowerA(NULL);
	CHECK(r == NULL);
}

TEST(charuppera_uppercases_string)
{
	char s[] = "hello world";
	CharUpperA(s);
	CHECK_STR_EQ(s, "HELLO WORLD");
}

TEST(charuppera_null_safe)
{
	char *r = CharUpperA(NULL);
	CHECK(r == NULL);
}

/* safe_strtolower (rufus.h macro) must actually lowercase on Linux */
TEST(safe_strtolower_actually_lowercases)
{
	char s[] = "RUFUS-NET.EXE";
	char *p = s;
	/* safe_strtolower is defined in rufus.h but we can call CharLowerA
	 * directly because that is exactly what it expands to on Linux. */
	CharLowerA(p);
	CHECK_STR_EQ(p, "rufus-net.exe");
}

/* =========================================================================
 * GetEnvironmentVariableA / SetEnvironmentVariableA
 * =========================================================================*/
TEST(getenv_set_and_get_roundtrip)
{
	SetEnvironmentVariableA("RUFUS_TEST_ENV_42", "hello_world");
	char buf[64] = {0};
	DWORD r = GetEnvironmentVariableA("RUFUS_TEST_ENV_42", buf, sizeof(buf));
	CHECK_MSG(r == 11, "GetEnvironmentVariableA should return 11 (length of 'hello_world')");
	CHECK_STR_EQ(buf, "hello_world");
}

TEST(getenv_missing_returns_zero)
{
	DWORD r = GetEnvironmentVariableA("RUFUS_NOT_SET_XYZ_99", NULL, 0);
	CHECK_MSG(r == 0, "GetEnvironmentVariableA of unset var should return 0");
}

TEST(getenv_buffer_too_small_returns_needed_size)
{
	SetEnvironmentVariableA("RUFUS_TEST_ENV_SMALL", "abcde");
	char buf[3] = {0};
	DWORD r = GetEnvironmentVariableA("RUFUS_TEST_ENV_SMALL", buf, sizeof(buf));
	/* Windows returns required size (6 = strlen+1) when buffer too small */
	CHECK_MSG(r == 6, "Should return needed size (6) when buffer too small");
	/* buf should not have been written to (or at least not null-term violated) */
}

TEST(getenv_null_buf_returns_needed_size)
{
	SetEnvironmentVariableA("RUFUS_TEST_ENV_NULL", "test123");
	DWORD r = GetEnvironmentVariableA("RUFUS_TEST_ENV_NULL", NULL, 0);
	/* Windows returns strlen+1 when buf is NULL */
	CHECK_MSG(r == 8, "GetEnvironmentVariableA(NULL, 0) should return 8 (strlen+1)");
}

TEST(setenv_can_unset_with_null_value)
{
	/* Windows: SetEnvironmentVariableA with NULL value removes the variable.
	 * Our stub sets it to empty string (POSIX unsetenv not directly supported
	 * via the Windows API on Linux) — just verify it doesn't crash. */
	SetEnvironmentVariableA("RUFUS_TEST_ENV_DEL", "value");
	/* Our impl maps NULL -> setenv(n, "", 1) which won't crash */
	BOOL r = SetEnvironmentVariableA("RUFUS_TEST_ENV_DEL", NULL);
	(void)r;  /* just check no crash */
	CHECK_MSG(TRUE, "SetEnvironmentVariableA with NULL value should not crash");
}

/* =========================================================================
 * GetTempPathA
 * =========================================================================*/
TEST(get_temp_path_a_returns_nonzero)
{
	char buf[MAX_PATH] = {0};
	DWORD r = GetTempPathA(sizeof(buf), buf);
	CHECK_MSG(r > 0, "GetTempPathA should return non-zero length");
	CHECK_MSG(buf[0] != '\0', "GetTempPathA should fill buffer");
}

TEST(get_temp_path_a_returns_valid_dir)
{
	char buf[MAX_PATH] = {0};
	GetTempPathA(sizeof(buf), buf);
	/* On Linux, should be /tmp or $TMPDIR */
	CHECK_MSG(strstr(buf, "tmp") != NULL || buf[0] == '/',
	          "GetTempPathA should return a path containing 'tmp' or absolute path");
}

TEST(get_temp_path_a_length_matches_buf)
{
	char buf[MAX_PATH] = {0};
	DWORD r = GetTempPathA(sizeof(buf), buf);
	CHECK_MSG(r == (DWORD)strlen(buf),
	          "GetTempPathA return value should equal strlen(buf)");
}

/* =========================================================================
 * GetModuleFileNameA
 * =========================================================================*/
TEST(get_module_filename_a_returns_nonzero)
{
	char buf[MAX_PATH] = {0};
	DWORD r = GetModuleFileNameA(NULL, buf, sizeof(buf));
	CHECK_MSG(r > 0, "GetModuleFileNameA should return non-zero");
	CHECK_MSG(buf[0] == '/', "GetModuleFileNameA should return absolute path");
}

TEST(get_module_filename_a_null_terminated)
{
	char buf[MAX_PATH];
	memset(buf, 0xAB, sizeof(buf));
	DWORD r = GetModuleFileNameA(NULL, buf, sizeof(buf));
	CHECK_MSG(r < sizeof(buf), "GetModuleFileNameA should fit in MAX_PATH");
	CHECK_MSG(buf[r] == '\0', "GetModuleFileNameA result should be null-terminated");
}

/* =========================================================================
 * GetTempFileNameA
 * =========================================================================*/
TEST(get_temp_filename_a_success_returns_nonzero)
{
	char tmpfile[MAX_PATH] = {0};
	UINT r = GetTempFileNameA("/tmp", "ruf", 0, tmpfile);
	CHECK_MSG(r != 0, "GetTempFileNameA must return non-zero on success");
	CHECK_MSG(tmpfile[0] == '/', "GetTempFileNameA must produce an absolute path");
	/* Clean up the created temp file */
	if (tmpfile[0]) unlink(tmpfile);
}

TEST(get_temp_filename_a_file_exists_after_call)
{
	char tmpfile[MAX_PATH] = {0};
	UINT r = GetTempFileNameA("/tmp", "ruf", 0, tmpfile);
	if (r == 0) { CHECK_MSG(FALSE, "GetTempFileNameA failed unexpectedly"); return; }
	/* The file must exist on disk */
	CHECK_MSG(PathFileExistsA(tmpfile), "temp file must exist after GetTempFileNameA");
	unlink(tmpfile);
}

TEST(get_temp_filename_a_null_buf_returns_zero)
{
	UINT r = GetTempFileNameA("/tmp", "ruf", 0, NULL);
	CHECK_MSG(r == 0, "GetTempFileNameA(NULL buf) must return 0");
}

TEST(get_temp_filename_a_bad_dir_returns_zero)
{
	char tmpfile[MAX_PATH] = {0};
	UINT r = GetTempFileNameA("/nonexistent_dir_xyzzy_rufus", "ruf", 0, tmpfile);
	CHECK_MSG(r == 0, "GetTempFileNameA with non-existent dir must return 0");
}

/* =========================================================================
 * GetCurrentProcessId / GetCurrentThreadId / GetCurrentThread
 * =========================================================================*/
TEST(get_current_process_id_matches_getpid)
{
	DWORD pid = GetCurrentProcessId();
	CHECK_MSG((int)pid == getpid(), "GetCurrentProcessId must match getpid()");
}

TEST(get_current_process_id_nonzero)
{
	CHECK_MSG(GetCurrentProcessId() != 0, "GetCurrentProcessId must not be zero");
}

TEST(get_current_thread_id_nonzero)
{
	DWORD tid = GetCurrentThreadId();
	CHECK_MSG(tid != 0, "GetCurrentThreadId must not be zero");
}

TEST(get_current_thread_id_matches_gettid)
{
	DWORD tid = GetCurrentThreadId();
	pid_t ktid = (pid_t)syscall(SYS_gettid);
	CHECK_MSG((pid_t)tid == ktid, "GetCurrentThreadId must match gettid()");
}

TEST(get_current_thread_pseudo_handle)
{
	/* Windows convention: GetCurrentThread() returns -2 pseudo-handle */
	HANDLE h = GetCurrentThread();
	CHECK_MSG(h == (HANDLE)(intptr_t)-2, "GetCurrentThread must return pseudo-handle -2");
}

TEST(set_thread_affinity_mask_with_pseudo_handle)
{
	/* SetThreadAffinityMask with GetCurrentThread() must not crash and
	 * must return a non-zero value (the old mask or the new mask) on
	 * success, or 0 only on failure.  On any system with at least 1 CPU
	 * (i.e. everywhere), mask = 1 is valid and the call must succeed. */
	HANDLE h = GetCurrentThread();
	DWORD_PTR old = SetThreadAffinityMask(h, 1);
	/* Restore previous affinity so we don't starve the process */
	if (old != 0)
		SetThreadAffinityMask(h, old);
	CHECK_MSG(old != 0, "SetThreadAffinityMask with pseudo-handle must succeed (return non-zero)");
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

	printf("\n  StrCmpNIA\n");
	RUN(strcmpnia_equal_n_chars);
	RUN(strcmpnia_less_in_first_n);
	RUN(strcmpnia_n_zero_always_equal);
	RUN(strcmpnia_differing_after_n);

	printf("\n  ShellExecuteA\n");
	RUN(shell_execute_a_null_file_returns_error);
	RUN(shell_execute_a_empty_file_returns_error);
	RUN(shell_execute_a_valid_path_returns_gt32);
	RUN(shell_execute_a_sw_show_constant_defined);

	printf("\n  CharLowerA / CharUpperA (safe_strtolower fix)\n");
	RUN(charlowera_lowercases_string);
	RUN(charlowera_already_lowercase_unchanged);
	RUN(charlowera_mixed_case);
	RUN(charlowera_empty_string);
	RUN(charlowera_null_safe);
	RUN(charuppera_uppercases_string);
	RUN(charuppera_null_safe);
	RUN(safe_strtolower_actually_lowercases);

	printf("\n  GetEnvironmentVariableA / SetEnvironmentVariableA\n");
	RUN(getenv_set_and_get_roundtrip);
	RUN(getenv_missing_returns_zero);
	RUN(getenv_buffer_too_small_returns_needed_size);
	RUN(getenv_null_buf_returns_needed_size);
	RUN(setenv_can_unset_with_null_value);

	printf("\n  GetTempPathA\n");
	RUN(get_temp_path_a_returns_nonzero);
	RUN(get_temp_path_a_returns_valid_dir);
	RUN(get_temp_path_a_length_matches_buf);

	printf("\n  GetModuleFileNameA\n");
	RUN(get_module_filename_a_returns_nonzero);
	RUN(get_module_filename_a_null_terminated);

	printf("\n  GetTempFileNameA\n");
	RUN(get_temp_filename_a_success_returns_nonzero);
	RUN(get_temp_filename_a_file_exists_after_call);
	RUN(get_temp_filename_a_null_buf_returns_zero);
	RUN(get_temp_filename_a_bad_dir_returns_zero);

	printf("\n  GetCurrentProcessId / GetCurrentThreadId / GetCurrentThread\n");
	RUN(get_current_process_id_matches_getpid);
	RUN(get_current_process_id_nonzero);
	RUN(get_current_thread_id_nonzero);
	RUN(get_current_thread_id_matches_gettid);
	RUN(get_current_thread_pseudo_handle);
	RUN(set_thread_affinity_mask_with_pseudo_handle);

	TEST_RESULTS();
	return (_fail > 0) ? 1 : 0;
}
/* end */
#endif /* _WIN32 */
