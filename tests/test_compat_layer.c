/* test_compat_layer_linux.c — ABI & macro correctness tests for src/linux/compat/
 *
 * Verifies that every key type, typedef, macro, and constant in the Linux
 * compat headers has the expected size / value, preventing silent ABI drift.
 *
 * Covers:
 *   windows.h  — primitive types, HANDLE-family, HRESULT, string types,
 *                 bit-manipulation macros, file constants, error codes,
 *                 CreateFileA/ReadFile/WriteFile/CloseHandle,
 *                 InterlockedIncrement/Decrement/Exchange/CompareExchange
 *   winioctl.h — PARTITION_STYLE enum
 *   winerror.h — standard HRESULT / Win32 error constants
 *   shlwapi.h  — already exercised in test_compat_linux; included here only for
 *                compilation smoke-test
 *
 * No GTK, no network, no device I/O — pure compile-time and run-time value checks.
 */
#ifdef _WIN32
#include "framework.h"
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include "framework.h"

#include <stdint.h>
#include <stddef.h>
#include <wchar.h>
#include <string.h>

/* Pull in every compat header we want to verify */
#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/winioctl.h"
#include "../src/linux/compat/shlwapi.h"

/* ==========================================================================
 * Primitive integer type sizes
 * ========================================================================== */

TEST(sizeof_byte_is_1)
{
	CHECK_MSG(sizeof(BYTE) == 1, "sizeof(BYTE) must be 1");
}

TEST(sizeof_word_is_2)
{
	CHECK_MSG(sizeof(WORD) == 2, "sizeof(WORD) must be 2");
}

TEST(sizeof_dword_is_4)
{
	CHECK_MSG(sizeof(DWORD) == 4, "sizeof(DWORD) must be 4");
}

TEST(sizeof_long_is_4)
{
	CHECK_MSG(sizeof(LONG) == 4, "sizeof(LONG) must be 4 (Windows LONG is always 32-bit)");
}

TEST(sizeof_bool_is_4)
{
	CHECK_MSG(sizeof(BOOL) == sizeof(int), "sizeof(BOOL) must equal sizeof(int)");
}

TEST(sizeof_dword64_is_8)
{
	CHECK_MSG(sizeof(DWORD64) == 8, "sizeof(DWORD64) must be 8");
}

TEST(sizeof_ulonglong_is_8)
{
	CHECK_MSG(sizeof(ULONGLONG) == 8, "sizeof(ULONGLONG) must be 8");
}

TEST(sizeof_dwordlong_is_8)
{
	CHECK_MSG(sizeof(DWORDLONG) == 8, "sizeof(DWORDLONG) must be 8");
}

TEST(sizeof_longlong_is_8)
{
	CHECK_MSG(sizeof(LONGLONG) == 8, "sizeof(LONGLONG) must be 8");
}

TEST(sizeof_long64_is_8)
{
	CHECK_MSG(sizeof(LONG64) == 8, "sizeof(LONG64) must be 8");
}

TEST(sizeof_ulong64_is_8)
{
	CHECK_MSG(sizeof(ULONG64) == 8, "sizeof(ULONG64) must be 8");
}

/* --- fixed-width aliases ------------------------------------------------- */

TEST(sizeof_uint8_is_1)  { CHECK_MSG(sizeof(UINT8)  == 1, "sizeof(UINT8) must be 1");  }
TEST(sizeof_uint16_is_2) { CHECK_MSG(sizeof(UINT16) == 2, "sizeof(UINT16) must be 2"); }
TEST(sizeof_uint32_is_4) { CHECK_MSG(sizeof(UINT32) == 4, "sizeof(UINT32) must be 4"); }
TEST(sizeof_uint64_is_8) { CHECK_MSG(sizeof(UINT64) == 8, "sizeof(UINT64) must be 8"); }
TEST(sizeof_int8_is_1)   { CHECK_MSG(sizeof(INT8)   == 1, "sizeof(INT8) must be 1");   }
TEST(sizeof_int16_is_2)  { CHECK_MSG(sizeof(INT16)  == 2, "sizeof(INT16) must be 2");  }
TEST(sizeof_int32_is_4)  { CHECK_MSG(sizeof(INT32)  == 4, "sizeof(INT32) must be 4");  }
TEST(sizeof_int64_is_8)  { CHECK_MSG(sizeof(INT64)  == 8, "sizeof(INT64) must be 8");  }

/* ==========================================================================
 * Pointer-sized types  (varies by architecture — must equal sizeof(void*))
 * ========================================================================== */

TEST(sizeof_handle_is_pointer)
{
	CHECK_MSG(sizeof(HANDLE) == sizeof(void *),
	          "sizeof(HANDLE) must equal sizeof(void*)");
}

TEST(sizeof_ulong_ptr_is_pointer)
{
	CHECK_MSG(sizeof(ULONG_PTR) == sizeof(void *),
	          "sizeof(ULONG_PTR) must equal sizeof(void*)");
}

TEST(sizeof_uint_ptr_is_pointer)
{
	CHECK_MSG(sizeof(UINT_PTR) == sizeof(void *),
	          "sizeof(UINT_PTR) must equal sizeof(void*)");
}

TEST(sizeof_long_ptr_is_pointer)
{
	CHECK_MSG(sizeof(LONG_PTR) == sizeof(void *),
	          "sizeof(LONG_PTR) must equal sizeof(void*)");
}

TEST(sizeof_int_ptr_is_pointer)
{
	CHECK_MSG(sizeof(INT_PTR) == sizeof(void *),
	          "sizeof(INT_PTR) must equal sizeof(void*)");
}

TEST(sizeof_size_t_matches)
{
	CHECK_MSG(sizeof(SIZE_T) == sizeof(size_t),
	          "sizeof(SIZE_T) must equal sizeof(size_t)");
}

TEST(sizeof_ssize_t_matches)
{
	CHECK_MSG(sizeof(SSIZE_T) == sizeof(ssize_t),
	          "sizeof(SSIZE_T) must equal sizeof(ssize_t)");
}

/* ==========================================================================
 * HRESULT / NTSTATUS
 * ========================================================================== */

TEST(sizeof_hresult_is_4)
{
	CHECK_MSG(sizeof(HRESULT) == 4, "sizeof(HRESULT) must be 4");
}

TEST(sizeof_ntstatus_is_4)
{
	CHECK_MSG(sizeof(NTSTATUS) == 4, "sizeof(NTSTATUS) must be 4");
}

/* ==========================================================================
 * String / character types
 * ========================================================================== */

TEST(sizeof_tchar_is_1)
{
	/* On Linux TCHAR == char (no UNICODE build) */
	CHECK_MSG(sizeof(TCHAR) == 1, "sizeof(TCHAR) must be 1 on Linux (non-Unicode)");
}

TEST(sizeof_wchar_matches_wchar_t)
{
	CHECK_MSG(sizeof(WCHAR) == sizeof(wchar_t),
	          "sizeof(WCHAR) must equal sizeof(wchar_t)");
}

/* ==========================================================================
 * Standard constants
 * ========================================================================== */

TEST(true_is_nonzero)
{
	CHECK_MSG(TRUE != 0, "TRUE must be non-zero");
}

TEST(false_is_zero)
{
	CHECK_MSG(FALSE == 0, "FALSE must be 0");
}

TEST(max_path_is_260)
{
	CHECK_MSG(MAX_PATH == 260, "MAX_PATH must be 260");
}

TEST(invalid_handle_value)
{
	/* INVALID_HANDLE_VALUE == (HANDLE)(LONG_PTR)-1 — i.e. all-bits-set pointer */
	HANDLE h = INVALID_HANDLE_VALUE;
	CHECK_MSG((intptr_t)h == -1,
	          "INVALID_HANDLE_VALUE must cast to -1 as intptr_t");
}

TEST(invalid_file_size)
{
	CHECK_MSG(INVALID_FILE_SIZE == (DWORD)0xFFFFFFFF,
	          "INVALID_FILE_SIZE must be 0xFFFFFFFF");
}

/* ==========================================================================
 * HRESULT constants and SUCCEEDED / FAILED macros
 * ========================================================================== */

TEST(s_ok_is_zero)
{
	CHECK_MSG(S_OK == 0, "S_OK must be 0");
}

TEST(s_false_is_one)
{
	CHECK_MSG(S_FALSE == 1, "S_FALSE must be 1");
}

TEST(e_fail_value)
{
	CHECK_MSG((DWORD)E_FAIL == 0x80004005UL,
	          "E_FAIL must be 0x80004005");
}

TEST(e_notimpl_value)
{
	CHECK_MSG((DWORD)E_NOTIMPL == 0x80004001UL,
	          "E_NOTIMPL must be 0x80004001");
}

TEST(e_outofmemory_value)
{
	CHECK_MSG((DWORD)E_OUTOFMEMORY == 0x8007000EUL,
	          "E_OUTOFMEMORY must be 0x8007000E");
}

TEST(e_invalidarg_value)
{
	CHECK_MSG((DWORD)E_INVALIDARG == 0x80070057UL,
	          "E_INVALIDARG must be 0x80070057");
}

TEST(succeeded_s_ok)
{
	CHECK_MSG(SUCCEEDED(S_OK) != 0, "SUCCEEDED(S_OK) must be true");
}

TEST(succeeded_s_false)
{
	CHECK_MSG(SUCCEEDED(S_FALSE) != 0, "SUCCEEDED(S_FALSE) must be true");
}

TEST(succeeded_e_fail)
{
	CHECK_MSG(!SUCCEEDED(E_FAIL), "SUCCEEDED(E_FAIL) must be false");
}

TEST(failed_s_ok)
{
	CHECK_MSG(!FAILED(S_OK), "FAILED(S_OK) must be false");
}

TEST(failed_e_fail)
{
	CHECK_MSG(FAILED(E_FAIL) != 0, "FAILED(E_FAIL) must be true");
}

/* ==========================================================================
 * Win32 error codes
 * ========================================================================== */

TEST(error_success_is_zero)
{
	CHECK_MSG(ERROR_SUCCESS == 0, "ERROR_SUCCESS must be 0");
}

TEST(error_access_denied_is_5)
{
	CHECK_MSG(ERROR_ACCESS_DENIED == 5, "ERROR_ACCESS_DENIED must be 5");
}

TEST(error_invalid_handle_is_6)
{
	CHECK_MSG(ERROR_INVALID_HANDLE == 6, "ERROR_INVALID_HANDLE must be 6");
}

TEST(error_insufficient_buffer_is_122)
{
	CHECK_MSG(ERROR_INSUFFICIENT_BUFFER == 122,
	          "ERROR_INSUFFICIENT_BUFFER must be 122");
}

/* ==========================================================================
 * Bit-manipulation macros
 * ========================================================================== */

TEST(loword_extracts_low_16)
{
	CHECK_MSG(LOWORD(0x12345678UL) == 0x5678,
	          "LOWORD(0x12345678) must be 0x5678");
}

TEST(hiword_extracts_high_16)
{
	CHECK_MSG(HIWORD(0x12345678UL) == 0x1234,
	          "HIWORD(0x12345678) must be 0x1234");
}

TEST(lobyte_extracts_low_8)
{
	CHECK_MSG(LOBYTE(0x1234U) == 0x34,
	          "LOBYTE(0x1234) must be 0x34");
}

TEST(hibyte_extracts_high_8)
{
	CHECK_MSG(HIBYTE(0x1234U) == 0x12,
	          "HIBYTE(0x1234) must be 0x12");
}

TEST(makeword_combines_bytes)
{
	/* MAKEWORD(low, high) → (high << 8) | low */
	CHECK_MSG(MAKEWORD(0xAB, 0xCD) == 0xCDAB,
	          "MAKEWORD(0xAB,0xCD) must be 0xCDAB");
}

TEST(makelong_combines_words)
{
	/* MAKELONG(low, high) → (high << 16) | low */
	CHECK_MSG((DWORD)MAKELONG(0x5678, 0x1234) == 0x12345678UL,
	          "MAKELONG(0x5678,0x1234) must be 0x12345678");
}

TEST(makelong_round_trips_loword)
{
	LONG l = MAKELONG(0xABCD, 0x1234);
	CHECK_MSG(LOWORD(l) == 0xABCD,
	          "LOWORD(MAKELONG(0xABCD,0x1234)) must recover 0xABCD");
}

TEST(makelong_round_trips_hiword)
{
	LONG l = MAKELONG(0xABCD, 0x1234);
	CHECK_MSG(HIWORD(l) == 0x1234,
	          "HIWORD(MAKELONG(0xABCD,0x1234)) must recover 0x1234");
}

/* ==========================================================================
 * File / I/O constants
 * ========================================================================== */

TEST(generic_read_value)
{
	CHECK_MSG(GENERIC_READ == 0x80000000UL,
	          "GENERIC_READ must be 0x80000000");
}

TEST(generic_write_value)
{
	CHECK_MSG(GENERIC_WRITE == 0x40000000UL,
	          "GENERIC_WRITE must be 0x40000000");
}

TEST(open_existing_is_3)
{
	CHECK_MSG(OPEN_EXISTING == 3, "OPEN_EXISTING must be 3");
}

TEST(create_always_is_2)
{
	CHECK_MSG(CREATE_ALWAYS == 2, "CREATE_ALWAYS must be 2");
}

/* ==========================================================================
 * File attribute constants
 * ========================================================================== */

TEST(file_attribute_readonly_is_1)
{
	CHECK_MSG(FILE_ATTRIBUTE_READONLY == 0x01,
	          "FILE_ATTRIBUTE_READONLY must be 0x01");
}

TEST(file_attribute_directory_is_0x10)
{
	CHECK_MSG(FILE_ATTRIBUTE_DIRECTORY == 0x10,
	          "FILE_ATTRIBUTE_DIRECTORY must be 0x10");
}

TEST(file_attribute_normal_is_0x80)
{
	CHECK_MSG(FILE_ATTRIBUTE_NORMAL == 0x80,
	          "FILE_ATTRIBUTE_NORMAL must be 0x80");
}

/* ==========================================================================
 * winioctl.h — PARTITION_STYLE enum
 * ========================================================================== */

TEST(partition_style_mbr_is_0)
{
	CHECK_MSG(PARTITION_STYLE_MBR == 0, "PARTITION_STYLE_MBR must be 0");
}

TEST(partition_style_gpt_is_1)
{
	CHECK_MSG(PARTITION_STYLE_GPT == 1, "PARTITION_STYLE_GPT must be 1");
}

TEST(partition_style_raw_is_2)
{
	CHECK_MSG(PARTITION_STYLE_RAW == 2, "PARTITION_STYLE_RAW must be 2");
}

/* ==========================================================================
 * HANDLE-derived pointer types (all must have pointer width)
 * ========================================================================== */

TEST(sizeof_hwnd_is_pointer)
{
	CHECK_MSG(sizeof(HWND) == sizeof(void *), "sizeof(HWND) must equal sizeof(void*)");
}

TEST(sizeof_hmodule_is_pointer)
{
	CHECK_MSG(sizeof(HMODULE) == sizeof(void *), "sizeof(HMODULE) must equal sizeof(void*)");
}

TEST(sizeof_hkey_is_pointer)
{
	CHECK_MSG(sizeof(HKEY) == sizeof(void *), "sizeof(HKEY) must equal sizeof(void*)");
}

/* ==========================================================================
 * Signed / unsigned relationships
 * ========================================================================== */

TEST(dword_is_unsigned)
{
	/* Arithmetic right-shift / wrap-around must behave like unsigned */
	DWORD d = (DWORD)-1;
	CHECK_MSG(d > 0, "DWORD must be unsigned (all-ones must be > 0)");
}

TEST(long_is_signed)
{
	LONG l = -1;
	CHECK_MSG(l < 0, "LONG must be signed (-1 must be < 0)");
}

TEST(hresult_failure_codes_are_negative)
{
	/* Failure HRESULTs have the top bit set, and HRESULT == LONG (signed) */
	CHECK_MSG(E_FAIL < 0,  "E_FAIL (signed HRESULT) must be negative");
	CHECK_MSG(E_NOTIMPL < 0, "E_NOTIMPL (signed HRESULT) must be negative");
}

/* ==========================================================================
 * String case-folding: _stricmp / _strnicmp
 * ========================================================================== */

TEST(stricmp_equal_same_case)
{
	CHECK_MSG(_stricmp("hello", "hello") == 0, "_stricmp equal strings must return 0");
}

TEST(stricmp_equal_diff_case)
{
	CHECK_MSG(_stricmp("HELLO", "hello") == 0, "_stricmp case-insensitive must return 0");
	CHECK_MSG(_stricmp("HeLLo", "hElLO") == 0, "_stricmp mixed case must return 0");
}

TEST(stricmp_less)
{
	CHECK_MSG(_stricmp("abc", "xyz") < 0, "_stricmp('abc','xyz') must be negative");
}

TEST(stricmp_greater)
{
	CHECK_MSG(_stricmp("xyz", "abc") > 0, "_stricmp('xyz','abc') must be positive");
}

TEST(strnicmp_n_chars)
{
	CHECK_MSG(_strnicmp("HELLO_WORLD", "hello_xyz", 5) == 0,
	          "_strnicmp first 5 chars equal (case insensitive)");
	CHECK_MSG(_strnicmp("HELLO_WORLD", "hello_xyz", 7) != 0,
	          "_strnicmp first 7 chars differ (W vs x)");
}

/* ==========================================================================
 * GetFileAttributesA
 * ========================================================================== */

TEST(get_file_attrs_real_file)
{
	/* /etc/passwd exists on virtually every POSIX system */
	DWORD a = GetFileAttributesA("/etc/passwd");
	CHECK_MSG(a != INVALID_FILE_ATTRIBUTES, "GetFileAttributesA on real file must not return INVALID");
	CHECK_MSG(!(a & FILE_ATTRIBUTE_DIRECTORY), "regular file must not have DIRECTORY attribute");
}

TEST(get_file_attrs_directory)
{
	DWORD a = GetFileAttributesA("/tmp");
	CHECK_MSG(a != INVALID_FILE_ATTRIBUTES, "GetFileAttributesA on /tmp must not return INVALID");
	CHECK_MSG(a & FILE_ATTRIBUTE_DIRECTORY, "/tmp must have FILE_ATTRIBUTE_DIRECTORY set");
}

TEST(get_file_attrs_missing_returns_invalid)
{
	DWORD a = GetFileAttributesA("/nonexistent_path_xyzzy_rufus");
	CHECK_MSG(a == INVALID_FILE_ATTRIBUTES,
	          "GetFileAttributesA on missing path must return INVALID_FILE_ATTRIBUTES");
}

TEST(get_file_attrs_null_returns_invalid)
{
	DWORD a = GetFileAttributesA(NULL);
	CHECK_MSG(a == INVALID_FILE_ATTRIBUTES,
	          "GetFileAttributesA(NULL) must return INVALID_FILE_ATTRIBUTES");
}

/* ==========================================================================
 * GetCurrentDirectoryA / SetCurrentDirectoryA
 * ========================================================================== */

TEST(get_current_directory_a_returns_nonzero)
{
	char buf[MAX_PATH] = {0};
	DWORD r = GetCurrentDirectoryA(sizeof(buf), buf);
	CHECK_MSG(r > 0, "GetCurrentDirectoryA must return non-zero length");
	CHECK_MSG(buf[0] == '/', "GetCurrentDirectoryA must return an absolute path");
}

TEST(get_current_directory_a_length_matches)
{
	char buf[MAX_PATH] = {0};
	DWORD r = GetCurrentDirectoryA(sizeof(buf), buf);
	CHECK_MSG(r == (DWORD)strlen(buf),
	          "GetCurrentDirectoryA return value must equal strlen(buf)");
}

TEST(set_current_directory_a_roundtrip)
{
	char orig[MAX_PATH] = {0};
	GetCurrentDirectoryA(sizeof(orig), orig);

	/* cd to /tmp and back */
	BOOL ok = SetCurrentDirectoryA("/tmp");
	CHECK_MSG(ok, "SetCurrentDirectoryA('/tmp') must succeed");

	char cwd[MAX_PATH] = {0};
	GetCurrentDirectoryA(sizeof(cwd), cwd);
	/* /tmp may be a symlink; just check it is non-empty and starts with '/' */
	CHECK_MSG(cwd[0] == '/', "After SetCurrentDirectory, cwd must be absolute path");

	/* Restore original directory */
	SetCurrentDirectoryA(orig);
}

/* ==========================================================================
 * sprintf_s / strcpy_s / strcat_s bounds safety
 * ========================================================================== */

TEST(sprintf_s_basic)
{
	char buf[32] = {0};
	int r = sprintf_s(buf, sizeof(buf), "hello %d", 42);
	CHECK_MSG(r > 0, "sprintf_s must return positive on success");
	CHECK_STR_EQ(buf, "hello 42");
}

TEST(strcpy_s_basic)
{
	char dst[16] = {0};
	strcpy_s(dst, sizeof(dst), "hello");
	CHECK_STR_EQ(dst, "hello");
}

TEST(strcpy_s_truncates_and_null_terminates)
{
	char dst[4] = {0};
	strcpy_s(dst, sizeof(dst), "hello_world");
	/* Must be null-terminated even if truncated */
	CHECK_MSG(dst[3] == '\0', "strcpy_s must null-terminate even on truncation");
}

TEST(strcat_s_basic)
{
	char buf[32] = "hello";
	strcat_s(buf, sizeof(buf), " world");
	CHECK_STR_EQ(buf, "hello world");
}

/* ==========================================================================
 * MultiByteToWideChar / WideCharToMultiByte
 * ========================================================================== */

TEST(multibyte_to_wide_ascii_roundtrip)
{
	wchar_t wbuf[32] = {0};
	int r = MultiByteToWideChar(CP_ACP, 0, "hello", -1, wbuf, 32);
	CHECK_MSG(r > 0, "MultiByteToWideChar must return positive on success");
	/* wide string must contain "hello" */
	CHECK_MSG(wbuf[0] == L'h', "first wide char must be 'h'");
	CHECK_MSG(wbuf[4] == L'o', "fifth wide char must be 'o'");
	CHECK_MSG(wbuf[5] == L'\0', "sixth wide char must be null terminator");
}

TEST(multibyte_to_wide_query_size)
{
	/* Calling with wc_sz == 0 should return needed size without writing */
	int needed = MultiByteToWideChar(CP_ACP, 0, "hello", -1, NULL, 0);
	CHECK_MSG(needed > 0, "MultiByteToWideChar size query must return positive");
}

TEST(multibyte_to_wide_null_input_returns_zero)
{
	wchar_t wbuf[32] = {0};
	int r = MultiByteToWideChar(CP_ACP, 0, NULL, -1, wbuf, 32);
	CHECK_MSG(r == 0, "MultiByteToWideChar(NULL) must return 0");
}

TEST(wide_to_multibyte_ascii_roundtrip)
{
	char buf[32] = {0};
	int r = WideCharToMultiByte(CP_ACP, 0, L"world", -1, buf, sizeof(buf), NULL, NULL);
	CHECK_MSG(r > 0, "WideCharToMultiByte must return positive on success");
	CHECK_STR_EQ(buf, "world");
}

TEST(wide_to_multibyte_query_size)
{
	int needed = WideCharToMultiByte(CP_ACP, 0, L"world", -1, NULL, 0, NULL, NULL);
	CHECK_MSG(needed > 0, "WideCharToMultiByte size query must return positive");
}

TEST(wide_to_multibyte_null_input_returns_zero)
{
	char buf[32] = {0};
	int r = WideCharToMultiByte(CP_ACP, 0, NULL, -1, buf, sizeof(buf), NULL, NULL);
	CHECK_MSG(r == 0, "WideCharToMultiByte(NULL) must return 0");
}

/* ==========================================================================
 * CreateDirectoryA / RemoveDirectoryA / DeleteFileA / MoveFileExA
 * ========================================================================== */

TEST(create_and_remove_directory)
{
	const char *dir = "/tmp/rufus_test_dir_compat_layer";
	/* Remove if it exists from a previous failed run */
	rmdir(dir);

	BOOL ok = CreateDirectoryA(dir, NULL);
	CHECK_MSG(ok, "CreateDirectoryA must succeed on valid path");
	CHECK_MSG(PathFileExistsA(dir), "Directory must exist after CreateDirectoryA");

	BOOL ok2 = RemoveDirectoryA(dir);
	CHECK_MSG(ok2, "RemoveDirectoryA must succeed on empty directory");
	CHECK_MSG(!PathFileExistsA(dir), "Directory must not exist after RemoveDirectoryA");
}

TEST(create_directory_already_exists_returns_false)
{
	/* /tmp always exists */
	BOOL ok = CreateDirectoryA("/tmp", NULL);
	CHECK_MSG(!ok, "CreateDirectoryA must fail if directory already exists");
}

TEST(delete_file_a_success)
{
	/* Create a temp file then delete it */
	char tmpf[MAX_PATH] = {0};
	GetTempFileNameA("/tmp", "ruf", 0, tmpf);
	CHECK_MSG(tmpf[0] != '\0', "GetTempFileNameA must provide a path");

	BOOL ok = DeleteFileA(tmpf);
	CHECK_MSG(ok, "DeleteFileA must succeed on existing file");
	CHECK_MSG(!PathFileExistsA(tmpf), "File must not exist after DeleteFileA");
}

TEST(delete_file_a_missing_returns_false)
{
	BOOL ok = DeleteFileA("/tmp/rufus_nonexistent_file_xyzzy_99.txt");
	CHECK_MSG(!ok, "DeleteFileA must fail on non-existent file");
}

TEST(move_file_ex_a_rename)
{
	char src[MAX_PATH] = {0};
	const char *dst = "/tmp/rufus_test_moved_compat.tmp";
	GetTempFileNameA("/tmp", "ruf", 0, src);
	CHECK_MSG(src[0] != '\0', "GetTempFileNameA must provide source path");

	/* Remove destination if it exists */
	unlink(dst);

	BOOL ok = MoveFileExA(src, dst, 0);
	CHECK_MSG(ok, "MoveFileExA must succeed");
	CHECK_MSG(!PathFileExistsA(src), "Source must not exist after MoveFileExA");
	CHECK_MSG(PathFileExistsA(dst), "Destination must exist after MoveFileExA");

	unlink(dst);
}

/* ==========================================================================
 * InterlockedIncrement / InterlockedDecrement / InterlockedExchange /
 * InterlockedCompareExchange
 * ========================================================================== */

TEST(interlocked_increment_returns_new_value)
{
	volatile LONG v = 0;
	LONG r = InterlockedIncrement(&v);
	CHECK_MSG(r == 1, "InterlockedIncrement must return new value (1)");
	CHECK_MSG(v == 1, "InterlockedIncrement must update the variable");
}

TEST(interlocked_decrement_returns_new_value)
{
	volatile LONG v = 5;
	LONG r = InterlockedDecrement(&v);
	CHECK_MSG(r == 4, "InterlockedDecrement must return new value (4)");
	CHECK_MSG(v == 4, "InterlockedDecrement must update the variable");
}

TEST(interlocked_exchange_sets_value)
{
	volatile LONG v = 10;
	LONG old = InterlockedExchange(&v, 99);
	CHECK_MSG(old == 10, "InterlockedExchange must return previous value");
	CHECK_MSG(v == 99, "InterlockedExchange must set the new value");
}

TEST(interlocked_compare_exchange_success)
{
	volatile LONG v = 42;
	/* Comparand matches — exchange should happen */
	LONG old = InterlockedCompareExchange(&v, 100, 42);
	CHECK_MSG(old == 42, "InterlockedCompareExchange must return old value on success");
	CHECK_MSG(v == 100, "InterlockedCompareExchange must set new value when comparand matches");
}

TEST(interlocked_compare_exchange_failure)
{
	volatile LONG v = 42;
	/* Comparand does not match — exchange must NOT happen */
	LONG old = InterlockedCompareExchange(&v, 100, 99);
	CHECK_MSG(old == 42, "InterlockedCompareExchange must return old value on failure");
	CHECK_MSG(v == 42, "InterlockedCompareExchange must not change value when comparand mismatches");
}

/* ==========================================================================
 * CreateFileA / ReadFile / WriteFile / CloseHandle
 * ========================================================================== */

TEST(createfile_open_existing_fails_for_missing_file)
{
	HANDLE h = CreateFileA("/tmp/rufus_compat_layer_nonexistent_xyz.tmp",
	                       GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	CHECK_MSG(h == INVALID_HANDLE_VALUE,
	          "CreateFileA with OPEN_EXISTING must return INVALID_HANDLE_VALUE for missing file");
}

TEST(createfile_create_always_creates_file)
{
	const char *path = "/tmp/rufus_compat_layer_createfile_test.tmp";
	unlink(path);
	HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	CHECK_MSG(h != INVALID_HANDLE_VALUE, "CreateFileA CREATE_ALWAYS must succeed");
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
	CHECK_MSG(PathFileExistsA(path), "CreateFileA CREATE_ALWAYS must create the file on disk");
	unlink(path);
}

TEST(writefile_and_readfile_roundtrip)
{
	const char *path = "/tmp/rufus_compat_layer_rw_test.tmp";
	const char payload[] = "hello rufus compat";
	unlink(path);

	/* Write */
	HANDLE hw = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	CHECK_MSG(hw != INVALID_HANDLE_VALUE, "CreateFileA for write must succeed");
	if (hw == INVALID_HANDLE_VALUE) { return; }
	DWORD written = 0;
	BOOL wok = WriteFile(hw, payload, sizeof(payload), &written, NULL);
	CloseHandle(hw);
	CHECK_MSG(wok, "WriteFile must return TRUE");
	CHECK_MSG(written == sizeof(payload), "WriteFile must write all bytes");

	/* Read back */
	HANDLE hr = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	CHECK_MSG(hr != INVALID_HANDLE_VALUE, "CreateFileA for read must succeed");
	if (hr == INVALID_HANDLE_VALUE) { unlink(path); return; }
	char buf[64] = {0};
	DWORD nread = 0;
	BOOL rok = ReadFile(hr, buf, sizeof(buf), &nread, NULL);
	CloseHandle(hr);
	CHECK_MSG(rok, "ReadFile must return TRUE");
	CHECK_MSG(nread == sizeof(payload), "ReadFile must read all bytes written");
	CHECK_MSG(memcmp(buf, payload, sizeof(payload)) == 0, "ReadFile content must match WriteFile content");
	unlink(path);
}

TEST(closehandle_invalid_returns_false)
{
	BOOL r = CloseHandle(INVALID_HANDLE_VALUE);
	CHECK_MSG(!r, "CloseHandle(INVALID_HANDLE_VALUE) must return FALSE");
}

TEST(closehandle_null_returns_false)
{
	BOOL r = CloseHandle(NULL);
	CHECK_MSG(!r, "CloseHandle(NULL) must return FALSE");
}

TEST(getfilesizeex_after_write)
{
	const char *path = "/tmp/rufus_compat_layer_fsize_test.tmp";
	const char data[] = "0123456789";  /* 11 bytes including null */
	unlink(path);

	HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	CHECK_MSG(h != INVALID_HANDLE_VALUE, "CreateFileA must succeed for GetFileSizeEx test");
	if (h == INVALID_HANDLE_VALUE) { return; }

	DWORD written = 0;
	WriteFile(h, data, sizeof(data), &written, NULL);
	CloseHandle(h);

	HANDLE hr = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	CHECK_MSG(hr != INVALID_HANDLE_VALUE, "CreateFileA for read must succeed");
	if (hr == INVALID_HANDLE_VALUE) { unlink(path); return; }

	LARGE_INTEGER sz; sz.QuadPart = 0;
	BOOL ok = GetFileSizeEx(hr, &sz);
	CloseHandle(hr);
	unlink(path);

	CHECK_MSG(ok, "GetFileSizeEx must return TRUE for open file");
	CHECK_MSG(sz.QuadPart == (LONGLONG)sizeof(data),
	          "GetFileSizeEx must return correct file size");
}

TEST(setfilepointerex_seek_set)
{
	const char *path = "/tmp/rufus_compat_layer_seek_test.tmp";
	const char data[] = "ABCDEFGHIJ";
	unlink(path);

	HANDLE hw = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hw == INVALID_HANDLE_VALUE) { return; }
	DWORD wr = 0;
	WriteFile(hw, data, sizeof(data), &wr, NULL);
	CloseHandle(hw);

	HANDLE h = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	CHECK_MSG(h != INVALID_HANDLE_VALUE, "CreateFileA must succeed for SetFilePointerEx test");
	if (h == INVALID_HANDLE_VALUE) { unlink(path); return; }

	/* Seek to offset 3 from beginning */
	LARGE_INTEGER dist; dist.QuadPart = 3;
	LARGE_INTEGER newpos; newpos.QuadPart = 0;
	BOOL ok = SetFilePointerEx(h, dist, &newpos, FILE_BEGIN);
	CHECK_MSG(ok, "SetFilePointerEx must return TRUE");
	CHECK_MSG(newpos.QuadPart == 3, "SetFilePointerEx must report new position as 3");

	/* Read one byte — should be 'D' (data[3]) */
	char buf[2] = {0};
	DWORD rd = 0;
	ReadFile(h, buf, 1, &rd, NULL);
	CloseHandle(h);
	unlink(path);

	CHECK_MSG(rd == 1, "ReadFile after seek must read 1 byte");
	CHECK_MSG(buf[0] == data[3], "ReadFile after seek must return byte at seeked offset");
}

/* ==========================================================================
 * LARGE_INTEGER / ULARGE_INTEGER struct layout
 * ========================================================================== */

TEST(large_integer_quadpart_is_8_bytes)
{
	CHECK_MSG(sizeof(LARGE_INTEGER) == 8, "sizeof(LARGE_INTEGER) must be 8");
}

TEST(large_integer_quadpart_set_low_high)
{
	LARGE_INTEGER li;
	li.QuadPart = (LONGLONG)0x0000000100000002LL;
	CHECK_MSG(li.LowPart  == 0x00000002U, "LARGE_INTEGER LowPart must be low 32 bits");
	CHECK_MSG(li.HighPart == 0x00000001,  "LARGE_INTEGER HighPart must be high 32 bits");
}

TEST(ularge_integer_quadpart_set_low_high)
{
	ULARGE_INTEGER uli;
	uli.QuadPart = (ULONGLONG)0xFFFFFFFF00000001ULL;
	CHECK_MSG(uli.LowPart  == 0x00000001U, "ULARGE_INTEGER LowPart must be low 32 bits");
	CHECK_MSG(uli.HighPart == 0xFFFFFFFFU, "ULARGE_INTEGER HighPart must be high 32 bits");
}

TEST(large_integer_u_member_aliases_direct_fields)
{
	LARGE_INTEGER li;
	li.QuadPart = (LONGLONG)0x0000ABCD0000EF12LL;
	CHECK_MSG(li.u.LowPart == li.LowPart, "LARGE_INTEGER .u.LowPart must alias .LowPart");
	CHECK_MSG(li.u.HighPart == li.HighPart, "LARGE_INTEGER .u.HighPart must alias .HighPart");
}

/* ==========================================================================
 * Run all tests
 * ========================================================================== */

int main(void)
{
	RUN_TEST(sizeof_byte_is_1);
	RUN_TEST(sizeof_word_is_2);
	RUN_TEST(sizeof_dword_is_4);
	RUN_TEST(sizeof_long_is_4);
	RUN_TEST(sizeof_bool_is_4);
	RUN_TEST(sizeof_dword64_is_8);
	RUN_TEST(sizeof_ulonglong_is_8);
	RUN_TEST(sizeof_dwordlong_is_8);
	RUN_TEST(sizeof_longlong_is_8);
	RUN_TEST(sizeof_long64_is_8);
	RUN_TEST(sizeof_ulong64_is_8);
	RUN_TEST(sizeof_uint8_is_1);
	RUN_TEST(sizeof_uint16_is_2);
	RUN_TEST(sizeof_uint32_is_4);
	RUN_TEST(sizeof_uint64_is_8);
	RUN_TEST(sizeof_int8_is_1);
	RUN_TEST(sizeof_int16_is_2);
	RUN_TEST(sizeof_int32_is_4);
	RUN_TEST(sizeof_int64_is_8);
	RUN_TEST(sizeof_handle_is_pointer);
	RUN_TEST(sizeof_ulong_ptr_is_pointer);
	RUN_TEST(sizeof_uint_ptr_is_pointer);
	RUN_TEST(sizeof_long_ptr_is_pointer);
	RUN_TEST(sizeof_int_ptr_is_pointer);
	RUN_TEST(sizeof_size_t_matches);
	RUN_TEST(sizeof_ssize_t_matches);
	RUN_TEST(sizeof_hresult_is_4);
	RUN_TEST(sizeof_ntstatus_is_4);
	RUN_TEST(sizeof_tchar_is_1);
	RUN_TEST(sizeof_wchar_matches_wchar_t);
	RUN_TEST(true_is_nonzero);
	RUN_TEST(false_is_zero);
	RUN_TEST(max_path_is_260);
	RUN_TEST(invalid_handle_value);
	RUN_TEST(invalid_file_size);
	RUN_TEST(s_ok_is_zero);
	RUN_TEST(s_false_is_one);
	RUN_TEST(e_fail_value);
	RUN_TEST(e_notimpl_value);
	RUN_TEST(e_outofmemory_value);
	RUN_TEST(e_invalidarg_value);
	RUN_TEST(succeeded_s_ok);
	RUN_TEST(succeeded_s_false);
	RUN_TEST(succeeded_e_fail);
	RUN_TEST(failed_s_ok);
	RUN_TEST(failed_e_fail);
	RUN_TEST(error_success_is_zero);
	RUN_TEST(error_access_denied_is_5);
	RUN_TEST(error_invalid_handle_is_6);
	RUN_TEST(error_insufficient_buffer_is_122);
	RUN_TEST(loword_extracts_low_16);
	RUN_TEST(hiword_extracts_high_16);
	RUN_TEST(lobyte_extracts_low_8);
	RUN_TEST(hibyte_extracts_high_8);
	RUN_TEST(makeword_combines_bytes);
	RUN_TEST(makelong_combines_words);
	RUN_TEST(makelong_round_trips_loword);
	RUN_TEST(makelong_round_trips_hiword);
	RUN_TEST(generic_read_value);
	RUN_TEST(generic_write_value);
	RUN_TEST(open_existing_is_3);
	RUN_TEST(create_always_is_2);
	RUN_TEST(file_attribute_readonly_is_1);
	RUN_TEST(file_attribute_directory_is_0x10);
	RUN_TEST(file_attribute_normal_is_0x80);
	RUN_TEST(partition_style_mbr_is_0);
	RUN_TEST(partition_style_gpt_is_1);
	RUN_TEST(partition_style_raw_is_2);
	RUN_TEST(sizeof_hwnd_is_pointer);
	RUN_TEST(sizeof_hmodule_is_pointer);
	RUN_TEST(sizeof_hkey_is_pointer);
	RUN_TEST(dword_is_unsigned);
	RUN_TEST(long_is_signed);
	RUN_TEST(hresult_failure_codes_are_negative);

	RUN_TEST(stricmp_equal_same_case);
	RUN_TEST(stricmp_equal_diff_case);
	RUN_TEST(stricmp_less);
	RUN_TEST(stricmp_greater);
	RUN_TEST(strnicmp_n_chars);

	RUN_TEST(get_file_attrs_real_file);
	RUN_TEST(get_file_attrs_directory);
	RUN_TEST(get_file_attrs_missing_returns_invalid);
	RUN_TEST(get_file_attrs_null_returns_invalid);

	RUN_TEST(get_current_directory_a_returns_nonzero);
	RUN_TEST(get_current_directory_a_length_matches);
	RUN_TEST(set_current_directory_a_roundtrip);

	RUN_TEST(sprintf_s_basic);
	RUN_TEST(strcpy_s_basic);
	RUN_TEST(strcpy_s_truncates_and_null_terminates);
	RUN_TEST(strcat_s_basic);

	RUN_TEST(multibyte_to_wide_ascii_roundtrip);
	RUN_TEST(multibyte_to_wide_query_size);
	RUN_TEST(multibyte_to_wide_null_input_returns_zero);
	RUN_TEST(wide_to_multibyte_ascii_roundtrip);
	RUN_TEST(wide_to_multibyte_query_size);
	RUN_TEST(wide_to_multibyte_null_input_returns_zero);

	RUN_TEST(create_and_remove_directory);
	RUN_TEST(create_directory_already_exists_returns_false);
	RUN_TEST(delete_file_a_success);
	RUN_TEST(delete_file_a_missing_returns_false);
	RUN_TEST(move_file_ex_a_rename);

	RUN_TEST(interlocked_increment_returns_new_value);
	RUN_TEST(interlocked_decrement_returns_new_value);
	RUN_TEST(interlocked_exchange_sets_value);
	RUN_TEST(interlocked_compare_exchange_success);
	RUN_TEST(interlocked_compare_exchange_failure);

	RUN_TEST(createfile_open_existing_fails_for_missing_file);
	RUN_TEST(createfile_create_always_creates_file);
	RUN_TEST(writefile_and_readfile_roundtrip);
	RUN_TEST(closehandle_invalid_returns_false);
	RUN_TEST(closehandle_null_returns_false);
	RUN_TEST(getfilesizeex_after_write);
	RUN_TEST(setfilepointerex_seek_set);

	RUN_TEST(large_integer_quadpart_is_8_bytes);
	RUN_TEST(large_integer_quadpart_set_low_high);
	RUN_TEST(ularge_integer_quadpart_set_low_high);
	RUN_TEST(large_integer_u_member_aliases_direct_fields);

	PRINT_RESULTS();
	return (g_failed == 0) ? 0 : 1;
}

#endif /* !_WIN32 */
