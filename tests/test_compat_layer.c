/* test_compat_layer_linux.c — ABI & macro correctness tests for src/linux/compat/
 *
 * Verifies that every key type, typedef, macro, and constant in the Linux
 * compat headers has the expected size / value, preventing silent ABI drift.
 *
 * Covers:
 *   windows.h  — primitive types, HANDLE-family, HRESULT, string types,
 *                 bit-manipulation macros, file constants, error codes
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

/* Pull in every compat header we want to verify */
#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/winioctl.h"

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

	PRINT_RESULTS();
	return (g_failed == 0) ? 0 : 1;
}

#endif /* !_WIN32 */
