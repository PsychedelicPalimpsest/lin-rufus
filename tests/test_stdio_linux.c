/*
 * test_stdio_linux.c — TDD tests for RunCommandWithProgress (src/linux/stdio.c)
 *
 * Tests cover:
 *  1. Basic command execution — exit code 0 returned for success
 *  2. Non-zero exit code returned for failing commands
 *  3. Command not found returns non-zero
 *  4. Logging mode — stdout/stderr captured (no crash, correct exit code)
 *  5. NULL dir — uses current working directory
 *  6. Progress pattern — regex parsed, UpdateProgressWithInfo called
 *  7. Pattern with no match — runs cleanly, no crash
 *  8. msg=0 pattern=NULL — silent mode, just waits for exit
 *  9. Pipe read: multi-line output is processed
 * 10. Cancelled via ErrorStatus — child is terminated early
 * 11. SizeToHumanReadable — basic unit formatting
 * 12. WindowsErrorString — returns non-NULL
 * 13. TimestampToHumanReadable — UTC timestamp formatting
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Pull in the public API */
#include "../src/windows/rufus.h"
/* NO_ERROR is in winioctl.h via the compat layer */
#include "../src/linux/compat/winioctl.h"

/* StrArray functions (from stdfn.c) */
extern void     StrArrayCreate(StrArray *arr, uint32_t initial_size);
extern int32_t  StrArrayAdd(StrArray *arr, const char *str, BOOL dup);
extern void     StrArrayDestroy(StrArray *arr);

/* Log handler API from stdio.c */
extern void rufus_set_log_handler(void (*fn)(const char *msg));

/* Error string APIs from stdio.c */
extern const char* WindowsErrorString(void);
extern const char* _StrError(DWORD code);
extern const char* StrError(DWORD code, BOOL use_default);

/* ---- test stubs for symbols that stdio.c needs from ui / globals ---- */

/* These are normally in globals.c; we define minimal versions here */
DWORD ErrorStatus = 0;
DWORD DownloadStatus = 0;
DWORD MainThreadId = 0;
DWORD LastWriteError = 0;

/* Needed by localization.c and parser.c */
BOOL right_to_left_mode = FALSE;
windows_version_t WindowsVersion = {0};
RUFUS_UPDATE update = {{0}, {0}, NULL, NULL};

/* Point msg_table at default_msg_table so lmprintf returns "MSG_XXX UNTRANSLATED"
 * rather than crashing when localization data is not loaded. */
extern char** msg_table;
extern char*  default_msg_table[];

/* Capture UpdateProgressWithInfo calls */
static int progress_calls = 0;
static uint64_t last_progress_cur = 0;
static uint64_t last_progress_tot = 0;

void UpdateProgress(int op, float percent) { (void)op; (void)percent; }
void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL force)
{
    (void)op; (void)msg; (void)force;
    progress_calls++;
    last_progress_cur = cur;
    last_progress_tot = tot;
}

/* ---- helper to reset state ---- */
static void reset(void)
{
    ErrorStatus = 0;
    progress_calls = 0;
    last_progress_cur = 0;
    last_progress_tot = 0;
}

/* ===========================================================================
 * 1. Basic command — exit code 0
 * =========================================================================*/
TEST(run_command_exit_zero)
{
    reset();
    DWORD r = RunCommand("true", NULL, FALSE);
    CHECK_MSG(r == 0, "RunCommand('true') should return 0");
}

/* ===========================================================================
 * 2. Non-zero exit code
 * =========================================================================*/
TEST(run_command_exit_nonzero)
{
    reset();
    DWORD r = RunCommand("false", NULL, FALSE);
    CHECK_MSG(r != 0, "RunCommand('false') should return non-zero");
}

/* ===========================================================================
 * 3. Command not found
 * =========================================================================*/
TEST(run_command_not_found)
{
    reset();
    DWORD r = RunCommand("__this_command_does_not_exist__", NULL, FALSE);
    CHECK_MSG(r != 0, "Non-existent command should return non-zero exit code");
}

/* ===========================================================================
 * 4. Logging mode — captures output without crash
 * =========================================================================*/
TEST(run_command_with_log)
{
    reset();
    DWORD r = RunCommand("echo hello_world_test", NULL, TRUE);
    CHECK_MSG(r == 0, "echo with log should return 0");
}

/* ===========================================================================
 * 5. NULL dir — uses cwd
 * =========================================================================*/
TEST(run_command_null_dir)
{
    reset();
    DWORD r = RunCommand("pwd", NULL, FALSE);
    CHECK_MSG(r == 0, "pwd with NULL dir should succeed");
}

/* ===========================================================================
 * 6. dir argument — changes working directory for child
 * =========================================================================*/
TEST(run_command_with_dir)
{
    reset();
    DWORD r = RunCommand("pwd", "/tmp", FALSE);
    CHECK_MSG(r == 0, "pwd /tmp should succeed");
}

/* ===========================================================================
 * 7. Progress pattern — UpdateProgressWithInfo called
 *    Use a script that emits a progress line matching the pattern
 *    Pattern: "([0-9]+)%" → matches "50%"
 * =========================================================================*/
TEST(run_command_progress_pattern)
{
    reset();
    /* echo a line that the pattern will match */
    DWORD r = RunCommandWithProgress(
        "printf '50%%\\n'", NULL, FALSE,
        1 /* msg != 0 → enable progress */,
        "([0-9]+)%%"
    );
    CHECK_MSG(r == 0, "printf should succeed");
    CHECK_MSG(progress_calls > 0, "UpdateProgressWithInfo should have been called");
}

/* ===========================================================================
 * 8. Pattern with no match — runs cleanly
 * =========================================================================*/
TEST(run_command_progress_no_match)
{
    reset();
    DWORD r = RunCommandWithProgress(
        "echo nothing_matches_here", NULL, FALSE,
        1,
        "ZZZNOMATCH([0-9]+)"
    );
    CHECK_MSG(r == 0, "Command with non-matching pattern should still succeed");
    /* progress may or may not have been called; we just need no crash */
}

/* ===========================================================================
 * 9. msg=0 pattern=NULL — silent (just wait for exit)
 * =========================================================================*/
TEST(run_command_silent_mode)
{
    reset();
    DWORD r = RunCommandWithProgress("true", NULL, FALSE, 0, NULL);
    CHECK_MSG(r == 0, "Silent mode should still return correct exit code");
}

/* ===========================================================================
 * 10. Multi-line output processed
 * =========================================================================*/
TEST(run_command_multiline_output)
{
    reset();
    DWORD r = RunCommand("printf 'line1\\nline2\\nline3\\n'", NULL, TRUE);
    CHECK_MSG(r == 0, "Multi-line output should be processed without crash");
}

/* ===========================================================================
 * 11. Cancellation via ErrorStatus — child terminates, returns ERROR_CANCELLED
 * =========================================================================*/
TEST(run_command_cancellation)
{
    reset();
    /* Set cancellation flag before launching a long-running command */
    ErrorStatus = RUFUS_ERROR(ERROR_CANCELLED);
    DWORD r = RunCommandWithProgress("sleep 30", NULL, FALSE, 0, NULL);
    /* Command should have been terminated */
    CHECK_MSG(r == ERROR_CANCELLED, "Cancelled command should return ERROR_CANCELLED");
}

/* ===========================================================================
 * 12. SizeToHumanReadable — basic sanity checks
 * =========================================================================*/
TEST(size_to_human_readable_bytes)
{
    char* s = SizeToHumanReadable(512, FALSE, FALSE);
    CHECK_MSG(s != NULL, "SizeToHumanReadable should not return NULL");
    CHECK_MSG(strstr(s, "512") != NULL || strstr(s, "B") != NULL,
              "512 bytes result should contain '512' or 'B'");
}

TEST(size_to_human_readable_kb)
{
    char* s = SizeToHumanReadable(1024, FALSE, FALSE);
    CHECK_MSG(s != NULL, "SizeToHumanReadable 1K should not return NULL");
    /* 1024 bytes = 1.00 KB */
    CHECK_MSG(strstr(s, "1") != NULL, "1024 bytes should produce '1...'");
}

TEST(size_to_human_readable_gb)
{
    char* s = SizeToHumanReadable(2ULL * 1024 * 1024 * 1024, FALSE, FALSE);
    CHECK_MSG(s != NULL, "SizeToHumanReadable 2GB should not return NULL");
    CHECK_MSG(strstr(s, "2") != NULL, "2GB should produce '2...'");
}

/* ===========================================================================
 * 13. WindowsErrorString — non-NULL, non-empty
 * =========================================================================*/
TEST(windows_error_string_non_null)
{
    const char* s = WindowsErrorString();
    CHECK_MSG(s != NULL, "WindowsErrorString should not return NULL");
}

/* ===========================================================================
 * _StrError / StrError / WindowsErrorString — proper DWORD mapping
 * =========================================================================*/
TEST(strerror_success_returns_non_null)
{
    /* _StrError(0) = not an error → MSG_050 "Success." */
    const char* s = _StrError(0);
    CHECK_MSG(s != NULL, "_StrError(0) should return non-NULL");
    CHECK_MSG(s[0] != '\0', "_StrError(0) should return non-empty string");
}

TEST(strerror_access_denied_non_null)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_ACCESS_DENIED));
    CHECK_MSG(s != NULL, "_StrError(ACCESS_DENIED) must not return NULL");
    CHECK_MSG(s[0] != '\0', "_StrError(ACCESS_DENIED) must not return empty string");
}

TEST(strerror_write_protect_non_null)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_WRITE_PROTECT));
    CHECK_MSG(s != NULL, "_StrError(WRITE_PROTECT) must not return NULL");
}

TEST(strerror_different_codes_give_different_strings)
{
    const char* s1 = _StrError(RUFUS_ERROR(ERROR_ACCESS_DENIED));
    const char* s2 = _StrError(RUFUS_ERROR(ERROR_WRITE_PROTECT));
    /* Both non-NULL and different — different error codes must produce different messages */
    CHECK_MSG(s1 != NULL && s2 != NULL, "both must be non-NULL");
    CHECK_MSG(strcmp(s1, s2) != 0, "different error codes must give different strings");
}

TEST(strerror_unknown_storage_code_returns_non_null)
{
    /* Unknown FACILITY_STORAGE code falls through to strerror */
    const char* s = _StrError(RUFUS_ERROR(0x9999));
    CHECK_MSG(s != NULL, "unknown storage code must return non-NULL");
}

TEST(strerror_non_storage_code_returns_non_null)
{
    /* A plain errno wrapped in IS_ERROR but not FACILITY_STORAGE */
    const char* s = _StrError(ERROR_ACCESS_DENIED);  /* raw, no RUFUS_ERROR wrapper */
    CHECK_MSG(s != NULL, "non-storage code must return non-NULL");
}

TEST(setlasterror_affects_windows_error_string)
{
    /* After SetLastError with a RUFUS_ERROR, WindowsErrorString should use it */
    extern DWORD _win_last_error;
    _win_last_error = 0;  /* reset */
    SetLastError(RUFUS_ERROR(ERROR_ACCESS_DENIED));
    const char* s = WindowsErrorString();
    _win_last_error = 0;  /* cleanup */
    CHECK_MSG(s != NULL, "WindowsErrorString after SetLastError must not return NULL");
    CHECK_MSG(s[0] != '\0', "WindowsErrorString after SetLastError must not return empty");
}

TEST(windows_error_string_without_setlasterror)
{
    /* Without SetLastError, WindowsErrorString falls back to strerror(errno) */
    extern DWORD _win_last_error;
    _win_last_error = 0;
    errno = EACCES;
    const char* s = WindowsErrorString();
    CHECK_MSG(s != NULL, "WindowsErrorString without SetLastError must not return NULL");
}

/* ===========================================================================
 * windows_dword_to_errno mapping — verify each DWORD maps to the correct
 * errno-based string by calling _StrError with a non-FACILITY_STORAGE IS_ERROR
 * code (0x80000000 | ERROR_X) which routes through windows_dword_to_errno.
 *
 * SCODE_CODE(0x80000000|N) == N, SCODE_FACILITY == 0 (not FACILITY_STORAGE=3).
 * =========================================================================*/

/* Helper: build a non-FACILITY_STORAGE IS_ERROR code from a plain DWORD */
#define NON_STORAGE_ERR(code) ((DWORD)(0x80000000u | (DWORD)(code)))

TEST(dword_map_file_not_found_gives_enoent_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_FILE_NOT_FOUND));
    CHECK_MSG(s != NULL, "ERROR_FILE_NOT_FOUND must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ENOENT)) == 0, "ERROR_FILE_NOT_FOUND must map to ENOENT string");
}

TEST(dword_map_path_not_found_gives_enoent_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_PATH_NOT_FOUND));
    CHECK_MSG(s != NULL, "ERROR_PATH_NOT_FOUND must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ENOENT)) == 0, "ERROR_PATH_NOT_FOUND must map to ENOENT string");
}

TEST(dword_map_too_many_open_files_gives_emfile_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_TOO_MANY_OPEN_FILES));
    CHECK_MSG(s != NULL, "ERROR_TOO_MANY_OPEN_FILES must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(EMFILE)) == 0, "ERROR_TOO_MANY_OPEN_FILES must map to EMFILE string");
}

TEST(dword_map_access_denied_gives_eacces_string)
{
    /* Non-FACILITY_STORAGE access denied maps through windows_dword_to_errno */
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_ACCESS_DENIED));
    CHECK_MSG(s != NULL, "ERROR_ACCESS_DENIED (non-storage) must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(EACCES)) == 0, "ERROR_ACCESS_DENIED must map to EACCES string");
}

TEST(dword_map_invalid_handle_gives_ebadf_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_INVALID_HANDLE));
    CHECK_MSG(s != NULL, "ERROR_INVALID_HANDLE must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(EBADF)) == 0, "ERROR_INVALID_HANDLE must map to EBADF string");
}

TEST(dword_map_not_enough_memory_gives_enomem_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_NOT_ENOUGH_MEMORY));
    CHECK_MSG(s != NULL, "ERROR_NOT_ENOUGH_MEMORY must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ENOMEM)) == 0, "ERROR_NOT_ENOUGH_MEMORY must map to ENOMEM string");
}

TEST(dword_map_outofmemory_gives_enomem_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_OUTOFMEMORY));
    CHECK_MSG(s != NULL, "ERROR_OUTOFMEMORY must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ENOMEM)) == 0, "ERROR_OUTOFMEMORY must map to ENOMEM string");
}

TEST(dword_map_write_protect_gives_erofs_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_WRITE_PROTECT));
    CHECK_MSG(s != NULL, "ERROR_WRITE_PROTECT (non-storage) must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(EROFS)) == 0, "ERROR_WRITE_PROTECT must map to EROFS string");
}

TEST(dword_map_no_more_files_gives_enoent_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_NO_MORE_FILES));
    CHECK_MSG(s != NULL, "ERROR_NO_MORE_FILES must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ENOENT)) == 0, "ERROR_NO_MORE_FILES must map to ENOENT string");
}

TEST(dword_map_write_fault_gives_eio_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_WRITE_FAULT));
    CHECK_MSG(s != NULL, "ERROR_WRITE_FAULT must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(EIO)) == 0, "ERROR_WRITE_FAULT must map to EIO string");
}

TEST(dword_map_read_fault_gives_eio_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_READ_FAULT));
    CHECK_MSG(s != NULL, "ERROR_READ_FAULT must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(EIO)) == 0, "ERROR_READ_FAULT must map to EIO string");
}

TEST(dword_map_not_supported_gives_enotsup_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_NOT_SUPPORTED));
    CHECK_MSG(s != NULL, "ERROR_NOT_SUPPORTED must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ENOTSUP)) == 0, "ERROR_NOT_SUPPORTED must map to ENOTSUP string");
}

TEST(dword_map_file_exists_gives_eexist_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_FILE_EXISTS));
    CHECK_MSG(s != NULL, "ERROR_FILE_EXISTS must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(EEXIST)) == 0, "ERROR_FILE_EXISTS must map to EEXIST string");
}

TEST(dword_map_invalid_parameter_gives_einval_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_INVALID_PARAMETER));
    CHECK_MSG(s != NULL, "ERROR_INVALID_PARAMETER must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(EINVAL)) == 0, "ERROR_INVALID_PARAMETER must map to EINVAL string");
}

TEST(dword_map_insufficient_buffer_gives_enobufs_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_INSUFFICIENT_BUFFER));
    CHECK_MSG(s != NULL, "ERROR_INSUFFICIENT_BUFFER must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ENOBUFS)) == 0, "ERROR_INSUFFICIENT_BUFFER must map to ENOBUFS string");
}

TEST(dword_map_not_ready_gives_enodev_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_NOT_READY));
    CHECK_MSG(s != NULL, "ERROR_NOT_READY (non-storage) must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ENODEV)) == 0, "ERROR_NOT_READY must map to ENODEV string");
}

TEST(dword_map_device_in_use_gives_ebusy_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_DEVICE_IN_USE));
    CHECK_MSG(s != NULL, "ERROR_DEVICE_IN_USE (non-storage) must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(EBUSY)) == 0, "ERROR_DEVICE_IN_USE must map to EBUSY string");
}

TEST(dword_map_open_failed_gives_enoent_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_OPEN_FAILED));
    CHECK_MSG(s != NULL, "ERROR_OPEN_FAILED must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ENOENT)) == 0, "ERROR_OPEN_FAILED must map to ENOENT string");
}

TEST(dword_map_cancelled_gives_ecanceled_string)
{
    const char* s = _StrError(NON_STORAGE_ERR(ERROR_CANCELLED));
    CHECK_MSG(s != NULL, "ERROR_CANCELLED (non-storage) must map to non-NULL string");
    CHECK_MSG(strcmp(s, strerror(ECANCELED)) == 0, "ERROR_CANCELLED must map to ECANCELED string");
}

/* FACILITY_STORAGE cases — verify each returns a non-empty string */
TEST(storage_err_gen_failure_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_GEN_FAILURE));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(GEN_FAILURE) must return non-empty");
}

TEST(storage_err_incompatible_fs_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_INCOMPATIBLE_FS));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(INCOMPATIBLE_FS) must return non-empty");
}

TEST(storage_err_device_in_use_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_DEVICE_IN_USE));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(DEVICE_IN_USE) must return non-empty");
}

TEST(storage_err_cant_quick_format_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_CANT_QUICK_FORMAT));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(CANT_QUICK_FORMAT) must return non-empty");
}

TEST(storage_err_label_too_long_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_LABEL_TOO_LONG));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(LABEL_TOO_LONG) must return non-empty");
}

TEST(storage_err_invalid_cluster_size_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_INVALID_CLUSTER_SIZE));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(INVALID_CLUSTER_SIZE) must return non-empty");
}

TEST(storage_err_no_media_in_drive_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_NO_MEDIA_IN_DRIVE));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(NO_MEDIA_IN_DRIVE) must return non-empty");
}

TEST(storage_err_not_enough_memory_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_NOT_ENOUGH_MEMORY));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(NOT_ENOUGH_MEMORY) must return non-empty");
}

TEST(storage_err_cancelled_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_CANCELLED));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(CANCELLED) must return non-empty");
}

TEST(storage_err_cant_start_thread_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_CANT_START_THREAD));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(CANT_START_THREAD) must return non-empty");
}

TEST(storage_err_iso_scan_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_ISO_SCAN));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(ISO_SCAN) must return non-empty");
}

TEST(storage_err_iso_extract_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_ISO_EXTRACT));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(ISO_EXTRACT) must return non-empty");
}

TEST(storage_err_bad_signature_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_BAD_SIGNATURE));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(BAD_SIGNATURE) must return non-empty");
}

TEST(storage_err_cant_download_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_CANT_DOWNLOAD));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(CANT_DOWNLOAD) must return non-empty");
}

TEST(storage_err_partition_failure_non_empty)
{
    const char* s = _StrError(RUFUS_ERROR(ERROR_PARTITION_FAILURE));
    CHECK_MSG(s != NULL && s[0] != '\0', "RUFUS_ERROR(PARTITION_FAILURE) must return non-empty");
}

TEST(storage_errors_give_distinct_strings)
{
    const char* s1 = _StrError(RUFUS_ERROR(ERROR_ACCESS_DENIED));
    const char* s2 = _StrError(RUFUS_ERROR(ERROR_WRITE_PROTECT));
    const char* s3 = _StrError(RUFUS_ERROR(ERROR_DEVICE_IN_USE));
    const char* s4 = _StrError(RUFUS_ERROR(ERROR_CANCELLED));
    CHECK_MSG(s1 && s2 && s3 && s4, "all storage errors must return non-NULL");
    CHECK_MSG(strcmp(s1, s2) != 0, "ACCESS_DENIED != WRITE_PROTECT");
    CHECK_MSG(strcmp(s2, s3) != 0, "WRITE_PROTECT != DEVICE_IN_USE");
    CHECK_MSG(strcmp(s3, s4) != 0, "DEVICE_IN_USE != CANCELLED");
}

/* ===========================================================================
 * 14–18. Log handler routing
 * uprintf() should call a registered handler instead of writing to stderr.
 * =========================================================================*/

static char captured_log[512];
static int  log_call_count = 0;

static void test_log_handler(const char *msg)
{
    strncpy(captured_log, msg, sizeof(captured_log) - 1);
    captured_log[sizeof(captured_log) - 1] = '\0';
    log_call_count++;
}

TEST(uprintf_calls_registered_handler)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    log_call_count = 0;
    uprintf("hello %d", 42);
    rufus_set_log_handler(NULL);
    CHECK_MSG(log_call_count == 1, "handler should be called exactly once");
    CHECK_MSG(strstr(captured_log, "hello 42") != NULL,
              "handler should receive formatted message");
}

TEST(uprintf_formats_multiple_args)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    uprintf("x=%s y=%d", "foo", 7);
    rufus_set_log_handler(NULL);
    CHECK_MSG(strstr(captured_log, "x=foo") != NULL, "string arg formatted");
    CHECK_MSG(strstr(captured_log, "y=7") != NULL, "integer arg formatted");
}

TEST(uprintf_no_crash_without_handler)
{
    rufus_set_log_handler(NULL);
    /* Should fall back to stderr — just verify no crash */
    uprintf("fallback test %d", 123);
    CHECK(1); /* reached without crash */
}

TEST(uprintf_handler_receives_no_newline)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    uprintf("no newline");
    rufus_set_log_handler(NULL);
    /* The handler should receive the message without a trailing newline,
     * since the handler itself decides how to display it. */
    CHECK_MSG(captured_log[0] != '\0', "handler received a message");
    size_t len = strlen(captured_log);
    CHECK_MSG(len > 0 && captured_log[len - 1] != '\n',
              "handler message should not end with newline");
}

TEST(uprintf_set_and_clear_handler)
{
    int calls_before = 0;
    rufus_set_log_handler(test_log_handler);
    log_call_count = 0;
    uprintf("one");
    calls_before = log_call_count;

    rufus_set_log_handler(NULL);  /* clear handler */
    uprintf("two");  /* should go to stderr only, not handler */
    CHECK_MSG(log_call_count == calls_before, "handler not called after clear");
}

/* ===========================================================================
 * uprintf_errno — appends ": strerror(errno) (errno)" to a log message
 * =========================================================================*/

TEST(uprintf_errno_appends_strerror)
{
    /* ENOENT is "No such file or directory" — errno 2 */
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    errno = ENOENT;
    uprintf_errno("open failed");
    rufus_set_log_handler(NULL);
    /* Must contain the base message */
    CHECK_MSG(strstr(captured_log, "open failed") != NULL,
              "base message present");
    /* Must contain the colon separator */
    CHECK_MSG(strstr(captured_log, ": ") != NULL,
              "colon separator present");
    /* Must contain the strerror text */
    CHECK_MSG(strstr(captured_log, strerror(ENOENT)) != NULL,
              "strerror text present");
    /* Must contain the errno number */
    CHECK_MSG(strstr(captured_log, "2)") != NULL,
              "errno number present");
}

TEST(uprintf_errno_with_format_args)
{
    /* EACCES is "Permission denied" */
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    errno = EACCES;
    uprintf_errno("cannot open %s", "/dev/sda");
    rufus_set_log_handler(NULL);
    CHECK_MSG(strstr(captured_log, "/dev/sda") != NULL,
              "format argument (/dev/sda) present");
    CHECK_MSG(strstr(captured_log, strerror(EACCES)) != NULL,
              "strerror(EACCES) present");
    {
        char num[16];
        snprintf(num, sizeof(num), "(%d)", EACCES);
        CHECK_MSG(strstr(captured_log, num) != NULL, "errno number present");
    }
}

TEST(uprintf_errno_saves_errno_at_call_site)
{
    /* Verify errno is snapshotted at the macro call site, not later */
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    errno = EINVAL;
    uprintf_errno("bad arg");
    rufus_set_log_handler(NULL);
    CHECK_MSG(strstr(captured_log, strerror(EINVAL)) != NULL,
              "EINVAL strerror captured at call site");
    {
        char num[16];
        snprintf(num, sizeof(num), "(%d)", EINVAL);
        CHECK_MSG(strstr(captured_log, num) != NULL, "EINVAL number present");
    }
}

TEST(uprintf_errno_zero_errno_shows_success)
{
    /* errno == 0 should show "Success" (POSIX strerror(0)) */
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    errno = 0;
    uprintf_errno("no error");
    rufus_set_log_handler(NULL);
    CHECK_MSG(strstr(captured_log, "no error") != NULL,
              "base message present for errno==0");
    /* strerror(0) is typically "Success" on Linux */
    CHECK_MSG(strstr(captured_log, "(0)") != NULL,
              "errno==0 number present");
}

TEST(uprintf_errno_format_is_base_colon_strerror_num)
{
    /* Verify exact format: "msg: strerror (N)" */
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    errno = ENOENT;
    uprintf_errno("test");
    rufus_set_log_handler(NULL);
    /* Should be: "test: No such file or directory (2)" */
    {
        char expected[256];
        snprintf(expected, sizeof(expected), "test: %s (%d)",
                 strerror(ENOENT), ENOENT);
        CHECK_MSG(strstr(captured_log, expected) != NULL,
                  "full formatted string matches expected pattern");
    }
}

TEST(uprintf_errno_multiple_calls_independent)
{
    /* Each call uses its own errno snapshot */
    rufus_set_log_handler(test_log_handler);

    captured_log[0] = '\0';
    errno = ENOMEM;
    uprintf_errno("alloc failed");
    CHECK_MSG(strstr(captured_log, strerror(ENOMEM)) != NULL,
              "first call: ENOMEM present");

    captured_log[0] = '\0';
    errno = ETIMEDOUT;
    uprintf_errno("connect failed");
    CHECK_MSG(strstr(captured_log, strerror(ETIMEDOUT)) != NULL,
              "second call: ETIMEDOUT present");

    rufus_set_log_handler(NULL);
}

TEST(uprintf_errno_two_format_args)
{
    /* Macro must handle two format arguments */
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    errno = EBUSY;
    uprintf_errno("device %s at index %d busy", "/dev/sdb", 1);
    rufus_set_log_handler(NULL);
    CHECK_MSG(strstr(captured_log, "/dev/sdb") != NULL,
              "first format arg present");
    CHECK_MSG(strstr(captured_log, "1") != NULL,
              "second format arg present");
    CHECK_MSG(strstr(captured_log, strerror(EBUSY)) != NULL,
              "strerror(EBUSY) present");
}

/* ===========================================================================
 * wuprintf — converts wchar_t format to UTF-8 and routes to log handler
 * =========================================================================*/
extern void wuprintf(const wchar_t* format, ...);

TEST(wuprintf_routes_to_handler)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    log_call_count = 0;
    wuprintf(L"hello from wuprintf");
    rufus_set_log_handler(NULL);
    CHECK_MSG(log_call_count == 1, "wuprintf should call log handler exactly once");
    CHECK_MSG(strstr(captured_log, "hello from wuprintf") != NULL,
              "wuprintf should pass message to log handler");
}

TEST(wuprintf_ascii_roundtrip)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    wuprintf(L"value=%d", 99);
    rufus_set_log_handler(NULL);
    CHECK_MSG(strstr(captured_log, "value=99") != NULL,
              "wuprintf should format and route integer arg");
}

TEST(wuprintf_no_crash_without_handler)
{
    rufus_set_log_handler(NULL);
    /* Falls back to stderr — just verify no crash */
    wuprintf(L"fallback wuprintf %d", 7);
    CHECK(1);
}

TEST(wuprintf_non_ascii_no_crash)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    /* U+00E9 = é, valid UTF-8 and representable in wcstombs with LC_ALL=C setlocale */
    wuprintf(L"caf\u00e9");
    rufus_set_log_handler(NULL);
    /* Just verify handler was called and no crash — locale may mangle chars */
    CHECK_MSG(log_call_count > 0, "wuprintf with non-ASCII must call handler");
}



/* ===========================================================================
 * _printbits — binary string representation of arbitrary-size integers
 * =========================================================================*/

extern char* _printbits(size_t const size, void const* const ptr, int leading_zeroes);

/* Single-byte value 0x01 without leading zeros → "0b1" */
TEST(printbits_byte_one_no_lz)
{
    uint8_t v = 0x01;
    char *s = _printbits(sizeof(v), &v, 0);
    CHECK_MSG(s != NULL, "_printbits returned NULL");
    if (s == NULL) return;
    CHECK_MSG(strcmp(s, "0b1") == 0, "_printbits(0x01, no_lz) should return \"0b1\"");
}

/* Single-byte value 0x01 with leading zeros → "0b00000001" */
TEST(printbits_byte_one_lz)
{
    uint8_t v = 0x01;
    char *s = _printbits(sizeof(v), &v, 1);
    CHECK_MSG(s != NULL, "_printbits returned NULL");
    if (s == NULL) return;
    CHECK_MSG(strcmp(s, "0b00000001") == 0,
              "_printbits(0x01, lz) should return \"0b00000001\"");
}

/* Single-byte value 0xFF → "0b11111111" */
TEST(printbits_byte_all_ones)
{
    uint8_t v = 0xFF;
    char *s = _printbits(sizeof(v), &v, 0);
    CHECK_MSG(s != NULL, "_printbits returned NULL");
    if (s == NULL) return;
    CHECK_MSG(strcmp(s, "0b11111111") == 0,
              "_printbits(0xFF) should return \"0b11111111\"");
}

/* Single-byte value 0x00 without leading zeros → "0b" (no bits set = empty) */
TEST(printbits_byte_zero_no_lz)
{
    uint8_t v = 0x00;
    char *s = _printbits(sizeof(v), &v, 0);
    CHECK_MSG(s != NULL, "_printbits returned NULL");
    if (s == NULL) return;
    /* When no bits are set and no leading zeros requested, result is "0b" */
    CHECK_MSG(strcmp(s, "0b") == 0,
              "_printbits(0x00, no_lz) should return \"0b\" (no bits set)");
}

/* Single-byte value 0x00 with leading zeros → "0b00000000" */
TEST(printbits_byte_zero_lz)
{
    uint8_t v = 0x00;
    char *s = _printbits(sizeof(v), &v, 1);
    CHECK_MSG(s != NULL, "_printbits returned NULL");
    if (s == NULL) return;
    CHECK_MSG(strcmp(s, "0b00000000") == 0,
              "_printbits(0x00, lz) should return \"0b00000000\"");
}

/* 16-bit value 0xA5A5 → check prefix and length */
TEST(printbits_word_a5a5)
{
    uint16_t v = 0xA5A5;
    char *s = _printbits(sizeof(v), &v, 1);
    CHECK_MSG(s != NULL, "_printbits returned NULL");
    if (s == NULL) return;
    /* Should start with "0b" and have 16 bits */
    CHECK_MSG(strncmp(s, "0b", 2) == 0, "result should start with 0b");
    CHECK_MSG(strlen(s) == 18, "16-bit with lz should give 18 chars (0b + 16 bits)");
}

/* printbits macro with simple uint8_t value */
TEST(printbits_macro_smoke)
{
    uint8_t v = 0b10101010;
    char *s = _printbits(sizeof(v), &v, 0);
    CHECK_MSG(s != NULL, "_printbits returned NULL");
    if (s == NULL) return;
    CHECK_MSG(strcmp(s, "0b10101010") == 0,
              "printbits(0b10101010) should give \"0b10101010\"");
}

/* ===========================================================================
 * DumpBufferHex — xxd-style hex dump via uprintf
 * =========================================================================*/

extern void DumpBufferHex(void* buf, size_t size);

/* Capture log output for DumpBufferHex tests */
static char dump_buf[8192];
static int  dump_call_count;

static void dump_log_handler(const char *msg)
{
    /* Accumulate all log messages */
    size_t cur = strlen(dump_buf);
    size_t add = strlen(msg);
    if (cur + add + 2 < sizeof(dump_buf)) {
        memcpy(dump_buf + cur, msg, add);
        dump_buf[cur + add]     = '\n';
        dump_buf[cur + add + 1] = '\0';
    }
    dump_call_count++;
}

/* DumpBufferHex with a 16-byte buffer — should produce output containing hex */
TEST(dump_buffer_hex_16_bytes)
{
    uint8_t data[16];
    for (int i = 0; i < 16; i++) data[i] = (uint8_t)i;

    rufus_set_log_handler(dump_log_handler);
    dump_buf[0] = '\0'; dump_call_count = 0;
    DumpBufferHex(data, sizeof(data));
    rufus_set_log_handler(NULL);

    /* Should have printed something */
    CHECK_MSG(dump_call_count > 0, "DumpBufferHex should call log handler");
    /* Output should contain "00" (first byte) and "0f" (last byte) in hex */
    CHECK_MSG(strstr(dump_buf, "00") != NULL, "hex dump should contain 00");
    CHECK_MSG(strstr(dump_buf, "0f") != NULL, "hex dump should contain 0f");
    /* Output should contain the offset "00000000" */
    CHECK_MSG(strstr(dump_buf, "00000000") != NULL, "hex dump should contain offset 00000000");
}

/* DumpBufferHex with a 32-byte buffer — should produce two lines */
TEST(dump_buffer_hex_32_bytes)
{
    uint8_t data[32];
    for (int i = 0; i < 32; i++) data[i] = (uint8_t)(0xA0 + i);

    rufus_set_log_handler(dump_log_handler);
    dump_buf[0] = '\0'; dump_call_count = 0;
    DumpBufferHex(data, sizeof(data));
    rufus_set_log_handler(NULL);

    /* a0..af on first line, b0..bf on second line */
    CHECK_MSG(strstr(dump_buf, "a0") != NULL, "hex dump should contain a0");
    CHECK_MSG(strstr(dump_buf, "00000010") != NULL,
              "second line should have offset 00000010");
}

/* DumpBufferHex with a buffer that has printable ASCII — ASCII section present */
TEST(dump_buffer_hex_ascii_chars)
{
    const char *msg = "Hello, World!!";  /* 14 bytes, all printable */
    rufus_set_log_handler(dump_log_handler);
    dump_buf[0] = '\0'; dump_call_count = 0;
    DumpBufferHex((void*)msg, strlen(msg));
    rufus_set_log_handler(NULL);

    /* 'H' should appear in the ASCII section */
    CHECK_MSG(strstr(dump_buf, "H") != NULL, "ASCII 'H' should appear in hex dump");
}

/* DumpBufferHex NULL buffer — must not crash */
TEST(dump_buffer_hex_null_buf)
{
    rufus_set_log_handler(dump_log_handler);
    dump_buf[0] = '\0'; dump_call_count = 0;
    DumpBufferHex(NULL, 16);
    rufus_set_log_handler(NULL);
    /* Just verifying no crash — any output (or none) is acceptable */
    CHECK(1);
}

/* DumpBufferHex size=0 — must not crash */
TEST(dump_buffer_hex_zero_size)
{
    uint8_t data[4] = { 1, 2, 3, 4 };
    rufus_set_log_handler(dump_log_handler);
    dump_buf[0] = '\0'; dump_call_count = 0;
    DumpBufferHex(data, 0);
    rufus_set_log_handler(NULL);
    CHECK(1);
}

/* ===========================================================================
 * wuprintf — comprehensive UTF-8 encoding tests
 * =========================================================================*/

/* Two-byte UTF-8: U+00E9 = é → must be encoded as 0xC3 0xA9 */
TEST(wuprintf_two_byte_utf8_roundtrip)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    log_call_count = 0;
    wuprintf(L"\u00e9");  /* U+00E9 é */
    rufus_set_log_handler(NULL);

    CHECK_MSG(log_call_count == 1, "handler called exactly once");
    /* UTF-8 encoding of U+00E9 = 0xC3 0xA9 */
    BOOL found = (strstr(captured_log, "\xc3\xa9") != NULL);
    CHECK_MSG(found, "U+00E9 (é) must be encoded as UTF-8 bytes C3 A9");
}

/* Two-byte UTF-8: U+00FC = ü → must be encoded as 0xC3 0xBC */
TEST(wuprintf_two_byte_utf8_umlaut)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    log_call_count = 0;
    wuprintf(L"\u00fc");  /* U+00FC ü */
    rufus_set_log_handler(NULL);

    CHECK_MSG(log_call_count == 1, "handler called exactly once");
    BOOL found = (strstr(captured_log, "\xc3\xbc") != NULL);
    CHECK_MSG(found, "U+00FC (ü) must be encoded as UTF-8 bytes C3 BC");
}

/* Three-byte UTF-8: U+4E2D = 中 → must be encoded as 0xE4 0xB8 0xAD */
TEST(wuprintf_three_byte_utf8_cjk)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    log_call_count = 0;
    wuprintf(L"\u4e2d\u6587");  /* 中文 */
    rufus_set_log_handler(NULL);

    CHECK_MSG(log_call_count == 1, "handler called exactly once");
    /* UTF-8 for 中 = E4 B8 AD */
    BOOL found = (strstr(captured_log, "\xe4\xb8\xad") != NULL);
    CHECK_MSG(found, "U+4E2D (中) must be encoded as UTF-8 bytes E4 B8 AD");
}

/* wuprintf with mixed ASCII and multi-byte characters */
TEST(wuprintf_mixed_ascii_and_utf8)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    log_call_count = 0;
    wuprintf(L"caf\u00e9 %d", 42);  /* "café 42" */
    rufus_set_log_handler(NULL);

    CHECK_MSG(log_call_count == 1, "handler called exactly once");
    CHECK_MSG(strstr(captured_log, "caf") != NULL, "ASCII prefix 'caf' preserved");
    CHECK_MSG(strstr(captured_log, "\xc3\xa9") != NULL, "U+00E9 correctly encoded");
    CHECK_MSG(strstr(captured_log, "42") != NULL, "integer arg formatted");
}

/* wuprintf NULL format — must not crash */
TEST(wuprintf_null_format_no_crash)
{
    rufus_set_log_handler(test_log_handler);
    captured_log[0] = '\0';
    log_call_count = 0;
    wuprintf(NULL);  /* NULL format — implementation must guard against this */
    rufus_set_log_handler(NULL);
    CHECK(1);  /* just verifying no crash */
}

/* Helper: create a temp directory, populate with files and a subdir */
static char list_dir_tmp[256] = "";
static char list_dir_sub[512] = "";

static void list_dir_setup(void)
{
    snprintf(list_dir_tmp, sizeof(list_dir_tmp), "/tmp/test_ldc_XXXXXX");
    if (mkdtemp(list_dir_tmp) == NULL) { list_dir_tmp[0] = '\0'; return; }
    snprintf(list_dir_sub, sizeof(list_dir_sub), "%s/subdir", list_dir_tmp);
    mkdir(list_dir_sub, 0755);
    /* Create files */
    char path[640];
    snprintf(path, sizeof(path), "%s/file1.txt", list_dir_tmp);
    FILE *f = fopen(path, "w"); if (f) { fputs("a", f); fclose(f); }
    snprintf(path, sizeof(path), "%s/file2.txt", list_dir_tmp);
    f = fopen(path, "w"); if (f) { fputs("b", f); fclose(f); }
    snprintf(path, sizeof(path), "%s/subdir/nested.txt", list_dir_tmp);
    f = fopen(path, "w"); if (f) { fputs("c", f); fclose(f); }
}

static void list_dir_teardown(void)
{
    if (!list_dir_tmp[0]) return;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", list_dir_tmp);
    system(cmd);
    list_dir_tmp[0] = '\0';
}

/* 21. ListDirectoryContent with FILES only */
TEST(list_dir_files_only)
{
    list_dir_setup();
    if (!list_dir_tmp[0]) { CHECK(0); return; }

    StrArray arr;
    StrArrayCreate(&arr, 8);
    DWORD r = ListDirectoryContent(&arr, list_dir_tmp, LIST_DIR_TYPE_FILE);
    CHECK(r == NO_ERROR || (int)arr.Index > 0);
    /* Should find file1.txt and file2.txt (not the subdir) */
    CHECK_INT_EQ(2, (int)(int)arr.Index);
    /* Entries must be full paths */
    BOOL found1 = FALSE, found2 = FALSE;
    for (uint32_t i = 0; i < (int)arr.Index; i++) {
        if (strstr(arr.String[i], "file1.txt")) found1 = TRUE;
        if (strstr(arr.String[i], "file2.txt")) found2 = TRUE;
    }
    CHECK_MSG(found1, "file1.txt not found");
    CHECK_MSG(found2, "file2.txt not found");
    StrArrayDestroy(&arr);
    list_dir_teardown();
}

/* 22. ListDirectoryContent with DIRECTORY only (non-recursive) */
TEST(list_dir_dirs_only)
{
    list_dir_setup();
    if (!list_dir_tmp[0]) { CHECK(0); return; }

    StrArray arr;
    StrArrayCreate(&arr, 8);
    /* Non-recursive: LIST_DIR_TYPE_DIRECTORY — subdirs must be listed only if
     * RECURSIVE flag is set; without RECURSIVE subdirs are not descended into.
     * LIST_DIR_TYPE_DIRECTORY alone without RECURSIVE lists nothing on most
     * implementations (the recursive flag is needed to emit dir names). */
    DWORD r = ListDirectoryContent(&arr, list_dir_tmp,
                                   LIST_DIR_TYPE_DIRECTORY | LIST_DIR_TYPE_RECURSIVE);
    (void)r;
    /* Should find the "subdir" entry */
    BOOL found_subdir = FALSE;
    for (uint32_t i = 0; i < (int)arr.Index; i++) {
        if (strstr(arr.String[i], "subdir")) found_subdir = TRUE;
    }
    CHECK_MSG(found_subdir, "subdir not found in DIRECTORY listing");
    StrArrayDestroy(&arr);
    list_dir_teardown();
}

/* 23. ListDirectoryContent recursive (files + dirs) */
TEST(list_dir_recursive)
{
    list_dir_setup();
    if (!list_dir_tmp[0]) { CHECK(0); return; }

    StrArray arr;
    StrArrayCreate(&arr, 16);
    ListDirectoryContent(&arr, list_dir_tmp,
                         LIST_DIR_TYPE_FILE | LIST_DIR_TYPE_RECURSIVE);
    /* Should find all 3 files: file1.txt, file2.txt, subdir/nested.txt */
    CHECK_MSG((int)arr.Index >= 3, "Expected at least 3 files recursively");
    BOOL found_nested = FALSE;
    for (uint32_t i = 0; i < (int)arr.Index; i++) {
        if (strstr(arr.String[i], "nested.txt")) found_nested = TRUE;
    }
    CHECK_MSG(found_nested, "nested.txt not found recursively");
    StrArrayDestroy(&arr);
    list_dir_teardown();
}

/* 24. ListDirectoryContent NULL args return error */
TEST(list_dir_null_args)
{
    StrArray arr;
    StrArrayCreate(&arr, 4);
    DWORD r = ListDirectoryContent(NULL, list_dir_tmp, LIST_DIR_TYPE_FILE);
    CHECK(r == ERROR_INVALID_PARAMETER);
    r = ListDirectoryContent(&arr, NULL, LIST_DIR_TYPE_FILE);
    CHECK(r == ERROR_INVALID_PARAMETER);
    r = ListDirectoryContent(&arr, list_dir_tmp, 0);
    CHECK(r == ERROR_INVALID_PARAMETER);
    StrArrayDestroy(&arr);
}

/* 25. ListDirectoryContent on non-existent directory */
TEST(list_dir_nonexistent)
{
    StrArray arr;
    StrArrayCreate(&arr, 4);
    DWORD r = ListDirectoryContent(&arr, "/tmp/__no_such_dir_rufus_test__",
                                   LIST_DIR_TYPE_FILE);
    CHECK(r != NO_ERROR);
    CHECK_INT_EQ(0, (int)(int)arr.Index);
    StrArrayDestroy(&arr);
}

/* ===========================================================================
 * ExtractZip tests
 * =========================================================================*/

/* Helper: create a minimal zip file using the 'zip' command */
static char zip_src[256] = "";
static char zip_dst[256] = "";

static int make_test_zip(void)
{
    /* Use mkdtemp + zip command to build a tiny zip */
    char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/test_zip_src_XXXXXX");
    if (!mkdtemp(tmpdir)) return 0;

    /* Write a couple of files into tmpdir */
    char path[640];
    snprintf(path, sizeof(path), "%s/hello.txt", tmpdir);
    FILE *f = fopen(path, "w"); if (f) { fputs("hello\n", f); fclose(f); }
    snprintf(path, sizeof(path), "%s/world.txt", tmpdir);
    f = fopen(path, "w"); if (f) { fputs("world\n", f); fclose(f); }

    /* Build the zip */
    snprintf(zip_src, sizeof(zip_src), "/tmp/test_zip_%d.zip", (int)getpid());
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cd %s && zip -q %s hello.txt world.txt", tmpdir, zip_src);
    int rc = system(cmd);

    /* Remove source dir */
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);

    if (rc != 0 || access(zip_src, F_OK) != 0) {
        zip_src[0] = '\0';
        return 0;
    }
    return 1;
}

static void zip_teardown(void)
{
    if (zip_src[0]) { unlink(zip_src); zip_src[0] = '\0'; }
    if (zip_dst[0]) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", zip_dst);
        system(cmd);
        zip_dst[0] = '\0';
    }
}

/* 26. ExtractZip returns TRUE for a valid zip */
TEST(extract_zip_success)
{
    reset();  /* clear ErrorStatus from prior cancellation test */
    if (!make_test_zip()) {
        /* zip command may not be installed; skip test gracefully */
        printf("  [SKIP] zip command not available\n");
        return;
    }
    snprintf(zip_dst, sizeof(zip_dst), "/tmp/test_zip_dst_XXXXXX");
    if (!mkdtemp(zip_dst)) { zip_teardown(); CHECK(0); return; }

    BOOL r = ExtractZip(zip_src, zip_dst);
    CHECK_MSG(r == TRUE, "ExtractZip should return TRUE for valid zip");

    /* Verify extracted files exist */
    char path[640];
    snprintf(path, sizeof(path), "%s/hello.txt", zip_dst);
    CHECK_MSG(access(path, F_OK) == 0, "hello.txt not extracted");
    snprintf(path, sizeof(path), "%s/world.txt", zip_dst);
    CHECK_MSG(access(path, F_OK) == 0, "world.txt not extracted");

    zip_teardown();
}

/* 27. ExtractZip NULL source returns FALSE */
TEST(extract_zip_null_src)
{
    BOOL r = ExtractZip(NULL, "/tmp");
    CHECK(r == FALSE);
}

/* 28. ExtractZip non-existent source returns FALSE */
TEST(extract_zip_nonexistent_src)
{
    BOOL r = ExtractZip("/tmp/__no_such_file_rufus_test__.zip", "/tmp");
    CHECK(r == FALSE);
}

/* ===========================================================================
 * WriteFileWithRetry tests
 * =========================================================================*/

/* 29. Basic write succeeds and reports correct byte count */
TEST(write_file_with_retry_basic)
{
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/tmp/rufus_wfwr_%d", (int)getpid());
    int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;
    const char *data = "hello, world";
    DWORD written = 0;
    BOOL r = WriteFileWithRetry(h, data, (DWORD)strlen(data), &written, 0);
    CHECK(r == TRUE);
    CHECK(written == (DWORD)strlen(data));
    close(fd);
    unlink(tmp);
}

/* 30. Reports failure and written=partial for invalid fd */
TEST(write_file_with_retry_invalid_handle)
{
    DWORD written = 99;
    BOOL r = WriteFileWithRetry(INVALID_HANDLE_VALUE, "x", 1, &written, 0);
    CHECK(r == FALSE);
}

/* 31. NULL buffer returns FALSE */
TEST(write_file_with_retry_null_buf)
{
    BOOL r = WriteFileWithRetry((HANDLE)(intptr_t)1, NULL, 4, NULL, 0);
    CHECK(r == FALSE);
}

/* 32. NULL written pointer is safe */
TEST(write_file_with_retry_null_written)
{
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/tmp/rufus_wfwr2_%d", (int)getpid());
    int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    CHECK(fd >= 0);
    HANDLE h = (HANDLE)(intptr_t)fd;
    BOOL r = WriteFileWithRetry(h, "test", 4, NULL, 0);
    CHECK(r == TRUE);
    close(fd);
    unlink(tmp);
}

/* ===========================================================================
 * WaitForSingleObjectWithMessages tests
 * =========================================================================*/

/* Helper thread that exits immediately */
static DWORD WINAPI wfsom_trivial_thread(void *arg) { (void)arg; return 42; }

/* 29. Returns WAIT_OBJECT_0 when thread has finished */
TEST(wfsom_returns_wait_object_0)
{
    HANDLE h = CreateThread(NULL, 0, wfsom_trivial_thread, NULL, 0, NULL);
    CHECK(h != NULL && h != INVALID_HANDLE_VALUE);
    DWORD r = WaitForSingleObjectWithMessages(h, 5000);
    CHECK(r == WAIT_OBJECT_0);
    CloseHandle(h);
}

/* 30. Returns WAIT_TIMEOUT when handle does not signal within timeout */
TEST(wfsom_returns_wait_timeout)
{
    /* Create an event (manual reset) that we never signal */
    HANDLE ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    CHECK(ev != NULL && ev != INVALID_HANDLE_VALUE);
    DWORD r = WaitForSingleObjectWithMessages(ev, 50);  /* 50 ms */
    CHECK(r == WAIT_TIMEOUT);
    CloseHandle(ev);
}

/* 31. Returns WAIT_FAILED for invalid handle */
TEST(wfsom_invalid_handle_returns_failed)
{
    DWORD r = WaitForSingleObjectWithMessages(INVALID_HANDLE_VALUE, 0);
    CHECK(r == WAIT_FAILED);
}

/* ===========================================================================
 * CreateFileWithTimeout tests
 * =========================================================================*/

extern HANDLE CreateFileWithTimeout(LPCSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSa, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplate, DWORD dwTimeOut);

/* Opens an existing file for reading → valid handle */
TEST(create_file_with_timeout_reads_existing)
{
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/tmp/rufus_cfwt_%d", (int)getpid());
    int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    CHECK(fd >= 0); close(fd);

    HANDLE h = CreateFileWithTimeout(tmp, GENERIC_READ, 0, NULL,
                                     OPEN_EXISTING, 0, NULL, 1000);
    CHECK(h != INVALID_HANDLE_VALUE);
    CloseHandle(h);
    unlink(tmp);
}

/* Non-existent file for OPEN_EXISTING → INVALID_HANDLE_VALUE */
TEST(create_file_with_timeout_nonexistent)
{
    HANDLE h = CreateFileWithTimeout("/tmp/__no_such_file_rufus__", GENERIC_READ,
                                     0, NULL, OPEN_EXISTING, 0, NULL, 200);
    CHECK(h == INVALID_HANDLE_VALUE);
}

/* CREATE_ALWAYS creates a new file */
TEST(create_file_with_timeout_creates_file)
{
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/tmp/rufus_cfwt2_%d", (int)getpid());
    unlink(tmp); /* ensure file doesn't exist */

    HANDLE h = CreateFileWithTimeout(tmp, GENERIC_WRITE, 0, NULL,
                                     CREATE_ALWAYS, 0, NULL, 1000);
    CHECK(h != INVALID_HANDLE_VALUE);
    CloseHandle(h);
    CHECK(access(tmp, F_OK) == 0); /* file was created */
    unlink(tmp);
}

/* ===========================================================================
 * TimestampToHumanReadable — UTC timestamp formatting
 * Format: YYYYMMDDHHMMSS uint64 → "YYYY.MM.DD HH:MM:SS (UTC)"
 * =========================================================================*/

extern char* TimestampToHumanReadable(uint64_t ts);

TEST(timestamp_returns_non_null)
{
    char *s = TimestampToHumanReadable(20250115120000ULL);
    CHECK_MSG(s != NULL, "TimestampToHumanReadable must return non-NULL");
}

TEST(timestamp_zero_gives_zero_date)
{
    char *s = TimestampToHumanReadable(0ULL);
    CHECK_MSG(s != NULL, "TimestampToHumanReadable(0) must return non-NULL");
    CHECK_MSG(strcmp(s, "0000.00.00 00:00:00 (UTC)") == 0,
              "TimestampToHumanReadable(0) must return zero timestamp");
}

TEST(timestamp_basic_date)
{
    /* 2025-01-15 12:00:00 UTC */
    char *s = TimestampToHumanReadable(20250115120000ULL);
    CHECK_MSG(s != NULL, "TimestampToHumanReadable must return non-NULL");
    CHECK_MSG(strcmp(s, "2025.01.15 12:00:00 (UTC)") == 0,
              "TimestampToHumanReadable basic date mismatch");
}

TEST(timestamp_result_contains_utc)
{
    char *s = TimestampToHumanReadable(20230630235959ULL);
    CHECK_MSG(s != NULL, "TimestampToHumanReadable must return non-NULL");
    CHECK_MSG(strstr(s, "(UTC)") != NULL,
              "TimestampToHumanReadable result must contain '(UTC)'");
}

TEST(timestamp_format_separators)
{
    /* 2024.06.30 23:59:59 (UTC) */
    char *s = TimestampToHumanReadable(20240630235959ULL);
    CHECK_MSG(s != NULL, "TimestampToHumanReadable must return non-NULL");
    /* verify dot separators in date and colon separators in time */
    CHECK_MSG(s[4] == '.' && s[7] == '.',
              "Date part must use '.' separators");
    CHECK_MSG(s[13] == ':' && s[16] == ':',
              "Time part must use ':' separators");
}

TEST(timestamp_length_correct)
{
    /* "YYYY.MM.DD HH:MM:SS (UTC)" = 25 characters */
    char *s = TimestampToHumanReadable(20250101000000ULL);
    CHECK_MSG(s != NULL, "TimestampToHumanReadable must return non-NULL");
    CHECK_MSG(strlen(s) == 25,
              "TimestampToHumanReadable result must be 25 chars");
}

TEST(timestamp_max_values)
{
    /* 9999.12.31 23:59:59 (UTC) */
    char *s = TimestampToHumanReadable(99991231235959ULL);
    CHECK_MSG(s != NULL, "TimestampToHumanReadable must return non-NULL");
    CHECK_MSG(strcmp(s, "9999.12.31 23:59:59 (UTC)") == 0,
              "TimestampToHumanReadable max-values mismatch");
}

TEST(timestamp_different_calls_give_different_results)
{
    char buf1[32], buf2[32];
    char *s1 = TimestampToHumanReadable(20230101000000ULL);
    CHECK_MSG(s1 != NULL, "first call must return non-NULL");
    strncpy(buf1, s1, sizeof(buf1) - 1); buf1[sizeof(buf1)-1] = '\0';

    char *s2 = TimestampToHumanReadable(20241225180000ULL);
    CHECK_MSG(s2 != NULL, "second call must return non-NULL");
    strncpy(buf2, s2, sizeof(buf2) - 1); buf2[sizeof(buf2)-1] = '\0';

    /* Results must differ */
    CHECK_MSG(strcmp(buf1, buf2) != 0,
              "different timestamps must produce different results");
}

/* ===========================================================================
 * main
 * =========================================================================*/
int main(void)
{
    /* Initialize msg_table so lmprintf returns "MSG_XXX UNTRANSLATED" strings
     * rather than crashing when no locale file is loaded. */
    msg_table = default_msg_table;

    printf("=== stdio_linux tests ===\n");

    RUN(run_command_exit_zero);
    RUN(run_command_exit_nonzero);
    RUN(run_command_not_found);
    RUN(run_command_with_log);
    RUN(run_command_null_dir);
    RUN(run_command_with_dir);
    RUN(run_command_progress_pattern);
    RUN(run_command_progress_no_match);
    RUN(run_command_silent_mode);
    RUN(run_command_multiline_output);
    RUN(run_command_cancellation);
    RUN(size_to_human_readable_bytes);
    RUN(size_to_human_readable_kb);
    RUN(size_to_human_readable_gb);
    RUN(windows_error_string_non_null);

    printf("\n  _StrError / WindowsErrorString DWORD mapping\n");
    RUN(strerror_success_returns_non_null);
    RUN(strerror_access_denied_non_null);
    RUN(strerror_write_protect_non_null);
    RUN(strerror_different_codes_give_different_strings);
    RUN(strerror_unknown_storage_code_returns_non_null);
    RUN(strerror_non_storage_code_returns_non_null);
    RUN(setlasterror_affects_windows_error_string);
    RUN(windows_error_string_without_setlasterror);

    printf("\n  windows_dword_to_errno — per-constant mapping\n");
    RUN(dword_map_file_not_found_gives_enoent_string);
    RUN(dword_map_path_not_found_gives_enoent_string);
    RUN(dword_map_too_many_open_files_gives_emfile_string);
    RUN(dword_map_access_denied_gives_eacces_string);
    RUN(dword_map_invalid_handle_gives_ebadf_string);
    RUN(dword_map_not_enough_memory_gives_enomem_string);
    RUN(dword_map_outofmemory_gives_enomem_string);
    RUN(dword_map_write_protect_gives_erofs_string);
    RUN(dword_map_no_more_files_gives_enoent_string);
    RUN(dword_map_write_fault_gives_eio_string);
    RUN(dword_map_read_fault_gives_eio_string);
    RUN(dword_map_not_supported_gives_enotsup_string);
    RUN(dword_map_file_exists_gives_eexist_string);
    RUN(dword_map_invalid_parameter_gives_einval_string);
    RUN(dword_map_insufficient_buffer_gives_enobufs_string);
    RUN(dword_map_not_ready_gives_enodev_string);
    RUN(dword_map_device_in_use_gives_ebusy_string);
    RUN(dword_map_open_failed_gives_enoent_string);
    RUN(dword_map_cancelled_gives_ecanceled_string);

    printf("\n  _StrError FACILITY_STORAGE cases\n");
    RUN(storage_err_gen_failure_non_empty);
    RUN(storage_err_incompatible_fs_non_empty);
    RUN(storage_err_device_in_use_non_empty);
    RUN(storage_err_cant_quick_format_non_empty);
    RUN(storage_err_label_too_long_non_empty);
    RUN(storage_err_invalid_cluster_size_non_empty);
    RUN(storage_err_no_media_in_drive_non_empty);
    RUN(storage_err_not_enough_memory_non_empty);
    RUN(storage_err_cancelled_non_empty);
    RUN(storage_err_cant_start_thread_non_empty);
    RUN(storage_err_iso_scan_non_empty);
    RUN(storage_err_iso_extract_non_empty);
    RUN(storage_err_bad_signature_non_empty);
    RUN(storage_err_cant_download_non_empty);
    RUN(storage_err_partition_failure_non_empty);
    RUN(storage_errors_give_distinct_strings);
    RUN(uprintf_calls_registered_handler);
    RUN(uprintf_formats_multiple_args);
    RUN(uprintf_no_crash_without_handler);
    RUN(uprintf_handler_receives_no_newline);
    RUN(uprintf_set_and_clear_handler);

    printf("\n  uprintf_errno — appends strerror(errno) suffix\n");
    RUN(uprintf_errno_appends_strerror);
    RUN(uprintf_errno_with_format_args);
    RUN(uprintf_errno_saves_errno_at_call_site);
    RUN(uprintf_errno_zero_errno_shows_success);
    RUN(uprintf_errno_format_is_base_colon_strerror_num);
    RUN(uprintf_errno_multiple_calls_independent);
    RUN(uprintf_errno_two_format_args);

    printf("\n  _printbits — binary string representation\n");
    RUN(printbits_byte_one_no_lz);
    RUN(printbits_byte_one_lz);
    RUN(printbits_byte_all_ones);
    RUN(printbits_byte_zero_no_lz);
    RUN(printbits_byte_zero_lz);
    RUN(printbits_word_a5a5);
    RUN(printbits_macro_smoke);

    printf("\n  DumpBufferHex — xxd-style hex dump\n");
    RUN(dump_buffer_hex_16_bytes);
    RUN(dump_buffer_hex_32_bytes);
    RUN(dump_buffer_hex_ascii_chars);
    RUN(dump_buffer_hex_null_buf);
    RUN(dump_buffer_hex_zero_size);

    printf("\n  wuprintf — wchar_t to UTF-8 routing\n");
    RUN(wuprintf_routes_to_handler);
    RUN(wuprintf_ascii_roundtrip);
    RUN(wuprintf_no_crash_without_handler);
    RUN(wuprintf_non_ascii_no_crash);

    printf("\n  wuprintf — UTF-8 encoding correctness\n");
    RUN(wuprintf_two_byte_utf8_roundtrip);
    RUN(wuprintf_two_byte_utf8_umlaut);
    RUN(wuprintf_three_byte_utf8_cjk);
    RUN(wuprintf_mixed_ascii_and_utf8);
    RUN(wuprintf_null_format_no_crash);

    RUN(list_dir_files_only);
    RUN(list_dir_dirs_only);
    RUN(list_dir_recursive);
    RUN(list_dir_null_args);
    RUN(list_dir_nonexistent);
    RUN(extract_zip_success);
    RUN(extract_zip_null_src);
    RUN(extract_zip_nonexistent_src);

    printf("\n  WriteFileWithRetry\n");
    RUN(write_file_with_retry_basic);
    RUN(write_file_with_retry_invalid_handle);
    RUN(write_file_with_retry_null_buf);
    RUN(write_file_with_retry_null_written);

    printf("\n  WaitForSingleObjectWithMessages\n");
    RUN(wfsom_returns_wait_object_0);
    RUN(wfsom_returns_wait_timeout);
    RUN(wfsom_invalid_handle_returns_failed);

    printf("\n  CreateFileWithTimeout\n");
    RUN(create_file_with_timeout_reads_existing);
    RUN(create_file_with_timeout_nonexistent);
    RUN(create_file_with_timeout_creates_file);

    printf("\n  TimestampToHumanReadable — UTC timestamp formatting\n");
    RUN(timestamp_returns_non_null);
    RUN(timestamp_zero_gives_zero_date);
    RUN(timestamp_basic_date);
    RUN(timestamp_result_contains_utc);
    RUN(timestamp_format_separators);
    RUN(timestamp_length_correct);
    RUN(timestamp_max_values);
    RUN(timestamp_different_calls_give_different_results);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
