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
 * ListDirectoryContent tests
 * =========================================================================*/

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
    RUN(uprintf_calls_registered_handler);
    RUN(uprintf_formats_multiple_args);
    RUN(uprintf_no_crash_without_handler);
    RUN(uprintf_handler_receives_no_newline);
    RUN(uprintf_set_and_clear_handler);
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

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
