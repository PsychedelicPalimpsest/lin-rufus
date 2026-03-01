/*
 * test_process_linux.c — Tests for Linux process management (src/linux/process.c)
 *
 * Tests cover:
 *   1. GetPPID          — read parent PID from /proc/PID/status
 *   2. StartProcessSearch / StopProcessSearch — lifecycle
 *   3. SetProcessSearch — register a device for scanning
 *   4. GetProcessSearch — scan /proc for open handles (returns 0 with no drive)
 *   5. SearchProcessAlt — scan /proc/PID/comm for a named process
 *
 * Linux-only (uses /proc filesystem).
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "framework.h"
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

/* ------------------------------------------------------------------ */
/* Required globals                                                     */
/* ------------------------------------------------------------------ */
DWORD  ErrorStatus    = 0;
DWORD  MainThreadId   = 0;
DWORD  DownloadStatus = 0;
DWORD  LastWriteError = 0;
HWND   hMainDialog    = NULL;
BOOL   usb_debug      = FALSE;

/* Minimal stubs */
void uprintf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}
void uprintfs(const char *s) { if (s) fputs(s, stderr); }
char *lmprintf(uint32_t id, ...) { (void)id; return ""; }

/* Stub for GetPhysicalName — process.c calls this; we don't link drive.c */
char *GetPhysicalName(DWORD DriveIndex) { (void)DriveIndex; return NULL; }

/* ------------------------------------------------------------------ */
/* Forward declarations (process.c exports)                            */
/* ------------------------------------------------------------------ */
extern DWORD GetPPID(DWORD pid);
extern BOOL  StartProcessSearch(void);
extern void  StopProcessSearch(void);
extern BOOL  SetProcessSearch(DWORD DeviceNum);
extern BYTE  GetProcessSearch(uint32_t timeout, uint8_t access_mask, BOOL bIgnoreStale);
extern BOOL  SearchProcessAlt(char *name);
extern BOOL  EnablePrivileges(void);

/* ================================================================== */
/* GetPPID tests                                                        */
/* ================================================================== */

TEST(getppid_current_process)
{
    DWORD my_pid  = (DWORD)getpid();
    DWORD my_ppid = (DWORD)getppid();
    DWORD result  = GetPPID(my_pid);
    CHECK_MSG(result == my_ppid,
              "GetPPID(getpid()) should equal getppid()");
}

TEST(getppid_zero_pid)
{
    /* PID 0 has no /proc entry; should return 0 gracefully */
    DWORD result = GetPPID(0);
    CHECK_MSG(result == 0, "GetPPID(0) should return 0");
}

TEST(getppid_nonexistent_pid)
{
    /* A very large PID that almost certainly doesn't exist */
    DWORD result = GetPPID(0x7FFFFFFF);
    CHECK_MSG(result == 0, "GetPPID with nonexistent PID should return 0");
}

TEST(getppid_pid1_doesnt_crash)
{
    /* PID 1 always exists; its PPID is 0 */
    DWORD result = GetPPID(1);
    /* On most systems, PID 1's parent is 0 */
    CHECK_MSG(result == 0, "PID 1 parent should be 0");
}

/* ================================================================== */
/* StartProcessSearch / StopProcessSearch                              */
/* ================================================================== */

TEST(start_process_search_returns_true)
{
    StopProcessSearch(); /* reset state first */
    BOOL r = StartProcessSearch();
    CHECK_MSG(r == TRUE, "StartProcessSearch should return TRUE on Linux");
    StopProcessSearch();
}

TEST(start_process_search_idempotent)
{
    StopProcessSearch();
    BOOL r1 = StartProcessSearch();
    BOOL r2 = StartProcessSearch(); /* second call should also succeed */
    CHECK(r1 == TRUE);
    CHECK(r2 == TRUE);
    StopProcessSearch();
}

TEST(stop_process_search_without_start)
{
    /* Calling stop without start should not crash */
    StopProcessSearch();
    CHECK(1); /* just need to not crash */
}

TEST(stop_process_search_after_start)
{
    StartProcessSearch();
    StopProcessSearch();
    CHECK(1);
}

/* ================================================================== */
/* SetProcessSearch                                                     */
/* ================================================================== */

TEST(set_process_search_without_start_fails)
{
    StopProcessSearch();
    /* Without StartProcessSearch, SetProcessSearch should fail */
    BOOL r = SetProcessSearch(0);
    CHECK_MSG(r == FALSE,
              "SetProcessSearch without StartProcessSearch should return FALSE");
}

TEST(set_process_search_after_start)
{
    StopProcessSearch();
    StartProcessSearch();
    /* DriveIndex 0 is likely not registered but the call should not crash */
    BOOL r = SetProcessSearch(0);
    /* On Linux with no drives registered, may return TRUE or FALSE */
    (void)r;
    CHECK(1); /* must not crash */
    StopProcessSearch();
}

/* ================================================================== */
/* GetProcessSearch                                                     */
/* ================================================================== */

TEST(get_process_search_without_start_returns_zero)
{
    StopProcessSearch();
    /* No search active → should return 0 */
    BYTE mask = GetProcessSearch(100, 0x07, FALSE);
    CHECK_MSG(mask == 0,
              "GetProcessSearch with no active search should return 0");
}

TEST(get_process_search_unregistered_device_returns_zero)
{
    StopProcessSearch();
    StartProcessSearch();
    /* Don't call SetProcessSearch — no device registered */
    BYTE mask = GetProcessSearch(100, 0x07, FALSE);
    CHECK_MSG(mask == 0,
              "GetProcessSearch with no device registered should return 0");
    StopProcessSearch();
}

TEST(get_process_search_does_not_crash)
{
    StartProcessSearch();
    /* Even with an invalid device index, must not crash */
    SetProcessSearch(0xDEAD);
    GetProcessSearch(0, 0x07, FALSE);
    StopProcessSearch();
    CHECK(1);
}

/* ================================================================== */
/* SearchProcessAlt                                                     */
/* ================================================================== */

TEST(search_process_null_name)
{
    BOOL r = SearchProcessAlt(NULL);
    CHECK_MSG(r == FALSE, "SearchProcessAlt(NULL) should return FALSE");
}

TEST(search_process_empty_name)
{
    BOOL r = SearchProcessAlt("");
    /* Empty name: no process should have an empty comm */
    CHECK_MSG(r == FALSE, "SearchProcessAlt('') should return FALSE");
}

TEST(search_process_nonexistent)
{
    BOOL r = SearchProcessAlt("__rufus_test_nonexistent_process__");
    CHECK_MSG(r == FALSE,
              "SearchProcessAlt with bogus name should return FALSE");
}

TEST(search_process_self)
{
    /*
     * The current test binary's comm name is the basename of argv[0],
     * truncated to 15 chars by the kernel.
     * We check that SearchProcessAlt with a name we KNOW is running
     * (the current process) returns TRUE.
     *
     * Read /proc/self/comm to get the exact name.
     */
    char comm[64] = "";
    FILE *f = fopen("/proc/self/comm", "r");
    if (f) {
        if (fgets(comm, sizeof(comm), f)) {
            size_t len = strlen(comm);
            if (len > 0 && comm[len - 1] == '\n')
                comm[len - 1] = '\0';
        }
        fclose(f);
    }
    if (comm[0] == '\0') {
        printf("  [SKIP] could not read /proc/self/comm\n");
        return;
    }
    BOOL r = SearchProcessAlt(comm);
    CHECK_MSG(r == TRUE,
              "SearchProcessAlt should find the current running process");
}

/* ================================================================== */
/* EnablePrivileges                                                     */
/* ================================================================== */

TEST(enable_privileges_always_true)
{
    CHECK(EnablePrivileges() == TRUE);
}

/* ================================================================== */
/* main                                                                 */
/* ================================================================== */
int main(void)
{
    printf("=== process_linux tests ===\n");

    RUN(getppid_current_process);
    RUN(getppid_zero_pid);
    RUN(getppid_nonexistent_pid);
    RUN(getppid_pid1_doesnt_crash);

    RUN(start_process_search_returns_true);
    RUN(start_process_search_idempotent);
    RUN(stop_process_search_without_start);
    RUN(stop_process_search_after_start);

    RUN(set_process_search_without_start_fails);
    RUN(set_process_search_after_start);

    RUN(get_process_search_without_start_returns_zero);
    RUN(get_process_search_unregistered_device_returns_zero);
    RUN(get_process_search_does_not_crash);

    RUN(search_process_null_name);
    RUN(search_process_empty_name);
    RUN(search_process_nonexistent);
    RUN(search_process_self);

    RUN(enable_privileges_always_true);

    TEST_RESULTS();
}

#endif /* __linux__ */
