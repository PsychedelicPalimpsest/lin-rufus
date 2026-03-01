/*
 * test_threading.c  — Tests for the Windows threading API compatibility layer.
 *
 * Tests CreateThread / WaitForSingleObject / WaitForMultipleObjects,
 * CreateEvent / SetEvent / ResetEvent, CreateMutex / ReleaseMutex,
 * CRITICAL_SECTION, GetExitCodeThread, CloseHandle, and TerminateThread.
 *
 * Compiles on Linux (against the compat header + -lpthread) and on Windows
 * (against the native Win32 API via MinGW).
 */

#ifdef _WIN32
#  include <windows.h>
#else
#  include "../src/linux/compat/windows.h"
#endif

#include "framework.h"
#include <stdlib.h>
#include <string.h>

/* ---- Helpers ------------------------------------------------------------ */

/* Portable millisecond sleep */
#ifdef _WIN32
#  define msleep(ms) Sleep(ms)
#else
#  include <time.h>
static void msleep(unsigned ms) {
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}
#endif

/* Shared counter used by several tests; marked volatile to prevent
 * the compiler from optimising away cross-thread reads/writes.      */
static volatile LONG g_counter = 0;

/* ---- Thread functions --------------------------------------------------- */

/* Increment g_counter and return 42 */
static DWORD WINAPI thread_increment(LPVOID param) {
    (void)param;
    g_counter++;
    return 42;
}

/* Return the value passed as param cast to DWORD */
static DWORD WINAPI thread_return_param(LPVOID param) {
    return (DWORD)(uintptr_t)param;
}

/* Sleep for 500 ms then set *param to 1 */
static DWORD WINAPI thread_sleep_then_set(LPVOID param) {
    msleep(500);
    *(volatile int *)param = 1;
    return 0;
}

/* SetEvent on the event handle passed as param */
static DWORD WINAPI thread_set_event(LPVOID param) {
    msleep(50);          /* small delay so waiter definitely starts first */
    SetEvent((HANDLE)param);
    return 0;
}

/* Acquire a mutex, sleep briefly, then release it */
static DWORD WINAPI thread_lock_mutex(LPVOID param) {
    HANDLE mx = (HANDLE)param;
    WaitForSingleObject(mx, INFINITE);
    msleep(50);
    ReleaseMutex(mx);
    return 0;
}

/* Increment g_counter under a CRITICAL_SECTION */
typedef struct { CRITICAL_SECTION *cs; int iterations; } cs_args_t;
static DWORD WINAPI thread_cs_increment(LPVOID param) {
    cs_args_t *a = (cs_args_t *)param;
    for (int i = 0; i < a->iterations; i++) {
        EnterCriticalSection(a->cs);
        g_counter++;
        LeaveCriticalSection(a->cs);
    }
    return 0;
}

/* Sleep indefinitely (used to test TerminateThread) */
static DWORD WINAPI thread_sleep_forever(LPVOID param) {
    (void)param;
    msleep(60000);  /* 60 s — test will terminate before this fires */
    return 0;
}

/* ======================================================================== */
/*  Tests                                                                    */
/* ======================================================================== */

/* 1. Basic thread creation and join */
TEST(test_create_thread_basic) {
    g_counter = 0;
    HANDLE h = CreateThread(NULL, 0, thread_increment, NULL, 0, NULL);
    CHECK(h != NULL);
    DWORD r = WaitForSingleObject(h, INFINITE);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r);
    CHECK_INT_EQ(1, (int)g_counter);
    CloseHandle(h);
}

/* 2. Thread exit code retrieved via GetExitCodeThread */
TEST(test_thread_exit_code) {
    HANDLE h = CreateThread(NULL, 0, thread_return_param,
                            (LPVOID)(uintptr_t)0xDEADBEEF, 0, NULL);
    CHECK(h != NULL);
    WaitForSingleObject(h, INFINITE);
    DWORD code = 0;
    BOOL ok = GetExitCodeThread(h, &code);
    CHECK(ok);
    CHECK_INT_EQ((int)0xDEADBEEF, (int)code);
    CloseHandle(h);
}

/* 3. WaitForSingleObject timeout — thread sleeps 500ms, wait only 100ms */
TEST(test_wait_timeout) {
    volatile int flag = 0;
    HANDLE h = CreateThread(NULL, 0, thread_sleep_then_set, (LPVOID)&flag, 0, NULL);
    CHECK(h != NULL);
    DWORD r = WaitForSingleObject(h, 100);
    CHECK_INT_EQ((int)WAIT_TIMEOUT, (int)r);
    /* Let the thread finish before CloseHandle */
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
}

/* 4. WaitForMultipleObjects — wait for all 4 threads */
TEST(test_wait_multiple_threads) {
    g_counter = 0;
    HANDLE handles[4];
    for (int i = 0; i < 4; i++) {
        handles[i] = CreateThread(NULL, 0, thread_increment, NULL, 0, NULL);
        CHECK(handles[i] != NULL);
    }
    DWORD r = WaitForMultipleObjects(4, handles, TRUE, INFINITE);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r);
    CHECK_INT_EQ(4, (int)g_counter);
    for (int i = 0; i < 4; i++) CloseHandle(handles[i]);
}

/* 5. Auto-reset event: signals once, then resets automatically */
TEST(test_auto_reset_event_basic) {
    HANDLE ev = CreateEvent(NULL, FALSE /*auto-reset*/, FALSE /*not signaled*/, NULL);
    CHECK(ev != NULL);

    /* Not yet signaled — brief wait should timeout */
    DWORD r = WaitForSingleObject(ev, 10);
    CHECK_INT_EQ((int)WAIT_TIMEOUT, (int)r);

    /* Signal; the single wait should succeed */
    SetEvent(ev);
    r = WaitForSingleObject(ev, 100);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r);

    /* After auto-reset the second wait should timeout */
    r = WaitForSingleObject(ev, 10);
    CHECK_INT_EQ((int)WAIT_TIMEOUT, (int)r);

    CloseHandle(ev);
}

/* 6. Manual-reset event: stays signaled after multiple waits */
TEST(test_manual_reset_event_basic) {
    HANDLE ev = CreateEvent(NULL, TRUE /*manual-reset*/, FALSE /*not signaled*/, NULL);
    CHECK(ev != NULL);

    SetEvent(ev);

    /* Both waits succeed while event is signaled */
    DWORD r1 = WaitForSingleObject(ev, 100);
    DWORD r2 = WaitForSingleObject(ev, 100);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r1);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r2);

    /* After reset, next wait should timeout */
    ResetEvent(ev);
    DWORD r3 = WaitForSingleObject(ev, 10);
    CHECK_INT_EQ((int)WAIT_TIMEOUT, (int)r3);

    CloseHandle(ev);
}

/* 7. Event initially signaled */
TEST(test_event_initially_signaled) {
    HANDLE ev = CreateEvent(NULL, TRUE, TRUE /*signaled*/, NULL);
    CHECK(ev != NULL);
    DWORD r = WaitForSingleObject(ev, 0);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r);
    CloseHandle(ev);
}

/* 8. SetEvent wakes a blocked thread */
TEST(test_event_wakes_thread) {
    HANDLE ev = CreateEvent(NULL, FALSE, FALSE, NULL);
    CHECK(ev != NULL);

    /* Thread will SetEvent after 50 ms */
    HANDLE h = CreateThread(NULL, 0, thread_set_event, (LPVOID)ev, 0, NULL);
    CHECK(h != NULL);

    /* This wait should be satisfied by the thread's SetEvent */
    DWORD r = WaitForSingleObject(ev, 2000);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r);

    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    CloseHandle(ev);
}

/* 9. Mutex: initially unowned, acquire and release from two threads */
TEST(test_mutex_basic) {
    HANDLE mx = CreateMutex(NULL, FALSE /*not owned*/, NULL);
    CHECK(mx != NULL);

    /* Acquire in this thread */
    DWORD r = WaitForSingleObject(mx, INFINITE);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r);

    /* Spin up a thread that also tries to acquire; it should be blocked */
    g_counter = 0;
    HANDLE h = CreateThread(NULL, 0, thread_lock_mutex, (LPVOID)mx, 0, NULL);
    CHECK(h != NULL);

    /* Hold for 80 ms, verify the thread hasn't finished */
    msleep(80);
    CHECK_INT_EQ(0, (int)g_counter);   /* thread still blocked */

    ReleaseMutex(mx);

    /* Now the thread can run */
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    CloseHandle(mx);
}

/* 10. Mutex initially owned — another thread times out trying to acquire */
TEST(test_mutex_initially_owned) {
    HANDLE mx = CreateMutex(NULL, TRUE /*owned*/, NULL);
    CHECK(mx != NULL);

    /* Different thread tries to lock with a short timeout */
    HANDLE h = CreateThread(NULL, 0, thread_lock_mutex, (LPVOID)mx, 0, NULL);
    CHECK(h != NULL);

    /* Thread should timeout waiting for the mutex (we hold it) */
    DWORD r = WaitForSingleObject(h, 300);
    /* The thread should NOT have finished yet — it's blocked */
    CHECK_INT_EQ((int)WAIT_TIMEOUT, (int)r);

    /* Release and let the thread complete */
    ReleaseMutex(mx);
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    CloseHandle(mx);
}

/* 11. CRITICAL_SECTION basic: exclusive access */
TEST(test_critical_section_basic) {
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);

    EnterCriticalSection(&cs);
    /* We own the CS; verify we can set a flag uncontested */
    int x = 0;
    x = 1;
    LeaveCriticalSection(&cs);

    CHECK_INT_EQ(1, x);
    DeleteCriticalSection(&cs);
}

/* 12. CRITICAL_SECTION recursive: same thread can re-enter */
TEST(test_critical_section_recursive) {
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);

    /* Windows CRITICAL_SECTIONs are recursive — this must not deadlock */
    EnterCriticalSection(&cs);
    EnterCriticalSection(&cs);
    LeaveCriticalSection(&cs);
    LeaveCriticalSection(&cs);

    /* If we got here without deadlock, the test passes */
    CHECK(1);
    DeleteCriticalSection(&cs);
}

/* 13. CRITICAL_SECTION contention: two threads, N iterations each */
TEST(test_critical_section_contention) {
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    g_counter = 0;

    cs_args_t args = { &cs, 1000 };
    HANDLE h1 = CreateThread(NULL, 0, thread_cs_increment, &args, 0, NULL);
    HANDLE h2 = CreateThread(NULL, 0, thread_cs_increment, &args, 0, NULL);
    CHECK(h1 != NULL);
    CHECK(h2 != NULL);

    HANDLE pair[2] = { h1, h2 };
    WaitForMultipleObjects(2, pair, TRUE, INFINITE);
    CloseHandle(h1);
    CloseHandle(h2);

    /* Without the CS protecting g_counter, we'd expect data races and
     * a final value less than 2000.  With the CS, it must be exactly 2000. */
    CHECK_INT_EQ(2000, (int)g_counter);
    DeleteCriticalSection(&cs);
}

/* 14. CloseHandle(NULL) must not crash */
TEST(test_close_null_handle) {
    BOOL r = CloseHandle(NULL);
    CHECK(r == FALSE);   /* documented to return FALSE for invalid handles */
}

/* 15. CloseHandle(INVALID_HANDLE_VALUE) must not crash */
TEST(test_close_invalid_handle) {
#ifdef _WIN32
    /* Wine's CloseHandle incorrectly returns TRUE for INVALID_HANDLE_VALUE;
     * real Windows returns FALSE.  Skip under Wine to avoid a false failure. */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    SKIP_IF(ntdll && GetProcAddress(ntdll, "wine_get_version") != NULL);
#endif
    BOOL r = CloseHandle(INVALID_HANDLE_VALUE);
    CHECK(r == FALSE);
}

/* 16. TerminateThread stops a sleeping thread */
TEST(test_terminate_thread) {
    HANDLE h = CreateThread(NULL, 0, thread_sleep_forever, NULL, 0, NULL);
    CHECK(h != NULL);

    msleep(20);  /* let it start */

    BOOL ok = TerminateThread(h, 99);
    CHECK(ok);

    /* After terminate, WaitForSingleObject should complete quickly */
    DWORD r = WaitForSingleObject(h, 2000);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r);

    CloseHandle(h);
}

/* 17. Auto-reset event is binary: SetEvent twice before any wait is the same
 *     as SetEvent once.  First wait succeeds; second times out.            */
TEST(test_auto_reset_multiple_waits) {
    HANDLE ev = CreateEvent(NULL, FALSE /*auto-reset*/, FALSE, NULL);
    CHECK(ev != NULL);

    /* Signal twice — second SetEvent is a no-op (already signaled) */
    SetEvent(ev);
    SetEvent(ev);

    DWORD r1 = WaitForSingleObject(ev, 100);
    /* After auto-reset, event is cleared */
    DWORD r2 = WaitForSingleObject(ev, 10);

    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r1);
    CHECK_INT_EQ((int)WAIT_TIMEOUT,  (int)r2);

    /* Now signal twice in a row; interleave with waits */
    SetEvent(ev);
    DWORD r3 = WaitForSingleObject(ev, 100);
    SetEvent(ev);
    DWORD r4 = WaitForSingleObject(ev, 100);

    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r3);
    CHECK_INT_EQ((int)WAIT_OBJECT_0, (int)r4);

    CloseHandle(ev);
}

/* 18. Thread DWORD tid output parameter */
TEST(test_create_thread_tid_param) {
    DWORD tid = 0;
    HANDLE h = CreateThread(NULL, 0, thread_increment, NULL, 0, &tid);
    CHECK(h != NULL);
    WaitForSingleObject(h, INFINITE);
    /* tid should be a non-zero thread ID */
    CHECK(tid != 0);
    CloseHandle(h);
}

/* ======================================================================== */
int main(void) {
    printf("--- Threading API compatibility layer tests ---\n\n");

    RUN(test_create_thread_basic);
    RUN(test_thread_exit_code);
    RUN(test_wait_timeout);
    RUN(test_wait_multiple_threads);
    RUN(test_auto_reset_event_basic);
    RUN(test_manual_reset_event_basic);
    RUN(test_event_initially_signaled);
    RUN(test_event_wakes_thread);
    RUN(test_mutex_basic);
    RUN(test_mutex_initially_owned);
    RUN(test_critical_section_basic);
    RUN(test_critical_section_recursive);
    RUN(test_critical_section_contention);
    RUN(test_close_null_handle);
    RUN(test_close_invalid_handle);
    RUN(test_terminate_thread);
    RUN(test_auto_reset_multiple_waits);
    RUN(test_create_thread_tid_param);

    TEST_RESULTS();
}
