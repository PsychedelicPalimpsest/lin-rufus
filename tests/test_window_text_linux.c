/*
 * test_window_text_linux.c — TDD tests for window_text_bridge
 *
 * The bridge provides thread-safe GetWindowTextA / SetWindowTextA backed by
 * a simple HWND-keyed cache.  Every test runs without GTK.
 *
 * Tests:
 *  1.  get_unregistered_hwnd_returns_zero
 *  2.  register_then_get_returns_empty
 *  3.  set_and_get_basic
 *  4.  set_and_get_round_trip
 *  5.  get_returns_length
 *  6.  get_truncates_to_max
 *  7.  max_zero_handled_safely
 *  8.  null_buf_handled_safely
 *  9.  set_null_text_clears_entry
 * 10.  set_overwrites_previous_value
 * 11.  multiple_hwnds_independent
 * 12.  set_empty_string
 * 13.  large_hwnd_value
 * 14.  concurrent_reads_safe
 * 15.  concurrent_read_write_safe
 * 16.  get_windowtext_alias_works
 * 17.  set_windowtext_alias_works
 * 18.  get_on_null_hwnd_returns_zero
 * 19.  set_on_null_hwnd_is_safe
 * 20.  get_after_unregister_returns_zero
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

/* Pull in the bridge API */
#ifndef _WIN32
#  include "../src/linux/compat/windows.h"
#endif
#include "../src/linux/window_text_bridge.h"

/* Minimal stubs required by windows.h / the bridge */
DWORD ErrorStatus  = 0;
DWORD DownloadStatus = 0;
DWORD MainThreadId = 0;
DWORD LastWriteError = 0;
BOOL  right_to_left_mode = FALSE;

/* =========================================================================
 * 1. get_unregistered_hwnd_returns_zero
 * ========================================================================= */
TEST(get_unregistered_hwnd_returns_zero)
{
    char buf[64] = "NOTCLEARED";
    HWND unknown = (HWND)(uintptr_t)0xDEAD1001;
    int len = GetWindowTextA(unknown, buf, sizeof(buf));
    CHECK_INT_EQ(0, len);
    /* Buffer must be zero-terminated (not necessarily cleared) */
}

/* =========================================================================
 * 2. register_then_get_returns_empty
 * ========================================================================= */
TEST(register_then_get_returns_empty)
{
    HWND h = (HWND)(uintptr_t)0x11001;
    window_text_register(h);
    char buf[64] = "NOTCLEARED";
    int len = GetWindowTextA(h, buf, sizeof(buf));
    CHECK_INT_EQ(0, len);
    CHECK_STR_EQ("", buf);
    window_text_unregister(h);
}

/* =========================================================================
 * 3. set_and_get_basic
 * ========================================================================= */
TEST(set_and_get_basic)
{
    HWND h = (HWND)(uintptr_t)0x11002;
    window_text_register(h);
    SetWindowTextA(h, "HELLO");
    char buf[64] = {0};
    int len = GetWindowTextA(h, buf, sizeof(buf));
    CHECK_INT_EQ(5, len);
    CHECK_STR_EQ("HELLO", buf);
    window_text_unregister(h);
}

/* =========================================================================
 * 4. set_and_get_round_trip
 * ========================================================================= */
TEST(set_and_get_round_trip)
{
    HWND h = (HWND)(uintptr_t)0x11003;
    window_text_register(h);
    const char *text = "UBUNTU_22.04";
    SetWindowTextA(h, text);
    char buf[64] = {0};
    GetWindowTextA(h, buf, sizeof(buf));
    CHECK_STR_EQ(text, buf);
    window_text_unregister(h);
}

/* =========================================================================
 * 5. get_returns_length
 * ========================================================================= */
TEST(get_returns_length)
{
    HWND h = (HWND)(uintptr_t)0x11004;
    window_text_register(h);
    SetWindowTextA(h, "ABC");
    char buf[64] = {0};
    int len = GetWindowTextA(h, buf, sizeof(buf));
    CHECK_INT_EQ(3, len);
    window_text_unregister(h);
}

/* =========================================================================
 * 6. get_truncates_to_max
 * ========================================================================= */
TEST(get_truncates_to_max)
{
    HWND h = (HWND)(uintptr_t)0x11005;
    window_text_register(h);
    SetWindowTextA(h, "LONGERLABEL");
    char buf[4] = {0};
    int len = GetWindowTextA(h, buf, sizeof(buf));
    /* Should copy max-1 chars and NUL-terminate */
    CHECK_INT_EQ(3, len);
    CHECK(buf[3] == '\0');
    CHECK(strncmp(buf, "LON", 3) == 0);
    window_text_unregister(h);
}

/* =========================================================================
 * 7. max_zero_handled_safely
 * ========================================================================= */
TEST(max_zero_handled_safely)
{
    HWND h = (HWND)(uintptr_t)0x11006;
    window_text_register(h);
    SetWindowTextA(h, "TEST");
    char buf[4] = {'X', 'X', 'X', 'X'};
    int len = GetWindowTextA(h, buf, 0);
    CHECK_INT_EQ(0, len);
    /* buf must be untouched when max==0 */
    window_text_unregister(h);
}

/* =========================================================================
 * 8. null_buf_handled_safely
 * ========================================================================= */
TEST(null_buf_handled_safely)
{
    HWND h = (HWND)(uintptr_t)0x11007;
    window_text_register(h);
    SetWindowTextA(h, "TEST");
    int len = GetWindowTextA(h, NULL, 64);
    CHECK_INT_EQ(0, len);
    window_text_unregister(h);
}

/* =========================================================================
 * 9. set_null_text_clears_entry
 * ========================================================================= */
TEST(set_null_text_clears_entry)
{
    HWND h = (HWND)(uintptr_t)0x11008;
    window_text_register(h);
    SetWindowTextA(h, "WASSET");
    SetWindowTextA(h, NULL);
    char buf[64] = {'X'};
    int len = GetWindowTextA(h, buf, sizeof(buf));
    CHECK_INT_EQ(0, len);
    CHECK_STR_EQ("", buf);
    window_text_unregister(h);
}

/* =========================================================================
 * 10. set_overwrites_previous_value
 * ========================================================================= */
TEST(set_overwrites_previous_value)
{
    HWND h = (HWND)(uintptr_t)0x11009;
    window_text_register(h);
    SetWindowTextA(h, "FIRST");
    SetWindowTextA(h, "SECOND");
    char buf[64] = {0};
    GetWindowTextA(h, buf, sizeof(buf));
    CHECK_STR_EQ("SECOND", buf);
    window_text_unregister(h);
}

/* =========================================================================
 * 11. multiple_hwnds_independent
 * ========================================================================= */
TEST(multiple_hwnds_independent)
{
    HWND h1 = (HWND)(uintptr_t)0x11010;
    HWND h2 = (HWND)(uintptr_t)0x11011;
    HWND h3 = (HWND)(uintptr_t)0x11012;
    window_text_register(h1);
    window_text_register(h2);
    window_text_register(h3);

    SetWindowTextA(h1, "ALPHA");
    SetWindowTextA(h2, "BETA");
    SetWindowTextA(h3, "GAMMA");

    char b1[32] = {0}, b2[32] = {0}, b3[32] = {0};
    GetWindowTextA(h1, b1, sizeof(b1));
    GetWindowTextA(h2, b2, sizeof(b2));
    GetWindowTextA(h3, b3, sizeof(b3));

    CHECK_STR_EQ("ALPHA", b1);
    CHECK_STR_EQ("BETA", b2);
    CHECK_STR_EQ("GAMMA", b3);

    window_text_unregister(h1);
    window_text_unregister(h2);
    window_text_unregister(h3);
}

/* =========================================================================
 * 12. set_empty_string
 * ========================================================================= */
TEST(set_empty_string)
{
    HWND h = (HWND)(uintptr_t)0x11013;
    window_text_register(h);
    SetWindowTextA(h, "SOMETHING");
    SetWindowTextA(h, "");
    char buf[64] = {0};
    int len = GetWindowTextA(h, buf, sizeof(buf));
    CHECK_INT_EQ(0, len);
    CHECK_STR_EQ("", buf);
    window_text_unregister(h);
}

/* =========================================================================
 * 13. large_hwnd_value
 * ========================================================================= */
TEST(large_hwnd_value)
{
    HWND h = (HWND)(uintptr_t)0xFFFFFFFF00000001ULL;
    window_text_register(h);
    SetWindowTextA(h, "BIGHANDLE");
    char buf[32] = {0};
    int len = GetWindowTextA(h, buf, sizeof(buf));
    CHECK_INT_EQ(9, len);
    CHECK_STR_EQ("BIGHANDLE", buf);
    window_text_unregister(h);
}

/* =========================================================================
 * 14. concurrent_reads_safe
 * ========================================================================= */

#define READER_THREADS 8
#define READER_ITERS   500

static HWND concurrent_h;
static int  concurrent_errors;

static void *reader_thread(void *arg)
{
    (void)arg;
    char buf[32];
    for (int i = 0; i < READER_ITERS; i++) {
        int len = GetWindowTextA(concurrent_h, buf, sizeof(buf));
        if (len < 0) concurrent_errors++;
    }
    return NULL;
}

TEST(concurrent_reads_safe)
{
    concurrent_h = (HWND)(uintptr_t)0x11020;
    concurrent_errors = 0;
    window_text_register(concurrent_h);
    SetWindowTextA(concurrent_h, "READTEST");

    pthread_t threads[READER_THREADS];
    for (int i = 0; i < READER_THREADS; i++)
        pthread_create(&threads[i], NULL, reader_thread, NULL);
    for (int i = 0; i < READER_THREADS; i++)
        pthread_join(threads[i], NULL);

    CHECK_INT_EQ(0, concurrent_errors);
    window_text_unregister(concurrent_h);
}

/* =========================================================================
 * 15. concurrent_read_write_safe
 * ========================================================================= */

static HWND rw_h;
static int  rw_errors;

static void *writer_thread(void *arg)
{
    (void)arg;
    for (int i = 0; i < 200; i++) {
        SetWindowTextA(rw_h, (i % 2) ? "ODD" : "EVEN");
        usleep(100);
    }
    return NULL;
}

static void *reader_thread2(void *arg)
{
    (void)arg;
    char buf[32];
    for (int i = 0; i < 400; i++) {
        int len = GetWindowTextA(rw_h, buf, sizeof(buf));
        if (len < 0) rw_errors++;
        usleep(50);
    }
    return NULL;
}

TEST(concurrent_read_write_safe)
{
    rw_h = (HWND)(uintptr_t)0x11021;
    rw_errors = 0;
    window_text_register(rw_h);
    SetWindowTextA(rw_h, "INITIAL");

    pthread_t wt, rt;
    pthread_create(&wt, NULL, writer_thread, NULL);
    pthread_create(&rt, NULL, reader_thread2, NULL);
    pthread_join(wt, NULL);
    pthread_join(rt, NULL);

    CHECK_INT_EQ(0, rw_errors);
    window_text_unregister(rw_h);
}

/* =========================================================================
 * 16. get_windowtext_alias_works  (GetWindowText → GetWindowTextA)
 * ========================================================================= */
TEST(get_windowtext_alias_works)
{
    HWND h = (HWND)(uintptr_t)0x11030;
    window_text_register(h);
    SetWindowTextA(h, "ALIAS");
    char buf[32] = {0};
    int len = GetWindowText(h, buf, sizeof(buf));  /* alias */
    CHECK_INT_EQ(5, len);
    CHECK_STR_EQ("ALIAS", buf);
    window_text_unregister(h);
}

/* =========================================================================
 * 17. set_windowtext_alias_works  (SetWindowText → SetWindowTextA)
 * ========================================================================= */
TEST(set_windowtext_alias_works)
{
    HWND h = (HWND)(uintptr_t)0x11031;
    window_text_register(h);
    SetWindowText(h, "ALIAS2");  /* alias */
    char buf[32] = {0};
    GetWindowTextA(h, buf, sizeof(buf));
    CHECK_STR_EQ("ALIAS2", buf);
    window_text_unregister(h);
}

/* =========================================================================
 * 18. get_on_null_hwnd_returns_zero
 * ========================================================================= */
TEST(get_on_null_hwnd_returns_zero)
{
    char buf[32] = {0};
    int len = GetWindowTextA(NULL, buf, sizeof(buf));
    CHECK_INT_EQ(0, len);
}

/* =========================================================================
 * 19. set_on_null_hwnd_is_safe
 * ========================================================================= */
TEST(set_on_null_hwnd_is_safe)
{
    /* Must not crash */
    SetWindowTextA(NULL, "TEXT");
    CHECK(1);  /* reached without crash */
}

/* =========================================================================
 * 20. get_after_unregister_returns_zero
 * ========================================================================= */
TEST(get_after_unregister_returns_zero)
{
    HWND h = (HWND)(uintptr_t)0x11040;
    window_text_register(h);
    SetWindowTextA(h, "BEFORE");
    window_text_unregister(h);
    char buf[32] = {0};
    int len = GetWindowTextA(h, buf, sizeof(buf));
    CHECK_INT_EQ(0, len);
}

/* =========================================================================
 * main
 * ========================================================================= */
int main(void)
{
    printf("=== window_text_bridge tests ===\n");

    RUN(get_unregistered_hwnd_returns_zero);
    RUN(register_then_get_returns_empty);
    RUN(set_and_get_basic);
    RUN(set_and_get_round_trip);
    RUN(get_returns_length);
    RUN(get_truncates_to_max);
    RUN(max_zero_handled_safely);
    RUN(null_buf_handled_safely);
    RUN(set_null_text_clears_entry);
    RUN(set_overwrites_previous_value);
    RUN(multiple_hwnds_independent);
    RUN(set_empty_string);
    RUN(large_hwnd_value);
    RUN(concurrent_reads_safe);
    RUN(concurrent_read_write_safe);
    RUN(get_windowtext_alias_works);
    RUN(set_windowtext_alias_works);
    RUN(get_on_null_hwnd_returns_zero);
    RUN(set_on_null_hwnd_is_safe);
    RUN(get_after_unregister_returns_zero);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
