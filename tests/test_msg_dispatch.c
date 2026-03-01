/*
 * test_msg_dispatch.c — Tests for the Windows PostMessage/SendMessage
 *                       compatibility dispatch layer.
 *
 * Tests cover:
 *   - Handler registration / unregistration
 *   - msg_send() calling handler directly on the same thread
 *   - msg_post() scheduling via a pluggable scheduler
 *   - Cross-thread msg_send() (blocks caller until main thread processes)
 *   - Cross-thread msg_post() (fire-and-forget, processed by main)
 *   - Unregistered HWND returns 0 / FALSE
 *   - Re-registration replaces the previous handler
 *   - NULL HWND edge case
 *   - Thread safety of the handler registry
 *
 * Compiles on Linux only (message dispatch is a Linux compat feature).
 */

#ifndef __linux__
int main(void) { return 0; } /* Skip on non-Linux */
#else

#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/msg_dispatch.h"

#include "framework.h"

#include <stdatomic.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- Portable millisecond sleep ---- */
static void msleep(unsigned ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* ===========================================================================
 * Fake HWND values — just distinct pointers (never dereferenced by dispatch)
 * ========================================================================= */
static int _hwnd_a_storage;
static int _hwnd_b_storage;
#define FAKE_HWND_A  ((HWND)&_hwnd_a_storage)
#define FAKE_HWND_B  ((HWND)&_hwnd_b_storage)

/* ===========================================================================
 * Synchronous test scheduler
 * Runs the callback immediately in the calling thread — deterministic.
 * ========================================================================= */
static void sync_scheduler(void (*fn)(void*), void *data) {
    fn(data);
}

/* ===========================================================================
 * Async test scheduler
 * Queues work items; the "main" thread drains them by calling
 * drain_async_scheduler().  Used to test cross-thread SendMessage blocking.
 * ========================================================================= */
#define SCHED_QUEUE_MAX 64
typedef struct { void (*fn)(void*); void *data; } SchedItem;
static SchedItem sched_queue[SCHED_QUEUE_MAX];
static int sched_head = 0, sched_tail = 0;
static pthread_mutex_t sched_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  sched_cond  = PTHREAD_COND_INITIALIZER;

static void async_scheduler(void (*fn)(void*), void *data) {
    pthread_mutex_lock(&sched_mutex);
    sched_queue[sched_tail % SCHED_QUEUE_MAX].fn   = fn;
    sched_queue[sched_tail % SCHED_QUEUE_MAX].data = data;
    sched_tail++;
    pthread_cond_signal(&sched_cond);
    pthread_mutex_unlock(&sched_mutex);
}

/* Drain one item; blocks for up to 2 s waiting for work. Returns 1 if drained. */
static int drain_one(void) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;

    pthread_mutex_lock(&sched_mutex);
    while (sched_head == sched_tail) {
        if (pthread_cond_timedwait(&sched_cond, &sched_mutex, &deadline) != 0) {
            pthread_mutex_unlock(&sched_mutex);
            return 0; /* timed out */
        }
    }
    SchedItem item = sched_queue[sched_head++ % SCHED_QUEUE_MAX];
    pthread_mutex_unlock(&sched_mutex);
    item.fn(item.data);
    return 1;
}

static void reset_async_scheduler(void) {
    pthread_mutex_lock(&sched_mutex);
    sched_head = sched_tail = 0;
    pthread_mutex_unlock(&sched_mutex);
}

/* ===========================================================================
 * Simple message handler helpers
 * ========================================================================= */

/* Records the last call's arguments and returns a configurable value. */
typedef struct {
    HWND   last_hwnd;
    UINT   last_msg;
    WPARAM last_w;
    LPARAM last_l;
    int    call_count;
    LRESULT retval;
} HandlerState;

static HandlerState g_handler_a = {0};
static HandlerState g_handler_b = {0};

static LRESULT handler_a(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    g_handler_a.last_hwnd = hwnd;
    g_handler_a.last_msg  = msg;
    g_handler_a.last_w    = w;
    g_handler_a.last_l    = l;
    g_handler_a.call_count++;
    return g_handler_a.retval;
}

static LRESULT handler_b(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    g_handler_b.last_hwnd = hwnd;
    g_handler_b.last_msg  = msg;
    g_handler_b.last_w    = w;
    g_handler_b.last_l    = l;
    g_handler_b.call_count++;
    return g_handler_b.retval;
}

/* Reset handler state before each test group */
static void reset_handlers(void) {
    memset(&g_handler_a, 0, sizeof(g_handler_a));
    memset(&g_handler_b, 0, sizeof(g_handler_b));
}

/* ===========================================================================
 * Tests — Registration
 * ========================================================================= */

TEST(register_and_send_basic) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    reset_handlers();

    msg_dispatch_register(FAKE_HWND_A, handler_a);

    g_handler_a.retval = 42;
    LRESULT r = msg_send(FAKE_HWND_A, WM_USER + 1, 10, 20);

    CHECK_INT_EQ(1, g_handler_a.call_count);
    CHECK(g_handler_a.last_hwnd == FAKE_HWND_A);
    CHECK_INT_EQ((int)(WM_USER + 1), (int)g_handler_a.last_msg);
    CHECK_INT_EQ(10, (int)g_handler_a.last_w);
    CHECK_INT_EQ(20, (int)g_handler_a.last_l);
    CHECK_INT_EQ(42, (int)r);

    msg_dispatch_unregister(FAKE_HWND_A);
}

TEST(send_to_unregistered_hwnd_returns_zero) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    reset_handlers();

    /* Do not register anything */
    LRESULT r = msg_send(FAKE_HWND_A, WM_USER, 0, 0);
    CHECK_INT_EQ(0, (int)r);
    CHECK_INT_EQ(0, g_handler_a.call_count);
}

TEST(post_to_unregistered_hwnd_returns_false) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);

    BOOL r = msg_post(FAKE_HWND_A, WM_USER, 0, 0);
    CHECK(r == FALSE);
}

TEST(send_to_null_hwnd_returns_zero) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    LRESULT r = msg_send(NULL, WM_USER, 0, 0);
    CHECK_INT_EQ(0, (int)r);
}

TEST(post_to_null_hwnd_returns_false) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    BOOL r = msg_post(NULL, WM_USER, 0, 0);
    CHECK(r == FALSE);
}

TEST(two_handlers_independent) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    reset_handlers();

    msg_dispatch_register(FAKE_HWND_A, handler_a);
    msg_dispatch_register(FAKE_HWND_B, handler_b);

    g_handler_a.retval = 1;
    g_handler_b.retval = 2;

    LRESULT ra = msg_send(FAKE_HWND_A, WM_USER,     1, 0);
    LRESULT rb = msg_send(FAKE_HWND_B, WM_USER + 1, 2, 0);

    CHECK_INT_EQ(1, g_handler_a.call_count);
    CHECK_INT_EQ(1, g_handler_b.call_count);
    CHECK_INT_EQ(1, (int)ra);
    CHECK_INT_EQ(2, (int)rb);
    /* Each handler only saw its own HWND */
    CHECK(g_handler_a.last_hwnd == FAKE_HWND_A);
    CHECK(g_handler_b.last_hwnd == FAKE_HWND_B);

    msg_dispatch_unregister(FAKE_HWND_A);
    msg_dispatch_unregister(FAKE_HWND_B);
}

TEST(unregister_stops_dispatch) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    reset_handlers();

    msg_dispatch_register(FAKE_HWND_A, handler_a);
    msg_send(FAKE_HWND_A, WM_USER, 0, 0);
    CHECK_INT_EQ(1, g_handler_a.call_count);

    msg_dispatch_unregister(FAKE_HWND_A);
    LRESULT r = msg_send(FAKE_HWND_A, WM_USER, 0, 0);
    CHECK_INT_EQ(1, g_handler_a.call_count);  /* not called again */
    CHECK_INT_EQ(0, (int)r);
}

TEST(re_register_replaces_handler) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    reset_handlers();

    msg_dispatch_register(FAKE_HWND_A, handler_a);
    msg_send(FAKE_HWND_A, WM_USER, 0, 0);
    CHECK_INT_EQ(1, g_handler_a.call_count);
    CHECK_INT_EQ(0, g_handler_b.call_count);

    /* Replace handler_a with handler_b for the same HWND */
    msg_dispatch_register(FAKE_HWND_A, handler_b);
    msg_send(FAKE_HWND_A, WM_USER, 0, 0);
    CHECK_INT_EQ(1, g_handler_a.call_count);  /* a NOT called again */
    CHECK_INT_EQ(1, g_handler_b.call_count);  /* b called instead */

    msg_dispatch_unregister(FAKE_HWND_A);
}

/* ===========================================================================
 * Tests — msg_post
 * ========================================================================= */

TEST(post_dispatches_via_scheduler) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    reset_handlers();
    g_handler_a.retval = 99;

    msg_dispatch_register(FAKE_HWND_A, handler_a);
    BOOL ok = msg_post(FAKE_HWND_A, WM_APP, 5, 6);

    CHECK(ok == TRUE);
    /* With sync_scheduler, the handler is invoked immediately */
    CHECK_INT_EQ(1, g_handler_a.call_count);
    CHECK_INT_EQ((int)WM_APP, (int)g_handler_a.last_msg);
    CHECK_INT_EQ(5, (int)g_handler_a.last_w);
    CHECK_INT_EQ(6, (int)g_handler_a.last_l);

    msg_dispatch_unregister(FAKE_HWND_A);
}

TEST(post_with_no_scheduler_still_dispatches) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(NULL);  /* no scheduler — should fall back to sync */
    reset_handlers();
    msg_dispatch_register(FAKE_HWND_A, handler_a);

    BOOL ok = msg_post(FAKE_HWND_A, WM_USER, 0, 0);
    CHECK(ok == TRUE);
    CHECK_INT_EQ(1, g_handler_a.call_count);

    msg_dispatch_unregister(FAKE_HWND_A);
    msg_dispatch_set_scheduler(sync_scheduler);
}

TEST(post_multiple_messages_in_order) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);

    /* Use a counter handler to verify ordering */
    static int order[4];
    static int order_idx = 0;
    order_idx = 0;

    LRESULT order_handler(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
        (void)hwnd; (void)l;
        if (order_idx < 4) order[order_idx++] = (int)w;
        return (LRESULT)msg;
    }

    msg_dispatch_register(FAKE_HWND_A, order_handler);

    msg_post(FAKE_HWND_A, WM_USER, 1, 0);
    msg_post(FAKE_HWND_A, WM_USER, 2, 0);
    msg_post(FAKE_HWND_A, WM_USER, 3, 0);

    CHECK_INT_EQ(3, order_idx);
    CHECK_INT_EQ(1, order[0]);
    CHECK_INT_EQ(2, order[1]);
    CHECK_INT_EQ(3, order[2]);

    msg_dispatch_unregister(FAKE_HWND_A);
}

/* ===========================================================================
 * Tests — Cross-thread msg_send
 * Spawns a worker thread that sends a message; the main thread is the
 * "scheduler" that drains the async queue.
 * ========================================================================= */

typedef struct {
    HWND    hwnd;
    UINT    msg;
    WPARAM  w;
    LPARAM  l;
    LRESULT result;
    int     done;
} ThreadSendArgs;

static void *thread_do_send(void *arg) {
    ThreadSendArgs *a = arg;
    a->result = msg_send(a->hwnd, a->msg, a->w, a->l);
    a->done = 1;
    return NULL;
}

TEST(cross_thread_send_blocks_and_returns_result) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(async_scheduler);
    reset_async_scheduler();
    reset_handlers();
    g_handler_a.retval = 77;

    msg_dispatch_register(FAKE_HWND_A, handler_a);

    ThreadSendArgs args = {
        .hwnd = FAKE_HWND_A,
        .msg  = WM_USER + 5,
        .w    = 100,
        .l    = 200,
        .result = 0,
        .done = 0,
    };

    pthread_t t;
    pthread_create(&t, NULL, thread_do_send, &args);

    /* Drain the one item the worker posted (simulates GTK main loop) */
    int drained = drain_one();
    CHECK(drained == 1);

    pthread_join(t, NULL);

    CHECK(args.done == 1);
    CHECK_INT_EQ(77, (int)args.result);
    CHECK_INT_EQ(1, g_handler_a.call_count);
    CHECK_INT_EQ((int)(WM_USER + 5), (int)g_handler_a.last_msg);
    CHECK_INT_EQ(100, (int)g_handler_a.last_w);
    CHECK_INT_EQ(200, (int)g_handler_a.last_l);

    msg_dispatch_unregister(FAKE_HWND_A);
    msg_dispatch_set_scheduler(sync_scheduler);
}

/* ===========================================================================
 * Tests — Cross-thread msg_post
 * Worker posts a message; main thread drains the queue.
 * ========================================================================= */

typedef struct {
    HWND   hwnd;
    UINT   msg;
    WPARAM w;
    LPARAM l;
    BOOL   result;
} ThreadPostArgs;

static void *thread_do_post(void *arg) {
    ThreadPostArgs *a = arg;
    a->result = msg_post(a->hwnd, a->msg, a->w, a->l);
    return NULL;
}

TEST(cross_thread_post_fires_on_main_thread) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(async_scheduler);
    reset_async_scheduler();
    reset_handlers();
    g_handler_a.retval = 0;

    msg_dispatch_register(FAKE_HWND_A, handler_a);

    ThreadPostArgs args = {
        .hwnd = FAKE_HWND_A,
        .msg  = WM_APP + 1,
        .w    = 55,
        .l    = 66,
        .result = FALSE,
    };

    pthread_t t;
    pthread_create(&t, NULL, thread_do_post, &args);
    pthread_join(t, NULL);  /* Post returns immediately; worker done */

    /* Handler NOT yet called — item sits in queue */
    CHECK_INT_EQ(0, g_handler_a.call_count);
    CHECK(args.result == TRUE);

    /* Main thread drains the queue */
    int drained = drain_one();
    CHECK(drained == 1);
    CHECK_INT_EQ(1, g_handler_a.call_count);
    CHECK_INT_EQ((int)(WM_APP + 1), (int)g_handler_a.last_msg);
    CHECK_INT_EQ(55, (int)g_handler_a.last_w);
    CHECK_INT_EQ(66, (int)g_handler_a.last_l);

    msg_dispatch_unregister(FAKE_HWND_A);
    msg_dispatch_set_scheduler(sync_scheduler);
}

/* ===========================================================================
 * Tests — Multiple concurrent msg_send calls from different threads
 * ========================================================================= */

#define CONCURRENT_THREADS 8
static atomic_int g_concurrent_counter = 0;

static LRESULT counting_handler(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    (void)hwnd; (void)msg; (void)w; (void)l;
    atomic_fetch_add(&g_concurrent_counter, 1);
    return 0;
}

static void *thread_concurrent_send(void *arg) {
    HWND hwnd = (HWND)arg;
    msg_send(hwnd, WM_USER, 0, 0);
    return NULL;
}

TEST(concurrent_sends_all_dispatched) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(async_scheduler);
    reset_async_scheduler();
    atomic_store(&g_concurrent_counter, 0);

    msg_dispatch_register(FAKE_HWND_A, counting_handler);

    pthread_t threads[CONCURRENT_THREADS];
    for (int i = 0; i < CONCURRENT_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_concurrent_send, FAKE_HWND_A);

    /* Drain all CONCURRENT_THREADS items */
    for (int i = 0; i < CONCURRENT_THREADS; i++)
        drain_one();

    for (int i = 0; i < CONCURRENT_THREADS; i++)
        pthread_join(threads[i], NULL);

    CHECK_INT_EQ(CONCURRENT_THREADS, atomic_load(&g_concurrent_counter));

    msg_dispatch_unregister(FAKE_HWND_A);
    msg_dispatch_set_scheduler(sync_scheduler);
}

/* ===========================================================================
 * Tests — Windows macro aliases (PostMessage / SendMessage)
 * The compat layer #defines PostMessage → msg_post and SendMessage → msg_send.
 * Verify the macros work correctly.
 * ========================================================================= */

TEST(postmessage_macro_works) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    reset_handlers();
    msg_dispatch_register(FAKE_HWND_A, handler_a);

    BOOL ok = PostMessage(FAKE_HWND_A, WM_USER, 7, 8);
    CHECK(ok == TRUE);
    CHECK_INT_EQ(1, g_handler_a.call_count);
    CHECK_INT_EQ(7, (int)g_handler_a.last_w);
    CHECK_INT_EQ(8, (int)g_handler_a.last_l);

    msg_dispatch_unregister(FAKE_HWND_A);
}

TEST(sendmessage_macro_works) {
    msg_dispatch_init();
    msg_dispatch_set_scheduler(sync_scheduler);
    reset_handlers();
    g_handler_a.retval = 55;
    msg_dispatch_register(FAKE_HWND_A, handler_a);

    LRESULT r = SendMessage(FAKE_HWND_A, WM_USER + 2, 3, 4);
    CHECK_INT_EQ(55, (int)r);
    CHECK_INT_EQ(1, g_handler_a.call_count);

    msg_dispatch_unregister(FAKE_HWND_A);
}

/* ===========================================================================
 * Tests — UM_* message constants defined in rufus.h
 * Just verify the constants exist and have sensible values.
 * ========================================================================= */

TEST(um_constants_are_in_wm_app_range) {
    /* UM_FORMAT_COMPLETED = WM_APP; rest follow sequentially */
    CHECK(UM_FORMAT_COMPLETED >= WM_APP);
    CHECK(UM_MEDIA_CHANGE     >  UM_FORMAT_COMPLETED);
    CHECK(UM_ENABLE_CONTROLS  >  UM_MEDIA_CHANGE);
    CHECK(UM_FORMAT_START     >  UM_ENABLE_CONTROLS);
    CHECK(UM_LANGUAGE_MENU    >= (UINT)(WM_APP + 0x100));
}

/* ===========================================================================
 * main
 * ========================================================================= */

int main(void) {
    printf("=== msg_dispatch tests ===\n");

    RUN(register_and_send_basic);
    RUN(send_to_unregistered_hwnd_returns_zero);
    RUN(post_to_unregistered_hwnd_returns_false);
    RUN(send_to_null_hwnd_returns_zero);
    RUN(post_to_null_hwnd_returns_false);
    RUN(two_handlers_independent);
    RUN(unregister_stops_dispatch);
    RUN(re_register_replaces_handler);

    RUN(post_dispatches_via_scheduler);
    RUN(post_with_no_scheduler_still_dispatches);
    RUN(post_multiple_messages_in_order);

    RUN(cross_thread_send_blocks_and_returns_result);
    RUN(cross_thread_post_fires_on_main_thread);
    RUN(concurrent_sends_all_dispatched);

    RUN(postmessage_macro_works);
    RUN(sendmessage_macro_works);

    RUN(um_constants_are_in_wm_app_range);

    TEST_RESULTS();
}

#endif /* __linux__ */
