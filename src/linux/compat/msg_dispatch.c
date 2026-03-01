/*
 * msg_dispatch.c — PostMessage / SendMessage compatibility dispatch layer
 *
 * See msg_dispatch.h for the full API description.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include "msg_dispatch.h"

/* ---- Configuration ---- */

/** Maximum number of simultaneously registered HWNDs. */
#define MAX_HANDLERS 32

/* ---- Handler registry ---- */

typedef struct {
    HWND         hwnd;
    MsgHandlerFn fn;
} HandlerEntry;

static HandlerEntry g_handlers[MAX_HANDLERS];
static int          g_handler_count = 0;
static pthread_mutex_t g_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ---- Main thread ID ---- */

static pthread_t g_main_thread;
static int       g_initialised = 0;

/* ---- Post scheduler ---- */

static MsgPostScheduler g_scheduler = NULL;

/* =========================================================================
 * Internal helpers
 * ======================================================================= */

/** Return the registered handler for hwnd, or NULL. Caller must hold registry lock. */
static MsgHandlerFn find_handler_locked(HWND hwnd) {
    for (int i = 0; i < g_handler_count; i++) {
        if (g_handlers[i].hwnd == hwnd)
            return g_handlers[i].fn;
    }
    return NULL;
}

/** TRUE if the calling thread is the main thread. */
static int is_main_thread(void) {
    return g_initialised && pthread_equal(pthread_self(), g_main_thread);
}

/* =========================================================================
 * Lifecycle
 * ======================================================================= */

void msg_dispatch_init(void) {
    g_main_thread  = pthread_self();
    g_initialised  = 1;
    g_handler_count = 0;
    g_scheduler     = NULL;
}

/* =========================================================================
 * Handler registry
 * ======================================================================= */

void msg_dispatch_register(HWND hwnd, MsgHandlerFn fn) {
    if (!hwnd || !fn) return;

    pthread_mutex_lock(&g_registry_mutex);

    /* Replace existing entry for this HWND if present */
    for (int i = 0; i < g_handler_count; i++) {
        if (g_handlers[i].hwnd == hwnd) {
            g_handlers[i].fn = fn;
            pthread_mutex_unlock(&g_registry_mutex);
            return;
        }
    }

    /* Add new entry */
    if (g_handler_count < MAX_HANDLERS) {
        g_handlers[g_handler_count].hwnd = hwnd;
        g_handlers[g_handler_count].fn   = fn;
        g_handler_count++;
    }
    /* Silently drop if table is full — shouldn't happen in practice */

    pthread_mutex_unlock(&g_registry_mutex);
}

void msg_dispatch_unregister(HWND hwnd) {
    if (!hwnd) return;

    pthread_mutex_lock(&g_registry_mutex);

    for (int i = 0; i < g_handler_count; i++) {
        if (g_handlers[i].hwnd == hwnd) {
            /* Swap with last entry and decrement count */
            g_handlers[i] = g_handlers[--g_handler_count];
            break;
        }
    }

    pthread_mutex_unlock(&g_registry_mutex);
}

/* =========================================================================
 * Scheduler
 * ======================================================================= */

void msg_dispatch_set_scheduler(MsgPostScheduler sched) {
    g_scheduler = sched;
}

/* =========================================================================
 * Asynchronous dispatch (PostMessage)
 * ======================================================================= */

typedef struct {
    HWND         hwnd;
    UINT         msg;
    WPARAM       w;
    LPARAM       l;
    MsgHandlerFn fn;
} AsyncMsg;

static void do_async_dispatch(void *data) {
    AsyncMsg *m = (AsyncMsg *)data;
    m->fn(m->hwnd, m->msg, m->w, m->l);
    free(m);
}

BOOL msg_post(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    if (!hwnd) return FALSE;

    pthread_mutex_lock(&g_registry_mutex);
    MsgHandlerFn fn = find_handler_locked(hwnd);
    pthread_mutex_unlock(&g_registry_mutex);

    if (!fn) return FALSE;

    AsyncMsg *m = (AsyncMsg *)malloc(sizeof(AsyncMsg));
    if (!m) return FALSE;
    m->hwnd = hwnd;
    m->msg  = msg;
    m->w    = w;
    m->l    = l;
    m->fn   = fn;

    if (g_scheduler) {
        g_scheduler(do_async_dispatch, m);
    } else {
        /* No scheduler installed — fall back to synchronous delivery. */
        do_async_dispatch(m);
    }

    return TRUE;
}

/* =========================================================================
 * Synchronous dispatch (SendMessage)
 * ======================================================================= */

/*
 * When msg_send() is called from a worker thread we need to run the handler
 * on the "main" thread (the scheduler's execution context) and block the
 * worker until it completes.  We use a heap-allocated SyncMsg struct that
 * carries the message arguments, a mutex+condvar for signalling completion,
 * and the LRESULT.
 *
 * The struct is allocated by the worker, passed through the scheduler, freed
 * by the worker after it collects the result.
 */

typedef struct {
    HWND         hwnd;
    UINT         msg;
    WPARAM       w;
    LPARAM       l;
    MsgHandlerFn fn;

    LRESULT      result;
    int          done;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
} SyncMsg;

static void do_sync_dispatch(void *data) {
    SyncMsg *m = (SyncMsg *)data;

    m->result = m->fn(m->hwnd, m->msg, m->w, m->l);

    pthread_mutex_lock(&m->mutex);
    m->done = 1;
    pthread_cond_signal(&m->cond);
    pthread_mutex_unlock(&m->mutex);
    /* The caller frees *m after waking. */
}

LRESULT msg_send(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    if (!hwnd) return 0;

    pthread_mutex_lock(&g_registry_mutex);
    MsgHandlerFn fn = find_handler_locked(hwnd);
    pthread_mutex_unlock(&g_registry_mutex);

    if (!fn) return 0;

    /* ---- Main thread: call directly ---- */
    if (is_main_thread()) {
        return fn(hwnd, msg, w, l);
    }

    /* ---- Worker thread: post and wait ---- */
    SyncMsg *m = (SyncMsg *)malloc(sizeof(SyncMsg));
    if (!m) return 0;

    m->hwnd   = hwnd;
    m->msg    = msg;
    m->w      = w;
    m->l      = l;
    m->fn     = fn;
    m->result = 0;
    m->done   = 0;
    pthread_mutex_init(&m->mutex, NULL);
    pthread_cond_init(&m->cond,   NULL);

    if (g_scheduler) {
        g_scheduler(do_sync_dispatch, m);
    } else {
        /* No scheduler — fall back to direct call in this thread. */
        do_sync_dispatch(m);
    }

    /* Block until the handler signals completion. */
    pthread_mutex_lock(&m->mutex);
    while (!m->done)
        pthread_cond_wait(&m->cond, &m->mutex);
    pthread_mutex_unlock(&m->mutex);

    LRESULT result = m->result;
    pthread_mutex_destroy(&m->mutex);
    pthread_cond_destroy(&m->cond);
    free(m);

    return result;
}

/* =========================================================================
 * Windows API aliases
 * windows.h declares PostMessageA / SendMessageA as extern; provide them
 * here as thin wrappers so that code using the PostMessage / SendMessage
 * macros (which expand to PostMessageA / SendMessageA) links correctly.
 * ======================================================================= */

BOOL PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
    return msg_post(h, m, w, l);
}

LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l) {
    return msg_send(h, m, w, l);
}
