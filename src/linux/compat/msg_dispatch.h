/*
 * msg_dispatch.h — PostMessage / SendMessage compatibility dispatch layer
 *
 * Provides a real, thread-safe implementation of Windows-style message passing
 * for the Linux port of Rufus.
 *
 * Architecture
 * ------------
 * Each HWND may have one registered MsgHandlerFn.  The two entry points are:
 *
 *   msg_post(hwnd, msg, w, l)
 *     Asynchronous: schedules delivery via the installed MsgPostScheduler
 *     (defaults to a direct synchronous call if no scheduler is set).
 *     Returns TRUE if the HWND has a registered handler, FALSE otherwise.
 *
 *   msg_send(hwnd, msg, w, l)
 *     Synchronous: if called from the main thread (as recorded by
 *     msg_dispatch_init), invokes the handler directly.  If called from any
 *     other thread, posts the message to the main thread and *blocks* until
 *     the handler has returned, then returns the handler's LRESULT.
 *
 * Scheduler
 * ---------
 * A MsgPostScheduler is a callback with signature:
 *
 *   void my_scheduler(void (*fn)(void *), void *data);
 *
 * The GTK integration in ui_gtk.c sets this to a wrapper around g_idle_add
 * so that both PostMessage and cross-thread SendMessage drive GTK widget
 * updates safely from the GLib main loop.
 *
 * In unit tests (no GTK) any scheduler — including NULL (fallback to
 * synchronous delivery) or a custom queue — may be installed.
 */

#pragma once
#ifndef MSG_DISPATCH_H
#define MSG_DISPATCH_H

/*
 * windows.h brings in the HWND / UINT / WPARAM / LPARAM / BOOL / LRESULT
 * types and the WM_* / UM_* constants that callers expect.
 */
#include "windows.h"
/* rufus.h defines the UM_* user message constants */
#include "../windows/rufus.h"

/* ---- Types ---- */

/**
 * MsgHandlerFn — handler function registered for a specific HWND.
 *
 * Called with the same arguments as a Windows WNDPROC but only the four
 * shown (hWnd, uMsg, wParam, lParam).  The return value is forwarded to the
 * caller of msg_send(); it is discarded for msg_post().
 */
typedef LRESULT (*MsgHandlerFn)(HWND hwnd, UINT msg, WPARAM w, LPARAM l);

/**
 * MsgPostScheduler — callback that schedules fn(data) on the "main"
 * execution context (e.g. the GTK main loop via g_idle_add).
 *
 * If NULL is passed to msg_dispatch_set_scheduler(), msg_post() falls back
 * to calling fn(data) synchronously in the calling thread.
 */
typedef void (*MsgPostScheduler)(void (*fn)(void *), void *data);

/* ---- Lifecycle ---- */

/**
 * msg_dispatch_init() — initialise the dispatch system.
 *
 * Must be called once from the main thread *before* any other msg_* call.
 * Records the calling thread as the "main thread" so that msg_send() can
 * detect cross-thread invocations.
 */
void msg_dispatch_init(void);

/* ---- Handler registry ---- */

/**
 * msg_dispatch_register() — register (or replace) the message handler for
 * the given HWND.  Thread-safe.
 */
void msg_dispatch_register(HWND hwnd, MsgHandlerFn fn);

/**
 * msg_dispatch_unregister() — remove the handler for the given HWND.
 * Subsequent msg_send/msg_post calls to this HWND return 0/FALSE.
 * Thread-safe.
 */
void msg_dispatch_unregister(HWND hwnd);

/* ---- Scheduler ---- */

/**
 * msg_dispatch_set_scheduler() — install the post scheduler.
 *
 * Pass NULL to revert to synchronous fall-back delivery.
 * Not thread-safe; call from the main thread during initialisation.
 */
void msg_dispatch_set_scheduler(MsgPostScheduler sched);

/* ---- Dispatch ---- */

/**
 * msg_post() — asynchronous message delivery.
 *
 * Returns TRUE if the HWND has a registered handler and the message was
 * scheduled, FALSE otherwise.  The handler's return value is discarded.
 *
 * Maps to Windows PostMessage().
 */
BOOL msg_post(HWND hwnd, UINT msg, WPARAM w, LPARAM l);

/**
 * msg_send() — synchronous message delivery.
 *
 * If called from the main thread: invokes the handler directly and returns
 * its LRESULT.
 *
 * If called from any other thread: posts the message to the scheduler and
 * *blocks* the calling thread until the handler completes on the main thread,
 * then returns the LRESULT.
 *
 * Returns 0 if the HWND has no registered handler.
 *
 * Maps to Windows SendMessage().
 */
LRESULT msg_send(HWND hwnd, UINT msg, WPARAM w, LPARAM l);

#endif /* MSG_DISPATCH_H */
