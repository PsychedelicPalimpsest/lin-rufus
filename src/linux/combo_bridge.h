/*
 * combo_bridge.h — Windows ComboBox message-dispatch bridge for Linux
 *
 * Provides a lightweight, GTK-optional combo box state machine.
 * Each logical combo is represented by a combo_state_t whose address is
 * used as the HWND.  Register the state with msg_dispatch so that the
 * standard SendMessageA(hCombo, CB_*, …) calls are routed correctly.
 *
 * In GTK builds the state machine optionally holds a GtkComboBoxText*
 * pointer and mirrors every state change onto the real widget.
 * In non-GTK / test builds the pointer is NULL and no GTK calls are made.
 *
 * Usage
 * -----
 *   combo_state_t *cs = combo_state_alloc(gtk_widget_or_NULL);
 *   msg_dispatch_register((HWND)cs, combo_msg_handler);
 *   hMyCombo = (HWND)cs;
 *   …
 *   msg_dispatch_unregister((HWND)cs);
 *   combo_state_free(cs);
 *
 * In the GTK UI call combo_register_all() (defined in ui_gtk.c) once all
 * widgets have been created.
 *
 * Supported messages
 * ------------------
 *   CB_RESETCONTENT  – clear all items
 *   CB_ADDSTRING     – append text; returns 0-based index of new item
 *   CB_GETCOUNT      – return number of items
 *   CB_SETCURSEL     – set active selection; CB_ERR if out of range
 *   CB_GETCURSEL     – return active index; CB_ERR if nothing selected
 *   CB_SETITEMDATA   – attach DWORD_PTR to item; CB_ERR if OOB
 *   CB_GETITEMDATA   – retrieve item data; CB_ERR if OOB
 *   CB_GETLBTEXT     – copy item text into caller buffer; return strlen
 *   CB_GETLBTEXTLEN  – return text length; CB_ERR if OOB
 *   CB_SETDROPPEDWIDTH, CB_SETMINVISIBLE – accepted, ignored (GTK handles)
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* Windows compat types */
#ifndef _WIN32
#  include "compat/windows.h"
#  include "compat/msg_dispatch.h"
#endif

/* Opaque forward declaration; definition below */
typedef struct combo_state combo_state_t;

/* ---- Item data --------------------------------------------------------- */

struct combo_state {
    char       **text;      /* array of NUL-terminated item strings */
    uintptr_t   *data;      /* array of per-item DWORD_PTR values   */
    int          count;     /* number of items currently stored      */
    int          cap;       /* allocated capacity (items)            */
    int          cur_sel;   /* current selection index; -1 = none    */

    /* Optional GTK back-end.  NULL in non-GTK / test builds. */
    void        *gtk_widget; /* cast to GtkComboBoxText* in GTK code  */
};

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Lifecycle --------------------------------------------------------- */

/**
 * combo_state_alloc - allocate a new combo state.
 *
 * @gtk_widget: pointer to the associated GtkComboBoxText widget, or NULL.
 *
 * Returns a heap-allocated combo_state_t, or NULL on allocation failure.
 * The caller must eventually call combo_state_free().
 */
combo_state_t *combo_state_alloc(void *gtk_widget);

/**
 * combo_state_free - release all resources held by a combo state.
 *
 * Safe to call with NULL.  Does NOT call msg_dispatch_unregister(); the
 * caller must do that before freeing to avoid dangling HWND registrations.
 */
void combo_state_free(combo_state_t *cs);

/* ---- Message handler --------------------------------------------------- */

/**
 * combo_msg_handler - MsgHandlerFn compatible handler for CB_* messages.
 *
 * Register this with msg_dispatch_register((HWND)cs, combo_msg_handler).
 * The hwnd parameter must be the combo_state_t* cast to HWND.
 */
LRESULT combo_msg_handler(HWND hwnd, UINT msg, WPARAM w, LPARAM l);

#ifdef __cplusplus
}
#endif
