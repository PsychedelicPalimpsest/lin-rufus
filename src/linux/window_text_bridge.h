/*
 * window_text_bridge.h — Thread-safe HWND→text cache for Linux
 *
 * Provides GetWindowTextA / SetWindowTextA implementations that work from
 * worker threads without requiring GTK calls.  In GTK builds, SetWindowTextA
 * also updates the underlying GtkEntry / GtkLabel / GtkButton widget.
 *
 * Usage:
 *   1. Call window_text_register(hwnd) once per text widget HWND.
 *   2. In GTK builds, connect the "changed" signal (GtkEntry) via
 *      window_text_on_entry_changed, or call window_text_register_gtk(h, widget).
 *   3. GetWindowTextA / SetWindowTextA are usable from any thread.
 *   4. Call window_text_unregister(hwnd) when the widget is destroyed.
 */

#pragma once

#ifndef _WIN32
#  include "compat/windows.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum text length stored per HWND (including NUL terminator). */
#define WINDOW_TEXT_MAX 512

/*
 * Register an HWND for text caching.  Subsequent Get/SetWindowTextA calls
 * on this HWND will use the internal cache.
 */
void window_text_register(HWND h);

/*
 * Unregister an HWND.  After this call GetWindowTextA returns 0 for @h.
 */
void window_text_unregister(HWND h);

/*
 * Directly update the cache for @h without touching any GTK widget.
 * Used by GTK signal handlers to keep the cache in sync.
 */
void window_text_set_cache(HWND h, const char *text);

#ifdef USE_GTK
#  include <gtk/gtk.h>

/*
 * Register an HWND and associate it with a GtkWidget.
 * SetWindowTextA will schedule a GTK update on the main loop.
 */
void window_text_register_gtk(HWND h, GtkWidget *widget);

/*
 * GtkEditable "changed" signal handler — keeps cache in sync when the user
 * types in a GtkEntry.  Connect as:
 *   g_signal_connect(entry, "changed",
 *                    G_CALLBACK(window_text_on_entry_changed), (gpointer)hwnd);
 */
void window_text_on_entry_changed(GtkEditable *editable, gpointer user_data);

/* Idle callbacks (called on GTK main loop — do not call directly) */
gboolean window_text_idle_set_entry(gpointer data);
gboolean window_text_idle_set_label(gpointer data);
gboolean window_text_idle_set_button(gpointer data);
#endif /* USE_GTK */

#ifdef __cplusplus
}
#endif
