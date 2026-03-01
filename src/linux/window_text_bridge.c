/*
 * window_text_bridge.c — Thread-safe GetWindowTextA / SetWindowTextA for Linux
 *
 * Maintains a registry of HWND → cached text entries protected by a mutex.
 * GetWindowTextA and SetWindowTextA read/write from this cache so that worker
 * threads (e.g. FormatThread) can safely call them without touching GTK.
 *
 * In GTK builds, SetWindowTextA also pushes the new text to the underlying
 * GtkEntry / GtkLabel / GtkButton widget via an idle callback on the main loop.
 * All GTK calls are guarded by USE_GTK so test binaries compile cleanly.
 */

#include "window_text_bridge.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#ifndef _WIN32
#  include "compat/windows.h"
#endif

/* ---------------------------------------------------------------------- */

#define REGISTRY_INIT_CAP 16

typedef struct {
    HWND hwnd;
    char text[WINDOW_TEXT_MAX];
#ifdef USE_GTK
    GtkWidget *gtk_widget;   /* optional; NULL for cache-only entries */
#endif
} wt_entry_t;

static wt_entry_t  *registry   = NULL;
static int          reg_count  = 0;
static int          reg_cap    = 0;
static pthread_mutex_t reg_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ---------------------------------------------------------------------- */

static void registry_ensure_cap(void)
{
    if (reg_count < reg_cap)
        return;
    int newcap = reg_cap ? reg_cap * 2 : REGISTRY_INIT_CAP;
    wt_entry_t *n = (wt_entry_t *)realloc(registry, (size_t)newcap * sizeof(wt_entry_t));
    if (!n) return;
    registry = n;
    reg_cap  = newcap;
}

static wt_entry_t *find_entry(HWND h)
{
    for (int i = 0; i < reg_count; i++)
        if (registry[i].hwnd == h)
            return &registry[i];
    return NULL;
}

/* ---------------------------------------------------------------------- */

void window_text_register(HWND h)
{
    if (!h) return;
    pthread_mutex_lock(&reg_mutex);
    if (!find_entry(h)) {
        registry_ensure_cap();
        if (reg_count < reg_cap) {
            wt_entry_t *e = &registry[reg_count++];
            e->hwnd    = h;
            e->text[0] = '\0';
#ifdef USE_GTK
            e->gtk_widget = NULL;
#endif
        }
    }
    pthread_mutex_unlock(&reg_mutex);
}

void window_text_unregister(HWND h)
{
    if (!h) return;
    pthread_mutex_lock(&reg_mutex);
    for (int i = 0; i < reg_count; i++) {
        if (registry[i].hwnd == h) {
            /* Swap with last entry and shrink */
            if (i < reg_count - 1)
                registry[i] = registry[reg_count - 1];
            reg_count--;
            break;
        }
    }
    pthread_mutex_unlock(&reg_mutex);
}

void window_text_set_cache(HWND h, const char *text)
{
    if (!h) return;
    pthread_mutex_lock(&reg_mutex);
    wt_entry_t *e = find_entry(h);
    if (e) {
        if (text)
            strncpy(e->text, text, WINDOW_TEXT_MAX - 1);
        else
            e->text[0] = '\0';
        e->text[WINDOW_TEXT_MAX - 1] = '\0';
    }
    pthread_mutex_unlock(&reg_mutex);
}

/* ---------------------------------------------------------------------- */
/* GetWindowTextA / SetWindowTextA                                         */
/* ---------------------------------------------------------------------- */

int GetWindowTextA(HWND h, LPSTR s, int max)
{
    if (!h || !s || max <= 0)
        return 0;

    pthread_mutex_lock(&reg_mutex);
    wt_entry_t *e = find_entry(h);
    if (!e) {
        pthread_mutex_unlock(&reg_mutex);
        return 0;
    }
    int len = (int)strlen(e->text);
    if (len >= max)
        len = max - 1;
    memcpy(s, e->text, (size_t)len);
    s[len] = '\0';
    pthread_mutex_unlock(&reg_mutex);
    return len;
}

#ifdef USE_GTK
/* Forward declarations for idle callbacks (defined below) */
typedef struct { GtkWidget *w; char *t; } wt_idle_arg_t;
static gboolean wt_idle_set_entry(gpointer data);
static gboolean wt_idle_set_label(gpointer data);
static gboolean wt_idle_set_button(gpointer data);
#endif

BOOL SetWindowTextA(HWND h, LPCSTR s)
{
    if (!h) return FALSE;

    pthread_mutex_lock(&reg_mutex);
    wt_entry_t *e = find_entry(h);
    if (!e) {
        pthread_mutex_unlock(&reg_mutex);
        return FALSE;
    }
    if (s)
        strncpy(e->text, s, WINDOW_TEXT_MAX - 1);
    else
        e->text[0] = '\0';
    e->text[WINDOW_TEXT_MAX - 1] = '\0';

#ifdef USE_GTK
    GtkWidget *w = e->gtk_widget;
    if (w) {
        /* Schedule a GTK update on the main loop */
        char *copy = strdup(e->text);
        if (copy) {
            wt_idle_arg_t *a = (wt_idle_arg_t *)malloc(sizeof(*a));
            if (a) {
                a->w = w;
                a->t = copy;
                if (GTK_IS_ENTRY(w))
                    g_idle_add(wt_idle_set_entry, a);
                else if (GTK_IS_LABEL(w))
                    g_idle_add(wt_idle_set_label, a);
                else if (GTK_IS_BUTTON(w))
                    g_idle_add(wt_idle_set_button, a);
                else {
                    free(a->t);
                    free(a);
                }
                copy = NULL;
            }
            free(copy);
        }
    }
#endif /* USE_GTK */

    pthread_mutex_unlock(&reg_mutex);
    return TRUE;
}

#ifdef USE_GTK
/* ---- GTK idle callbacks — run on the main loop ---- */

static gboolean wt_idle_set_entry(gpointer data)
{
    wt_idle_arg_t *a = (wt_idle_arg_t *)data;
    if (a && a->w && GTK_IS_ENTRY(a->w))
        gtk_entry_set_text(GTK_ENTRY(a->w), a->t ? a->t : "");
    if (a) free(a->t);
    free(a);
    return G_SOURCE_REMOVE;
}

/* Public aliases referenced from the header */
gboolean window_text_idle_set_entry(gpointer d)  { return wt_idle_set_entry(d);  }

static gboolean wt_idle_set_label(gpointer data)
{
    wt_idle_arg_t *a = (wt_idle_arg_t *)data;
    if (a && a->w && GTK_IS_LABEL(a->w))
        gtk_label_set_text(GTK_LABEL(a->w), a->t ? a->t : "");
    if (a) free(a->t);
    free(a);
    return G_SOURCE_REMOVE;
}

gboolean window_text_idle_set_label(gpointer d)  { return wt_idle_set_label(d);  }

static gboolean wt_idle_set_button(gpointer data)
{
    wt_idle_arg_t *a = (wt_idle_arg_t *)data;
    if (a && a->w && GTK_IS_BUTTON(a->w))
        gtk_button_set_label(GTK_BUTTON(a->w), a->t ? a->t : "");
    if (a) free(a->t);
    free(a);
    return G_SOURCE_REMOVE;
}

gboolean window_text_idle_set_button(gpointer d) { return wt_idle_set_button(d); }

/*
 * window_text_register_gtk — register with an associated GtkWidget.
 */
void window_text_register_gtk(HWND h, GtkWidget *widget)
{
    if (!h) return;
    window_text_register(h);
    pthread_mutex_lock(&reg_mutex);
    wt_entry_t *e = find_entry(h);
    if (e)
        e->gtk_widget = widget;
    pthread_mutex_unlock(&reg_mutex);
}

/*
 * Signal handler for GtkEntry "changed" — keeps cache in sync when user types.
 */
void window_text_on_entry_changed(GtkEditable *editable, gpointer user_data)
{
    HWND h = (HWND)user_data;
    if (!h) return;
    const char *text = gtk_entry_get_text(GTK_ENTRY(editable));
    window_text_set_cache(h, text);
}
#endif /* USE_GTK */
