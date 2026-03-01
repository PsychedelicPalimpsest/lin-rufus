/*
 * combo_bridge.c — Windows ComboBox message-dispatch bridge for Linux
 *
 * See combo_bridge.h for the full API description.
 */

#include "combo_bridge.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Windows compat — CB_* message codes, CB_ERR, LRESULT etc. */
#ifndef _WIN32
#  include "compat/windows.h"
#endif

/* In GTK builds we sync state changes onto the real GtkComboBoxText widget.
 * Guard with USE_GTK so that test binaries compile cleanly without GTK. */
#ifdef USE_GTK
#  include <gtk/gtk.h>
#  define HAVE_GTK 1
#else
#  define HAVE_GTK 0
#endif

/* CB_ERR is not defined by our compat windows.h; define it here if missing. */
#ifndef CB_ERR
#  define CB_ERR ((LRESULT)-1)
#endif

/* ---------------------------------------------------------------------- */

#define COMBO_INIT_CAP 8

/* -------------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------- */

combo_state_t *combo_state_alloc(void *gtk_widget)
{
    combo_state_t *cs = (combo_state_t *)calloc(1, sizeof(*cs));
    if (!cs) return NULL;

    cs->text     = (char **)calloc(COMBO_INIT_CAP, sizeof(char *));
    cs->data     = (uintptr_t *)calloc(COMBO_INIT_CAP, sizeof(uintptr_t));
    cs->cap      = COMBO_INIT_CAP;
    cs->count    = 0;
    cs->cur_sel  = -1;
    cs->gtk_widget = gtk_widget;

    if (!cs->text || !cs->data) {
        free(cs->text);
        free(cs->data);
        free(cs);
        return NULL;
    }
    return cs;
}

void combo_state_free(combo_state_t *cs)
{
    if (!cs) return;
    for (int i = 0; i < cs->count; i++)
        free(cs->text[i]);
    free(cs->text);
    free(cs->data);
    free(cs);
}

/* -------------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------- */

/* Grow the backing arrays by doubling capacity. */
static int combo_grow(combo_state_t *cs)
{
    int newcap = cs->cap * 2;
    char **nt = (char **)realloc(cs->text, (size_t)newcap * sizeof(char *));
    uintptr_t *nd = (uintptr_t *)realloc(cs->data, (size_t)newcap * sizeof(uintptr_t));
    if (!nt || !nd) {
        /* realloc failure: restore original pointers (which are still valid) */
        if (nt) cs->text = nt;
        if (nd) cs->data = nd;
        return -1;
    }
    cs->text = nt;
    cs->data = nd;
    cs->cap  = newcap;
    return 0;
}

/* -------------------------------------------------------------------------
 * Message handler
 * --------------------------------------------------------------------- */

LRESULT combo_msg_handler(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
    combo_state_t *cs = (combo_state_t *)(uintptr_t)hwnd;
    if (!cs) return CB_ERR;

    switch (msg) {

    /* ------------------------------------------------------------------ */
    case CB_RESETCONTENT: {
        for (int i = 0; i < cs->count; i++) {
            free(cs->text[i]);
            cs->text[i] = NULL;
        }
        cs->count   = 0;
        cs->cur_sel = -1;

#if HAVE_GTK
        if (cs->gtk_widget)
            gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(cs->gtk_widget));
#endif
        return 0;
    }

    /* ------------------------------------------------------------------ */
    case CB_ADDSTRING: {
        const char *text = (const char *)(uintptr_t)l;
        if (!text) text = "";

        if (cs->count >= cs->cap) {
            if (combo_grow(cs) != 0)
                return (LRESULT)-2; /* CB_ERRSPACE */
        }

        cs->text[cs->count] = strdup(text);
        if (!cs->text[cs->count])
            return (LRESULT)-2; /* CB_ERRSPACE */

        cs->data[cs->count] = 0;
        int idx = cs->count++;

#if HAVE_GTK
        if (cs->gtk_widget)
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(cs->gtk_widget), text);
#endif
        return (LRESULT)idx;
    }

    /* ------------------------------------------------------------------ */
    case CB_GETCOUNT:
        return (LRESULT)cs->count;

    /* ------------------------------------------------------------------ */
    case CB_SETCURSEL: {
        int idx = (int)(intptr_t)w;
        if (idx == -1) {
            cs->cur_sel = -1;
#if HAVE_GTK
            if (cs->gtk_widget)
                gtk_combo_box_set_active(GTK_COMBO_BOX(cs->gtk_widget), -1);
#endif
            return (LRESULT)-1;
        }
        if (idx < 0 || idx >= cs->count)
            return CB_ERR;

        cs->cur_sel = idx;

#if HAVE_GTK
        if (cs->gtk_widget)
            gtk_combo_box_set_active(GTK_COMBO_BOX(cs->gtk_widget), idx);
#endif
        return (LRESULT)idx;
    }

    /* ------------------------------------------------------------------ */
    case CB_GETCURSEL:
        if (cs->cur_sel < 0) return CB_ERR;
        return (LRESULT)cs->cur_sel;

    /* ------------------------------------------------------------------ */
    case CB_SETITEMDATA: {
        int idx = (int)(uintptr_t)w;
        if (idx < 0 || idx >= cs->count)
            return CB_ERR;
        cs->data[idx] = (uintptr_t)l;
        return (LRESULT)l;
    }

    /* ------------------------------------------------------------------ */
    case CB_GETITEMDATA: {
        int idx = (int)(uintptr_t)w;
        if (idx < 0 || idx >= cs->count)
            return CB_ERR;
        return (LRESULT)cs->data[idx];
    }

    /* ------------------------------------------------------------------ */
    case CB_GETLBTEXT: {
        int idx = (int)(uintptr_t)w;
        char *buf = (char *)(uintptr_t)l;
        if (idx < 0 || idx >= cs->count || !buf)
            return CB_ERR;
        size_t len = strlen(cs->text[idx]);
        memcpy(buf, cs->text[idx], len + 1);
        return (LRESULT)len;
    }

    /* ------------------------------------------------------------------ */
    case CB_GETLBTEXTLEN: {
        int idx = (int)(uintptr_t)w;
        if (idx < 0 || idx >= cs->count)
            return CB_ERR;
        return (LRESULT)strlen(cs->text[idx]);
    }

    /* ------------------------------------------------------------------ */
    case CB_SETDROPPEDWIDTH:
    case CB_SETMINVISIBLE:
        /* No-op: GTK handles dropped-width automatically. */
        return 0;

    default:
        return 0;
    }
}
