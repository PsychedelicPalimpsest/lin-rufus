/*
 * test_localization_common.c — Cross-platform tests for common/localization.c
 *
 * Tests the pure-logic functions from src/common/localization.c:
 *   lmprintf(), get_locale_from_name(), get_locale_from_lcid(),
 *   toggle_default_locale(), get_name_from_id(), free_loc_cmd(),
 *   _init_localization() / _exit_localization().
 *
 * None of these functions have platform-specific behaviour; they operate
 * entirely on in-memory data structures and static tables.
 *
 * Runs on Linux (native) and Windows (Wine / MinGW cross-compile).
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2025 PsychedelicPalimpsest
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifdef _WIN32
#include "../src/windows/rufus.h"
#include "../src/windows/localization.h"
#include "../src/windows/resource.h"
#else
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/windows/localization.h"
#include "../src/windows/resource.h"
#endif

/* -----------------------------------------------------------------------
 * Required globals
 * --------------------------------------------------------------------- */
DWORD  ErrorStatus    = 0;
DWORD  MainThreadId   = 0;
DWORD  DownloadStatus = 0;
DWORD  LastWriteError = 0;
HWND   hMainDialog    = NULL;
HWND   hStatus        = NULL;
BOOL   right_to_left_mode = FALSE;
int    fs_type        = 0;
char   szFolderPath[MAX_PATH] = "";
char   app_dir[MAX_PATH]      = "";
char   temp_dir[MAX_PATH]     = "";
char   app_data_dir[MAX_PATH] = "";
char   ubuffer[UBUFFER_SIZE]  = "";

/* -----------------------------------------------------------------------
 * Stubs
 * --------------------------------------------------------------------- */
void uprintf(const char *fmt, ...) { (void)fmt; }
void uprintfs(const char *s)       { (void)s; }

/* get_loc_data_file is called from dispatch_loc_cmd (LC_BASE) and parser.c.
 * We never exercise those paths in these tests; a stub returning FALSE is
 * sufficient to resolve the link dependency. */
BOOL get_loc_data_file(const char *f, loc_cmd *l) { (void)f; (void)l; return FALSE; }

/* -----------------------------------------------------------------------
 * Helpers — build a minimal LC_LOCALE loc_cmd manually
 * --------------------------------------------------------------------- */
static loc_cmd *make_locale(const char *name, uint32_t lcid)
{
    loc_cmd *lc = calloc(1, sizeof(loc_cmd));
    if (!lc) return NULL;
    lc->command    = LC_LOCALE;
    lc->ctrl_id    = -1;
    lc->txt[0]     = strdup(name);
    lc->txt[1]     = strdup(name);  /* friendly name — same value for tests */
    lc->unum       = malloc(sizeof(uint32_t));
    if (lc->unum) { lc->unum[0] = lcid; lc->unum_size = 1; }
    list_init(&lc->list);
    return lc;
}

/* -----------------------------------------------------------------------
 * Init / exit lifecycle
 * --------------------------------------------------------------------- */
TEST(init_exit_lifecycle)
{
    init_localization();
    exit_localization();
    CHECK(1);
}

TEST(double_exit_safe)
{
    init_localization();
    exit_localization();
    exit_localization();    /* second exit must be a no-op, not a crash */
    CHECK(1);
}

TEST(reinit_preserves_locale_list)
{
    /*
     * reinit_localization() must NOT reset locale_list (it preserves across
     * reinit), while a full exit+init cycle does clear it.
     */
    init_localization();
    loc_cmd *en = make_locale("en_US", 0x0009);
    list_add_tail(&en->list, &locale_list);

    /* reinit — locale_list survives */
    reinit_localization();
    loc_cmd *found = get_locale_from_name("en_US", FALSE);
    CHECK(found != NULL);

    exit_localization();
}

/* -----------------------------------------------------------------------
 * lmprintf() tests
 * --------------------------------------------------------------------- */
TEST(lmprintf_null_table_returns_untranslated)
{
    /* After init, msg_table == NULL → lmprintf must return "UNTRANSLATED" */
    init_localization();
    char *s = lmprintf(MSG_000);
    CHECK(s != NULL);
    CHECK(strstr(s, "UNTRANSLATED") != NULL);
    exit_localization();
}

TEST(lmprintf_with_table_formats_correctly)
{
    init_localization();
    /* Manually point msg_table at current_msg_table and plant a format string */
    msg_table = current_msg_table;
    msg_table[0] = "hello %s";   /* MSG_000 → index 0 */
    char *s = lmprintf(MSG_000, "world");
    CHECK(s != NULL);
    CHECK(strcmp(s, "hello world") == 0);
    msg_table[0] = NULL;
    exit_localization();
}

TEST(lmprintf_out_of_range_returns_untranslated)
{
    /* msg_ids beyond MSG_MAX must still return an "UNTRANSLATED" string */
    init_localization();
    char *s = lmprintf(MSG_MAX + 1);
    CHECK(s != NULL);
    CHECK(strstr(s, "UNTRANSLATED") != NULL);
    exit_localization();
}

TEST(lmprintf_rolling_buffer_does_not_crash)
{
    /*
     * lmprintf uses a rolling pool of LOC_MESSAGE_NB slots.
     * Cycling through more than LOC_MESSAGE_NB calls must not crash.
     */
    init_localization();
    for (int i = 0; i < LOC_MESSAGE_NB + 4; i++) {
        char *s = lmprintf(MSG_000);
        CHECK(s != NULL);
    }
    exit_localization();
}

/* -----------------------------------------------------------------------
 * get_locale_from_name() tests
 * --------------------------------------------------------------------- */
TEST(get_locale_from_name_empty_list_returns_null)
{
    init_localization();
    loc_cmd *r = get_locale_from_name("en_US", FALSE);
    CHECK(r == NULL);
    exit_localization();
}

TEST(get_locale_from_name_exact_match)
{
    init_localization();
    loc_cmd *en = make_locale("en_US", 0x0009);
    list_add_tail(&en->list, &locale_list);

    loc_cmd *r = get_locale_from_name("en_US", FALSE);
    CHECK(r == en);
    exit_localization();
}

TEST(get_locale_from_name_no_match_no_fallback_returns_null)
{
    init_localization();
    loc_cmd *en = make_locale("en_US", 0x0009);
    list_add_tail(&en->list, &locale_list);

    loc_cmd *r = get_locale_from_name("fr_FR", FALSE);
    CHECK(r == NULL);
    exit_localization();
}

TEST(get_locale_from_name_no_match_fallback_returns_first)
{
    init_localization();
    loc_cmd *en = make_locale("en_US", 0x0009);
    loc_cmd *fr = make_locale("fr_FR", 0x000c);
    list_add_tail(&en->list, &locale_list);
    list_add_tail(&fr->list, &locale_list);

    loc_cmd *r = get_locale_from_name("de_DE", TRUE);
    CHECK(r == en);   /* fallback → first entry */
    exit_localization();
}

TEST(get_locale_from_name_second_entry_found)
{
    init_localization();
    loc_cmd *en = make_locale("en_US", 0x0009);
    loc_cmd *fr = make_locale("fr_FR", 0x000c);
    list_add_tail(&en->list, &locale_list);
    list_add_tail(&fr->list, &locale_list);

    loc_cmd *r = get_locale_from_name("fr_FR", FALSE);
    CHECK(r == fr);
    exit_localization();
}

/* -----------------------------------------------------------------------
 * get_locale_from_lcid() tests
 * --------------------------------------------------------------------- */
TEST(get_locale_from_lcid_empty_list_returns_null)
{
    init_localization();
    loc_cmd *r = get_locale_from_lcid(0x0409, FALSE);
    CHECK(r == NULL);
    exit_localization();
}

TEST(get_locale_from_lcid_exact_match)
{
    init_localization();
    loc_cmd *en = make_locale("en_US", 0x0009);
    list_add_tail(&en->list, &locale_list);

    loc_cmd *r = get_locale_from_lcid(0x0009, FALSE);
    CHECK(r == en);
    exit_localization();
}

TEST(get_locale_from_lcid_no_match_no_fallback_returns_null)
{
    init_localization();
    loc_cmd *en = make_locale("en_US", 0x0009);
    list_add_tail(&en->list, &locale_list);

    loc_cmd *r = get_locale_from_lcid(0xFFFF, FALSE);
    CHECK(r == NULL);
    exit_localization();
}

TEST(get_locale_from_lcid_no_match_fallback_returns_first)
{
    init_localization();
    loc_cmd *en = make_locale("en_US", 0x0009);
    loc_cmd *fr = make_locale("fr_FR", 0x000c);
    list_add_tail(&en->list, &locale_list);
    list_add_tail(&fr->list, &locale_list);

    loc_cmd *r = get_locale_from_lcid(0xFFFF, TRUE);
    CHECK(r == en);   /* fallback → first entry */
    exit_localization();
}

/* -----------------------------------------------------------------------
 * toggle_default_locale() tests
 * --------------------------------------------------------------------- */
TEST(toggle_default_locale_switches_and_restores)
{
    init_localization();
    /* Point msg_table at current_msg_table so toggle has something to save */
    msg_table = current_msg_table;

    char **before = msg_table;
    toggle_default_locale();
    /* After first toggle msg_table must equal default_msg_table */
    CHECK(msg_table == default_msg_table);

    toggle_default_locale();
    /* After second toggle msg_table must be restored */
    CHECK(msg_table == before);
    exit_localization();
}

TEST(toggle_default_locale_idempotent_round_trip)
{
    init_localization();
    msg_table = current_msg_table;

    toggle_default_locale();
    toggle_default_locale();
    toggle_default_locale();
    toggle_default_locale();
    /* Four toggles → even number → back to original */
    CHECK(msg_table == current_msg_table);
    exit_localization();
}

/* -----------------------------------------------------------------------
 * get_name_from_id() tests
 * --------------------------------------------------------------------- */
TEST(get_name_from_id_known_control_device)
{
    const char *name = get_name_from_id(IDC_DEVICE);
    CHECK(name != NULL);
    CHECK(strcmp(name, "IDC_DEVICE") == 0);
}

TEST(get_name_from_id_known_dialog_id)
{
    const char *name = get_name_from_id(IDD_DIALOG);
    CHECK(name != NULL);
    CHECK(strcmp(name, "IDD_DIALOG") == 0);
}

TEST(get_name_from_id_unknown_returns_unknown_string)
{
    const char *name = get_name_from_id(-9999);
    /* Per implementation, unknown IDs return "UNKNOWN ID", not NULL */
    CHECK(name != NULL);
    CHECK(strcmp(name, "UNKNOWN ID") == 0);
}

/* -----------------------------------------------------------------------
 * free_loc_cmd() tests
 * --------------------------------------------------------------------- */
TEST(free_loc_cmd_null_safe)
{
    free_loc_cmd(NULL);   /* must not crash */
    CHECK(1);
}

TEST(free_loc_cmd_frees_without_crash)
{
    loc_cmd *lc = make_locale("en_US", 0x0009);
    CHECK(lc != NULL);
    /* Detach from any list before freeing (it was never added to one) */
    free_loc_cmd(lc);
    CHECK(1);
}

/* -----------------------------------------------------------------------
 * dispatch_loc_cmd() tests
 * --------------------------------------------------------------------- */
TEST(dispatch_loc_cmd_null_returns_false)
{
    init_localization();
    BOOL r = dispatch_loc_cmd(NULL);
    CHECK(r == FALSE);
    exit_localization();
}

TEST(dispatch_loc_cmd_group_does_not_crash)
{
    /*
     * A GROUP command sets the dialog index for subsequent TEXT commands.
     * It should not crash even without GTK/UI.
     * Note: dispatch_loc_cmd takes ownership of lcmd — don't free manually.
     */
    init_localization();
    /* Need msg_table != default_msg_table or the command is silently discarded */
    msg_table = current_msg_table;

    loc_cmd *grp = calloc(1, sizeof(loc_cmd));
    grp->command = LC_GROUP;
    grp->ctrl_id = IDD_DIALOG;
    grp->txt[0]  = strdup("IDD_DIALOG");
    list_init(&grp->list);

    BOOL r = dispatch_loc_cmd(grp);
    /* ownership transferred to localization system — don't free grp */
    CHECK(r == TRUE);
    exit_localization();
}

TEST(dispatch_loc_cmd_text_msg_prefix_adds_message)
{
    /*
     * An LC_TEXT command whose txt[0] starts with "MSG_" must be routed
     * through add_message_command() — this is the path that populates
     * msg_table with translated strings.
     */
    init_localization();
    msg_table = current_msg_table;

    loc_cmd *txt = calloc(1, sizeof(loc_cmd));
    txt->command = LC_TEXT;
    txt->ctrl_id = -1;
    txt->txt[0]  = strdup("MSG_001");
    txt->txt[1]  = strdup("Hello, world");
    list_init(&txt->list);

    BOOL r = dispatch_loc_cmd(txt);
    /* ownership transferred */
    CHECK(r == TRUE);
    /* After dispatch, MSG_001 must be in msg_table */
    CHECK(msg_table[1] != NULL);
    CHECK(strcmp(msg_table[1], "Hello, world") == 0);
    exit_localization();
}

TEST(dispatch_loc_cmd_text_unknown_control_returns_false)
{
    init_localization();
    msg_table = current_msg_table;

    loc_cmd *txt = calloc(1, sizeof(loc_cmd));
    txt->command = LC_TEXT;
    txt->ctrl_id = -1;
    txt->txt[0]  = strdup("IDC_DOES_NOT_EXIST_9999");
    txt->txt[1]  = strdup("Some text");
    list_init(&txt->list);

    BOOL r = dispatch_loc_cmd(txt);
    /* ownership transferred (or freed on error path) */
    CHECK(r == FALSE);
    exit_localization();
}

/* -----------------------------------------------------------------------
 * get_loc_dlg_count() / get_loc_dlg_entry() accessors
 * --------------------------------------------------------------------- */
TEST(get_loc_dlg_count_is_positive)
{
    int count = get_loc_dlg_count();
    CHECK(count > 0);
}

TEST(get_loc_dlg_entry_first_is_non_null)
{
    loc_dlg_list *entry = get_loc_dlg_entry(0);
    CHECK(entry != NULL);
}

/* ================================================================== */
int main(void)
{
    /* lifecycle */
    RUN(init_exit_lifecycle);
    RUN(double_exit_safe);
    RUN(reinit_preserves_locale_list);

    /* lmprintf */
    RUN(lmprintf_null_table_returns_untranslated);
    RUN(lmprintf_with_table_formats_correctly);
    RUN(lmprintf_out_of_range_returns_untranslated);
    RUN(lmprintf_rolling_buffer_does_not_crash);

    /* get_locale_from_name */
    RUN(get_locale_from_name_empty_list_returns_null);
    RUN(get_locale_from_name_exact_match);
    RUN(get_locale_from_name_no_match_no_fallback_returns_null);
    RUN(get_locale_from_name_no_match_fallback_returns_first);
    RUN(get_locale_from_name_second_entry_found);

    /* get_locale_from_lcid */
    RUN(get_locale_from_lcid_empty_list_returns_null);
    RUN(get_locale_from_lcid_exact_match);
    RUN(get_locale_from_lcid_no_match_no_fallback_returns_null);
    RUN(get_locale_from_lcid_no_match_fallback_returns_first);

    /* toggle_default_locale */
    RUN(toggle_default_locale_switches_and_restores);
    RUN(toggle_default_locale_idempotent_round_trip);

    /* get_name_from_id */
    RUN(get_name_from_id_known_control_device);
    RUN(get_name_from_id_known_dialog_id);
    RUN(get_name_from_id_unknown_returns_unknown_string);

    /* free_loc_cmd */
    RUN(free_loc_cmd_null_safe);
    RUN(free_loc_cmd_frees_without_crash);

    /* dispatch_loc_cmd */
    RUN(dispatch_loc_cmd_null_returns_false);
    RUN(dispatch_loc_cmd_group_does_not_crash);
    RUN(dispatch_loc_cmd_text_msg_prefix_adds_message);
    RUN(dispatch_loc_cmd_text_unknown_control_returns_false);

    /* accessors */
    RUN(get_loc_dlg_count_is_positive);
    RUN(get_loc_dlg_entry_first_is_non_null);

    TEST_RESULTS();
}
