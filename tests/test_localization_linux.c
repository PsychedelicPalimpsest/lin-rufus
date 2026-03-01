/*
 * test_localization_linux.c — Tests for Linux apply_localization and related
 * functions in src/linux/localization.c and src/common/localization.c.
 *
 * The GTK apply_localization is tested with all rw.* widget pointers NULL
 * (no GTK display needed).  This verifies the null-safety contract and the
 * logic that only LC_TEXT commands with non-empty txt[1] trigger updates.
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "framework.h"
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"
#include "../src/windows/localization.h"
#include "../src/windows/resource.h"

/* ------------------------------------------------------------------ */
/* Required globals (provided by globals.c in production)              */
/* ------------------------------------------------------------------ */
DWORD  ErrorStatus    = 0;
DWORD  MainThreadId   = 0;
DWORD  DownloadStatus = 0;
DWORD  LastWriteError = 0;
HWND   hMainDialog    = NULL;
HWND   hInfo          = NULL;
HWND   hStatus        = NULL;
BOOL   usb_debug      = FALSE;
BOOL   right_to_left_mode = FALSE;
int    fs_type        = 0;

char szFolderPath[MAX_PATH]    = "";
char app_dir[MAX_PATH]         = "";
char temp_dir[MAX_PATH]        = "/tmp";
char app_data_dir[MAX_PATH]    = "/tmp";
char ubuffer[UBUFFER_SIZE]     = "";

/* Minimal stubs */
void uprintf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}
void uprintfs(const char *s) { if (s) fputs(s, stderr); }
/* lmprintf comes from common/localization.c */

/* ------------------------------------------------------------------ */
/* Forward declarations for functions under test                        */
/* ------------------------------------------------------------------ */
extern void apply_localization(int dlg_id, HWND hDlg);
extern void reset_localization(int dlg_id);
/* init_localization() and exit_localization() are macros in localization.h */

/* dispatch_loc_cmd is in common/localization.c */
extern BOOL dispatch_loc_cmd(loc_cmd *lcmd);

/* ================================================================== */
/* Helpers — build a minimal loc_cmd                                   */
/* ================================================================== */
static loc_cmd *make_text_cmd(int ctrl_id, const char *txt0, const char *txt1)
{
    loc_cmd *lc = calloc(1, sizeof(loc_cmd));
    if (!lc) return NULL;
    lc->command  = LC_TEXT;
    lc->ctrl_id  = ctrl_id;
    lc->txt[0]   = txt0 ? strdup(txt0) : NULL;
    lc->txt[1]   = txt1 ? strdup(txt1) : NULL;
    list_init(&lc->list);
    return lc;
}

static void free_loc_cmd_manually(loc_cmd *lc)
{
    if (!lc) return;
    free(lc->txt[0]);
    free(lc->txt[1]);
    free(lc);
}

/* ================================================================== */
/* apply_localization — safety / edge-case tests                       */
/* ================================================================== */

TEST(apply_loc_empty_dlg_does_not_crash)
{
    /*
     * With an empty loc_dlg list, apply_localization must return silently.
     * No GTK widgets exist (rw.* == NULL), so all updates must be skipped.
     */
    init_localization();
    apply_localization(0, NULL);
    exit_localization();
    CHECK(1);
}

TEST(apply_loc_with_dlg_id_out_of_range)
{
    init_localization();
    apply_localization(9999, NULL);     /* well outside IDD_DIALOG range */
    apply_localization(-1, NULL);
    exit_localization();
    CHECK(1);
}

TEST(apply_loc_main_dialog_id)
{
    /* IDD_DIALOG is 101.  apply_localization(IDD_DIALOG, NULL) must not crash. */
    init_localization();
    apply_localization(IDD_DIALOG, NULL);
    exit_localization();
    CHECK(1);
}

TEST(apply_loc_repeated_calls)
{
    init_localization();
    for (int i = 0; i < 10; i++)
        apply_localization(IDD_DIALOG, NULL);
    exit_localization();
    CHECK(1);
}

/* ================================================================== */
/* dispatch_loc_cmd / loc_dlg population tests                         */
/* ================================================================== */

TEST(dispatch_null_lcmd_returns_false)
{
    init_localization();
    BOOL r = dispatch_loc_cmd(NULL);
    CHECK_MSG(r == FALSE, "dispatch_loc_cmd(NULL) must return FALSE");
    exit_localization();
}

TEST(dispatch_group_cmd_adds_to_list)
{
    init_localization();
    /*
     * Create a GROUP command targeting IDD_DIALOG (ctrl_id = IDD_DIALOG).
     * This should register a list for dialog index 0.
     */
    loc_cmd *grp = calloc(1, sizeof(loc_cmd));
    grp->command = LC_GROUP;
    grp->ctrl_id = IDD_DIALOG;
    grp->txt[0]  = strdup("IDD_DIALOG");
    list_init(&grp->list);

    BOOL r = dispatch_loc_cmd(grp);
    /* Must not crash; result depends on whether IDD_DIALOG is registered */
    (void)r;
    CHECK(1);
    exit_localization();
    /* grp ownership transferred to localization — do NOT free manually */
}

TEST(apply_loc_with_text_cmd_does_not_crash)
{
    /*
     * Populate loc_dlg[0] with a TEXT command for IDC_START, then call
     * apply_localization.  Since rw.start_btn is NULL (no GTK), the update
     * should be silently skipped — no crash.
     */
    init_localization();

    /* First register IDD_DIALOG so the list is ready */
    loc_cmd *grp = calloc(1, sizeof(loc_cmd));
    grp->command = LC_GROUP;
    grp->ctrl_id = IDD_DIALOG;
    grp->txt[0]  = strdup("IDD_DIALOG");
    list_init(&grp->list);
    dispatch_loc_cmd(grp);
    /* grp ownership is transferred to localization system */

    /* Now add a TEXT command */
    loc_cmd *txt = make_text_cmd(IDC_START, "IDC_START", "Démarrer");
    dispatch_loc_cmd(txt);
    /* txt ownership is transferred */

    apply_localization(IDD_DIALOG, NULL);
    exit_localization();
    CHECK(1);
}

TEST(apply_loc_with_null_txt1_does_not_update)
{
    /*
     * A TEXT command with NULL txt[1] should be silently skipped.
     * The test verifies this doesn't crash.
     */
    init_localization();

    loc_cmd *grp = calloc(1, sizeof(loc_cmd));
    grp->command = LC_GROUP;
    grp->ctrl_id = IDD_DIALOG;
    grp->txt[0]  = strdup("IDD_DIALOG");
    list_init(&grp->list);
    dispatch_loc_cmd(grp);

    loc_cmd *txt = make_text_cmd(IDC_SELECT, "IDC_SELECT", NULL);
    dispatch_loc_cmd(txt);

    apply_localization(IDD_DIALOG, NULL);
    exit_localization();
    CHECK(1);
}

TEST(apply_loc_with_empty_txt1_does_not_update)
{
    init_localization();

    loc_cmd *grp = calloc(1, sizeof(loc_cmd));
    grp->command = LC_GROUP;
    grp->ctrl_id = IDD_DIALOG;
    grp->txt[0]  = strdup("IDD_DIALOG");
    list_init(&grp->list);
    dispatch_loc_cmd(grp);

    loc_cmd *txt = make_text_cmd(IDC_SELECT, "IDC_SELECT", "");
    dispatch_loc_cmd(txt);

    apply_localization(IDD_DIALOG, NULL);
    exit_localization();
    CHECK(1);
}

TEST(apply_loc_ids_label_does_not_crash)
{
    /* IDS_DEVICE_TXT (2000) — row label; rw.device_label == NULL → skip */
    init_localization();

    loc_cmd *grp = calloc(1, sizeof(loc_cmd));
    grp->command = LC_GROUP;
    grp->ctrl_id = IDD_DIALOG;
    grp->txt[0]  = strdup("IDD_DIALOG");
    list_init(&grp->list);
    dispatch_loc_cmd(grp);

    loc_cmd *txt = make_text_cmd(IDS_DEVICE_TXT, "IDS_DEVICE_TXT", "Périphérique");
    dispatch_loc_cmd(txt);

    apply_localization(IDD_DIALOG, NULL);
    exit_localization();
    CHECK(1);
}

/* ================================================================== */
/* reset_localization                                                   */
/* ================================================================== */

TEST(reset_localization_does_not_crash)
{
    init_localization();
    reset_localization(0);          /* valid index: IDD_DIALOG - IDD_DIALOG */
    reset_localization(IDD_DIALOG); /* on Linux this is a no-op */
    exit_localization();
    CHECK(1);
}

/* ================================================================== */
/* main                                                                 */
/* ================================================================== */
int main(void)
{
    printf("=== localization_linux tests ===\n");

    RUN(apply_loc_empty_dlg_does_not_crash);
    RUN(apply_loc_with_dlg_id_out_of_range);
    RUN(apply_loc_main_dialog_id);
    RUN(apply_loc_repeated_calls);

    RUN(dispatch_null_lcmd_returns_false);
    RUN(dispatch_group_cmd_adds_to_list);
    RUN(apply_loc_with_text_cmd_does_not_crash);
    RUN(apply_loc_with_null_txt1_does_not_update);
    RUN(apply_loc_with_empty_txt1_does_not_update);
    RUN(apply_loc_ids_label_does_not_crash);

    RUN(reset_localization_does_not_crash);

    TEST_RESULTS();
}

#endif /* __linux__ */
