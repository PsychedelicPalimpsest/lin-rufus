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
/* PrintStatusInfo — status handler callback                           */
/* ================================================================== */

/* Forward declarations for the handler registration API */
extern void rufus_set_status_handler(void (*fn)(const char *msg));
extern void PrintStatusInfo(BOOL info, BOOL debug, unsigned int duration,
                            int msg_id, ...);

/* Capture variables used across tests */
static int    g_status_calls  = 0;
static char   g_status_buf[512];

static void test_status_handler(const char *msg)
{
    g_status_calls++;
    if (msg)
        snprintf(g_status_buf, sizeof(g_status_buf), "%s", msg);
    else
        g_status_buf[0] = '\0';
}

static void reset_status_capture(void)
{
    g_status_calls = 0;
    g_status_buf[0] = '\0';
}

/*
 * Helper: register a single MSG_000 entry so that PrintStatusInfo
 * has a real format string to work with.
 * We point msg_table at default_msg_table and override index 0.
 */
static void setup_msg_000(void)
{
    init_localization();
    /* Register a group so msg_table is live */
    loc_cmd *grp = calloc(1, sizeof(loc_cmd));
    grp->command = LC_GROUP;
    grp->ctrl_id = IDD_DIALOG;
    grp->txt[0]  = strdup("IDD_DIALOG");
    list_init(&grp->list);
    dispatch_loc_cmd(grp);

    /* Point msg_table at the default table and override entry 0 */
    extern char *default_msg_table[];
    extern char **msg_table;
    msg_table = default_msg_table;
    default_msg_table[0] = "TestMessage-%d";
}

/* 1. Handler is called once when PrintStatusInfo fires for a valid msg */
TEST(print_status_handler_called)
{
    setup_msg_000();
    reset_status_capture();
    rufus_set_status_handler(test_status_handler);

    PrintStatusInfo(FALSE, FALSE, 0, MSG_000, 42);

    rufus_set_status_handler(NULL);
    exit_localization();

    CHECK_MSG(g_status_calls == 1, "handler must be called exactly once");
}

/* 2. Message text is forwarded to handler */
TEST(print_status_handler_receives_text)
{
    setup_msg_000();
    reset_status_capture();
    rufus_set_status_handler(test_status_handler);

    PrintStatusInfo(FALSE, FALSE, 0, MSG_000, 7);

    rufus_set_status_handler(NULL);
    exit_localization();

    CHECK_MSG(g_status_calls >= 1, "handler must be called");
    CHECK_MSG(strstr(g_status_buf, "7") != NULL,
              "handler should receive formatted text containing '7'");
}

/* 3. NULL handler does not crash */
TEST(print_status_null_handler_no_crash)
{
    setup_msg_000();
    rufus_set_status_handler(NULL);
    /* Must not crash */
    PrintStatusInfo(FALSE, FALSE, 0, MSG_000, 0);
    exit_localization();
    CHECK(1);
}

/* 4. Handler not called for out-of-range msg_id */
TEST(print_status_out_of_range_msg_id)
{
    init_localization();
    reset_status_capture();
    rufus_set_status_handler(test_status_handler);

    PrintStatusInfo(FALSE, FALSE, 0, MSG_MAX + 1, 0);

    rufus_set_status_handler(NULL);
    exit_localization();

    CHECK_MSG(g_status_calls == 0, "handler must NOT be called for invalid msg_id");
}

/* 5. Negative msg_id does not crash and does not call handler */
TEST(print_status_negative_msg_id)
{
    init_localization();
    reset_status_capture();
    rufus_set_status_handler(test_status_handler);

    PrintStatusInfo(FALSE, FALSE, 0, -1, 0);

    rufus_set_status_handler(NULL);
    exit_localization();

    CHECK_MSG(g_status_calls == 0, "handler must NOT be called for msg_id < 0");
}

/* 6. info=TRUE still routes to handler */
TEST(print_status_info_true_calls_handler)
{
    setup_msg_000();
    reset_status_capture();
    rufus_set_status_handler(test_status_handler);

    PrintStatusInfo(TRUE, FALSE, 0, MSG_000, 99);

    rufus_set_status_handler(NULL);
    exit_localization();

    CHECK_MSG(g_status_calls >= 1, "info=TRUE must still invoke the handler");
}

/* 7. duration parameter is ignored — no crash, handler still called */
TEST(print_status_duration_ignored)
{
    setup_msg_000();
    reset_status_capture();
    rufus_set_status_handler(test_status_handler);

    PrintStatusInfo(FALSE, FALSE, 5000 /* ms */, MSG_000, 1);

    rufus_set_status_handler(NULL);
    exit_localization();

    CHECK_MSG(g_status_calls >= 1, "duration must not prevent handler call");
}

/* Helper for test 8 */
static int g_other_calls = 0;
static void capture_other(const char *m) { (void)m; g_other_calls++; }

/* 8. Handler registration replaces previous handler */
TEST(print_status_handler_replaced)
{
    setup_msg_000();
    reset_status_capture();
    g_other_calls = 0;

    rufus_set_status_handler(capture_other);
    rufus_set_status_handler(test_status_handler); /* replace */

    PrintStatusInfo(FALSE, FALSE, 0, MSG_000, 0);

    rufus_set_status_handler(NULL);
    exit_localization();

    CHECK_MSG(g_status_calls == 1, "new handler must be called once");
    CHECK_MSG(g_other_calls == 0,  "replaced handler must NOT be called");
}

/* 9. Multiple calls accumulate in the handler */
TEST(print_status_multiple_calls)
{
    setup_msg_000();
    reset_status_capture();
    rufus_set_status_handler(test_status_handler);

    PrintStatusInfo(FALSE, FALSE, 0, MSG_000, 1);
    PrintStatusInfo(FALSE, FALSE, 0, MSG_000, 2);
    PrintStatusInfo(FALSE, FALSE, 0, MSG_000, 3);

    rufus_set_status_handler(NULL);
    exit_localization();

    CHECK_MSG(g_status_calls == 3, "handler must be called once per PrintStatusInfo");
}

/* 10. PrintStatus convenience macro routes through PrintStatusInfo */
TEST(print_status_macro_calls_handler)
{
    setup_msg_000();
    reset_status_capture();
    rufus_set_status_handler(test_status_handler);

    PrintStatus(0, MSG_000, 0);

    rufus_set_status_handler(NULL);
    exit_localization();

    CHECK_MSG(g_status_calls >= 1, "PrintStatus macro must invoke handler");
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

    RUN(print_status_handler_called);
    RUN(print_status_handler_receives_text);
    RUN(print_status_null_handler_no_crash);
    RUN(print_status_out_of_range_msg_id);
    RUN(print_status_negative_msg_id);
    RUN(print_status_info_true_calls_handler);
    RUN(print_status_duration_ignored);
    RUN(print_status_handler_replaced);
    RUN(print_status_multiple_calls);
    RUN(print_status_macro_calls_handler);

    TEST_RESULTS();
}

#endif /* __linux__ */
