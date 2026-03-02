/* tests/test_csm_help_linux.c
 * Tests for CSM help label logic (item 41).
 *
 * Tests for:
 *   csm_help_should_show(int target_type, BOOL has_csm)
 *   csm_help_get_msg_id(int target_type, BOOL has_csm)
 *
 * These functions encapsulate the display/tooltip logic for the CSM help
 * indicator shown next to the Target System combo. They are pure C (no GTK).
 */
#include "../src/linux/csm_help.h"
#include "../src/windows/rufus.h"      /* TT_BIOS, TT_UEFI */
#include "../src/windows/resource.h"   /* MSG_151, MSG_152, IDS_CSM_HELP_TXT */
#include <stdio.h>
#include <string.h>

/* Minimal test harness */
static int _pass = 0, _fail = 0;
#define CHECK_MSG(cond, msg) do { \
    if (cond) { _pass++; } else { _fail++; printf("  FAIL: %s\n", msg); } \
} while(0)
#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s\n", #name); test_##name(); } while(0)
#define TEST_RESULTS() printf("\n%d passed, %d failed\n", _pass, _fail)

/* Stub lmprintf — not needed for pure-logic tests but required by linker */
char *lmprintf(int id, ...) { (void)id; return ""; }

/* ─────────────────────────────────────────────────────────── *
 *  csm_help_should_show                                        *
 *  The label must appear when:                                 *
 *    a) target_type == TT_UEFI (non-CSM mode — explains what   *
 *       "non CSM" means via MSG_152), OR                       *
 *    b) has_csm == TRUE (BIOS/CSM mode — explains "UEFI-CSM"). *
 * ─────────────────────────────────────────────────────────── */

TEST(show_when_target_uefi_no_csm)
{
    /* Pure UEFI, no CSM entry in list → show to explain "non CSM" */
    CHECK_MSG(csm_help_should_show(TT_UEFI, FALSE) == TRUE,
              "should show for TT_UEFI without CSM");
}

TEST(show_when_target_uefi_with_csm)
{
    /* UEFI selected but CSM entry also present (unusual) → still show */
    CHECK_MSG(csm_help_should_show(TT_UEFI, TRUE) == TRUE,
              "should show for TT_UEFI when CSM present");
}

TEST(show_when_target_bios_has_csm)
{
    /* BIOS/CSM mode selected → show to explain "UEFI-CSM" */
    CHECK_MSG(csm_help_should_show(TT_BIOS, TRUE) == TRUE,
              "should show for TT_BIOS when has_csm is TRUE");
}

TEST(hide_when_target_bios_no_csm)
{
    /* Pure BIOS mode (no CSM in list) → nothing to explain, hide */
    CHECK_MSG(csm_help_should_show(TT_BIOS, FALSE) == FALSE,
              "should hide for TT_BIOS without CSM");
}

TEST(hide_when_invalid_target_no_csm)
{
    /* Unknown target type with no CSM → hide */
    CHECK_MSG(csm_help_should_show(-1, FALSE) == FALSE,
              "should hide for invalid target_type without CSM");
}

TEST(show_when_invalid_target_has_csm)
{
    /* Unknown target type but CSM present → show (CSM flag takes priority) */
    CHECK_MSG(csm_help_should_show(-1, TRUE) == TRUE,
              "should show when has_csm regardless of target_type");
}

TEST(show_when_large_target_type_no_csm)
{
    /* TT_UEFI == 1; any value that equals TT_UEFI must show */
    CHECK_MSG(csm_help_should_show(TT_UEFI, FALSE) == TRUE,
              "TT_UEFI (==1) triggers show");
}

TEST(hide_returns_false_not_negative)
{
    /* Return type is BOOL; FALSE must be exactly FALSE (0), not negative */
    int result = csm_help_should_show(TT_BIOS, FALSE);
    CHECK_MSG(result == FALSE, "hide result must be FALSE (0), not another falsey value");
}

TEST(show_returns_true_not_arbitrary)
{
    /* Return type is BOOL; TRUE must be exactly TRUE (1) */
    int result = csm_help_should_show(TT_UEFI, FALSE);
    CHECK_MSG(result == TRUE, "show result must be TRUE (1)");
}

/* ─────────────────────────────────────────────────────────── *
 *  csm_help_get_msg_id                                         *
 *  MSG_152 → "non CSM" explanation  (TT_UEFI selected)        *
 *  MSG_151 → "UEFI-CSM" explanation (TT_BIOS + has_csm)       *
 * ─────────────────────────────────────────────────────────── */

TEST(msg_id_uefi_no_csm_returns_152)
{
    CHECK_MSG(csm_help_get_msg_id(TT_UEFI, FALSE) == MSG_152,
              "TT_UEFI without CSM → MSG_152 (non-CSM explanation)");
}

TEST(msg_id_uefi_with_csm_returns_152)
{
    /* UEFI is selected → always use MSG_152 for "non CSM" note */
    CHECK_MSG(csm_help_get_msg_id(TT_UEFI, TRUE) == MSG_152,
              "TT_UEFI with CSM also → MSG_152");
}

TEST(msg_id_bios_has_csm_returns_151)
{
    CHECK_MSG(csm_help_get_msg_id(TT_BIOS, TRUE) == MSG_151,
              "TT_BIOS with CSM → MSG_151 (UEFI-CSM explanation)");
}

TEST(msg_id_bios_no_csm_returns_151)
{
    /* Even if we shouldn't show, the ID still resolves to MSG_151 for BIOS */
    CHECK_MSG(csm_help_get_msg_id(TT_BIOS, FALSE) == MSG_151,
              "TT_BIOS without CSM → MSG_151");
}

TEST(msg_id_values_are_distinct)
{
    CHECK_MSG(MSG_151 != MSG_152, "MSG_151 and MSG_152 must be different constants");
}

TEST(msg_id_uefi_differs_from_bios)
{
    int id_uefi = csm_help_get_msg_id(TT_UEFI, FALSE);
    int id_bios = csm_help_get_msg_id(TT_BIOS, TRUE);
    CHECK_MSG(id_uefi != id_bios,
              "UEFI and BIOS/CSM scenarios must return different message IDs");
}

TEST(msg_id_returns_valid_msg_number)
{
    /* MSG IDs are in the range 3000-4095 by convention in rufus */
    int id = csm_help_get_msg_id(TT_UEFI, FALSE);
    CHECK_MSG(id >= 3000 && id < 4096,
              "message ID must be in valid MSG range [3000, 4096)");
}

TEST(msg_id_bios_csm_in_valid_range)
{
    int id = csm_help_get_msg_id(TT_BIOS, TRUE);
    CHECK_MSG(id >= 3000 && id < 4096,
              "BIOS/CSM message ID must be in valid MSG range");
}

/* ─────────────────────────────────────────────────────────── *
 *  IDS_CSM_HELP_TXT resource constant                         *
 * ─────────────────────────────────────────────────────────── */

TEST(ids_csm_help_txt_defined)
{
    /* Sanity check that the resource ID is available in this build */
    int id = IDS_CSM_HELP_TXT;
    CHECK_MSG(id > 0, "IDS_CSM_HELP_TXT must be a positive resource ID");
}

TEST(ids_csm_help_txt_value)
{
    /* Fixed to 2005 per resource.h */
    CHECK_MSG(IDS_CSM_HELP_TXT == 2005,
              "IDS_CSM_HELP_TXT must equal 2005");
}

int main(void)
{
    printf("=== CSM help label logic tests ===\n\n");

    printf("-- csm_help_should_show --\n");
    RUN(show_when_target_uefi_no_csm);
    RUN(show_when_target_uefi_with_csm);
    RUN(show_when_target_bios_has_csm);
    RUN(hide_when_target_bios_no_csm);
    RUN(hide_when_invalid_target_no_csm);
    RUN(show_when_invalid_target_has_csm);
    RUN(show_when_large_target_type_no_csm);
    RUN(hide_returns_false_not_negative);
    RUN(show_returns_true_not_arbitrary);

    printf("\n-- csm_help_get_msg_id --\n");
    RUN(msg_id_uefi_no_csm_returns_152);
    RUN(msg_id_uefi_with_csm_returns_152);
    RUN(msg_id_bios_has_csm_returns_151);
    RUN(msg_id_bios_no_csm_returns_151);
    RUN(msg_id_values_are_distinct);
    RUN(msg_id_uefi_differs_from_bios);
    RUN(msg_id_returns_valid_msg_number);
    RUN(msg_id_bios_csm_in_valid_range);

    printf("\n-- resource constants --\n");
    RUN(ids_csm_help_txt_defined);
    RUN(ids_csm_help_txt_value);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}
