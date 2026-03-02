/* src/linux/csm_help.h
 * Pure-C logic for the CSM help indicator label shown next to the
 * Target System combo box.
 *
 * These functions have no GTK dependency and are fully unit-testable.
 */
#pragma once
#include "../windows/rufus.h"   /* TT_BIOS, TT_UEFI, BOOL */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * csm_help_should_show - Decide whether the CSM help label is visible.
 *
 * Returns TRUE when:
 *   - target_type == TT_UEFI (show "non CSM" explanation via MSG_152), OR
 *   - has_csm == TRUE       (show "UEFI-CSM" explanation via MSG_151).
 * Returns FALSE otherwise (plain BIOS with no CSM option listed).
 */
BOOL csm_help_should_show(int tgt, BOOL has_csm);

/*
 * csm_help_get_msg_id - Return the localisation message ID for the tooltip.
 *
 * Returns MSG_152 when target_type == TT_UEFI  ("non CSM" explanation).
 * Returns MSG_151 in all other cases            ("UEFI-CSM" explanation).
 */
int csm_help_get_msg_id(int tgt, BOOL has_csm);

#ifdef __cplusplus
}
#endif
