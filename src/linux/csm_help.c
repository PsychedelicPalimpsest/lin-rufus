/* src/linux/csm_help.c
 * Pure-C logic for the CSM help indicator label.
 * No GTK dependency — fully unit-testable.
 */
#include "csm_help.h"
#include "../windows/resource.h"   /* MSG_151, MSG_152 */

BOOL csm_help_should_show(int tgt, BOOL has_csm)
{
    return (tgt == TT_UEFI) || (has_csm == TRUE);
}

int csm_help_get_msg_id(int tgt, BOOL has_csm)
{
    (void)has_csm;  /* unused — tgt is the sole discriminator */
    return (tgt == TT_UEFI) ? MSG_152 : MSG_151;
}
