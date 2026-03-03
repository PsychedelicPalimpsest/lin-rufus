#pragma once
/*
 * proposed_label.h — Pure logic for computing the proposed volume label.
 *
 * Extracted from SetProposedLabel() so that the decision logic can be
 * unit-tested without a GTK environment.
 */
#include "../windows/rufus.h"

/*
 * get_iso_proposed_label()
 *
 * Returns the string that should be placed in the label entry after an ISO
 * scan completes.  All arguments are pure inputs — no globals are touched.
 *
 *   user_changed  – TRUE if the user has manually edited the label field since
 *                   the last ISO scan.  When TRUE the function returns NULL to
 *                   signal "do not overwrite the user's text".
 *   image_path    – Current image_path global (may be NULL).
 *   img_label     – img_report.label string (may be NULL or empty).
 *
 * Returns:
 *   NULL           – user manually changed the label; caller must not update.
 *   img_label      – when a non-empty ISO label is available.
 *   ""             – clear the label (no ISO label available).
 */
const char *get_iso_proposed_label(BOOL user_changed,
                                   const char *image_path,
                                   const char *img_label);
