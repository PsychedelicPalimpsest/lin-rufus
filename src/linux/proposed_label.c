/*
 * proposed_label.c — Pure logic for computing the proposed volume label.
 *
 * See proposed_label.h for the interface contract.
 */
#include "proposed_label.h"

const char *get_iso_proposed_label(BOOL user_changed,
                                   const char *image_path,
                                   const char *img_label)
{
	/* If the user manually edited the label, preserve it. */
	if (user_changed)
		return NULL;

	/* When a valid image with a non-empty label is selected, use the ISO label. */
	if (image_path != NULL && image_path[0] != '\0' &&
	    img_label  != NULL && img_label[0]  != '\0')
		return img_label;

	/* No usable ISO label — clear the entry. */
	return "";
}
