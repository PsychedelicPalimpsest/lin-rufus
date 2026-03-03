/*
 * Rufus: The Reliable USB Formatting Utility
 * Drag-and-drop URI helpers — Linux header
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#pragma once

/*
 * path_from_file_uri  —  convert a "file://" URI to a local filesystem path.
 *
 * Handles percent-encoding (%20 → space, etc.) and strips the host component.
 * Returns a malloc'd string; caller must free().  Returns NULL on invalid input.
 */
char *path_from_file_uri(const char *uri);
