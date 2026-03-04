/*
 * Rufus: The Reliable USB Formatting Utility
 * Boot-time validation predicates — Linux build shim
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * The canonical implementation lives in src/common/boot_validation.c.
 * This file is compiled by the main autotools build (which references
 * linux/boot_validation.c) and simply re-exports that implementation.
 */
#include "../common/boot_validation.c"
