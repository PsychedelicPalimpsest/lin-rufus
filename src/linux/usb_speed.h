/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux: usb_speed.h — USB speed Mbps → version string conversion
 * Copyright © 2024-2025 PsychedelicPalimpsest
 */

#pragma once

/**
 * Convert a sysfs USB speed string (Mbps) to a human-readable label.
 * @speed_mbps: e.g. "480", "5000", "10000".  May be NULL or empty.
 * Returns a static string such as "USB 2.0", "USB 3.0", etc.
 * Falls back to "USB" for unknown or missing values.
 */
const char *usb_speed_string(const char *speed_mbps);
