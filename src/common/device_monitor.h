/*
 * device_monitor.h — Abstract interface for block-device hotplug notifications.
 *
 * Provides a portable, OS-agnostic API for monitoring block device
 * arrival/removal events.  Callers register a callback once and receive
 * a notification no more than once per DEVICE_MONITOR_DEBOUNCE_MS
 * milliseconds regardless of how many raw events arrive.
 *
 * Platform implementations live in:
 *   src/linux/device_monitor.c  — udev netlink monitor (Linux)
 *   Windows notifications are handled natively by the message loop
 *   via WM_DEVICECHANGE / UM_MEDIA_CHANGE, so no Windows impl is needed.
 *
 * Usage:
 *   device_monitor_start(my_cb, my_data);   // begin monitoring
 *   ...
 *   device_monitor_stop();                  // stop monitoring, join thread
 *
 * Testing / manual rescan:
 *   device_monitor_inject();                // fire callback now (if debounce allows)
 */

#pragma once
#ifndef DEVICE_MONITOR_H
#define DEVICE_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

/* Milliseconds between successive notifications.  Rapid events within this
 * window are collapsed into a single callback invocation. */
#define DEVICE_MONITOR_DEBOUNCE_MS 1000

/* Callback signature.  Invoked on the GLib main thread (GTK builds) or
 * directly from the caller's context (non-GUI / test builds).
 * user_data is the value passed to device_monitor_start(). */
typedef void (*device_change_cb_t)(void *user_data);

/* Start the device-change monitor.  cb is called (with user_data) whenever
 * a block device is added or removed, subject to debounce.  Calling start
 * while already running is a no-op — the existing callback / data are kept.
 *
 * cb may be NULL; in that case the monitor thread still runs but no
 * notification is delivered. */
void device_monitor_start(device_change_cb_t cb, void *user_data);

/* Stop the device-change monitor and block until the monitor thread exits.
 * Safe to call before start() or multiple times. */
void device_monitor_stop(void);

/* Returns non-zero if the monitor thread is currently running. */
int  device_monitor_is_running(void);

/* Inject a synthetic device-change event (subject to debounce).
 * Useful for a manual "rescan" action and for unit testing without real
 * hardware.  Safe to call regardless of whether the monitor is running;
 * if not running, the call is silently ignored. */
void device_monitor_inject(void);

/* Force the debounce timer to expire so that the very next inject() or real
 * event will always fire the callback immediately.  Only intended for use in
 * tests; do not call from production code. */
void device_monitor_reset_debounce(void);

#ifdef __cplusplus
}
#endif

#endif /* DEVICE_MONITOR_H */
