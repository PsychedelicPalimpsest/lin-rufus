/*
 * device_monitor.c — Linux block-device hotplug monitor (udev backend).
 *
 * Spawns a background pthread that polls a udev netlink socket for block
 * device add/remove events.  When an event is received the registered
 * callback is invoked — but no more than once per DEVICE_MONITOR_DEBOUNCE_MS
 * milliseconds to avoid flooding the UI with rapid-fire notifications.
 *
 * device_monitor_inject() provides a testing and "manual rescan" hook that
 * synthesises a device-change event without requiring real hardware.
 *
 * Thread safety: all public functions are protected by state_mutex.
 */

#include "device_monitor.h"   /* ../common/device_monitor.h via -I flag */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <poll.h>
#include <libudev.h>

/* -------------------------------------------------------------------------
 * Internal state
 * --------------------------------------------------------------------- */

static pthread_t          g_thread;
static volatile int       g_running    = 0;
static device_change_cb_t g_cb         = NULL;
static void              *g_user_data  = NULL;

/* Protects g_running, g_cb, g_user_data and thread lifecycle. */
static pthread_mutex_t    g_state_mtx  = PTHREAD_MUTEX_INITIALIZER;

/* Debounce: record the monotonic time of the last callback invocation. */
static struct timespec    g_last_notify = { 0, 0 };
static pthread_mutex_t    g_debounce_mtx = PTHREAD_MUTEX_INITIALIZER;

/* -------------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------- */

/* Return milliseconds elapsed since g_last_notify.  Returns a very large
 * number if g_last_notify has never been set (tv_sec == 0). */
static long ms_since_last_notify(void)
{
	if (g_last_notify.tv_sec == 0 && g_last_notify.tv_nsec == 0)
		return (long)0x7FFFFFFF; /* "infinite" — never notified */

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	long ms = (now.tv_sec  - g_last_notify.tv_sec)  * 1000L
	        + (now.tv_nsec - g_last_notify.tv_nsec) / 1000000L;
	return ms;
}

/* Invoke the callback if the debounce window has passed.
 * Must NOT be called with g_state_mtx held (callback may re-enter). */
static void maybe_notify(void)
{
	pthread_mutex_lock(&g_debounce_mtx);
	long elapsed = ms_since_last_notify();
	if (elapsed < DEVICE_MONITOR_DEBOUNCE_MS) {
		pthread_mutex_unlock(&g_debounce_mtx);
		return;
	}
	/* Record the notification time before releasing the lock so that
	 * concurrent calls see it immediately. */
	clock_gettime(CLOCK_MONOTONIC, &g_last_notify);
	pthread_mutex_unlock(&g_debounce_mtx);

	/* Snapshot callback/data under state lock to avoid TOCTOU. */
	pthread_mutex_lock(&g_state_mtx);
	device_change_cb_t cb   = g_cb;
	void              *data = g_user_data;
	pthread_mutex_unlock(&g_state_mtx);

	if (cb)
		cb(data);
}

/* -------------------------------------------------------------------------
 * Monitor thread
 * --------------------------------------------------------------------- */

static void *monitor_thread_fn(void *arg)
{
	(void)arg;

	struct udev         *udev = udev_new();
	struct udev_monitor *mon  = NULL;
	int                  fd   = -1;

	if (!udev)
		goto done;

	mon = udev_monitor_new_from_netlink(udev, "udev");
	if (!mon)
		goto done;

	udev_monitor_filter_add_match_subsystem_devtype(mon, "block", NULL);
	udev_monitor_enable_receiving(mon);

	fd = udev_monitor_get_fd(mon);

	while (g_running) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int r = poll(&pfd, 1, 200); /* 200 ms timeout to check g_running */
		if (r <= 0)
			continue;
		if (!(pfd.revents & POLLIN))
			continue;

		struct udev_device *dev = udev_monitor_receive_device(mon);
		if (!dev)
			continue;

		const char *action = udev_device_get_action(dev);
		if (action && (strcmp(action, "add")    == 0 ||
		               strcmp(action, "remove") == 0)) {
			maybe_notify();
		}
		udev_device_unref(dev);
	}

done:
	if (mon)  udev_monitor_unref(mon);
	if (udev) udev_unref(udev);

	/* Always clear the running flag so is_running() returns 0 even if
	 * udev initialisation failed. */
	pthread_mutex_lock(&g_state_mtx);
	g_running = 0;
	pthread_mutex_unlock(&g_state_mtx);

	return NULL;
}

/* =========================================================================
 * Public API
 * ====================================================================== */

void device_monitor_start(device_change_cb_t cb, void *user_data)
{
	pthread_mutex_lock(&g_state_mtx);

	if (g_running) {
		/* Already running — second start is a no-op. */
		pthread_mutex_unlock(&g_state_mtx);
		return;
	}

	g_cb        = cb;
	g_user_data = user_data;
	g_running   = 1;

	if (pthread_create(&g_thread, NULL, monitor_thread_fn, NULL) != 0)
		g_running = 0;

	pthread_mutex_unlock(&g_state_mtx);
}

void device_monitor_stop(void)
{
	pthread_mutex_lock(&g_state_mtx);

	if (!g_running) {
		pthread_mutex_unlock(&g_state_mtx);
		return;
	}

	g_running = 0;
	pthread_mutex_unlock(&g_state_mtx);

	pthread_join(g_thread, NULL);
}

int device_monitor_is_running(void)
{
	pthread_mutex_lock(&g_state_mtx);
	int r = g_running;
	pthread_mutex_unlock(&g_state_mtx);
	return r;
}

void device_monitor_inject(void)
{
	if (!device_monitor_is_running())
		return;
	maybe_notify();
}

void device_monitor_reset_debounce(void)
{
	pthread_mutex_lock(&g_debounce_mtx);
	g_last_notify.tv_sec  = 0;
	g_last_notify.tv_nsec = 0;
	pthread_mutex_unlock(&g_debounce_mtx);
}
