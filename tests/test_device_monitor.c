/*
 * test_device_monitor.c — Unit tests for the device_monitor abstraction.
 *
 * These tests exercise the lifecycle, callback dispatch, debounce, and
 * safety properties of the device_monitor API without requiring real hardware
 * or an actual udev daemon.  Synthetic events are injected via
 * device_monitor_inject() and device_monitor_reset_debounce().
 *
 * Build with the tests/Makefile target; see CFLAGS_LINUX_test_device_monitor
 * and friends defined there.
 */

#include "framework.h"
#include "../src/common/device_monitor.h"

#include <unistd.h>   /* usleep */
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Helpers shared across tests
 * --------------------------------------------------------------------- */

/* Simple counter callback — increments an int pointed to by user_data. */
static void count_cb(void *user_data)
{
	int *n = (int *)user_data;
	if (n) (*n)++;
}

/* Ensure the monitor is fully stopped before each test to avoid leaking
 * state from a previous test. */
static void teardown(void)
{
	device_monitor_stop();
	device_monitor_reset_debounce();
}

/* =========================================================================
 * 1. Lifecycle tests
 * ====================================================================== */

TEST(not_running_initially)
{
	teardown();
	CHECK(device_monitor_is_running() == 0);
}

TEST(running_after_start)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	/* Give the thread time to initialise. */
	usleep(50000); /* 50 ms */
	CHECK(device_monitor_is_running() != 0);
	teardown();
}

TEST(not_running_after_stop)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	usleep(50000);
	device_monitor_stop();
	CHECK(device_monitor_is_running() == 0);
}

TEST(stop_before_start_is_safe)
{
	teardown();
	/* Must not crash, assert, or hang. */
	device_monitor_stop();
	CHECK(device_monitor_is_running() == 0);
}

TEST(double_stop_is_safe)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	usleep(50000);
	device_monitor_stop();
	device_monitor_stop(); /* second stop must not crash */
	CHECK(device_monitor_is_running() == 0);
}

TEST(double_start_is_idempotent)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	usleep(50000);
	device_monitor_start(count_cb, &n); /* second call ignored */
	usleep(50000);
	CHECK(device_monitor_is_running() != 0);
	teardown();
}

TEST(start_with_null_callback_is_safe)
{
	teardown();
	device_monitor_start(NULL, NULL);
	usleep(50000);
	/* Monitor should be running (or have exited cleanly if udev is absent). */
	/* Either state is valid — what matters is no crash. */
	device_monitor_stop();
	CHECK(1); /* reached here without crashing */
}

/* =========================================================================
 * 2. Callback dispatch tests
 * ====================================================================== */

TEST(inject_fires_callback_when_running)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	usleep(50000);

	device_monitor_inject();
	usleep(20000); /* let any async dispatch settle */

	CHECK(n == 1);
	teardown();
}

TEST(user_data_passed_correctly)
{
	teardown();
	int val = 42;
	device_monitor_start(count_cb, &val);
	usleep(50000);

	device_monitor_inject();
	usleep(20000);

	/* val should have been incremented from 42 to 43 */
	CHECK(val == 43);
	teardown();
}

TEST(inject_without_start_is_safe)
{
	teardown();
	/* Must not crash. */
	device_monitor_inject();
	CHECK(1);
}

TEST(inject_without_start_does_not_fire_callback)
{
	teardown();
	int n = 0;
	/* Register a callback via start then stop, then inject — cb must not fire. */
	device_monitor_start(count_cb, &n);
	usleep(50000);
	device_monitor_stop();

	n = 0;
	device_monitor_inject();
	usleep(20000);

	CHECK(n == 0);
}

/* =========================================================================
 * 3. Debounce tests
 * ====================================================================== */

TEST(rapid_injects_fire_callback_only_once)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	usleep(50000);

	/* Three rapid injects — only the first should trigger the callback. */
	device_monitor_inject();
	device_monitor_inject();
	device_monitor_inject();
	usleep(20000);

	CHECK(n == 1);
	teardown();
}

TEST(inject_after_debounce_window_fires_again)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	usleep(50000);

	/* First inject */
	device_monitor_inject();
	usleep(20000);
	CHECK(n == 1);

	/* Reset the debounce timer so the next inject fires immediately. */
	device_monitor_reset_debounce();
	device_monitor_inject();
	usleep(20000);
	CHECK(n == 2);

	teardown();
}

TEST(inject_waits_for_debounce_if_not_reset)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	usleep(50000);

	device_monitor_inject();
	usleep(20000);
	CHECK(n == 1);

	/* Immediate second inject within debounce window — must NOT fire. */
	device_monitor_inject();
	usleep(20000);
	CHECK(n == 1); /* still 1 */

	teardown();
}

TEST(inject_fires_after_real_debounce_window)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	usleep(50000);

	device_monitor_inject();
	usleep(20000);
	CHECK(n == 1);

	/* Wait for the full debounce window to elapse naturally. */
	usleep((DEVICE_MONITOR_DEBOUNCE_MS + 50) * 1000UL);

	device_monitor_inject();
	usleep(20000);
	CHECK(n == 2);

	teardown();
}

/* =========================================================================
 * 4. Thread safety / stress tests
 * ====================================================================== */

#include <pthread.h>

typedef struct { int count; int iterations; } StressArg;

static void *stress_inject_thread(void *arg)
{
	StressArg *a = (StressArg *)arg;
	for (int i = 0; i < a->iterations; i++) {
		device_monitor_inject();
		usleep(1000); /* 1 ms between injects */
	}
	return NULL;
}

TEST(concurrent_injects_do_not_crash)
{
	teardown();
	int n = 0;
	device_monitor_start(count_cb, &n);
	usleep(50000);

	/* Spawn 4 threads each injecting 20 events — must not crash or corrupt. */
	pthread_t threads[4];
	StressArg arg = { 0, 20 };
	for (int i = 0; i < 4; i++)
		pthread_create(&threads[i], NULL, stress_inject_thread, &arg);
	for (int i = 0; i < 4; i++)
		pthread_join(threads[i], NULL);

	usleep(20000);
	/* n may be any value ≥ 1; we just verify no crash and some callbacks fired. */
	CHECK(n >= 1);
	teardown();
}

TEST(start_stop_start_works)
{
	teardown();
	int n = 0;

	device_monitor_start(count_cb, &n);
	usleep(50000);
	device_monitor_stop();

	device_monitor_reset_debounce();
	device_monitor_start(count_cb, &n);
	usleep(50000);

	device_monitor_inject();
	usleep(20000);
	CHECK(n == 1);

	teardown();
}

/* =========================================================================
 * main
 * ====================================================================== */

int main(void)
{
	printf("=== device_monitor tests ===\n\n");

	/* Lifecycle */
	RUN(not_running_initially);
	RUN(running_after_start);
	RUN(not_running_after_stop);
	RUN(stop_before_start_is_safe);
	RUN(double_stop_is_safe);
	RUN(double_start_is_idempotent);
	RUN(start_with_null_callback_is_safe);

	/* Callback dispatch */
	RUN(inject_fires_callback_when_running);
	RUN(user_data_passed_correctly);
	RUN(inject_without_start_is_safe);
	RUN(inject_without_start_does_not_fire_callback);

	/* Debounce */
	RUN(rapid_injects_fire_callback_only_once);
	RUN(inject_after_debounce_window_fires_again);
	RUN(inject_waits_for_debounce_if_not_reset);
	RUN(inject_fires_after_real_debounce_window);

	/* Thread safety */
	RUN(concurrent_injects_do_not_crash);
	RUN(start_stop_start_works);

	TEST_RESULTS();
}
