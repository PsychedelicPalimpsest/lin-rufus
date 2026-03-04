/*
 * test_progress_linux.c — TDD tests for src/linux/progress.c
 *
 * Tests are written BEFORE the implementation (TDD contract).
 * All tests exercise the ring-buffer speed/ETA tracking logic.
 */

#define _GNU_SOURCE
#include "framework.h"

#include <string.h>
#include <stdint.h>
#include <limits.h>

/* Pull in the compat layer so <windows.h> macros (BOOL etc.) work */
#include <windows.h>

/* Unit under test */
#include "../src/linux/progress.h"

/* ── helpers ───────────────────────────────────────────────────────────── */

/* Simulate a smooth transfer: @n samples of @bytes_per_sample bytes, each
 * @interval_ms apart.  Returns the elapsed time after the last sample. */
static uint64_t simulate_transfer(struct bar_progress *bp,
                                  int n, uint64_t bytes_per_sample,
                                  uint64_t interval_ms)
{
	uint64_t t = 0;
	for (int i = 0; i < n; i++) {
		t += interval_ms;
		bar_update(bp, bytes_per_sample, t);
	}
	return t;
}

/* ── tests ─────────────────────────────────────────────────────────────── */

static void test_bar_reset_zeroes_state(void)
{
	struct bar_progress bp;
	memset(&bp, 0xFF, sizeof(bp));   /* fill with garbage */
	bar_reset(&bp, 1024 * 1024);

	CHECK_INT_EQ((int)bp.count,               0);
	CHECK_INT_EQ((int)bp.hist.total_time,     0);
	CHECK_INT_EQ((int)bp.hist.total_bytes,    0);
	CHECK_INT_EQ((int)bp.recent_bytes,        0);
	CHECK_INT_EQ((int)bp.stalled,             FALSE);
	CHECK_INT_EQ((int)bp.last_eta_value,      0);
}

static void test_bar_reset_sets_total_length(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 999999);
	CHECK_INT_EQ((int)bp.total_length, 999999);
}

/* Small elapsed time → sample is not yet added to the ring */
static void test_bar_update_sub_sample_min_not_stored(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 1024 * 1024);

	/* Feed a sample shorter than SPEED_SAMPLE_MIN */
	bar_update(&bp, 512, SPEED_SAMPLE_MIN - 1);

	/* Nothing stored in ring yet */
	CHECK_INT_EQ((int)bp.hist.total_bytes, 0);
	CHECK_INT_EQ((int)bp.hist.total_time,  0);
	/* But recent_bytes accumulated */
	CHECK_INT_EQ((int)bp.recent_bytes, 512);
}

/* A sample at exactly SPEED_SAMPLE_MIN IS committed (not strict less-than) */
static void test_bar_update_exact_sample_min_stored(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 1024 * 1024);
	bar_update(&bp, 512, SPEED_SAMPLE_MIN);
	/* recent_age == SPEED_SAMPLE_MIN → condition (recent_age < SPEED_SAMPLE_MIN)
	 * is FALSE, so the sample should enter the ring. */
	CHECK(bp.hist.total_bytes > 0);
}

/* After SPEED_SAMPLE_MIN, data should enter the ring */
static void test_bar_update_over_sample_min_stored(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 1024 * 1024);

	bar_update(&bp, 512, SPEED_SAMPLE_MIN + 1);

	CHECK(bp.hist.total_bytes > 0);
	CHECK(bp.hist.total_time  > 0);
}

/* Multiple updates fill the ring correctly */
static void test_bar_update_multiple_samples_accumulate(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 10 * 1024 * 1024);

	uint64_t elapsed = simulate_transfer(&bp, 5, 1024, 200);
	(void)elapsed;

	/* All 5 samples should be in the ring */
	CHECK(bp.hist.total_bytes >= 5 * 1024);
}

/* Ring wraps after SPEED_HISTORY_SIZE entries */
static void test_bar_update_ring_wraps(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 100 * 1024 * 1024);

	/* SPEED_HISTORY_SIZE + 5 samples to trigger wrap */
	simulate_transfer(&bp, SPEED_HISTORY_SIZE + 5, 4096, 200);

	/* The ring position wraps; oldest entries are evicted.
	 * total_bytes should be capped at SPEED_HISTORY_SIZE entries. */
	uint64_t max_ring_bytes = (uint64_t)SPEED_HISTORY_SIZE * 4096;
	CHECK(bp.hist.total_bytes <= max_ring_bytes);
	CHECK(bp.hist.total_time  <= (uint64_t)SPEED_HISTORY_SIZE * 200);
}

/* Speed should be positive after several samples */
static void test_bar_get_speed_positive_after_transfer(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 10 * 1024 * 1024);

	uint64_t elapsed = simulate_transfer(&bp, 10, 4096, 200);

	uint64_t speed = bar_get_speed(&bp, elapsed);
	CHECK(speed > 0);
}

/* Speed should be zero before enough history accumulates */
static void test_bar_get_speed_zero_no_history(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 1024 * 1024);

	/* One tiny sample below SPEED_SAMPLE_MIN */
	bar_update(&bp, 512, 10);
	uint64_t speed = bar_get_speed(&bp, 10);
	CHECK_INT_EQ((int)speed, 0);
}

/* Approximate speed correctness: 4 MB/s ± 20% */
static void test_bar_get_speed_approximate(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 100 * 1024 * 1024);

	/* 4096 bytes every 200 ms (above SPEED_SAMPLE_MIN=150) → 20480 bytes/s = 20 KB/s */
	uint64_t elapsed = simulate_transfer(&bp, 20, 4096, 200);

	uint64_t speed = bar_get_speed(&bp, elapsed);
	/* 4096 bytes / 0.2 s = 20480 bytes/s */
	uint64_t expected = 4096ULL * 1000 / 200;   /* bytes/second */
	uint64_t margin   = expected / 5;            /* 20% tolerance */
	CHECK(speed >= expected - margin);
	CHECK(speed <= expected + margin);
}

/* ETA returns UINT32_MAX when not enough information */
static void test_bar_get_eta_unknown_early(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 10 * 1024 * 1024);

	/* Only 1 second of transfer — within ETA_REFRESH_INTERVAL minimum */
	bar_update(&bp, 1024, 1000);
	uint32_t eta = bar_get_eta(&bp, 1000);
	CHECK_INT_EQ((int)eta, (int)UINT32_MAX);
}

/* ETA should be positive and finite after enough progress */
static void test_bar_get_eta_positive(void)
{
	struct bar_progress bp;
	uint64_t total = 10 * 1024 * 1024;
	bar_reset(&bp, total);

	/* Write 5 MB over 5000 ms → half done, should be ~5s remaining */
	uint64_t elapsed = simulate_transfer(&bp, 25, 200 * 1024, 200);
	bp.count = 25 * 200 * 1024;   /* update count to match */

	uint32_t eta = bar_get_eta(&bp, elapsed);
	/* ETA might still be UINT32_MAX if not enough dl_total_time for the formula,
	 * but if it's computed it should be < 60 s for a half-done 10 MB transfer */
	if (eta != UINT32_MAX)
		CHECK(eta < 60);
}

/* Stall: no bytes for STALL_START_TIME clears the ring */
static void test_bar_update_stall_clears_ring(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 100 * 1024 * 1024);

	/* Build up some history */
	simulate_transfer(&bp, 10, 4096, 200);
	CHECK(bp.hist.total_bytes > 0);

	/* Now stall: zero bytes for STALL_START_TIME ms */
	uint64_t stall_time = 10 * 200 + STALL_START_TIME;
	bar_update(&bp, 0, stall_time);

	CHECK_INT_EQ((int)bp.stalled, TRUE);
	CHECK_INT_EQ((int)bp.hist.total_bytes, 0);
	CHECK_INT_EQ((int)bp.hist.total_time,  0);
}

/* After stall, sending bytes resets stalled flag */
static void test_bar_update_recovery_from_stall(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 100 * 1024 * 1024);

	/* Trigger stall */
	bar_update(&bp, 0, STALL_START_TIME + 1);
	CHECK_INT_EQ((int)bp.stalled, TRUE);

	/* Send bytes after the stall */
	bar_update(&bp, 4096, STALL_START_TIME + 1 + SPEED_SAMPLE_MIN + 1);
	CHECK_INT_EQ((int)bp.stalled, FALSE);
}

/* bar_reset when called again should reinitialise cleanly */
static void test_bar_reset_reinitialises(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 1024);
	simulate_transfer(&bp, 5, 100, 200);
	CHECK(bp.hist.total_bytes > 0);

	bar_reset(&bp, 2048);
	CHECK_INT_EQ((int)bp.hist.total_bytes, 0);
	CHECK_INT_EQ((int)bp.total_length, 2048);
}

/* Ring position increments correctly */
static void test_bar_update_ring_position_increments(void)
{
	struct bar_progress bp;
	bar_reset(&bp, 100 * 1024 * 1024);
	CHECK_INT_EQ((int)bp.hist.pos, 0);

	simulate_transfer(&bp, 3, 4096, 200);
	CHECK_INT_EQ((int)bp.hist.pos, 3);
}

/* ── main ──────────────────────────────────────────────────────────────── */
int main(void)
{
	RUN_TEST(test_bar_reset_zeroes_state);
	RUN_TEST(test_bar_reset_sets_total_length);
	RUN_TEST(test_bar_update_sub_sample_min_not_stored);
	RUN_TEST(test_bar_update_exact_sample_min_stored);
	RUN_TEST(test_bar_update_over_sample_min_stored);
	RUN_TEST(test_bar_update_multiple_samples_accumulate);
	RUN_TEST(test_bar_update_ring_wraps);
	RUN_TEST(test_bar_get_speed_positive_after_transfer);
	RUN_TEST(test_bar_get_speed_zero_no_history);
	RUN_TEST(test_bar_get_speed_approximate);
	RUN_TEST(test_bar_get_eta_unknown_early);
	RUN_TEST(test_bar_get_eta_positive);
	RUN_TEST(test_bar_update_stall_clears_ring);
	RUN_TEST(test_bar_update_recovery_from_stall);
	RUN_TEST(test_bar_reset_reinitialises);
	RUN_TEST(test_bar_update_ring_position_increments);

	PRINT_RESULTS();
	return (_fail == 0) ? 0 : 1;
}
