/*
 * test_multidev_linux.c — Unit tests for multi-device write logic
 *
 * Tests the pure-C session management in src/linux/multidev.c.
 * No GTK, no FormatThread — purely the state-machine logic.
 *
 * Build:
 *   gcc -I../src -I../src/linux -I../src/windows \
 *       test_multidev_linux.c ../src/linux/multidev.c \
 *       -o test_multidev_linux
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---- lightweight test harness ---- */
static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT(cond, msg) do {                                  \
	tests_run++;                                                \
	if (cond) {                                                 \
		tests_passed++;                                         \
	} else {                                                    \
		tests_failed++;                                         \
		fprintf(stderr, "FAIL [%s:%d] %s\n",                   \
		        __FILE__, __LINE__, msg);                       \
	}                                                           \
} while (0)

#define ASSERT_EQ(a, b) do {                                    \
	tests_run++;                                                \
	if ((a) == (b)) {                                           \
		tests_passed++;                                         \
	} else {                                                    \
		tests_failed++;                                         \
		fprintf(stderr, "FAIL [%s:%d] expected %lld, got %lld\n",\
		        __FILE__, __LINE__, (long long)(b), (long long)(a));\
	}                                                           \
} while (0)

/* ---- stubs needed by multidev.c ---- */
/* multidev.c is pure logic; it pulls in multidev.h which includes
   rufus.h for BOOL/DWORD.  Provide the minimal definitions. */

/* Include the module under test */
#include "../src/linux/multidev.h"
#include "../src/linux/multidev.c"

/* ======================================================
   TESTS
   ====================================================== */

/* --- init --- */
static void test_init_zeroes_session(void)
{
	multidev_session_t s;
	/* Pre-fill with garbage */
	memset(&s, 0xAB, sizeof(s));
	multidev_init(&s);
	ASSERT_EQ(s.n_targets, 0);
}

static void test_init_null_safe(void)
{
	multidev_init(NULL);   /* must not crash */
	tests_run++;
	tests_passed++;
}

/* --- add_target --- */
static void test_add_single_target(void)
{
	multidev_session_t s;
	multidev_init(&s);
	int idx = multidev_add_target(&s, 1, "Disk1 [8 GB]", 8ULL * 1024 * 1024 * 1024);
	ASSERT_EQ(idx, 0);
	ASSERT_EQ(s.n_targets, 1);
	ASSERT(s.targets[0].DriveIndex == 1, "DriveIndex");
	ASSERT(s.targets[0].size == 8ULL * 1024 * 1024 * 1024, "size");
	ASSERT(s.targets[0].selected == FALSE, "not selected by default");
	ASSERT(s.targets[0].result == MULTIDEV_RESULT_PENDING, "result pending");
}

static void test_add_many_targets(void)
{
	multidev_session_t s;
	multidev_init(&s);
	for (int i = 0; i < MULTIDEV_MAX_TARGETS; i++) {
		char name[32];
		snprintf(name, sizeof(name), "Disk%d", i);
		int idx = multidev_add_target(&s, (DWORD)i, name, (uint64_t)i * 1024 * 1024);
		ASSERT_EQ(idx, i);
	}
	ASSERT_EQ(s.n_targets, MULTIDEV_MAX_TARGETS);
}

static void test_add_target_overflow(void)
{
	multidev_session_t s;
	multidev_init(&s);
	for (int i = 0; i < MULTIDEV_MAX_TARGETS; i++)
		multidev_add_target(&s, (DWORD)i, "x", 512);
	/* One extra should fail */
	int idx = multidev_add_target(&s, 99, "overflow", 512);
	ASSERT_EQ(idx, -1);
	ASSERT_EQ(s.n_targets, MULTIDEV_MAX_TARGETS);
}

static void test_add_target_null_name(void)
{
	multidev_session_t s;
	multidev_init(&s);
	int idx = multidev_add_target(&s, 2, NULL, 1024);
	ASSERT_EQ(idx, 0);
	ASSERT(s.targets[0].name[0] == '\0', "empty name");
}

/* --- set_selected / count_selected --- */
static void test_select_deselect(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	multidev_add_target(&s, 1, "D1", 512);

	ASSERT_EQ(multidev_count_selected(&s), 0);

	multidev_set_selected(&s, 0, TRUE);
	ASSERT_EQ(multidev_count_selected(&s), 1);

	multidev_set_selected(&s, 1, TRUE);
	ASSERT_EQ(multidev_count_selected(&s), 2);

	multidev_set_selected(&s, 0, FALSE);
	ASSERT_EQ(multidev_count_selected(&s), 1);
}

static void test_select_out_of_range(void)
{
	multidev_session_t s;
	multidev_init(&s);
	int rc = multidev_set_selected(&s, 0, TRUE);  /* no targets yet */
	ASSERT_EQ(rc, -1);
}

static void test_select_negative_idx(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	int rc = multidev_set_selected(&s, -1, TRUE);
	ASSERT_EQ(rc, -1);
}

static void test_count_selected_empty(void)
{
	multidev_session_t s;
	multidev_init(&s);
	ASSERT_EQ(multidev_count_selected(&s), 0);
}

static void test_count_selected_null(void)
{
	ASSERT_EQ(multidev_count_selected(NULL), 0);
}

/* --- set_progress --- */
static void test_set_progress_normal(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	int rc = multidev_set_progress(&s, 0, 42.5f);
	ASSERT_EQ(rc, 0);
	ASSERT(s.targets[0].progress == 42.5f, "progress value");
}

static void test_set_progress_out_of_range(void)
{
	multidev_session_t s;
	multidev_init(&s);
	int rc = multidev_set_progress(&s, 0, 50.0f);
	ASSERT_EQ(rc, -1);
}

/* --- set_result --- */
static void test_set_result_success(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	multidev_set_result(&s, 0, MULTIDEV_RESULT_SUCCESS);
	ASSERT_EQ(s.targets[0].result, MULTIDEV_RESULT_SUCCESS);
}

static void test_set_result_failure(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	multidev_set_result(&s, 0, MULTIDEV_RESULT_FAILURE);
	ASSERT_EQ(s.targets[0].result, MULTIDEV_RESULT_FAILURE);
}

static void test_set_result_out_of_range(void)
{
	multidev_session_t s;
	multidev_init(&s);
	int rc = multidev_set_result(&s, 5, MULTIDEV_RESULT_SUCCESS);
	ASSERT_EQ(rc, -1);
}

/* --- all_done --- */
static void test_all_done_no_selected(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	/* target not selected */
	ASSERT(multidev_all_done(&s) == FALSE, "no selected targets → false");
}

static void test_all_done_one_pending(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	multidev_set_selected(&s, 0, TRUE);
	ASSERT(multidev_all_done(&s) == FALSE, "still pending");
}

static void test_all_done_one_success(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	multidev_set_selected(&s, 0, TRUE);
	multidev_set_result(&s, 0, MULTIDEV_RESULT_SUCCESS);
	ASSERT(multidev_all_done(&s) == TRUE, "done after success");
}

static void test_all_done_one_failure(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	multidev_set_selected(&s, 0, TRUE);
	multidev_set_result(&s, 0, MULTIDEV_RESULT_FAILURE);
	ASSERT(multidev_all_done(&s) == TRUE, "done after failure");
}

static void test_all_done_mixed_one_pending(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	multidev_add_target(&s, 1, "D1", 512);
	multidev_set_selected(&s, 0, TRUE);
	multidev_set_selected(&s, 1, TRUE);
	multidev_set_result(&s, 0, MULTIDEV_RESULT_SUCCESS);
	/* D1 still pending */
	ASSERT(multidev_all_done(&s) == FALSE, "one pending → not done");
}

static void test_all_done_mixed_all_done(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	multidev_add_target(&s, 1, "D1", 512);
	multidev_set_selected(&s, 0, TRUE);
	multidev_set_selected(&s, 1, TRUE);
	multidev_set_result(&s, 0, MULTIDEV_RESULT_SUCCESS);
	multidev_set_result(&s, 1, MULTIDEV_RESULT_FAILURE);
	ASSERT(multidev_all_done(&s) == TRUE, "all done");
}

static void test_all_done_unselected_not_counted(void)
{
	/* An unselected target with PENDING result should not affect done-ness */
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);  /* selected, success */
	multidev_add_target(&s, 1, "D1", 512);  /* not selected, pending */
	multidev_set_selected(&s, 0, TRUE);
	multidev_set_result(&s, 0, MULTIDEV_RESULT_SUCCESS);
	ASSERT(multidev_all_done(&s) == TRUE, "unselected target ignored");
}

static void test_all_done_null(void)
{
	ASSERT(multidev_all_done(NULL) == FALSE, "null session → false");
}

/* --- count_success / count_failure --- */
static void test_count_success_empty(void)
{
	multidev_session_t s;
	multidev_init(&s);
	ASSERT_EQ(multidev_count_success(&s), 0);
}

static void test_count_success_one(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);
	multidev_add_target(&s, 1, "D1", 512);
	multidev_set_selected(&s, 0, TRUE);
	multidev_set_selected(&s, 1, TRUE);
	multidev_set_result(&s, 0, MULTIDEV_RESULT_SUCCESS);
	multidev_set_result(&s, 1, MULTIDEV_RESULT_FAILURE);
	ASSERT_EQ(multidev_count_success(&s), 1);
	ASSERT_EQ(multidev_count_failure(&s), 1);
}

static void test_count_success_only_selected_counted(void)
{
	multidev_session_t s;
	multidev_init(&s);
	multidev_add_target(&s, 0, "D0", 512);  /* selected success */
	multidev_add_target(&s, 1, "D1", 512);  /* not selected success */
	multidev_set_selected(&s, 0, TRUE);
	multidev_set_result(&s, 0, MULTIDEV_RESULT_SUCCESS);
	multidev_set_result(&s, 1, MULTIDEV_RESULT_SUCCESS);
	ASSERT_EQ(multidev_count_success(&s), 1);  /* only selected counted */
}

static void test_count_null(void)
{
	ASSERT_EQ(multidev_count_success(NULL), 0);
	ASSERT_EQ(multidev_count_failure(NULL), 0);
}

/* --- name boundary --- */
static void test_name_truncation(void)
{
	multidev_session_t s;
	multidev_init(&s);
	char long_name[512];
	memset(long_name, 'A', 511);
	long_name[511] = '\0';
	multidev_add_target(&s, 0, long_name, 512);
	/* Must be nul-terminated and ≤ 255 chars */
	ASSERT(s.targets[0].name[255] == '\0', "name nul-terminated");
}

/* ======================================================
   MAIN
   ====================================================== */
int main(void)
{
	printf("=== test_multidev_linux ===\n");

	test_init_zeroes_session();
	test_init_null_safe();
	test_add_single_target();
	test_add_many_targets();
	test_add_target_overflow();
	test_add_target_null_name();
	test_select_deselect();
	test_select_out_of_range();
	test_select_negative_idx();
	test_count_selected_empty();
	test_count_selected_null();
	test_set_progress_normal();
	test_set_progress_out_of_range();
	test_set_result_success();
	test_set_result_failure();
	test_set_result_out_of_range();
	test_all_done_no_selected();
	test_all_done_one_pending();
	test_all_done_one_success();
	test_all_done_one_failure();
	test_all_done_mixed_one_pending();
	test_all_done_mixed_all_done();
	test_all_done_unselected_not_counted();
	test_all_done_null();
	test_count_success_empty();
	test_count_success_one();
	test_count_success_only_selected_counted();
	test_count_null();
	test_name_truncation();

	printf("Results: %d/%d passed", tests_passed, tests_run);
	if (tests_failed)
		printf(" (%d FAILED)", tests_failed);
	printf("\n");

	return tests_failed ? 1 : 0;
}
