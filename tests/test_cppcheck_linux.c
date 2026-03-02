/*
 * test_cppcheck_linux.c — Tests for cppcheck static analysis integration.
 *
 * Verifies that:
 *  - cppcheck is installed and available
 *  - the suppressions file exists and is well-formed
 *  - cppcheck finds no errors/warnings in the Linux and common source
 *  - the shift-by-negative UB in ui_combo_logic.c is resolved
 *  - the make target definition is correct
 *
 * Copyright © 2025 Rufus contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

/* -------------------------------------------------------------------------
 * Path helpers
 * --------------------------------------------------------------------- */

/* Try repo root then ../  relative to tests/ */
static int find_repo_root(char *out, size_t sz)
{
	struct stat st;
	/* Are we in the repo root already? */
	if (stat("src/linux", &st) == 0 && S_ISDIR(st.st_mode)) {
		snprintf(out, sz, ".");
		return 1;
	}
	/* One level up (running from tests/) */
	if (stat("../src/linux", &st) == 0 && S_ISDIR(st.st_mode)) {
		snprintf(out, sz, "..");
		return 1;
	}
	return 0;
}

/* =========================================================================
 * Tests
 * ======================================================================= */

/* cppcheck must be available on PATH */
TEST(cppcheck_is_installed)
{
	int rc = system("command -v cppcheck >/dev/null 2>&1");
	CHECK_INT_EQ(rc, 0);
}

/* The suppressions file must exist and be non-empty */
TEST(cppcheck_suppress_file_exists)
{
	char root[256];
	char path[512];
	if (!find_repo_root(root, sizeof(root))) return;

	snprintf(path, sizeof(path), "%s/cppcheck.suppress", root);

	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	if (!f) return;

	/* Must have at least one real suppression line */
	char line[256];
	int has_suppression = 0;
	while (fgets(line, sizeof(line), f)) {
		/* Skip blank lines and comments */
		char *p = line;
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '\0' || *p == '\n' || *p == '#' || (p[0] == '/' && p[1] == '/'))
			continue;
		has_suppression = 1;
		break;
	}
	fclose(f);
	CHECK(has_suppression);
}

/* The suppressions file must list nullPointerRedundantCheck for rufus.h */
TEST(cppcheck_suppress_contains_null_ptr_check)
{
	char root[256];
	char path[512];
	if (!find_repo_root(root, sizeof(root))) return;
	snprintf(path, sizeof(path), "%s/cppcheck.suppress", root);

	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	if (!f) return;

	char buf[65536];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	CHECK(strstr(buf, "nullPointerRedundantCheck") != NULL);
}

/* The suppressions file must suppress literalWithCharPtrCompare for iso_check.c */
TEST(cppcheck_suppress_contains_literal_cmp)
{
	char root[256];
	char path[512];
	if (!find_repo_root(root, sizeof(root))) return;
	snprintf(path, sizeof(path), "%s/cppcheck.suppress", root);

	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	if (!f) return;

	char buf[65536];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	CHECK(strstr(buf, "literalWithCharPtrCompare") != NULL);
}

/* The Makefile.am must define a check-cppcheck target */
TEST(makefile_am_has_cppcheck_target)
{
	char root[256];
	char path[512];
	if (!find_repo_root(root, sizeof(root))) return;
	snprintf(path, sizeof(path), "%s/Makefile.am", root);

	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	if (!f) return;

	char buf[65536];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	CHECK(strstr(buf, "check-cppcheck") != NULL);
	CHECK(strstr(buf, "cppcheck") != NULL);
	CHECK(strstr(buf, "--error-exitcode") != NULL);
}

/* The Makefile.am target must suppress missingIncludeSystem */
TEST(makefile_am_suppresses_missing_include)
{
	char root[256];
	char path[512];
	if (!find_repo_root(root, sizeof(root))) return;
	snprintf(path, sizeof(path), "%s/Makefile.am", root);

	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	if (!f) return;

	char buf[65536];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	CHECK(strstr(buf, "missingIncludeSystem") != NULL);
}

/* cppcheck must pass (exit 0) on the linux and common source with our suppressions */
TEST(cppcheck_passes_on_linux_source)
{
	char root[256];
	char abs_root[PATH_MAX];
	char cmd[2048];
	if (!find_repo_root(root, sizeof(root))) return;

	/* Resolve to absolute path so we can cd to it */
	if (!realpath(root, abs_root))
		snprintf(abs_root, sizeof(abs_root), "%s", root);

	/*
	 * Run cppcheck from the repo root so that relative paths in
	 * cppcheck.suppress (e.g. "src/linux/foo.c") match what cppcheck
	 * reports.  The command mirrors the Makefile check-cppcheck target.
	 */
	snprintf(cmd, sizeof(cmd),
		"cd '%s' && cppcheck --enable=warning,performance"
		" --suppress=missingIncludeSystem"
		" --suppress=normalCheckLevelMaxBranches"
		" --suppressions-list=cppcheck.suppress"
		" --error-exitcode=1"
		" -I src/linux -I src/linux/compat"
		" -I src/windows -I src/common"
		" -D__linux__"
		" src/linux/*.c src/common/*.c"
		" >/dev/null 2>&1",
		abs_root);

	int rc = system(cmd);
	CHECK_INT_EQ(rc, 0);
}

/* The ui_combo_logic.c must not have shiftNegative — verify by checking the
 * condition guards the shift correctly (preselected_fs >= 0 check present) */
TEST(ui_combo_logic_no_shift_negative)
{
	char root[256];
	char path[512];
	if (!find_repo_root(root, sizeof(root))) return;
	snprintf(path, sizeof(path), "%s/src/linux/ui_combo_logic.c", root);

	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	if (!f) return;

	char buf[1 << 20];  /* 1 MiB should be enough */
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	/* The guard must be >= 0 (not just != FS_UNKNOWN) */
	CHECK(strstr(buf, "preselected_fs >= 0") != NULL);
}

/* set_preselected_fs() must be declared in the public header */
TEST(set_preselected_fs_declared_in_header)
{
	char root[256];
	char path[512];
	if (!find_repo_root(root, sizeof(root))) return;
	snprintf(path, sizeof(path), "%s/src/linux/ui_combo_logic.h", root);

	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	if (!f) return;

	char buf[65536];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	CHECK(strstr(buf, "set_preselected_fs") != NULL);
}

/* cli_apply_options() must call set_preselected_fs() when opts->fs is valid */
TEST(cli_apply_calls_set_preselected_fs)
{
	char root[256];
	char path[512];
	if (!find_repo_root(root, sizeof(root))) return;
	snprintf(path, sizeof(path), "%s/src/linux/cli.c", root);

	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	if (!f) return;

	char buf[1 << 18];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	CHECK(strstr(buf, "set_preselected_fs") != NULL);
}

/* =========================================================================
 * main
 * ======================================================================= */
int main(void)
{
	printf("=== cppcheck integration tests ===\n");

	RUN(cppcheck_is_installed);
	RUN(cppcheck_suppress_file_exists);
	RUN(cppcheck_suppress_contains_null_ptr_check);
	RUN(cppcheck_suppress_contains_literal_cmp);
	RUN(makefile_am_has_cppcheck_target);
	RUN(makefile_am_suppresses_missing_include);
	RUN(cppcheck_passes_on_linux_source);
	RUN(ui_combo_logic_no_shift_negative);
	RUN(set_preselected_fs_declared_in_header);
	RUN(cli_apply_calls_set_preselected_fs);

	TEST_RESULTS();
	return (_fail > 0) ? 1 : 0;
}
