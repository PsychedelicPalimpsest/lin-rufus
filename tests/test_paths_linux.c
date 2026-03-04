/*
 * test_paths_linux.c — TDD tests for SUDO_USER-aware settings paths
 *
 * Feature 222: When running as root via 'sudo rufus', settings should be
 * stored in the original user's home directory (from SUDO_USER), not in
 * root's home directory.  This mirrors the Windows UAC behaviour where
 * elevated processes still see the original user's profile.
 *
 * Tests cover rufus_effective_home_impl():
 *  1. SUDO_USER unset + euid!=0 → use HOME env
 *  2. SUDO_USER unset + euid==0  → use HOME env (running as real root, no sudo)
 *  3. SUDO_USER set   + euid!=0  → use HOME env (not root, ignore SUDO_USER)
 *  4. SUDO_USER set   + euid==0  → use real user's home from passwd
 *  5. SUDO_USER set to invalid   → fall back to HOME env
 *  6. SUDO_USER set   + HOME NULL→ fall back to /tmp
 *  7. SUDO_USER=""    + euid==0  → empty SUDO_USER treated as unset, use HOME
 *  8. HOME NULL + no SUDO_USER   → fall back to /tmp
 *  9. HOME==""  + no SUDO_USER   → fall back to /tmp
 * 10. Real passwd lookup for "root" user works (root always has /root)
 */

#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "framework.h"

/* Declare the testable implementation function */
const char *rufus_effective_home_impl(uid_t euid,
                                      const char *sudo_user,
                                      const char *home_env,
                                      char *buf, size_t sz);

/* =========================================================================
 * 1. SUDO_USER not set, non-root → use HOME env
 * =========================================================================*/
TEST(no_sudo_user_nonroot_uses_home_env)
{
    char buf[256];
    const char *result = rufus_effective_home_impl(
        1000, NULL, "/home/testuser", buf, sizeof(buf));
    CHECK_STR_EQ("/home/testuser", result);
    CHECK_STR_EQ("/home/testuser", buf);
}

/* =========================================================================
 * 2. SUDO_USER not set, root → use HOME env (real root, not sudo)
 * =========================================================================*/
TEST(no_sudo_user_root_uses_home_env)
{
    char buf[256];
    const char *result = rufus_effective_home_impl(
        0, NULL, "/root", buf, sizeof(buf));
    CHECK_STR_EQ("/root", result);
    CHECK_STR_EQ("/root", buf);
}

/* =========================================================================
 * 3. SUDO_USER set but not root → HOME env wins (ignore SUDO_USER)
 * =========================================================================*/
TEST(sudo_user_set_nonroot_uses_home_env)
{
    char buf[256];
    const char *result = rufus_effective_home_impl(
        1000, "someuser", "/home/testuser", buf, sizeof(buf));
    CHECK_STR_EQ("/home/testuser", result);
}

/* =========================================================================
 * 4. SUDO_USER set AND root → look up original user's home via getpwnam
 *    Use "root" as the SUDO_USER because /root always exists.
 * =========================================================================*/
TEST(sudo_user_set_root_uses_passwd_home)
{
    char buf[256];
    struct passwd *pw = getpwnam("root");
    if (!pw) {
        printf("  (skip: cannot look up 'root' passwd entry)\n");
        return;
    }
    const char *expected = pw->pw_dir;

    const char *result = rufus_effective_home_impl(
        0, "root", "/home/ignored", buf, sizeof(buf));
    CHECK_STR_EQ(expected, result);
}

/* =========================================================================
 * 5. SUDO_USER set to nonexistent user, root → fall back to HOME env
 * =========================================================================*/
TEST(sudo_user_invalid_falls_back_to_home_env)
{
    char buf[256];
    const char *result = rufus_effective_home_impl(
        0, "xyzzy_nonexistent_user_99999", "/home/fallback", buf, sizeof(buf));
    CHECK_STR_EQ("/home/fallback", result);
}

/* =========================================================================
 * 6. SUDO_USER set, root, HOME is NULL → fall back to /tmp
 * =========================================================================*/
TEST(sudo_user_set_root_home_null_falls_back_to_tmp)
{
    char buf[256];
    /* "xyzzy_nonexistent_user_99999" won't be in passwd, so after failing
     * the passwd lookup we fall back to home_env which is NULL → /tmp */
    const char *result = rufus_effective_home_impl(
        0, "xyzzy_nonexistent_user_99999", NULL, buf, sizeof(buf));
    CHECK_STR_EQ("/tmp", result);
}

/* =========================================================================
 * 7. SUDO_USER="" (empty) + root → treated as unset, use HOME env
 * =========================================================================*/
TEST(sudo_user_empty_root_uses_home_env)
{
    char buf[256];
    const char *result = rufus_effective_home_impl(
        0, "", "/root", buf, sizeof(buf));
    CHECK_STR_EQ("/root", result);
}

/* =========================================================================
 * 8. HOME NULL + no SUDO_USER → fall back to /tmp
 * =========================================================================*/
TEST(home_null_no_sudo_user_returns_tmp)
{
    char buf[256];
    const char *result = rufus_effective_home_impl(
        1000, NULL, NULL, buf, sizeof(buf));
    CHECK_STR_EQ("/tmp", result);
}

/* =========================================================================
 * 9. HOME="" + no SUDO_USER → fall back to /tmp
 * =========================================================================*/
TEST(home_empty_no_sudo_user_returns_tmp)
{
    char buf[256];
    const char *result = rufus_effective_home_impl(
        1000, NULL, "", buf, sizeof(buf));
    CHECK_STR_EQ("/tmp", result);
}

/* =========================================================================
 * 10. Passwd lookup for the current user succeeds and returns a non-empty
 *     directory — validates the getpwnam path in the implementation.
 * =========================================================================*/
TEST(passwd_lookup_current_user_works)
{
    char buf[256];
    /* Get the name of the process owner */
    struct passwd *pw = getpwuid(geteuid());
    if (!pw) {
        printf("  (skip: cannot look up current user)\n");
        return;
    }
    const char *uname = pw->pw_name;
    const char *expected = pw->pw_dir;

    /* Simulate running as root with SUDO_USER = current user name */
    const char *result = rufus_effective_home_impl(
        0, uname, "/home/ignored", buf, sizeof(buf));
    CHECK_STR_EQ(expected, result);
}

/* =========================================================================
 * main
 * =========================================================================*/
int main(void)
{
    printf("=== paths Linux tests (Feature 222: SUDO_USER-aware paths) ===\n");

    RUN(no_sudo_user_nonroot_uses_home_env);
    RUN(no_sudo_user_root_uses_home_env);
    RUN(sudo_user_set_nonroot_uses_home_env);
    RUN(sudo_user_set_root_uses_passwd_home);
    RUN(sudo_user_invalid_falls_back_to_home_env);
    RUN(sudo_user_set_root_home_null_falls_back_to_tmp);
    RUN(sudo_user_empty_root_uses_home_env);
    RUN(home_null_no_sudo_user_returns_tmp);
    RUN(home_empty_no_sudo_user_returns_tmp);
    RUN(passwd_lookup_current_user_works);

    TEST_RESULTS();
    return (_fail > 0) ? 1 : 0;
}

#endif /* __linux__ */
