/*
 * test_cregex.c - Unit tests for src/common/cregex
 */

#include "framework.h"
#include "cregex.h"

/* Helper: returns number of matches for pattern against string, or -1 on error */
static int match(const char *pattern, const char *string)
{
    cregex_node_t *node = cregex_parse(pattern);
    if (!node)
        return -1;

    cregex_program_t *prog = cregex_compile_node(node);
    cregex_parse_free(node);
    if (!prog)
        return -1;

    const char *matches[REGEX_VM_MAX_MATCHES * 2];
    int n = cregex_program_run(prog, string, matches, REGEX_VM_MAX_MATCHES);
    cregex_compile_free(prog);
    return n;
}

TEST(test_literal_match)
{
    CHECK(match("hello", "hello") > 0);
    CHECK(match("hello", "world") <= 0);
    CHECK(match("world", "hello world") > 0);
}

TEST(test_anchors)
{
    CHECK(match("^hello", "hello world") > 0);
    CHECK(match("^hello", "say hello") <= 0);
    CHECK(match("world$", "hello world") > 0);
    CHECK(match("world$", "world peace") <= 0);
    CHECK(match("^hello$", "hello") > 0);
    CHECK(match("^hello$", "hello world") <= 0);
}

TEST(test_dot_wildcard)
{
    CHECK(match("h.llo", "hello") > 0);
    CHECK(match("h.llo", "hllo") <= 0);
    CHECK(match(".", "a") > 0);
}

TEST(test_quantifiers)
{
    CHECK(match("ab*c", "ac") > 0);
    CHECK(match("ab*c", "abc") > 0);
    CHECK(match("ab*c", "abbc") > 0);
    CHECK(match("ab+c", "ac") <= 0);
    CHECK(match("ab+c", "abc") > 0);
    CHECK(match("ab?c", "ac") > 0);
    CHECK(match("ab?c", "abc") > 0);
    CHECK(match("ab?c", "abbc") <= 0);
}

TEST(test_character_classes)
{
    CHECK(match("[abc]", "a") > 0);
    CHECK(match("[abc]", "b") > 0);
    CHECK(match("[abc]", "d") <= 0);
    CHECK(match("[a-z]", "m") > 0);
    CHECK(match("[a-z]", "M") <= 0);
    CHECK(match("[^abc]", "d") > 0);
    CHECK(match("[^abc]", "a") <= 0);
}

TEST(test_alternation)
{
    CHECK(match("cat|dog", "cat") > 0);
    CHECK(match("cat|dog", "dog") > 0);
    CHECK(match("cat|dog", "fish") <= 0);
}

TEST(test_captures)
{
    cregex_node_t *node = cregex_parse("(hello)");
    CHECK(node != NULL);
    if (node) {
        cregex_program_t *prog = cregex_compile_node(node);
        cregex_parse_free(node);
        CHECK(prog != NULL);
        if (prog) {
            const char *matches[REGEX_VM_MAX_MATCHES * 2];
            int n = cregex_program_run(prog, "hello world", matches, REGEX_VM_MAX_MATCHES);
            CHECK(n > 0);
            /* matches[0]/[1] = full match; matches[2]/[3] = capture group 1 */
            if (n > 0) {
                CHECK(matches[2] != NULL);
                CHECK(matches[3] != NULL);
                CHECK_INT_EQ((int)(matches[3] - matches[2]), 5); /* "hello" is 5 chars */
            }
            cregex_compile_free(prog);
        }
    }
}

TEST(test_invalid_pattern)
{
    /* Unmatched parenthesis should return NULL or fail gracefully */
    cregex_node_t *node = cregex_parse("(unclosed");
    /* Either NULL is returned or a node with degraded behaviour - just no crash */
    if (node)
        cregex_parse_free(node);
    CHECK(1); /* reached here without crashing = pass */
}

int main(void)
{
    printf("cregex tests\n");
    RUN(test_literal_match);
    RUN(test_anchors);
    RUN(test_dot_wildcard);
    RUN(test_quantifiers);
    RUN(test_character_classes);
    RUN(test_alternation);
    RUN(test_captures);
    RUN(test_invalid_pattern);
    TEST_RESULTS();
}
