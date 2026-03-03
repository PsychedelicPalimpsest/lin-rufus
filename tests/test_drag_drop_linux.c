/*
 * test_drag_drop_linux.c — Tests for drag-and-drop URI path extraction.
 *
 * Covers path_from_file_uri() in src/linux/drag_drop.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "framework.h"
#include "../src/linux/drag_drop.h"

/* =========================================================================
 * path_from_file_uri tests
 * ======================================================================= */

TEST(simple_file_uri_stripped)
{
	char *p = path_from_file_uri("file:///tmp/ubuntu.iso");
	CHECK(p != NULL);
	CHECK_STR_EQ(p, "/tmp/ubuntu.iso");
	free(p);
}

TEST(file_uri_with_spaces_decoded)
{
	char *p = path_from_file_uri("file:///home/user/My%20Image.iso");
	CHECK(p != NULL);
	CHECK_STR_EQ(p, "/home/user/My Image.iso");
	free(p);
}

TEST(file_uri_with_multiple_encoded_chars)
{
	char *p = path_from_file_uri("file:///tmp/test%20file%28copy%29.iso");
	CHECK(p != NULL);
	CHECK_STR_EQ(p, "/tmp/test file(copy).iso");
	free(p);
}

TEST(file_uri_trailing_crlf_stripped)
{
	/* Some GTK versions append \r\n to dropped URIs */
	char *p = path_from_file_uri("file:///tmp/test.iso\r\n");
	CHECK(p != NULL);
	CHECK_STR_EQ(p, "/tmp/test.iso");
	free(p);
}

TEST(file_uri_trailing_lf_stripped)
{
	char *p = path_from_file_uri("file:///tmp/test.iso\n");
	CHECK(p != NULL);
	CHECK_STR_EQ(p, "/tmp/test.iso");
	free(p);
}

TEST(file_uri_with_host_stripped)
{
	/* file://hostname/path form — host is dropped */
	char *p = path_from_file_uri("file://localhost/tmp/foo.img");
	CHECK(p != NULL);
	CHECK_STR_EQ(p, "/tmp/foo.img");
	free(p);
}

TEST(file_uri_deep_path)
{
	char *p = path_from_file_uri("file:///home/user/Downloads/rufus-4.6.iso");
	CHECK(p != NULL);
	CHECK_STR_EQ(p, "/home/user/Downloads/rufus-4.6.iso");
	free(p);
}

TEST(null_input_returns_null)
{
	char *p = path_from_file_uri(NULL);
	CHECK(p == NULL);
}

TEST(non_file_scheme_returns_null)
{
	char *p = path_from_file_uri("https://example.com/image.iso");
	CHECK(p == NULL);
}

TEST(empty_string_returns_null)
{
	char *p = path_from_file_uri("");
	CHECK(p == NULL);
}

TEST(file_uri_root_path)
{
	char *p = path_from_file_uri("file:///");
	CHECK(p != NULL);
	CHECK_STR_EQ(p, "/");
	free(p);
}

/* =========================================================================
 * main
 * ======================================================================= */
int main(void)
{
	printf("=== drag_drop tests ===\n");

	RUN(simple_file_uri_stripped);
	RUN(file_uri_with_spaces_decoded);
	RUN(file_uri_with_multiple_encoded_chars);
	RUN(file_uri_trailing_crlf_stripped);
	RUN(file_uri_trailing_lf_stripped);
	RUN(file_uri_with_host_stripped);
	RUN(file_uri_deep_path);
	RUN(null_input_returns_null);
	RUN(non_file_scheme_returns_null);
	RUN(empty_string_returns_null);
	RUN(file_uri_root_path);

	TEST_RESULTS();
	return (_fail > 0) ? 1 : 0;
}
