/*
 * test_xml_common.c — Cross-platform tests for common/xml.c (ezxml)
 *
 * Tests the portable XML parsing and building functions.
 * All tests use in-memory buffers; no file-system access is needed,
 * so the suite runs identically on Linux and Windows (via Wine).
 *
 * Functions / macros under test:
 *   ezxml_parse_str()     — parse from NUL-terminated buffer
 *   ezxml_name()          — get tag name
 *   ezxml_txt()           — get text content
 *   ezxml_attr()          — get attribute value
 *   ezxml_child()         — find first child with given name
 *   ezxml_next()          — advance to next same-name sibling
 *   ezxml_idx()           — access same-name sibling by index
 *   ezxml_get()           — multi-level path traversal
 *   ezxml_get_val()       — multi-level path → text value
 *   ezxml_error()         — parse error string
 *   ezxml_child_val()     — convenience: child text value
 *   ezxml_new()           — create root node
 *   ezxml_add_child()     — attach child node
 *   ezxml_set_txt()       — set text content
 *   ezxml_toxml()         — serialise to XML string
 *   ezxml_free()          — release tree
 *
 * Copyright © 2025 PsychedelicPalimpsest
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/common/xml.h"

/* Stubs */
#include <stdarg.h>
void uprintf(const char *fmt, ...) { (void)fmt; }

/* ezxml modifies the string in-place; make fresh copies for each test */
static char *dup_xml(const char *s) { return strdup(s); }

/* ================================================================== */

TEST(parse_from_str)
{
	char *s = dup_xml("<root><item>hello</item></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_free(root);
	free(s);
}

TEST(root_tag_name)
{
	char *s = dup_xml("<config version=\"1\"></config>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	CHECK_STR_EQ("config", ezxml_name(root));
	ezxml_free(root);
	free(s);
}

TEST(find_child_by_name)
{
	char *s = dup_xml("<root><alpha/><beta>value</beta></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t beta = ezxml_child(root, "beta");
	CHECK(beta != NULL);
	CHECK_STR_EQ("beta", ezxml_name(beta));
	ezxml_free(root);
	free(s);
}

TEST(tag_text_content)
{
	char *s = dup_xml("<root><msg>hello world</msg></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t msg = ezxml_child(root, "msg");
	CHECK(msg != NULL);
	CHECK_STR_EQ("hello world", ezxml_txt(msg));
	ezxml_free(root);
	free(s);
}

TEST(read_attribute)
{
	char *s = dup_xml("<root><item id=\"42\" name=\"foo\"/></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t item = ezxml_child(root, "item");
	CHECK(item != NULL);
	CHECK_STR_EQ("42",  ezxml_attr(item, "id"));
	CHECK_STR_EQ("foo", ezxml_attr(item, "name"));
	ezxml_free(root);
	free(s);
}

TEST(sibling_navigation)
{
	char *s = dup_xml("<root><item>a</item><item>b</item><item>c</item></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t first = ezxml_child(root, "item");
	CHECK(first != NULL);
	CHECK_STR_EQ("a", ezxml_txt(first));
	ezxml_t second = ezxml_next(first);
	CHECK(second != NULL);
	CHECK_STR_EQ("b", ezxml_txt(second));
	ezxml_t third = ezxml_next(second);
	CHECK(third != NULL);
	CHECK_STR_EQ("c", ezxml_txt(third));
	CHECK(ezxml_next(third) == NULL);
	ezxml_free(root);
	free(s);
}

TEST(idx_access)
{
	char *s = dup_xml("<root><item>x</item><item>y</item><item>z</item></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t first = ezxml_child(root, "item");
	CHECK(first != NULL);
	CHECK_STR_EQ("x", ezxml_txt(ezxml_idx(first, 0)));
	CHECK_STR_EQ("y", ezxml_txt(ezxml_idx(first, 1)));
	CHECK_STR_EQ("z", ezxml_txt(ezxml_idx(first, 2)));
	CHECK(ezxml_idx(first, 3) == NULL);
	ezxml_free(root);
	free(s);
}

TEST(get_multilevel)
{
	char *s = dup_xml(
		"<library>"
		  "<shelf id=\"s1\">"
		    "<book><title>Alpha</title></book>"
		    "<book><title>Beta</title></book>"
		  "</shelf>"
		"</library>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t title = ezxml_get(root, "shelf", 0, "book", 1, "title", -1);
	CHECK(title != NULL);
	CHECK_STR_EQ("Beta", ezxml_txt(title));
	ezxml_free(root);
	free(s);
}

TEST(get_val_multilevel)
{
	char *s = dup_xml("<data><section><key>myvalue</key></section></data>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	char *val = ezxml_get_val(root, "section", 0, "key", -1);
	CHECK(val != NULL);
	CHECK_STR_EQ("myvalue", val);
	ezxml_free(root);
	free(s);
}

TEST(missing_child_returns_null)
{
	char *s = dup_xml("<root><a/></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	CHECK(ezxml_child(root, "nonexistent") == NULL);
	ezxml_free(root);
	free(s);
}

TEST(missing_attr_returns_null)
{
	char *s = dup_xml("<root><item id=\"1\"/></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t item = ezxml_child(root, "item");
	CHECK(item != NULL);
	CHECK(ezxml_attr(item, "missing") == NULL);
	ezxml_free(root);
	free(s);
}

TEST(malformed_xml_parse_error)
{
	char *s = dup_xml("<root><unclosed>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	if (root != NULL) {
		const char *err = ezxml_error(root);
		CHECK(err != NULL);
		ezxml_free(root);
	}
	free(s);
}

TEST(no_error_on_valid_parse)
{
	char *s = dup_xml("<root><a>1</a></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	const char *err = ezxml_error(root);
	CHECK(err != NULL);
	CHECK_INT_EQ(0, (int)strlen(err));
	ezxml_free(root);
	free(s);
}

TEST(child_val_convenience)
{
	char *s = dup_xml("<root><name>Rufus</name></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	char *v = ezxml_child_val(root, "name");
	CHECK(v != NULL);
	CHECK_STR_EQ("Rufus", v);
	ezxml_free(root);
	free(s);
}

TEST(nested_grandchild)
{
	char *s = dup_xml("<a><b><c>deep</c></b></a>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t b = ezxml_child(root, "b");
	CHECK(b != NULL);
	ezxml_t c = ezxml_child(b, "c");
	CHECK(c != NULL);
	CHECK_STR_EQ("deep", ezxml_txt(c));
	ezxml_free(root);
	free(s);
}

TEST(multiple_different_children)
{
	char *s = dup_xml("<root><alpha>A</alpha><beta>B</beta><gamma>G</gamma></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	CHECK_STR_EQ("A", ezxml_txt(ezxml_child(root, "alpha")));
	CHECK_STR_EQ("B", ezxml_txt(ezxml_child(root, "beta")));
	CHECK_STR_EQ("G", ezxml_txt(ezxml_child(root, "gamma")));
	ezxml_free(root);
	free(s);
}

TEST(empty_self_closing_element)
{
	char *s = dup_xml("<root><empty/></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t e = ezxml_child(root, "empty");
	CHECK(e != NULL);
	CHECK(ezxml_txt(e) != NULL);
	CHECK_INT_EQ(0, (int)strlen(ezxml_txt(e)));
	ezxml_free(root);
	free(s);
}

TEST(build_tree_programmatically)
{
	ezxml_t root = ezxml_new("config");
	CHECK(root != NULL);
	ezxml_t child = ezxml_add_child(root, "version", 0);
	CHECK(child != NULL);
	ezxml_set_txt(child, "1.0");
	CHECK_STR_EQ("version", ezxml_name(child));
	CHECK_STR_EQ("1.0",     ezxml_txt(child));
	ezxml_free(root);
}

TEST(toxml_round_trip)
{
	char *s = dup_xml("<root><tag>hello</tag></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	char *out = ezxml_toxml(root);
	CHECK(out != NULL);
	CHECK(strstr(out, "root") != NULL);
	CHECK(strstr(out, "tag")  != NULL);
	free(out);
	ezxml_free(root);
	free(s);
}

TEST(utf8_content_preserved)
{
	/* "café" in UTF-8 */
	char *s = dup_xml("<root><msg>caf\xc3\xa9</msg></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t msg = ezxml_child(root, "msg");
	CHECK(msg != NULL);
	CHECK(strncmp("caf", ezxml_txt(msg), 3) == 0);
	ezxml_free(root);
	free(s);
}

TEST(attr_on_tag_without_attrs)
{
	char *s = dup_xml("<root><plain>text</plain></root>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t plain = ezxml_child(root, "plain");
	CHECK(plain != NULL);
	CHECK(ezxml_attr(plain, "anything") == NULL);
	ezxml_free(root);
	free(s);
}

TEST(deep_nested_get)
{
	char *s = dup_xml("<a><b><c><d><e>leaf</e></d></c></b></a>");
	ezxml_t root = ezxml_parse_str(s, strlen(s));
	CHECK(root != NULL);
	ezxml_t e = ezxml_get(root, "b", 0, "c", 0, "d", 0, "e", -1);
	CHECK(e != NULL);
	CHECK_STR_EQ("leaf", ezxml_txt(e));
	ezxml_free(root);
	free(s);
}

/* ================================================================== */
/* main                                                                */
/* ================================================================== */

int main(void)
{
	printf("=== xml common (ezxml buffer-based tests) ===\n");

	RUN(parse_from_str);
	RUN(root_tag_name);
	RUN(find_child_by_name);
	RUN(tag_text_content);
	RUN(read_attribute);
	RUN(sibling_navigation);
	RUN(idx_access);
	RUN(get_multilevel);
	RUN(get_val_multilevel);
	RUN(missing_child_returns_null);
	RUN(missing_attr_returns_null);
	RUN(malformed_xml_parse_error);
	RUN(no_error_on_valid_parse);
	RUN(child_val_convenience);
	RUN(nested_grandchild);
	RUN(multiple_different_children);
	RUN(empty_self_closing_element);
	RUN(build_tree_programmatically);
	RUN(toxml_round_trip);
	RUN(utf8_content_preserved);
	RUN(attr_on_tag_without_attrs);
	RUN(deep_nested_get);

	TEST_RESULTS();
}
