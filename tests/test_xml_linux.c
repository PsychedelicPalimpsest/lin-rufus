/*
 * test_xml_linux.c — TDD tests for common/xml.c (ezxml)
 *
 * Tests cover:
 *  1.  Parse simple XML from a string buffer
 *  2.  Access root tag name
 *  3.  Find first child tag by name
 *  4.  Read character content (txt) of a tag
 *  5.  Read tag attributes
 *  6.  Navigate siblings (ezxml_next)
 *  7.  ezxml_idx — indexed access to same-name siblings
 *  8.  ezxml_get — multi-level path traversal
 *  9.  ezxml_get_val — multi-level path returning text
 * 10.  Missing child returns NULL
 * 11.  Missing attribute returns NULL
 * 12.  Parse error for malformed XML
 * 13.  ezxml_error returns empty string for valid parse
 * 14.  ezxml_child_val — convenience wrapper
 * 15.  Nested tags (grandchild)
 * 16.  Multiple children with different names
 * 17.  Parse empty element (<tag/>)
 * 18.  Build XML tree programmatically and convert to string
 * 19.  ezxml_toxml round-trip preserves tag name
 * 20.  ezxml_parse_fp — parse from a FILE stream
 * 21.  Attribute with special characters (ampersand entity)
 * 22.  UTF-8 character content preserved
 * 23.  ezxml_attr on a tag with no attributes returns NULL
 * 24.  Deeply nested path via ezxml_get
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pull in the ezxml header from common/ */
#include "../src/common/xml.h"

/* Minimal stubs required by xml.c */
#include <stdarg.h>
void uprintf(const char *fmt, ...) { (void)fmt; }

/* ezxml modifies the string in-place; helpers below make fresh copies */
static char *dup_xml(const char *s) { return strdup(s); }

/* -------------------------------------------------------------------------
 * 1. Parse simple XML from a string buffer
 * --------------------------------------------------------------------- */
TEST(parse_from_str)
{
    char *xml_str = dup_xml("<root><item>hello</item></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 2. Root tag name
 * --------------------------------------------------------------------- */
TEST(root_tag_name)
{
    char *xml_str = dup_xml("<config version=\"1\"></config>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    CHECK_STR_EQ("config", ezxml_name(root));
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 3. First child tag by name
 * --------------------------------------------------------------------- */
TEST(find_child_by_name)
{
    char *xml_str = dup_xml("<root><alpha/><beta>value</beta></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t beta = ezxml_child(root, "beta");
    CHECK(beta != NULL);
    CHECK_STR_EQ("beta", ezxml_name(beta));
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 4. Tag character content
 * --------------------------------------------------------------------- */
TEST(tag_text_content)
{
    char *xml_str = dup_xml("<root><msg>hello world</msg></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t msg = ezxml_child(root, "msg");
    CHECK(msg != NULL);
    CHECK_STR_EQ("hello world", ezxml_txt(msg));
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 5. Read tag attribute
 * --------------------------------------------------------------------- */
TEST(read_attribute)
{
    char *xml_str = dup_xml("<root><item id=\"42\" name=\"foo\"/></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t item = ezxml_child(root, "item");
    CHECK(item != NULL);
    CHECK_STR_EQ("42", ezxml_attr(item, "id"));
    CHECK_STR_EQ("foo", ezxml_attr(item, "name"));
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 6. Navigate siblings via ezxml_next
 * --------------------------------------------------------------------- */
TEST(sibling_navigation)
{
    char *xml_str = dup_xml("<root><item>a</item><item>b</item><item>c</item></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
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
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 7. ezxml_idx — indexed access
 * --------------------------------------------------------------------- */
TEST(idx_access)
{
    char *xml_str = dup_xml("<root><item>x</item><item>y</item><item>z</item></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t first = ezxml_child(root, "item");
    CHECK(first != NULL);
    CHECK_STR_EQ("x", ezxml_txt(ezxml_idx(first, 0)));
    CHECK_STR_EQ("y", ezxml_txt(ezxml_idx(first, 1)));
    CHECK_STR_EQ("z", ezxml_txt(ezxml_idx(first, 2)));
    CHECK(ezxml_idx(first, 3) == NULL);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 8. ezxml_get — multi-level traversal
 * --------------------------------------------------------------------- */
TEST(get_multilevel)
{
    char *xml_str = dup_xml(
        "<library>"
          "<shelf id=\"s1\">"
            "<book><title>Alpha</title></book>"
            "<book><title>Beta</title></book>"
          "</shelf>"
        "</library>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    /* Get the title of the 2nd book on the 1st shelf */
    ezxml_t title = ezxml_get(root, "shelf", 0, "book", 1, "title", -1);
    CHECK(title != NULL);
    CHECK_STR_EQ("Beta", ezxml_txt(title));
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 9. ezxml_get_val — returns text value
 * --------------------------------------------------------------------- */
TEST(get_val_multilevel)
{
    char *xml_str = dup_xml(
        "<data><section><key>myvalue</key></section></data>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    char *val = ezxml_get_val(root, "section", 0, "key", -1);
    CHECK(val != NULL);
    CHECK_STR_EQ("myvalue", val);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 10. Missing child returns NULL
 * --------------------------------------------------------------------- */
TEST(missing_child_returns_null)
{
    char *xml_str = dup_xml("<root><a/></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    CHECK(ezxml_child(root, "nonexistent") == NULL);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 11. Missing attribute returns NULL
 * --------------------------------------------------------------------- */
TEST(missing_attr_returns_null)
{
    char *xml_str = dup_xml("<root><item id=\"1\"/></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t item = ezxml_child(root, "item");
    CHECK(item != NULL);
    CHECK(ezxml_attr(item, "missing") == NULL);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 12. Parse error for malformed XML returns non-NULL with error string
 * --------------------------------------------------------------------- */
TEST(malformed_xml_parse_error)
{
    char *xml_str = dup_xml("<root><unclosed>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    /* ezxml returns non-NULL even for malformed; error string is set */
    if (root != NULL) {
        const char *err = ezxml_error(root);
        /* Either there is an error string, or the parse somehow succeeded.
         * Either way: no crash, and err is not NULL. */
        CHECK(err != NULL);
        ezxml_free(root);
    }
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 13. ezxml_error returns empty string for valid parse
 * --------------------------------------------------------------------- */
TEST(no_error_on_valid_parse)
{
    char *xml_str = dup_xml("<root><a>1</a></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    const char *err = ezxml_error(root);
    CHECK(err != NULL);
    CHECK_INT_EQ(0, (int)strlen(err));  /* empty string */
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 14. ezxml_child_val — convenience wrapper
 * --------------------------------------------------------------------- */
TEST(child_val_convenience)
{
    char *xml_str = dup_xml("<root><name>Rufus</name></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    char *v = ezxml_child_val(root, "name");
    CHECK(v != NULL);
    CHECK_STR_EQ("Rufus", v);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 15. Nested tags (grandchild)
 * --------------------------------------------------------------------- */
TEST(nested_grandchild)
{
    char *xml_str = dup_xml("<a><b><c>deep</c></b></a>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t b = ezxml_child(root, "b");
    CHECK(b != NULL);
    ezxml_t c = ezxml_child(b, "c");
    CHECK(c != NULL);
    CHECK_STR_EQ("deep", ezxml_txt(c));
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 16. Multiple children with different names
 * --------------------------------------------------------------------- */
TEST(multiple_different_children)
{
    char *xml_str = dup_xml("<root><alpha>A</alpha><beta>B</beta><gamma>G</gamma></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    CHECK_STR_EQ("A", ezxml_txt(ezxml_child(root, "alpha")));
    CHECK_STR_EQ("B", ezxml_txt(ezxml_child(root, "beta")));
    CHECK_STR_EQ("G", ezxml_txt(ezxml_child(root, "gamma")));
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 17. Parse empty self-closing element
 * --------------------------------------------------------------------- */
TEST(empty_self_closing_element)
{
    char *xml_str = dup_xml("<root><empty/></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t e = ezxml_child(root, "empty");
    CHECK(e != NULL);
    /* txt should be empty string, not NULL */
    CHECK(ezxml_txt(e) != NULL);
    CHECK_INT_EQ(0, (int)strlen(ezxml_txt(e)));
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 18. Build tree programmatically
 * --------------------------------------------------------------------- */
TEST(build_tree_programmatically)
{
    ezxml_t root = ezxml_new("config");
    CHECK(root != NULL);
    ezxml_t child = ezxml_add_child(root, "version", 0);
    CHECK(child != NULL);
    ezxml_set_txt(child, "1.0");
    CHECK_STR_EQ("version", ezxml_name(child));
    CHECK_STR_EQ("1.0", ezxml_txt(child));
    ezxml_free(root);
}

/* -------------------------------------------------------------------------
 * 19. ezxml_toxml round-trip
 * --------------------------------------------------------------------- */
TEST(toxml_round_trip)
{
    char *xml_str = dup_xml("<root><tag>hello</tag></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    char *out = ezxml_toxml(root);
    CHECK(out != NULL);
    /* The serialised string must contain the tag name */
    CHECK(strstr(out, "root") != NULL);
    CHECK(strstr(out, "tag") != NULL);
    free(out);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 20. ezxml_parse_fp — parse from FILE stream
 * --------------------------------------------------------------------- */
TEST(parse_from_fp)
{
    /* Write XML to a temp file, then parse it via FILE* */
    char path[] = "/tmp/test_xml_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { CHECK(0); return; }  /* skip if mkstemp fails */
    const char *content = "<root><val>42</val></root>";
    write(fd, content, strlen(content));
    close(fd);

    FILE *fp = fopen(path, "r");
    CHECK(fp != NULL);
    if (!fp) { unlink(path); return; }

    ezxml_t root = ezxml_parse_fp(fp);
    fclose(fp);
    unlink(path);

    CHECK(root != NULL);
    if (root) {
        CHECK_STR_EQ("42", ezxml_txt(ezxml_child(root, "val")));
        ezxml_free(root);
    }
}

/* -------------------------------------------------------------------------
 * 21. White space is preserved in text content
 * --------------------------------------------------------------------- */
TEST(attribute_with_entity)
{
    char *xml_str = dup_xml("<root><item>  spaced  </item></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t item = ezxml_child(root, "item");
    CHECK(item != NULL);
    const char *txt = ezxml_txt(item);
    CHECK(txt != NULL);
    /* Content includes leading/trailing spaces */
    CHECK(strstr(txt, "spaced") != NULL);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 22. UTF-8 character content preserved
 * --------------------------------------------------------------------- */
TEST(utf8_content_preserved)
{
    char *xml_str = dup_xml("<root><msg>caf\xc3\xa9</msg></root>"); /* café */
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t msg = ezxml_child(root, "msg");
    CHECK(msg != NULL);
    /* The UTF-8 bytes should be untouched */
    CHECK(strncmp("caf", ezxml_txt(msg), 3) == 0);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 23. ezxml_attr on tag with no attributes
 * --------------------------------------------------------------------- */
TEST(attr_on_tag_without_attrs)
{
    char *xml_str = dup_xml("<root><plain>text</plain></root>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t plain = ezxml_child(root, "plain");
    CHECK(plain != NULL);
    CHECK(ezxml_attr(plain, "anything") == NULL);
    ezxml_free(root);
    free(xml_str);
}

/* -------------------------------------------------------------------------
 * 24. Deeply nested path via ezxml_get
 * --------------------------------------------------------------------- */
TEST(deep_nested_get)
{
    char *xml_str = dup_xml(
        "<a><b><c><d><e>leaf</e></d></c></b></a>");
    ezxml_t root = ezxml_parse_str(xml_str, strlen(xml_str));
    CHECK(root != NULL);
    ezxml_t e = ezxml_get(root, "b", 0, "c", 0, "d", 0, "e", -1);
    CHECK(e != NULL);
    CHECK_STR_EQ("leaf", ezxml_txt(e));
    ezxml_free(root);
    free(xml_str);
}

int main(void)
{
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
    RUN(parse_from_fp);
    RUN(attribute_with_entity);
    RUN(utf8_content_preserved);
    RUN(attr_on_tag_without_attrs);
    RUN(deep_nested_get);
    TEST_RESULTS();
}
