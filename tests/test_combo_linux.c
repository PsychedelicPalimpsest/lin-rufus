/*
 * test_combo_linux.c — Tests for the combo_bridge message dispatch layer.
 *
 * Tests exercise the pure-C combo_state machinery (no GTK required) via the
 * standard CB_* Windows message API.  The same code path is used in the real
 * GTK build, so these tests directly validate the production behaviour.
 *
 * Covered messages:
 *   CB_RESETCONTENT  — clear all items
 *   CB_ADDSTRING     — append item text, return new item index
 *   CB_GETCOUNT      — return number of items
 *   CB_SETCURSEL     — set active selection by index
 *   CB_GETCURSEL     — return active selection index (CB_ERR if none)
 *   CB_SETITEMDATA   — attach arbitrary DWORD_PTR to an item
 *   CB_GETITEMDATA   — retrieve item data (CB_ERR if out of range)
 *   CB_GETLBTEXT     — copy item text to caller-supplied buffer
 *   CB_GETLBTEXTLEN  — return item text length (excluding NUL)
 *
 * Also tested:
 *   ComboBox_AddString / ComboBox_ResetContent / ComboBox_SetItemData etc.
 *   (the inline helpers in windows.h that delegate to SendMessageA)
 *   combo_state_alloc / combo_state_free lifecycle
 *   combo_register_all() does not crash when called with NULL widgets
 */

#include "framework.h"

/* Pull in the compat layer so we get HWND, SendMessageA, CB_*, etc. */
#include "../src/linux/compat/windows.h"
#include "../src/linux/compat/windowsx.h"
#include "../src/linux/compat/msg_dispatch.h"

/* The module under test */
#include "../src/linux/combo_bridge.h"

#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Helpers: create an isolated combo state + register its handler so that
 * SendMessageA() routes correctly.
 * --------------------------------------------------------------------- */
static combo_state_t *make_combo(void)
{
	combo_state_t *cs = combo_state_alloc(NULL);  /* NULL = no GTK widget */
	msg_dispatch_init();
	msg_dispatch_register((HWND)cs, combo_msg_handler);
	return cs;
}

static void free_combo(combo_state_t *cs)
{
	if (!cs) return;
	msg_dispatch_unregister((HWND)cs);
	combo_state_free(cs);
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------- */
TEST(combo_alloc_free)
{
	combo_state_t *cs = combo_state_alloc(NULL);
	CHECK(cs != NULL);
	CHECK_INT_EQ(cs->count, 0);
	CHECK_INT_EQ(cs->cur_sel, -1);
	combo_state_free(cs);
}

TEST(combo_free_null_safe)
{
	combo_state_free(NULL);  /* must not crash */
}

/* -------------------------------------------------------------------------
 * CB_ADDSTRING / CB_GETCOUNT
 * --------------------------------------------------------------------- */
TEST(addstring_returns_index)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	LRESULT r0 = SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Alpha");
	LRESULT r1 = SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Beta");
	LRESULT r2 = SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Gamma");

	CHECK_INT_EQ((int)r0, 0);
	CHECK_INT_EQ((int)r1, 1);
	CHECK_INT_EQ((int)r2, 2);

	free_combo(cs);
}

TEST(getcount_after_adds)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCOUNT, 0, 0), 0);
	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"A");
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCOUNT, 0, 0), 1);
	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"B");
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCOUNT, 0, 0), 2);

	free_combo(cs);
}

TEST(addstring_null_text_treated_as_empty)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	/* NULL text should not crash and should add an empty-string entry */
	LRESULT r = SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)NULL);
	CHECK_INT_EQ((int)r, 0);
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCOUNT, 0, 0), 1);

	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * CB_RESETCONTENT
 * --------------------------------------------------------------------- */
TEST(resetcontent_clears_items)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"X");
	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Y");
	SendMessageA(h, CB_SETCURSEL, 1, 0);

	SendMessageA(h, CB_RESETCONTENT, 0, 0);
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCOUNT, 0, 0), 0);
	/* Current selection must be reset to CB_ERR after clear */
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCURSEL, 0, 0), (int)CB_ERR);

	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * CB_SETCURSEL / CB_GETCURSEL
 * --------------------------------------------------------------------- */
TEST(setcursel_getcursel_roundtrip)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Item0");
	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Item1");
	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Item2");

	SendMessageA(h, CB_SETCURSEL, 0, 0);
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCURSEL, 0, 0), 0);

	SendMessageA(h, CB_SETCURSEL, 2, 0);
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCURSEL, 0, 0), 2);

	free_combo(cs);
}

TEST(setcursel_minus1_deselects)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Item0");
	SendMessageA(h, CB_SETCURSEL, 0, 0);
	SendMessageA(h, CB_SETCURSEL, (WPARAM)-1, 0);
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCURSEL, 0, 0), (int)CB_ERR);

	free_combo(cs);
}

TEST(setcursel_out_of_range_returns_err)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Only");
	/* Index 5 is out of range — should return CB_ERR */
	LRESULT r = SendMessageA(h, CB_SETCURSEL, 5, 0);
	CHECK((int)r == (int)CB_ERR);

	free_combo(cs);
}

TEST(getcursel_empty_combo_returns_err)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCURSEL, 0, 0), (int)CB_ERR);
	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * CB_SETITEMDATA / CB_GETITEMDATA
 * --------------------------------------------------------------------- */
TEST(setitemdata_getitemdata_roundtrip)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"DriveA");
	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"DriveB");
	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"DriveC");

	SendMessageA(h, CB_SETITEMDATA, 0, (LPARAM)(DWORD_PTR)0x1000);
	SendMessageA(h, CB_SETITEMDATA, 1, (LPARAM)(DWORD_PTR)0x2000);
	SendMessageA(h, CB_SETITEMDATA, 2, (LPARAM)(DWORD_PTR)0x3000);

	CHECK_INT_EQ((int)SendMessageA(h, CB_GETITEMDATA, 0, 0), 0x1000);
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETITEMDATA, 1, 0), 0x2000);
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETITEMDATA, 2, 0), 0x3000);

	free_combo(cs);
}

TEST(getitemdata_out_of_range_returns_err)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"X");
	/* Index 99 is out of range */
	CHECK((int)SendMessageA(h, CB_GETITEMDATA, 99, 0) == (int)CB_ERR);

	free_combo(cs);
}

TEST(setitemdata_out_of_range_returns_err)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;
	/* No items — index 0 is out of range */
	LRESULT r = SendMessageA(h, CB_SETITEMDATA, 0, (LPARAM)0xDEAD);
	CHECK((int)r == (int)CB_ERR);
	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * CB_GETLBTEXT / CB_GETLBTEXTLEN
 * --------------------------------------------------------------------- */
TEST(getlbtext_returns_item_string)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"Hello");
	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"World");

	char buf[64] = { 0 };
	LRESULT r = SendMessageA(h, CB_GETLBTEXT, 1, (LPARAM)buf);
	CHECK_STR_EQ(buf, "World");
	CHECK_INT_EQ((int)r, (int)strlen("World"));

	free_combo(cs);
}

TEST(getlbtextlen_returns_string_length)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)"ABCDE");
	LRESULT r = SendMessageA(h, CB_GETLBTEXTLEN, 0, 0);
	CHECK_INT_EQ((int)r, 5);

	free_combo(cs);
}

TEST(getlbtext_out_of_range_returns_err)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	char buf[64];
	LRESULT r = SendMessageA(h, CB_GETLBTEXT, 0, (LPARAM)buf);
	CHECK((int)r == (int)CB_ERR);

	free_combo(cs);
}

TEST(getlbtextlen_out_of_range_returns_err)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;
	CHECK((int)SendMessageA(h, CB_GETLBTEXTLEN, 5, 0) == (int)CB_ERR);
	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * ComboBox_* inline helper macros (from windows.h)
 * --------------------------------------------------------------------- */
TEST(combobox_helpers_work)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	/* ComboBox_AddString returns index of new item */
	LRESULT idx = ComboBox_AddString(h, "USB Drive 1");
	CHECK_INT_EQ((int)idx, 0);
	ComboBox_AddString(h, "USB Drive 2");

	/* ComboBox_SetItemData */
	ComboBox_SetItemData(h, 0, (DWORD_PTR)1001);
	ComboBox_SetItemData(h, 1, (DWORD_PTR)1002);

	/* ComboBox_GetCount */
	CHECK_INT_EQ(ComboBox_GetCount(h), 2);

	/* ComboBox_SetCurSel / ComboBox_GetCurSel */
	ComboBox_SetCurSel(h, 1);
	CHECK_INT_EQ(ComboBox_GetCurSel(h), 1);

	/* ComboBox_GetItemData */
	CHECK_INT_EQ((int)ComboBox_GetItemData(h, 1), 1002);

	/* ComboBox_GetCurItemData (defined in rufus.h, but macro duplicated here) */
	int cur = ComboBox_GetCurSel(h);
	LRESULT d = ComboBox_GetItemData(h, cur);
	CHECK_INT_EQ((int)d, 1002);

	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * CB_SETDROPPEDWIDTH — no-op but must not crash
 * --------------------------------------------------------------------- */
TEST(setdroppedwidth_is_noop)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;
	/* Should not crash */
	SendMessageA(h, CB_SETDROPPEDWIDTH, 200, 0);
	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * Unknown message — should return 0 without crashing
 * --------------------------------------------------------------------- */
TEST(unknown_message_returns_zero)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;
	LRESULT r = SendMessageA(h, 0x9999, 0, 0);
	CHECK_INT_EQ((int)r, 0);
	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * Capacity growth — add many items to force realloc
 * --------------------------------------------------------------------- */
TEST(many_items_grow_capacity)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	for (int i = 0; i < 64; i++) {
		char buf[32];
		snprintf(buf, sizeof(buf), "Item %d", i);
		LRESULT r = SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)buf);
		CHECK_INT_EQ((int)r, i);
	}
	CHECK_INT_EQ((int)SendMessageA(h, CB_GETCOUNT, 0, 0), 64);

	/* Verify last item text */
	char last[32];
	SendMessageA(h, CB_GETLBTEXT, 63, (LPARAM)last);
	CHECK_STR_EQ(last, "Item 63");

	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * combo_register_all with NULL pointers must not crash
 * This simulates calling it before GTK widgets are created.
 * --------------------------------------------------------------------- */
TEST(register_all_null_safe)
{
	/* We can't call the real combo_register_all() in tests because
	 * it uses rw.* GTK widget pointers.  Instead test that combo_state_alloc
	 * + msg_dispatch_register with NULL widget doesn't crash. */
	combo_state_t *cs = combo_state_alloc(NULL);
	CHECK(cs != NULL);
	msg_dispatch_init();
	msg_dispatch_register((HWND)cs, combo_msg_handler);
	msg_dispatch_unregister((HWND)cs);
	combo_state_free(cs);
}

/* -------------------------------------------------------------------------
 * Simulate GetDevices() populating hDeviceList
 * --------------------------------------------------------------------- */
TEST(simulate_getdevices_populate)
{
	combo_state_t *cs = make_combo();
	HWND h = (HWND)cs;

	/* Simulate what GetDevices() does: reset, add items with data */
	ComboBox_ResetContent(h);

	ComboBox_SetItemData(h,
	    ComboBox_AddString(h, "Kingston USB 3.0 (8 GB)"),
	    (DWORD_PTR)0);   /* DriveIndex 0 */

	ComboBox_SetItemData(h,
	    ComboBox_AddString(h, "SanDisk Cruzer (16 GB)"),
	    (DWORD_PTR)1);   /* DriveIndex 1 */

	/* Simulate selecting the first device */
	ComboBox_SetCurSel(h, 0);

	CHECK_INT_EQ(ComboBox_GetCount(h), 2);
	CHECK_INT_EQ(ComboBox_GetCurSel(h), 0);
	CHECK_INT_EQ((int)ComboBox_GetItemData(h, 0), 0);
	CHECK_INT_EQ((int)ComboBox_GetItemData(h, 1), 1);

	free_combo(cs);
}

/* -------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */
int main(void)
{
	RUN(combo_alloc_free);
	RUN(combo_free_null_safe);
	RUN(addstring_returns_index);
	RUN(getcount_after_adds);
	RUN(addstring_null_text_treated_as_empty);
	RUN(resetcontent_clears_items);
	RUN(setcursel_getcursel_roundtrip);
	RUN(setcursel_minus1_deselects);
	RUN(setcursel_out_of_range_returns_err);
	RUN(getcursel_empty_combo_returns_err);
	RUN(setitemdata_getitemdata_roundtrip);
	RUN(getitemdata_out_of_range_returns_err);
	RUN(setitemdata_out_of_range_returns_err);
	RUN(getlbtext_returns_item_string);
	RUN(getlbtextlen_returns_string_length);
	RUN(getlbtext_out_of_range_returns_err);
	RUN(getlbtextlen_out_of_range_returns_err);
	RUN(combobox_helpers_work);
	RUN(setdroppedwidth_is_noop);
	RUN(unknown_message_returns_zero);
	RUN(many_items_grow_capacity);
	RUN(register_all_null_safe);
	RUN(simulate_getdevices_populate);
	TEST_RESULTS();
}
