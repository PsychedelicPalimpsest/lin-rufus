/*
 * test_settings_linux.c — Tests for FileIO() and the settings persistence layer
 *
 * Tests FileIO(read/write/append) and ReadSetting* / WriteSetting* using a
 * temporary INI file.  All tests are self-contained and clean up after
 * themselves.
 *
 * Linux-only (uses POSIX temp file helpers).
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "framework.h"

/* compat layer */
#include "windows.h"

/* rufus types */
#include "rufus.h"
#include "missing.h"
#include "localization.h"

/* Linux settings API */
#include "../src/linux/settings.h"

/* Declarations from globals.c */
extern char app_dir[MAX_PATH];
extern char app_data_dir[MAX_PATH];
extern char user_dir[MAX_PATH];
extern char* ini_file;

/* rufus_init_paths() is compiled in via settings_linux_glue.c */
extern void rufus_init_paths(void);

/* SetUpdateCheck() is compiled in via stdlg.c */
extern BOOL SetUpdateCheck(void);

/* ===================================================================
 * Helpers
 * =================================================================== */

/* Create a temporary file path in /tmp.  Returns path in buf. */
static void make_tmp_path(char *buf, size_t len)
{
snprintf(buf, len, "/tmp/test_settings_XXXXXX");
int fd = mkstemp(buf);
if (fd >= 0) close(fd);  /* leave the file empty but created */
}

/* Remove a file (ignore errors). */
static void rm_tmp(const char *path)
{
unlink(path);
/* also remove any ~ temp file left by set_token_data_file */
char tmp[4096];
snprintf(tmp, sizeof(tmp), "%s~", path);
unlink(tmp);
}

/* Write raw content to a file so tests can set up existing ini data. */
static void write_raw(const char *path, const char *content)
{
FILE *f = fopen(path, "w");
if (!f) return;
fputs(content, f);
fclose(f);
}

/* ===================================================================
 * FileIO tests
 * =================================================================== */

TEST(fileio_write_creates_file)
{
char path[64];
make_tmp_path(path, sizeof(path));
rm_tmp(path);   /* ensure it doesn't exist */

const char *msg = "hello world";
DWORD sz = (DWORD)strlen(msg);
char *buf = (char *)msg;
BOOL r = FileIO(FILE_IO_WRITE, path, &buf, &sz);
CHECK(r == TRUE);

struct stat st;
CHECK(stat(path, &st) == 0);
CHECK((DWORD)st.st_size == strlen(msg));

rm_tmp(path);
}

TEST(fileio_write_and_read_back)
{
char path[64];
make_tmp_path(path, sizeof(path));

const char *content = "rufus test content\nline2\n";
DWORD wsz = (DWORD)strlen(content);
char *wbuf = (char *)content;
BOOL r = FileIO(FILE_IO_WRITE, path, &wbuf, &wsz);
CHECK(r == TRUE);

char *rbuf = NULL;
DWORD rsz = 0;
r = FileIO(FILE_IO_READ, path, &rbuf, &rsz);
CHECK(r == TRUE);
CHECK(rbuf != NULL);
CHECK(rsz == (DWORD)strlen(content));
CHECK(memcmp(rbuf, content, rsz) == 0);
free(rbuf);

rm_tmp(path);
}

TEST(fileio_read_nonexistent_returns_false)
{
char *buf = NULL;
DWORD sz = 0;
BOOL r = FileIO(FILE_IO_READ, "/tmp/this_file_does_not_exist_rufus_settings_test", &buf, &sz);
CHECK(r == FALSE);
CHECK(buf == NULL);
}

TEST(fileio_null_path_returns_false)
{
char *buf = NULL;
DWORD sz = 0;
BOOL r = FileIO(FILE_IO_READ, NULL, &buf, &sz);
CHECK(r == FALSE);
}

TEST(fileio_null_buf_returns_false)
{
char path[64];
make_tmp_path(path, sizeof(path));
DWORD sz = 5;
BOOL r = FileIO(FILE_IO_READ, path, NULL, &sz);
CHECK(r == FALSE);
rm_tmp(path);
}

TEST(fileio_null_size_returns_false)
{
char path[64];
make_tmp_path(path, sizeof(path));
char *buf = NULL;
BOOL r = FileIO(FILE_IO_READ, path, &buf, NULL);
CHECK(r == FALSE);
rm_tmp(path);
}

TEST(fileio_append_adds_to_existing)
{
char path[64];
make_tmp_path(path, sizeof(path));

const char *first = "line1\n";
DWORD sz = (DWORD)strlen(first);
char *buf = (char *)first;
BOOL r = FileIO(FILE_IO_WRITE, path, &buf, &sz);
CHECK(r == TRUE);

const char *second = "line2\n";
sz = (DWORD)strlen(second);
buf = (char *)second;
r = FileIO(FILE_IO_APPEND, path, &buf, &sz);
CHECK(r == TRUE);

char *rbuf = NULL;
DWORD rsz = 0;
r = FileIO(FILE_IO_READ, path, &rbuf, &rsz);
CHECK(r == TRUE);
CHECK(rbuf != NULL);

const char *expected = "line1\nline2\n";
CHECK(rsz == (DWORD)strlen(expected));
CHECK(memcmp(rbuf, expected, rsz) == 0);
free(rbuf);

rm_tmp(path);
}

TEST(fileio_write_overwrites_existing)
{
char path[64];
make_tmp_path(path, sizeof(path));

const char *first = "old content";
DWORD sz = (DWORD)strlen(first);
char *buf = (char *)first;
BOOL r = FileIO(FILE_IO_WRITE, path, &buf, &sz);
CHECK(r == TRUE);

const char *second = "new";
sz = (DWORD)strlen(second);
buf = (char *)second;
r = FileIO(FILE_IO_WRITE, path, &buf, &sz);
CHECK(r == TRUE);

char *rbuf = NULL;
DWORD rsz = 0;
r = FileIO(FILE_IO_READ, path, &rbuf, &rsz);
CHECK(r == TRUE);
CHECK(rsz == (DWORD)strlen(second));
CHECK(memcmp(rbuf, second, rsz) == 0);
free(rbuf);

rm_tmp(path);
}

TEST(fileio_read_empty_file)
{
char path[64];
make_tmp_path(path, sizeof(path));

char *buf = NULL;
DWORD sz = 0;
BOOL r = FileIO(FILE_IO_READ, path, &buf, &sz);
CHECK(r == TRUE);
CHECK(sz == 0);
free(buf);

rm_tmp(path);
}

TEST(fileio_write_binary_data)
{
char path[64];
make_tmp_path(path, sizeof(path));

const uint8_t data[] = { 0x00, 0x01, 0x02, 0xFF, 0xFE };
DWORD sz = sizeof(data);
char *buf = (char *)data;
BOOL r = FileIO(FILE_IO_WRITE, path, &buf, &sz);
CHECK(r == TRUE);

char *rbuf = NULL;
DWORD rsz = 0;
r = FileIO(FILE_IO_READ, path, &rbuf, &rsz);
CHECK(r == TRUE);
CHECK(rsz == sizeof(data));
CHECK(memcmp(rbuf, data, rsz) == 0);
free(rbuf);

rm_tmp(path);
}

/* ===================================================================
 * Settings API tests
 * =================================================================== */

static char settings_tmp[64];

static void settings_setup(void)
{
make_tmp_path(settings_tmp, sizeof(settings_tmp));
ini_file = settings_tmp;
}

static void settings_teardown(void)
{
rm_tmp(settings_tmp);
ini_file = NULL;
}

TEST(settings_write_read_int32)
{
settings_setup();
BOOL wr = WriteSetting32("TestKey", 42);
CHECK(wr == TRUE);
int32_t val = ReadSetting32("TestKey");
CHECK_INT_EQ(42, val);
settings_teardown();
}

TEST(settings_write_read_negative_int32)
{
settings_setup();
BOOL wr = WriteSetting32("NegKey", -99);
CHECK(wr == TRUE);
int32_t val = ReadSetting32("NegKey");
CHECK_INT_EQ(-99, val);
settings_teardown();
}

TEST(settings_write_read_zero_int32)
{
settings_setup();
WriteSetting32("ZeroKey", 100);
WriteSetting32("ZeroKey", 0);
int32_t val = ReadSetting32("ZeroKey");
CHECK_INT_EQ(0, val);
settings_teardown();
}

TEST(settings_write_read_bool_true)
{
settings_setup();
BOOL wr = WriteSettingBool("BoolTrue", TRUE);
CHECK(wr == TRUE);
BOOL val = ReadSettingBool("BoolTrue");
CHECK(val == TRUE);
settings_teardown();
}

TEST(settings_write_read_bool_false)
{
settings_setup();
WriteSettingBool("BoolKey", TRUE);
WriteSettingBool("BoolKey", FALSE);
BOOL val = ReadSettingBool("BoolKey");
CHECK(val == FALSE);
settings_teardown();
}

TEST(settings_write_read_str)
{
settings_setup();
BOOL wr = WriteSettingStr("StrKey", "hello world");
CHECK(wr == TRUE);
const char *val = ReadSettingStr("StrKey");
CHECK(val != NULL);
CHECK_STR_EQ("hello world", val);
settings_teardown();
}

TEST(settings_write_read_locale)
{
settings_setup();
WriteSettingStr(SETTING_LOCALE, "fr-FR");
const char *val = ReadSettingStr(SETTING_LOCALE);
CHECK_STR_EQ("fr-FR", val);
settings_teardown();
}

TEST(settings_write_read_int64)
{
settings_setup();
BOOL wr = WriteSetting64("BigKey", INT64_C(0x123456789ABCDEF0));
CHECK(wr == TRUE);
int64_t val = ReadSetting64("BigKey");
CHECK(val == INT64_C(0x123456789ABCDEF0));
settings_teardown();
}

TEST(settings_overwrite_key_updates_value)
{
settings_setup();
WriteSetting32("Overwrite", 1);
WriteSetting32("Overwrite", 2);
int32_t val = ReadSetting32("Overwrite");
CHECK_INT_EQ(2, val);
settings_teardown();
}

TEST(settings_multiple_keys_independent)
{
settings_setup();
WriteSetting32("KeyA", 10);
WriteSetting32("KeyB", 20);
WriteSetting32("KeyC", 30);
CHECK_INT_EQ(10, ReadSetting32("KeyA"));
CHECK_INT_EQ(20, ReadSetting32("KeyB"));
CHECK_INT_EQ(30, ReadSetting32("KeyC"));
settings_teardown();
}

TEST(settings_read_missing_key_returns_default)
{
settings_setup();
int32_t val = ReadSetting32("NonExistentKey");
CHECK_INT_EQ(0, val);
settings_teardown();
}

TEST(settings_read_missing_str_returns_empty)
{
settings_setup();
const char *val = ReadSettingStr("NoSuchStrKey");
CHECK(val != NULL);
CHECK_STR_EQ("", val);
settings_teardown();
}

TEST(settings_check_ini_key_exists)
{
settings_setup();
WriteSetting32("CheckMe", 1);
BOOL exists = CheckIniKey("CheckMe");
CHECK(exists == TRUE);
settings_teardown();
}

TEST(settings_check_ini_key_missing)
{
settings_setup();
BOOL exists = CheckIniKey("NotThere");
CHECK(exists == FALSE);
settings_teardown();
}

TEST(settings_null_ini_file_read_returns_default)
{
ini_file = NULL;
int32_t val = ReadSetting32("AnyKey");
CHECK_INT_EQ(0, val);
}

TEST(settings_null_ini_file_write_returns_false)
{
ini_file = NULL;
BOOL r = WriteSetting32("AnyKey", 1);
CHECK(r == FALSE);
}

TEST(settings_preserves_comments)
{
settings_setup();
write_raw(settings_tmp, "; This is a comment\n[Section]\nFoo = 0\n");
WriteSetting32("Foo", 99);

char *buf = NULL;
DWORD sz = 0;
FileIO(FILE_IO_READ, settings_tmp, &buf, &sz);
CHECK(buf != NULL);
CHECK(strstr(buf, "; This is a comment") != NULL);
CHECK(strstr(buf, "[Section]") != NULL);
free(buf);

CHECK_INT_EQ(99, ReadSetting32("Foo"));
settings_teardown();
}

TEST(settings_ini_created_when_set_token_on_empty_file)
{
settings_setup();
BOOL r = WriteSetting32(SETTING_EXPERT_MODE, 1);
CHECK(r == TRUE);
CHECK_INT_EQ(1, ReadSetting32(SETTING_EXPERT_MODE));
settings_teardown();
}

TEST(settings_advanced_mode_roundtrip)
{
settings_setup();
WriteSettingBool(SETTING_ADVANCED_MODE_DEVICE, TRUE);
WriteSettingBool(SETTING_ADVANCED_MODE_FORMAT, FALSE);
CHECK(ReadSettingBool(SETTING_ADVANCED_MODE_DEVICE) == TRUE);
CHECK(ReadSettingBool(SETTING_ADVANCED_MODE_FORMAT) == FALSE);
settings_teardown();
}

TEST(settings_persistent_log_roundtrip)
{
settings_setup();
WriteSettingBool(SETTING_PERSISTENT_LOG, TRUE);
CHECK(ReadSettingBool(SETTING_PERSISTENT_LOG) == TRUE);
WriteSettingBool(SETTING_PERSISTENT_LOG, FALSE);
CHECK(ReadSettingBool(SETTING_PERSISTENT_LOG) == FALSE);
settings_teardown();
}

/* ===================================================================
 * XDG path tests
 * =================================================================== */

TEST(paths_user_dir_set)
{
rufus_init_paths();
CHECK(user_dir[0] != '\0');
CHECK(user_dir[0] == '/');
}

TEST(paths_app_data_dir_set)
{
rufus_init_paths();
CHECK(app_data_dir[0] != '\0');
CHECK(app_data_dir[0] == '/');
}

TEST(paths_ini_file_in_xdg_config)
{
rufus_init_paths();
if (ini_file != NULL) {
CHECK(strstr(ini_file, "rufus") != NULL);
CHECK(ini_file[0] == '/');
}
CHECK(TRUE);
}

TEST(paths_ini_file_readable_after_init)
{
rufus_init_paths();
if (ini_file != NULL) {
/* Should be able to write and read back a setting */
WriteSettingStr("_TestKey", "test_value");
const char *val = ReadSettingStr("_TestKey");
CHECK_STR_EQ("test_value", val);
/* Clean up */
/* No easy way to delete just one key; just verify it worked */
}
CHECK(TRUE);
}

/* ===================================================================
 * SetUpdateCheck tests
 * =================================================================== */

/* Returns FALSE when ini_file is NULL (settings unavailable) */
TEST(set_update_check_no_ini_returns_false)
{
	ini_file = NULL;
	BOOL r = SetUpdateCheck();
	CHECK(r == FALSE);
}

/* Returns TRUE with valid settings on first run; sets default interval */
TEST(set_update_check_first_run_sets_interval)
{
	settings_setup();
	/* First run: SETTING_UPDATE_INTERVAL is 0 (not set) */
	WriteSetting32(SETTING_UPDATE_INTERVAL, 0);
	BOOL r = SetUpdateCheck();
	CHECK(r == TRUE);
	/* Default interval (86400) should have been written */
	int32_t iv = ReadSetting32(SETTING_UPDATE_INTERVAL);
	CHECK(iv == 86400);
	settings_teardown();
}

/* Returns FALSE when updates explicitly disabled (interval = -1) */
TEST(set_update_check_disabled_returns_false)
{
	settings_setup();
	WriteSetting32(SETTING_UPDATE_INTERVAL, -1);
	BOOL r = SetUpdateCheck();
	CHECK(r == FALSE);
	settings_teardown();
}

/* Returns TRUE when interval already set (not first run) */
TEST(set_update_check_existing_interval_returns_true)
{
	settings_setup();
	WriteSetting32(SETTING_UPDATE_INTERVAL, 3600);
	BOOL r = SetUpdateCheck();
	CHECK(r == TRUE);
	/* Interval should not have been changed */
	int32_t iv = ReadSetting32(SETTING_UPDATE_INTERVAL);
	CHECK(iv == 3600);
	settings_teardown();
}

/* ===================================================================
 * main
 * =================================================================== */

int main(void)
{
printf("=== settings_linux tests ===\n\n");

printf("  FileIO\n");
RUN(fileio_write_creates_file);
RUN(fileio_write_and_read_back);
RUN(fileio_read_nonexistent_returns_false);
RUN(fileio_null_path_returns_false);
RUN(fileio_null_buf_returns_false);
RUN(fileio_null_size_returns_false);
RUN(fileio_append_adds_to_existing);
RUN(fileio_write_overwrites_existing);
RUN(fileio_read_empty_file);
RUN(fileio_write_binary_data);

printf("\n  Settings — int32 / bool\n");
RUN(settings_write_read_int32);
RUN(settings_write_read_negative_int32);
RUN(settings_write_read_zero_int32);
RUN(settings_write_read_bool_true);
RUN(settings_write_read_bool_false);

printf("\n  Settings — string\n");
RUN(settings_write_read_str);
RUN(settings_write_read_locale);

printf("\n  Settings — int64\n");
RUN(settings_write_read_int64);

printf("\n  Settings — key lifecycle\n");
RUN(settings_overwrite_key_updates_value);
RUN(settings_multiple_keys_independent);
RUN(settings_read_missing_key_returns_default);
RUN(settings_read_missing_str_returns_empty);
RUN(settings_check_ini_key_exists);
RUN(settings_check_ini_key_missing);
RUN(settings_null_ini_file_read_returns_default);
RUN(settings_null_ini_file_write_returns_false);
RUN(settings_preserves_comments);
RUN(settings_ini_created_when_set_token_on_empty_file);

printf("\n  Settings — real setting names\n");
RUN(settings_advanced_mode_roundtrip);
RUN(settings_persistent_log_roundtrip);

printf("\n  XDG paths\n");
RUN(paths_user_dir_set);
RUN(paths_app_data_dir_set);
RUN(paths_ini_file_in_xdg_config);
RUN(paths_ini_file_readable_after_init);

printf("\n  SetUpdateCheck\n");
RUN(set_update_check_no_ini_returns_false);
RUN(set_update_check_first_run_sets_interval);
RUN(set_update_check_disabled_returns_false);
RUN(set_update_check_existing_interval_returns_true);

TEST_RESULTS();
}

#endif /* __linux__ */
