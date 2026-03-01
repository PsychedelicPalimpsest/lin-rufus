/*
 * test_fido_linux.c — Tests for Fido script version-check logic.
 *
 * Tests fido_check_url_updated(): the function that detects when the Fido
 * download script URL has changed (indicating a newer Fido version), persists
 * the URL in settings, and signals whether an update occurred.
 *
 * Linux-only.
 */
#ifndef __linux__
#include <stdio.h>
int main(void) { printf("SKIP: Linux-only test\n"); return 0; }
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>

#include "framework.h"

#include "windows.h"
#include "commctrl.h"
#include "rufus.h"
#include "resource.h"
#include "missing.h"
#include "localization.h"
#include "../src/linux/settings.h"

/* ================================================================
 * Minimal globals required by net.c and its dependencies.
 * ================================================================ */

HWND hMainDialog   = NULL;
HWND hDeviceList   = NULL;
HWND hProgress     = NULL;
HWND hStatus       = NULL;
HWND hInfo         = NULL;
HWND hLog          = NULL;
HWND hCapacity     = NULL;

BOOL op_in_progress        = FALSE;
BOOL enable_HDDs           = FALSE;
BOOL enable_VHDs           = TRUE;
BOOL right_to_left_mode    = FALSE;
BOOL appstore_version      = FALSE;
BOOL expert_mode           = FALSE;
BOOL persistent_log        = FALSE;
BOOL has_ffu_support       = FALSE;
BOOL app_changed_size      = FALSE;
BOOL use_fake_units        = FALSE;
BOOL preserve_timestamps   = FALSE;
BOOL validate_md5sum       = FALSE;
BOOL cpu_has_sha1_accel    = FALSE;
BOOL cpu_has_sha256_accel  = FALSE;
BOOL enable_extra_hashes   = FALSE;
BOOL fast_zeroing_global   = FALSE;
BOOL use_vds               = FALSE;
BOOL ignore_boot_marker    = FALSE;
BOOL save_image            = FALSE;
BOOL enable_vmdk           = FALSE;
BOOL write_as_image_global = FALSE;
BOOL write_as_esp_global   = FALSE;
BOOL usb_debug             = FALSE;
BOOL detect_fakes          = FALSE;
BOOL use_own_c32[NB_OLD_C32];
BOOL has_uefi_csm          = FALSE, its_a_me_mario = FALSE;
BOOL enable_VHDs_global    = TRUE;
BOOL allow_dual_uefi_bios  = FALSE;
BOOL is_vds_available      = FALSE;

int default_fs             = 0;
int default_thread_priority= 0;
unsigned long syslinux_ldlinux_len[2] = {0,0};

char sysnative_dir[MAX_PATH]  = "/tmp";
char user_dir[MAX_PATH]       = "/tmp";
char cur_dir[MAX_PATH]        = "";
char embedded_sl_version_str[2][12] = {"", ""};
char embedded_sl_version_ext[2][32] = {"", ""};
char ClusterSizeLabel[MAX_CLUSTER_SIZES][64];
char msgbox[1024]             = "";
char msgbox_title[32]         = "";
char image_option_txt[128]    = "";
char ubuffer[UBUFFER_SIZE]    = "";

char *ini_file            = NULL;
char *image_path          = NULL;
char *archive_path        = NULL;
char *fido_url            = NULL;
char *save_image_type     = NULL;
char *sbat_level_txt      = NULL;
char *sb_active_txt       = NULL;
char *sb_revoked_txt      = NULL;

HINSTANCE hMainInstance    = NULL;
HWND hMultiToolbar = NULL, hSaveToolbar = NULL, hHashToolbar = NULL;
HWND hAdvancedDeviceToolbar = NULL, hAdvancedFormatToolbar = NULL;
HWND hUpdatesDlg = NULL;
HWND hPartitionScheme = NULL, hTargetSystem = NULL, hFileSystem = NULL;
HWND hClusterSize = NULL, hLabel = NULL, hBootType = NULL, hNBPasses = NULL;
HWND hImageOption = NULL, hLogDialog = NULL;
WORD selected_langid       = 0;
size_t ubuffer_pos         = 0;
uint64_t md5sum_totalbytes = 0;

RUFUS_IMG_REPORT img_report       = { 0 };
RUFUS_UPDATE update               = { {0,0,0}, {0,0}, NULL, NULL };
RUFUS_DRIVE rufus_drive[MAX_DRIVES] = { { 0 } };

sbat_entry_t *sbat_entries        = NULL;
thumbprint_list_t *sb_active_certs = NULL, *sb_revoked_certs = NULL;

HANDLE dialog_handle       = NULL;
HANDLE format_thread       = NULL;
StrArray modified_files    = { 0 };

char hash_str[HASH_MAX][150];

UINT_PTR UM_LANGUAGE_MENU_MAX     = 0;
int advanced_device_section_height= 0;
int advanced_format_section_height= 0;
int cbw = 0, ddw = 0, ddbh = 0, bh = 0;
const char *sfd_name              = NULL;
const char *flash_type[BADLOCKS_PATTERN_TYPES] = { 0 };
HFONT hInfoFont                   = NULL;
loc_cmd *selected_locale          = NULL;

/* wue stubs */
int unattend_xml_flags = 0, wintogo_index = -1, wininst_index = 0;
int unattend_xml_mask  = 0;
char *unattend_xml_path = NULL;

const int nb_steps[FS_MAX] = { 0 };
windows_version_t WindowsVersion  = { 0 };

DWORD ErrorStatus          = 0;
DWORD DownloadStatus       = 0;
uint16_t rufus_version[3]  = {0,0,0};
char temp_dir[MAX_PATH]    = "/tmp";
char app_data_dir[MAX_PATH]= "/tmp";

/* UI stubs */
void EnableControls(BOOL e, BOOL r)   { (void)e;(void)r; }
void UpdateProgress(int op, float pct) { (void)op; (void)pct; }
void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL f)
{ (void)op; (void)msg; (void)cur; (void)tot; (void)f; }

/* localization stub — lmprintf is provided by common/localization.c */

/* ================================================================
 * fido_check_url_updated — the function under test
 *   - returns FALSE if new_url is NULL
 *   - reads stored URL from SETTING_FIDO_URL
 *   - returns FALSE (no-op) when URL matches stored value
 *   - saves new_url and returns TRUE when URL differs or wasn't stored
 * ================================================================ */
extern BOOL fido_check_url_updated(const char *new_url);

/* Helper: create a temp ini file and return its path (caller must free+unlink) */
static char *make_temp_ini(void)
{
	char *path = strdup("/tmp/test_fido_ini_XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) { free(path); return NULL; }
	close(fd);
	return path;
}

#define URL_V142 "https://github.com/pbatard/Fido/releases/download/v1.42/Fido.ps1.lzma"
#define URL_V143 "https://github.com/pbatard/Fido/releases/download/v1.43/Fido.ps1.lzma"
#define URL_V144 "https://github.com/pbatard/Fido/releases/download/v1.44/Fido.ps1.lzma"
#define URL_V145 "https://github.com/pbatard/Fido/releases/download/v1.45/Fido.ps1.lzma"

/* ================================================================
 * Tests
 * ================================================================ */

TEST(fido_url_update_null_returns_false)
{
	CHECK_MSG(fido_check_url_updated(NULL) == FALSE,
	          "NULL url must return FALSE");
}

/* When ini_file is NULL, ReadSettingStr returns "" (no stored URL) → update */
TEST(fido_url_update_no_ini_returns_true)
{
	char *saved_ini = ini_file;
	ini_file = NULL;
	BOOL r = fido_check_url_updated(URL_V145);
	ini_file = saved_ini;
	CHECK_MSG(r == TRUE, "No ini_file → treat as first-time URL → TRUE");
}

/* First time a URL is seen (nothing stored yet) → returns TRUE */
TEST(fido_url_update_no_stored_returns_true)
{
	char *tmp = make_temp_ini();
	char *saved_ini = ini_file;
	ini_file = tmp;

	BOOL r = fido_check_url_updated(URL_V142);

	ini_file = saved_ini;
	if (tmp) { unlink(tmp); free(tmp); }
	CHECK_MSG(r == TRUE, "First-time URL must return TRUE");
}

/* Same URL stored and presented again → returns FALSE */
TEST(fido_url_update_same_url_returns_false)
{
	char *tmp = make_temp_ini();
	char *saved_ini = ini_file;
	ini_file = tmp;

	fido_check_url_updated(URL_V142);   /* store it */
	BOOL r = fido_check_url_updated(URL_V142); /* same → no update */

	ini_file = saved_ini;
	if (tmp) { unlink(tmp); free(tmp); }
	CHECK_MSG(r == FALSE, "Same URL must return FALSE (no update)");
}

/* Different URL after storing an older one → returns TRUE */
TEST(fido_url_update_different_url_returns_true)
{
	char *tmp = make_temp_ini();
	char *saved_ini = ini_file;
	ini_file = tmp;

	fido_check_url_updated(URL_V142); /* store old */
	BOOL r = fido_check_url_updated(URL_V143); /* newer → update */

	ini_file = saved_ini;
	if (tmp) { unlink(tmp); free(tmp); }
	CHECK_MSG(r == TRUE, "Different URL must return TRUE");
}

/* URL is persisted to settings after a call */
TEST(fido_url_update_saves_url_to_settings)
{
	char *tmp = make_temp_ini();
	char *saved_ini = ini_file;
	ini_file = tmp;

	fido_check_url_updated(URL_V144);

	const char *stored = ReadSettingStr(SETTING_FIDO_URL);
	BOOL saved_ok = (strcmp(stored, URL_V144) == 0);

	ini_file = saved_ini;
	if (tmp) { unlink(tmp); free(tmp); }
	CHECK_MSG(saved_ok, "URL must be persisted to SETTING_FIDO_URL");
}

/* After an update, the new URL replaces the old one in settings */
TEST(fido_url_update_stores_new_url_on_change)
{
	char *tmp = make_temp_ini();
	char *saved_ini = ini_file;
	ini_file = tmp;

	fido_check_url_updated(URL_V142); /* store old */
	fido_check_url_updated(URL_V143); /* update to new */

	const char *stored = ReadSettingStr(SETTING_FIDO_URL);
	BOOL is_new = (strcmp(stored, URL_V143) == 0);

	ini_file = saved_ini;
	if (tmp) { unlink(tmp); free(tmp); }
	CHECK_MSG(is_new, "After update, new URL must be stored in settings");
}

/* Calling twice with different URLs: second update is also detected */
TEST(fido_url_update_sequential_updates_detected)
{
	char *tmp = make_temp_ini();
	char *saved_ini = ini_file;
	ini_file = tmp;

	fido_check_url_updated(URL_V142);
	BOOL r1 = fido_check_url_updated(URL_V143); /* first update */
	BOOL r2 = fido_check_url_updated(URL_V144); /* second update */

	ini_file = saved_ini;
	if (tmp) { unlink(tmp); free(tmp); }
	CHECK_MSG(r1 == TRUE, "First update must return TRUE");
	CHECK_MSG(r2 == TRUE, "Second update must return TRUE");
}

int main(void)
{
	printf("=== Fido version-check Linux tests ===\n");

	printf("\n  fido_check_url_updated\n");
	RUN(fido_url_update_null_returns_false);
	RUN(fido_url_update_no_ini_returns_true);
	RUN(fido_url_update_no_stored_returns_true);
	RUN(fido_url_update_same_url_returns_false);
	RUN(fido_url_update_different_url_returns_true);
	RUN(fido_url_update_saves_url_to_settings);
	RUN(fido_url_update_stores_new_url_on_change);
	RUN(fido_url_update_sequential_updates_detected);

	TEST_RESULTS();
}

#endif /* __linux__ */
