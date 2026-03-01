/*
 * Linux stub: globals.c
 * Defines all global variables declared as extern in rufus.h and related headers.
 * This replaces the definitions scattered across the Windows .c files.
 */
#include "rufus.h"
#include "resource.h"
#include "drive.h"
#include "version.h"
#include <stdint.h>
#include "localization.h"
#include "ui.h"
#include "wue.h"

/* ---- From rufus.c ---- */
HINSTANCE hMainInstance;
HWND hMainDialog, hMultiToolbar, hSaveToolbar, hHashToolbar;
HWND hAdvancedDeviceToolbar, hAdvancedFormatToolbar, hUpdatesDlg = NULL;
HWND hDeviceList, hPartitionScheme, hTargetSystem, hFileSystem;
HWND hClusterSize, hLabel, hBootType, hNBPasses, hLog = NULL;
HWND hImageOption, hLogDialog = NULL, hProgress = NULL;
HWND hCapacity, hInfo, hStatus;
WORD selected_langid;
DWORD MainThreadId, ErrorStatus, DownloadStatus, LastWriteError;
BOOL op_in_progress = FALSE, right_to_left_mode = FALSE;
BOOL allow_dual_uefi_bios = FALSE, large_drive = FALSE, usb_debug = FALSE;
BOOL detect_fakes = FALSE, use_own_c32[NB_OLD_C32];
uint8_t image_options = 0, *pe256ssp = NULL;
uint16_t rufus_version[3], embedded_sl_version[2];
uint32_t pe256ssp_size = 0;
uint64_t persistence_size = 0;
int64_t iso_blocking_status = -1;
float fScale = 1.0f;
int dialog_showing = 0, force_update = 0, fs_type = 0, boot_type = 0;
int partition_type = 0, target_type = 0, selection_default = 0;
int persistence_unit_selection = -1;
unsigned long syslinux_ldlinux_len[2];
char ubuffer[UBUFFER_SIZE], embedded_sl_version_str[2][12];
char szFolderPath[MAX_PATH], app_dir[MAX_PATH], system_dir[MAX_PATH];
char temp_dir[MAX_PATH], sysnative_dir[MAX_PATH];
char app_data_dir[MAX_PATH], user_dir[MAX_PATH], cur_dir[MAX_PATH];
char embedded_sl_version_ext[2][32];
char ClusterSizeLabel[MAX_CLUSTER_SIZES][64];
char msgbox[1024], msgbox_title[32];
char *ini_file = NULL, *image_path = NULL;
char *archive_path = NULL, image_option_txt[128];
char *fido_url = NULL, *save_image_type = NULL;
char *sbat_level_txt = NULL, *sb_active_txt = NULL, *sb_revoked_txt = NULL;
sbat_entry_t* sbat_entries = NULL;
thumbprint_list_t *sb_active_certs = NULL, *sb_revoked_certs = NULL;
RUFUS_UPDATE update = { {0,0,0}, {0,0}, NULL, NULL };

/* More bools from rufus.c */
BOOL has_uefi_csm = FALSE, its_a_me_mario = FALSE;
BOOL enable_HDDs = FALSE, enable_VHDs = TRUE;
BOOL enable_ntfs_compression = FALSE, no_confirmation_on_cancel = FALSE;
BOOL advanced_mode_device = FALSE, advanced_mode_format = FALSE;
BOOL enable_vmdk = FALSE, force_large_fat32 = FALSE;
BOOL use_fake_units = FALSE, preserve_timestamps = FALSE;
BOOL fast_zeroing = FALSE, app_changed_size = FALSE;
BOOL zero_drive = FALSE, list_non_usb_removable_drives = FALSE;
BOOL quick_format = TRUE;
BOOL enable_bad_blocks = FALSE;
BOOL enable_verify_write = FALSE;
int  nb_passes_sel = 0;   /* raw nb-passes combo index (0-4) */
BOOL enable_file_indexing = FALSE;
BOOL write_as_image = FALSE, write_as_esp = FALSE;
BOOL use_vds = FALSE, ignore_boot_marker = FALSE, save_image = FALSE;
BOOL appstore_version = FALSE, is_vds_available = FALSE;
BOOL persistent_log = FALSE, has_ffu_support = FALSE;
BOOL expert_mode = FALSE, use_rufus_mbr = TRUE;
int default_fs = 0, default_thread_priority = 0;
size_t ubuffer_pos = 0;

/* ---- From iso.c ---- */
RUFUS_IMG_REPORT img_report = { 0 };

/* ---- SelectedDrive is defined in drive.c (Windows) or linux/drive.c (Linux) ---- */
/* Do NOT define SelectedDrive here — it is owned by drive.c */

/* ---- From stdfn.c ---- */
windows_version_t WindowsVersion = { 0 };

/* ---- From ui.c ---- */
UINT_PTR UM_LANGUAGE_MENU_MAX = 0;
int update_progress_type = 0;
int advanced_device_section_height = 0, advanced_format_section_height = 0;
int cbw = 0, ddw = 0, ddbh = 0, bh = 0;
HFONT hInfoFont = NULL;
loc_cmd* selected_locale = NULL;
const char *sfd_name = NULL;
const char *flash_type[BADLOCKS_PATTERN_TYPES] = { 0 };

/* ---- From localization.c ---- */
int loc_line_nr = 0;
char *loc_filename = NULL, *embedded_loc_filename = "embedded.loc";
char *default_msg_table[MSG_MAX] = { 0 };
char *current_msg_table[MSG_MAX] = { 0 };
char **msg_table = NULL;
BOOL en_msg_mode = FALSE;

/* ---- From wue.c ---- */
int unattend_xml_flags = 0, wintogo_index = -1, wininst_index = 0;
int unattend_xml_mask = 0;
char *unattend_xml_path = NULL;

/* ---- From hash.c ---- */
char hash_str[HASH_MAX][150];
BOOL enable_extra_hashes = FALSE, validate_md5sum = FALSE;
BOOL cpu_has_sha1_accel = FALSE, cpu_has_sha256_accel = FALSE;
uint64_t md5sum_totalbytes = 0;

/* hash_init / hash_write / hash_final are defined in linux/hash.c
 * (populated when hash_algos.c is included there).
 * modified_files is used by UpdateMD5Sum in hash.c. */
StrArray modified_files = { 0 };

/* ---- From net.c ---- */
/* DownloadStatus already defined above */

/* ---- From localization.c - struct list heads ---- */
struct list_head locale_list = { &locale_list, &locale_list };
const loc_parse parse_cmd[7] = { 0 };

/* ---- nb_steps from format.c ---- */
const int nb_steps[FS_MAX] = { 0 };

/* ---- FileSystemLabel from format.c ---- */
/* Must match the FS_* enum order: FAT=0,FAT32=1,NTFS=2,UDF=3,exFAT=4,ReFS=5,ext2=6,ext3=7,ext4=8 */
const char* FileSystemLabel[FS_MAX] = { "FAT", "FAT32", "NTFS", "UDF", "exFAT", "ReFS", "ext2", "ext3", "ext4" };

/* ---- From rufus.c ---- */
HANDLE dialog_handle = NULL, format_thread = NULL;

/* ---- From dev.c / rufus.c ---- */
RUFUS_DRIVE rufus_drive[MAX_DRIVES] = { 0 };


/* ---- Version initialization ---- */
void init_rufus_version(void) {
rufus_version[0] = RUFUS_LINUX_VERSION_MAJOR;
rufus_version[1] = RUFUS_LINUX_VERSION_MINOR;
rufus_version[2] = RUFUS_LINUX_VERSION_PATCH;
}
