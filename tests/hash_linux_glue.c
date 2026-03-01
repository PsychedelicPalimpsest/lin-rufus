/*
 * hash_linux_glue.c — test-build shim for src/linux/hash.c
 *
 * hash_algos.c (included by hash.c) reads cpu_has_sha1_accel and
 * cpu_has_sha256_accel.  In the real binary these are defined in
 * linux/globals.c; for the test binary we define them here so the
 * test does not need to pull in the entirety of globals.c.
 *
 * BufferMatchesHash in linux/hash.c hard-codes SHA256.  The correct
 * behaviour is to auto-detect the hash type from the string length so
 * it can match MD5, SHA1, SHA256 or SHA512 hex strings.  We rename
 * the broken version while including hash.c and replace it below.
 *
 * For HashThread / IndividualHashThread tests (Linux only) we also
 * define the globals that are normally supplied by linux/globals.c.
 */
#include "rufus.h"
#include <sys/stat.h>

/* ---- Acceleration flags (from globals.c in the real binary) ---- */
BOOL cpu_has_sha1_accel   = FALSE;
BOOL cpu_has_sha256_accel = FALSE;

/* ---- Globals required by HashThread (from globals.c in real binary) ---- */
char*  image_path       = NULL;
char   hash_str[HASH_MAX][150];
BOOL   enable_extra_hashes = FALSE;
BOOL   validate_md5sum     = FALSE;
RUFUS_IMG_REPORT img_report = { 0 };
DWORD  ErrorStatus      = 0;
HWND   hMainDialog      = NULL;
int    default_thread_priority = 0;
uint64_t md5sum_totalbytes = 0;
StrArray modified_files = { 0 };
uint8_t* pe256ssp       = NULL;
uint32_t pe256ssp_size  = 0;
char*  ini_file         = NULL;

/* ---- Globals needed by parser.c ---- */
#include "../src/windows/rufus.h"
RUFUS_UPDATE update = { {0,0,0}, {0,0}, NULL, NULL };
windows_version_t WindowsVersion = { 0 };

/* ---- Globals for Secure Boot checks (IsSignedBySecureBootAuthority / IsBootloaderRevoked) ---- */
char *sbat_level_txt    = NULL;
char *sb_active_txt     = NULL;
char *sb_revoked_txt    = NULL;
sbat_entry_t*     sbat_entries   = NULL;
thumbprint_list_t *sb_active_certs  = NULL;
thumbprint_list_t *sb_revoked_certs = NULL;
BOOL expert_mode        = FALSE;
char app_data_dir[MAX_PATH] = "/tmp";
char app_dir[MAX_PATH]  = "/tmp";
BOOL usb_debug          = FALSE;
BOOL right_to_left_mode = FALSE;

/* ---- fd_resources stub (stdfn.c/GetResource uses this, but we have no FreeDOS data in hash tests) ---- */
#include "../src/linux/freedos_data.h"
const fd_resource_t fd_resources[FD_RESOURCES_COUNT] = {{ 0, NULL, 0 }};

/* ---- efi_archname and MachineToArch stubs (normally from iso.c / rufus.c) ---- */
const char* efi_archname[ARCH_MAX] = {
	"",         /* ARCH_UNKNOWN */
	"ia32",     /* ARCH_X86_32  */
	"x64",      /* ARCH_X86_64  */
	"arm",      /* ARCH_ARM_32  */
	"aa64",     /* ARCH_ARM_64  */
	"ia64",     /* ARCH_IA_64   */
	"riscv64",  /* ARCH_RISCV_64 */
	"loongarch64", /* ARCH_LOONGARCH_64 */
	"ebc",      /* ARCH_EBC     */
};

enum ArchType MachineToArch(WORD machine)
{
	switch (machine) {
	case IMAGE_FILE_MACHINE_I386:   return ARCH_X86_32;
	case IMAGE_FILE_MACHINE_AMD64:  return ARCH_X86_64;
	case IMAGE_FILE_MACHINE_ARM:    return ARCH_ARM_32;
	case IMAGE_FILE_MACHINE_ARMNT:  return ARCH_ARM_32;
	case IMAGE_FILE_MACHINE_ARM64:  return ARCH_ARM_64;
	case IMAGE_FILE_MACHINE_IA64:   return ARCH_IA_64;
	default:                        return ARCH_UNKNOWN;
	}
}

/* ---- UseLocalDbx stub (no cached DBX in test environment) ---- */
BOOL UseLocalDbx(int arch) { (void)arch; return FALSE; }

/* ---- Stubs for bled (not needed for hash tests) ---- */
void bled_init(void *a, void *b, void *c, void *d, void *e, void *f, void *g)
     { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; }
int  bled_uncompress_to_dir(const char *src, const char *dst) { (void)src;(void)dst; return -1; }
void bled_exit(void) {}

/* ---- Rename the hard-coded-SHA256 BufferMatchesHash before including hash.c ---- */
#define BufferMatchesHash BufferMatchesHash_sha256only
#include "../src/linux/hash.c"
#undef BufferMatchesHash

/* ---- Auto-detect hash type from the hex-string length ---- */
BOOL BufferMatchesHash(const uint8_t* buf, const size_t len, const char* str)
{
	uint8_t hash[MAX_HASHSIZE];
	unsigned type;
	size_t slen;

	if (buf == NULL || str == NULL)
		return FALSE;
	slen = safe_strlen(str);
	if      (slen == MD5_HASHSIZE    * 2) type = HASH_MD5;
	else if (slen == SHA1_HASHSIZE   * 2) type = HASH_SHA1;
	else if (slen == SHA256_HASHSIZE * 2) type = HASH_SHA256;
	else if (slen == SHA512_HASHSIZE * 2) type = HASH_SHA512;
	else return FALSE;
	if (!HashBuffer(type, buf, len, hash))
		return FALSE;
	return (memcmp(hash, StringToHash(str), slen / 2) == 0);
}
