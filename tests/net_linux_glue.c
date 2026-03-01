/*
 * net_linux_glue.c — stubs needed by test_net_linux to link net.c with
 * the CheckForUpdates implementation.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

/* ---- compat layer (windows.h etc.) ---- */
#include "windows.h"
#include "commctrl.h"
#include "rufus.h"

/* ---- parse_update stub ---- */
void parse_update(char *buf, size_t len)
{
	(void)buf; (void)len;
	/* In the test environment we don't parse anything. */
}

/* ---- DownloadNewVersion stub ---- */
void DownloadNewVersion(void) {}

/* ---- efi_archname stub (defined in iso.c, used by net.c/hash.c) ---- */
const char* efi_archname[] = {
    "", "ia32", "x64", "arm", "aa64", "ia64", "riscv64", "loongarch64", "ebc"
};

/* ---- PostMessage / SendMessage stubs ----
 * msg_dispatch.c provides the real PostMessageA / SendMessageA in the build,
 * but the test link doesn't include it.  Provide minimal no-ops. */
BOOL PostMessageA(HWND h, UINT msg, WPARAM w, LPARAM l)
{
	(void)h; (void)msg; (void)w; (void)l;
	return TRUE;
}
LRESULT SendMessageA(HWND h, UINT msg, WPARAM w, LPARAM l)
{
	(void)h; (void)msg; (void)w; (void)l;
	return 0;
}

/* ---- bled stubs (used by stdio.c's ExtractZip and DownloadISOThread) ---- */
typedef void (*bled_printf_t)(const char *, ...);
typedef long ssize_t;
int bled_init(uint32_t buffer_size, void *printf_fn, void *read_fn, void *write_fn,
              void *progress_fn, void *switch_fn, unsigned long *cancel_request)
{
	(void)buffer_size; (void)printf_fn; (void)read_fn; (void)write_fn;
	(void)progress_fn; (void)switch_fn; (void)cancel_request;
	return 0;
}
long bled_uncompress_to_dir(const char *src, const char *dst, bled_printf_t fn)
{
	(void)src; (void)dst; (void)fn;
	return -1;
}
ssize_t bled_uncompress_from_buffer_to_buffer(const uint8_t *in, size_t in_size,
                                               uint8_t **out, size_t *out_size)
{
	(void)in; (void)in_size; (void)out; (void)out_size;
	return -1;
}
void bled_exit(void) {}

/* ---- settings parser stubs ----
 * ReadSetting* / WriteSetting* in settings.h call get_token_data_file_indexed
 * (via the get_token_data_file macro) and set_token_data_file.
 * The inline guards already return early when ini_file==NULL, but the linker
 * still needs the symbols to exist. */
char *get_token_data_file_indexed(const char *token, const char *filename, int index)
{
	(void)token; (void)filename; (void)index;
	return NULL;
}

char *set_token_data_file(const char *token, const char *data, const char *filename)
{
	(void)token; (void)data; (void)filename;
	return NULL;
}

char *get_sanitized_token_data_buffer(const char *token, int index,
                                       const char *buf, size_t buf_len)
{
	(void)token; (void)index; (void)buf; (void)buf_len;
	return NULL;
}

char *get_token_data_buffer(const char *token, unsigned int n,
                             const char *buffer, size_t buffer_size)
{
	(void)token; (void)n; (void)buffer; (void)buffer_size;
	return NULL;
}

/* ---- localization stubs ---- */
char *lmprintf(uint32_t msg_id, ...)
{
	(void)msg_id;
	return "";
}

/* ---- dialog stubs (FileDialog, NotificationEx) ---- */
char *FileDialog(BOOL save, char *path, const ext_t *ext, UINT *selected_ext)
{
	(void)save; (void)path; (void)ext; (void)selected_ext;
	return NULL;
}

int NotificationEx(int type, const char *dont_display_setting,
                   const notification_info *more_info,
                   const char *title, const char *format, ...)
{
	(void)type; (void)dont_display_setting; (void)more_info;
	(void)title; (void)format;
	return IDOK;
}

/* ---- ValidateOpensslSignature — test implementation ----
 *
 * In the test build we cannot link pki.c (which uses the hardcoded Rufus
 * production RSA public key).  Instead we provide a functionally identical
 * implementation that uses a TEST RSA-2048 key pair.  The test vectors were
 * generated with:
 *
 *   openssl genrsa -out test.pem 2048
 *   echo -n "test signed file content" > data.txt
 *   openssl dgst -sha256 -sign test.pem -out sig_be.bin data.txt
 *   python3 -c "open('sig_le.bin','wb').write(bytes(reversed(open('sig_be.bin','rb').read())))"
 *
 * The modulus bytes below are the 256-byte big-endian RSA modulus (no leading
 * 0x00 padding byte).  The signature is stored little-endian, matching Rufus
 * conventions (ValidateOpensslSignature reverses it before calling OpenSSL).
 */

#define TEST_RSA_MOD_SIZE 256

static const uint8_t test_rsa_modulus[TEST_RSA_MOD_SIZE] = {
	0xe5, 0xcc, 0x5b, 0x4b, 0x03, 0x2e, 0xdf, 0xad,
	0xa4, 0x23, 0x8d, 0x92, 0xe5, 0x57, 0x40, 0x46,
	0xf9, 0x8f, 0x1e, 0x86, 0xee, 0xec, 0x9b, 0x0f,
	0xcd, 0x2e, 0x99, 0xa2, 0xc2, 0xe6, 0x1f, 0x03,
	0x19, 0x63, 0xad, 0xdf, 0xb1, 0x3b, 0xd7, 0xa3,
	0xfd, 0xb5, 0xbc, 0x2c, 0x86, 0x8d, 0x9b, 0xc4,
	0xe6, 0x93, 0xaf, 0xee, 0x75, 0x72, 0x86, 0x05,
	0xe4, 0xce, 0x8b, 0x77, 0xd7, 0xe1, 0xdf, 0x72,
	0xff, 0x73, 0x34, 0x5f, 0x05, 0x01, 0x4d, 0x82,
	0xc6, 0xbe, 0x07, 0x43, 0xfd, 0xdf, 0x7a, 0x32,
	0xc9, 0xb1, 0x43, 0x88, 0x68, 0x33, 0x06, 0x46,
	0x0b, 0xd5, 0x83, 0x00, 0x6f, 0xd5, 0x76, 0x9a,
	0xbd, 0xfb, 0xcb, 0x17, 0x30, 0xc8, 0x16, 0x2e,
	0x22, 0xd3, 0x3f, 0xcd, 0x7a, 0xa1, 0x68, 0x0b,
	0x30, 0x09, 0xf3, 0xdb, 0x05, 0xaf, 0x97, 0xd4,
	0x84, 0x65, 0x93, 0xbf, 0x88, 0x13, 0xbe, 0x6e,
	0xa5, 0xb9, 0x9a, 0x72, 0x1e, 0xc0, 0xc4, 0x97,
	0x20, 0x40, 0xfd, 0x7b, 0x56, 0x7d, 0x15, 0x9f,
	0xac, 0xf8, 0xe8, 0x22, 0x6d, 0x03, 0x70, 0xce,
	0x63, 0x38, 0x00, 0x2d, 0x7f, 0x5d, 0x02, 0xb6,
	0x30, 0x5b, 0x4f, 0x91, 0x3c, 0x96, 0x42, 0x01,
	0x05, 0xf1, 0xc0, 0x49, 0x02, 0x76, 0x52, 0x55,
	0x7a, 0xf5, 0xa2, 0x05, 0x30, 0x7f, 0xec, 0x1b,
	0xfe, 0x8c, 0xb7, 0x09, 0x13, 0xa9, 0x07, 0x96,
	0x84, 0x0a, 0x31, 0x7d, 0xef, 0x8d, 0xc2, 0x41,
	0xf7, 0xaa, 0x43, 0xdd, 0xc9, 0x74, 0x15, 0xa1,
	0xfd, 0x3c, 0x40, 0x52, 0x4e, 0x69, 0x49, 0xb8,
	0xac, 0x38, 0x01, 0xa9, 0xd1, 0x3a, 0x7a, 0x4c,
	0x74, 0x07, 0x4d, 0xfc, 0xc9, 0x20, 0xc5, 0x7e,
	0x93, 0x67, 0x14, 0x8f, 0x6e, 0x9c, 0x3c, 0xd5,
	0x26, 0x87, 0x7c, 0x13, 0x9a, 0x32, 0x25, 0x13,
	0x28, 0x6d, 0xf6, 0x7f, 0x34, 0x12, 0x83, 0xd9
};

/*
 * ValidateOpensslSignature — RSA-SHA256 verify using the test key modulus.
 * Identical algorithm to src/linux/pki.c; uses test_rsa_modulus instead of
 * the production Rufus public key.
 */
BOOL ValidateOpensslSignature(BYTE *pbBuffer, DWORD dwBufferLen,
                               BYTE *pbSignature, DWORD dwSigLen)
{
	BIGNUM *n = NULL, *e = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;
	uint8_t sig_be[TEST_RSA_MOD_SIZE];
	BOOL r = FALSE;
	int i, j;

	if (!pbBuffer || !pbSignature || dwBufferLen == 0 ||
	    dwSigLen != TEST_RSA_MOD_SIZE)
		return FALSE;

	/* Rufus stores signatures little-endian; reverse to big-endian for OpenSSL */
	for (i = 0, j = TEST_RSA_MOD_SIZE - 1; i < TEST_RSA_MOD_SIZE; i++, j--)
		sig_be[i] = pbSignature[j];

	n = BN_bin2bn(test_rsa_modulus, TEST_RSA_MOD_SIZE, NULL);
	e = BN_new();
	if (!n || !e || !BN_set_word(e, 65537))
		goto out;

	bld = OSSL_PARAM_BLD_new();
	if (!bld) goto out;
	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n)) goto out;
	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) goto out;
	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) goto out;

	kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!kctx) goto out;
	if (EVP_PKEY_fromdata_init(kctx) <= 0) goto out;
	if (EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) goto out;

	ctx = EVP_MD_CTX_new();
	if (!ctx) goto out;

	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
	    EVP_DigestVerifyUpdate(ctx, pbBuffer, dwBufferLen) == 1 &&
	    EVP_DigestVerifyFinal(ctx, sig_be, TEST_RSA_MOD_SIZE) == 1)
		r = TRUE;

out:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(kctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(n);
	BN_free(e);
	return r;
}
