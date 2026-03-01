/*
 * hash_win_glue.c — Windows test-build shim
 *
 * Provides the globals and wrapper functions required by test_hash.c when
 * building with MinGW.  Includes hash_algos.c directly (avoiding the full
 * windows/hash.c dependency chain) and re-implements the thin wrappers that
 * linux/hash.c contains, adapted for MinGW's POSIX-compat layer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <io.h>
#include <fcntl.h>

#include "rufus.h"
#include "../src/windows/missing.h"

BOOL cpu_has_sha1_accel   = FALSE;
BOOL cpu_has_sha256_accel = FALSE;

#include "../src/common/hash_algos.c"

#include "../src/windows/db.h"

BOOL HashFile(const unsigned type, const char* path, uint8_t* hash)
{
	BOOL r = FALSE;
	HASH_CONTEXT hash_ctx = { {0} };
	int fd = -1;
	int nr;
	uint8_t buf[4096];

	if ((type >= HASH_MAX) || (path == NULL) || (hash == NULL))
		goto out;

	fd = _open(path, _O_RDONLY | _O_BINARY);
	if (fd < 0)
		goto out;

	hash_init[type](&hash_ctx);
	while ((nr = _read(fd, buf, (unsigned)sizeof(buf))) > 0)
		hash_write[type](&hash_ctx, buf, (size_t)nr);

	if (nr < 0)
		goto out;

	hash_final[type](&hash_ctx);
	memcpy(hash, hash_ctx.buf, hash_count[type]);
	r = TRUE;

out:
	if (fd >= 0)
		_close(fd);
	return r;
}

uint8_t* StringToHash(const char* str)
{
	static uint8_t ret[MAX_HASHSIZE];
	size_t i, len = safe_strlen(str);
	uint8_t val = 0;
	char c;

	if_assert_fails(len / 2 == MD5_HASHSIZE || len / 2 == SHA1_HASHSIZE ||
	                len / 2 == SHA256_HASHSIZE || len / 2 == SHA512_HASHSIZE)
		return NULL;
	memset(ret, 0, sizeof(ret));

	for (i = 0; i < len; i++) {
		val <<= 4;
		c = (char)tolower((unsigned char)str[i]);
		if_assert_fails((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
			return NULL;
		val |= ((c - '0') < 0xa) ? (c - '0') : (c - 'a' + 0xa);
		if (i % 2)
			ret[i / 2] = val;
	}
	return ret;
}

BOOL IsBufferInDB(const unsigned char* buf, const size_t len)
{
	int i;
	uint8_t hash[SHA256_HASHSIZE];
	if (!HashBuffer(HASH_SHA256, buf, len, hash))
		return FALSE;
	for (i = 0; i < (int)ARRAYSIZE(sha256db); i += SHA256_HASHSIZE)
		if (memcmp(hash, &sha256db[i], SHA256_HASHSIZE) == 0)
			return TRUE;
	return FALSE;
}

BOOL IsFileInDB(const char* path)
{
	int i;
	uint8_t hash[SHA256_HASHSIZE];
	if (!HashFile(HASH_SHA256, path, hash))
		return FALSE;
	for (i = 0; i < (int)ARRAYSIZE(sha256db); i += SHA256_HASHSIZE)
		if (memcmp(hash, &sha256db[i], SHA256_HASHSIZE) == 0)
			return TRUE;
	return FALSE;
}

BOOL FileMatchesHash(const char* path, const char* str)
{
	uint8_t hash[SHA256_HASHSIZE];
	if (!HashFile(HASH_SHA256, path, hash))
		return FALSE;
	return (memcmp(hash, StringToHash(str), SHA256_HASHSIZE) == 0);
}

/* Auto-detect hash type from hex-string length. */
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

/* Stubs for functions not tested but referenced via headers. */
BOOL PE256Buffer(uint8_t* b, uint32_t l, uint8_t* h)              { (void)b; (void)l; (void)h; return FALSE; }
BOOL IsSignedBySecureBootAuthority(uint8_t* b, uint32_t l)        { (void)b; (void)l; return FALSE; }
int  IsBootloaderRevoked(uint8_t* b, uint32_t l)                  { (void)b; (void)l; return 0; }
void UpdateMD5Sum(const char* d, const char* m)                   { (void)d; (void)m; }
