/*
 * common/hash_db.c — Portable hash database lookup helpers
 *
 * This file is designed to be #included by platform-specific hash.c files,
 * after common/hash_algos.c has been included.  The including file must also
 * have arranged for sha256db[] (from windows/db.h) to be available.
 *
 * Provides:
 *   StringToHash()
 *   IsBufferInDB()
 *   IsFileInDB()
 *   FileMatchesHash()
 *   BufferMatchesHash()
 *
 * Copyright © 2015-2025 Pete Batard <pete@akeo.ie>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * StringToHash() - convert a hex-string hash to a binary byte array
 * @str:  Null-terminated hex string (length must equal 2 * one of the known hash sizes)
 *
 * Returns a pointer to a static buffer, or NULL on invalid input.
 */
uint8_t *StringToHash(const char *str)
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
		/* Cast to unsigned char before tolower() to avoid UB on signed char */
		c = (char)tolower((unsigned char)str[i]);
		if_assert_fails((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
			return NULL;
		val |= ((c - '0') < 0xa) ? (c - '0') : (c - 'a' + 0xa);
		if (i % 2)
			ret[i / 2] = val;
	}
	return ret;
}

/**
 * IsBufferInDB() - check whether a buffer's SHA-256 hash appears in the hash DB
 * @buf:  Buffer to hash
 * @len:  Buffer size in bytes
 *
 * Returns TRUE if the hash matches any entry in sha256db[].
 */
BOOL IsBufferInDB(const unsigned char *buf, const size_t len)
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

/**
 * IsFileInDB() - check whether a file's SHA-256 hash appears in the hash DB
 * @path:  Path to file
 *
 * Returns TRUE if the hash matches any entry in sha256db[].
 */
BOOL IsFileInDB(const char *path)
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

/**
 * FileMatchesHash() - check whether a file's SHA-256 matches a given hex string
 * @path:  Path to file
 * @str:   Expected hash as a hex string
 *
 * Returns TRUE on match.
 */
BOOL FileMatchesHash(const char *path, const char *str)
{
	uint8_t hash[SHA256_HASHSIZE];
	if (!HashFile(HASH_SHA256, path, hash))
		return FALSE;
	return (memcmp(hash, StringToHash(str), SHA256_HASHSIZE) == 0);
}

/**
 * BufferMatchesHash() - check whether a buffer's SHA-256 matches a given hex string
 * @buf:  Buffer to hash
 * @len:  Buffer size in bytes
 * @str:  Expected hash as a hex string
 *
 * Returns TRUE on match.  Returns FALSE immediately if @buf or @str is NULL.
 */
BOOL BufferMatchesHash(const uint8_t *buf, const size_t len, const char *str)
{
	uint8_t hash[SHA256_HASHSIZE];
	if (buf == NULL || str == NULL)
		return FALSE;
	if (!HashBuffer(HASH_SHA256, buf, len, hash))
		return FALSE;
	return (memcmp(hash, StringToHash(str), SHA256_HASHSIZE) == 0);
}
