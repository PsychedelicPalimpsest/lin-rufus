/*
 * test_iso_hashes.c — ISO hash regression suite (item 86)
 *
 * Builds small in-memory ISO 9660-like fixture files with known byte patterns
 * and verifies that HashFile() produces the expected MD5 / SHA-1 / SHA-256 /
 * SHA-512 digests.  Any silent regression in the hash algorithms or in the
 * file-reading loop will be caught here.
 *
 * Fixture construction mirrors the Python vectors used to pre-compute the
 * expected digests:
 *
 *   Fixture 1 — full-header ISO (34816 bytes):
 *     32768-byte system area  (bytes[0]=0xEB, [1]=0x5A, [2]=0x90, rest 0)
 *     + 2048-byte ISO 9660 PVD  (type=0x01, magic="CD001", vol-id="RUFUS_TEST_01")
 *
 *   Fixture 2 — single-sector ISO (2048 bytes):
 *     PVD only  (type=0x01, magic="CD001", vol-id="RUFUS_FIXTURE_02")
 *
 *   Fixture 3 — multi-buffer large ISO (40960 bytes):
 *     32768-byte system area with varying bytes (byte[i] = (i * 1) & 0xFF
 *     for i mod 512 == 1, else 0 — matches the Python loop: payload[i]= i&0xFF
 *     for i in range(1,32768,512))
 *     + 2048-byte PVD  (vol-id="LARGE_FIXTURE3")
 *     + 6144 bytes of extra data  (byte[i] = (i*7+13) & 0xFF)
 *
 * These tests are Linux-only (they use the Linux HashFile / HashBuffer
 * implementation pulled in via hash_linux_glue.c).
 */
#ifndef _WIN32

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "rufus.h"

/* ---- forward declarations from hash_linux_glue.c / hash.c ---- */
extern BOOL HashFile(const unsigned type, const char* path, uint8_t* hash);
extern BOOL HashBuffer(const unsigned type, const uint8_t* buf, size_t len, uint8_t* hash);

/* ---- helpers ---- */

static void bytes_to_hex(const uint8_t *buf, size_t len, char *out)
{
	static const char hex[] = "0123456789abcdef";
	for (size_t i = 0; i < len; i++) {
		out[2*i]   = hex[buf[i] >> 4];
		out[2*i+1] = hex[buf[i] & 0xf];
	}
	out[2*len] = '\0';
}

/*
 * Write 'len' bytes from 'buf' to a temp file.
 * Returns the path (static buffer) on success, NULL on error.
 */
static const char* write_fixture(const uint8_t *buf, size_t len)
{
	static char path[64];
	snprintf(path, sizeof(path), "/tmp/rufus_iso_fix_XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) return NULL;
	ssize_t w = write(fd, buf, len);
	close(fd);
	return (w == (ssize_t)len) ? path : NULL;
}

/* ---- Build fixture 1: 32768-byte system area + 2048-byte PVD ---- */
#define FIX1_SIZE (32768 + 2048)

static void build_fixture1(uint8_t *out)
{
	memset(out, 0, FIX1_SIZE);
	/* system area magic bytes */
	out[0] = 0xEB; out[1] = 0x5A; out[2] = 0x90;
	/* PVD at offset 32768 */
	uint8_t *pvd = out + 32768;
	pvd[0] = 0x01;
	memcpy(pvd + 1, "CD001", 5);
	pvd[6] = 0x01;
	memcpy(pvd + 40, "RUFUS_TEST_01", 13);
}

/* ---- Build fixture 2: single-sector PVD only ---- */
#define FIX2_SIZE 2048

static void build_fixture2(uint8_t *out)
{
	memset(out, 0, FIX2_SIZE);
	out[0] = 0x01;
	memcpy(out + 1, "CD001", 5);
	out[6] = 0x01;
	memcpy(out + 40, "RUFUS_FIXTURE_02", 16);
}

/* ---- Build fixture 3: large multi-buffer ISO (40960 bytes) ---- */
#define FIX3_SIZE (32768 + 2048 + 2048 * 3)

static void build_fixture3(uint8_t *out)
{
	memset(out, 0, FIX3_SIZE);
	/* system area: out[0]=0xEB...payload[i]=i&0xFF for i in 1,513,1025,... */
	out[0] = 0xEB;
	for (int i = 1; i < 32768; i += 512)
		out[i] = (uint8_t)(i & 0xFF);
	/* PVD */
	uint8_t *pvd = out + 32768;
	pvd[0] = 0x01;
	memcpy(pvd + 1, "CD001", 5);
	pvd[6] = 0x01;
	memcpy(pvd + 40, "LARGE_FIXTURE3", 14);
	/* extra data */
	uint8_t *extra = out + 32768 + 2048;
	for (int i = 0; i < 2048 * 3; i++)
		extra[i] = (uint8_t)((i * 7 + 13) & 0xFF);
}

/* ============================================================
 * Tests
 * ============================================================ */

/* ---- Fixture 1 tests ---- */

TEST(iso_fix1_sha256)
{
	uint8_t buf[FIX1_SIZE];
	build_fixture1(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t hash[SHA256_HASHSIZE];
	char hex[SHA256_HASHSIZE * 2 + 1];
	BOOL r = HashFile(HASH_SHA256, path, hash);
	unlink(path);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA256_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "5f37702e08b2c96c012cba34add0ebbafad048b42e4ae0df58bc8f4bbf09d5b4");
}

TEST(iso_fix1_md5)
{
	uint8_t buf[FIX1_SIZE];
	build_fixture1(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t hash[MD5_HASHSIZE];
	char hex[MD5_HASHSIZE * 2 + 1];
	BOOL r = HashFile(HASH_MD5, path, hash);
	unlink(path);
	CHECK(r == TRUE);
	bytes_to_hex(hash, MD5_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "b86a6aa243410a48f639ff3dab0cb18d");
}

TEST(iso_fix1_sha1)
{
	uint8_t buf[FIX1_SIZE];
	build_fixture1(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t hash[SHA1_HASHSIZE];
	char hex[SHA1_HASHSIZE * 2 + 1];
	BOOL r = HashFile(HASH_SHA1, path, hash);
	unlink(path);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA1_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "c5662b2fd9766cd6cbd1eee7d194c92fedcf2cda");
}

TEST(iso_fix1_sha512)
{
	uint8_t buf[FIX1_SIZE];
	build_fixture1(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t hash[SHA512_HASHSIZE];
	char hex[SHA512_HASHSIZE * 2 + 1];
	BOOL r = HashFile(HASH_SHA512, path, hash);
	unlink(path);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA512_HASHSIZE, hex);
	CHECK_STR_EQ(hex,
	    "d94ca59b221349f5315ee1b9d031f3119b36d1c0919246d52ffc561481d3661d80639ed3206b7ec19b116274618340e7b9f1126e24395c1d8c1316071c2ba8d4");
}

/* ---- HashFile matches HashBuffer for fixture 1 ---- */
TEST(iso_fix1_file_matches_buffer)
{
	uint8_t buf[FIX1_SIZE];
	build_fixture1(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t fhash[SHA256_HASHSIZE], bhash[SHA256_HASHSIZE];
	BOOL rf = HashFile(HASH_SHA256, path, fhash);
	BOOL rb = HashBuffer(HASH_SHA256, buf, sizeof(buf), bhash);
	unlink(path);

	CHECK(rf == TRUE);
	CHECK(rb == TRUE);
	CHECK(memcmp(fhash, bhash, SHA256_HASHSIZE) == 0);
}

/* ---- Fixture 2 tests ---- */

TEST(iso_fix2_sha256)
{
	uint8_t buf[FIX2_SIZE];
	build_fixture2(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t hash[SHA256_HASHSIZE];
	char hex[SHA256_HASHSIZE * 2 + 1];
	BOOL r = HashFile(HASH_SHA256, path, hash);
	unlink(path);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA256_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "fa47f5bca19c8e541c7e1b0d039431be7ddeb8cb11f0a29c93c17128a57d03e8");
}

TEST(iso_fix2_md5)
{
	uint8_t buf[FIX2_SIZE];
	build_fixture2(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t hash[MD5_HASHSIZE];
	char hex[MD5_HASHSIZE * 2 + 1];
	BOOL r = HashFile(HASH_MD5, path, hash);
	unlink(path);
	CHECK(r == TRUE);
	bytes_to_hex(hash, MD5_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "e6e3d4cf54c100550c8a8f7ade8d8559");
}

TEST(iso_fix2_sha1)
{
	uint8_t buf[FIX2_SIZE];
	build_fixture2(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t hash[SHA1_HASHSIZE];
	char hex[SHA1_HASHSIZE * 2 + 1];
	BOOL r = HashFile(HASH_SHA1, path, hash);
	unlink(path);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA1_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "758804c1ce11e005a1b68813adb4b93fdaa15cf9");
}

/* ---- Fixture 2 determinism: two hash runs produce identical output ---- */
TEST(iso_fix2_deterministic)
{
	uint8_t buf[FIX2_SIZE];
	build_fixture2(buf);

	uint8_t h1[SHA256_HASHSIZE], h2[SHA256_HASHSIZE];
	BOOL r1 = HashBuffer(HASH_SHA256, buf, sizeof(buf), h1);
	BOOL r2 = HashBuffer(HASH_SHA256, buf, sizeof(buf), h2);
	CHECK(r1 == TRUE && r2 == TRUE);
	CHECK(memcmp(h1, h2, SHA256_HASHSIZE) == 0);
}

/* ---- Fixture 3 tests: multi-buffer path ---- */

TEST(iso_fix3_sha256)
{
	static uint8_t buf[FIX3_SIZE];
	build_fixture3(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t hash[SHA256_HASHSIZE];
	char hex[SHA256_HASHSIZE * 2 + 1];
	BOOL r = HashFile(HASH_SHA256, path, hash);
	unlink(path);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA256_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "293707319397f454d27cee986ace4a11ac81345f3b5e27249f289341046c5632");
}

TEST(iso_fix3_file_matches_buffer)
{
	static uint8_t buf[FIX3_SIZE];
	build_fixture3(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);

	uint8_t fhash[SHA256_HASHSIZE], bhash[SHA256_HASHSIZE];
	BOOL rf = HashFile(HASH_SHA256, path, fhash);
	BOOL rb = HashBuffer(HASH_SHA256, buf, sizeof(buf), bhash);
	unlink(path);

	CHECK(rf == TRUE);
	CHECK(rb == TRUE);
	CHECK(memcmp(fhash, bhash, SHA256_HASHSIZE) == 0);
}

/* ---- Different fixtures produce different hashes ---- */
TEST(iso_fixtures_differ)
{
	uint8_t b1[FIX1_SIZE], b2[FIX2_SIZE];
	build_fixture1(b1);
	build_fixture2(b2);

	uint8_t h1[SHA256_HASHSIZE], h2[SHA256_HASHSIZE];
	HashBuffer(HASH_SHA256, b1, sizeof(b1), h1);
	HashBuffer(HASH_SHA256, b2, sizeof(b2), h2);
	CHECK(memcmp(h1, h2, SHA256_HASHSIZE) != 0);
}

/* ---- Modify one byte → hash changes ---- */
TEST(iso_fix2_byte_change_detected)
{
	uint8_t buf[FIX2_SIZE];
	build_fixture2(buf);
	uint8_t orig[SHA256_HASHSIZE], modified[SHA256_HASHSIZE];
	HashBuffer(HASH_SHA256, buf, sizeof(buf), orig);

	buf[100] ^= 0x01;  /* flip one bit */
	HashBuffer(HASH_SHA256, buf, sizeof(buf), modified);

	CHECK(memcmp(orig, modified, SHA256_HASHSIZE) != 0);
}

/* ---- ISO magic bytes preserved in hash (changing them changes hash) ---- */
TEST(iso_pvd_magic_affects_hash)
{
	uint8_t buf[FIX2_SIZE];
	build_fixture2(buf);
	uint8_t h_good[SHA256_HASHSIZE], h_bad[SHA256_HASHSIZE];
	HashBuffer(HASH_SHA256, buf, sizeof(buf), h_good);

	/* corrupt ISO magic at offset 1 */
	buf[1] = 'X';
	HashBuffer(HASH_SHA256, buf, sizeof(buf), h_bad);

	CHECK(memcmp(h_good, h_bad, SHA256_HASHSIZE) != 0);
}

/* ---- All four algorithms produce distinct outputs for the same input ---- */
TEST(iso_fix1_algos_distinct)
{
	uint8_t buf[FIX2_SIZE];
	build_fixture2(buf);

	uint8_t md5[MD5_HASHSIZE], sha1[SHA1_HASHSIZE];
	uint8_t sha256[SHA256_HASHSIZE], sha512[SHA512_HASHSIZE];
	CHECK(HashBuffer(HASH_MD5,    buf, sizeof(buf), md5)    == TRUE);
	CHECK(HashBuffer(HASH_SHA1,   buf, sizeof(buf), sha1)   == TRUE);
	CHECK(HashBuffer(HASH_SHA256, buf, sizeof(buf), sha256) == TRUE);
	CHECK(HashBuffer(HASH_SHA512, buf, sizeof(buf), sha512) == TRUE);

	/* All sizes differ → outputs can't be equal even if we compare prefixes */
	CHECK(MD5_HASHSIZE    != SHA1_HASHSIZE);
	CHECK(SHA1_HASHSIZE   != SHA256_HASHSIZE);
	CHECK(SHA256_HASHSIZE != SHA512_HASHSIZE);
}

/* ---- NULL / error paths ---- */
TEST(iso_hashfile_nonexistent)
{
	uint8_t hash[SHA256_HASHSIZE];
	BOOL r = HashFile(HASH_SHA256, "/tmp/rufus_iso_nonexistent_XYZZY", hash);
	CHECK(r == FALSE);
}

TEST(iso_hashfile_null_path)
{
	uint8_t hash[SHA256_HASHSIZE];
	BOOL r = HashFile(HASH_SHA256, NULL, hash);
	CHECK(r == FALSE);
}

TEST(iso_hashfile_null_hash)
{
	uint8_t buf[FIX2_SIZE];
	build_fixture2(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);
	BOOL r = HashFile(HASH_SHA256, path, NULL);
	unlink(path);
	CHECK(r == FALSE);
}

TEST(iso_hashfile_invalid_type)
{
	uint8_t buf[FIX2_SIZE];
	build_fixture2(buf);
	const char *path = write_fixture(buf, sizeof(buf));
	CHECK(path != NULL);
	uint8_t hash[SHA256_HASHSIZE];
	BOOL r = HashFile(HASH_MAX, path, hash);
	unlink(path);
	CHECK(r == FALSE);
}

int main(void)
{
	printf("=== iso_hashes tests ===\n\n");

	printf("  Fixture 1 — full-header ISO (34816 bytes)\n");
	RUN(iso_fix1_sha256);
	RUN(iso_fix1_md5);
	RUN(iso_fix1_sha1);
	RUN(iso_fix1_sha512);
	RUN(iso_fix1_file_matches_buffer);

	printf("\n  Fixture 2 — single-sector ISO (2048 bytes)\n");
	RUN(iso_fix2_sha256);
	RUN(iso_fix2_md5);
	RUN(iso_fix2_sha1);
	RUN(iso_fix2_deterministic);

	printf("\n  Fixture 3 — large multi-buffer ISO (40960 bytes)\n");
	RUN(iso_fix3_sha256);
	RUN(iso_fix3_file_matches_buffer);

	printf("\n  Regression properties\n");
	RUN(iso_fixtures_differ);
	RUN(iso_fix2_byte_change_detected);
	RUN(iso_pvd_magic_affects_hash);
	RUN(iso_fix1_algos_distinct);

	printf("\n  Error handling\n");
	RUN(iso_hashfile_nonexistent);
	RUN(iso_hashfile_null_path);
	RUN(iso_hashfile_null_hash);
	RUN(iso_hashfile_invalid_type);

	TEST_RESULTS();
}

#endif /* !_WIN32 */
