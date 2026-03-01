/*
 * test_hash.c — Tests for HashBuffer, HashFile, and HashThread
 *
 * Tests the core hash computation (HashBuffer, HashFile) using known NIST/RFC
 * test vectors.  These tests must pass on both Linux and Windows.
 *
 * HashThread / IndividualHashThread tests are Linux-only (they use pthreads
 * under the hood via the Windows threading compat layer).
 */
#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Pull in the rufus type definitions and hash API */
#include "rufus.h"

/* ---- Helpers ---- */

/* Format a hash buffer as a lowercase hex string into 'out' (must be >= 2*len+1 bytes). */
static void bytes_to_hex(const uint8_t* buf, size_t len, char* out)
{
	static const char hex[] = "0123456789abcdef";
	for (size_t i = 0; i < len; i++) {
		out[2*i]   = hex[buf[i] >> 4];
		out[2*i+1] = hex[buf[i] & 0xf];
	}
	out[2*len] = '\0';
}

/* ---- Known-vector tests for HashBuffer ---- */

/* MD5("") = d41d8cd98f00b204e9800998ecf8427e */
TEST(hashbuf_md5_empty)
{
	uint8_t hash[MD5_HASHSIZE];
	char hex[MD5_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_MD5, (const uint8_t*)"", 0, hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, MD5_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "d41d8cd98f00b204e9800998ecf8427e");
}

/* MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 */
TEST(hashbuf_md5_abc)
{
	uint8_t hash[MD5_HASHSIZE];
	char hex[MD5_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_MD5, (const uint8_t*)"abc", 3, hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, MD5_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "900150983cd24fb0d6963f7d28e17f72");
}

/* MD5("The quick brown fox jumps over the lazy dog")
   = 9e107d9d372bb6826bd81d3542a419d6 */
TEST(hashbuf_md5_fox)
{
	static const char msg[] = "The quick brown fox jumps over the lazy dog";
	uint8_t hash[MD5_HASHSIZE];
	char hex[MD5_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_MD5, (const uint8_t*)msg, strlen(msg), hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, MD5_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "9e107d9d372bb6826bd81d3542a419d6");
}

/* SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d */
TEST(hashbuf_sha1_abc)
{
	uint8_t hash[SHA1_HASHSIZE];
	char hex[SHA1_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_SHA1, (const uint8_t*)"abc", 3, hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA1_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
}

/* SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709 */
TEST(hashbuf_sha1_empty)
{
	uint8_t hash[SHA1_HASHSIZE];
	char hex[SHA1_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_SHA1, (const uint8_t*)"", 0, hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA1_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

/* SHA1("The quick brown fox jumps over the lazy dog")
   = 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 */
TEST(hashbuf_sha1_fox)
{
	static const char msg[] = "The quick brown fox jumps over the lazy dog";
	uint8_t hash[SHA1_HASHSIZE];
	char hex[SHA1_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_SHA1, (const uint8_t*)msg, strlen(msg), hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA1_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
}

/* SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
TEST(hashbuf_sha256_abc)
{
	uint8_t hash[SHA256_HASHSIZE];
	char hex[SHA256_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_SHA256, (const uint8_t*)"abc", 3, hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA256_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

/* SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
TEST(hashbuf_sha256_empty)
{
	uint8_t hash[SHA256_HASHSIZE];
	char hex[SHA256_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_SHA256, (const uint8_t*)"", 0, hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA256_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

/* SHA256("The quick brown fox jumps over the lazy dog")
   = d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592 */
TEST(hashbuf_sha256_fox)
{
	static const char msg[] = "The quick brown fox jumps over the lazy dog";
	uint8_t hash[SHA256_HASHSIZE];
	char hex[SHA256_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_SHA256, (const uint8_t*)msg, strlen(msg), hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA256_HASHSIZE, hex);
	CHECK_STR_EQ(hex, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
}

/* SHA512("abc")
   = ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
     2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f */
TEST(hashbuf_sha512_abc)
{
	uint8_t hash[SHA512_HASHSIZE];
	char hex[SHA512_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_SHA512, (const uint8_t*)"abc", 3, hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA512_HASHSIZE, hex);
	CHECK_STR_EQ(hex,
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

/* SHA512("") = cf83e135... */
TEST(hashbuf_sha512_empty)
{
	uint8_t hash[SHA512_HASHSIZE];
	char hex[SHA512_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_SHA512, (const uint8_t*)"", 0, hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA512_HASHSIZE, hex);
	CHECK_STR_EQ(hex,
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

/* SHA512("The quick brown fox...") */
TEST(hashbuf_sha512_fox)
{
	static const char msg[] = "The quick brown fox jumps over the lazy dog";
	uint8_t hash[SHA512_HASHSIZE];
	char hex[SHA512_HASHSIZE * 2 + 1];
	BOOL r = HashBuffer(HASH_SHA512, (const uint8_t*)msg, strlen(msg), hash);
	CHECK(r == TRUE);
	bytes_to_hex(hash, SHA512_HASHSIZE, hex);
	CHECK_STR_EQ(hex,
		"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64"
		"2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
}

/* ---- Error handling ---- */
TEST(hashbuf_null_hash_ptr)
{
	BOOL r = HashBuffer(HASH_MD5, (const uint8_t*)"abc", 3, NULL);
	CHECK(r == FALSE);
}

TEST(hashbuf_invalid_type)
{
	uint8_t hash[MD5_HASHSIZE];
	BOOL r = HashBuffer(HASH_MAX, (const uint8_t*)"abc", 3, hash);
	CHECK(r == FALSE);
}

/* ---- HashFile tests ---- */

/* Write known content to a temp file, then hash it, compare to HashBuffer result. */
static char tmp_path[256];

static void make_tmp_file(const char* content, size_t len)
{
	snprintf(tmp_path, sizeof(tmp_path), "/tmp/test_hash_XXXXXX");
	int fd = mkstemp(tmp_path);
	if (fd < 0) { tmp_path[0] = '\0'; return; }
	ssize_t written = write(fd, content, len);
	(void)written;
	close(fd);
}

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

TEST(hashfile_md5_abc)
{
	make_tmp_file("abc", 3);
	if (tmp_path[0] == '\0') { CHECK(0); return; }

	uint8_t fhash[MD5_HASHSIZE], bhash[MD5_HASHSIZE];
	char fhex[MD5_HASHSIZE * 2 + 1], bhex[MD5_HASHSIZE * 2 + 1];

	BOOL fr = HashFile(HASH_MD5, tmp_path, fhash);
	BOOL br = HashBuffer(HASH_MD5, (const uint8_t*)"abc", 3, bhash);

	CHECK(fr == TRUE);
	CHECK(br == TRUE);
	bytes_to_hex(fhash, MD5_HASHSIZE, fhex);
	bytes_to_hex(bhash, MD5_HASHSIZE, bhex);
	CHECK_STR_EQ(fhex, bhex);

	unlink(tmp_path);
}

TEST(hashfile_sha256_fox)
{
	static const char msg[] = "The quick brown fox jumps over the lazy dog";
	make_tmp_file(msg, strlen(msg));
	if (tmp_path[0] == '\0') { CHECK(0); return; }

	uint8_t fhash[SHA256_HASHSIZE], bhash[SHA256_HASHSIZE];
	char fhex[SHA256_HASHSIZE * 2 + 1], bhex[SHA256_HASHSIZE * 2 + 1];

	BOOL fr = HashFile(HASH_SHA256, tmp_path, fhash);
	BOOL br = HashBuffer(HASH_SHA256, (const uint8_t*)msg, strlen(msg), bhash);

	CHECK(fr == TRUE);
	CHECK(br == TRUE);
	bytes_to_hex(fhash, SHA256_HASHSIZE, fhex);
	bytes_to_hex(bhash, SHA256_HASHSIZE, bhex);
	CHECK_STR_EQ(fhex, bhex);

	unlink(tmp_path);
}

TEST(hashfile_nonexistent)
{
	uint8_t hash[SHA256_HASHSIZE];
	BOOL r = HashFile(HASH_SHA256, "/tmp/this_file_does_not_exist_rufus_test", hash);
	CHECK(r == FALSE);
}

TEST(hashfile_null_path)
{
	uint8_t hash[SHA256_HASHSIZE];
	BOOL r = HashFile(HASH_SHA256, NULL, hash);
	CHECK(r == FALSE);
}

TEST(hashfile_null_hash)
{
	make_tmp_file("abc", 3);
	if (tmp_path[0] == '\0') { CHECK(0); return; }
	BOOL r = HashFile(HASH_MD5, tmp_path, NULL);
	CHECK(r == FALSE);
	unlink(tmp_path);
}

/* ---- BufferMatchesHash ---- */
TEST(buffer_matches_hash_md5)
{
	/* MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 */
	BOOL r = BufferMatchesHash((const uint8_t*)"abc", 3,
	                           "900150983cd24fb0d6963f7d28e17f72");
	CHECK(r == TRUE);
}

TEST(buffer_matches_hash_wrong)
{
	BOOL r = BufferMatchesHash((const uint8_t*)"abc", 3,
	                           "ffffffffffffffffffffffffffffffff");
	CHECK(r == FALSE);
}

TEST(buffer_matches_hash_sha256)
{
	static const char msg[] = "The quick brown fox jumps over the lazy dog";
	BOOL r = BufferMatchesHash((const uint8_t*)msg, strlen(msg),
	    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
	CHECK(r == TRUE);
}

TEST(buffer_matches_hash_null_buf)
{
	BOOL r = BufferMatchesHash(NULL, 0, "900150983cd24fb0d6963f7d28e17f72");
	CHECK(r == FALSE);
}

TEST(buffer_matches_hash_null_str)
{
	BOOL r = BufferMatchesHash((const uint8_t*)"abc", 3, NULL);
	CHECK(r == FALSE);
}

/* ---- DetectSHA*Acceleration (just check it doesn't crash) ---- */
TEST(detect_sha1_accel)
{
	/* Just verify the function runs without crashing and returns BOOL */
	BOOL r = DetectSHA1Acceleration();
	CHECK(r == TRUE || r == FALSE); /* Either is valid */
}

TEST(detect_sha256_accel)
{
	BOOL r = DetectSHA256Acceleration();
	CHECK(r == TRUE || r == FALSE);
}

/* ---- hash_init/write/final tables are populated ---- */
TEST(hash_tables_populated)
{
	CHECK(hash_init[HASH_MD5]    != NULL);
	CHECK(hash_init[HASH_SHA1]   != NULL);
	CHECK(hash_init[HASH_SHA256] != NULL);
	CHECK(hash_init[HASH_SHA512] != NULL);
	CHECK(hash_write[HASH_MD5]    != NULL);
	CHECK(hash_write[HASH_SHA1]   != NULL);
	CHECK(hash_write[HASH_SHA256] != NULL);
	CHECK(hash_write[HASH_SHA512] != NULL);
	CHECK(hash_final[HASH_MD5]    != NULL);
	CHECK(hash_final[HASH_SHA1]   != NULL);
	CHECK(hash_final[HASH_SHA256] != NULL);
	CHECK(hash_final[HASH_SHA512] != NULL);
}

/* ====================================================================
 * HashThread / IndividualHashThread tests (Linux only)
 *
 * HashThread reads image_path, spawns IndividualHashThread workers for
 * MD5/SHA1/SHA256 (and optionally SHA512), and populates hash_str[].
 * ==================================================================== */
#ifdef __linux__

#include <pthread.h>

/*
 * Globals declared extern in rufus.h — defined in hash_linux_glue.c for
 * the test build.
 */
extern char*  image_path;
extern char   hash_str[HASH_MAX][150];
extern BOOL   enable_extra_hashes;
extern RUFUS_IMG_REPORT img_report;
extern DWORD  ErrorStatus;
extern BOOL   validate_md5sum;
extern uint64_t md5sum_totalbytes;
extern StrArray modified_files;

/* Forward declarations for PE256Buffer / efi_image_parse (defined in hash.c) */
struct image_region { const uint8_t *data; uint32_t size; };
struct efi_image_regions { int max; int num; struct image_region reg[]; };
extern BOOL efi_image_parse(uint8_t *efi, size_t len, struct efi_image_regions **regp);
extern BOOL PE256Buffer(uint8_t *buf, uint32_t len, uint8_t *hash);

/* Build a minimal 1024-byte PE32+ image suitable for PE256Buffer testing */
static uint8_t *make_pe64(size_t *out_len)
{
	const size_t total = 1024;
	const DWORD hdr_size = 512;    /* SizeOfHeaders, file-aligned */
	const DWORD file_align = 512;
	const size_t nt_off = 64;      /* e_lfanew */

	uint8_t *buf = calloc(total, 1);
	if (!buf) return NULL;

	IMAGE_DOS_HEADER *dos = (void *)buf;
	dos->e_magic = IMAGE_DOS_SIGNATURE;
	dos->e_lfanew = (LONG)nt_off;

	IMAGE_NT_HEADERS64 *nt = (void *)(buf + nt_off);
	nt->Signature = IMAGE_NT_SIGNATURE;
	nt->FileHeader.Machine = 0x8664;
	nt->FileHeader.NumberOfSections = 1;
	nt->FileHeader.SizeOfOptionalHeader = (WORD)sizeof(IMAGE_OPTIONAL_HEADER64);

	IMAGE_OPTIONAL_HEADER64 *opt = &nt->OptionalHeader;
	opt->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	opt->FileAlignment = file_align;
	opt->SectionAlignment = 0x1000;
	opt->SizeOfHeaders = hdr_size;
	opt->SizeOfImage = (DWORD)total;
	opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	/* DataDirectory zeroed → security entry size=0, so no auth trailer */

	/* Section header follows the optional header */
	size_t sec_hdr_off = nt_off + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
	IMAGE_SECTION_HEADER *sec = (void *)(buf + sec_hdr_off);
	memcpy(sec->Name, ".text\0\0\0", 8);
	sec->SizeOfRawData = 512;
	sec->PointerToRawData = 512;
	sec->VirtualAddress = 0x1000;
	sec->Misc.VirtualSize = 512;
	/* fill section data with a known pattern for determinism */
	memset(buf + 512, 0xAA, 512);

	*out_len = total;
	return buf;
}

/* Helper: create a temp file and fill it with 'content' bytes */
static char ht_tmp[256];

static int make_ht_file(const void* content, size_t len)
{
	snprintf(ht_tmp, sizeof(ht_tmp), "/tmp/test_ht_XXXXXX");
	int fd = mkstemp(ht_tmp);
	if (fd < 0) return -1;
	if (len > 0) {
		ssize_t w = write(fd, content, len);
		if (w != (ssize_t)len) { close(fd); unlink(ht_tmp); return -1; }
	}
	close(fd);
	return 0;
}

/*
 * Run HashThread synchronously: set up globals, spawn HashThread, wait
 * for completion, return the thread exit code (0 = success, 1 = failure).
 *
 * 'affinity' is passed as the thread parameter.  Pass a zeroed array to
 * request no CPU affinity restrictions.
 */
static int run_hash_thread_with_affinity(DWORD_PTR* affinity)
{
	HANDLE t = CreateThread(NULL, 0, HashThread, affinity, 0, NULL);
	if (t == NULL) return -1;
	WaitForSingleObject(t, 30000);  /* up to 30 s */
	DWORD code = 1;
	GetExitCodeThread(t, &code);
	CloseHandle(t);
	return (int)code;
}

static DWORD_PTR zero_affinity[HASH_MAX + 1]; /* all zeros */

static int run_hash_thread(void)
{
	memset(zero_affinity, 0, sizeof(zero_affinity));
	return run_hash_thread_with_affinity(zero_affinity);
}

/* ---- NULL image_path ---- */
TEST(hashthread_null_path)
{
	image_path = NULL;
	ErrorStatus = 0;
	int r = run_hash_thread();
	/* Must fail; exit code non-zero */
	CHECK(r != 0);
}

/* ---- Non-existent file ---- */
TEST(hashthread_nonexistent_file)
{
	image_path = "/tmp/this_file_does_not_exist_rufus_ht_test";
	ErrorStatus = 0;
	memset(hash_str, 0, sizeof(hash_str));
	enable_extra_hashes = FALSE;
	img_report.image_size = 0;
	int r = run_hash_thread();
	CHECK(r != 0);
}

/* ---- Basic: "abc" — verify MD5, SHA1, SHA256 strings ---- */
TEST(hashthread_basic_abc)
{
	if (make_ht_file("abc", 3) < 0) { CHECK(0); return; }
	image_path = ht_tmp;
	ErrorStatus = 0;
	memset(hash_str, 0, sizeof(hash_str));
	enable_extra_hashes = FALSE;
	img_report.image_size = 3;

	int r = run_hash_thread();
	CHECK(r == 0);

	/* MD5("abc") */
	CHECK_STR_EQ(hash_str[HASH_MD5],    "900150983cd24fb0d6963f7d28e17f72");
	/* SHA1("abc") */
	CHECK_STR_EQ(hash_str[HASH_SHA1],   "a9993e364706816aba3e25717850c26c9cd0d89d");
	/* SHA256("abc") */
	CHECK_STR_EQ(hash_str[HASH_SHA256],
	    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	/* SHA512 not requested — should be empty */
	CHECK(hash_str[HASH_SHA512][0] == '\0');

	unlink(ht_tmp);
}

/* ---- With extra hashes: also verify SHA512 ---- */
TEST(hashthread_with_sha512)
{
	if (make_ht_file("abc", 3) < 0) { CHECK(0); return; }
	image_path = ht_tmp;
	ErrorStatus = 0;
	memset(hash_str, 0, sizeof(hash_str));
	enable_extra_hashes = TRUE;
	img_report.image_size = 3;

	int r = run_hash_thread();
	CHECK(r == 0);

	CHECK_STR_EQ(hash_str[HASH_MD5],    "900150983cd24fb0d6963f7d28e17f72");
	CHECK_STR_EQ(hash_str[HASH_SHA256],
	    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	/* SHA512("abc") */
	CHECK_STR_EQ(hash_str[HASH_SHA512],
	    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
	    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

	enable_extra_hashes = FALSE;
	unlink(ht_tmp);
}

/* ---- Empty file ---- */
TEST(hashthread_empty_file)
{
	if (make_ht_file("", 0) < 0) { CHECK(0); return; }
	image_path = ht_tmp;
	ErrorStatus = 0;
	memset(hash_str, 0, sizeof(hash_str));
	enable_extra_hashes = FALSE;
	img_report.image_size = 0;

	int r = run_hash_thread();
	CHECK(r == 0);

	CHECK_STR_EQ(hash_str[HASH_MD5],   "d41d8cd98f00b204e9800998ecf8427e");
	CHECK_STR_EQ(hash_str[HASH_SHA1],  "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	CHECK_STR_EQ(hash_str[HASH_SHA256],
	    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	unlink(ht_tmp);
}

/* ---- Large file (> BUFFER_SIZE = 64 KiB) ---- */
#define HT_LARGE_SIZE (96 * 1024)  /* 96 KiB — 1.5 × BUFFER_SIZE */

TEST(hashthread_large_file)
{
	/* Build a buffer filled with a repeating pattern */
	static uint8_t big[HT_LARGE_SIZE];
	for (size_t i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)(i & 0xFF);

	if (make_ht_file(big, sizeof(big)) < 0) { CHECK(0); return; }
	image_path = ht_tmp;
	ErrorStatus = 0;
	memset(hash_str, 0, sizeof(hash_str));
	enable_extra_hashes = FALSE;
	img_report.image_size = sizeof(big);

	int r = run_hash_thread();
	CHECK(r == 0);

	/* Compare MD5 and SHA256 against HashBuffer on the same data */
	uint8_t expected_md5[MD5_HASHSIZE], expected_sha256[SHA256_HASHSIZE];
	HashBuffer(HASH_MD5,    big, sizeof(big), expected_md5);
	HashBuffer(HASH_SHA256, big, sizeof(big), expected_sha256);

	char exp_md5_hex[MD5_HASHSIZE * 2 + 1];
	char exp_sha256_hex[SHA256_HASHSIZE * 2 + 1];
	bytes_to_hex(expected_md5,    MD5_HASHSIZE,    exp_md5_hex);
	bytes_to_hex(expected_sha256, SHA256_HASHSIZE, exp_sha256_hex);

	CHECK_STR_EQ(hash_str[HASH_MD5],    exp_md5_hex);
	CHECK_STR_EQ(hash_str[HASH_SHA256], exp_sha256_hex);

	unlink(ht_tmp);
}

/* ---- "fox" message ---- */
TEST(hashthread_fox_message)
{
	static const char msg[] = "The quick brown fox jumps over the lazy dog";
	if (make_ht_file(msg, strlen(msg)) < 0) { CHECK(0); return; }
	image_path = ht_tmp;
	ErrorStatus = 0;
	memset(hash_str, 0, sizeof(hash_str));
	enable_extra_hashes = FALSE;
	img_report.image_size = strlen(msg);

	int r = run_hash_thread();
	CHECK(r == 0);

	CHECK_STR_EQ(hash_str[HASH_MD5],   "9e107d9d372bb6826bd81d3542a419d6");
	CHECK_STR_EQ(hash_str[HASH_SHA1],  "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
	CHECK_STR_EQ(hash_str[HASH_SHA256],
	    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");

	unlink(ht_tmp);
}

/* ---- IsBufferInDB returns FALSE for arbitrary buffers ---- */
TEST(hashthread_is_buffer_in_db_miss)
{
	BOOL r = IsBufferInDB((const unsigned char*)"abc", 3);
	/* "abc" is not in the hash DB — must return FALSE */
	CHECK(r == FALSE);
}

/* ---- IsFileInDB returns FALSE for a file with arbitrary content ---- */
TEST(hashthread_is_file_in_db_miss)
{
	if (make_ht_file("hello world", 11) < 0) { CHECK(0); return; }
	BOOL r = IsFileInDB(ht_tmp);
	CHECK(r == FALSE);
	unlink(ht_tmp);
}

/* ====================================================================
 * Hash dialog — hash_str content after successful HashThread run
 *
 * After HashThread completes, hash_str[] must contain valid hex strings
 * ready to display in a dialog.  UM_HASH_COMPLETED is posted to hMainDialog
 * (which is NULL in tests, so PostMessage is a silent no-op) to trigger
 * the GTK dialog on the main thread.
 * ==================================================================== */

/* Hash dialog: MD5/SHA1/SHA256 non-empty after success */
TEST(hash_dialog_strings_non_empty_after_run)
{
	if (make_ht_file("abc", 3) < 0) { CHECK(0); return; }
	image_path = ht_tmp;
	ErrorStatus = 0;
	memset(hash_str, 0, sizeof(hash_str));
	enable_extra_hashes = FALSE;
	img_report.image_size = 3;

	int r = run_hash_thread();
	CHECK_MSG(r == 0, "hash thread should succeed");

	/* These strings must be non-empty and look like hex */
	CHECK_MSG(hash_str[HASH_MD5][0] != '\0',    "MD5 must be populated");
	CHECK_MSG(hash_str[HASH_SHA1][0] != '\0',   "SHA1 must be populated");
	CHECK_MSG(hash_str[HASH_SHA256][0] != '\0', "SHA256 must be populated");
	/* Without extra hashes, SHA512 must be empty */
	CHECK_MSG(hash_str[HASH_SHA512][0] == '\0', "SHA512 must be empty without enable_extra_hashes");

	unlink(ht_tmp);
}

/* Hash dialog: SHA512 populated when enable_extra_hashes is set */
TEST(hash_dialog_sha512_populated_when_extra_enabled)
{
	if (make_ht_file("abc", 3) < 0) { CHECK(0); return; }
	image_path = ht_tmp;
	ErrorStatus = 0;
	memset(hash_str, 0, sizeof(hash_str));
	enable_extra_hashes = TRUE;
	img_report.image_size = 3;

	int r = run_hash_thread();
	CHECK_MSG(r == 0, "hash thread should succeed");
	CHECK_MSG(hash_str[HASH_SHA512][0] != '\0', "SHA512 must be populated with enable_extra_hashes");

	enable_extra_hashes = FALSE;  /* reset */
	unlink(ht_tmp);
}

/* Hash dialog: UM_HASH_COMPLETED constant is defined and distinct from UM_FORMAT_COMPLETED */
TEST(hash_dialog_um_hash_completed_constant)
{
	CHECK_MSG(UM_HASH_COMPLETED != UM_FORMAT_COMPLETED,
	          "UM_HASH_COMPLETED must differ from UM_FORMAT_COMPLETED");
	CHECK_MSG(UM_HASH_COMPLETED != 0,
	          "UM_HASH_COMPLETED must be non-zero");
}

/* ====================================================================
 * UpdateMD5Sum tests
 *
 * UpdateMD5Sum(dest_dir, md5sum_name):
 *  - reads dest_dir/md5sum_name
 *  - for each path in modified_files, finds the matching 32-hex entry
 *    and updates it in-place with the new MD5
 *  - writes the file back
 * ==================================================================== */

/* Write 'content' (null-terminated) to path */
static void write_str(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	if (!f) return;
	fputs(content, f);
	fclose(f);
}

/* Read full file into static buffer (≤ 4 KB for tests); returns pointer */
static char md5_rd_buf[4096];
static const char *read_str(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) { md5_rd_buf[0] = '\0'; return md5_rd_buf; }
	size_t n = fread(md5_rd_buf, 1, sizeof(md5_rd_buf) - 1, f);
	fclose(f);
	md5_rd_buf[n] = '\0';
	return md5_rd_buf;
}

/* Create a temp dir under /tmp; returns fd of a sentinel file (ignored),
 * path written to dir_out[64].  Caller must rmdir after cleanup. */
static void make_tmp_dir(char dir_out[64])
{
	snprintf(dir_out, 64, "/tmp/rufus_md5_XXXXXX");
	char *r = mkdtemp(dir_out);
	if (!r) dir_out[0] = '\0';
}

/* ---- no-op when has_md5sum is FALSE and validate_md5sum is FALSE ---- */
TEST(update_md5sum_noop_when_disabled)
{
	char dir[64];
	make_tmp_dir(dir);
	if (dir[0] == '\0') { CHECK(0); return; }

	/* Write a sentinel md5sum.txt — it must NOT be modified */
	char md5path[128];
	snprintf(md5path, sizeof(md5path), "%s/md5sum.txt", dir);
	write_str(md5path, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ./boot/grub.cfg\n");

	img_report.has_md5sum = FALSE;
	validate_md5sum = FALSE;
	StrArrayClear(&modified_files);

	UpdateMD5Sum(dir, "md5sum.txt");

	/* File content must be unchanged */
	const char *got = read_str(md5path);
	CHECK(strstr(got, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") != NULL);

	unlink(md5path);
	rmdir(dir);
}

/* ---- updates the MD5 entry for a modified file ---- */
TEST(update_md5sum_updates_hash)
{
	char dir[64];
	make_tmp_dir(dir);
	if (dir[0] == '\0') { CHECK(0); return; }

	/* Create a file with known content "abc" → MD5 = 900150983cd24fb0d6963f7d28e17f72 */
	char data_path[128];
	snprintf(data_path, sizeof(data_path), "%s/boot/grub.cfg", dir);
	mkdir("%s/boot", 0755); /* ignore error if exists */
	{
		char boot_dir[128];
		snprintf(boot_dir, sizeof(boot_dir), "%s/boot", dir);
		mkdir(boot_dir, 0755);
	}
	write_str(data_path, "abc");

	/* md5sum.txt has a wrong hash for this file */
	char md5path[128];
	snprintf(md5path, sizeof(md5path), "%s/md5sum.txt", dir);
	write_str(md5path, "00000000000000000000000000000000  ./boot/grub.cfg\n");

	img_report.has_md5sum = TRUE;
	validate_md5sum = FALSE;
	StrArrayClear(&modified_files);
	StrArrayCreate(&modified_files, 4);
	StrArrayAdd(&modified_files, data_path, TRUE);

	UpdateMD5Sum(dir, "md5sum.txt");

	const char *got = read_str(md5path);
	CHECK(strstr(got, "900150983cd24fb0d6963f7d28e17f72") != NULL);

	unlink(data_path);
	unlink(md5path);
	{
		char boot_dir[128];
		snprintf(boot_dir, sizeof(boot_dir), "%s/boot", dir);
		rmdir(boot_dir);
	}
	rmdir(dir);
}

/* ---- file not listed in md5sum.txt → entry untouched ---- */
TEST(update_md5sum_skips_unlisted_file)
{
	char dir[64];
	make_tmp_dir(dir);
	if (dir[0] == '\0') { CHECK(0); return; }

	char data_path[128];
	snprintf(data_path, sizeof(data_path), "%s/other.bin", dir);
	write_str(data_path, "abc");

	char md5path[128];
	snprintf(md5path, sizeof(md5path), "%s/md5sum.txt", dir);
	write_str(md5path, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  ./boot/grub.cfg\n");

	img_report.has_md5sum = TRUE;
	validate_md5sum = FALSE;
	StrArrayClear(&modified_files);
	StrArrayCreate(&modified_files, 4);
	StrArrayAdd(&modified_files, data_path, TRUE);

	UpdateMD5Sum(dir, "md5sum.txt");

	const char *got = read_str(md5path);
	/* The boot/grub.cfg entry must be unchanged */
	CHECK(strstr(got, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") != NULL);

	unlink(data_path);
	unlink(md5path);
	rmdir(dir);
}

/* ---- nonexistent md5sum file → no crash ---- */
TEST(update_md5sum_no_crash_missing_file)
{
	img_report.has_md5sum = TRUE;
	validate_md5sum = FALSE;
	StrArrayClear(&modified_files);

	/* Should return silently without crashing */
	UpdateMD5Sum("/tmp/nonexistent_rufus_dir_xyz", "md5sum.txt");
	CHECK(1);  /* just check no crash/abort */
}

/* ====================================================================
 * PE256Buffer / efi_image_parse tests
 * ==================================================================== */

TEST(pe256_null_buf)
{
	uint8_t hash[32] = {0};
	BOOL r = PE256Buffer(NULL, 1024, hash);
	CHECK(r == FALSE);
}

TEST(pe256_too_small)
{
	uint8_t data[128] = {0};
	uint8_t hash[32] = {0};
	BOOL r = PE256Buffer(data, sizeof(data), hash);
	CHECK(r == FALSE);  /* < 1 KB */
}

TEST(pe256_invalid_pe)
{
	uint8_t data[1024];
	memset(data, 0x55, sizeof(data));
	uint8_t hash[32] = {0};
	BOOL r = PE256Buffer(data, sizeof(data), hash);
	CHECK(r == FALSE);  /* no MZ/PE signature */
}

TEST(pe256_valid_pe64)
{
	size_t len = 0;
	uint8_t *pe = make_pe64(&len);
	CHECK(pe != NULL);
	uint8_t hash[32] = {0};
	BOOL r = PE256Buffer(pe, (uint32_t)len, hash);
	CHECK(r == TRUE);
	/* hash must be non-zero */
	int all_zero = 1;
	for (int i = 0; i < 32; i++) if (hash[i]) { all_zero = 0; break; }
	CHECK(!all_zero);
	free(pe);
}

TEST(pe256_deterministic)
{
	size_t len = 0;
	uint8_t *pe = make_pe64(&len);
	CHECK(pe != NULL);
	uint8_t h1[32] = {0}, h2[32] = {0};
	BOOL r1 = PE256Buffer(pe, (uint32_t)len, h1);
	BOOL r2 = PE256Buffer(pe, (uint32_t)len, h2);
	CHECK(r1 == TRUE && r2 == TRUE);
	CHECK(memcmp(h1, h2, 32) == 0);
	free(pe);
}

TEST(efi_parse_null)
{
	struct efi_image_regions *regs = NULL;
	BOOL r = efi_image_parse(NULL, 0, &regs);
	CHECK(r == FALSE);
}

TEST(efi_parse_too_short)
{
	uint8_t data[64] = {0};
	struct efi_image_regions *regs = NULL;
	BOOL r = efi_image_parse(data, sizeof(data), &regs);
	CHECK(r == FALSE);  /* len < 0x80 */
}

TEST(efi_parse_bad_magic)
{
	uint8_t data[256];
	memset(data, 0, sizeof(data));
	/* DOS header with valid e_lfanew but bad PE magic */
	IMAGE_DOS_HEADER *dos = (void *)data;
	dos->e_magic = IMAGE_DOS_SIGNATURE;
	dos->e_lfanew = 64;
	/* NT magic NOT set → OptionalHeader.Magic == 0 → should fail */
	struct efi_image_regions *regs = NULL;
	BOOL r = efi_image_parse(data, sizeof(data), &regs);
	CHECK(r == FALSE);
	free(regs);
}

TEST(efi_parse_valid_pe64)
{
	size_t len = 0;
	uint8_t *pe = make_pe64(&len);
	CHECK(pe != NULL);
	struct efi_image_regions *regs = NULL;
	BOOL r = efi_image_parse(pe, len, &regs);
	CHECK(r == TRUE);
	CHECK(regs != NULL);
	CHECK(regs->num > 0);
	free(regs);
	free(pe);
}

#endif /* __linux__ */

int main(void)
{
	printf("=== hash tests ===\n\n");
	printf("  HashBuffer — MD5\n");
	RUN(hashbuf_md5_empty);
	RUN(hashbuf_md5_abc);
	RUN(hashbuf_md5_fox);

	printf("\n  HashBuffer — SHA1\n");
	RUN(hashbuf_sha1_empty);
	RUN(hashbuf_sha1_abc);
	RUN(hashbuf_sha1_fox);

	printf("\n  HashBuffer — SHA256\n");
	RUN(hashbuf_sha256_empty);
	RUN(hashbuf_sha256_abc);
	RUN(hashbuf_sha256_fox);

	printf("\n  HashBuffer — SHA512\n");
	RUN(hashbuf_sha512_empty);
	RUN(hashbuf_sha512_abc);
	RUN(hashbuf_sha512_fox);

	printf("\n  HashBuffer — error handling\n");
	RUN(hashbuf_null_hash_ptr);
	RUN(hashbuf_invalid_type);

	printf("\n  HashFile\n");
	RUN(hashfile_md5_abc);
	RUN(hashfile_sha256_fox);
	RUN(hashfile_nonexistent);
	RUN(hashfile_null_path);
	RUN(hashfile_null_hash);

	printf("\n  BufferMatchesHash\n");
	RUN(buffer_matches_hash_md5);
	RUN(buffer_matches_hash_wrong);
	RUN(buffer_matches_hash_sha256);
	RUN(buffer_matches_hash_null_buf);
	RUN(buffer_matches_hash_null_str);

	printf("\n  CPU acceleration detection\n");
	RUN(detect_sha1_accel);
	RUN(detect_sha256_accel);

	printf("\n  Hash function tables\n");
	RUN(hash_tables_populated);

#ifdef __linux__
	printf("\n  HashThread / IndividualHashThread (Linux only)\n");
	RUN(hashthread_null_path);
	RUN(hashthread_nonexistent_file);
	RUN(hashthread_basic_abc);
	RUN(hashthread_with_sha512);
	RUN(hashthread_empty_file);
	RUN(hashthread_large_file);
	RUN(hashthread_fox_message);
	RUN(hashthread_is_buffer_in_db_miss);
	RUN(hashthread_is_file_in_db_miss);

	printf("\n  Hash dialog (Linux only)\n");
	RUN(hash_dialog_strings_non_empty_after_run);
	RUN(hash_dialog_sha512_populated_when_extra_enabled);
	RUN(hash_dialog_um_hash_completed_constant);

	printf("\n  UpdateMD5Sum (Linux only)\n");
	RUN(update_md5sum_noop_when_disabled);
	RUN(update_md5sum_updates_hash);
	RUN(update_md5sum_skips_unlisted_file);
	RUN(update_md5sum_no_crash_missing_file);

	printf("\n  PE256Buffer / efi_image_parse (Linux only)\n");
	RUN(pe256_null_buf);
	RUN(pe256_too_small);
	RUN(pe256_invalid_pe);
	RUN(pe256_valid_pe64);
	RUN(pe256_deterministic);
	RUN(efi_parse_null);
	RUN(efi_parse_too_short);
	RUN(efi_parse_bad_magic);
	RUN(efi_parse_valid_pe64);
#endif

	TEST_RESULTS();
}
