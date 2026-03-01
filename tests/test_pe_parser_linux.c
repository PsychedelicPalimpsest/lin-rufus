/*
 * test_pe_parser_linux.c
 *
 * Tests for the PE parsing helpers in common/parser.c:
 *   GetPeArch, GetPeSection, RvaToPhysical, FindResourceRva, GetPeSignatureData
 *
 * All tests operate entirely in memory — no files are opened.
 * PE buffers are synthesised from scratch using the structures now
 * provided by src/linux/compat/winnt.h.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Pull in compat types + PE structures */
#define _LINUX_WINDOWS_COMPAT_H  /* not defined yet, so we get the real header */
#undef _LINUX_WINDOWS_COMPAT_H
#include "../src/linux/compat/windows.h"
#include "../src/windows/rufus.h"

#include "framework.h"

/* -------------------------------------------------------------------------
 * Minimal stubs (same as test_parser.c) so we don't need to link the whole
 * Rufus UI infrastructure.
 * ---------------------------------------------------------------------- */
#include <stdarg.h>
void uprintf(const char *fmt, ...) { (void)fmt; }
windows_version_t WindowsVersion = {0};
RUFUS_UPDATE update = {{0}, {0}, NULL, NULL};
BOOL en_msg_mode = FALSE;
BOOL right_to_left_mode = FALSE;

/* -------------------------------------------------------------------------
 * Forward declarations of functions under test (defined in common/parser.c)
 * ---------------------------------------------------------------------- */
extern uint16_t  GetPeArch(uint8_t* buf);
extern uint8_t*  GetPeSection(uint8_t* buf, const char* name, uint32_t* len);
extern uint8_t*  RvaToPhysical(uint8_t* buf, uint32_t rva);
extern uint32_t  FindResourceRva(const wchar_t* name, uint8_t* root, uint8_t* dir, uint32_t* len);
extern uint8_t*  GetPeSignatureData(uint8_t* buf);

/* -------------------------------------------------------------------------
 * Minimal PE builder
 *
 * Layout:
 *   [0 .. 63]  DOS header        (e_lfanew = 64)
 *   [64 .. ]   NT signature      (4 bytes, "PE\0\0")
 *   [68 .. ]   IMAGE_FILE_HEADER (20 bytes)
 *   [88 .. ]   OptionalHeader    (sizeof(IMAGE_OPTIONAL_HEADER32) or 64)
 *   [hdr_end..]  Section headers (NumberOfSections × sizeof(IMAGE_SECTION_HEADER))
 *   [data_off..]  Section raw data
 * ---------------------------------------------------------------------- */
#define NT_OFFSET  64u

typedef struct {
    uint8_t* buf;
    size_t   total;
    uint32_t data_offset;   /* byte offset of first section's raw data */
} PeImage;

static void pe_free(PeImage* p) { free(p->buf); p->buf = NULL; }

/*
 * Build a minimal 32-bit PE image with one section.
 * machine: IMAGE_FILE_MACHINE_I386 / IMAGE_FILE_MACHINE_AMD64 / ...
 * section_name: up to 8 chars, may be NULL (no section)
 * sec_rva: virtual address of the section
 * sec_data / sec_data_len: raw bytes of the section
 */
static PeImage make_pe(uint16_t machine,
                       const char* section_name,
                       uint32_t sec_rva,
                       const uint8_t* sec_data,
                       uint32_t sec_data_len,
                       uint32_t sec_vsize)
{
    PeImage p = {0};
    int is64 = (machine != IMAGE_FILE_MACHINE_I386 &&
                machine != IMAGE_FILE_MACHINE_ARM   &&
                machine != IMAGE_FILE_MACHINE_ARMNT);

    uint16_t nb_sec = (section_name != NULL) ? 1 : 0;
    size_t   opt_sz = is64 ? sizeof(IMAGE_OPTIONAL_HEADER64)
                           : sizeof(IMAGE_OPTIONAL_HEADER32);
    size_t   hdr_sz = NT_OFFSET + 4 + sizeof(IMAGE_FILE_HEADER) + opt_sz
                      + nb_sec * sizeof(IMAGE_SECTION_HEADER);
    /* align raw data to 512-byte sector */
    size_t   data_off = (hdr_sz + 511) & ~(size_t)511;
    size_t   total    = data_off + (nb_sec ? sec_data_len : 0);

    p.buf = (uint8_t*)calloc(1, total);
    if (!p.buf) return p;
    p.total       = total;
    p.data_offset = (uint32_t)data_off;

    /* --- DOS header --- */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)p.buf;
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = NT_OFFSET;

    /* --- NT signature --- */
    *(uint32_t*)(p.buf + NT_OFFSET) = IMAGE_NT_SIGNATURE;

    /* --- FILE header --- */
    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(p.buf + NT_OFFSET + 4);
    fh->Machine            = machine;
    fh->NumberOfSections   = nb_sec;
    fh->SizeOfOptionalHeader = (uint16_t)opt_sz;

    /* --- Optional header --- */
    uint8_t* opt_ptr = p.buf + NT_OFFSET + 4 + sizeof(IMAGE_FILE_HEADER);
    if (is64) {
        IMAGE_OPTIONAL_HEADER64* opt64 = (IMAGE_OPTIONAL_HEADER64*)opt_ptr;
        opt64->Magic = 0x020B; /* PE32+ */
        /* Leave DataDirectory zeroed — tests that need it fill it in. */
    } else {
        IMAGE_OPTIONAL_HEADER32* opt32 = (IMAGE_OPTIONAL_HEADER32*)opt_ptr;
        opt32->Magic = 0x010B; /* PE32 */
    }

    /* --- Section header --- */
    if (nb_sec) {
        IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)(opt_ptr + opt_sz);
        if (section_name)
            strncpy((char*)sh->Name, section_name, IMAGE_SIZEOF_SHORT_NAME);
        sh->Misc.VirtualSize   = sec_vsize ? sec_vsize : sec_data_len;
        sh->VirtualAddress     = sec_rva;
        sh->SizeOfRawData      = sec_data_len;
        sh->PointerToRawData   = (uint32_t)data_off;
        /* Copy raw data */
        if (sec_data && sec_data_len)
            memcpy(p.buf + data_off, sec_data, sec_data_len);
    }

    return p;
}

/* =========================================================================
 * GetPeArch tests
 * ====================================================================== */

TEST(get_pe_arch_null_returns_unknown)
{
    CHECK_INT_EQ(IMAGE_FILE_MACHINE_UNKNOWN, (int)GetPeArch(NULL));
}

TEST(get_pe_arch_bad_mz_returns_unknown)
{
    uint8_t buf[512] = {0};  /* e_magic == 0 */
    CHECK_INT_EQ(IMAGE_FILE_MACHINE_UNKNOWN, (int)GetPeArch(buf));
}

TEST(get_pe_arch_bad_pe_sig_returns_unknown)
{
    uint8_t buf[512] = {0};
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 64;
    /* NT signature at offset 64 is 0 — not "PE\0\0" */
    CHECK_INT_EQ(IMAGE_FILE_MACHINE_UNKNOWN, (int)GetPeArch(buf));
}

TEST(get_pe_arch_x86)
{
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, NULL, 0, NULL, 0, 0);
    CHECK(p.buf != NULL);
    CHECK_INT_EQ(IMAGE_FILE_MACHINE_I386, (int)GetPeArch(p.buf));
    pe_free(&p);
}

TEST(get_pe_arch_x64)
{
    PeImage p = make_pe(IMAGE_FILE_MACHINE_AMD64, NULL, 0, NULL, 0, 0);
    CHECK(p.buf != NULL);
    CHECK_INT_EQ(IMAGE_FILE_MACHINE_AMD64, (int)GetPeArch(p.buf));
    pe_free(&p);
}

TEST(get_pe_arch_arm32)
{
    PeImage p = make_pe(IMAGE_FILE_MACHINE_ARM, NULL, 0, NULL, 0, 0);
    CHECK(p.buf != NULL);
    CHECK_INT_EQ(IMAGE_FILE_MACHINE_ARM, (int)GetPeArch(p.buf));
    pe_free(&p);
}

TEST(get_pe_arch_arm64)
{
    PeImage p = make_pe(IMAGE_FILE_MACHINE_ARM64, NULL, 0, NULL, 0, 0);
    CHECK(p.buf != NULL);
    CHECK_INT_EQ(IMAGE_FILE_MACHINE_ARM64, (int)GetPeArch(p.buf));
    pe_free(&p);
}

/* =========================================================================
 * GetPeSection tests
 * ====================================================================== */

TEST(get_pe_section_null_buf)
{
    CHECK(GetPeSection(NULL, ".text", NULL) == NULL);
}

TEST(get_pe_section_null_name)
{
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".text", 0x1000,
                        (const uint8_t*)"abcd", 4, 4);
    CHECK(p.buf != NULL);
    CHECK(GetPeSection(p.buf, NULL, NULL) == NULL);
    pe_free(&p);
}

TEST(get_pe_section_found_x86)
{
    const uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".text", 0x1000, data, 4, 4);
    CHECK(p.buf != NULL);

    uint32_t len = 0;
    uint8_t* sec = GetPeSection(p.buf, ".text", &len);
    CHECK(sec != NULL);
    CHECK_INT_EQ(4, (int)len);
    CHECK_INT_EQ(0xDE, (int)sec[0]);
    CHECK_INT_EQ(0xAD, (int)sec[1]);
    CHECK_INT_EQ(0xBE, (int)sec[2]);
    CHECK_INT_EQ(0xEF, (int)sec[3]);
    pe_free(&p);
}

TEST(get_pe_section_found_x64)
{
    const uint8_t data[] = { 0x11, 0x22, 0x33, 0x44 };
    PeImage p = make_pe(IMAGE_FILE_MACHINE_AMD64, ".data", 0x2000, data, 4, 4);
    CHECK(p.buf != NULL);

    uint32_t len = 0;
    uint8_t* sec = GetPeSection(p.buf, ".data", &len);
    CHECK(sec != NULL);
    CHECK_INT_EQ(4, (int)len);
    pe_free(&p);
}

TEST(get_pe_section_not_found)
{
    const uint8_t data[] = { 1, 2, 3 };
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".text", 0x1000, data, 3, 3);
    CHECK(p.buf != NULL);
    CHECK(GetPeSection(p.buf, ".rsrc", NULL) == NULL);
    pe_free(&p);
}

TEST(get_pe_section_no_len_param)
{
    const uint8_t data[] = { 0xFF };
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".foo", 0x1000, data, 1, 1);
    CHECK(p.buf != NULL);
    /* len == NULL must not crash */
    uint8_t* sec = GetPeSection(p.buf, ".foo", NULL);
    CHECK(sec != NULL);
    CHECK_INT_EQ(0xFF, (int)sec[0]);
    pe_free(&p);
}

/* =========================================================================
 * RvaToPhysical tests
 * ====================================================================== */

TEST(rva_to_physical_null_buf)
{
    CHECK(RvaToPhysical(NULL, 0x1000) == NULL);
}

TEST(rva_to_physical_rva_in_section)
{
    const uint8_t data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    /* section at RVA 0x1000, size 8 */
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".text", 0x1000, data, 8, 8);
    CHECK(p.buf != NULL);

    uint8_t* phys = RvaToPhysical(p.buf, 0x1003);
    CHECK(phys != NULL);
    CHECK_INT_EQ(0x03, (int)phys[0]);
    pe_free(&p);
}

TEST(rva_to_physical_rva_before_sections)
{
    const uint8_t data[] = { 1, 2, 3, 4 };
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".text", 0x2000, data, 4, 4);
    CHECK(p.buf != NULL);
    /* RVA 0x1000 is below the section start 0x2000 */
    CHECK(RvaToPhysical(p.buf, 0x1000) == NULL);
    pe_free(&p);
}

TEST(rva_to_physical_rva_after_sections)
{
    const uint8_t data[] = { 1, 2, 3, 4 };
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".text", 0x1000, data, 4, 4);
    CHECK(p.buf != NULL);
    /* RVA 0x3000 is past the end of the only section */
    CHECK(RvaToPhysical(p.buf, 0x3000) == NULL);
    pe_free(&p);
}

TEST(rva_to_physical_x64)
{
    const uint8_t data[] = { 0xAA, 0xBB };
    PeImage p = make_pe(IMAGE_FILE_MACHINE_AMD64, ".init", 0x4000, data, 2, 2);
    CHECK(p.buf != NULL);
    uint8_t* phys = RvaToPhysical(p.buf, 0x4001);
    CHECK(phys != NULL);
    CHECK_INT_EQ(0xBB, (int)phys[0]);
    pe_free(&p);
}

/* =========================================================================
 * GetPeSignatureData tests
 * ====================================================================== */

TEST(get_pe_sig_null)
{
    CHECK(GetPeSignatureData(NULL) == NULL);
}

TEST(get_pe_sig_no_security_dir)
{
    /* make_pe leaves DataDirectory zeroed, so no security dir */
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, NULL, 0, NULL, 0, 0);
    CHECK(p.buf != NULL);
    CHECK(GetPeSignatureData(p.buf) == NULL);
    pe_free(&p);
}

TEST(get_pe_sig_with_valid_certificate)
{
    /* Build a PE32 with a WIN_CERTIFICATE in the security data directory.
     * The certificate is appended right after the section header area.
     * We use a dummy single-byte cert payload. */

    /* Step 1: build base PE with a .text section so we have a real image */
    const uint8_t text[] = { 0x90 }; /* NOP */
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".text", 0x1000, text, 1, 1);
    CHECK(p.buf != NULL);

    /* Step 2: append WIN_CERTIFICATE at the end of the image buffer */
    size_t cert_offset = p.total;
    size_t cert_size   = sizeof(WIN_CERTIFICATE);
    uint8_t* newbuf = (uint8_t*)realloc(p.buf, p.total + cert_size + 4);
    CHECK(newbuf != NULL);
    p.buf   = newbuf;
    p.total += cert_size + 4;

    WIN_CERTIFICATE* cert = (WIN_CERTIFICATE*)(p.buf + cert_offset);
    cert->dwLength          = (DWORD)(cert_size + 4);
    cert->wRevision         = 0x0200;
    cert->wCertificateType  = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
    /* Leave the 4 dummy payload bytes zeroed */

    /* Step 3: patch the DataDirectory[SECURITY] to point to our cert */
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(p.buf + NT_OFFSET);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
        = (DWORD)cert_offset;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size
        = (DWORD)(cert_size + 4);

    uint8_t* result = GetPeSignatureData(p.buf);
    CHECK(result != NULL);
    CHECK(result == (uint8_t*)cert);
    pe_free(&p);
}

TEST(get_pe_sig_wrong_cert_type)
{
    const uint8_t text[] = { 0x90 };
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".text", 0x1000, text, 1, 1);
    CHECK(p.buf != NULL);

    size_t cert_offset = p.total;
    size_t cert_size   = sizeof(WIN_CERTIFICATE);
    uint8_t* newbuf    = (uint8_t*)realloc(p.buf, p.total + cert_size);
    CHECK(newbuf != NULL);
    p.buf   = newbuf;
    p.total += cert_size;

    WIN_CERTIFICATE* cert = (WIN_CERTIFICATE*)(p.buf + cert_offset);
    cert->dwLength         = (DWORD)cert_size;
    cert->wRevision        = 0x0200;
    cert->wCertificateType = WIN_CERT_TYPE_X509; /* wrong type */

    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(p.buf + NT_OFFSET);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
        = (DWORD)cert_offset;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size
        = (DWORD)cert_size;

    CHECK(GetPeSignatureData(p.buf) == NULL);
    pe_free(&p);
}

TEST(get_pe_sig_zero_length_cert)
{
    const uint8_t text[] = { 0x90 };
    PeImage p = make_pe(IMAGE_FILE_MACHINE_I386, ".text", 0x1000, text, 1, 1);
    CHECK(p.buf != NULL);

    size_t cert_offset = p.total;
    size_t cert_size   = sizeof(WIN_CERTIFICATE);
    uint8_t* newbuf    = (uint8_t*)realloc(p.buf, p.total + cert_size);
    CHECK(newbuf != NULL);
    p.buf   = newbuf;
    p.total += cert_size;

    WIN_CERTIFICATE* cert = (WIN_CERTIFICATE*)(p.buf + cert_offset);
    cert->dwLength         = 0; /* zero length */
    cert->wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA;

    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(p.buf + NT_OFFSET);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
        = (DWORD)cert_offset;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size
        = (DWORD)cert_size;

    CHECK(GetPeSignatureData(p.buf) == NULL);
    pe_free(&p);
}

/* =========================================================================
 * FindResourceRva tests
 * ====================================================================== */

/* Minimal resource directory builder: one named entry pointing to data. */
typedef struct {
    IMAGE_RESOURCE_DIRECTORY     root_dir;
    IMAGE_RESOURCE_DIRECTORY_ENTRY root_entry;
    /* leaf data directory */
    IMAGE_RESOURCE_DIRECTORY     leaf_dir;
    IMAGE_RESOURCE_DIRECTORY_ENTRY leaf_entry;
    IMAGE_RESOURCE_DATA_ENTRY    data_entry;
    /* inline name string: "HELLO" in UTF-16 */
    WORD  name_len;
    WCHAR name_str[6];  /* "HELLO\0" */
    /* padding so offsets are valid */
} ResourceBlock;

TEST(find_resource_rva_null_args)
{
    uint8_t buf[256] = {0};
    CHECK_INT_EQ(0, (int)FindResourceRva(NULL, buf, buf, NULL));
    CHECK_INT_EQ(0, (int)FindResourceRva(L"X", NULL, buf, NULL));
    CHECK_INT_EQ(0, (int)FindResourceRva(L"X", buf, NULL, NULL));
}

TEST(find_resource_rva_empty_directory)
{
    /* A root directory with 0 named + 0 id entries */
    uint8_t buf[sizeof(IMAGE_RESOURCE_DIRECTORY)] = {0};
    uint32_t len = 0;
    CHECK_INT_EQ(0, (int)FindResourceRva(L"MISSING", buf, buf, &len));
}

TEST(find_resource_rva_name_not_found)
{
    /* One named entry "FOO" but we search for "BAR" */
    size_t total = sizeof(IMAGE_RESOURCE_DIRECTORY)
                 + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)
                 + sizeof(IMAGE_RESOURCE_DIRECTORY)
                 + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)
                 + sizeof(IMAGE_RESOURCE_DATA_ENTRY)
                 + sizeof(WORD) + 3 * sizeof(WCHAR);
    uint8_t* root = (uint8_t*)calloc(1, total);
    CHECK(root != NULL);

    IMAGE_RESOURCE_DIRECTORY* rdir = (IMAGE_RESOURCE_DIRECTORY*)root;
    rdir->NumberOfNamedEntries = 1;
    IMAGE_RESOURCE_DIRECTORY_ENTRY* rentry =
        (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(rdir + 1);
    size_t name_off = sizeof(IMAGE_RESOURCE_DIRECTORY)
                    + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)
                    + sizeof(IMAGE_RESOURCE_DIRECTORY)
                    + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)
                    + sizeof(IMAGE_RESOURCE_DATA_ENTRY);
    rentry->NameOffset   = (DWORD)name_off;
    rentry->NameIsString = 1;
    rentry->OffsetToData = 0; /* not a directory */
    rentry->DataIsDirectory = 0;

    /* name "FOO" */
    WORD* name_len_ptr = (WORD*)(root + name_off);
    *name_len_ptr = 3;
    WCHAR* name_str_ptr = (WCHAR*)(root + name_off + sizeof(WORD));
    name_str_ptr[0] = L'F';
    name_str_ptr[1] = L'O';
    name_str_ptr[2] = L'O';

    uint32_t len = 0;
    uint32_t rva = FindResourceRva(L"BAR", root, root, &len);
    CHECK_INT_EQ(0, (int)rva);
    free(root);
}

/* =========================================================================
 * main
 * ====================================================================== */

int main(void)
{
    printf("=== PE parser tests ===\n");

    RUN(get_pe_arch_null_returns_unknown);
    RUN(get_pe_arch_bad_mz_returns_unknown);
    RUN(get_pe_arch_bad_pe_sig_returns_unknown);
    RUN(get_pe_arch_x86);
    RUN(get_pe_arch_x64);
    RUN(get_pe_arch_arm32);
    RUN(get_pe_arch_arm64);

    RUN(get_pe_section_null_buf);
    RUN(get_pe_section_null_name);
    RUN(get_pe_section_found_x86);
    RUN(get_pe_section_found_x64);
    RUN(get_pe_section_not_found);
    RUN(get_pe_section_no_len_param);

    RUN(rva_to_physical_null_buf);
    RUN(rva_to_physical_rva_in_section);
    RUN(rva_to_physical_rva_before_sections);
    RUN(rva_to_physical_rva_after_sections);
    RUN(rva_to_physical_x64);

    RUN(get_pe_sig_null);
    RUN(get_pe_sig_no_security_dir);
    RUN(get_pe_sig_with_valid_certificate);
    RUN(get_pe_sig_wrong_cert_type);
    RUN(get_pe_sig_zero_length_cert);

    RUN(find_resource_rva_null_args);
    RUN(find_resource_rva_empty_directory);
    RUN(find_resource_rva_name_not_found);

    TEST_RESULTS();
}
