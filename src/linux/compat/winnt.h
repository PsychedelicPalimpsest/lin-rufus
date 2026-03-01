/* Linux compat stub for winnt.h — PE / COFF structures */
#pragma once
#ifndef _WIN32
/* windows.h includes this file; all basic types (WORD, DWORD, etc.) are
 * already defined at this point.  Do NOT re-include windows.h here to
 * avoid a circular dependency. */

/* ---- PE / COFF constants (guard against duplicates from windows.h) ---- */
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE                 0x5A4D      /* MZ */
#endif
#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE                  0x00004550  /* PE\0\0 */
#endif

#ifndef IMAGE_FILE_MACHINE_UNKNOWN
#define IMAGE_FILE_MACHINE_UNKNOWN          0x0000
#endif
#ifndef IMAGE_FILE_MACHINE_I386
#define IMAGE_FILE_MACHINE_I386             0x014C
#endif
#ifndef IMAGE_FILE_MACHINE_ARM
#define IMAGE_FILE_MACHINE_ARM              0x01C0
#endif
#ifndef IMAGE_FILE_MACHINE_ARMNT
#define IMAGE_FILE_MACHINE_ARMNT            0x01C4
#endif
#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64            0x8664
#endif
#ifndef IMAGE_FILE_MACHINE_IA64
#define IMAGE_FILE_MACHINE_IA64             0x0200
#endif
#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64            0xAA64
#endif

#ifndef IMAGE_SIZEOF_SHORT_NAME
#define IMAGE_SIZEOF_SHORT_NAME             8
#endif
#ifndef IMAGE_NUMBEROF_DIRECTORY_ENTRIES
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_SECURITY
#define IMAGE_DIRECTORY_ENTRY_SECURITY      4
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC       0x010b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC       0x020b
#endif
#ifndef IMAGE_RESOURCE_DATA_IS_DIRECTORY
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY    0x80000000U
#endif
#ifndef WIN_CERT_TYPE_X509
#define WIN_CERT_TYPE_X509                  0x0001
#endif
#ifndef WIN_CERT_TYPE_PKCS_SIGNED_DATA
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA      0x0002
#endif

/* ---- DOS header ---- */
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;          /* offset to NT headers */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

/* ---- COFF file header ---- */
typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

/* ---- Data directory entry ---- */
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

/* ---- Optional header (PE32) ---- */
typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

/* ---- Optional header (PE32+) ---- */
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD      Magic;
    BYTE      MajorLinkerVersion;
    BYTE      MinorLinkerVersion;
    DWORD     SizeOfCode;
    DWORD     SizeOfInitializedData;
    DWORD     SizeOfUninitializedData;
    DWORD     AddressOfEntryPoint;
    DWORD     BaseOfCode;
    ULONGLONG ImageBase;
    DWORD     SectionAlignment;
    DWORD     FileAlignment;
    WORD      MajorOperatingSystemVersion;
    WORD      MinorOperatingSystemVersion;
    WORD      MajorImageVersion;
    WORD      MinorImageVersion;
    WORD      MajorSubsystemVersion;
    WORD      MinorSubsystemVersion;
    DWORD     Win32VersionValue;
    DWORD     SizeOfImage;
    DWORD     SizeOfHeaders;
    DWORD     CheckSum;
    WORD      Subsystem;
    WORD      DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD     LoaderFlags;
    DWORD     NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

/* ---- NT headers ---- */
typedef struct _IMAGE_NT_HEADERS32 {
    DWORD                 Signature;
    IMAGE_FILE_HEADER     FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                 Signature;
    IMAGE_FILE_HEADER     FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#define IMAGE_NT_HEADERS IMAGE_NT_HEADERS32

/* ---- Section header ---- */
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

/* ---- Resource directory ---- */
typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    WORD  NumberOfNamedEntries;
    WORD  NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

/* ---- Resource directory entry ---- */
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset:31;
            DWORD NameIsString:1;
        };
        DWORD Name;
        WORD  Id;
    };
    union {
        DWORD OffsetToData;
        struct {
            DWORD OffsetToDirectory:31;
            DWORD DataIsDirectory:1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

/* ---- Resource string ---- */
typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
    WORD  Length;
    WCHAR NameString[1];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;

/* ---- Resource data entry ---- */
typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    DWORD OffsetToData;
    DWORD Size;
    DWORD CodePage;
    DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

/* ---- WIN_CERTIFICATE (Authenticode) ---- */
typedef struct _WIN_CERTIFICATE {
    DWORD dwLength;
    WORD  wRevision;
    WORD  wCertificateType;
    /* followed by variable-length bCertificate[] */
} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;

#endif /* _WIN32 */
