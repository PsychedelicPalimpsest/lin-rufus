/*
 * Linux compatibility header: fake windows.h for porting Rufus to Linux.
 * Provides Windows type aliases, constants, and stub macros so that
 * Windows-specific source files can be parsed by a Linux compiler.
 */
#pragma once
#ifndef _LINUX_WINDOWS_COMPAT_H
#define _LINUX_WINDOWS_COMPAT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>

/*
 * Partition-handle offset table for image files.
 *
 * On real block devices, /dev/sda1 starts at byte 0 of the partition.
 * For raw image files (no sysfs node), we open the whole file and register
 * the partition's byte offset here so that SetFilePointerEx() can add it
 * to all FILE_BEGIN seeks transparently.
 *
 * Strong implementations are in drive.c; these weak no-ops are used by
 * test binaries that do not link drive.c.
 */
#ifndef LINUX_DRIVE_C   /* drive.c provides strong implementations */
__attribute__((weak)) uint64_t linux_get_fd_base_offset(int fd)   { (void)fd; return 0; }
__attribute__((weak)) uint64_t linux_get_fd_part_size(int fd)     { (void)fd; return 0; }
__attribute__((weak)) void     linux_unregister_fd_offset(int fd) { (void)fd; }
#else
/* Declare prototypes so code in drive.c can still call them */
uint64_t linux_get_fd_base_offset(int fd);
uint64_t linux_get_fd_part_size(int fd);
void     linux_unregister_fd_offset(int fd);
#endif
/* NOTE: WINAPI/CALLBACK etc. will be re-defined later with correct values */
#define __stdcall
#define __cdecl
#define __fastcall
#define __pascal
#define DECLSPEC_NOINLINE      __attribute__((noinline))
#define DECLSPEC_NORETURN      __attribute__((noreturn))
#define __forceinline          __attribute__((always_inline)) inline
#define __declspec(x)
#define __unaligned

/* Calling convention macros (set early to avoid redefinition issues) */
#define WINAPI
#define CALLBACK __attribute__((cdecl))
#define APIENTRY WINAPI
#define WINAPIV
#define PASCAL
#define STDCALL

/* ---- Boolean ---- */
typedef int BOOL;
typedef int WINBOOL;
#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* ---- Basic integer types ---- */
typedef uint8_t   BYTE;
typedef uint8_t   UCHAR;
typedef int8_t    CHAR;
typedef uint16_t  WORD;
typedef uint16_t  USHORT;
typedef int16_t   SHORT;
typedef uint32_t  DWORD;
typedef int32_t   LONG;
typedef uint32_t  ULONG;
typedef int32_t   INT;
typedef uint32_t  UINT;
typedef uint64_t  DWORD64;
typedef uint64_t  ULONGLONG;
typedef uint64_t  DWORDLONG;
typedef int64_t   LONGLONG;
typedef int64_t   LONG64;
typedef uint64_t  ULONG64;
typedef float     FLOAT;
typedef double    DOUBLE;

/* ---- Fixed-width WinAPI aliases (used by UEFI/EFI headers) ---- */
typedef uint8_t   UINT8;
typedef int8_t    INT8;
typedef uint16_t  UINT16;
typedef int16_t   INT16;
typedef uint32_t  UINT32;
typedef int32_t   INT32;
typedef uint64_t  UINT64;
typedef int64_t   INT64;

/* ---- Pointer-sized types ---- */
typedef uintptr_t ULONG_PTR;
typedef uintptr_t UINT_PTR;
typedef uintptr_t DWORD_PTR;
typedef intptr_t  LONG_PTR;
typedef intptr_t  INT_PTR;
typedef size_t    SIZE_T;
typedef ssize_t   SSIZE_T;

/* ---- HRESULT / NTSTATUS ---- */
typedef LONG      HRESULT;
typedef LONG      NTSTATUS;
#define S_OK                ((HRESULT)0x00000000L)
#define S_FALSE             ((HRESULT)0x00000001L)
#define E_FAIL              ((HRESULT)0x80004005L)
#define E_NOTIMPL           ((HRESULT)0x80004001L)
#define E_OUTOFMEMORY       ((HRESULT)0x8007000EL)
#define E_INVALIDARG        ((HRESULT)0x80070057L)
#define E_NOINTERFACE       ((HRESULT)0x80004002L)
#define E_UNEXPECTED        ((HRESULT)0x8000FFFFL)
#define SUCCEEDED(hr)       ((HRESULT)(hr) >= 0)
#define FAILED(hr)          ((HRESULT)(hr) < 0)
#define MAKE_HRESULT(sev,fac,code) ((HRESULT)(((unsigned long)(sev)<<31)|((unsigned long)(fac)<<16)|((unsigned long)(code))))

/* ---- Character types ---- */
typedef wchar_t   WCHAR;
typedef char      TCHAR;
typedef WCHAR*    LPWSTR;
typedef WCHAR*    PWSTR;
typedef const WCHAR* LPCWSTR;
typedef const WCHAR* PCWSTR;
typedef char*     LPSTR;
typedef char*     PSTR;
typedef const char* LPCSTR;
typedef const char* PCSTR;
typedef TCHAR*    LPTSTR;
typedef const TCHAR* LPCTSTR;
typedef void*     LPVOID;
typedef const void* LPCVOID;
typedef BYTE*     LPBYTE;
typedef BYTE*     PBYTE;
typedef WORD*     LPWORD;
typedef DWORD*    LPDWORD;
typedef DWORD*    PDWORD;
typedef LONG*     LPLONG;
typedef LONG*     PLONG;
typedef BOOL*     LPBOOL;
typedef UINT*     PUINT;
typedef INT*      PINT;
typedef ULONG*    PULONG;
typedef USHORT*   PUSHORT;
typedef BYTE*     PUCHAR;
typedef void*     PSECURITY_DESCRIPTOR;

/* ---- Handle types (opaque pointers) ---- */
typedef void*     HANDLE;
typedef void*     HWND;
typedef void*     HINSTANCE;
typedef void*     HMODULE;
typedef void*     HICON;
typedef void*     HCURSOR;
typedef void*     HDC;
typedef void*     HFONT;
typedef void*     HBRUSH;
typedef void*     HPEN;
typedef void*     HBITMAP;
typedef void*     HMENU;
typedef void*     HKEY;
typedef void*     HLOCAL;
typedef void*     HGLOBAL;
typedef void*     HRSRC;
typedef void*     HMETAFILE;
typedef void*     HTREEITEM;
typedef void*     HIMAGELIST;
typedef void*     HRGN;
typedef void*     HDESK;
typedef void*     HWINSTA;
typedef void*     SC_HANDLE;
typedef void*     SERVICE_STATUS_HANDLE;
typedef void*     HGDIOBJ;
typedef void*     HTHEME;
typedef HINSTANCE HMODULEHANDLE;
typedef HANDLE    HTHREAD;
typedef HANDLE    HEVENT;
typedef HANDLE    HMUTEX;
typedef BOOL*     PBOOL;
typedef TCHAR*    PTSTR;
typedef CHAR*     PCHAR;

/* ---- Special handle values ---- */
#define INVALID_HANDLE_VALUE    ((HANDLE)(LONG_PTR)-1)
#define INVALID_FILE_SIZE       ((DWORD)0xFFFFFFFF)
#define INVALID_SET_FILE_POINTER ((DWORD)-1)

/* ---- NULL / VOID ---- */
#ifndef NULL
#define NULL ((void*)0)
#endif
typedef void VOID;
typedef void* PVOID;
typedef void* LPVOID;

/* ---- Common constants ---- */
#define MAX_PATH         260
#define MAX_COMPUTERNAME_LENGTH 15
#define MAX_USERNAME_LENGTH 256
#define MAXDWORD         0xFFFFFFFF
#define MAXBYTE          0xFF
#define MAXWORD          0xFFFF
#define INFINITE         0xFFFFFFFF

/* ---- WaitForSingleObject / WaitForMultipleObjects return codes ---- */
#define WAIT_OBJECT_0    ((DWORD)0x00000000)
#define WAIT_ABANDONED   ((DWORD)0x00000080)
#define WAIT_TIMEOUT     ((DWORD)0x00000102)
#define WAIT_FAILED      ((DWORD)0xFFFFFFFF)

/* ---- File access ---- */
#define GENERIC_READ          0x80000000
#define GENERIC_WRITE         0x40000000
#define GENERIC_EXECUTE       0x20000000
#define GENERIC_ALL           0x10000000

#define FILE_SHARE_READ       0x00000001
#define FILE_SHARE_WRITE      0x00000002
#define FILE_SHARE_DELETE     0x00000004

#define CREATE_NEW            1
#define CREATE_ALWAYS         2
#define OPEN_EXISTING         3
#define OPEN_ALWAYS           4
#define TRUNCATE_EXISTING     5

#define FILE_BEGIN            0
#define FILE_CURRENT          1
#define FILE_END              2

/* ---- Drive type constants (GetDriveType / GetDriveTypeFromIndex) ---- */
#define DRIVE_UNKNOWN       0
#define DRIVE_NO_ROOT_DIR   1
#define DRIVE_REMOVABLE     2
#define DRIVE_FIXED         3
#define DRIVE_REMOTE        4
#define DRIVE_CDROM         5
#define DRIVE_RAMDISK       6

#define FILE_ATTRIBUTE_READONLY     0x00000001
#define FILE_ATTRIBUTE_HIDDEN       0x00000002
#define FILE_ATTRIBUTE_SYSTEM       0x00000004
#define FILE_ATTRIBUTE_DIRECTORY    0x00000010
#define FILE_ATTRIBUTE_ARCHIVE      0x00000020
#define FILE_ATTRIBUTE_NORMAL       0x00000080
#define FILE_ATTRIBUTE_TEMPORARY    0x00000100
#define FILE_FLAG_WRITE_THROUGH     0x80000000
#define FILE_FLAG_NO_BUFFERING      0x20000000
#define FILE_FLAG_RANDOM_ACCESS     0x10000000
#define FILE_FLAG_SEQUENTIAL_SCAN   0x08000000
#define FILE_FLAG_OVERLAPPED        0x40000000

/* ---- Registry ---- */
#define HKEY_CLASSES_ROOT           ((HKEY)(ULONG_PTR)(LONG)0x80000000)
#define HKEY_CURRENT_USER           ((HKEY)(ULONG_PTR)(LONG)0x80000001)
#define HKEY_LOCAL_MACHINE          ((HKEY)(ULONG_PTR)(LONG)0x80000002)
#define HKEY_USERS                  ((HKEY)(ULONG_PTR)(LONG)0x80000003)
#define HKEY_PERFORMANCE_DATA       ((HKEY)(ULONG_PTR)(LONG)0x80000004)
#define KEY_READ             0x20019
#define KEY_WRITE            0x20006
#define KEY_ALL_ACCESS       0xF003F
#define REG_NONE             0
#define REG_SZ               1
#define REG_EXPAND_SZ        2
#define REG_BINARY           3
#define REG_DWORD            4
#define REG_DWORD_LITTLE_ENDIAN 4
#define REG_DWORD_BIG_ENDIAN 5
#define REG_LINK             6
#define REG_MULTI_SZ         7
#define REG_QWORD            11
#define ERROR_SUCCESS        0L
#define ERROR_NO_MORE_ITEMS  259L

/* ---- Process/Thread ---- */
#define PROCESS_ALL_ACCESS   0x001FFFFF
#define THREAD_ALL_ACCESS    0x001FFFFF
#define STILL_ACTIVE         259
#define CREATE_SUSPENDED     0x00000004
#define CREATE_NEW_CONSOLE   0x00000010
#define DETACHED_PROCESS     0x00000008
#define NORMAL_PRIORITY_CLASS 0x00000020

/* ---- Memory ---- */
#define MEM_COMMIT       0x00001000
#define MEM_RESERVE      0x00002000
#define MEM_DECOMMIT     0x00004000
#define MEM_RELEASE      0x00008000
#define MEM_FREE         0x00010000
#define PAGE_NOACCESS    0x01
#define PAGE_READONLY    0x02
#define PAGE_READWRITE   0x04
#define PAGE_EXECUTE     0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40

/* ---- Error codes ---- */
#define ERROR_SUCCESS                    0L
#define ERROR_INVALID_FUNCTION           1L
#define ERROR_FILE_NOT_FOUND             2L
#define ERROR_PATH_NOT_FOUND             3L
#define ERROR_ACCESS_DENIED              5L
#define ERROR_INVALID_HANDLE             6L
#define ERROR_NOT_ENOUGH_MEMORY          8L
#define ERROR_OUTOFMEMORY                14L
#define ERROR_NOT_READY                  21L
#define ERROR_BAD_COMMAND                22L
#define ERROR_SHARING_VIOLATION          32L
#define ERROR_LOCK_VIOLATION             33L
#define ERROR_SHARING_BUFFER_EXCEEDED    36L
#define ERROR_HANDLE_EOF                 38L
#define ERROR_NOT_SUPPORTED              50L
#define ERROR_FILE_EXISTS                80L
#define ERROR_INVALID_PARAMETER          87L
#define ERROR_INSUFFICIENT_BUFFER        122L
#define ERROR_ALREADY_EXISTS             183L
#define ERROR_ENVVAR_NOT_FOUND           203L
#define ERROR_MORE_DATA                  234L
#define ERROR_NO_MORE_ITEMS              259L
#define ERROR_NOT_FOUND                  1168L
#define ERROR_CANCELLED                  1223L
#define ERROR_CALL_NOT_IMPLEMENTED       120L
#define ERROR_BAD_LENGTH                 24L
#define ERROR_BAD_PATHNAME               161L
#define ERROR_BAD_NET_NAME               67L
#define ERROR_BAD_NETPATH                53L
#define ERROR_DEVICE_NOT_CONNECTED       1167L
#define ERROR_OPEN_FAILED                110L
#define ERROR_PIPE_NOT_CONNECTED         233L
#define ERROR_BROKEN_PIPE                109L
#define ERROR_NO_DATA                    232L
#define ERROR_BUFFER_OVERFLOW            111L
#define ERROR_WRITE_FAULT                29L
#define ERROR_READ_FAULT                 30L
#define ERROR_PARTITION_FAILURE          1105L
#define ERROR_INSTALL_FAILURE            1603L

/* ---- Window messages ---- */
#define WM_NULL          0x0000
#define WM_CREATE        0x0001
#define WM_DESTROY       0x0002
#define WM_MOVE          0x0003
#define WM_SIZE          0x0005
#define WM_ACTIVATE      0x0006
#define WM_SETFOCUS      0x0007
#define WM_KILLFOCUS     0x0008
#define WM_QUIT          0x0012
#define WM_PAINT         0x000F
#define WM_CLOSE         0x0010
#define WM_TIMER         0x0113
#define WM_COMMAND       0x0111
#define WM_NEXTDLGCTL    0x0028
#define WM_NOTIFY        0x004E
#define WM_INITDIALOG    0x0110
#define WM_USER          0x0400
#define WM_APP           0x8000
#define WM_SETTEXT       0x000C
#define WM_GETTEXT       0x000D
#define WM_GETTEXTLENGTH 0x000E
#define WM_SETFONT       0x0030
#define WM_GETFONT       0x0031
#define WM_DRAWITEM      0x002B
#define WM_MEASUREITEM   0x002C
#define WM_CTLCOLORBTN   0x0135
#define WM_CTLCOLORSTATIC 0x0138
#define WM_CTLCOLORDLG   0x0136
#define WM_CTLCOLOREDIT  0x0133
#define WM_CTLCOLORLISTBOX 0x0134
#define WM_HSCROLL       0x0114
#define WM_VSCROLL       0x0115
#define WM_LBUTTONDOWN   0x0201
#define WM_LBUTTONUP     0x0202
#define WM_MOUSEMOVE     0x0200
#define WM_RBUTTONDOWN   0x0204
#define WM_KEYDOWN       0x0100
#define WM_KEYUP         0x0101
#define WM_SYSKEYDOWN    0x0104
#define WM_SYSKEYUP      0x0105
#define WM_SYSCOMMAND    0x0112
#define WM_DROPFILES     0x0233
#define WM_DEVICECHANGE  0x0219
#define WM_TASKBARBUTTONCREATED 0  /* stub */

/* ---- Show window commands ---- */
#define SW_HIDE             0
#define SW_SHOWNORMAL       1
#define SW_SHOWMINIMIZED    2
#define SW_SHOWMAXIMIZED    3
#define SW_SHOW             5
#define SW_MINIMIZE         6
#define SW_RESTORE          9
#define SW_SHOWDEFAULT      10

/* ---- Common GDI/Control IDs ---- */
#define IDOK      1
#define IDCANCEL  2
#define IDABORT   3
#define IDRETRY   4
#define IDIGNORE  5
#define IDYES     6
#define IDNO      7
#define IDCLOSE   8
#define IDHELP    9

#define MB_OK                0x00000000L
#define MB_OKCANCEL          0x00000001L
#define MB_ABORTRETRYIGNORE  0x00000002L
#define MB_YESNOCANCEL       0x00000003L
#define MB_YESNO             0x00000004L
#define MB_RETRYCANCEL       0x00000005L
#define MB_ICONERROR         0x00000010L
#define MB_ICONQUESTION      0x00000020L
#define MB_ICONWARNING       0x00000030L
#define MB_ICONINFORMATION   0x00000040L
#define MB_DEFBUTTON1        0x00000000L
#define MB_DEFBUTTON2        0x00000100L
#define MB_TOPMOST           0x00040000L
#define MB_SETFOREGROUND     0x00010000L

/* Button styles used by CustomSelectionDialog */
#define BS_PUSHBUTTON        0x00000000L
#define BS_CHECKBOX          0x00000002L
#define BS_AUTOCHECKBOX      0x00000003L
#define BS_RADIOBUTTON       0x00000004L
#define BS_AUTORADIOBUTTON   0x00000009L

/* ---- LOWORD/HIWORD ---- */
#define LOWORD(l)   ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#define HIWORD(l)   ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#define LOBYTE(w)   ((BYTE)(((DWORD_PTR)(w)) & 0xff))
#define HIBYTE(w)   ((BYTE)((((DWORD_PTR)(w)) >> 8) & 0xff))
#define MAKELONG(a, b) ((LONG)(((WORD)(((DWORD_PTR)(a)) & 0xffff)) | ((DWORD)((WORD)(((DWORD_PTR)(b)) & 0xffff))) << 16))
#define MAKEWORD(a, b) ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))
#define MAKEWPARAM(l, h) ((WPARAM)(DWORD)(MAKELONG(l,h)))
#define MAKELPARAM(l, h) ((LPARAM)(DWORD)(MAKELONG(l,h)))

typedef LONG_PTR  LPARAM;
typedef UINT_PTR  WPARAM;
typedef LONG_PTR  LRESULT;

/* ---- GUID ---- */
typedef struct _GUID {
    DWORD  Data1;
    WORD   Data2;
    WORD   Data3;
    BYTE   Data4[8];
} GUID, *LPGUID;
typedef const GUID* LPCGUID;
typedef GUID IID;
typedef GUID CLSID;
typedef GUID FMTID;
#define REFGUID const GUID*
#define REFIID  const IID*
#define REFCLSID const CLSID*
#define IsEqualGUID(a,b) (memcmp((a),(b),sizeof(GUID))==0)

/* ---- CoCreateGuid: generate a random GUID via /dev/urandom ---- */
#include <fcntl.h>
static inline HRESULT CoCreateGuid(GUID* guid) {
    if (!guid) return E_INVALIDARG;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return E_FAIL;
    ssize_t r = read(fd, guid, sizeof(*guid));
    close(fd);
    if (r != (ssize_t)sizeof(*guid)) return E_FAIL;
    /* Variant bits: RFC 4122 variant 1, version 4 (random) */
    guid->Data3 = (guid->Data3 & 0x0FFF) | 0x4000;
    guid->Data4[0] = (guid->Data4[0] & 0x3F) | 0x80;
    return S_OK;
}

/* ---- RECT / POINT / SIZE ---- */
typedef struct tagPOINT { LONG x, y; } POINT, *PPOINT, *LPPOINT;
typedef struct tagSIZE  { LONG cx, cy; } SIZE, *PSIZE, *LPSIZE;
typedef struct tagRECT  { LONG left, top, right, bottom; } RECT, *PRECT, *LPRECT;
typedef struct tagMSG { HWND hwnd; UINT message; WPARAM wParam; LPARAM lParam; DWORD time; POINT pt; } MSG, *PMSG, *LPMSG;

/* ---- SYSTEMTIME ---- */
typedef struct _SYSTEMTIME {
    WORD wYear, wMonth, wDayOfWeek, wDay;
    WORD wHour, wMinute, wSecond, wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef struct _FILETIME { DWORD dwLowDateTime, dwHighDateTime; } FILETIME, *PFILETIME, *LPFILETIME;

/* ---- OVERLAPPED ---- */
typedef struct _OVERLAPPED {
    ULONG_PTR Internal, InternalHigh;
    union { struct { DWORD Offset, OffsetHigh; }; PVOID Pointer; };
    HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

/* ---- SECURITY_ATTRIBUTES ---- */
typedef struct _SECURITY_ATTRIBUTES {
    DWORD  nLength;
    LPVOID lpSecurityDescriptor;
    BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

/* ---- PROCESS/THREAD info ---- */
typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess, hThread;
    DWORD  dwProcessId, dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
typedef struct _STARTUPINFOA {
    DWORD  cb;
    LPSTR  lpReserved, lpDesktop, lpTitle;
    DWORD  dwX, dwY, dwXSize, dwYSize;
    DWORD  dwXCountChars, dwYCountChars;
    DWORD  dwFillAttribute, dwFlags;
    WORD   wShowWindow, cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput, hStdOutput, hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;
typedef STARTUPINFOA STARTUPINFO;
typedef LPSTARTUPINFOA LPSTARTUPINFO;

/* ---- Windows version ---- */
typedef struct _OSVERSIONINFOEXA {
    DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion;
    DWORD dwBuildNumber, dwPlatformId;
    CHAR  szCSDVersion[128];
    WORD  wServicePackMajor, wServicePackMinor;
    WORD  wSuiteMask;
    BYTE  wProductType, wReserved;
} OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;
typedef OSVERSIONINFOEXA OSVERSIONINFOEX;
typedef POSVERSIONINFOEXA POSVERSIONINFOEX;

/* ---- LARGE_INTEGER ---- */
typedef union _LARGE_INTEGER {
    struct { DWORD LowPart; LONG HighPart; };
    struct { DWORD LowPart; LONG HighPart; } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;
typedef union _ULARGE_INTEGER {
    struct { DWORD LowPart; DWORD HighPart; };
    struct { DWORD LowPart; DWORD HighPart; } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

/* ---- LIST_ENTRY ---- */
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;

/* ---- String macros ---- */
#define MAKEINTRESOURCEA(i) ((LPSTR)((ULONG_PTR)((WORD)(i))))
#define MAKEINTRESOURCE MAKEINTRESOURCEA
#define TEXT(s)  s
#define _T(s)    s

/* ---- Memory / String helpers ---- */
#define ZeroMemory(p,s)     memset((p),0,(s))
#define FillMemory(p,s,b)   memset((p),(b),(s))
#define CopyMemory(d,s,l)   memcpy((d),(s),(l))
#define MoveMemory(d,s,l)   memmove((d),(s),(l))
#define RtlZeroMemory(p,s)  memset((p),0,(s))

/* ---- Safe string macros ---- */
#ifndef _stricmp
#define _stricmp strcasecmp
#endif
#ifndef _strnicmp
#define _strnicmp strncasecmp
#endif
#ifndef _wcsicmp
#define _wcsicmp wcscasecmp
#endif
#ifndef sprintf_s
#define sprintf_s(buf,sz,...) snprintf(buf,sz,__VA_ARGS__)
#endif
#ifndef _TRUNCATE
#define _TRUNCATE ((size_t)-1)
#endif
#ifndef _snprintf_s
#define _snprintf_s(buf,sz,count,...) snprintf(buf, (count)==_TRUNCATE?(sz):(count)<(sz)?(count):(sz), __VA_ARGS__)
#endif
#ifndef _vsnprintf_s
#define _vsnprintf_s(buf,sz,count,fmt,args) vsnprintf(buf, (count)==_TRUNCATE?(sz):(count)<(sz)?(count):(sz), fmt, args)
#endif
#ifndef strcpy_s
#define strcpy_s(d,n,s) (strncpy(d,s,n),(d)[(n)-1]='\0',0)
#endif
#ifndef strncpy_s
#define strncpy_s(d,n,s,c) (strncpy(d,s,(c)==_TRUNCATE?(n)-1:(c)),(d)[(n)-1]='\0',0)
#endif
#ifndef strcat_s
#define strcat_s(d,n,s) strncat(d,s,(n)-strlen(d)-1)
#endif
#ifndef strncat_s
/* strncat_s(dest, destsz, src, count): append at most count chars.
 * If count == _TRUNCATE, append as much as fits in destsz. */
static __inline int strncat_s(char* dest, size_t destsz, const char* src, size_t count)
{
    size_t dlen = strlen(dest);
    size_t avail = (destsz > dlen + 1) ? (destsz - dlen - 1) : 0;
    size_t n = (count == (size_t)(-1) /*_TRUNCATE*/) ? avail : (count < avail ? count : avail);
    strncat(dest, src, n);
    return 0;
}
#endif
#ifndef StrStrIA
#define StrStrIA(haystack, needle) strcasestr((haystack), (needle))
#endif
#ifndef _strdup
#define _strdup strdup
#endif
#ifndef _wcsdup
#define _wcsdup wcsdup
#endif
#ifndef _vsnprintf
#define _vsnprintf vsnprintf
#endif
#ifndef _snprintf
#define _snprintf snprintf
#endif
#ifndef _snwprintf
#define _snwprintf swprintf
#endif

/* ---- intptr helpers ---- */
#define InterlockedIncrement(p) __sync_add_and_fetch(p, 1)
#define InterlockedDecrement(p) __sync_sub_and_fetch(p, 1)
#define InterlockedIncrement16(p) __sync_add_and_fetch(p, 1)
#define InterlockedDecrement16(p) __sync_sub_and_fetch(p, 1)
#define InterlockedExchange(p,v) __sync_lock_test_and_set(p, v)
#define InterlockedCompareExchange(p,e,c) __sync_val_compare_and_swap(p, c, e)

/* ---- Stub function declarations for commonly used Win32 APIs ---- */
/* These are declared but NOT defined here; Linux stubs provide the bodies */
extern DWORD _win_last_error;
static inline DWORD GetLastError(void)    { return _win_last_error; }
static inline void  SetLastError(DWORD e) { _win_last_error = e; }
static inline ULONGLONG GetTickCount64(void) { return 0; }

static inline HANDLE GetCurrentProcess(void) { return (HANDLE)(intptr_t)getpid(); }
static inline DWORD  GetCurrentProcessId(void) { return (DWORD)getpid(); }
static inline HANDLE GetCurrentThread(void) { return (HANDLE)0; }
static inline DWORD  GetCurrentThreadId(void) { return (DWORD)0; }

/* OutputDebugString is a no-op on Linux */
static inline void OutputDebugStringA(LPCSTR s) { (void)s; }
static inline void OutputDebugStringW(LPCWSTR s) { (void)s; }
#define OutputDebugString OutputDebugStringA

/* LocalAlloc/LocalFree/GlobalAlloc/GlobalFree → malloc/free */
#define LMEM_FIXED   0x0000
#define LMEM_ZEROINIT 0x0040
static inline HLOCAL LocalAlloc(UINT flags, SIZE_T n) { return (flags & LMEM_ZEROINIT) ? calloc(1,n) : malloc(n); }
static inline HLOCAL LocalFree(HLOCAL p) { free(p); return NULL; }
static inline HGLOBAL GlobalAlloc(UINT flags, SIZE_T n) { return (flags & LMEM_ZEROINIT) ? calloc(1,n) : malloc(n); }
static inline HGLOBAL GlobalFree(HGLOBAL p) { free(p); return NULL; }
static inline LPVOID  GlobalLock(HGLOBAL p) { return p; }
static inline BOOL    GlobalUnlock(HGLOBAL p) { (void)p; return TRUE; }
static inline SIZE_T  GlobalSize(HGLOBAL p) { (void)p; return 0; }
static inline PVOID   VirtualAlloc(PVOID a, SIZE_T s, DWORD t, DWORD p) { (void)a;(void)t;(void)p; return malloc(s); }
static inline BOOL    VirtualFree(PVOID p, SIZE_T s, DWORD t) { (void)s;(void)t; free(p); return TRUE; }

/* ---- MessageBox stub ---- */
static inline int MessageBoxA(HWND h, LPCSTR t, LPCSTR c, UINT f) {
    (void)h;(void)f;
    fprintf(stderr, "[%s] %s\n", c ? c : "", t ? t : "");
    return IDOK;
}
#define MessageBox MessageBoxA

/* ---- Sleep ---- */
static inline void Sleep(DWORD ms) {
    struct timespec ts = { ms/1000, (ms%1000)*1000000L };
    nanosleep(&ts, NULL);
}

/* ---- Misc stubs ---- */
#define _MAX_PATH MAX_PATH
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#define _WIN32_IE 0x0A00

/* ---- String functions ---- */
#define lstrcpyA  strcpy
#define lstrcpynA strncpy
#define lstrcatA  strcat
#define lstrlenA  (int)strlen
#define CompareStringA(l,f,s1,c1,s2,c2) strcasecmp(s1,s2)
#define CharLowerA(s) (s)
#define CharUpperA(s) (s)

/* ---- Numeric conversion ---- */
#define atoi64 atoll
#define _atoi64 atoll

/* ---- Unused annotation ---- */
#define UNREFERENCED_PARAMETER(p) (void)(p)

/* ---- COM stub macros ---- */
#define DECLARE_INTERFACE(i)      struct i
#define DECLARE_INTERFACE_(i,b)   struct i
#define STDMETHOD(m)              HRESULT (WINAPI *m)
#define STDMETHOD_(t,m)           t (WINAPI *m)
#define PURE
#define THIS_                     void* This,
#define THIS                      void* This
#define DECLARE_HANDLE(name)      typedef HANDLE name

/* ---- Misc types ---- */
typedef DWORD COLORREF;
#define RGB(r,g,b) ((COLORREF)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))
#define GetRValue(rgb) (LOBYTE(rgb))
#define GetGValue(rgb) (LOBYTE(((WORD)(rgb)) >> 8))
#define GetBValue(rgb) (LOBYTE((rgb)>>16))

typedef struct tagPAINTSTRUCT { HDC hdc; BOOL fErase; RECT rcPaint; BOOL fRestore; BOOL fIncUpdate; BYTE rgbReserved[32]; } PAINTSTRUCT, *PPAINTSTRUCT;
typedef struct tagLOGFONTA { LONG lfHeight; LONG lfWidth; LONG lfEscapement; LONG lfOrientation; LONG lfWeight; BYTE lfItalic; BYTE lfUnderline; BYTE lfStrikeOut; BYTE lfCharSet; BYTE lfOutPrecision; BYTE lfClipPrecision; BYTE lfQuality; BYTE lfPitchAndFamily; CHAR lfFaceName[32]; } LOGFONTA, *PLOGFONTA;
typedef LOGFONTA LOGFONT;

/* ---- Exception / SEH stubs ---- */
#define __try       if(1)
#define __except(x) if(0)
#define __finally
#define GetExceptionCode() 0

/* ---- Misc ---- */
#define VOID void
#define IN
#define OUT
#define OPTIONAL
#define FAR
#define NEAR
#define CONST const
#define interface struct
#define EXTERN_C extern

/* Language IDs */
#define LANG_NEUTRAL                 0x00
#define LANG_ENGLISH                 0x09
#define SUBLANG_DEFAULT              0x01
#define SUBLANG_NEUTRAL              0x00
#define MAKELANGID(p,s)              ((WORD)(((WORD)(s) << 10) | (WORD)(p)))
#define PRIMARYLANGID(lgid)          ((WORD)(lgid) & 0x3ff)
#define SUBLANGID(lgid)              ((WORD)(lgid) >> 10)
#define MAKELCID(lgid,srtid)         ((DWORD)(((DWORD)((WORD)(srtid)))<<16)|((DWORD)((WORD)(lgid))))
#define SORT_DEFAULT                 0x0
#define LOCALE_USER_DEFAULT          MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), SORT_DEFAULT)
#define LOCALE_SYSTEM_DEFAULT        MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), SORT_DEFAULT)

/* Thread priorities */
#define THREAD_PRIORITY_ABOVE_NORMAL 1
#define THREAD_PRIORITY_NORMAL       0
#define THREAD_PRIORITY_BELOW_NORMAL (-1)
#define THREAD_PRIORITY_HIGHEST      2
#define THREAD_PRIORITY_LOWEST       (-2)
#define THREAD_PRIORITY_IDLE         (-15)
#define THREAD_PRIORITY_TIME_CRITICAL 15

/* Image machine types */
#define IMAGE_FILE_MACHINE_UNKNOWN   0
#define IMAGE_FILE_MACHINE_I386      0x014c
#define IMAGE_FILE_MACHINE_AMD64     0x8664
#define IMAGE_FILE_MACHINE_ARM       0x01c0
#define IMAGE_FILE_MACHINE_ARM64     0xAA64
#define IMAGE_FILE_MACHINE_ARMNT     0x01c4

/* ---- BOOLEAN type ---- */
#ifndef BOOLEAN
typedef BYTE BOOLEAN;
#endif

/* ---- Dialog/callback types ---- */
typedef INT_PTR (CALLBACK *DLGPROC)(HWND, UINT, WPARAM, LPARAM);
typedef LRESULT (CALLBACK *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef VOID (CALLBACK *TIMERPROC)(HWND, UINT, UINT_PTR, DWORD);
typedef BOOL (CALLBACK *WNDENUMPROC)(HWND, LPARAM);
typedef void* FARPROC;

/* ---- min/max macros ---- */
#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif
#define __min min
#define __max max

/* ---- HRESULT severity/facility ---- */
#define SEVERITY_SUCCESS     0
#define SEVERITY_ERROR       1
#define ERROR_SEVERITY_SUCCESS   0x00000000
#define ERROR_SEVERITY_INFORMATIONAL 0x40000000
#define ERROR_SEVERITY_WARNING   0x80000000
#define ERROR_SEVERITY_ERROR     0xC0000000
#ifndef APPLICATION_ERROR_MASK
#define APPLICATION_ERROR_MASK   0x20000000
#endif

/* Facility codes */
#define FACILITY_NULL        0
#define FACILITY_RPC         1
#define FACILITY_DISPATCH    2
#define FACILITY_STORAGE     3
#define FACILITY_ITF         4
#define FACILITY_WIN32       7
#define FACILITY_WINDOWS     8
#define FACILITY_SECURITY    9
#define FACILITY_SSPI        9
#define FACILITY_CONTROL     10
#define FACILITY_CERT        11
#define FACILITY_INTERNET    12
#define FACILITY_MEDIASERVER 13
#define FACILITY_MSMQ        14
#define FACILITY_SETUPAPI    15
#define FACILITY_SCARD       16
#define FACILITY_COMPLUS     17
#define FACILITY_AAF         18
#define FACILITY_URT         19
#define FACILITY_ACS         20
#define FACILITY_DPLAY       21
#define FACILITY_UMI         22
#define FACILITY_SXS         23
#define FACILITY_WINDOWS_CE  24
#define FACILITY_HTTP        25
#define FACILITY_USERMODE_COMMONLOG 26
#define FACILITY_USERMODE_FILTER_MANAGER 31
#define FACILITY_BACKGROUNDCOPY 32
#define FACILITY_CONFIGURATION  33
#define FACILITY_STATE_MANAGEMENT 34
#define FACILITY_METADIRECTORY 35

/* HRESULT / SCODE helpers */
#ifndef SCODE_CODE
#define SCODE_CODE(sc)       ((DWORD)(sc) & 0xFFFF)
#endif
#ifndef SCODE_FACILITY
#define SCODE_FACILITY(sc)   (((DWORD)(sc) >> 16) & 0x1FFF)
#endif
#ifndef SCODE_SEVERITY
#define SCODE_SEVERITY(sc)   (((DWORD)(sc) >> 31) & 0x1)
#endif
#ifndef IS_ERROR
#define IS_ERROR(scode)      (((DWORD)(scode) >> 31) == 1)
#endif
#ifndef HRESULT_SEVERITY
#define HRESULT_SEVERITY(hr) (((DWORD)(hr) >> 31) & 0x1)
#endif

/* ---- Additional error codes ---- */
#define ERROR_TOO_MANY_OPEN_FILES    4L
#define ERROR_ARENA_TRASHED          7L
#define ERROR_INVALID_BLOCK          9L
#define ERROR_OBJECT_IN_LIST         5000L
#define ERROR_BAD_ENVIRONMENT        10L
#define ERROR_BAD_FORMAT             11L
#define ERROR_INVALID_ACCESS         12L
#define ERROR_INVALID_DATA           13L
#define ERROR_INVALID_DRIVE          15L
#define ERROR_CURRENT_DIRECTORY      16L
#define ERROR_NOT_SAME_DEVICE        17L
#define ERROR_NO_MORE_FILES          18L
#define ERROR_WRITE_PROTECT          19L
#define ERROR_BAD_UNIT               20L
#define ERROR_BAD_NETPATH            53L
#define ERROR_NETWORK_ACCESS_DENIED  65L
#define ERROR_BAD_NET_NAME           67L
#define ERROR_CANNOT_MAKE            82L
#define ERROR_FAIL_I24               83L
#define ERROR_NO_PROC_SLOTS          89L
#define ERROR_DRIVE_LOCKED           108L
#define ERROR_BROKEN_PIPE            109L
#define ERROR_DISK_FULL              112L
#define ERROR_INVALID_TARGET_HANDLE  114L
#define ERROR_WAIT_NO_CHILDREN       128L
#define ERROR_CHILD_NOT_COMPLETE     129L
#define ERROR_DIRECT_ACCESS_HANDLE   130L
#define ERROR_NEGATIVE_SEEK          131L
#define ERROR_SEEK_ON_DEVICE         132L
#define ERROR_DIR_NOT_EMPTY          145L
#define ERROR_NOT_LOCKED             158L
#define ERROR_BAD_PATHNAME           161L
#define ERROR_MAX_THRDS_REACHED      164L
#define ERROR_LOCK_FAILED            167L
#define ERROR_BUSY                   170L
#define ERROR_CANCEL_VIOLATION       173L
#define ERROR_ATOMIC_LOCKS_NOT_SUPPORTED 174L
#define ERROR_WRITE_FAULT            29L
#define ERROR_READ_FAULT             30L
#define ERROR_GEN_FAILURE            31L
#define ERROR_SEEK                   25L
#define ERROR_DEV_NOT_EXIST          55L
#define ERROR_NETWORK_BUSY           54L
#define ERROR_ADAP_HDW_ERR           57L
#define ERROR_BAD_NET_RESP           58L
#define ERROR_UNEXP_NET_ERR          59L
#define ERROR_BAD_REM_ADAP           60L
#define ERROR_PRINTQ_FULL            61L
#define ERROR_NO_SPOOL_SPACE         62L
#define ERROR_PRINT_CANCELLED        63L
#define ERROR_NETNAME_DELETED        64L
#define ERROR_NETWORK_ACCESS_DENIED  65L
#define ERROR_SECTOR_NOT_FOUND       27L
#define ERROR_OUT_OF_PAPER           28L
#define ERROR_FILE_CORRUPT           1392L
#define ERROR_OPERATION_ABORTED      995L
#define ERROR_IO_INCOMPLETE          996L
#define ERROR_IO_PENDING             997L
#define ERROR_NOACCESS               998L
#define ERROR_SWAPERROR              999L
#define ERROR_PRIVILEGE_NOT_HELD     1314L
#define ERROR_DEVICE_NOT_CONNECTED   1167L
#define ERROR_DEVICE_BUSY            1165L
#define ERROR_DEVICE_IN_USE          2404L
#define ERROR_LABEL_TOO_LONG         154L
#define ERROR_NO_MEDIA_IN_DRIVE      1112L
#define ERROR_INSTALL_FAILURE        1603L
#define ERROR_PARTITION_FAILURE      1105L
#define ERROR_CANNOT_COPY            266L

/* ---- File I/O stubs ---- */
static inline BOOL ReadFile(HANDLE h, LPVOID buf, DWORD n, LPDWORD rd, LPOVERLAPPED ov) {
    (void)ov;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ssize_t r = read((int)(intptr_t)h, buf, n);
    if (rd) *rd = (r > 0) ? (DWORD)r : 0;
    return (r >= 0);
}
static inline BOOL WriteFile(HANDLE h, LPCVOID buf, DWORD n, LPDWORD wr, LPOVERLAPPED ov) {
    (void)ov;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ssize_t r = write((int)(intptr_t)h, buf, n);
    if (wr) *wr = (r > 0) ? (DWORD)r : 0;
    return (r >= 0);
}
static inline BOOL SetFilePointerEx(HANDLE h, LARGE_INTEGER dist, PLARGE_INTEGER newpos, DWORD method) {
    int whence = (method == FILE_BEGIN) ? SEEK_SET : (method == FILE_END ? SEEK_END : SEEK_CUR);
    if (method == FILE_BEGIN) {
        uint64_t base = linux_get_fd_base_offset((int)(intptr_t)h);
        dist.QuadPart += (LONGLONG)base;
    }
    off_t r = lseek((int)(intptr_t)h, (off_t)dist.QuadPart, whence);
    if (newpos) newpos->QuadPart = r;
    return (r != (off_t)-1);
}
static inline DWORD SetFilePointer(HANDLE h, LONG dist, PLONG disthigh, DWORD method) {
    LARGE_INTEGER d; d.QuadPart = dist;
    if (disthigh) d.HighPart = *disthigh;
    LARGE_INTEGER np; np.QuadPart = 0;
    SetFilePointerEx(h, d, &np, method);
    return (DWORD)np.LowPart;
}
static inline HANDLE CreateFileA(LPCSTR path, DWORD access, DWORD share,
    LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl) {
    (void)share;(void)sa;(void)flags;(void)tmpl;
    int oflags = 0;
    if ((access & GENERIC_READ) && (access & GENERIC_WRITE)) oflags = O_RDWR;
    else if (access & GENERIC_WRITE) oflags = O_WRONLY;
    else oflags = O_RDONLY;
    if (disp == CREATE_ALWAYS || disp == OPEN_ALWAYS) oflags |= O_CREAT;
    if (disp == CREATE_ALWAYS || disp == TRUNCATE_EXISTING) oflags |= O_TRUNC;
    if (disp == CREATE_NEW) oflags |= O_CREAT|O_EXCL;
    int fd = open(path, oflags, 0666);
    return (fd >= 0) ? (HANDLE)(intptr_t)fd : INVALID_HANDLE_VALUE;
}
#define CreateFile CreateFileA
/* ===========================================================================
 * Threading / synchronisation bridge (pthread → Win32 API)
 *
 * HANDLE values are one of:
 *   • A raw file descriptor cast:   (HANDLE)(intptr_t)fd   — small integer
 *   • A win_handle_t* (heap):       thread / event / mutex  — large pointer
 *
 * We distinguish them by: if (uintptr_t)h < WIN_HANDLE_ADDR_THRESHOLD, treat
 * as fd; otherwise check the win_handle_t magic word.  On any modern 64-bit
 * Linux, malloc() never returns a pointer below 64 KB, while fds are always
 * small (< ~1 M in practice, well below the 1 MB threshold).
 * =========================================================================*/

#define WIN_HANDLE_MAGIC          0x57494E48u   /* "WINH" */
#define WIN_HANDLE_ADDR_THRESHOLD ((uintptr_t)(1u << 20)) /* 1 MB */

typedef enum {
    WH_THREAD = 1,
    WH_EVENT  = 2,
    WH_MUTEX  = 3
} _wh_type_t;

typedef struct _win_handle_s {
    uint32_t    magic;   /* WIN_HANDLE_MAGIC — must be first field */
    _wh_type_t  type;
    union {
        /* --- Thread --- */
        struct {
            pthread_t tid;
            DWORD     exit_code;
            int       joined;   /* 1 after pthread_join completes */
        } thread;
        /* --- Event (auto-reset or manual-reset) --- */
        struct {
            pthread_mutex_t mx;
            pthread_cond_t  cond;
            int             signaled;
            int             manual_reset;
        } event;
        /* --- Mutex --- */
        struct {
            pthread_mutex_t mx;
        } mutex;
    } u;
} _win_handle_t;

/* Returns 1 if h points to a valid win_handle_t (thread/event/mutex).
 * Returns 0 if h is NULL, INVALID_HANDLE_VALUE, or a raw fd cast.       */
static inline int _wh_is_sync(HANDLE h)
{
    uintptr_t v = (uintptr_t)h;
    if (v < WIN_HANDLE_ADDR_THRESHOLD) return 0;
    if (h == INVALID_HANDLE_VALUE)     return 0;
    return ((_win_handle_t *)h)->magic == WIN_HANDLE_MAGIC;
}

/* Internal helper: compute an absolute timespec deadline for timeouts.   */
static inline struct timespec _wh_deadline(DWORD ms)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += (time_t)(ms / 1000);
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    return ts;
}

/* ---------------------------------------------------------------------------
 * Thread wrapper: adapts pthreads void* return to Windows DWORD exit code.
 * -------------------------------------------------------------------------*/
typedef struct {
    DWORD (WINAPI *fn)(LPVOID);
    LPVOID         param;
    _win_handle_t *handle;
} _wh_thread_args_t;

static void * __attribute__((unused))
_wh_thread_wrapper(void *raw)
{
    _wh_thread_args_t *a = (_wh_thread_args_t *)raw;
    _win_handle_t     *h = a->handle;
    DWORD (WINAPI *fn)(LPVOID) = a->fn;
    LPVOID param = a->param;
    free(a);
    DWORD ec = fn(param);
    h->u.thread.exit_code = ec;
    return (void *)(uintptr_t)ec;
}

/* ---------------------------------------------------------------------------
 * CRITICAL_SECTION  (recursive mutex)
 * -------------------------------------------------------------------------*/
typedef struct {
    pthread_mutex_t _mx;
} CRITICAL_SECTION, *LPCRITICAL_SECTION, *PCRITICAL_SECTION;

static inline void InitializeCriticalSection(LPCRITICAL_SECTION cs)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&cs->_mx, &attr);
    pthread_mutexattr_destroy(&attr);
}
static inline void InitializeCriticalSectionEx(LPCRITICAL_SECTION cs,
                                               DWORD spin, DWORD flags)
{
    (void)spin; (void)flags;
    InitializeCriticalSection(cs);
}
static inline void EnterCriticalSection(LPCRITICAL_SECTION cs)
{
    pthread_mutex_lock(&cs->_mx);
}
static inline void LeaveCriticalSection(LPCRITICAL_SECTION cs)
{
    pthread_mutex_unlock(&cs->_mx);
}
static inline BOOL TryEnterCriticalSection(LPCRITICAL_SECTION cs)
{
    return pthread_mutex_trylock(&cs->_mx) == 0;
}
static inline void DeleteCriticalSection(LPCRITICAL_SECTION cs)
{
    pthread_mutex_destroy(&cs->_mx);
}

/* ---------------------------------------------------------------------------
 * CloseHandle: close fd *or* free a win_handle_t sync object.
 * -------------------------------------------------------------------------*/
static inline BOOL CloseHandle(HANDLE h)
{
    if (!h || h == INVALID_HANDLE_VALUE) return FALSE;

    if (_wh_is_sync(h)) {
        _win_handle_t *wh = (_win_handle_t *)h;
        switch (wh->type) {
        case WH_THREAD:
            if (!wh->u.thread.joined) {
                void *_rv = NULL;
                pthread_join(wh->u.thread.tid, &_rv);
                wh->u.thread.exit_code = (DWORD)(uintptr_t)_rv;
            }
            break;
        case WH_EVENT:
            pthread_cond_destroy(&wh->u.event.cond);
            pthread_mutex_destroy(&wh->u.event.mx);
            break;
        case WH_MUTEX:
            pthread_mutex_destroy(&wh->u.mutex.mx);
            break;
        }
        wh->magic = 0;   /* invalidate */
        free(wh);
        return TRUE;
    }

    linux_unregister_fd_offset((int)(intptr_t)h);
    return close((int)(intptr_t)h) == 0;
}
static inline BOOL GetFileSizeEx(HANDLE h, PLARGE_INTEGER size) {
    struct stat st;
    if (fstat((int)(intptr_t)h, &st) != 0) return FALSE;
    if (size) size->QuadPart = st.st_size;
    return TRUE;
}
static inline DWORD GetFileSize(HANDLE h, LPDWORD high) {
    LARGE_INTEGER sz; sz.QuadPart = 0;
    GetFileSizeEx(h, &sz);
    if (high) *high = sz.HighPart;
    return sz.LowPart;
}
static inline BOOL DeleteFileA(LPCSTR p) { return unlink(p) == 0; }
#define DeleteFile DeleteFileA
static inline BOOL MoveFileExA(LPCSTR src, LPCSTR dst, DWORD f) { (void)f; return rename(src, dst) == 0; }
#define MoveFileEx MoveFileExA
#define MoveFile(s,d) MoveFileExA(s,d,0)
static inline BOOL FlushFileBuffers(HANDLE h) { return fsync((int)(intptr_t)h) == 0; }
static inline BOOL DeviceIoControl(HANDLE h, DWORD ctl, LPVOID in, DWORD insz,
    LPVOID out, DWORD outsz, LPDWORD ret, LPOVERLAPPED ov) {
    (void)h;(void)ctl;(void)in;(void)insz;(void)out;(void)outsz;(void)ret;(void)ov;
    return FALSE;
}
static inline BOOL GetOverlappedResult(HANDLE h, LPOVERLAPPED ov, LPDWORD tr, BOOL w) {
    (void)h;(void)ov;(void)tr;(void)w; return FALSE;
}
static inline HANDLE CreateEventA(LPSECURITY_ATTRIBUTES sa, BOOL manual,
                                  BOOL init, LPCSTR name)
{
    (void)sa; (void)name;
    _win_handle_t *wh = (_win_handle_t *)malloc(sizeof(_win_handle_t));
    if (!wh) return NULL;
    wh->magic             = WIN_HANDLE_MAGIC;
    wh->type              = WH_EVENT;
    pthread_mutex_init(&wh->u.event.mx, NULL);
    pthread_cond_init(&wh->u.event.cond, NULL);
    wh->u.event.signaled     = init     ? 1 : 0;
    wh->u.event.manual_reset = manual   ? 1 : 0;
    return (HANDLE)wh;
}
#define CreateEvent CreateEventA

static inline BOOL SetEvent(HANDLE h)
{
    if (!_wh_is_sync(h)) return FALSE;
    _win_handle_t *wh = (_win_handle_t *)h;
    if (wh->type != WH_EVENT) return FALSE;
    pthread_mutex_lock(&wh->u.event.mx);
    wh->u.event.signaled = 1;
    /* Manual-reset: wake all waiters; auto-reset: wake one */
    if (wh->u.event.manual_reset)
        pthread_cond_broadcast(&wh->u.event.cond);
    else
        pthread_cond_signal(&wh->u.event.cond);
    pthread_mutex_unlock(&wh->u.event.mx);
    return TRUE;
}

static inline BOOL ResetEvent(HANDLE h)
{
    if (!_wh_is_sync(h)) return FALSE;
    _win_handle_t *wh = (_win_handle_t *)h;
    if (wh->type != WH_EVENT) return FALSE;
    pthread_mutex_lock(&wh->u.event.mx);
    wh->u.event.signaled = 0;
    pthread_mutex_unlock(&wh->u.event.mx);
    return TRUE;
}

static inline DWORD WaitForSingleObject(HANDLE h, DWORD ms)
{
    if (!h || h == INVALID_HANDLE_VALUE) return WAIT_FAILED;

    if (!_wh_is_sync(h))
        /* Raw fd handle — not a waitable object in the sync sense */
        return WAIT_OBJECT_0;

    _win_handle_t *wh = (_win_handle_t *)h;

    switch (wh->type) {

    case WH_THREAD: {
        if (wh->u.thread.joined) return WAIT_OBJECT_0;
        if (ms == INFINITE) {
            void *_rv = NULL;
            pthread_join(wh->u.thread.tid, &_rv);
            wh->u.thread.exit_code = (DWORD)(uintptr_t)_rv;
            wh->u.thread.joined = 1;
            return WAIT_OBJECT_0;
        }
        struct timespec ts = _wh_deadline(ms);
        void *_rv = NULL;
        int r = pthread_timedjoin_np(wh->u.thread.tid, &_rv, &ts);
        if (r == 0) {
            wh->u.thread.exit_code = (DWORD)(uintptr_t)_rv;
            wh->u.thread.joined = 1;
            return WAIT_OBJECT_0;
        }
        if (r == ETIMEDOUT) return WAIT_TIMEOUT;
        return WAIT_FAILED;
    }

    case WH_EVENT: {
        pthread_mutex_lock(&wh->u.event.mx);
        DWORD result;
        if (ms == INFINITE) {
            while (!wh->u.event.signaled)
                pthread_cond_wait(&wh->u.event.cond, &wh->u.event.mx);
            result = WAIT_OBJECT_0;
        } else {
            struct timespec ts = _wh_deadline(ms);
            int r = 0;
            while (!wh->u.event.signaled && r != ETIMEDOUT)
                r = pthread_cond_timedwait(&wh->u.event.cond,
                                           &wh->u.event.mx, &ts);
            result = wh->u.event.signaled ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
        }
        /* Auto-reset: clear signal after waking one waiter */
        if (result == WAIT_OBJECT_0 && !wh->u.event.manual_reset)
            wh->u.event.signaled = 0;
        pthread_mutex_unlock(&wh->u.event.mx);
        return result;
    }

    case WH_MUTEX: {
        if (ms == INFINITE) {
            pthread_mutex_lock(&wh->u.mutex.mx);
            return WAIT_OBJECT_0;
        }
        struct timespec ts = _wh_deadline(ms);
        int r = pthread_mutex_timedlock(&wh->u.mutex.mx, &ts);
        if (r == 0)         return WAIT_OBJECT_0;
        if (r == ETIMEDOUT) return WAIT_TIMEOUT;
        return WAIT_FAILED;
    }

    default:
        return WAIT_FAILED;
    }
}

static inline DWORD WaitForMultipleObjects(DWORD n, const HANDLE *handles,
                                           BOOL all, DWORD ms)
{
    if (all) {
        for (DWORD i = 0; i < n; i++) {
            DWORD r = WaitForSingleObject(handles[i], ms);
            if (r != WAIT_OBJECT_0)
                return r;  /* propagate TIMEOUT / FAILED */
        }
        return WAIT_OBJECT_0;
    } else {
        /* Wait-for-any: poll in a loop with a short sleep between rounds */
        struct timespec deadline = {0,0};
        int has_deadline = 0;
        if (ms != INFINITE) {
            deadline    = _wh_deadline(ms);
            has_deadline = 1;
        }
        for (;;) {
            for (DWORD i = 0; i < n; i++) {
                DWORD r = WaitForSingleObject(handles[i], 0);
                if (r == WAIT_OBJECT_0)
                    return WAIT_OBJECT_0 + i;
            }
            if (has_deadline) {
                struct timespec now;
                clock_gettime(CLOCK_REALTIME, &now);
                if (now.tv_sec > deadline.tv_sec ||
                    (now.tv_sec == deadline.tv_sec &&
                     now.tv_nsec >= deadline.tv_nsec))
                    return WAIT_TIMEOUT;
            }
            struct timespec sl = {0, 1000000}; /* 1 ms */
            nanosleep(&sl, NULL);
        }
    }
}

/* ---- Mutex ---- */
static inline HANDLE CreateMutexA(LPSECURITY_ATTRIBUTES sa, BOOL own,
                                   LPCSTR name)
{
    (void)sa; (void)name;
    _win_handle_t *wh = (_win_handle_t *)malloc(sizeof(_win_handle_t));
    if (!wh) return NULL;
    wh->magic = WIN_HANDLE_MAGIC;
    wh->type  = WH_MUTEX;
    pthread_mutex_init(&wh->u.mutex.mx, NULL);
    if (own) pthread_mutex_lock(&wh->u.mutex.mx);
    return (HANDLE)wh;
}
#define CreateMutex CreateMutexA

static inline BOOL ReleaseMutex(HANDLE h)
{
    if (!_wh_is_sync(h)) return FALSE;
    _win_handle_t *wh = (_win_handle_t *)h;
    if (wh->type != WH_MUTEX) return FALSE;
    return pthread_mutex_unlock(&wh->u.mutex.mx) == 0;
}

/* ---- Thread ---- */
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

static inline HANDLE CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stack,
                                   LPTHREAD_START_ROUTINE fn, LPVOID param,
                                   DWORD flags, LPDWORD out_tid)
{
    (void)sa; (void)stack; (void)flags;

    _win_handle_t *wh = (_win_handle_t *)malloc(sizeof(_win_handle_t));
    if (!wh) return NULL;
    wh->magic              = WIN_HANDLE_MAGIC;
    wh->type               = WH_THREAD;
    wh->u.thread.exit_code = 0;
    wh->u.thread.joined    = 0;

    _wh_thread_args_t *a = (_wh_thread_args_t *)malloc(sizeof(_wh_thread_args_t));
    if (!a) { free(wh); return NULL; }
    a->fn     = fn;
    a->param  = param;
    a->handle = wh;

    if (pthread_create(&wh->u.thread.tid, NULL, _wh_thread_wrapper, a) != 0) {
        free(a);
        free(wh);
        return NULL;
    }

    if (out_tid) *out_tid = (DWORD)wh->u.thread.tid;
    return (HANDLE)wh;
}

static inline BOOL TerminateThread(HANDLE h, DWORD code)
{
    (void)code;
    if (!_wh_is_sync(h)) return FALSE;
    _win_handle_t *wh = (_win_handle_t *)h;
    if (wh->type != WH_THREAD) return FALSE;
    return pthread_cancel(wh->u.thread.tid) == 0;
}

static inline BOOL SetThreadPriority(HANDLE h, int prio)
{
    (void)h; (void)prio;
    return TRUE;   /* scheduler priority — ignored on Linux */
}

static inline DWORD_PTR SetThreadAffinityMask(HANDLE h, DWORD_PTR mask)
{
    if (mask == 0) return 0;

    cpu_set_t cs;
    CPU_ZERO(&cs);
    for (int i = 0; i < (int)(sizeof(DWORD_PTR) * 8); i++) {
        if (mask & ((DWORD_PTR)1 << i))
            CPU_SET(i, &cs);
    }

    /* Handle GetCurrentThread() pseudo-handle (returns 0 on Linux) */
    if (h == NULL || h == (HANDLE)0) {
        pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);
        return mask;
    }
    if (!_wh_is_sync(h)) return 0;
    _win_handle_t *wh = (_win_handle_t *)h;
    if (wh->type != WH_THREAD) return 0;
    pthread_setaffinity_np(wh->u.thread.tid, sizeof(cs), &cs);
    return mask; /* approximate: return new mask as old */
}

static inline BOOL GetExitCodeThread(HANDLE h, LPDWORD code)
{
    if (!_wh_is_sync(h)) return FALSE;
    _win_handle_t *wh = (_win_handle_t *)h;
    if (wh->type != WH_THREAD) return FALSE;
    if (!wh->u.thread.joined) {
        /* Thread still running — return STILL_ACTIVE */
        if (code) *code = 259; /* STILL_ACTIVE */
        return TRUE;
    }
    if (code) *code = wh->u.thread.exit_code;
    return TRUE;
}

static inline void ExitThread(DWORD code)
{
    pthread_exit((void *)(uintptr_t)code);
}

/* ---- Process stubs ---- */
static inline HANDLE OpenProcess(DWORD access, BOOL inh, DWORD pid) { (void)access;(void)inh;(void)pid; return NULL; }
static inline BOOL TerminateProcess(HANDLE h, UINT code) { (void)h;(void)code; return FALSE; }
static inline BOOL GetExitCodeProcess(HANDLE h, LPDWORD code) { (void)h;(void)code; return FALSE; }

/* ---- Token/privilege stubs ---- */
#define TOKEN_QUERY         0x0008
#define TOKEN_ADJUST_PRIVILEGES 0x0020
static inline BOOL OpenProcessToken(HANDLE h, DWORD access, HANDLE* tok) { (void)h;(void)access;(void)tok; return FALSE; }
static inline BOOL OpenThreadToken(HANDLE h, DWORD access, BOOL self, HANDLE* tok) { (void)h;(void)access;(void)self;(void)tok; return FALSE; }

/* ---- Registry stubs ---- */
static inline LONG RegOpenKeyExA(HKEY h, LPCSTR sk, DWORD opt, DWORD sam, HKEY* res) { (void)h;(void)sk;(void)opt;(void)sam;(void)res; return -1; }
static inline LONG RegQueryValueExA(HKEY h, LPCSTR n, LPDWORD r, LPDWORD t, LPBYTE d, LPDWORD ds) { (void)h;(void)n;(void)r;(void)t;(void)d;(void)ds; return -1; }
static inline LONG RegSetValueExA(HKEY h, LPCSTR n, DWORD r, DWORD t, const BYTE* d, DWORD ds) { (void)h;(void)n;(void)r;(void)t;(void)d;(void)ds; return -1; }
static inline LONG RegCloseKey(HKEY h) { (void)h; return 0; }
static inline LONG RegCreateKeyExA(HKEY h, LPCSTR sk, DWORD r, LPSTR cls, DWORD opt, DWORD sam, LPSECURITY_ATTRIBUTES sa, HKEY* res, LPDWORD disp) { (void)h;(void)sk;(void)r;(void)cls;(void)opt;(void)sam;(void)sa;(void)res;(void)disp; return -1; }
static inline LONG RegDeleteKeyA(HKEY h, LPCSTR sk) { (void)h;(void)sk; return -1; }
static inline LONG RegDeleteValueA(HKEY h, LPCSTR n) { (void)h;(void)n; return -1; }
#define RegOpenKeyEx RegOpenKeyExA
#define RegQueryValueEx RegQueryValueExA
#define RegSetValueEx RegSetValueExA
#define RegCreateKeyEx RegCreateKeyExA
#define RegDeleteKey RegDeleteKeyA
#define RegDeleteValue RegDeleteValueA

/* ---- Windows version stubs ---- */
static inline BOOL GetVersionExA(OSVERSIONINFOEXA* vi) { (void)vi; return FALSE; }
#define GetVersionEx GetVersionExA

/* ---- Environment/path stubs ---- */
static inline DWORD GetEnvironmentVariableA(LPCSTR n, LPSTR buf, DWORD sz) {
    char* v = getenv(n);
    if (!v) return 0;
    if (buf) strncpy(buf, v, sz);
    return (DWORD)strlen(v);
}
#define GetEnvironmentVariable GetEnvironmentVariableA
static inline BOOL SetEnvironmentVariableA(LPCSTR n, LPCSTR v) { return setenv(n, v ? v : "", 1) == 0; }
#define SetEnvironmentVariable SetEnvironmentVariableA
static inline DWORD GetTempPathA(DWORD sz, LPSTR buf) {
    const char* t = getenv("TMPDIR"); if (!t) t = "/tmp";
    if (buf) strncpy(buf, t, sz);
    return (DWORD)strlen(t);
}
#define GetTempPath GetTempPathA
static inline UINT GetTempFileNameA(LPCSTR path, LPCSTR prefix, UINT unum, LPSTR tmpfile) {
    (void)unum;
    snprintf(tmpfile, MAX_PATH, "%s/%sXXXXXX", path ? path : "/tmp", prefix ? prefix : "tmp");
    int fd = mkstemp(tmpfile);
    if (fd >= 0) close(fd);
    return (UINT)fd;
}
#define GetTempFileName GetTempFileNameA
static inline DWORD GetModuleFileNameA(HMODULE h, LPSTR buf, DWORD sz) {
    (void)h;
    ssize_t r = readlink("/proc/self/exe", buf, sz - 1);
    if (r < 0) return 0;
    buf[r] = 0;
    return (DWORD)r;
}
#define GetModuleFileName GetModuleFileNameA
static inline HMODULE GetModuleHandleA(LPCSTR n) { (void)n; return NULL; }
#define GetModuleHandle GetModuleHandleA
static inline HMODULE GetModuleHandleW(LPCWSTR n) { (void)n; return NULL; }
static inline HMODULE LoadLibraryA(LPCSTR n) { (void)n; return NULL; }
#define LoadLibrary LoadLibraryA
static inline HMODULE LoadLibraryExA(LPCSTR n, HANDLE f, DWORD fl) { (void)n;(void)f;(void)fl; return NULL; }
static inline HMODULE LoadLibraryExW(LPCWSTR n, HANDLE f, DWORD fl) { (void)n;(void)f;(void)fl; return NULL; }
#define LOAD_LIBRARY_SEARCH_SYSTEM32    0x00000800
#define LOAD_LIBRARY_AS_DATAFILE        0x00000002
#define LOAD_LIBRARY_AS_IMAGE_RESOURCE  0x00000020
static inline BOOL FreeLibrary(HMODULE h) { (void)h; return FALSE; }
static inline FARPROC GetProcAddress(HMODULE h, LPCSTR n) { (void)h;(void)n; return NULL; }

/* ---- SetLastError / FormatMessage stubs ---- */
static inline DWORD FormatMessageA(DWORD flags, LPCVOID src, DWORD msgid, DWORD langid, LPSTR buf, DWORD sz, va_list* args) {
    (void)flags;(void)src;(void)langid;(void)args;
    if (buf && sz) snprintf(buf, sz, "Error %lu", msgid);
    return buf ? (DWORD)strlen(buf) : 0;
}
#define FORMAT_MESSAGE_FROM_SYSTEM      0x00001000
#define FORMAT_MESSAGE_IGNORE_INSERTS   0x00000200
#define FORMAT_MESSAGE_FROM_HMODULE     0x00000800
#define FORMAT_MESSAGE_FROM_STRING      0x00000400
#define FORMAT_MESSAGE_ALLOCATE_BUFFER  0x00000100
#define FORMAT_MESSAGE_ARGUMENT_ARRAY   0x00002000

/* ---- GetFileAttributes stub ---- */
static inline DWORD GetFileAttributesA(LPCSTR p) {
    struct stat st;
    if (stat(p, &st) != 0) return 0xFFFFFFFF; /* INVALID_FILE_ATTRIBUTES */
    DWORD attr = 0;
    if (S_ISDIR(st.st_mode)) attr |= FILE_ATTRIBUTE_DIRECTORY;
    if (!(st.st_mode & S_IRUSR)) attr |= FILE_ATTRIBUTE_READONLY;
    if (!attr) attr = FILE_ATTRIBUTE_NORMAL;
    return attr;
}
#define GetFileAttributes GetFileAttributesA
#define INVALID_FILE_ATTRIBUTES ((DWORD)0xFFFFFFFF)
static inline BOOL SetFileAttributesA(LPCSTR p, DWORD a) { (void)p;(void)a; return FALSE; }
#define SetFileAttributes SetFileAttributesA

/* ---- FindFirstFile / FindNextFile stubs ---- */
typedef struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
    DWORD nFileSizeHigh, nFileSizeLow;
    DWORD dwReserved0, dwReserved1;
    CHAR  cFileName[MAX_PATH];
    CHAR  cAlternateFileName[14];
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;
typedef WIN32_FIND_DATAA WIN32_FIND_DATA;
static inline HANDLE FindFirstFileA(LPCSTR p, LPWIN32_FIND_DATAA fd) { (void)p;(void)fd; return INVALID_HANDLE_VALUE; }
static inline BOOL   FindNextFileA(HANDLE h, LPWIN32_FIND_DATAA fd)  { (void)h;(void)fd; return FALSE; }
static inline BOOL   FindClose(HANDLE h)                              { (void)h; return FALSE; }
#define FindFirstFile FindFirstFileA
#define FindNextFile  FindNextFileA

/* ---- Console stubs ---- */
static inline BOOL AllocConsole(void) { return FALSE; }
static inline BOOL FreeConsole(void) { return FALSE; }
static inline HANDLE GetStdHandle(DWORD n) { (void)n; return NULL; }
#define STD_INPUT_HANDLE   ((DWORD)-10)
#define STD_OUTPUT_HANDLE  ((DWORD)-11)
#define STD_ERROR_HANDLE   ((DWORD)-12)

/* ---- Timer stubs ---- */
static inline UINT_PTR SetTimer(HWND h, UINT_PTR id, UINT elapse, TIMERPROC fn) { (void)h;(void)id;(void)elapse;(void)fn; return 0; }
static inline BOOL KillTimer(HWND h, UINT_PTR id) { (void)h;(void)id; return FALSE; }

/* ---- Dialog/Window stubs ---- */
static inline BOOL ShowWindow(HWND h, int cmd) { (void)h;(void)cmd; return FALSE; }
static inline BOOL UpdateWindow(HWND h) { (void)h; return FALSE; }
static inline BOOL EnableWindow(HWND h, BOOL e) { (void)h;(void)e; return FALSE; }
static inline HWND GetDlgItem(HWND h, int id) { (void)h;(void)id; return NULL; }
static inline BOOL SetDlgItemTextA(HWND h, int id, LPCSTR s) { (void)h;(void)id;(void)s; return FALSE; }
#define SetDlgItemText SetDlgItemTextA
static inline UINT GetDlgItemTextA(HWND h, int id, LPSTR s, int max) { (void)h;(void)id;(void)s;(void)max; return 0; }
#define GetDlgItemText GetDlgItemTextA
static inline BOOL CheckDlgButton(HWND h, int id, UINT check) { (void)h;(void)id;(void)check; return FALSE; }
static inline UINT IsDlgButtonChecked(HWND h, int id) { (void)h;(void)id; return 0; }
#define BST_UNCHECKED 0
#define BST_CHECKED   1
#define BST_INDETERMINATE 2
static inline HWND GetParent(HWND h) { (void)h; return NULL; }
static inline HWND GetDlgCtrlID(HWND h) { (void)h; return NULL; }
static inline BOOL GetWindowRect(HWND h, LPRECT r) { (void)h;(void)r; return FALSE; }
static inline BOOL GetClientRect(HWND h, LPRECT r) { (void)h;(void)r; return FALSE; }
static inline BOOL InvalidateRect(HWND h, const RECT* r, BOOL e) { (void)h;(void)r;(void)e; return FALSE; }
/* PostMessage / SendMessage — real implementations in msg_dispatch.c.
 * Declared extern so any TU that calls them will link against the dispatch
 * module; TUs that never call them (e.g. test_threading) incur no penalty. */
extern BOOL    PostMessageA(HWND h, UINT m, WPARAM w, LPARAM l);
extern LRESULT SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l);
#define PostMessage  PostMessageA
#define SendMessage  SendMessageA
/* Wide-char variant — forward to the ANSI version (Rufus uses UTF-8 on Linux) */
static inline LRESULT SendMessageW(HWND h, UINT m, WPARAM w, LPARAM l) { return SendMessageA(h, m, w, l); }
static inline int GetWindowTextA(HWND h, LPSTR s, int max) { (void)h;(void)s;(void)max; return 0; }
#define GetWindowText GetWindowTextA
static inline BOOL SetWindowTextA(HWND h, LPCSTR s) { (void)h;(void)s; return FALSE; }
#define SetWindowText SetWindowTextA
static inline BOOL IsWindowEnabled(HWND h) { (void)h; return FALSE; }
static inline BOOL IsWindowVisible(HWND h) { (void)h; return FALSE; }
static inline BOOL PostQuitMessage(int code) { (void)code; return FALSE; }
static inline LRESULT DefWindowProcA(HWND h, UINT m, WPARAM w, LPARAM l) { (void)h;(void)m;(void)w;(void)l; return 0; }
#define DefWindowProc DefWindowProcA
static inline BOOL DestroyWindow(HWND h) { (void)h; return FALSE; }
static inline BOOL SetForegroundWindow(HWND h) { (void)h; return FALSE; }
static inline HWND SetFocus(HWND h) { (void)h; return NULL; }

/* ---- GDI stubs ---- */
static inline int GetDeviceCaps(HDC h, int i) { (void)h;(void)i; return 96; }
#define LOGPIXELSX 88
#define LOGPIXELSY 90
static inline COLORREF SetTextColor(HDC h, COLORREF c) { (void)h; return c; }
static inline COLORREF SetBkColor(HDC h, COLORREF c) { (void)h; return c; }
static inline int SetBkMode(HDC h, int m) { (void)h;(void)m; return 0; }
#define TRANSPARENT 1
#define OPAQUE 2
static inline HFONT CreateFontIndirectA(const LOGFONTA* lf) { (void)lf; return NULL; }
#define CreateFontIndirect CreateFontIndirectA
static inline HGDIOBJ SelectObject(HDC h, HGDIOBJ o) { (void)h;(void)o; return NULL; }
static inline BOOL DeleteObject(HGDIOBJ o) { (void)o; return FALSE; }
static inline HBRUSH CreateSolidBrush(COLORREF c) { (void)c; return NULL; }
static inline HDC GetDC(HWND h) { (void)h; return NULL; }
static inline int ReleaseDC(HWND h, HDC dc) { (void)h;(void)dc; return 0; }
static inline BOOL BeginPaint(HWND h, PAINTSTRUCT* ps) { (void)h;(void)ps; return FALSE; }
static inline BOOL EndPaint(HWND h, const PAINTSTRUCT* ps) { (void)h;(void)ps; return FALSE; }

/* ---- Combo box / list box stubs ---- */
#define CB_ERR           ((LRESULT)-1)   /* General combo-box error return */
#define CB_ERRSPACE      ((LRESULT)-2)   /* Out-of-memory return */
#define CB_ADDSTRING     0x0143
#define CB_RESETCONTENT  0x014B
#define CB_SETCURSEL     0x014E
#define CB_GETCURSEL     0x0147
#define CB_GETLBTEXT     0x0148
#define CB_GETLBTEXTLEN  0x0149
#define CB_SETITEMDATA   0x0151
#define CB_GETITEMDATA   0x0150
#define CB_FINDSTRINGEXACT 0x0158
#define CB_SETMINVISIBLE 0x1701
#define CB_GETCOUNT      0x0146
#define CB_SETDROPPEDWIDTH 0x0160
#define CBN_SELCHANGE    1
#define LB_ADDSTRING     0x0180
#define LB_RESETCONTENT  0x0184
#define LB_SETCURSEL     0x0186
#define LB_GETCURSEL     0x0188
#define LB_GETTEXT       0x0189
#define LB_SETTOPINDEX   0x0197
#define LB_SETITEMDATA   0x019A
#define LB_GETITEMDATA   0x0199
#define LB_FINDSTRINGEXACT 0x01A2
#define LB_GETCOUNT      0x018B
#define BM_SETCHECK      0x00F1
#define BM_GETCHECK      0x00F0
#define BM_SETSTATE      0x00F3
#define EM_SETSEL        0x00B1
#define EM_SETLIMITTEXT  0x00C5
static inline LRESULT ComboBox_AddString(HWND h, LPCSTR s) { return SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)s); }
static inline LRESULT ComboBox_ResetContent(HWND h) { return SendMessageA(h, CB_RESETCONTENT, 0, 0); }
static inline LRESULT ComboBox_AddStringU(HWND h, LPCSTR s) { return SendMessageA(h, CB_ADDSTRING, 0, (LPARAM)s); }
static inline LRESULT ComboBox_SetItemData(HWND h, int i, DWORD_PTR d) { return SendMessageA(h, CB_SETITEMDATA, (WPARAM)i, (LPARAM)d); }
static inline LRESULT ComboBox_GetItemData(HWND h, int i) { return SendMessageA(h, CB_GETITEMDATA, (WPARAM)i, 0); }
static inline int     ComboBox_GetCount(HWND h) { return (int)SendMessageA(h, CB_GETCOUNT, 0, 0); }
static inline int     ComboBox_SetCurSel(HWND h, int i) { return (int)SendMessageA(h, CB_SETCURSEL, (WPARAM)i, 0); }

/* ---- Misc missing items ---- */
#define APIPRIVATE WINAPI

static inline BOOL IsWindow(HWND h) { return h != NULL; }
static inline BOOL MoveWindow(HWND h, int x, int y, int w, int ht, BOOL repaint) { (void)h;(void)x;(void)y;(void)w;(void)ht;(void)repaint; return FALSE; }
static inline BOOL SetWindowPos(HWND h, HWND hi, int x, int y, int w, int ht, UINT f) { (void)h;(void)hi;(void)x;(void)y;(void)w;(void)ht;(void)f; return FALSE; }

/* ---- GetSystemInfo / SYSTEM_INFO ---- */
typedef struct _SYSTEM_INFO {
    union { DWORD dwOemId; struct { WORD wProcessorArchitecture; WORD wReserved; }; };
    DWORD dwPageSize, dwActiveProcessorMask;
    DWORD dwNumberOfProcessors, dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD  wProcessorLevel, wProcessorRevision;
    LPVOID lpMinimumApplicationAddress, lpMaximumApplicationAddress;
} SYSTEM_INFO, *LPSYSTEM_INFO;
static inline void GetSystemInfo(LPSYSTEM_INFO si) { if(si) memset(si,0,sizeof(*si)); }
static inline void GetNativeSystemInfo(LPSYSTEM_INFO si) { GetSystemInfo(si); }
#define PROCESSOR_ARCHITECTURE_AMD64  9
#define PROCESSOR_ARCHITECTURE_ARM    5
#define PROCESSOR_ARCHITECTURE_ARM64  12
#define PROCESSOR_ARCHITECTURE_INTEL  0
#define PROCESSOR_ARCHITECTURE_UNKNOWN 0xffff

/* ---- MEMORYSTATUSEX ---- */
typedef struct _MEMORYSTATUSEX {
    DWORD  dwLength;
    DWORD  dwMemoryLoad;
    DWORDLONG ullTotalPhys, ullAvailPhys;
    DWORDLONG ullTotalPageFile, ullAvailPageFile;
    DWORDLONG ullTotalVirtual, ullAvailVirtual;
    DWORDLONG ullAvailExtendedVirtual;
} MEMORYSTATUSEX, *LPMEMORYSTATUSEX;
static inline BOOL GlobalMemoryStatusEx(LPMEMORYSTATUSEX ms) { (void)ms; return FALSE; }

/* ---- CRT types ---- */
typedef struct _stat stat_t;
#define _stat64i32 stat
#define _stat32i64 stat
#define _stat32    stat

/* ---- wchar_t helpers ---- */
static inline int MultiByteToWideChar(UINT cp, DWORD flags, LPCSTR mb, int mb_sz, LPWSTR wc, int wc_sz) {
    (void)cp;(void)flags;
    if (!mb) return 0;
    size_t n = mbstowcs(wc, mb, wc_sz > 0 ? (size_t)wc_sz : 0);
    return (int)(n == (size_t)-1 ? 0 : n + 1);
}
static inline int WideCharToMultiByte(UINT cp, DWORD flags, LPCWSTR wc, int wc_sz, LPSTR mb, int mb_sz, LPCSTR def, LPBOOL used) {
    (void)cp;(void)flags;(void)wc_sz;(void)def;(void)used;
    if (!wc) return 0;
    size_t n = wcstombs(mb, wc, mb_sz > 0 ? (size_t)mb_sz : 0);
    return (int)(n == (size_t)-1 ? 0 : n + 1);
}
#define CP_ACP     0
#define CP_UTF8    65001
#define CP_UTF16   1200

/* ---- DPAPI stub ---- */
typedef struct _DATA_BLOB { DWORD cbData; BYTE* pbData; } DATA_BLOB, *PDATA_BLOB;
static inline BOOL CryptProtectData(DATA_BLOB* in, LPCWSTR desc, DATA_BLOB* ent, PVOID r, void* ui, DWORD fl, DATA_BLOB* out) { (void)in;(void)desc;(void)ent;(void)r;(void)ui;(void)fl;(void)out; return FALSE; }
static inline BOOL CryptUnprotectData(DATA_BLOB* in, LPWSTR* desc, DATA_BLOB* ent, PVOID r, void* ui, DWORD fl, DATA_BLOB* out) { (void)in;(void)desc;(void)ent;(void)r;(void)ui;(void)fl;(void)out; return FALSE; }

/* ---- GetCurrentDirectory / SetCurrentDirectory ---- */
static inline DWORD GetCurrentDirectoryA(DWORD n, LPSTR buf) {
    if (!getcwd(buf, n)) return 0;
    return (DWORD)strlen(buf);
}
#define GetCurrentDirectory GetCurrentDirectoryA
static inline BOOL SetCurrentDirectoryA(LPCSTR p) { return chdir(p) == 0; }
#define SetCurrentDirectory SetCurrentDirectoryA

/* ---- Misc API stubs ---- */
static inline BOOL CreateDirectoryA(LPCSTR p, LPSECURITY_ATTRIBUTES sa) { (void)sa; return mkdir(p, 0755) == 0; }
#define CreateDirectory CreateDirectoryA
static inline BOOL RemoveDirectoryA(LPCSTR p) { return rmdir(p) == 0; }
#define RemoveDirectory RemoveDirectoryA

/* ---- wprintf/printf wide variants (already included) ---- */

/* ---- GetLastError / errno mapping ---- */
static inline DWORD GetLastError_win(void) {
    switch(errno) {
    case ENOENT: return ERROR_FILE_NOT_FOUND;
    case EACCES: return ERROR_ACCESS_DENIED;
    case EEXIST: return ERROR_ALREADY_EXISTS;
    case ENOMEM: return ERROR_NOT_ENOUGH_MEMORY;
    case ENOTEMPTY: return ERROR_DIR_NOT_EMPTY;
    default: return (DWORD)errno;
    }
}

/* ---- WINTERNL types used in ext2fs/ms-sys ---- */
typedef struct _UNICODE_STRING {
    USHORT Length, MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor, SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define InitializeObjectAttributes(p,n,a,r,s) \
    do { (p)->Length=sizeof(OBJECT_ATTRIBUTES);(p)->RootDirectory=(r);(p)->Attributes=(a); \
         (p)->ObjectName=(n);(p)->SecurityDescriptor=(s);(p)->SecurityQualityOfService=NULL; } while(0)
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

/* ---- NTDLL stubs ---- */
static inline NTSTATUS NtOpenFile(HANDLE* h, DWORD access, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK io, DWORD share, DWORD open) {
    (void)h;(void)access;(void)oa;(void)io;(void)share;(void)open; return -1;
}
static inline NTSTATUS NtClose(HANDLE h) { (void)h; return 0; }
static inline NTSTATUS NtDeviceIoControlFile(HANDLE h, HANDLE ev, void* a1, void* a2, PIO_STATUS_BLOCK io, DWORD ctl, void* in, ULONG insz, void* out, ULONG outsz) {
    (void)h;(void)ev;(void)a1;(void)a2;(void)io;(void)ctl;(void)in;(void)insz;(void)out;(void)outsz; return -1;
}
static inline NTSTATUS NtFsControlFile(HANDLE h, HANDLE ev, void* a1, void* a2, PIO_STATUS_BLOCK io, DWORD ctl, void* in, ULONG insz, void* out, ULONG outsz) {
    (void)h;(void)ev;(void)a1;(void)a2;(void)io;(void)ctl;(void)in;(void)insz;(void)out;(void)outsz; return -1;
}
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#define STATUS_END_OF_FILE ((NTSTATUS)0xC0000011L)
#define STATUS_PENDING ((NTSTATUS)0x00000103L)

/* ---- geteuid for linux ---- */
#include <unistd.h>


/* ---- PE / COFF structures (from winnt.h) ---- */
#include "winnt.h"

/* ---- Prevent re-inclusion of other windows headers ---- */
#define _WINDOWS_
#define _INC_WINDOWS
#define WIN32_LEAN_AND_MEAN

#endif /* _LINUX_WINDOWS_COMPAT_H */
