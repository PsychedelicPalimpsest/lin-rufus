/* Linux compat stub for io.h (MSVC low-level I/O) */
#pragma once
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>

/* Map MSVC/MinGW underscore variants to POSIX */
#define _open         open
#define _close        close
#define _read         read
#define _write        write
#define _lseek        lseek
#define _lseeki64     lseek
#define _tell(fd)     lseek(fd, 0, SEEK_CUR)
#define _eof(fd)      (lseek(fd,0,SEEK_CUR)==lseek(fd,0,SEEK_END))
#define _access       access
#define _unlink       unlink
#define _chmod        chmod
#define _dup2         dup2
#define _dup          dup
#define _fileno       fileno
#define _isatty       isatty
#define _pipe(fds, sz, flags) pipe(fds)

/* Map to POSIX equivalents */
#define _openU        open
#define _mkdirU(p)    mkdir(p, 0755)

/* Binary mode flags - on Linux everything is binary */
#ifndef _O_RDONLY
#define _O_RDONLY     O_RDONLY
#define _O_WRONLY     O_WRONLY
#define _O_RDWR       O_RDWR
#define _O_APPEND     O_APPEND
#define _O_CREAT      O_CREAT
#define _O_TRUNC      O_TRUNC
#define _O_EXCL       O_EXCL
#define _O_BINARY     0
#define _O_TEXT       0
#endif

/* stat mode constants */
#ifndef _S_IREAD
#define _S_IREAD      S_IRUSR
#define _S_IWRITE     S_IWUSR
#define _S_IFMT       S_IFMT
#define _S_IFDIR      S_IFDIR
#define _S_IFCHR      S_IFCHR
#define _S_IFIFO      S_IFIFO
#define _S_IFREG      S_IFREG
#define _S_IFBLK      S_IFBLK
#endif

/* _TRUNCATE for _snprintf_s - ignored on Linux */
#undef _TRUNCATE
#define _TRUNCATE     ((size_t)-1)
/* Safe snprintf mapping — undef the macro from windows.h first */
#undef _snprintf_s
static inline int _snprintf_s(char* buf, size_t bufsz, size_t count, const char* fmt, ...) {
    (void)count;
    int r;
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    r = vsnprintf(buf, bufsz, fmt, ap);
    __builtin_va_end(ap);
    return r;
}

/* _sopen_s: open with sharing flags - simplified for Linux */
static inline int _sopen_s(int* pfh, const char* fn, int oflag, int shflag, int pmode) {
    (void)shflag;
    *pfh = open(fn, oflag, pmode);
    return (*pfh == -1) ? errno : 0;
}
#define _SH_DENYNO    0
#define _SH_DENYRW    1
#define _SH_DENYWR    2
#define _SH_DENYRD    3

/* _open_osfhandle: on Linux, HANDLE is just an int fd wrapper */
static inline int _open_osfhandle(intptr_t osfh, int flags) {
    (void)flags;
    return (int)osfh;
}

/* MAX_PATH */
#ifndef MAX_PATH
#define MAX_PATH      PATH_MAX
#endif

typedef struct _finddata_t { unsigned attrib; long size; char name[260]; } _finddata_t;
#endif
