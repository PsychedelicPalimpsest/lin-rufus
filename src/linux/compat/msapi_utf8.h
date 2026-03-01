/* Linux compat stub for msapi_utf8.h
 * On Linux, string APIs are natively UTF-8, so no wrappers are needed.
 */
#pragma once
#ifndef _MSAPI_UTF8_H
#define _MSAPI_UTF8_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <io.h>

/* On Linux, strings are already UTF-8 — no conversion needed. */
/* These macros make wimlib.h's _RUFUS helpers compile as pass-throughs. */
static __inline char* utf8_to_wchar(const char* str) { return (char*)(str); }
static __inline char* wchar_to_utf8(const char* wstr) { return (char*)(wstr); }
#define wconvert(p)     char* w ## p = (char*)(p)
#define walloc(p, size) char* w ## p = (p == NULL) ? NULL : (char*)(p)
#define wfree(p)        ((void)w ## p)
#define sfree(p)        do { if ((p) != NULL) { free((void*)(p)); (p) = NULL; } } while(0)

/* Pass-through UTF-8 variants of common APIs */
#define fopenU(p,m)     fopen(p,m)
#define _statU(p,s)     stat(p,s)
#define _openU          open
#define _mkdirU(p)      mkdir(p, 0755)
#define _rmdirU(p)      rmdir(p)
#define _unlinkU(p)     unlink(p)
#define _accessU(p,m)   access(p,m)
#define _renameU(o,n)   rename(o,n)
#define _strdupU(s)     strdup(s)

/* CRT compatibility */
#ifndef _strdup
#define _strdup         strdup
#endif
#ifndef _TRUNCATE
#define _TRUNCATE       ((size_t)-1)
#endif
#ifndef strncpy_s
#define strncpy_s(d,n,s,c) (strncpy(d,s,(c)==_TRUNCATE?(n)-1:(c)),(d)[(n)-1]='\0',0)
#endif
#ifndef strcpy_s
#define strcpy_s(d,n,s) (strncpy(d,s,n),(d)[(n)-1]='\0',0)
#endif

/* Character type helpers */
#define isdigitU(c)     isdigit((unsigned char)(c))
#define isspaceU(c)     isspace((unsigned char)(c))
#define isxdigitU(c)    isxdigit((unsigned char)(c))

#endif /* _MSAPI_UTF8_H */
