/* Linux compat stub for shlwapi.h */
#pragma once
#ifndef _WIN32
#include "windows.h"
#include <unistd.h>   /* access() */
#include <string.h>   /* strcasestr, strlen, strcpy */
#include <strings.h>  /* strcasecmp, strncasecmp */

/* PathFileExistsA: TRUE if the file/directory exists and is accessible */
#ifndef PathFileExistsA
static inline BOOL PathFileExistsA(LPCSTR path)
{
	if (!path || !path[0]) return FALSE;
	return (access(path, F_OK) == 0) ? TRUE : FALSE;
}
#endif

/* PathFileExistsW: wide-char variant — convert to UTF-8 and delegate */
#ifndef PathFileExistsW
static inline BOOL PathFileExistsW(LPCWSTR path)
{
	if (!path) return FALSE;
	char buf[4096];
	if (wcstombs(buf, path, sizeof(buf)) == (size_t)-1) return FALSE;
	return PathFileExistsA(buf);
}
#endif

/* PathCombineA: combine dir and file into result with a single '/' separator.
 * Returns result on success, NULL on overflow (matching Windows behaviour). */
#ifndef PathCombineA
static inline LPSTR PathCombineA(LPSTR result, LPCSTR dir, LPCSTR file)
{
	if (!result) return NULL;
	result[0] = '\0';
	size_t dlen = dir  ? strlen(dir)  : 0;
	size_t flen = file ? strlen(file) : 0;

	/* Determine whether we need a separator between dir and file */
	int need_sep = (dlen > 0 && flen > 0 &&
	                dir[dlen - 1] != '/' && dir[dlen - 1] != '\\');

	/* Check for overflow (MAX_PATH is 260 on Windows compat) */
	if (dlen + (need_sep ? 1 : 0) + flen + 1 > MAX_PATH) return NULL;

	if (dir)  strcpy(result, dir);
	if (need_sep) { result[dlen] = '/'; result[dlen + 1] = '\0'; }
	if (file) strcat(result, file);

	/* Normalise backslashes to forward slashes */
	for (char *p = result; *p; p++)
		if (*p == '\\') *p = '/';

	return result;
}
#endif

/* StrStrIA: case-insensitive substring search (already in windows.h; provide
 * fallback here for files that only include shlwapi.h) */
#ifndef StrStrIA
#define StrStrIA(haystack, needle) strcasestr((haystack), (needle))
#endif

/* StrCmpIA: case-insensitive string compare (returns 0 if equal) */
#ifndef StrCmpIA
#define StrCmpIA(a, b) strcasecmp((a), (b))
#endif

/* StrCmpNIA: case-insensitive n-char string compare */
#ifndef StrCmpNIA
#define StrCmpNIA(a, b, n) strncasecmp((a), (b), (n))
#endif

#endif /* !_WIN32 */
