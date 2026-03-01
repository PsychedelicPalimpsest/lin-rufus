/* Linux compat stub for shellapi.h */
#pragma once
#ifndef _WIN32
#include "windows.h"
#include <stdlib.h>   /* system() */
#include <stdio.h>    /* snprintf */
#include <wchar.h>    /* wcstombs */

/* ShellExecuteA: open a file/URL/directory with the user's default application.
 * On Linux we delegate to xdg-open(1) which handles all three cases.
 * Returns a fake HINSTANCE > 32 on success (matching Windows convention where
 * values <= 32 indicate errors). */
#ifndef ShellExecuteA
static inline HINSTANCE ShellExecuteA(HWND hwnd, LPCSTR op,
                                       LPCSTR file, LPCSTR params,
                                       LPCSTR dir,  INT show)
{
	(void)hwnd; (void)op; (void)params; (void)dir; (void)show;
	if (!file || !file[0]) return (HINSTANCE)(intptr_t)2; /* SE_ERR_FNF */
	char cmd[4096];
	snprintf(cmd, sizeof(cmd), "xdg-open \"%s\" >/dev/null 2>&1 &", file);
	int r = system(cmd);
	/* system() returns -1 on fork failure; treat as error */
	return (r == -1) ? (HINSTANCE)(intptr_t)2 : (HINSTANCE)(intptr_t)33;
}
#endif

/* ShellExecuteW: wide-char variant — convert path to UTF-8 and delegate */
#ifndef ShellExecuteW
static inline HINSTANCE ShellExecuteW(HWND hwnd, LPCWSTR op,
                                       LPCWSTR file, LPCWSTR params,
                                       LPCWSTR dir, INT show)
{
	(void)op; (void)params; (void)dir; (void)show;
	if (!file) return (HINSTANCE)(intptr_t)2;
	char buf[4096];
	if (wcstombs(buf, file, sizeof(buf)) == (size_t)-1)
		return (HINSTANCE)(intptr_t)2;
	return ShellExecuteA(hwnd, NULL, buf, NULL, NULL, show);
}
#endif

/* SW_* show constants used as the 'show' argument */
#ifndef SW_SHOWNORMAL
#define SW_SHOWNORMAL   1
#define SW_SHOW         5
#define SW_SHOWDEFAULT  10
#endif

#endif /* !_WIN32 */
