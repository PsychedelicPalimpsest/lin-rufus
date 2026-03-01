/* Linux compat stub for windowsx.h */
#pragma once
#ifndef _WIN32
#include "windows.h"
#endif

#ifndef ComboBox_GetCurSel
/* SendMessage to CB_GETCURSEL returns the zero-based index of the current selection,
 * or CB_ERR (-1) if no item is selected. */
#define ComboBox_GetCurSel(hwnd) ((int)(intptr_t)SendMessageA((hwnd), CB_GETCURSEL, 0, 0))
#endif
