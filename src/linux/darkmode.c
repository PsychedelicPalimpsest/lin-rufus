/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: darkmode.c — dark mode detection/application
 * Copyright © 2025 Rufus contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Linux stub: darkmode.c - Windows dark mode (no-op on Linux) */
#include "rufus.h"
#include "darkmode.h"

BOOL is_darkmode_enabled = FALSE;

BOOL GetDarkModeFromRegistry(void)             { return FALSE; }
void InitDarkMode(HWND hWnd)                   { (void)hWnd; }
void SetDarkTitleBar(HWND hWnd)                { (void)hWnd; }
void SetDarkTheme(HWND hWnd)                   { (void)hWnd; }
BOOL InitAccentColor(void)                     { return FALSE; }
BOOL ChangeIconColor(HICON* hIcon, COLORREF c) { (void)hIcon; (void)c; return FALSE; }
void DestroyDarkModeGDIObjects(void)           {}
void SubclassCtlColor(HWND hWnd)               { (void)hWnd; }
void SubclassNotifyCustomDraw(HWND hWnd)       { (void)hWnd; }
void SubclassStatusBar(HWND hWnd)              { (void)hWnd; }
void SubclassProgressBarControl(HWND hWnd)     { (void)hWnd; }
void SetDarkModeForChild(HWND hParent)         { (void)hParent; }
