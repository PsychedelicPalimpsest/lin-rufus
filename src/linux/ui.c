/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: ui.c — UI abstraction layer
 * Copyright © 2018-2024 Pete Batard <pete@akeo.ie>
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

/* Linux stub: ui.c - user interface (no-op on Linux) */
#include "rufus.h"
#include "ui.h"


void SetAccessibleName(HWND hCtrl, const char* name)       { (void)hCtrl;(void)name; }
void SetComboEntry(HWND hDlg, int data)                    { (void)hDlg;(void)data; }
void GetBasicControlsWidth(HWND hDlg)                      { (void)hDlg; }
void GetMainButtonsWidth(HWND hDlg)                        { (void)hDlg; }
void GetHalfDropwdownWidth(HWND hDlg)                      { (void)hDlg; }
void GetFullWidth(HWND hDlg)                               { (void)hDlg; }
void PositionMainControls(HWND hDlg)                       { (void)hDlg; }
void AdjustForLowDPI(HWND hDlg)                            { (void)hDlg; }
void SetSectionHeaders(HWND hDlg, HFONT* hFont)            { (void)hDlg;(void)hFont; }
void ToggleAdvancedDeviceOptions(BOOL enable)              { (void)enable; }
void ToggleAdvancedFormatOptions(BOOL enable)              { (void)enable; }
void TogglePersistenceControls(BOOL display)               { (void)display; }
void SetPersistencePos(uint64_t pos)                       { (void)pos; }
void SetPersistenceSize(void)                              {}
void ToggleImageOptions(void)                              {}
void CreateSmallButtons(HWND hDlg)                         { (void)hDlg; }
void CreateAdditionalControls(HWND hDlg)                   { (void)hDlg; }
void InitProgress(BOOL bOnlyFormat)                        { (void)bOnlyFormat; }
void UpdateProgress(int op, float percent)                 { (void)op;(void)percent; }
void _UpdateProgressWithInfo(int op, int msg, uint64_t cur, uint64_t tot, BOOL f) { (void)op;(void)msg;(void)cur;(void)tot;(void)f; }
void ShowLanguageMenu(RECT rcExclude)                      { (void)rcExclude; }
void SetPassesTooltip(void)                                {}
void SetBootTypeDropdownWidth(void)                        {}
void OnPaint(HDC hdc)                                      { (void)hdc; }
