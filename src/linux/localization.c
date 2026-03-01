/* Linux stub: localization.c - localization (stub for porting) */
#include "rufus.h"
#include "resource.h"
#include "localization.h"
#include <stdarg.h>

void    add_dialog_command(int index, loc_cmd* lcmd)        { (void)index;(void)lcmd; }
void    add_message_command(loc_cmd* lcmd)                   { (void)lcmd; }
void    free_loc_cmd(loc_cmd* lcmd)                          { free(lcmd); }
void    free_dialog_list(void)                               {}
void    free_locale_list(void)                               {}
BOOL    dispatch_loc_cmd(loc_cmd* lcmd)                      { (void)lcmd; return FALSE; }
void    apply_localization(int dlg_id, HWND hDlg)            { (void)dlg_id;(void)hDlg; }
void    reset_localization(int dlg_id)                       { (void)dlg_id; }
char*   lmprintf(uint32_t msg_id, ...)                       { (void)msg_id; return ""; }
void    PrintStatusInfo(BOOL info, BOOL dbg, unsigned int d, int msg_id, ...) { (void)info;(void)dbg;(void)d;(void)msg_id; }
loc_cmd* get_locale_from_lcid(int lcid, BOOL fb)             { (void)lcid;(void)fb; return NULL; }
loc_cmd* get_locale_from_name(char* name, BOOL fb)           { (void)name;(void)fb; return NULL; }
void    toggle_default_locale(void)                          {}
const char* get_name_from_id(int id)                         { (void)id; return ""; }
WORD    get_language_id(loc_cmd* lcmd)                       { (void)lcmd; return 0; }
