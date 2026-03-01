/* Linux stub: parser.c - config/locale parser (stub for porting) */
#include "rufus.h"
#include "localization.h"
#include <stdarg.h>

FILE* open_loc_file(const char* fn)                        { (void)fn; return NULL; }
BOOL  get_supported_locales(const char* fn)                { (void)fn; return FALSE; }
BOOL  get_loc_data_file(const char* fn, loc_cmd* lcmd)     { (void)fn;(void)lcmd; return FALSE; }
char* get_token_data_file_indexed(const char* tok, const char* fn, int idx) { (void)tok;(void)fn;(void)idx; return NULL; }
char* set_token_data_file(const char* tok, const char* data, const char* fn) { (void)tok;(void)data;(void)fn; return NULL; }
char* get_token_data_buffer(const char* tok, unsigned int n, const char* buf, size_t sz) { (void)tok;(void)n;(void)buf;(void)sz; return NULL; }
void  parse_update(char* buf, size_t len)                  { (void)buf;(void)len; }
char* insert_section_data(const char* fn, const char* sec, const char* data, BOOL d2u) { (void)fn;(void)sec;(void)data;(void)d2u; return NULL; }
char* replace_in_token_data(const char* fn, const char* tok, const char* src, const char* rep, BOOL d2u) { (void)fn;(void)tok;(void)src;(void)rep;(void)d2u; return NULL; }
char* replace_char(const char* src, const char c, const char* rep) { (void)src;(void)c;(void)rep; return NULL; }
void  filter_chars(char* str, const char* rem, const char rep) { (void)str;(void)rem;(void)rep; }
char* remove_substr(const char* src, const char* sub)      { (void)src;(void)sub; return NULL; }
void* get_data_from_asn1(const uint8_t* b, size_t bl, const char* oid, uint8_t t, size_t* dl) { (void)b;(void)bl;(void)oid;(void)t;(void)dl; return NULL; }
int   sanitize_label(char* label)                          { (void)label; return 0; }
sbat_entry_t* GetSbatEntries(char* sbatlevel)              { (void)sbatlevel; return NULL; }
thumbprint_list_t* GetThumbprintEntries(char* txt)         { (void)txt; return NULL; }
uint16_t GetPeArch(uint8_t* buf)                           { (void)buf; return 0; }
uint8_t* GetPeSection(uint8_t* buf, const char* name, uint32_t* len) { (void)buf;(void)name;(void)len; return NULL; }
uint8_t* RvaToPhysical(uint8_t* buf, uint32_t rva)         { (void)buf;(void)rva; return NULL; }
uint32_t FindResourceRva(const wchar_t* name, uint8_t* root, uint8_t* dir, uint32_t* len) { (void)name;(void)root;(void)dir;(void)len; return 0; }
uint8_t* GetPeSignatureData(uint8_t* buf)                  { (void)buf; return NULL; }
