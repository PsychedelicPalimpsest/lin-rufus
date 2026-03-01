/* Linux stub: hash.c - hashing functions (stub for porting) */
#include "rufus.h"

struct efi_image_regions;

BOOL DetectSHA1Acceleration(void)              { return FALSE; }
BOOL DetectSHA256Acceleration(void)            { return FALSE; }
BOOL HashFile(const unsigned t, const char* p, uint8_t* h) { (void)t;(void)p;(void)h; return FALSE; }
BOOL HashBuffer(const unsigned t, const uint8_t* b, const size_t l, uint8_t* h) { (void)t;(void)b;(void)l;(void)h; return FALSE; }
BOOL PE256Buffer(uint8_t* b, uint32_t l, uint8_t* h) { (void)b;(void)l;(void)h; return FALSE; }
BOOL efi_image_parse(uint8_t* e, size_t l, struct efi_image_regions** r) { (void)e;(void)l;(void)r; return FALSE; }
DWORD WINAPI IndividualHashThread(void* param)  { (void)param; return 0; }
DWORD WINAPI HashThread(void* param)            { (void)param; return 0; }
BOOL IsBufferInDB(const unsigned char* b, const size_t l) { (void)b;(void)l; return FALSE; }
BOOL IsFileInDB(const char* path)              { (void)path; return FALSE; }
BOOL FileMatchesHash(const char* p, const char* s) { (void)p;(void)s; return FALSE; }
BOOL BufferMatchesHash(const uint8_t* b, const size_t l, const char* s) { (void)b;(void)l;(void)s; return FALSE; }
BOOL IsSignedBySecureBootAuthority(uint8_t* b, uint32_t l) { (void)b;(void)l; return FALSE; }
int IsBootloaderRevoked(uint8_t* b, uint32_t l) { (void)b;(void)l; return 0; }
void UpdateMD5Sum(const char* d, const char* m)  { (void)d;(void)m; }
INT_PTR CALLBACK HashCallback(HWND h, UINT msg, WPARAM w, LPARAM l) { (void)h;(void)msg;(void)w;(void)l; return 0; }

