/* Linux stub: pki.c - PKI/certificate handling (stub for porting) */
#include "rufus.h"

const char* WinPKIErrorString(void)                        { return ""; }
char* GetSignatureName(const char* p, const char* cc, uint8_t* t, BOOL s) { (void)p;(void)cc;(void)t;(void)s; return NULL; }
int   GetIssuerCertificateInfo(uint8_t* cert, cert_info_t* info)  { (void)cert;(void)info; return 0; }
uint64_t GetSignatureTimeStamp(const char* path)           { (void)path; return 0; }
LONG  ValidateSignature(HWND hDlg, const char* path)       { (void)hDlg;(void)path; return 0; }
BOOL  ValidateOpensslSignature(BYTE* buf, DWORD buflen, BYTE* sig, DWORD siglen) { (void)buf;(void)buflen;(void)sig;(void)siglen; return FALSE; }
BOOL  ParseSKUSiPolicy(void)                               { return FALSE; }
