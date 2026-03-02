/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: pki.c — PKI/certificate utilities
 * Copyright © 2015-2024 Pete Batard <pete@akeo.ie>
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

/* Linux implementation: pki.c - PKI/certificate handling via OpenSSL */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* OpenSSL headers */
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/asn1.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/x509_vfy.h>

#include "rufus.h"
#include "resource.h"

/* CA bundle path — injectable for tests */
#ifdef RUFUS_TEST
static const char *_ca_bundle_override = NULL;
void pki_set_ca_bundle_path(const char *path) { _ca_bundle_override = path; }
static const char *get_ca_bundle_path(void) {
	return _ca_bundle_override ? _ca_bundle_override
	                           : "/etc/ssl/certs/ca-certificates.crt";
}
#else
static const char *get_ca_bundle_path(void) {
	return "/etc/ssl/certs/ca-certificates.crt";
}
#endif

/* Rufus RSA-2048 public key modulus (from windows/pki.c, big-endian).
 * The array includes a leading 0x00 byte (DER sign bit); skip it for BN. */
static const uint8_t rsa_pubkey_modulus[] = {
	0x00, 0xb6, 0x40, 0x7d, 0xd1, 0x98, 0x7b, 0x81, 0x9e, 0xbe, 0x23, 0x0f, 0x32, 0x5d, 0x55,
	0x60, 0xc6, 0xbf, 0xb4, 0x41, 0xbb, 0x43, 0x1b, 0xf1, 0xe1, 0xe6, 0xf9, 0x2b, 0xd6, 0xdd,
	0x11, 0x50, 0xe8, 0xb9, 0x3f, 0x19, 0x97, 0x5e, 0xa7, 0x8b, 0x4a, 0x30, 0xc6, 0x76, 0x58,
	0x72, 0x1c, 0xac, 0xff, 0xa1, 0xf8, 0x96, 0x6c, 0x51, 0x5d, 0x13, 0x11, 0xe3, 0x5b, 0x11,
	0x82, 0xf5, 0x9a, 0x69, 0xe4, 0x28, 0x97, 0x0f, 0xca, 0x1f, 0x02, 0xea, 0x1f, 0x7d, 0xdc,
	0xf9, 0xfc, 0x79, 0x2f, 0x61, 0xff, 0x8e, 0x45, 0x60, 0x65, 0xba, 0x37, 0x9b, 0xde, 0x49,
	0x05, 0x6a, 0xa8, 0xfd, 0x70, 0xd0, 0x0c, 0x79, 0xb6, 0xd7, 0x81, 0xaa, 0x54, 0xc3, 0xc6,
	0x4a, 0x87, 0xa0, 0x45, 0xee, 0xca, 0xd5, 0xd5, 0xc5, 0xc2, 0xac, 0x86, 0x42, 0xb3, 0x58,
	0x27, 0xd2, 0x43, 0xb9, 0x37, 0xf2, 0xe6, 0x75, 0x66, 0x17, 0x53, 0xd0, 0x38, 0xd0, 0xc6,
	0x57, 0xc2, 0x55, 0x36, 0xa2, 0x43, 0x87, 0xea, 0x24, 0xf0, 0x96, 0xec, 0x34, 0xdd, 0x79,
	0x4d, 0x80, 0x54, 0x9d, 0x84, 0x81, 0xa7, 0xcf, 0x0c, 0xa5, 0x7c, 0xd6, 0x63, 0xfa, 0x7a,
	0x66, 0x30, 0xa9, 0x50, 0xee, 0xf0, 0xe5, 0xf8, 0xa2, 0x2d, 0xac, 0xfc, 0x24, 0x21, 0xfe,
	0xef, 0xe8, 0xd3, 0x6f, 0x0e, 0x27, 0xb0, 0x64, 0x22, 0x95, 0x3e, 0x6d, 0xa6, 0x66, 0x97,
	0xc6, 0x98, 0xc2, 0x47, 0xb3, 0x98, 0x69, 0x4d, 0xb1, 0xb5, 0xd3, 0x6f, 0x43, 0xf5, 0xd7,
	0xa5, 0x13, 0x5e, 0x8c, 0x28, 0x4f, 0x62, 0x4e, 0x01, 0x48, 0x0a, 0x63, 0x89, 0xe7, 0xca,
	0x34, 0xaa, 0x7d, 0x2f, 0xbb, 0x70, 0xe0, 0x31, 0xbb, 0x39, 0x49, 0xa3, 0xd2, 0xc9, 0x2e,
	0xa6, 0x30, 0x54, 0x9a, 0x5c, 0x4d, 0x58, 0x17, 0xd9, 0xfc, 0x3a, 0x43, 0xe6, 0x8e, 0x2a,
	0x18, 0xe9
};
#define RSA_MOD_OFFSET  1  /* skip leading 0x00 */
#define RSA_MOD_SIZE    256 /* 2048 bits = 256 bytes */

const char* WinPKIErrorString(void)
{
	static char buf[256];
	unsigned long err = ERR_peek_last_error();
	if (err != 0)
		ERR_error_string_n(err, buf, sizeof(buf));
	else
		snprintf(buf, sizeof(buf), "No error");
	return buf;
}

BOOL ValidateOpensslSignature(BYTE* pbBuffer, DWORD dwBufferLen, BYTE* pbSignature, DWORD dwSigLen)
{
	BIGNUM *n = NULL, *e = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;
	uint8_t sig_be[RSA_MOD_SIZE];
	BOOL r = FALSE;
	int i, j;

	if (!pbBuffer || !pbSignature || dwBufferLen == 0 || dwSigLen != RSA_MOD_SIZE)
		return FALSE;

	/* Copy and reverse signature: Rufus stores it little-endian */
	for (i = 0, j = RSA_MOD_SIZE - 1; i < RSA_MOD_SIZE; i++, j--)
		sig_be[i] = pbSignature[j];

	/* Build RSA public key from hard-coded modulus using EVP_PKEY_fromdata */
	n = BN_bin2bn(rsa_pubkey_modulus + RSA_MOD_OFFSET, RSA_MOD_SIZE, NULL);
	e = BN_new();
	if (!n || !e || !BN_set_word(e, 65537))
		goto out;

	bld = OSSL_PARAM_BLD_new();
	if (!bld) goto out;
	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n)) goto out;
	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) goto out;
	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) goto out;

	kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!kctx) goto out;
	if (EVP_PKEY_fromdata_init(kctx) <= 0) goto out;
	if (EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) goto out;

	ctx = EVP_MD_CTX_new();
	if (!ctx) goto out;

	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
	    EVP_DigestVerifyUpdate(ctx, pbBuffer, dwBufferLen) == 1 &&
	    EVP_DigestVerifyFinal(ctx, sig_be, RSA_MOD_SIZE) == 1)
		r = TRUE;

out:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(kctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(n);
	BN_free(e);
	return r;
}

/* -----------------------------------------------------------------------
 * PE file helpers — mmap the file, find the security (certificate) data,
 * parse it as PKCS7, and return the result.  The caller owns the PKCS7*.
 * ---------------------------------------------------------------------- */

/* PE structures we need (mirroring winnt.h layout) */
#pragma pack(push, 1)
typedef struct { uint16_t e_magic; uint8_t _pad[58]; int32_t e_lfanew; } Dos_Hdr;
typedef struct { uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader; uint16_t Characteristics; } File_Hdr;
typedef struct { uint32_t VirtualAddress; uint32_t Size; } Data_Dir;
typedef struct { uint16_t Magic; uint8_t _pad[94]; Data_Dir DataDirectory[16]; } Opt_Hdr32;
typedef struct { uint16_t Magic; uint8_t _pad[110]; Data_Dir DataDirectory[16]; } Opt_Hdr64;
#pragma pack(pop)

#define PE_MAGIC32  0x10B
#define PE_MAGIC64  0x20B
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4

/* WIN_CERTIFICATE wCertificateType for PKCS7 */
#ifndef WIN_CERT_TYPE_PKCS_SIGNED_DATA
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#endif

static PKCS7* open_pe_pkcs7(const char* path)
{
	int fd = -1;
	uint8_t *buf = MAP_FAILED;
	struct stat st;
	PKCS7 *p7 = NULL;
	uint32_t pe_off, sec_off, sec_size;
	uint16_t opt_magic;
	File_Hdr *fhdr;
	Dos_Hdr *dos;
	const uint8_t *cert_data;
	uint32_t cert_hdr_size;

	fd = open(path, O_RDONLY);
	if (fd < 0) return NULL;
	if (fstat(fd, &st) < 0 || st.st_size < 64) goto out;

	buf = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) goto out;

	dos = (Dos_Hdr*)buf;
	if (dos->e_magic != 0x5A4D) goto out; /* 'MZ' */

	pe_off = (uint32_t)dos->e_lfanew;
	if (pe_off + 4 + sizeof(File_Hdr) + 2 > (uint32_t)st.st_size) goto out;
	if (*(uint32_t*)(buf + pe_off) != 0x00004550) goto out; /* 'PE\0\0' */

	fhdr = (File_Hdr*)(buf + pe_off + 4);
	if (fhdr->SizeOfOptionalHeader < 2) goto out;

	opt_magic = *(uint16_t*)(buf + pe_off + 4 + sizeof(File_Hdr));
	if (opt_magic == PE_MAGIC32) {
		Opt_Hdr32 *opt = (Opt_Hdr32*)(buf + pe_off + 4 + sizeof(File_Hdr));
		sec_off  = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
		sec_size = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	} else if (opt_magic == PE_MAGIC64) {
		Opt_Hdr64 *opt = (Opt_Hdr64*)(buf + pe_off + 4 + sizeof(File_Hdr));
		sec_off  = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
		sec_size = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	} else {
		goto out;
	}

	if (sec_off == 0 || sec_size < 8 ||
	    (uint64_t)sec_off + sec_size > (uint64_t)st.st_size)
		goto out;

	/* WIN_CERTIFICATE layout: DWORD dwLength, WORD wRevision, WORD wCertificateType */
	{
		uint32_t cert_len  = *(uint32_t*)(buf + sec_off);
		uint16_t cert_type = *(uint16_t*)(buf + sec_off + 6);
		cert_hdr_size = 8; /* sizeof(dwLength) + sizeof(wRevision) + sizeof(wCertificateType) */
		if (cert_len < cert_hdr_size || cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA) goto out;
		if ((uint64_t)sec_off + cert_len > (uint64_t)st.st_size) goto out;
		cert_data = buf + sec_off + cert_hdr_size;
		p7 = d2i_PKCS7(NULL, &cert_data, (long)(cert_len - cert_hdr_size));
	}

out:
	if (buf != MAP_FAILED) munmap(buf, (size_t)st.st_size);
	close(fd);
	return p7;
}

/* Resolve NULL path to current executable via /proc/self/exe */
static char* resolve_path(const char* path, char* exebuf, size_t exebuf_len)
{
	if (path != NULL) return (char*)path;
	ssize_t len = readlink("/proc/self/exe", exebuf, exebuf_len - 1);
	if (len <= 0) return NULL;
	exebuf[len] = '\0';
	return exebuf;
}

char* GetSignatureName(const char* path, const char* country_code,
                       uint8_t* thumbprint, BOOL bSilent)
{
	static char szSubjectName[128];
	char exebuf[4096];
	char *resolved;
	PKCS7 *p7 = NULL;
	STACK_OF(X509) *certs = NULL;
	X509 *signer = NULL;
	X509_NAME *subj = NULL;
	char *ret = NULL;
	(void)bSilent;

	resolved = resolve_path(path, exebuf, sizeof(exebuf));
	if (!resolved) return NULL;

	p7 = open_pe_pkcs7(resolved);
	if (!p7) return NULL;

	/* Extract the list of certificates embedded in the PKCS7 */
	if (PKCS7_type_is_signed(p7))
		certs = p7->d.sign->cert;
	else
		goto out;

	if (!certs || sk_X509_num(certs) == 0) goto out;

	/* Use the first (signer) certificate */
	signer = sk_X509_value(certs, 0);
	if (!signer) goto out;

	/* Get the SHA-1 thumbprint if requested */
	if (thumbprint != NULL) {
		unsigned int len = SHA_DIGEST_LENGTH;
		if (!X509_digest(signer, EVP_sha1(), thumbprint, &len))
			goto out;
	}

	/* Validate country code if provided */
	if (country_code != NULL) {
		char country[3] = "__";
		subj = X509_get_subject_name(signer);
		X509_NAME_get_text_by_NID(subj, NID_countryName, country, sizeof(country));
		if (strcasecmp(country_code, country) != 0) {
			uprintf("PKI: Unexpected country code (found '%s', expected '%s')",
			        country, country_code);
			goto out;
		}
	}

	/* Extract Common Name */
	subj = X509_get_subject_name(signer);
	if (X509_NAME_get_text_by_NID(subj, NID_commonName,
	                               szSubjectName, sizeof(szSubjectName)) <= 0)
		goto out;

	ret = szSubjectName;

out:
	PKCS7_free(p7);
	return ret;
}

uint64_t GetSignatureTimeStamp(const char* path)
{
	char exebuf[4096];
	char *resolved;
	PKCS7 *p7 = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	ASN1_TYPE *attr_val = NULL;
	ASN1_UTCTIME *asn1_time = NULL;
	uint64_t ts = 0ULL;
	int i, n;

	resolved = resolve_path(path, exebuf, sizeof(exebuf));
	if (!resolved) return 0;

	p7 = open_pe_pkcs7(resolved);
	if (!p7) return 0;

	if (!PKCS7_type_is_signed(p7) || !p7->d.sign->signer_info) goto out;
	n = sk_PKCS7_SIGNER_INFO_num(p7->d.sign->signer_info);
	if (n <= 0) goto out;
	si = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
	if (!si) goto out;

	/* Look for signingTime (OID 1.2.840.113549.1.9.5) in unauth or auth attrs */
	for (i = 0; i < sk_X509_ATTRIBUTE_num(si->unauth_attr); i++) {
		X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value(si->unauth_attr, i);
		if (!attr) continue;
		if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) == NID_pkcs9_signingTime) {
			attr_val = X509_ATTRIBUTE_get0_type(attr, 0);
			break;
		}
	}
	if (!attr_val) {
		for (i = 0; i < sk_X509_ATTRIBUTE_num(si->auth_attr); i++) {
			X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value(si->auth_attr, i);
			if (!attr) continue;
			if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) == NID_pkcs9_signingTime) {
				attr_val = X509_ATTRIBUTE_get0_type(attr, 0);
				break;
			}
		}
	}
	if (!attr_val) goto out;

	if (attr_val->type == V_ASN1_UTCTIME)
		asn1_time = attr_val->value.utctime;
	else if (attr_val->type == V_ASN1_GENERALIZEDTIME) {
		/* Parse generalizedTime: YYYYMMDDHHMMSSZ */
		const char *s = (const char*)attr_val->value.generalizedtime->data;
		if (attr_val->value.generalizedtime->length >= 14) {
			char tmp[15]; memcpy(tmp, s, 14); tmp[14] = '\0';
			ts = (uint64_t)strtoull(tmp, NULL, 10);
		}
		goto out;
	}

	if (asn1_time) {
		/* UTCTime: YYMMDDHHMMSSZ → prefix 20 for year */
		const char *s = (const char*)asn1_time->data;
		if (asn1_time->length >= 12) {
			int yr2 = (s[0]-'0')*10 + (s[1]-'0');
			int century = yr2 >= 50 ? 19 : 20;
			ts = (uint64_t)(century * 100 + yr2) * 10000000000ULL
			   + (uint64_t)((s[2]-'0')*10 + (s[3]-'0')) * 100000000ULL
			   + (uint64_t)((s[4]-'0')*10 + (s[5]-'0')) * 1000000ULL
			   + (uint64_t)((s[6]-'0')*10 + (s[7]-'0')) * 10000ULL
			   + (uint64_t)((s[8]-'0')*10 + (s[9]-'0')) * 100ULL
			   + (uint64_t)((s[10]-'0')*10 + (s[11]-'0'));
		}
	}

out:
	PKCS7_free(p7);
	return ts;
}

int GetIssuerCertificateInfo(uint8_t* cert, cert_info_t* info)
{
	WIN_CERTIFICATE *wc = (WIN_CERTIFICATE*)cert;
	PKCS7 *p7 = NULL;
	STACK_OF(X509) *certs = NULL;
	X509 *signer = NULL;
	X509_NAME *subj = NULL;
	const uint8_t *der;
	uint32_t der_len;
	int ret = 0;

	if (info == NULL) return -1;
	info->chain_trusted = FALSE;
	if (wc == NULL || wc->dwLength == 0) return 0;

	/* The PKCS7 DER data follows the WIN_CERTIFICATE header (8 bytes) */
	if (wc->dwLength <= 8) return 0;
	der = (const uint8_t*)cert + 8;
	der_len = wc->dwLength - 8;

	p7 = d2i_PKCS7(NULL, &der, (long)der_len);
	if (!p7) { ret = -1; goto out; }

	if (!PKCS7_type_is_signed(p7)) { ret = -1; goto out; }
	certs = p7->d.sign->cert;
	if (!certs || sk_X509_num(certs) == 0) goto out;

	/* Prefer the issuer (second cert if available), else use the signer (first) */
	if (sk_X509_num(certs) >= 2)
		signer = sk_X509_value(certs, 1);
	else
		signer = sk_X509_value(certs, 0);
	if (!signer) { ret = -1; goto out; }

	subj = X509_get_subject_name(signer);
	if (X509_NAME_get_text_by_NID(subj, NID_commonName,
	                               info->name, sizeof(info->name)) <= 0) {
		ret = -1; goto out;
	}

	{
		unsigned int sha1_len = SHA_DIGEST_LENGTH;
		if (!X509_digest(signer, EVP_sha1(), info->thumbprint, &sha1_len)) {
			ret = -1; goto out;
		}
	}

	ret = (sk_X509_num(certs) >= 2) ? 2 : 1;

	/* Chain validation: verify the leaf signer against the system CA bundle */
	{
		STACK_OF(X509) *signers = PKCS7_get0_signers(p7, certs, 0);
		if (signers && sk_X509_num(signers) > 0) {
			X509 *leaf = sk_X509_value(signers, 0);
			X509_STORE *store = X509_STORE_new();
			if (store) {
				if (X509_STORE_load_locations(store, get_ca_bundle_path(), NULL) == 1) {
					X509_STORE_CTX *ctx = X509_STORE_CTX_new();
					if (ctx) {
						if (X509_STORE_CTX_init(ctx, store, leaf, certs) == 1)
							info->chain_trusted = (X509_verify_cert(ctx) == 1);
						X509_STORE_CTX_free(ctx);
					}
				}
				X509_STORE_free(store);
			}
			sk_X509_free(signers);
		}
	}

out:
	PKCS7_free(p7);
	return ret;
}

/*
 * GetSignatureCertInfo: extract certificate info (name, thumbprint, chain_trusted)
 * from a PE file's embedded PKCS7 signature.
 * Returns 1 or 2 on success (same as GetIssuerCertificateInfo), -1 on error.
 */
int GetSignatureCertInfo(const char *path, cert_info_t *info)
{
	uint8_t *buf = NULL;
	uint32_t buf_len;
	uint8_t *cert_data;
	int ret;

	if (path == NULL || info == NULL)
		return -1;
	buf_len = read_file(path, &buf);
	if (buf == NULL || buf_len == 0) {
		free(buf);
		return -1;
	}
	cert_data = GetPeSignatureData(buf);
	ret = GetIssuerCertificateInfo(cert_data, info);
	free(buf);
	return ret;
}


LONG ValidateSignature(HWND hDlg, const char* path)
{
	(void)hDlg;
	/* WinVerifyTrust is not available on Linux.
	 * We do a minimal check: if path is given, verify the file exists. */
	if (path != NULL) {
		struct stat st;
		if (stat(path, &st) != 0)
			return (LONG)0x800B0100L; /* TRUST_E_NOSIGNATURE */
	}
	return 0; /* NO_ERROR */
}

BOOL ParseSKUSiPolicy(void)
{
	return FALSE; /* Windows-only feature */
}
