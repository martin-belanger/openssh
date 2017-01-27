/* $OpenBSD: ssh-rsa.c,v 1.60 2016/09/12 23:39:34 djm Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011 Roumen Petrov.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "compat.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "evp-compat.h"
#include "xmalloc.h"
#include "log.h"

/*NOTE: Do not define USE_LEGACY_RSA_... if build
  is with FIPS capable OpenSSL */
/* Define if you want yo use legacy sign code */
#undef USE_LEGACY_RSA_SIGN
/* Define if you want yo use legacy verify code */
#undef USE_LEGACY_RSA_VERIFY


#ifdef USE_LEGACY_RSA_VERIFY
static int openssh_RSA_verify(int, u_char *, size_t, u_char *, size_t, RSA *);
#endif

static const char *
rsa_hash_alg_ident(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return "ssh-rsa";
	case SSH_DIGEST_SHA256:
		return "rsa-sha2-256";
	case SSH_DIGEST_SHA512:
		return "rsa-sha2-512";
	}
	return NULL;
}

static int
rsa_hash_alg_from_ident(const char *ident)
{
	if (strcmp(ident, "ssh-rsa") == 0 ||
	    strcmp(ident, "ssh-rsa-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(ident, "rsa-sha2-256") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(ident, "rsa-sha2-512") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

static int
rsa_hash_alg_nid(int type)
{
	switch (type) {
	case SSH_DIGEST_SHA1:
		return NID_sha1;
	case SSH_DIGEST_SHA256:
		return NID_sha256;
	case SSH_DIGEST_SHA512:
		return NID_sha512;
	default:
		return -1;
	}
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg_ident)
{
#ifdef USE_LEGACY_RSA_SIGN
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	u_int dlen;
#endif
	u_char *sig = NULL;
	size_t slen;
	u_int len;
	int nid, hash_alg, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg_ident == NULL || strlen(alg_ident) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_alg_from_ident(alg_ident);
	if (key == NULL || key->rsa == NULL || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;
{
	const BIGNUM *n = NULL;
	RSA_get0_key(key->rsa, &n, NULL, NULL);
	if (BN_num_bits(n) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_INVALID_ARGUMENT;
}
	slen = RSA_size(key->rsa);
	if (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;

	/* hash the data */
	nid = rsa_hash_alg_nid(hash_alg);
#ifdef USE_LEGACY_RSA_SIGN
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if ((sig = malloc(slen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (RSA_sign(nid, digest, dlen, sig, &len, key->rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#else /*ndef USE_LEGACY_RSA_SIGN*/
{
	const EVP_MD *evp_md;
	EVP_PKEY *pkey = NULL;
	int ok = -1;

	sig = NULL;

	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error("%s: EVP_get_digestbynid %d failed", __func__, nid);
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto done;
	}

	EVP_PKEY_set1_RSA(pkey, key->rsa);

	slen = EVP_PKEY_size(pkey);
	sig = xmalloc(slen);	/*fatal on error*/

{
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		ok = -1;
		error("%s: out of memory", __func__);
		goto clean;
	}

	ok = EVP_SignInit_ex(md, evp_md, NULL);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignInit_ex fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

	ok = EVP_SignUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignUpdate fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

	ok = EVP_SignFinal(md, sig, &len, pkey);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: SignFinal fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

clean:
	EVP_MD_CTX_free(md);
}

done:
	if (pkey != NULL) EVP_PKEY_free(pkey);

	if (ok <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
}
#endif /*ndef USE_LEGACY_RSA_SIGN*/

	if (len < slen) {
		size_t diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} else if (len > slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
#ifdef USE_LEGACY_RSA_SIGN
	explicit_bzero(digest, sizeof(digest));
#endif
	if (sig != NULL) {
		explicit_bzero(sig, slen);
		free(sig);
	}
	sshbuf_free(b);
	return ret;
}

int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen, const u_char *data, size_t datalen)
{
	char *ktype = NULL;
	int hash_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len, diff, modlen;
	struct sshbuf *b = NULL;
	u_char *osigblob, *sigblob = NULL;
#ifdef USE_LEGACY_RSA_VERIFY
	size_t dlen;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
#endif

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
{
	const BIGNUM *n = NULL;
	RSA_get0_key(key->rsa, &n, NULL, NULL);
	if (BN_num_bits(n) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_INVALID_ARGUMENT;
}

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((hash_alg = rsa_hash_alg_from_ident(ktype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = RSA_size(key->rsa);
	if (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
	} else if (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		if ((sigblob = realloc(sigblob, modlen)) == NULL) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}
#ifdef USE_LEGACY_RSA_VERIFY
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	ret = openssh_RSA_verify(hash_alg, digest, dlen, sigblob, len,
	    key->rsa);
#else /*ndef USE_LEGACY_RSA_VERIFY*/
{
	int nid;
	const EVP_MD *evp_md;
	EVP_PKEY *pkey;
	int ok = -1;

	nid = rsa_hash_alg_nid(hash_alg);
	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error("%s: EVP_get_digestbynid %d failed", __func__, nid);
		free(sigblob);
		return -1;
	}

	ok = -1;
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto done;
	}

	EVP_PKEY_set1_RSA(pkey, key->rsa);

{
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		ok = -1;
		error("%s: out of memory", __func__);
		goto clean;
	}

	ok = EVP_VerifyInit(md, evp_md);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyInit fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

	ok = EVP_VerifyUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyUpdate fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

	ok = EVP_VerifyFinal(md, sigblob, len, pkey);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyFinal fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

clean:
	EVP_MD_CTX_free(md);
}

done:
	if (pkey != NULL) EVP_PKEY_free(pkey);

	if (ok <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	} else
		ret = SSH_ERR_SUCCESS;
}
#endif /*ndef USE_LEGACY_RSA_VERIFY*/

 out:
	if (sigblob != NULL) {
		explicit_bzero(sigblob, len);
		free(sigblob);
	}
	free(ktype);
	sshbuf_free(b);
#ifdef USE_LEGACY_RSA_VERIFY
	explicit_bzero(digest, sizeof(digest));
#endif
	return ret;
}

#ifdef USE_LEGACY_RSA_VERIFY
/*
 * See:
 * http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/
 * ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.asn
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
static const u_char id_sha1[] = {
	0x30, 0x21, /* type Sequence, length 0x21 (33) */
	0x30, 0x09, /* type Sequence, length 0x09 */
	0x06, 0x05, /* type OID, length 0x05 */
	0x2b, 0x0e, 0x03, 0x02, 0x1a, /* id-sha1 OID */
	0x05, 0x00, /* NULL */
	0x04, 0x14  /* Octet string, length 0x14 (20), followed by sha1 hash */
};

/*
 * See http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html
 * id-sha256 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
 *      organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2)
 *      id-sha256(1) }
 */
static const u_char id_sha256[] = {
	0x30, 0x31, /* type Sequence, length 0x31 (49) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, /* id-sha256 */
	0x05, 0x00, /* NULL */
	0x04, 0x20  /* Octet string, length 0x20 (32), followed by sha256 hash */
};

/*
 * See http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html
 * id-sha512 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
 *      organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2)
 *      id-sha256(3) }
 */
static const u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

static int
rsa_hash_alg_oid(int hash_alg, const u_char **oidp, size_t *oidlenp)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = sizeof(id_sha1);
		break;
	case SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = sizeof(id_sha256);
		break;
	case SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = sizeof(id_sha512);
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	return 0;
}

static int
openssh_RSA_verify(int hash_alg, u_char *hash, size_t hashlen,
    u_char *sigbuf, size_t siglen, RSA *rsa)
{
	size_t rsasize = 0, oidlen = 0, hlen = 0;
	int ret, len, oidmatch, hashmatch;
	const u_char *oid = NULL;
	u_char *decrypted = NULL;

	if ((ret = rsa_hash_alg_oid(hash_alg, &oid, &oidlen)) != 0)
		return ret;
	ret = SSH_ERR_INTERNAL_ERROR;
	hlen = ssh_digest_bytes(hash_alg);
	if (hashlen != hlen) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}
	rsasize = RSA_size(rsa);
	if (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    siglen == 0 || siglen > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}
	if ((decrypted = malloc(rsasize)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto done;
	}
	if ((len = RSA_public_decrypt(siglen, sigbuf, decrypted, rsa,
	    RSA_PKCS1_PADDING)) < 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto done;
	}
	if (len < 0 || (size_t)len != hlen + oidlen) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto done;
	}
	oidmatch = timingsafe_bcmp(decrypted, oid, oidlen) == 0;
	hashmatch = timingsafe_bcmp(decrypted + oidlen, hash, hlen) == 0;
	if (!oidmatch || !hashmatch) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto done;
	}
	ret = 0;
done:
	if (decrypted) {
		explicit_bzero(decrypted, rsasize);
		free(decrypted);
	}
	return ret;
}
#endif /*def USE_LEGACY_RSA_VERIFY*/

#endif /* WITH_OPENSSL */
