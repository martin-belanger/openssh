/* $OpenBSD: ssh-pkcs11.c,v 1.23 2016/10/28 03:33:52 djm Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
 * Copyright (c) 2011 Kenneth Robinette.  All rights reserved.
 * Copyright (c) 2013 Andrew Cooke.  All rights reserved.
 * Copyright (c) 2016 Roumen Petrov.  All rights reserved.
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

#ifdef ENABLE_PKCS11

#ifndef HAVE_RSA_PKCS1_OPENSSL
# undef RSA_PKCS1_OpenSSL
# define RSA_PKCS1_OpenSSL RSA_PKCS1_SSLeay
#endif

#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <stdarg.h>
#include <stdio.h>

#include <string.h>
#include <dlfcn.h>

#include "openbsd-compat/sys-queue.h"

#include <openssl/x509.h>
#include "evp-compat.h"

#define CRYPTOKI_COMPAT
#include "pkcs11.h"

#include "log.h"
#include "misc.h"
#include "sshkey.h"
#include "ssh-pkcs11.h"
#include "xmalloc.h"

/* Define if you want yo use legacy rsa key code */
#undef USE_LEGACY_PKCS11_RSAKEY

#ifndef USE_LEGACY_PKCS11_RSAKEY
#include "ssh-x509.h"
#endif


struct pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	int			logged_in;
};

struct pkcs11_provider {
	char			*name;
	void			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	struct pkcs11_slotinfo	*slotinfo;
	int			valid;
	int			refcount;
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;


/*
 * Constants used when creating the context extra data
 */
static int ssh_pkcs11_rsa_ctx_index = -1;
static int ssh_pkcs11_dsa_ctx_index = -1;
#ifdef OPENSSL_HAS_ECC
static int ssh_pkcs11_ec_ctx_index = -1;
#endif /*def OPENSSL_HAS_ECC*/

struct pkcs11_key {
	struct pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	char			*keyid;
	int			keyid_len;
};

static void pkcs11_provider_unref(struct pkcs11_provider *p);

static void
pkcs11_key_free(struct pkcs11_key *k11) {
	if (k11 == NULL) return;

	if (k11->provider)
		pkcs11_provider_unref(k11->provider);
	free(k11->keyid);
	free(k11);
}

static void
CRYPTO_EX_pkcs11_key_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad, long argl, void *argp
) {
	(void)parent;
	pkcs11_key_free(ptr);
	(void)ad;
	(void)argl;
	(void)argp;
}

static void
CRYPTO_EX_pkcs11_rsa_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp
) {
	if (idx == ssh_pkcs11_rsa_ctx_index)
		CRYPTO_EX_pkcs11_key_free(parent, ptr, ad, argl, argp);
}

static void
CRYPTO_EX_pkcs11_dsa_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp
) {
	if (idx == ssh_pkcs11_dsa_ctx_index)
		CRYPTO_EX_pkcs11_key_free(parent, ptr, ad, argl, argp);
}

#ifdef OPENSSL_HAS_ECC
static void
CRYPTO_EX_pkcs11_ec_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp
) {
	if (idx == ssh_pkcs11_ec_ctx_index)
		CRYPTO_EX_pkcs11_key_free(parent, ptr, ad, argl, argp);
}
#endif /*def OPENSSL_HAS_ECC*/


int pkcs11_interactive = 0;

int
pkcs11_init(int interactive)
{
	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	return (0);
}

/*
 * finalize a provider shared libarary, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actuall freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
static void
pkcs11_provider_finalize(struct pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug("pkcs11_provider_finalize: %p refcount %d valid %d",
	    (void*)p, p->refcount, p->valid);
	if (!p->valid)
		return;
	for (i = 0; i < p->nslots; i++) {
		if (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	if ((rv = p->function_list->C_Finalize(NULL)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = NULL;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
static void
pkcs11_provider_unref(struct pkcs11_provider *p)
{
	debug("pkcs11_provider_unref: %p refcount %d", (void*)p, p->refcount);
	if (--p->refcount <= 0) {
		if (p->valid)
			error("pkcs11_provider_unref: %p still valid", (void*)p);
		free(p->slotlist);
		free(p->slotinfo);
		free(p);
	}
}

/* unregister all providers, keys might still point to the providers */
void
pkcs11_terminate(void)
{
	struct pkcs11_provider *p;

	while ((p = TAILQ_FIRST(&pkcs11_providers)) != NULL) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/* lookup provider by name */
static struct pkcs11_provider *
pkcs11_provider_lookup(char *provider_id)
{
	struct pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check %p %s", (void*)p, p->name);
		if (!strcmp(provider_id, p->name))
			return (p);
	}
	return (NULL);
}

/* unregister provider by name */
int
pkcs11_del_provider(char *provider_id)
{
	struct pkcs11_provider *p;

	if ((p = pkcs11_provider_lookup(provider_id)) != NULL) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		return (0);
	}
	return (-1);
}

/* openssl callback for freeing an RSA key */
static int
pkcs11_rsa_finish(RSA *rsa)
{
	struct pkcs11_key	*k11;

	k11 = RSA_get_ex_data(rsa, ssh_pkcs11_rsa_ctx_index);
	RSA_set_ex_data(rsa, ssh_pkcs11_rsa_ctx_index, NULL);
	pkcs11_key_free(k11);
	return (1);
}

/* openssl callback for freeing an DSA key */
static int
pkcs11_dsa_finish(DSA *dsa)
{
	struct pkcs11_key	*k11;

	k11 = DSA_get_ex_data(dsa, ssh_pkcs11_dsa_ctx_index);
	DSA_set_ex_data(dsa, ssh_pkcs11_dsa_ctx_index, NULL);
	pkcs11_key_free(k11);
	return (1);
}

#ifdef OPENSSL_HAS_ECC
/* openssl callback for freeing an EC key */
static void
pkcs11_ec_finish(EC_KEY *ec)
{
	struct pkcs11_key	*k11;

#ifdef HAVE_EC_KEY_METHOD_NEW
	k11 = EC_KEY_get_ex_data(ec, ssh_pkcs11_ec_ctx_index);
	EC_KEY_set_ex_data(ec, ssh_pkcs11_ec_ctx_index, NULL);
#else
	k11 = ECDSA_get_ex_data(ec, ssh_pkcs11_ec_ctx_index);
	ECDSA_set_ex_data(ec, ssh_pkcs11_ec_ctx_index, NULL);
#endif
	pkcs11_key_free(k11);
}
#endif /*def OPENSSL_HAS_ECC*/


/* find a single 'obj' for given attributes */
static int
pkcs11_find(struct pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	int			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	if ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		return (-1);
	}
	if ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} else
		ret = 0;
	if ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	return (ret);
}

/* openssl callback doing the actual signing operation */
static int
pkcs11_rsa_private_encrypt(int flen, const u_char *from, u_char *to, RSA *rsa,
    int padding)
{
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		tlen = 0;
	CK_RV			rv;
	CK_OBJECT_CLASS	private_key_class = CKO_PRIVATE_KEY;
	CK_BBOOL		true_val = CK_TRUE;
	CK_MECHANISM		mech = {
		CKM_RSA_PKCS, NULL_PTR, 0
	};
	CK_ATTRIBUTE		key_filter[] = {
		{CKA_CLASS, NULL, sizeof(private_key_class) },
		{CKA_ID, NULL, 0},
		{CKA_SIGN, NULL, sizeof(true_val) }
	};
	char			*pin = NULL, prompt[1024];
	int			rval = -1;

	(void)padding;
	key_filter[0].pValue = &private_key_class;
	key_filter[2].pValue = &true_val;

	k11 = RSA_get_ex_data(rsa, ssh_pkcs11_rsa_ctx_index);
	if (k11 == NULL) {
		error("RSA_get_ex_data failed for rsa %p", (void*)rsa);
		return (-1);
	}
	if (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider for rsa %p", (void*)rsa);
		return (-1);
	}
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];
	if ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		if (!pkcs11_interactive) {
			error("need pin entry%s", (si->token.flags &
			    CKF_PROTECTED_AUTHENTICATION_PATH) ?
			    " on reader keypad" : "");
			return (-1);
		}
		if (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
			verbose("Deferring PIN entry to reader keypad.");
		else {
			snprintf(prompt, sizeof(prompt),
			    "Enter PIN for '%s': ", si->token.label);
			pin = read_passphrase(prompt, RP_ALLOW_EOF);
			if (pin == NULL)
				return (-1);	/* bail out */
		}
		rv = f->C_Login(si->session, CKU_USER, (u_char *)pin,
		    (pin != NULL) ? strlen(pin) : 0);
		if (pin != NULL) {
			explicit_bzero(pin, strlen(pin));
			free(pin);
		}
		if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			return (-1);
		}
		si->logged_in = 1;
	}
	key_filter[1].pValue = k11->keyid;
	key_filter[1].ulValueLen = k11->keyid_len;
	/* try to find object w/CKA_SIGN first, retry w/o */
	if (pkcs11_find(k11->provider, k11->slotidx, key_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, key_filter, 2, &obj) < 0) {
		error("cannot find private key");
	} else if ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
	} else {
		/* XXX handle CKR_BUFFER_TOO_SMALL */
		tlen = RSA_size(rsa);
		rv = f->C_Sign(si->session, (CK_BYTE *)from, flen, to, &tlen);
		if (rv == CKR_OK) 
			rval = tlen;
		else 
			error("C_Sign failed: %lu", rv);
	}
	return (rval);
}

static int
pkcs11_rsa_private_decrypt(int flen, const u_char *from, u_char *to, RSA *rsa,
    int padding)
{
	(void)flen;
	(void)from;
	(void)to;
	(void)rsa;
	(void)padding;
	return (-1);
}

static RSA_METHOD *ssh_pkcs11_rsa_method = NULL;

/* redirect private key operations for rsa key to pkcs11 token */
static int
pkcs11_rsa_wrap(struct pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, RSA *rsa)
{
	struct pkcs11_key	*k11;

	/* ensure RSA context index */
	if (ssh_pkcs11_rsa_ctx_index < 0)
		ssh_pkcs11_rsa_ctx_index = RSA_get_ex_new_index(0, NULL, NULL, NULL, CRYPTO_EX_pkcs11_rsa_free);
	if (ssh_pkcs11_rsa_ctx_index < 0) {
		return (-1);
	}

	if (ssh_pkcs11_rsa_method == NULL) {
		const RSA_METHOD *def = RSA_PKCS1_OpenSSL();

		ssh_pkcs11_rsa_method = RSA_meth_new("SSH PKCS#11 RSA method",
		#ifdef RSA_FLAG_FIPS_METHOD
			RSA_FLAG_FIPS_METHOD |
		#endif
			0);
		if (ssh_pkcs11_rsa_method == NULL)
			return (-1);

		if (!RSA_meth_set_priv_enc(ssh_pkcs11_rsa_method, pkcs11_rsa_private_encrypt)
		||  !RSA_meth_set_priv_dec(ssh_pkcs11_rsa_method, pkcs11_rsa_private_decrypt)
		||  !RSA_meth_set_finish(ssh_pkcs11_rsa_method, pkcs11_rsa_finish)
		)
			goto err;

		if (!RSA_meth_set_pub_enc(ssh_pkcs11_rsa_method, RSA_meth_get_pub_enc(def))
		||  !RSA_meth_set_pub_dec(ssh_pkcs11_rsa_method, RSA_meth_get_pub_dec(def))
		||  !RSA_meth_set_mod_exp(ssh_pkcs11_rsa_method, RSA_meth_get_mod_exp(def))
		||  !RSA_meth_set_bn_mod_exp(ssh_pkcs11_rsa_method, RSA_meth_get_bn_mod_exp(def))
		)
			goto err;
	}

	k11 = xcalloc(1, sizeof(*k11));
	k11->provider = provider;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ulValueLen;
	if (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->pValue, k11->keyid_len);
	}
	RSA_set_method(rsa, ssh_pkcs11_rsa_method);
	RSA_set_ex_data(rsa, ssh_pkcs11_rsa_ctx_index, k11);
	return (0);

err:
	RSA_meth_free(ssh_pkcs11_rsa_method);
	ssh_pkcs11_rsa_method = NULL;
	return (-1);
}

static DSA_SIG*
parse_DSA_SIG(char *buf, CK_ULONG blen) {
	DSA_SIG *sig;
	BIGNUM *ps, *pr;
	int  k = blen >> 1;

	pr = BN_bin2bn(buf    , k, NULL);
	ps = BN_bin2bn(buf + k, k, NULL);
	if ((pr == NULL) || (ps == NULL)) goto parse_err;

	sig = DSA_SIG_new();
	if (sig == NULL) goto parse_err;

	if (DSA_SIG_set0(sig, pr, ps))
		return (sig);

/*error*/
	DSA_SIG_free(sig);
parse_err:
	BN_free(pr);
	BN_free(ps);
	return (NULL);
}

/* redirect private key operations for dsa key to pkcs11 token */
static DSA_SIG*
pkcs11_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		tlen = 0;
	CK_RV			rv;
	CK_OBJECT_CLASS		private_key_class = CKO_PRIVATE_KEY;
	CK_BBOOL		true_val = CK_TRUE;
	CK_MECHANISM		mech = {
		CKM_DSA, NULL_PTR, 0
	};
	CK_ATTRIBUTE		key_filter[] = {
		{CKA_CLASS, NULL, sizeof(private_key_class) },
		{CKA_ID, NULL, 0},
		{CKA_SIGN, NULL, sizeof(true_val) }
	};
	char			*pin, prompt[1024];
	DSA_SIG			*sig = NULL;

	debug3("pkcs11_dsa_do_sign");

	/* some compilers complain about non-constant initializer so we
	   use NULL in CK_ATTRIBUTE above and set the values here */
	key_filter[0].pValue = &private_key_class;
	key_filter[2].pValue = &true_val;

	k11 = DSA_get_ex_data(dsa, ssh_pkcs11_dsa_ctx_index);
	if (k11 == NULL) {
		error("DSA_get_ex_data failed for dsa %p", (void*)dsa);
		return NULL;
	}
	if (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider for dsa %p", (void*)dsa);
		return NULL;
	}
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];
	if ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		if (!pkcs11_interactive) {
			error("need pin");
			return (NULL);
		}
		snprintf(prompt, sizeof(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		pin = read_passphrase(prompt, RP_ALLOW_EOF);
		if (pin == NULL)
			return (NULL);	/* bail out */
		if ((rv = f->C_Login(si->session, CKU_USER, pin, strlen(pin)))
		    != CKR_OK) {
			free(pin);
			error("C_Login failed: %lu", rv);
			return (NULL);
		}
		free(pin);
		si->logged_in = 1;
	}
	key_filter[1].pValue = k11->keyid;
	key_filter[1].ulValueLen = k11->keyid_len;
	/* try to find object w/CKA_SIGN first, retry w/o */
	if (pkcs11_find(k11->provider, k11->slotidx, key_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, key_filter, 2, &obj) < 0) {
		error("cannot find private key");
	} else if ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
	} else {
		char rs[(2*SHA_DIGEST_LENGTH)];
		tlen = (2*SHA_DIGEST_LENGTH);
		rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dlen, rs, &tlen);
		if (rv == CKR_OK) {
			sig = parse_DSA_SIG(rs, tlen);
		}
		else
			error("C_Sign failed: %lu", rv);
	}
	return (sig);
}


static DSA_METHOD *ssh_pkcs11_dsa_method = NULL;


static int
pkcs11_dsa_wrap(struct pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, DSA *dsa)
{
	struct pkcs11_key	*k11;

	/* ensure DSA context index */
	if (ssh_pkcs11_dsa_ctx_index < 0)
		ssh_pkcs11_dsa_ctx_index = DSA_get_ex_new_index(0, NULL, NULL, NULL, CRYPTO_EX_pkcs11_dsa_free);
	if (ssh_pkcs11_dsa_ctx_index < 0) {
		return (-1);
	}

	if (ssh_pkcs11_dsa_method == NULL) {
		const DSA_METHOD *def = DSA_OpenSSL();

		ssh_pkcs11_dsa_method = DSA_meth_new("SSH PKCS#11 DSA method",
		#ifdef DSA_FLAG_FIPS_METHOD
			DSA_FLAG_FIPS_METHOD |
		#endif
			0);
		if (ssh_pkcs11_dsa_method == NULL)
			return (-1);

		if (!DSA_meth_set_sign(ssh_pkcs11_dsa_method, pkcs11_dsa_do_sign)
		||  !DSA_meth_set_finish(ssh_pkcs11_dsa_method, pkcs11_dsa_finish)
		)
			goto err;

		if (!DSA_meth_set_verify(ssh_pkcs11_dsa_method, DSA_meth_get_verify(def))
		||  !DSA_meth_set_mod_exp(ssh_pkcs11_dsa_method, DSA_meth_get_mod_exp(def))
		||  !DSA_meth_set_bn_mod_exp(ssh_pkcs11_dsa_method, DSA_meth_get_bn_mod_exp(def))
		)
			goto err;
	}

	k11 = xcalloc(1, sizeof(*k11));
	k11->provider = provider;
	provider->refcount++;	/* provider referenced by DSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ulValueLen;
	if (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->pValue, k11->keyid_len);
	}
	DSA_set_method(dsa, ssh_pkcs11_dsa_method);
	DSA_set_ex_data(dsa, ssh_pkcs11_dsa_ctx_index, k11);
	return (0);

err:
	DSA_meth_free(ssh_pkcs11_dsa_method);
	ssh_pkcs11_dsa_method = NULL;
	return (-1);
}


#ifdef OPENSSL_HAS_ECC
static ECDSA_SIG*
parse_ECDSA_SIG(char *buf, CK_ULONG blen) {
	ECDSA_SIG *sig;
	BIGNUM *ps, *pr;
	int  k = blen >> 1;

	pr = BN_bin2bn(buf    , k, NULL);
	ps = BN_bin2bn(buf + k, k, NULL);
	if ((pr == NULL) || (ps == NULL)) goto parse_err;

	sig = ECDSA_SIG_new();
	if (sig == NULL) goto parse_err;

	if (ECDSA_SIG_set0(sig, pr, ps))
		return (sig);

/*error*/
	ECDSA_SIG_free(sig);
parse_err:
	BN_free(pr);
	BN_free(ps);
	return (NULL);
}


/* redirect private key operations for ec key to pkcs11 token */
static ECDSA_SIG*
pkcs11_ecdsa_do_sign(
	const unsigned char *dgst, int dlen,
	const BIGNUM *inv, const BIGNUM *rp,
	EC_KEY *ec
) {
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		tlen = 0;
	CK_RV			rv;
	CK_OBJECT_CLASS		private_key_class = CKO_PRIVATE_KEY;
	CK_BBOOL		true_val = CK_TRUE;
	CK_MECHANISM		mech = {
		CKM_ECDSA, NULL_PTR, 0
	};
	CK_ATTRIBUTE		key_filter[] = {
		{CKA_CLASS, NULL, sizeof(private_key_class) },
		{CKA_ID, NULL, 0},
		{CKA_SIGN, NULL, sizeof(true_val) }
	};
	char			*pin, prompt[1024];
	ECDSA_SIG		*sig = NULL;

	debug3("pkcs11_ecdsa_do_sign");

	(void)inv;
	(void)rp;

	/* some compilers complain about non-constant initializer so we
	   use NULL in CK_ATTRIBUTE above and set the values here */
	key_filter[0].pValue = &private_key_class;
	key_filter[2].pValue = &true_val;

#ifdef HAVE_EC_KEY_METHOD_NEW
	k11 = EC_KEY_get_ex_data(ec, ssh_pkcs11_ec_ctx_index);
#else
	k11 = ECDSA_get_ex_data(ec, ssh_pkcs11_ec_ctx_index);
#endif
	if (k11 == NULL) {
	#ifdef HAVE_EC_KEY_METHOD_NEW
		error("EC_KEY_get_ex_data failed for ec %p", (void*)ec);
	#else
		error("ECDSA_get_ex_data failed for ec %p", (void*)ec);
	#endif
		return NULL;
	}
	if (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider for ec %p", (void*)ec);
		return NULL;
	}
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];
	if ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		if (!pkcs11_interactive) {
			error("need pin");
			return (NULL);
		}
		snprintf(prompt, sizeof(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		pin = read_passphrase(prompt, RP_ALLOW_EOF);
		if (pin == NULL)
			return (NULL);	/* bail out */
		if ((rv = f->C_Login(si->session, CKU_USER, pin, strlen(pin)))
		    != CKR_OK) {
			free(pin);
			error("C_Login failed: %lu", rv);
			return (NULL);
		}
		free(pin);
		si->logged_in = 1;
	}
	key_filter[1].pValue = k11->keyid;
	key_filter[1].ulValueLen = k11->keyid_len;
	/* try to find object w/CKA_SIGN first, retry w/o */
	if (pkcs11_find(k11->provider, k11->slotidx, key_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, key_filter, 2, &obj) < 0) {
		error("cannot find private key");
	} else if ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
	} else {
		char rs[(1024>>2)/*> 2*[521/8]=2*66 */];

		tlen = sizeof(rs);
		rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dlen, rs, &tlen);
		if (rv == CKR_OK) {
			sig = parse_ECDSA_SIG(rs, tlen);
		}
		else
			error("C_Sign failed: %lu", rv);
	}
	return (sig);
}


#ifdef HAVE_EC_KEY_METHOD_NEW
static int
pkcs11_ecdsa_sign(int type,
	const unsigned char *dgst, int dlen,
	unsigned char *sig, unsigned int *siglen,
	const BIGNUM *inv, const BIGNUM *rp,
	EC_KEY *ec
) {
	ECDSA_SIG *s;

	debug3("pkcs11_ecdsa_sign");
	(void)type;

	s = pkcs11_ecdsa_do_sign(dgst, dlen, inv, rp, ec);
	if (s == NULL) {
		*siglen = 0;
		return (0);
	}

	*siglen = i2d_ECDSA_SIG(s, &sig);

	ECDSA_SIG_free(s);
	return (1);
}
#endif /*def HAVE_EC_KEY_METHOD_NEW*/


#ifdef HAVE_EC_KEY_METHOD_NEW
static EC_KEY_METHOD *pkcs11_ec_method = NULL;
#else
static ECDSA_METHOD  *pkcs11_ec_method = NULL;
#endif


static int
pkcs11_ec_wrap(struct pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, EC_KEY *ec)
{
	struct pkcs11_key	*k11;

	/* ensure EC context index */
	if (ssh_pkcs11_ec_ctx_index < 0)
	#ifdef HAVE_EC_KEY_METHOD_NEW
		ssh_pkcs11_ec_ctx_index = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, CRYPTO_EX_pkcs11_ec_free);
	#else
		ssh_pkcs11_ec_ctx_index = ECDSA_get_ex_new_index(0, NULL, NULL, NULL, CRYPTO_EX_pkcs11_ec_free);
	#endif
	if (ssh_pkcs11_ec_ctx_index < 0) {
		return (-1);
	}

	if (pkcs11_ec_method == NULL) {
	#ifdef HAVE_EC_KEY_METHOD_NEW
		pkcs11_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());

		EC_KEY_METHOD_set_init(pkcs11_ec_method,
		    NULL /* int (*init)(...) */,
		    pkcs11_ec_finish,
		    NULL /* int (*copy)(...) */,
		    NULL /* int (*set_group)(...) */,
		    NULL /* int (*set_private)(...) */,
		    NULL /* int (*set_public)(...) */
		);

		EC_KEY_METHOD_set_sign(pkcs11_ec_method,
		    pkcs11_ecdsa_sign,
		    NULL /* *sign_setup */,
		    pkcs11_ecdsa_do_sign
		);
	#else
		pkcs11_ec_method = ECDSA_METHOD_new(ECDSA_OpenSSL());

		ECDSA_METHOD_set_sign(pkcs11_ec_method,
		    pkcs11_ecdsa_do_sign
		);
	#endif
	}

	k11 = xcalloc(1, sizeof(*k11));
	k11->provider = provider;
	provider->refcount++;	/* provider referenced by EC key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ulValueLen;
	if (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->pValue, k11->keyid_len);
	}
#ifdef HAVE_EC_KEY_METHOD_NEW
	EC_KEY_set_method(ec, pkcs11_ec_method);
	EC_KEY_set_ex_data(ec, ssh_pkcs11_ec_ctx_index, k11);
#else
	ECDSA_set_method(ec, pkcs11_ec_method);
	ECDSA_set_ex_data(ec, ssh_pkcs11_ec_ctx_index, k11);
#endif
	return (0);
}
#endif /*def OPENSSL_HAS_ECC*/


/* remove trailing spaces */
static void
rmspace(u_char *buf, size_t len)
{
	size_t i;

	if (!len)
		return;
	for (i = len - 1;  i > 0; i--)
		if (i == len - 1 || buf[i] == ' ')
			buf[i] = '\0';
		else
			break;
}

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
static int
pkcs11_open_session(struct pkcs11_provider *p, CK_ULONG slotidx, char *pin)
{
	CK_RV			rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	int			login_required;

	f = p->function_list;
	login_required = p->slotinfo[slotidx].token.flags & CKF_LOGIN_REQUIRED;
	if (pin && login_required && !strlen(pin)) {
		error("pin required");
		return (-1);
	}
	if ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, NULL, NULL, &session))
	    != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		return (-1);
	}
	if (login_required && pin) {
		rv = f->C_Login(session, CKU_USER,
		    (u_char *)pin, strlen(pin));
		if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			if ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			return (-1);
		}
		p->slotinfo[slotidx].logged_in = 1;
	}
	p->slotinfo[slotidx].session = session;
	return (0);
}

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
static int pkcs11_fetch_keys_filter(struct pkcs11_provider *, CK_ULONG,
    CK_ATTRIBUTE [], int, CK_ATTRIBUTE [3], struct sshkey ***, int *)
	__attribute__((__bounded__(__minbytes__,4, 3 * sizeof(CK_ATTRIBUTE))));

static int
pkcs11_fetch_keys(struct pkcs11_provider *p, CK_ULONG slotidx,
    struct sshkey ***keysp, int *nkeys)
{
	CK_OBJECT_CLASS	pubkey_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS	cert_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE		pubkey_filter[] = {
		{ CKA_CLASS, NULL, sizeof(pubkey_class) }
	};
#ifndef USE_LEGACY_PKCS11_RSAKEY
	/* Find objects with cert class and X.509 cert type. */
	CK_CERTIFICATE_TYPE	type = CKC_X_509;
#endif
	CK_ATTRIBUTE		cert_filter[] = {
		{ CKA_CLASS, NULL, sizeof(cert_class) }
#ifndef USE_LEGACY_PKCS11_RSAKEY
	,	{ CKA_CERTIFICATE_TYPE, NULL, sizeof(type) }
#endif
	};
	CK_ATTRIBUTE		pubkey_attribs[] = {
		{ CKA_ID, NULL, 0 },
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 }
	};
	CK_ATTRIBUTE		cert_attribs[] = {
		{ CKA_ID, NULL, 0 },
		{ CKA_SUBJECT, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	};
	/* some compilers complain about non-constant initializer so we
	   use NULL in CK_ATTRIBUTE above and set the value here */
	pubkey_filter[0].pValue = &pubkey_class;
	cert_filter[0].pValue = &cert_class;
#ifndef USE_LEGACY_PKCS11_RSAKEY
	cert_filter[1].pValue = &type;
#endif

#ifdef USE_LEGACY_PKCS11_RSAKEY
	if (pkcs11_fetch_keys_filter(p, slotidx, pubkey_filter, 1, pubkey_attribs,
	    keysp, nkeys) < 0 ||
#else
	(void)pubkey_filter;
	(void)pubkey_attribs;
	if (
#endif
	    pkcs11_fetch_keys_filter(p, slotidx, cert_filter, sizeof(cert_filter)/sizeof(*cert_filter),
	    cert_attribs, keysp, nkeys) < 0)
		return (-1);
	return (0);
}


#ifdef USE_LEGACY_PKCS11_RSAKEY
static int
pkcs11_key_included(struct sshkey ***keysp, int *nkeys, struct sshkey *key)
{
	int i;

	for (i = 0; i < *nkeys; i++)
		if (sshkey_equal(key, (*keysp)[i]))
			return (1);
	return (0);
}
#endif /*def USE_LEGACY_PKCS11_RSAKEY*/

static int
pkcs11_fetch_keys_filter(struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_ATTRIBUTE filter[], int filter_size, CK_ATTRIBUTE attribs[3],
    struct sshkey ***keysp, int *nkeys)
{
	struct sshkey		*key;
#ifdef USE_LEGACY_PKCS11_RSAKEY
	RSA			*rsa;
	X509 			*x509;
	EVP_PKEY		*evp;
#endif
	int			i;
	const u_char		*cp;
	CK_RV			rv;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		nfound;
	CK_SESSION_HANDLE	session;
	CK_FUNCTION_LIST	*f;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	/* setup a filter the looks for public keys */
	if ((rv = f->C_FindObjectsInit(session, filter, filter_size)) != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		return (-1);
	}
	while (1) {
		/* XXX 3 attributes in attribs[] */
		for (i = 0; i < 3; i++) {
			attribs[i].pValue = NULL;
			attribs[i].ulValueLen = 0;
		}
		if ((rv = f->C_FindObjects(session, &obj, 1, &nfound)) != CKR_OK
		    || nfound == 0)
			break;
		/* found a object, so figure out size of the attributes */
		if ((rv = f->C_GetAttributeValue(session, obj, attribs, 3))
		    != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			continue;
		}
		/*
		 * Allow CKA_ID (always first attribute) to be empty, but
		 * ensure that none of the others are zero length.
		 * XXX assumes CKA_ID is always first.
		 */
		if (attribs[1].ulValueLen == 0 ||
		    attribs[2].ulValueLen == 0) {
			continue;
		}
		/* allocate buffers for attributes */
		for (i = 0; i < 3; i++) {
			if (attribs[i].ulValueLen > 0) {
				attribs[i].pValue = xmalloc(
				    attribs[i].ulValueLen);
			}
		}

		/*
		 * retrieve ID, modulus and public exponent of RSA key,
		 * or ID, subject and value for certificates.
		 */
#ifdef USE_LEGACY_PKCS11_RSAKEY
		rsa = NULL;
#endif
		if ((rv = f->C_GetAttributeValue(session, obj, attribs, 3))
		    != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
#ifdef USE_LEGACY_PKCS11_RSAKEY
		} else if (attribs[1].type == CKA_MODULUS ) {
			if ((rsa = RSA_new()) == NULL) {
				error("RSA_new failed");
			} else {
				rsa->n = BN_bin2bn(attribs[1].pValue,
				    attribs[1].ulValueLen, NULL);
				rsa->e = BN_bin2bn(attribs[2].pValue,
				    attribs[2].ulValueLen, NULL);
			}
		} else {
			cp = attribs[2].pValue;
			if ((x509 = X509_new()) == NULL) {
				error("X509_new failed");
			} else if (d2i_X509(&x509, &cp, attribs[2].ulValueLen)
			    == NULL) {
				error("d2i_X509 failed");
			} else if ((evp = X509_get_pubkey(x509)) == NULL ||
			    evp->type != EVP_PKEY_RSA ||
			    evp->pkey.rsa == NULL) {
				debug("X509_get_pubkey failed or no rsa");
			} else if ((rsa = RSAPublicKey_dup(evp->pkey.rsa))
			    == NULL) {
				error("RSAPublicKey_dup");
			}
			if (x509)
				X509_free(x509);
		}
		if (rsa && rsa->n && rsa->e &&
		    pkcs11_rsa_wrap(p, slotidx, &attribs[0], rsa) == 0) {
			key = sshkey_new(KEY_UNSPEC);
			key->rsa = rsa;
			key->type = KEY_RSA;
			key->flags |= SSHKEY_FLAG_EXT;
			if (pkcs11_key_included(keysp, nkeys, key)) {
				sshkey_free(key);
			} else {
				/* expand key array and add key */
				*keysp = xreallocarray(*keysp, *nkeys + 1,
				    sizeof(struct sshkey *));
				(*keysp)[*nkeys] = key;
				*nkeys = *nkeys + 1;
				debug("have %d keys", *nkeys);
			}
		} else if (rsa) {
			RSA_free(rsa);
#else /* ndef USE_LEGACY_PKCS11_RSAKEY */
		} else {
			int rv_wrap;
			(void)cp;
			key = x509key_from_blob(attribs[2].pValue, attribs[2].ulValueLen);
			if (key == NULL) {
				/* x509key_from_blob return NULL if key type is not
				 * supported and if can not extract X.509 certificate
				 */
				debug3("%s: x509key_from_blob fail", __func__);
				continue;
			}

			switch(X509KEY_BASETYPE(key)) {
			case KEY_RSA:
				rv_wrap = pkcs11_rsa_wrap(p, slotidx, &attribs[0], key->rsa);
				break;
			case KEY_DSA:
				rv_wrap = pkcs11_dsa_wrap(p, slotidx, &attribs[0], key->dsa);
				break;
#ifdef OPENSSL_HAS_ECC
			case KEY_ECDSA:
				rv_wrap = pkcs11_ec_wrap(p, slotidx, &attribs[0], key->ecdsa);
				break;
#endif /*def OPENSSL_HAS_ECC*/
			default:
				rv_wrap = -1;
			}

			if (rv_wrap == 0) {
				key->flags |= KEY_FLAG_EXT;
				/* expand key array and add key */
				*keysp = xreallocarray(*keysp, *nkeys + 1, sizeof(Key *));
				(*keysp)[*nkeys] = key;
				*nkeys = *nkeys + 1;
				debug("have %d keys", *nkeys);
			}
#endif /* ndef USE_LEGACY_PKCS11_RSAKEY */
		}
		for (i = 0; i < 3; i++)
			free(attribs[i].pValue);
	}
	if ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	return (0);
}

/* register a new provider, fails if provider already exists */
int
pkcs11_add_provider(char *provider_id, char *pin, struct sshkey ***keyp)
{
	int nkeys, need_finalize = 0;
	struct pkcs11_provider *p = NULL;
	void *handle = NULL;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = NULL;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	*keyp = NULL;
	if (pkcs11_provider_lookup(provider_id) != NULL) {
		debug("%s: provider already registered: %s",
		    __func__, provider_id);
		goto fail;
	}
	/* open shared pkcs11-libarary */
	if ((handle = dlopen(provider_id, RTLD_NOW)) == NULL) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		goto fail;
	}
	if ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == NULL) {
		error("dlsym(C_GetFunctionList) failed: %s", dlerror());
		goto fail;
	}
	p = xcalloc(1, sizeof(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* setup the pkcs11 callbacks */
	if ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		goto fail;
	}
	p->function_list = f;
	if ((rv = f->C_Initialize(NULL)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		goto fail;
	}
	need_finalize = 1;
	if ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		goto fail;
	}
	rmspace(p->info.manufacturerID, sizeof(p->info.manufacturerID));
	rmspace(p->info.libraryDescription, sizeof(p->info.libraryDescription));
	debug("provider %s: manufacturerID <%s> cryptokiVersion %d.%d"
	    " libraryDescription <%s> libraryVersion %d.%d",
	    provider_id,
	    p->info.manufacturerID,
	    p->info.cryptokiVersion.major,
	    p->info.cryptokiVersion.minor,
	    p->info.libraryDescription,
	    p->info.libraryVersion.major,
	    p->info.libraryVersion.minor);
	if ((rv = f->C_GetSlotList(CK_TRUE, NULL, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		goto fail;
	}
	if (p->nslots == 0) {
		debug("%s: provider %s returned no slots", __func__,
		    provider_id);
		goto fail;
	}
	p->slotlist = xcalloc(p->nslots, sizeof(CK_SLOT_ID));
	if ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		goto fail;
	}
	p->slotinfo = xcalloc(p->nslots, sizeof(struct pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	for (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		if ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (unsigned long)i, rv);
			continue;
		}
		if ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2("%s: ignoring uninitialised token in "
			    "provider %s slot %lu", __func__,
			    provider_id, (unsigned long)i);
			continue;
		}
		rmspace(token->label, sizeof(token->label));
		rmspace(token->manufacturerID, sizeof(token->manufacturerID));
		rmspace(token->model, sizeof(token->model));
		rmspace(token->serialNumber, sizeof(token->serialNumber));
		debug("provider %s slot %lu: label <%s> manufacturerID <%s> "
		    "model <%s> serial <%s> flags 0x%lx",
		    provider_id, (unsigned long)i,
		    token->label, token->manufacturerID, token->model,
		    token->serialNumber, token->flags);
		/* open session, login with pin and retrieve public keys */
		if (pkcs11_open_session(p, i, pin) == 0)
			pkcs11_fetch_keys(p, i, keyp, &nkeys);
	}
	if (nkeys > 0) {
		TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
		p->refcount++;	/* add to provider list */
		return (nkeys);
	}
	debug("%s: provider %s returned no keys", __func__, provider_id);
	/* don't add the provider, since it does not have any keys */
fail:
	if (need_finalize && (rv = f->C_Finalize(NULL)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	if (p) {
		free(p->slotlist);
		free(p->slotinfo);
		free(p);
	}
	if (handle)
		dlclose(handle);
	return (-1);
}

#else

int
pkcs11_init(int interactive)
{
	return (0);
}

void
pkcs11_terminate(void)
{
	return;
}

#endif /* ENABLE_PKCS11 */
