/*
 * Copyright (c) 2002-2015 Roumen Petrov.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ssh-x509.h"
#include <ctype.h>
#include <string.h>

#include "ssh-xkalg.h"
#include "x509store.h"
#include <openssl/pem.h>
#include "evp-compat.h"
#include "xmalloc.h"
#include "ssherr.h"
#include "uuencode.h"
#include "log.h"

#ifndef ISSPACE
#  define ISSPACE(ch) (isspace((int)(unsigned char)(ch)))
#endif

/* pointer to x509store function to minimize build dependencies */
int (*pssh_x509store_verify_cert)(X509 *_cert, STACK_OF(X509) *_chain) = NULL;
STACK_OF(X509)* (*pssh_x509store_build_certchain)(X509 *cert, STACK_OF(X509) *untrusted) = NULL;


static int x509key_to_blob2(const Key *key, Buffer *b);


/* Temporary solution, see key.h */
#define TO_X509_KEY_TYPE(key)	SET_X509_KEY_TYPE(key, key->type)

static inline void
SET_X509_KEY_TYPE(Key *key, int k_type) {
	switch (k_type) {
	case KEY_RSA	: key->type = KEY_X509_RSA	; break;
	case KEY_ECDSA	: key->type = KEY_X509_ECDSA	; break;
	case KEY_DSA	: key->type = KEY_X509_DSA	; break;
	default		: /* avoid compiler warnings */	  break;
	}
}


struct ssh_x509_st {
	X509           *cert;  /* key certificate */
	STACK_OF(X509) *chain; /* reserved for future use */
};


SSH_X509*
SSH_X509_new() {
	SSH_X509 *xd;

	xd = xmalloc(sizeof(SSH_X509)); /*fatal on error*/
	xd->cert = NULL;
	xd->chain = NULL;

	return(xd);
}


static inline void
SSH_X509_free_data(SSH_X509* xd) {
	if (xd->cert != NULL) {
		X509_free(xd->cert);
		xd->cert = NULL;
	}

	if (xd->chain != NULL) {
		sk_X509_pop_free(xd->chain, X509_free);
		xd->chain = NULL;
	}
}


void
SSH_X509_free(SSH_X509* xd) {
	if (xd == NULL) return;

	SSH_X509_free_data(xd);
	free(xd);
}


X509*
SSH_X509_get_cert(SSH_X509 *xd) {
	return((xd != NULL) ? xd->cert : NULL);
}


int
ssh_X509_NAME_print(BIO* bio, X509_NAME *xn) {
	static u_long print_flags =	((XN_FLAG_ONELINE & \
					  ~XN_FLAG_SPC_EQ & \
					  ~XN_FLAG_SEP_MASK) | \
					 XN_FLAG_SEP_COMMA_PLUS);

	if (xn == NULL) return(-1);

	X509_NAME_print_ex(bio, xn, 0, print_flags);
	(void)BIO_flush(bio);

	return(BIO_pending(bio));
}


char*
ssh_X509_NAME_oneline(X509_NAME *xn) {
	char *buf = NULL;
	int size;
	BIO* mbio = NULL;

	if (xn == NULL) return(NULL);

	mbio = BIO_new(BIO_s_mem());
	if (mbio == NULL) return(buf);

	size = ssh_X509_NAME_print(mbio, xn);
	if (size <= 0) {
		error("ssh_X509_NAME_oneline: no data in buffer");
		goto done;
	}

	buf = xmalloc(size + 1); /*fatal on error*/

	/* we should request one byte more !?!? */
	if (size != BIO_gets(mbio, buf, size + 1)) {
		error("ssh_X509_NAME_oneline: cannot get data from buffer");
		goto done;
	}
	buf[size] = '\0';

done:
	/* This call will walk the chain freeing all the BIOs */
	BIO_free_all(mbio);

	return(buf);
}


static inline int
ssh_x509_support_plain_type(int k_type) {
	return (
	    (k_type == KEY_RSA) ||
#ifdef OPENSSL_HAS_ECC
	    (k_type == KEY_ECDSA) ||
#endif
	    (k_type == KEY_DSA)
	) ? 1 : 0;
}


int/*bool*/
key_is_x509(const Key *k) {
	if (k == NULL) return(0);

	if ( (k->type == KEY_X509_RSA) ||
#ifdef OPENSSL_HAS_ECC
	     (k->type == KEY_X509_ECDSA) ||
#endif
	     (k->type == KEY_X509_DSA) ) {
		return(1);
	}

	return(0);
}


#ifndef SSH_X509STORE_DISABLED
static const char*
x509key_find_subject(const char* s) {
	static const char *keywords[] = {
		"subject",
		"distinguished name",
		"distinguished-name",
		"distinguished_name",
		"distinguishedname",
		"dn",
		NULL
	};
	const char **q, *p;
	size_t len;

	if (s == NULL) {
		error("x509key_find_subject: no input data");
		return(NULL);
	}
	for (; *s && ISSPACE(*s); s++)
	{/*skip space*/}

	for (q=keywords; *q; q++) {
		len = strlen(*q);
		if (strncasecmp(s, *q, len) != 0) continue;

		for (p = s + len; *p && ISSPACE(*p); p++)
		{/*skip space*/}
		if (!*p) {
			error("x509key_find_subject: no data after keyword");
			return(NULL);
		}
		if (*p == ':' || *p == '=') {
			for (p++; *p && ISSPACE(*p); p++)
			{/*skip space*/}
			if (!*p) {
				error("x509key_find_subject: no data after separator");
				return(NULL);
			}
		}
		if (*p == '/' || *p == ',') {
			/*skip leading [Relative]DistinguishedName elements separator*/
			for (p++; *p && ISSPACE(*p); p++)
			{/*skip space*/}
			if (!*p) {
				error("x509key_find_subject: no data");
				return(NULL);
			}
		}
		return(p);
	}
	return(NULL);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
static unsigned long
ssh_hctol(u_char ch) {
/* '0'-'9' = 0x30 - 0x39 (ascii) */
/* 'A'-'F' = 0x41 - 0x46 (ascii) */
/* 'a'-'f' = 0x61 - 0x66 (ascii) */
/* should work for EBCDIC */
	if (('0' <= ch) && (ch <= '9')) {
		return((long)(ch - '0'));
	}
	if (('A' <= ch) && (ch <= 'F')) {
		return((long)(ch - ('A' - 10)));
	}
	if (('a' <= ch) && (ch <= 'f')) {
		return((long)(ch - ('a' - 10)));
	}

	return(-1);
}


static unsigned long
ssh_hatol(const u_char *str, size_t maxsize) {
	int k;
	long v, ret = 0;

	for(k = maxsize; k > 0; k--, str++) {
		v = ssh_hctol(*str);
		if (v < 0) return(-1);
		ret = (ret << 4) + v;
	}
	return(ret);
}


static int
get_escsymbol(const u_char* str, size_t len, u_long *value) {
	const char ch = *str;
	long v;

	if (len < 1) {
		error("get_escsymbol:"
		" missing characters in escape sequence");
		return(-1);
	}

	/*escape formats:
		"{\\}\\W%08lX"
		"{\\}\\U%04lX"
		"{\\}\\%02X"
		"{\\}\\x%02X" - X509_NAME_oneline format
	*/
	if (ch == '\\') {
		if (value) *value = ch;
		return(1);
	}
	if (ch == 'W') {
		if (len < 9) {
			error("get_escsymbol:"
			" to short 32-bit escape sequence");
			return(-1);
		}
		v = ssh_hatol(++str, 8);
		if (v < 0) {
			error("get_escsymbol:"
			" invalid character in 32-bit hex sequence");
			 return(-1);
		}
		if (value) *value = v;
		return(9);
	}
	if (ch == 'U') {
		if (len < 5) {
			error("get_escsymbol:"
			" to short 16-bit escape sequence");
			return(-1);
		}
		v = ssh_hatol(++str, 4);
		if (v < 0) {
			error("get_escsymbol:"
			" invalid character in 16-bit hex sequence");
			 return(-1);
		}
		if (value) *value = v;
		return(5);
	}
#if 0
/*
The code bellow isn't correct. Let 'O' is not 8-bit string(as example
BMPString) then "X509_NAME_oneline" will output "\x00O"(!).
The X509_NAME_oneline output format will left unsupported, i.e.:
Unsupported:
$ openssl x509 -in cert_file -subject -noout
Supported:
  v0.9.7+
$ openssl x509 -in cert_file -subject -noout -nameopt oneline[,<more_name_options>]
  v0.9.6
$ openssl x509 -in cert_file -subject -noout -nameopt oneline [-nameopt <other_name_option>]
*/
	if ((ch == 'x') || (ch == 'X')) {
		if (len < 3) {
			error("get_escsymbol:"
			" to short 8-bit hex sequence");
			return(-1);
		}
		v = ssh_hatol(++str, 2);
		if (v < 0) {
			error("get_escsymbol:"
			" invalid character in 8-bit hex sequence");
			 return(-1);
		}
		if (value) *value = v;
		return(3);
	}
#endif
	v = ssh_hctol(*str);
	if (v < 0) {
		/*a character is escaped ?*/
		if (*str > 127) { /*ASCII comparision !*/
			/* there is no reason symbol above 127
                           to be escaped in this way */
			error("get_escsymbol:"
			" non-ascii character in escape sequence");
			return(-1);
		}
		if (value) *value = *str;
		return(1);
	}

	/*two hex numbers*/
	{
		long vlo;
		if (len < 2) {
			error("get_escsymbol:"
			" to short 8-bit escape sequence");
			return(-1);
		}
		vlo = ssh_hctol(*++str);
		if (vlo < 0) {
			error("get_escsymbol:"
			" invalid character in 8-bit hex sequence");
			 return(-1);
		}
		v = (v << 4) + vlo;
	}
	if (value) *value = v;
	return(2);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
static int/*bool*/
ssh_X509_NAME_add_entry_by_NID(X509_NAME* name, int nid, const u_char* str, size_t len) {
/* default maxsizes:
  C: 2
  L, ST: 128
  O, OU, CN: 64
  emailAddress: 128
*/
	u_char  buf[129*6+1]; /*enough for 128 UTF-8 symbols*/
	int     ret = 0;
	int     type = MBSTRING_ASC;
	u_long  ch;
	u_char *p;
	const u_char *q;
	size_t  k;

	/*this is internal method and we don't check validity of some arguments*/

	p = buf;
	q = str;
	k = sizeof(buf);

	while ((len > 0) && (k > 0)) {
		int ch_utf8 = 1;
		if (*q == '\0') {
			error("ssh_X509_NAME_add_entry_by_NID:"
			" unsupported zero(NIL) symbol in name");
			return(0);
		}
		if (*q == '\\') {
			len--;
			if (len <= 0) {
				error("ssh_X509_NAME_add_entry_by_NID:"
				" escape sequence without data");
				return(0);
			}

			ret = get_escsymbol(++q, len, &ch);
			if (ret < 0) return(0);
			if (ret == 2) {
				/*escaped two hex numbers*/
				ch_utf8 = 0;
			}
		} else {
			ret = UTF8_getc(q, len, &ch);
			if(ret < 0) {
				error("ssh_X509_NAME_add_entry_by_NID:"
				" cannot get next symbol(%.32s)"
				, q);
				return(0);
			}
		}
		len -= ret;
		q += ret;

		if (ch_utf8) {
			/* UTF8_putc return negative if buffer is too short */
			ret = UTF8_putc(p, k, ch);
			if (ret < 0) {
				error("ssh_X509_NAME_add_entry_by_NID:"
				" UTF8_putc fail for symbol %ld", ch);
				return(0);
			}
		} else {
			*p = (u_char)ch;
			ret = 1;
		}
		k -= ret;
		p += ret;
	}
	if (len > 0) {
		error("ssh_X509_NAME_add_entry_by_NID:"
		" too long data");
		return(0);
	}
	*p = '\0';

	for (p = buf; *p; p++) {
		if (*p > 127) {
			type = MBSTRING_UTF8;
			break;
		}
	}
	k = strlen((char*)buf);

	debug3("ssh_X509_NAME_add_entry_by_NID:"
		" type=%s, k=%d"
		, ((type == MBSTRING_ASC) ? "ASCII" : "UTF-8")
		, (int)k
	);

	/* this method will fail if string exceed max size limit for nid */
	ret = X509_NAME_add_entry_by_NID(name, nid, type, buf, (int)k, -1, 0);
	if (!ret) {
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("ssh_X509_NAME_add_entry_by_NID: X509_NAME_add_entry_by_NID"
		" fail with errormsg='%.*s'"
		" for nid=%d/%.32s"
		" and data='%.512s'"
		, (int)sizeof(ebuf), ebuf
		, nid, OBJ_nid2ln(nid)
		, str);
	}
	return(ret);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
static int/*bool*/
x509key_str2X509NAME(const char* _str, X509_NAME *_name) {
	int   ret = 1;
	char *str = NULL;
	char *p, *q, *token;
	int   has_more = 0;

	str = xmalloc(strlen(_str) + 1); /*fatal on error*/
	strcpy(str, _str);

	p = (char*)str;
	while (*p) {
		int nid;
		for (; *p && ISSPACE(*p); p++)
		{/*skip space*/}
		if (!*p) break;

		/* get shortest token */
		{
			char *tokenA = strchr(p, ',');
			char *tokenB = strchr(p, '/');

			if (tokenA == NULL) {
				token = tokenB;
			} else if (tokenB == NULL) {
				token = tokenA;
			} else {
				token = (tokenA < tokenB) ? tokenA : tokenB;
			}
		}
		if (token) {
			has_more = 1;
			*token = 0;
		} else {
			has_more = 0;
			token = p + strlen(p);
		}
		q = strchr(p, '=');
		if (!q) {
			error("x509key_str2X509NAME: cannot parse '%.200s' ...", p);
			ret = 0;
			break;
		}
		{
			char *s = q;
			for(--s; ISSPACE(*s) && (s > p); s--)
			{/*skip trailing space*/}
			*++s = 0;
		}
		nid = OBJ_txt2nid(p);
#ifdef SSH_OPENSSL_DN_WITHOUT_EMAIL
		if (nid == NID_undef) {
			/* work around for OpenSSL 0.9.7+ */
			if (strcasecmp(p, "Email") == 0) {
				nid = OBJ_txt2nid("emailAddress");
			}
		}
#endif /* def SSH_OPENSSL_DN_WITHOUT_EMAIL */
		if (nid == NID_undef) {
			error("x509key_str2X509NAME: cannot get nid from string '%.200s'", p);
			ret = 0;
			break;
		}

		p = q + 1;
		if (!*p) {
			error("x509key_str2X509NAME: no data");
			ret = 0;
			break;
		}

		for (; *p && ISSPACE(*p); p++)
		{/*skip space*/}
		for (q = token - 1; (q >= p) && ISSPACE(*q); q--)
		{/*skip unexpected \n, etc. from end*/}
		*++q = 0;

		ret = ssh_X509_NAME_add_entry_by_NID(_name, nid, (u_char*)p, (size_t)(q - p));
		if (!ret) {
			break;
		}

		p = token;
		if (has_more) p++;
	}

	free(str);
	debug3("x509key_str2X509NAME: return %d", ret);
	return(ret);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
static Key*
x509key_from_subject(int _keytype, const char* _cp) {
	const char *subject;
	Key        *key;
	X509       *x;

	if (_keytype != KEY_X509_RSA &&
	    _keytype != KEY_X509_ECDSA &&
	    _keytype != KEY_X509_DSA) {
		debug3("x509key_from_subject: %d is not x509 key type", _keytype);
		return(NULL);
	}
	debug3("x509key_from_subject(%d, [%.1024s]) called",
		_keytype, (_cp ? _cp : ""));
	subject = x509key_find_subject(_cp);
	if (subject == NULL)
		return(NULL);

	debug3("x509key_from_subject: subject=[%.1024s]", subject);
	key = key_new(KEY_UNSPEC);
	if (key == NULL) {
		error("x509key_from_subject: out of memory");
		return(NULL);
	}

	x = X509_new();
	if (x == NULL) {
		error("%s: out of memory X509_new()", __func__);
		goto err;
	}


	{	/*set distinguished name*/
		X509_NAME  *xn = X509_get_subject_name(x);

		if (xn == NULL) {
			error("%s: X.509 certificate without subject", __func__);
			goto err;
		}

		if (!x509key_str2X509NAME(subject, xn)) {
			error("%s: x509key_str2X509NAME fail", __func__);
			goto err;
		}
	}

	key->type = _keytype;
	if (!ssh_x509_set_cert(key, x)) {
		error("%s: ssh_x509_set_cert fail", __func__);
		goto err;
	}
	goto done;

err:
	if (x != NULL)
		X509_free(x);
	if (key != NULL) {
		key_free(key);
		key = NULL;
	}

done:
	debug3("x509key_from_subject: return %p", (void*)key);
	return(key);
}


Key*
X509key_from_subject(const char *pkalg, const char *cp, char **ep) {
	Key *ret;

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return NULL;

	ret = x509key_from_subject(p->type, cp);
}

	if (ret != NULL && ep != NULL) {
		/* NOTE line with subject lack comment part */
		*ep = (char*)cp + strlen(cp);
	}

	return(ret);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


static Key*
x509_to_key(X509 *x509) {
	Key      *key = NULL;
	EVP_PKEY *env_pkey;

	env_pkey = X509_get_pubkey(x509);
	if (env_pkey == NULL) {
		char ebuf[256];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("x509_to_key: X509_get_pubkey fail %.*s",
			(int)sizeof(ebuf), ebuf);
		return(NULL);
	}
	/*else*/
	debug3("x509_to_key: X509_get_pubkey done!");

	switch (EVP_PKEY_id(env_pkey)) {
	case EVP_PKEY_RSA:
		key = key_new(KEY_UNSPEC);
		key->rsa = EVP_PKEY_get1_RSA(env_pkey);
		key->type = KEY_RSA;
		(void)ssh_x509_set_cert(key, x509);
#ifdef DEBUG_PK
		RSA_print_fp(stderr, key->rsa, 8);
#endif
		break;

	case EVP_PKEY_DSA:
		key = key_new(KEY_UNSPEC);
		key->dsa = EVP_PKEY_get1_DSA(env_pkey);
		key->type = KEY_DSA;
		(void)ssh_x509_set_cert(key, x509);
#ifdef DEBUG_PK
		DSA_print_fp(stderr, key->dsa, 8);
#endif
		break;

#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC: {
		const EC_POINT *q = NULL;

		key = key_new(KEY_UNSPEC);
		key->ecdsa = EVP_PKEY_get1_EC_KEY(env_pkey);
		key->type = KEY_ECDSA;
		key->ecdsa_nid = key_ecdsa_key_to_nid(key->ecdsa);
		if (key->ecdsa_nid < 0) {
			error("%s: unsupported elliptic curve", __func__);
			goto err;
		}
		q = EC_KEY_get0_public_key(key->ecdsa);
		if (q == NULL) {
			error("%s: cannot get public ec key ", __func__);
			goto err;
		}
		if (key_ec_validate_public(EC_KEY_get0_group(key->ecdsa), q) < 0) {
			debug3("%s: cannot validate public ec key ", __func__);
			goto err;
		}
		(void)ssh_x509_set_cert(key, x509);
#ifdef DEBUG_PK
		key_dump_ec_point(EC_KEY_get0_group(key->ecdsa), q);
#endif
		} break;
#endif /*def OPENSSL_HAS_ECC*/

	default:
		error("%s: unsupported EVP_PKEY type %d", __func__, EVP_PKEY_id(env_pkey));
	}

	EVP_PKEY_free(env_pkey);
	return(key);

err:
	EVP_PKEY_free(env_pkey);
	key_free(key);
	return(NULL);
}


static X509*
x509_from_blob(const u_char *blob, int blen, int check_pending) {
	X509* x509 = NULL;
	BIO *mbio;

	if (blob == NULL) return(NULL);
	if (blen <= 0) return(NULL);

	/* convert blob data to BIO certificate data */
	mbio = BIO_new_mem_buf((void*)blob, blen);
	if (mbio == NULL) return(NULL);

	/* read X509 certificate from BIO data */
	x509 = d2i_X509_bio(mbio, NULL);
	if (x509 == NULL) {
		char ebuf[256];
		openssl_errormsg(ebuf, sizeof(ebuf));
		debug3("%s: read X509 from BIO fail %.*s", __func__,
			(int)sizeof(ebuf), ebuf);
	}

	if (check_pending) {
		size_t k;

		k = BIO_ctrl_pending(mbio);
		if (k > 0)
			error("%s: remaining bytes in X.509 blob %d", __func__,
				(int) k);
	}

	/* This call will walk the chain freeing all the BIOs */
	BIO_free_all(mbio);

	return(x509);
}


Key*
x509key_from_blob(const u_char *blob, int blen) {
	Key* key = NULL;
	X509* x509 = NULL;

	x509 = x509_from_blob(blob, blen, 0);
	if (x509 == NULL) {
		/* print only debug info !!!
		 * This method is used in place where we can only check incomming data.
		 * If data contain x506 certificate blob we will return a key otherwise NULL.
		 */
		debug3("%s: no X.509 certificate data", __func__);
	} else {
		key = x509_to_key(x509);
		if (key == NULL)
			X509_free(x509);
	}

	return(key);
}


static Key*
x509key_from_blob2(const u_char *blob, int blen) {
	Key      *key = NULL;
	SSH_X509 *xd = NULL;
	STACK_OF(X509) *pchain = NULL;
	Buffer   b;
	u_int    nc, no, k;
	int      e = 0;

	X509*  x;
	const u_char *xs;
	u_int  xlen;


	buffer_init(&b);
	buffer_append(&b, blob, blen);

	/* RFC6187: uint32  certificate-count */
	nc = buffer_get_int(&b);
	if (nc > 100) {
		error("%s: the number of X.509 certificates exceed limit(%d > 100)", __func__, nc);
		goto err;
	}
	if (nc < 1) {
		error("%s: at least one X.509 certificate must present (%d)", __func__, nc);
		goto err;
	}

	/* RFC6187: string  certificate[1..certificate-count] */
	xs = buffer_get_string(&b, &xlen);
	x = x509_from_blob(xs, xlen, 1);
	if (x != NULL) {
		key = x509_to_key(x);
		if (key != NULL)
			xd = key->x509_data;
		else
			e = 1;
	} else
		e = 1;

	if (xd != NULL) {
		if (pchain == NULL)
			pchain = sk_X509_new_null();
		if (pchain == NULL)
			fatal("x509key_from_blob2: out of memory - sk_X509_new_null");
		xd->chain = pchain;
	}

	for (k=1; k < nc; k++) {
		xs = buffer_get_string(&b, &xlen);
		if (xs == NULL) {
			e = 1;
			continue;
		}

		x = x509_from_blob(xs, xlen, 1);
		if (x == NULL) {
			e = 1;
			continue;
		}

		if (!e)
			sk_X509_insert(pchain, x, -1 /*last*/);
	}


	/* RFC6187: uint32  ocsp-response-count */
	no = buffer_get_int(&b);

	/* The number of OCSP responses MUST NOT exceed the number of certificates. */
	if (no > nc) {
		error("%s: the number of OCSP responses(%d) exceed the number of certificates(%d)", __func__, no, nc);
		e = 1;
	}

	/* RFC6187: string  ocsp-response[0..ocsp-response-count]
	 * NOTE: we will consider that OCSP responses start from 1 and
	 * zero in desctiption above is just to indicate that
	 * OCSP-responses are optional
	 */
	for (k=0; k < no; k++) {
		char *s;
		s = buffer_get_string(&b, NULL);
		if (s == NULL)
			e = 1;

		/* nop */
	}


	if (e)
		goto err;

{
	k = buffer_len(&b);
	if (k > 0)
		error("%s: remaining bytes in key blob %d", __func__, k);
}

	goto done;

err:
	if (key)
		key_free(key);
	key = NULL;

done:
	buffer_free(&b);
	return(key);
}


static int
x509key_check(const char* method, const Key *key) {
	SSH_X509 *xd;

	if (key == NULL)
		{ error("%.50s: no key", method); return(0); }

	if (!key_is_x509(key))
		{ error("%.50s: cannot handle key type %d", method, key->type); return(0); }

	xd = key->x509_data;
	if (xd == NULL)
		{ error("%.50s: no X.509 identity", method); return(0); }

	if (xd->cert == NULL)
		{ error("%.50s: no X.509 certificate", method); return(0); }

	return(1);
}


static void
buffer_put_x509_f(Buffer *b, X509 *x, void (*f)(Buffer *, const void *, u_int)) {
	void   *p;
	int     l, k;

	l = i2d_X509(x, NULL);
	p = xmalloc(l); /*fatal on error*/
	{
		u_char *q = p;
		k = i2d_X509(x, &q);
	}

	if (l == k)
		f(b, p, l);
	else
		fatal("%s: i2d_X509 failure", __func__);

	free(p);

	return;
}


static inline void
buffer_put_x509(Buffer *b, X509 *x) {
	buffer_put_x509_f(b, x, buffer_put_string);
}


static inline void
buffer_append_x509(Buffer *b, X509 *x) {
	buffer_put_x509_f(b, x, buffer_append);
}


int
X509key_encode_identity(const struct sshkey *key, struct sshbuf *b) {
	int ret;

	if (!key_is_x509(key))
		return SSH_ERR_SUCCESS;

	/* if RFC6187 key format */
	if (key->x509_data->chain) {
		struct sshbuf *d;

		d = sshbuf_new();
		if (d == NULL)
			return SSH_ERR_ALLOC_FAIL;

		ret = x509key_to_blob2(key, d)
		    ? SSH_ERR_SUCCESS
		    : SSH_ERR_INTERNAL_ERROR;
		if (ret != SSH_ERR_SUCCESS)
			debug3("%s: x509key_to_blob2 fail" , __func__);

		if (ret == SSH_ERR_SUCCESS)
			ret = sshbuf_put_stringb(b, d);

		buffer_free(d);
	} else {
		buffer_put_x509(b, key->x509_data->cert);
		ret = SSH_ERR_SUCCESS;
	}

	return ret;
}


int
X509key_decode_identity(const char *pkalg, struct sshbuf *b, struct sshkey *k) {
	int RFC6187_format;
	struct sshkey *tkey = NULL;
	int ret;

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return SSH_ERR_SUCCESS;

	RFC6187_format = p->chain;
}

{	/* fetch X.509 key */
	size_t blen;
	u_char *blob = NULL;

	ret = sshbuf_get_string(b, &blob, &blen);
	if (ret != SSH_ERR_SUCCESS)
		return ret;

	/* save cast size_t-> int as buffer limit < int */
	tkey = RFC6187_format
		? x509key_from_blob2(blob, blen)
		: x509key_from_blob(blob, blen);
	ret = tkey ? SSH_ERR_SUCCESS : SSH_ERR_INVALID_FORMAT;
	free(blob);
}

	if (ret != SSH_ERR_SUCCESS)
		return ret;

	SSH_X509_free(k->x509_data);
	k->x509_data = tkey->x509_data;
	tkey->x509_data = NULL;

	key_free(tkey);

	return ret;
}


void
x509key_move_identity(Key *from, Key *to) {
	/* Temporary controls for key types based on enumerate.
	 *
	 * Caller is responsible to perform all controlls before to call this
	 * method. For instance public key of X.509 certificate has to match
	 * plain public key.
	 * NOTE X.509 certificate may contain only distinguished name!
	 */
	if (!x509key_check("move_identity", from)) return;

	SSH_X509_free(to->x509_data);
	to->x509_data = from->x509_data;
	from->x509_data = NULL;
}


void
x509key_copy_identity(const Key *from, Key *to) {
	X509 *x;
	SSH_X509 *xd;
	STACK_OF(X509) *chain;
	STACK_OF(X509) *pchain;
	int n;

	if (!key_is_x509(from)) return;

	if (!x509key_check("copy_identity", from))
		fatal("x509key_copy_identity: no X.509 identity");

	xd = to->x509_data;
	if (xd)
		SSH_X509_free_data(xd);
	else {
		xd = SSH_X509_new(); /*fatal on error*/
		to->x509_data = xd;
	}

	x = X509_dup(from->x509_data->cert);
	if (x == NULL)
		fatal("x509key_copy_identity: X509_dup failed");
	xd->cert = x;

	/* legacy keys does not use chain */
	chain = from->x509_data->chain;
	if (chain == NULL)
		return;

	pchain = sk_X509_new_null();
	if (pchain == NULL)
		fatal("x509key_copy_identity: sk_X509_new_null failed");
	xd->chain = pchain;

	for (n = 0; n < sk_X509_num(chain); n++) {
		x = sk_X509_value(chain, n);
		x = X509_dup(x);
		if (x == NULL)
			fatal("x509key_copy_identity: X509_dup failed");
		sk_X509_insert(pchain, x, -1 /*last*/);
	}
}


void
x509key_demote(const Key *k, Key *pk) {
	x509key_copy_identity(k, pk);
}


static inline int
x509key_to_blob(const Key *key, Buffer *b) {
	buffer_append_x509(b, key->x509_data->cert);
	return(1);
}


static int
x509key_to_blob2(const Key *key, Buffer *b) {
	int    i, n;
	X509   *x;
	STACK_OF(X509) *chain;

	if (!x509key_check("x509key_to_blob2", key)) return(0);

	/* RFC6187 key format */
	chain = key->x509_data->chain;
	if (chain == NULL) {
		/* NOTE Historic key algorithm use only one X.509
		 * certificate. Empty chain is protocol error for
		 * keys in RFC6187 format, but we accept them.
		 */
		verbose("%s: X.509 certificate chain is not set."
		    " Some server may refuse key.", __func__);
	}

	/* NOTE: sk_num returns -1 if argument is null */
	n = chain ? sk_X509_num(chain) : 0;

	/* uint32  certificate-count */
	buffer_put_int(b, n + 1);
	/* string  certificate[1..certificate-count] */
	x = key->x509_data->cert;
	buffer_put_x509(b, x);
	for (i = 0; i < n; i++) {
		x = sk_X509_value(chain, i);
		buffer_put_x509(b, x);
	}

	/* uint32  ocsp-response-count */
	buffer_put_int(b, 0);
	/* string  ocsp-response[0..ocsp-response-count] */
	/* nop */

	return(1);
}


char*
x509key_subject(const Key *key) {
	X509_NAME *dn;

	if (!x509key_check("x509key_subject", key)) return(NULL);

	/* it is better to match format used in x509key_write_subject */
	dn = X509_get_subject_name(key->x509_data->cert);
	return(ssh_X509_NAME_oneline(dn)); /*fatal on error*/
}


int
x509key_write(const Key *key, FILE *f) {
	int    ret = 0;
	Buffer b;
	char  *uu;
	int    k;
	size_t n;

	if (!x509key_check("x509key_write_blob", key)) return(ret);

	buffer_init(&b);
	buffer_append_x509(&b, key->x509_data->cert);

	k = buffer_len(&b);
	n = (size_t)(k << 1);
	if (n < (size_t)k) goto done;	/* overflow */

	uu = xmalloc(n); /*fatal on error*/
	/* uuencode return int */
	k = uuencode(buffer_ptr(&b), k, uu, n);
	ret = k > 0;
	if (ret) {
		/* write ssh "blob" key */
		const char *ktype = key_ssh_name(key);
		n = strlen(ktype);
		ret = ( fwrite(ktype, 1, n, f) == n ) &&
		      ( fwrite(" ", 1, 1, f) == 1 ) &&
		      ( fwrite(uu, 1, k, f) ==  (size_t)k );
	}
	free(uu);

done:
	buffer_free(&b);
	return(ret);
}


#ifndef SSH_X509STORE_DISABLED
int
x509key_write_subject(const Key *key, FILE *f) {
	return(x509key_write_subject2(key, key_ssh_name(key), f));
}
#endif /*ndef SSH_X509STORE_DISABLED*/


#ifndef SSH_X509STORE_DISABLED
int
x509key_write_subject2(const Key *key, const char *keyname, FILE *f) {
	BIO  *out;

	if (!x509key_check("x509key_write_subject2", key)) return(0);
	if (keyname == NULL) return(0);

	out = BIO_new_fp(f, BIO_NOCLOSE);
	if (out == NULL) return(0);
#ifdef VMS
	{
		BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		out = BIO_push(tmpbio, out);
	}
#endif

	BIO_puts(out, keyname);
	BIO_puts(out, " Subject:");
	ssh_X509_NAME_print(out, X509_get_subject_name(key->x509_data->cert));

	BIO_free_all(out);
	return(1);
}
#endif /*ndef SSH_X509STORE_DISABLED*/


static int
x509key_load_certs_bio(Key *key, BIO *bio) {
	int ret = 0;
	STACK_OF(X509) *chain;

	chain = sk_X509_new_null();
	if (chain == NULL) {
		fatal("x509key_load_certs_bio: out of memory");
		return(-1); /*unreachable code*/
	}

	do {
		X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (x == NULL) {
			/*TODO:
			  - to analize errors
			  - to return negative value if error
			*/
			break;
		}

		sk_X509_insert(chain, x, -1 /*last*/);
	} while (1);

{	/* clear OpenSSL "error buffer" */
	char ebuf[64];
	(void) openssl_errormsg(ebuf, sizeof(ebuf));
}

	if (ret < 0) {
		sk_X509_pop_free(chain, X509_free);
		sk_X509_free(chain);
	} else {
		key->x509_data->chain = chain;
		ret = sk_X509_num(chain);
	}

	return(ret);
}


void
x509key_parse_cert(Key *key, EVP_PKEY *pk, BIO *bio) {
	X509 *x;
	SSH_X509 *xd;

	if (key == NULL) return;

	if (!ssh_x509_support_plain_type(key->type))
		return;

	debug("read X.509 certificate begin");
	x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (x == NULL) {
		char ebuf[512];
		openssl_errormsg(ebuf, sizeof(ebuf));
		debug3("%s: PEM_read_X509 fail %.*s", __func__,
			(int)sizeof(ebuf), ebuf);
		return;
	}

	if (!X509_check_private_key(x, pk)) {
		fatal("X.509 certificate don't match private key");
		/*unreachable code*/
	}

	xd = key->x509_data = SSH_X509_new(); /*fatal on error*/
	xd->cert = x;

	TO_X509_KEY_TYPE(key);

	/* TODO: temporary limit to EC keys as RSA algorithm
	 *  from RFC6187 is not supported yet
	 */
	if (key->type == KEY_X509_ECDSA)
		(void)x509key_load_certs_bio(key, bio);

	debug("read X.509 certificate done: type %.40s", key_type(key));
	return;
}


void
x509key_load_certs(const char *pkalg, Key *key, const char *filename) {
	size_t len;
	char file[PATH_MAX];

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return;

	/* return if public key algorithm is not in RFC6187 format */
	if (!p->chain)
		return;
}

	len = strlen(filename);
	if ((len > 9) &&
	    (strcmp (filename + len - 9,"-cert.pub") == 0)
	)	return;
	if ((len > 4) &&
	    (strcmp (filename + len - 4,".pub") != 0)
	)	return;

	/* Remove .pub suffix and try to extract extract certificates
	 * from "private" key file. Note that for pkcs11 module we may
	 * have only "public" part.
	 */
	if (strlcpy(file, filename, sizeof(file)) < len) {
		fatal("x509key_load_certs: length of filename exceed PATH_MAX");
		return; /*unreachable code*/
	}
	file[len - 4] = '\0';

{
	BIO *bio = BIO_new_file(filename, "r");
	if (bio == NULL) return;

	(void)x509key_load_certs_bio(key, bio);

	BIO_free_all(bio);
}

	x509key_build_chain(key);

	return;
}


void
x509key_build_chain(Key *key) {
	SSH_X509 *x509_data;
	STACK_OF(X509)* chain;

	if (pssh_x509store_build_certchain == NULL) return;

	/* TODO: temporary limit to EC keys as RSA algorithm
	 *  from RFC6187 is not supported yet
	 */
	if (key->type != KEY_X509_ECDSA) return;

	x509_data = key->x509_data;
	if (x509_data == NULL) return;

	chain = (*pssh_x509store_build_certchain)(x509_data->cert, x509_data->chain);
	if (chain == NULL) return;

	sk_X509_pop_free(x509_data->chain, X509_free);
	x509_data->chain = chain;
}


static int
x509key_write_bio_cert(BIO *out, X509 *x509) {
	int  ret = 0;

	BIO_puts(out, "issuer= ");
	ssh_X509_NAME_print(out, X509_get_issuer_name(x509));
	BIO_puts(out, "\n");

	BIO_puts(out, "subject= ");
	ssh_X509_NAME_print(out, X509_get_subject_name(x509));
	BIO_puts(out, "\n");

	{
		const char *alstr = (const char*)X509_alias_get0(x509, NULL);
		if (alstr == NULL) alstr = "<No Alias>";
		BIO_puts(out, alstr);
		BIO_puts(out, "\n");
	}

	ret = PEM_write_bio_X509(out, x509);
	if (!ret) {
		char ebuf[256];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: PEM_write_bio_X509 fail %.*s",
			__func__, (int)sizeof(ebuf), ebuf);
	}

	return(ret);
}


int/*bool*/
x509key_write_identity_bio_pem(
	BIO *bio,
	const Key *key
) {
	int flag = 0;
	X509 *x;
	STACK_OF(X509) *chain;
	int k;

	if (!x509key_check("save_identity_pem", key)) return(0);

	x = key->x509_data->cert;
	flag = x509key_write_bio_cert(bio, x);
	if (!flag)
		goto done;

	chain = key->x509_data->chain;
	if (chain == NULL)
		goto done;

	for (k = 0; k < sk_X509_num(chain); k++) {
		x = sk_X509_value(chain, k);
		flag = x509key_write_bio_cert(bio, x);
		if (!flag)
			goto done;
	}

done:
	return(flag);
}


#ifndef OPENSSH_KEYS_USE_BIO
int/*bool*/
x509key_save_identity_pem(FILE *fp, const Key *key) {
	int  flag;
	BIO *out;

	out = BIO_new_fp(fp, BIO_NOCLOSE);
	if (out == NULL) return(0);

#ifdef VMS
	{
		BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		if (tmpbio == NULL) {
			BIO_free_all(out);
			return(0);
		}
		out = BIO_push(tmpbio, out);
	}
#endif
	flag = x509key_write_identity_bio_pem(bio, key);

	BIO_free_all(out);

	return(flag);
}
#endif /*ndef OPENSSH_KEYS_USE_BIO*/


#ifndef SSH_X509STORE_DISABLED
/*
 * We can check only by Subject (Distinguished Name):
 *   - sshd receive from client only x509 certificate !!!
 *   - sshadd -d ... send only x509 certificate !!!
 *   - otherwise Key might contain private key
 */
int
ssh_x509_equal(const Key *a, const Key *b) {
	X509 *xa;
	X509 *xb;

	if (!x509key_check("ssh_x509_equal", a)) return(1);
	if (!x509key_check("ssh_x509_equal", b)) return(-1);

	xa = a->x509_data->cert;
	xb = b->x509_data->cert;
#if 1
/*
 * We must use own method to compare two X509_NAMEs instead of OpenSSL
 * function[s]! See notes before body of "ssh_X509_NAME_cmp()".
 */
	{
		X509_NAME *nameA = X509_get_subject_name(xa);
		X509_NAME *nameB = X509_get_subject_name(xb);
		return(ssh_X509_NAME_cmp(nameA, nameB));
	}
#else
	return(X509_subject_name_cmp(xa, xb));
#endif
}
#endif /*ndef SSH_X509STORE_DISABLED*/


int
ssh_x509key_type(const char *name) {
	const SSHX509KeyAlgs *p;
	int k;

	if (name == NULL) {
		fatal("ssh_x509key_type: name is NULL");
		return(KEY_UNSPEC); /*unreachable code*/
	}

	k = ssh_xkalg_nameind(name, &p, -1);
	return((k >= 0) ? p->type : KEY_UNSPEC);
}


static const SSHX509KeyAlgs*
ssh_first_xkalg(int type, int subtype) {
	const SSHX509KeyAlgs *p;
	int k;

	k = ssh_xkalg_typeind(type, subtype, &p, -1);
	if (k < 0)
		error("%s: cannot handle type %d, subtype %d", __func__,
			type, subtype);
	return((k >= 0) ? p : NULL);
}


const char*
ssh_x509key_name(const Key *k) {
	const SSHX509KeyAlgs *p;

	if (k == NULL) {
		fatal("ssh_x509key_name: key is NULL");
		return(NULL); /*unreachable code*/
	}
	if (!key_is_x509(k)) return(NULL);

	p = ssh_first_xkalg(k->type, k->ecdsa_nid);
	if (p != NULL) return(p->name);

	error("ssh_x509key_name: cannot handle type %d, curve %d",
		k->type, k->ecdsa_nid);
	return(NULL);
}


int
ssh_x509key_verify_cert(const Key *k) {
	int ret = -1;
	X509 *x;

	if (!x509key_check("verify_cert", k)) goto done;

	x = k->x509_data->cert;

	if (pssh_x509store_verify_cert != NULL) {
		ret = pssh_x509store_verify_cert(x, NULL);
	} else {
		error("%s: pssh_x509store_verify_cert is NULL", __func__);
	}

done:
	return(ret);
}


static int
ssh_x509_EVP_PKEY_sign(
	EVP_PKEY *privkey, const ssh_x509_md *dgst,
	u_char *sigret, u_int *siglen,
	const u_char *data, u_int datalen
) {
	int         ret = 1;
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		ret = -1;
		error("ssh_x509_EVP_PKEY_sign: out of memory");
	}

	if (ret > 0) {
		ret = EVP_SignInit_ex(ctx, dgst->evp, NULL);
		if (ret <= 0) {
			char ebuf[1024];
			openssl_errormsg(ebuf, sizeof(ebuf));
			error("ssh_x509_EVP_PKEY_sign: EVP_SignInit_ex"
			" fail with errormsg='%.*s'"
			, (int)sizeof(ebuf), ebuf);
		}
	}
	if (ret > 0) {
		ret = EVP_SignUpdate(ctx, data, datalen);
		if (ret <= 0) {
			char ebuf[1024];
			openssl_errormsg(ebuf, sizeof(ebuf));
			error("ssh_x509_EVP_PKEY_sign: EVP_SignUpdate"
			" fail with errormsg='%.*s'"
			, (int)sizeof(ebuf), ebuf);
		}
	}
	if (ret > 0) {
		ret = dgst->SignFinal(ctx, sigret, siglen, privkey);
		debug3("ssh_x509_EVP_PKEY_sign: keylen=%d, siglen=%u",
		       EVP_PKEY_size(privkey), *siglen);
		if (ret <= 0) {
			char ebuf[1024];
			openssl_errormsg(ebuf, sizeof(ebuf));
			error("ssh_x509_EVP_PKEY_sign: digest failed: %.*s"
			, (int)sizeof(ebuf), ebuf);
		}
	}

	EVP_MD_CTX_free(ctx);

	return(ret);
}


int
ssh_x509_sign(
	const Key *key,
	u_char **psignature, size_t *psignaturelen,
	const u_char *data, u_int datalen
) {
	int    ret = -1;
	const SSHX509KeyAlgs *xkalg = NULL;
	int  keylen = 0;
	u_char *sigret = NULL;
	u_int  siglen;

	if (!x509key_check("ssh_x509_sign", key)) return(ret);
	if ((key->rsa == NULL) && (key->dsa == NULL) && (key->ecdsa==NULL)) {
		error("ssh_x509_sign: missing private key");
		return(ret);
	}

	debug3("ssh_x509_sign: key_type=%s, key_ssh_name=%s", key_type(key), key_ssh_name(key));
	ret = 1;

	xkalg = ssh_first_xkalg(key->type, key->ecdsa_nid);
	if (xkalg == NULL) {
		error("ssh_x509_sign: cannot handle type %d[, curve %d]",
			key->type, key->ecdsa_nid);
		ret = -1;
	}

	if (ret > 0) {
		EVP_PKEY *privkey = EVP_PKEY_new();
		if (privkey == NULL) {
			error("ssh_x509_sign: out of memory - EVP_PKEY_new");
			ret = -1;
		}
		else {
			if (key->rsa)
				ret = EVP_PKEY_set1_RSA(privkey, key->rsa);
			else if (key->dsa)
				ret = EVP_PKEY_set1_DSA(privkey, key->dsa);
		#ifdef OPENSSL_HAS_ECC
			else if (key->ecdsa)
				ret = EVP_PKEY_set1_EC_KEY(privkey, key->ecdsa);
		#endif
			else
				ret = -1;

			if (ret <= 0) {
				char ebuf[256];
				openssl_errormsg(ebuf, sizeof(ebuf));
				error("ssh_x509_sign: EVP_PKEY_set1_XXX: failed %.*s",
					(int)sizeof(ebuf), ebuf);
			}
		}

		if (ret > 0) {
			keylen = EVP_PKEY_size(privkey);
			if (keylen > 0) {
				sigret = xmalloc(keylen); /*fatal on error*/
			} else {
				error("ssh_x509_sign: cannot get key size for type %d", key->type);
				ret = -1;
			}
		}
		if (ret > 0) {
			debug3("ssh_x509_sign: alg=%.50s, md=%.30s", xkalg->name, xkalg->dgst.name);
			ret = ssh_x509_EVP_PKEY_sign(privkey, &xkalg->dgst, sigret, &siglen, data, datalen);
		}
		EVP_PKEY_free(privkey);
	}
	if (ret > 0) {
		Buffer b;
		const char *signame;

		buffer_init(&b);
		signame = X509PUBALG_SIGNAME(xkalg);
		debug3("ssh_x509_sign: signame=%.50s", signame);
		buffer_put_cstring(&b, signame);
		buffer_put_string(&b, sigret, siglen);

		{
			u_int  len = buffer_len(&b);
			if (psignaturelen != NULL)
				*psignaturelen = len;

			if (psignature != NULL) {
				*psignature = xmalloc(len); /*fatal on error*/
				memcpy(*psignature, buffer_ptr(&b), len);
			}
		}
		buffer_free(&b);
	}
	if (sigret) {
		memset(sigret, 's', keylen);
		free(sigret);
	}
	ret = ret > 0 ? 0 : -1;
	debug3("ssh_x509_sign: return %d", ret);
	return(ret);
}


int
ssh_x509_verify(
	const Key *key,
	const u_char *signature, u_int signaturelen,
	const u_char *data, u_int datalen
) {
	int ret = -1;
	u_char *sigblob = NULL;
	u_int len = 0;

	if (!x509key_check("ssh_x509_verify", key)) return(ret);

	{ /* get signature data only */
		Buffer b;

		ret = 1;
		buffer_init(&b);
		buffer_append(&b, signature, signaturelen);

		{ /* check signature format */
			char *sigformat = buffer_get_string(&b, NULL);

			debug3("ssh_x509_verify: signature format = %.40s", sigformat);
			if (!ssh_is_x509signame(sigformat)) {
				error("ssh_x509_verify: cannot handle signature format %.40s", sigformat);
				ret = 0;
			}
			free(sigformat);
		}

		if (ret > 0) {
			int rlen;

			sigblob = buffer_get_string(&b, &len);
			rlen = buffer_len(&b);
			if (rlen != 0) {
				error("ssh_x509_verify: remaining bytes in signature %d", rlen);
				ret = -1;
			}
		}
		buffer_free(&b);
	}

	if (ret > 0 ) {
		EVP_PKEY* pubkey;
		const SSHX509KeyAlgs *xkalg;
		int loc;

		pubkey = X509_get_pubkey(key->x509_data->cert);
		if (pubkey == NULL) {
			error("ssh_x509_verify: no 'X509 Public Key'");
			ret = -1;
		}
		if (ret > 0) {
			loc = ssh_xkalg_typeind(key->type, key->ecdsa_nid, &xkalg, -1);
			if (loc < 0) {
				error("ssh_x509_verify: cannot handle type %d", key->type);
				ret = -1;
			}
		}
		if (ret > 0) {
			for (; loc >= 0; loc = ssh_xkalg_typeind(key->type, key->ecdsa_nid, &xkalg, loc)) {
				EVP_MD_CTX *ctx;

				debug3("ssh_x509_verify: md=%.30s, loc=%d", xkalg->dgst.name, loc);

				ctx = EVP_MD_CTX_new();
				if (ctx == NULL) {
					ret = -1;
					error("ssh_x509_verify: out of memory");
					break;
				}

				ret = EVP_VerifyInit(ctx, xkalg->dgst.evp);
				if (ret <= 0) {
					char ebuf[256];
					openssl_errormsg(ebuf, sizeof(ebuf));
					error("ssh_x509_verify: EVP_VerifyInit"
					" fail with errormsg='%.*s'"
					, (int)sizeof(ebuf), ebuf);
				}
				if (ret > 0) {
					ret = EVP_VerifyUpdate(ctx, data, datalen);
					if (ret <= 0) {
						char ebuf[256];
						openssl_errormsg(ebuf, sizeof(ebuf));
						error("ssh_x509_verify: EVP_VerifyUpdate"
						" fail with errormsg='%.*s'"
						, (int)sizeof(ebuf), ebuf);
					}
				}
				if (ret > 0)
					ret = xkalg->dgst.VerifyFinal(ctx, sigblob, len, pubkey);

				EVP_MD_CTX_free(ctx);

				if (ret > 0) break;
			}
			if (ret <= 0) {
				debug3("ssh_x509_verify: failed for all digests");
				ret = 0;
			}
		}
		EVP_PKEY_free(pubkey);
	}
	if (sigblob) {
		memset(sigblob, 's', len);
		free(sigblob);
		sigblob = NULL;
	}
	if (ret > 0) {
		ret = ssh_x509key_verify_cert(key);
	}
	ret = ret > 0 ? 1 : (ret < 0 ? -1 : 0);
	debug3("ssh_x509_verify: return %d", ret);
	return(ret);
}


u_int
ssh_x509_key_size(const Key *key) {
	EVP_PKEY *pkey;
	int k = 0;

	if (!x509key_check("key_size", key)) goto done;

	pkey = X509_get_pubkey(key->x509_data->cert);
	if (pkey == NULL) goto done;

	/* NOTE BN_num_bits returns int! */
	switch(EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA: {
		RSA *rsa;
		const BIGNUM *n;

		rsa = EVP_PKEY_get0_RSA(pkey);
		RSA_get0_key(rsa, &n, NULL, NULL);
		k = BN_num_bits(n);
		} break;
	case EVP_PKEY_DSA: {
		DSA *dsa;
		const BIGNUM *p;

		dsa = EVP_PKEY_get0_DSA(pkey);
		DSA_get0_pqg(dsa, &p, NULL, NULL);
		k = BN_num_bits(p);
		} break;
#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC: {
		int     ecdsa_nid;
		{
			EC_KEY *ecdsa = EVP_PKEY_get0_EC_KEY(pkey);
			ecdsa_nid = key_ecdsa_key_to_nid(ecdsa);
		}
		k = key_curve_nid_to_bits(ecdsa_nid);
		} break;
#endif
	default:
		fatal("ssh_x509_key_size: unknow EVP_PKEY type %d", EVP_PKEY_id(pkey));
		/*unreachable code*/
	}
	EVP_PKEY_free(pkey);
done:
	return((u_int) k);
}


int/*bool*/
ssh_x509_set_cert(Key *key, X509 *x509) {
	int ret = 0;
	SSH_X509 *xd;

	if (key == NULL) {
		fatal("%s: key is NULL", __func__);
		goto done; /*unreachable code*/
	}

{	int k_type = key_type_plain(key->type);
	if (!ssh_x509_support_plain_type(k_type)) {
		fatal("%s: unsupported key type %d", __func__, key->type);
		goto done; /*unreachable code*/
	}
}

	xd = key->x509_data;
	if (xd != NULL) {
		if (xd->cert != NULL) {
			fatal("%s: X.509 certificate is alreasy set", __func__);
			goto done; /*unreachable code*/
		}
	} else
		xd = key->x509_data = SSH_X509_new(); /*fatal on error*/

	/* NOTE caller is responsible to ensure that X.509 certificate
	 * match private key
	 */
	xd->cert = x509;

	TO_X509_KEY_TYPE(key);

	ret = 1;
done:
	return(ret);
}


int
ssh_x509_cmp_cert(const Key *key1, const Key *key2) {
	/* only dns.c call this function so skip checks ...
	if (!x509key_check("cmp_cert", key1)) return(-1);
	if (!x509key_check("cmp_cert", key2)) return(1);
	*/
	return(X509_cmp(key1->x509_data->cert, key2->x509_data->cert));
}


int
Xkey_from_blob(const char *pkalg, const u_char *blob, size_t blen, struct sshkey **keyp) {
	int RFC6187_format;
	struct sshkey *key = NULL;

	if (pkalg == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return sshkey_from_blob(blob, blen, keyp);

	RFC6187_format = p->chain;
}

	key = RFC6187_format
		? x509key_from_blob2(blob, blen)
		: x509key_from_blob(blob, blen);

	/* TODO test for match between pkalg and key */
	if (keyp)
		*keyp = key;

	return SSH_ERR_SUCCESS;
}


Key*
xkey_from_blob(const char *pkalg, const u_char *blob, u_int blen) {
	int RFC6187_format;
	Key* key;

	if (pkalg == NULL) {
		error("%s: pkalg is NULL", __func__);
		return NULL;
	}

	debug3("%s(%s, ..., %d)", __func__, pkalg, blen);

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return key_from_blob(blob, blen);

	RFC6187_format = p->chain;
}

	key = RFC6187_format
		? x509key_from_blob2(blob, blen)
		: x509key_from_blob(blob, blen);

	/* TODO test for match between pkalg and key */
	return key;
}


int
Xkey_to_blob(const char *pkalg, struct sshkey *key, u_char **blobp, size_t *lenp) {
	int RFC6187_format;

	if (pkalg == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (key == NULL) {
		return SSH_ERR_INVALID_ARGUMENT;
	}

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return sshkey_to_blob(key, blobp, lenp);

	RFC6187_format = p->chain;
}

{
	int ret;
	struct sshbuf *b;
	size_t len;

	b = sshbuf_new();
	if (b == NULL)
		return SSH_ERR_ALLOC_FAIL;

	ret = RFC6187_format
		? x509key_to_blob2(key, b)
		: x509key_to_blob(key, b);

	if (!ret)
		return SSH_ERR_INTERNAL_ERROR;

	len = sshbuf_len(b);
	if (lenp != NULL)
		*lenp = len;
	if (blobp != NULL) {
		*blobp = xmalloc(len);
		memcpy(*blobp, sshbuf_ptr(b), len);
	}

	memset(buffer_ptr(b), 0, len);
	sshbuf_free(b);

	return SSH_ERR_SUCCESS;
}
}


int
xkey_to_blob(const char *pkalg, const Key *key, u_char **blobp, u_int *lenp) {
	int RFC6187_format;

	if (pkalg == NULL) {
		error("%s: pkalg is NULL", __func__);
		return 0;
	}
	if (key == NULL) {
		error("%s: key is NULL", __func__);
		return 0;
	}

{	/* check if public algorithm is with X.509 certificates */
	const SSHX509KeyAlgs *p;

	if (ssh_xkalg_nameind(pkalg, &p, -1) < 0)
		return key_to_blob(key, blobp, lenp);

	RFC6187_format = p->chain;
}

{
	Buffer   b;
	int      ret;
	int      len;

	buffer_init(&b);

	ret = RFC6187_format
		? x509key_to_blob2(key, &b)
		: x509key_to_blob(key, &b);

	if (!ret) return 0;

	len = buffer_len(&b);
	if (lenp != NULL)
		*lenp = len;
	if (blobp != NULL) {
		*blobp = xmalloc(len);
		memcpy(*blobp, buffer_ptr(&b), len);
	}
	memset(buffer_ptr(&b), 0, len);

	buffer_free(&b);
	return len;
}
}


int
X509key_to_buf(const struct sshkey *key, struct sshbuf *b) {
	SSH_X509 *xd;
	X509 *x;
	STACK_OF(X509) *chain;

	/*ensure that caller check for non-null X.509 key argument*/

	xd = key->x509_data;
	if (xd == NULL)
		return SSH_ERR_INVALID_FORMAT;

	if (xd->cert == NULL)
		return SSH_ERR_INVALID_FORMAT;

	x = xd->cert;
	buffer_append_x509(b, x);

	chain = key->x509_data->chain;
	if (chain == NULL)
		return SSH_ERR_SUCCESS;

{	/* append certificates from chain */
	int n;

	for (n = 0; n < sk_X509_num(chain); n++) {
		x = sk_X509_value(chain, n);
		buffer_append_x509(b, x);
	}
}

	return SSH_ERR_SUCCESS;
}


int
X509key_from_buf(struct sshbuf *b, struct sshkey **keyp) {
	struct sshkey* key = NULL;
	BIO *mbio;
	X509* x;

{
	const u_char *blob = sshbuf_ptr(b);
	/* ssh buffer is limited to SSHBUF_SIZE_MAX(0x08000000) < int(0x7FFFFFFF) */
	int           blen = sshbuf_len(b);
	mbio = BIO_new_mem_buf((void*)blob, blen);
	if (mbio == NULL)
		return SSH_ERR_ALLOC_FAIL;
}
	x = d2i_X509_bio(mbio, NULL);
	if (x == NULL)
		return SSH_ERR_INVALID_FORMAT;

{	/* rewind buffer */
	size_t l = i2d_X509(x, NULL);
	sshbuf_consume(b, l);
}

	key = x509_to_key(x);
	if (key == NULL) {
		X509_free(x);
		return SSH_ERR_ALLOC_FAIL;
	}

	if (BIO_pending(mbio) > 0) {
		STACK_OF(X509) *chain;

		chain = sk_X509_new_null();
		if (chain == NULL) {
			sshkey_free(key);
			return SSH_ERR_ALLOC_FAIL;
		}

		for (
		    x = d2i_X509_bio(mbio, NULL);
		    x != NULL;
		    x = d2i_X509_bio(mbio, NULL)
		) {
		{	/* rewind buffer */
			size_t l = i2d_X509(x, NULL);
			sshbuf_consume(b, l);
		}
			sk_X509_insert(chain, x, -1 /*last*/);
		}
		key->x509_data->chain = chain;
	}

	if (keyp == NULL)
		sshkey_free(key);
	else
		*keyp = key;
	return SSH_ERR_SUCCESS;
}
