/*
 * Copyright (c) 2005 Darren Tucker <dtucker@zip.com.au>
 * Copyright (c) 2011-2016 Roumen Petrov.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _OPENSSL_COMPAT_H
#define _OPENSSL_COMPAT_H

#include "includes.h"
#ifdef WITH_OPENSSL

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif

int ssh_compatible_openssl(long, long);

#if OPENSSL_VERSION_NUMBER <= 0x00906fffL
# error "OpenSSL 0.9.7 or greater is required"
#endif

#if OPENSSL_VERSION_NUMBER <= 0x00907fffL
/* Workaround for bug in some openssl versions before 0.9.8f
 * We will not use configure check as 0.9.7x define correct
 * macro or some verdors patch their versions.
 */
#undef EVP_CIPHER_CTX_key_length
#define EVP_CIPHER_CTX_key_length ssh_EVP_CIPHER_CTX_key_length

static inline int
ssh_EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx) {
	return ctx->key_len;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10000001L
# define LIBCRYPTO_EVP_INL_TYPE unsigned int
#else
# define LIBCRYPTO_EVP_INL_TYPE size_t
#endif

#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
# define OPENSSL_RSA_MAX_MODULUS_BITS	16384
#endif
#ifndef OPENSSL_DSA_MAX_MODULUS_BITS
# define OPENSSL_DSA_MAX_MODULUS_BITS	10000
#endif

#ifndef OPENSSL_HAVE_EVPCTR
# define EVP_aes_128_ctr evp_aes_128_ctr
# define EVP_aes_192_ctr evp_aes_128_ctr
# define EVP_aes_256_ctr evp_aes_128_ctr
const EVP_CIPHER *evp_aes_128_ctr(void);
void ssh_aes_ctr_iv(EVP_CIPHER_CTX *, int, u_char *, size_t);
#endif

/* Avoid some #ifdef. Code that uses these is unreachable without GCM */
#if !defined(OPENSSL_HAVE_EVPGCM) && !defined(EVP_CTRL_GCM_SET_IV_FIXED)
# define EVP_CTRL_GCM_SET_IV_FIXED -1
# define EVP_CTRL_GCM_IV_GEN -1
# define EVP_CTRL_GCM_SET_TAG -1
# define EVP_CTRL_GCM_GET_TAG -1
#endif

/* Replace missing EVP_CIPHER_CTX_ctrl() with something that returns failure */
#ifndef HAVE_EVP_CIPHER_CTX_CTRL
# ifdef OPENSSL_HAVE_EVPGCM
#  error AES-GCM enabled without EVP_CIPHER_CTX_ctrl /* shouldn't happen */
# else
# define EVP_CIPHER_CTX_ctrl(a,b,c,d) (0)
# endif
#endif

#if defined(HAVE_EVP_RIPEMD160)
# if defined(OPENSSL_NO_RIPEMD) || defined(OPENSSL_NO_RMD160)
#  undef HAVE_EVP_RIPEMD160
# endif
#endif


#ifndef HAVE_BN_IS_NEGATIVE
# ifndef BN_is_negative
    /* before OpenSSL 0.9.8 */
#   define BN_is_negative(a) ((a)->neg != 0)
#endif
#endif

# ifndef HAVE_BN_IS_PRIME_EX
int BN_is_prime_ex(const BIGNUM *, int, BN_CTX *, void *);
# endif

#ifndef HAVE_RSA_GENERATE_KEY_EX
int RSA_generate_key_ex(RSA *, int, BIGNUM *, void *);
#endif

#ifndef HAVE_DSA_GENERATE_PARAMETERS_EX
int DSA_generate_parameters_ex(DSA *, int, const unsigned char *, int, int *,
    unsigned long *, void *);
#endif

extern int  ssh_FIPS_mode(int onoff);

extern void ssh_OpenSSL_startup(void);
extern void ssh_OpenSSL_shuthdown(void);

#endif /* WITH_OPENSSL */
#endif /* _OPENSSL_COMPAT_H */
