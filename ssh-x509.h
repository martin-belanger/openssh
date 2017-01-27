#ifndef SSH_X509_H
#define SSH_X509_H
/*
 * Copyright (c) 2002-2005,2012 Roumen Petrov.  All rights reserved.
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

#include "includes.h"
#include "key.h"
#include "buffer.h"


#ifndef SSH_X509STORE_DISABLED
/*
 * Method return a key(x509) only with "Subject"("Distinguished Name") !
 */
Key*	X509key_from_subject(const char *pkalg, const char *cp, char **ep);
#endif /*ndef SSH_X509STORE_DISABLED*/


/* draft-ietf-secsh-transport-12.txt */
Key*	x509key_from_blob(const u_char *blob, int blen);

int	X509key_encode_identity(const struct sshkey *key, struct sshbuf *b);
int	X509key_decode_identity(const char *pkalg, struct sshbuf *b, struct sshkey *k);

void	x509key_move_identity(Key *from, Key *to);
void	x509key_copy_identity(const Key *from, Key *to);
void	x509key_demote(const Key *k, Key *pk);

char*	x509key_subject(const Key *key);

/*
 * Method write base 64 encoded X.509 identity of key.
 */
int	x509key_write(const Key *key, FILE *f);
#ifndef SSH_X509STORE_DISABLED
/*
 * Method write subject of key X.509 certificate.
 */
int	x509key_write_subject(const Key *key, FILE *f);
int	x509key_write_subject2(const Key *key, const char *keyname, FILE *f);
#endif /*ndef SSH_X509STORE_DISABLED*/

/*
 * The patched configure script define OPENSSH_KEYS_USE_BIO
 * depending from OpenSSH version
 */

void	x509key_parse_cert(Key *key, EVP_PKEY *pk, BIO *bio);
void	x509key_load_certs(const char *pkalg, Key *key, const char *filename);
void	x509key_build_chain(Key *key);

int/*bool*/	x509key_write_identity_bio_pem(BIO *bio, const Key *key);
#ifndef OPENSSH_KEYS_USE_BIO
int/*bool*/	x509key_save_identity_pem(FILE *fp, const Key *key);
#endif

#ifndef SSH_X509STORE_DISABLED
int	ssh_x509_equal(const Key *a, const Key *b);
#endif /*ndef SSH_X509STORE_DISABLED*/

int		ssh_x509key_type(const char *name);
const char*	ssh_x509key_name(const Key *k);
int		ssh_x509key_verify_cert(const Key *k);

int	ssh_x509_sign(const Key *key, u_char **psignature, size_t *psignaturelen, const u_char *data, u_int datalen);
int	ssh_x509_verify(const Key *key, const u_char *signature, u_int signaturelen, const u_char *data, u_int datalen);
u_int	ssh_x509_key_size(const Key *key);

int/*bool*/	ssh_x509_set_cert(Key *key, X509 *x509);
int		ssh_x509_cmp_cert(const Key *key1, const Key *key2);


/* extended key format support */
int	Xkey_from_blob(const char *pkalg, const u_char *blob, size_t blen, struct sshkey **keyp);
Key	*xkey_from_blob(const char *pkalg, const u_char *blob, u_int blen);

int	Xkey_to_blob(const char *pkalg, struct sshkey *key, u_char **blobp, size_t *lenp);
int	xkey_to_blob(const char *pkalg, const Key *key, u_char **blobp, u_int *lenp);

int	X509key_to_buf(const struct sshkey *key, struct sshbuf *b);
int	X509key_from_buf(struct sshbuf *b, struct sshkey **keyp);


/* backward compatibility */
int	 key_is_x509(const Key *);
#define KEY_FLAG_EXT	SSHKEY_FLAG_EXT

#endif /* SSH_X509_H */
