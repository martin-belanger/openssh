/*
 * Copyright (c) 2011-2015 Roumen Petrov.  All rights reserved.
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

#ifdef USE_OPENSSL_ENGINE
#include <string.h>
#include <openssl/ui.h>
#include "evp-compat.h"

#include "key-eng.h"
#include "ssh-x509.h"

#include "misc.h"
#include "log.h"
#include "xmalloc.h"
#include "ssherr.h"


/* structure reserved for future use */
typedef struct ssh_pw_cb_data {
	const void *password;
} SSH_PW_CB_DATA;


static UI_METHOD *ssh_ui_method = NULL;

/**/
static int
ui_open(UI *ui) {
	return(UI_method_get_opener(UI_OpenSSL())(ui));
}


static int
ui_read(UI *ui, UI_STRING *uis) {
	enum UI_string_types  uis_type;
	int ui_flags;

	ui_flags = UI_get_input_flags(uis);
	uis_type = UI_get_string_type(uis);

	if (ui_flags & UI_INPUT_FLAG_DEFAULT_PWD) {
		SSH_PW_CB_DATA* cb_data = (SSH_PW_CB_DATA*)UI_get0_user_data(ui);
		if (cb_data != NULL) {
			switch(uis_type) {
			case UIT_PROMPT:
			case UIT_VERIFY: {
				const char *password = cb_data->password;
				if (password && password[0] != '\0') {
					UI_set_result(ui, uis, password);
					return(1);
				}
				} break;
			default:
				break;
			}
		}
	}

{ /* use own method to prompt properly */
	int flags = RP_USE_ASKPASS | RP_ALLOW_STDIN;
	if (ui_flags & UI_INPUT_FLAG_ECHO)
		flags |= RP_ECHO;

	switch(uis_type) {
	case UIT_PROMPT:
	case UIT_VERIFY: {
		const char *prompt;
		char *password;

		prompt = UI_get0_output_string(uis);
		debug3("%s: read_passphrase prompt=%s", __func__, prompt);
		password = read_passphrase(prompt, flags);
		UI_set_result(ui, uis, password);
		memset(password, 'x', strlen(password));
		free(password);
		return(1);
		} break;
	case UIT_INFO: {
		const char *s = UI_get0_output_string(uis);
		verbose("%s: UIT_INFO '%s'", __func__, s);
		return(1);
		} break;
	case UIT_ERROR: {
		const char *s = UI_get0_output_string(uis);
		error("%s: UIT_ERROR '%s'", __func__, s);
		return(1);
		} break;
	default:
		break;
	}
}

	return(UI_method_get_reader(UI_OpenSSL())(ui, uis));
}


static int
ui_write(UI *ui, UI_STRING *uis) {
	enum UI_string_types  uis_type;
	int ui_flags;

	ui_flags = UI_get_input_flags(uis);
	uis_type = UI_get_string_type(uis);

	if (ui_flags & UI_INPUT_FLAG_DEFAULT_PWD) {
		SSH_PW_CB_DATA* cb_data = (SSH_PW_CB_DATA*)UI_get0_user_data(ui);
		if (cb_data != NULL) {
			switch(uis_type) {
			case UIT_PROMPT:
			case UIT_VERIFY: {
				const char *password = cb_data->password;
				if (password && password[0] != '\0') {
					return(1);
				}
				} break;
			default:
				break;
			}
		}
	}
	switch(uis_type) {
	case UIT_INFO: {
		const char *s = UI_get0_output_string(uis);
		verbose("%s: UIT_INFO '%s'", __func__, s);
		return(1);
		} break;
	case UIT_ERROR: {
		const char *s = UI_get0_output_string(uis);
		error("%s: UIT_ERROR '%s'", __func__, s);
		return(1);
		} break;
	default:
		break;
	}
	return(UI_method_get_writer(UI_OpenSSL())(ui, uis));
}


static int
ui_close(UI *ui) {
	return(UI_method_get_closer(UI_OpenSSL())(ui));
}


static int/*bool*/setup_ssh_ui_method(void);
static void destroy_ssh_ui_method(void);


static int/*bool*/
setup_ssh_ui_method() {
	ssh_ui_method = UI_create_method("PKIX-SSH application user interface");

	if (ssh_ui_method == NULL) return(0);

	if ((UI_method_set_opener(ssh_ui_method, ui_open ) < 0)
	||  (UI_method_set_reader(ssh_ui_method, ui_read ) < 0)
	||  (UI_method_set_writer(ssh_ui_method, ui_write) < 0)
	||  (UI_method_set_closer(ssh_ui_method, ui_close) < 0)) {
		destroy_ssh_ui_method();
		return(0);
	}
	return(1);
}


static void
destroy_ssh_ui_method() {
	if (ssh_ui_method == NULL) return;

	UI_destroy_method(ssh_ui_method);
	ssh_ui_method = NULL;
}


static void
eng_try_load_cert(ENGINE *e, const char *keyid, EVP_PKEY *pk, Key *k) {
	X509*	x509 = NULL;
	int ctrl_ret = 0;

	if (e == NULL)
		return;

	if ((k->type != KEY_RSA) &&
#ifdef OPENSSL_HAS_ECC
	    (k->type != KEY_ECDSA) &&
#endif
	    (k->type != KEY_DSA))
		return;

	/* try to load certificate with LOAD_CERT_EVP command */
	{
		struct {
			EVP_PKEY *pkey;
			X509 *x509;
		} param = {NULL, NULL};
		param.pkey = pk;

		ctrl_ret = ENGINE_ctrl_cmd(e, "LOAD_CERT_EVP", 0, &param, 0, 0);
		debug3("%s: eng cmd LOAD_CERT_EVP return %d", __func__, ctrl_ret);
		if (ctrl_ret == 1)
			x509 = param.x509;
	}

	/* try to load certificate with LOAD_CERT_CTRL command */
	if (ctrl_ret != 1) {
		struct {
			const char *keyid;
			X509 *x509;
		} param = {NULL, NULL};
		param.keyid = keyid;

		ctrl_ret = ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &param, 0, 0);
		debug3("%s: eng cmd LOAD_CERT_CTRL return %d", __func__, ctrl_ret);
		if (ctrl_ret == 1)
			x509 = param.x509;
	}
	debug3("%s: eng certificate=%p", __func__, (void*)x509);

	if (x509 == NULL)
		return;

	if (!ssh_x509_set_cert(k, x509)) {
		error("%s: can not set X.509 certificate to key ", __func__);
	}

	x509key_build_chain(k);
}


static ENGINE*
split_eng_keyid(const char *keyid, char **engkeyid) {
	ENGINE* e = NULL;
	char *p, *q;

	q = xstrdup(keyid);	/*fatal on error*/

	p = strchr(q, ':');
	if (p == NULL) {
		fatal("%s missing engine identifier", __func__);
		goto done; /*;-)*/
	}
	*p = '\0';
	p++;
	if (*p == '\0') {
		fatal("%s missing key identifier", __func__);
		goto done; /*;-)*/
	}

	e = ENGINE_by_id(q);
	if (e != NULL) {
		*engkeyid = xstrdup(p);
	}
done:
	free(q);
	return(e);
}


int
eng_key_load_private_type(int type, const char *keyid,
	const char *passphrase, struct sshkey **keyp, char **commentp
) {
	char *engkeyid;
	const char *name = "<no key>";
	ENGINE *e = NULL;
	EVP_PKEY *pk = NULL;
	Key *prv = NULL;

	e = split_eng_keyid(keyid, &engkeyid);
	if (e == NULL)
		goto done;

	(void)passphrase;
	pk = ENGINE_load_private_key(e, engkeyid, ssh_ui_method, NULL);
	if (pk == NULL) {
		char ebuf[512];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: ENGINE_load_private_key(%s) fail with errormsg='%.*s'"
		, __func__, ENGINE_get_id(e)
		, (int)sizeof(ebuf), ebuf);
		goto done;
	}

	/* NOTE do not set flags |= KEY_FLAG_EXT !!! */

	if (EVP_PKEY_id(pk) == EVP_PKEY_RSA
	&&  (type == KEY_UNSPEC || type == KEY_RSA)) {
		prv = key_new(KEY_UNSPEC);
		prv->rsa = EVP_PKEY_get1_RSA(pk);
		prv->type = KEY_RSA;
		name = "rsa(nss)";
#ifdef DEBUG_PK
		RSA_print_fp(stderr, prv->rsa, 8);
#endif
		if (RSA_blinding_on(prv->rsa, NULL) != 1) {
			error("%s: RSA_blinding_on failed", __func__);
			key_free(prv);
			prv = NULL;
		}
	} else if (EVP_PKEY_id(pk) == EVP_PKEY_DSA
	&&  (type == KEY_UNSPEC || type == KEY_DSA)) {
		prv = key_new(KEY_UNSPEC);
		prv->dsa = EVP_PKEY_get1_DSA(pk);
		prv->type = KEY_DSA;
		name = "dsa(nss)";
#ifdef DEBUG_PK
		DSA_print_fp(stderr, prv->dsa, 8);
#endif
#ifdef OPENSSL_HAS_ECC
	} else if (EVP_PKEY_id(pk) == EVP_PKEY_EC
	&&  (type == KEY_UNSPEC || type == KEY_ECDSA)) {
		const EC_POINT *q = NULL;
		int ec_err = 0;

		prv = key_new(KEY_UNSPEC);
		prv->type = KEY_ECDSA;
		prv->ecdsa = EVP_PKEY_get1_EC_KEY(pk);
		prv->ecdsa_nid = key_ecdsa_key_to_nid(prv->ecdsa);
		if (prv->ecdsa_nid < 0) {
			error("%s: unsupported elliptic curve", __func__);
			ec_err = 1;
		}
		q = EC_KEY_get0_public_key(prv->ecdsa);
		if (!ec_err &&
		    (q == NULL)
		) {
			error("%s: cannot get public ec key ", __func__);
			ec_err = 1;
		}
		if (!ec_err &&
		   (key_ec_validate_public(EC_KEY_get0_group(prv->ecdsa), q) < 0)
		) {
			debug3("%s: cannot validate public ec key ", __func__);
			ec_err = 1;
		}
		name = "ecdsa(nss)";
#ifdef DEBUG_PK
		key_dump_ec_point(EC_KEY_get0_group(key->ecdsa), q);
#endif
		if (ec_err) {
			key_free(prv);
			prv = NULL;
		}
#endif /*def OPENSSL_HAS_ECC*/
	} else {
		error("%s: mismatch or "
		    "unknown EVP_PKEY type %d", __func__, EVP_PKEY_id(pk));
	}

	if ((pk != NULL) && (prv != NULL))
		eng_try_load_cert(e, engkeyid, pk, prv);

	if (pk != NULL)
		EVP_PKEY_free(pk);

	if (prv != NULL) {
		if (keyp!= NULL)
			*keyp = prv;
		if (commentp!= NULL)
			*commentp = xstrdup(name);
	}

done:
	free(engkeyid);
	if (e != NULL)
		ENGINE_free(e);
	debug("read ENGINE private key done: type %s", (prv ? key_type(prv) : "<not found>"));
	return prv
		? SSH_ERR_SUCCESS
		: SSH_ERR_LIBCRYPTO_ERROR;
}


int
eng_key_try_load_public(struct sshkey *k, const char *filename, char **commentp) {
	int ret = SSH_ERR_INTERNAL_ERROR;
	char *keyid = NULL;
	char *engkeyid;
	ENGINE *e = NULL;
	EVP_PKEY *pk = NULL;

	if (k->type != KEY_UNSPEC)
		return SSH_ERR_INVALID_ARGUMENT;

	debug3("%s filename=%s", __func__, filename);
{ /* magic to ignore suffixes in file name*/
	size_t len = strlen(filename);
	if (len <= 4)
		goto done;

	{ /* skip bogus certificates "-cert" */
		const char sfx[5] = "-cert";
		if (len >= sizeof(sfx)) {
			const char *s = filename + len - sizeof(sfx);
			if (strncmp(s, sfx, sizeof(sfx)) == 0)
				return SSH_ERR_INVALID_FORMAT;
		}
	}
	{ /* skip bogus certificates "-cert.pub" */
		const char sfx[9] = "-cert.pub";
		if (len >= sizeof(sfx)) {
			const char *s = filename + len - sizeof(sfx);
			if (strncmp(s, sfx, sizeof(sfx)) == 0)
				return SSH_ERR_INVALID_FORMAT;
		}
	}

	keyid = xstrdup(filename); /*fatal on error*/
	{ /* drop suffix ".pub" on copy */
		char *s = keyid + len - 4;
		if (strncmp(s, ".pub", 4) == 0)
			*s = '\0';
	}
}
	debug3("%s keyid=%s", __func__, keyid);

	e = split_eng_keyid(keyid, &engkeyid);
	if (e == NULL)
		goto done;

	pk = ENGINE_load_public_key(e, engkeyid, ssh_ui_method, NULL);
	if (pk == NULL) {
		char ebuf[512];
		/* fatal here to avoid PIN lock, for instance
		 * when ssh-askpass program is missing.
		 * NOTE programs still try to load public key many times!
		 */
		openssl_errormsg(ebuf, sizeof(ebuf));
		fatal("%s: ENGINE_load_public_key(%s) fail with errormsg='%.*s'"
		, __func__, ENGINE_get_id(e)
		, (int)sizeof(ebuf), ebuf);
		/* TODO library mode in case of failure */
		ret = SSH_ERR_INTERNAL_ERROR;
		goto done;
	}

	/* NOTE do not set flags |= KEY_FLAG_EXT !!! */
	if (EVP_PKEY_id(pk) == EVP_PKEY_RSA) {
		k->rsa = EVP_PKEY_get1_RSA(pk);
		k->type = KEY_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, k->rsa, 8);
#endif
		if (RSA_blinding_on(k->rsa, NULL) == 1) {
			ret = SSH_ERR_SUCCESS;
		}
		else {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			error("%s: RSA_blinding_on failed", __func__);
		}
	} else if (EVP_PKEY_id(pk) == EVP_PKEY_DSA) {
		k->dsa = EVP_PKEY_get1_DSA(pk);
		k->type = KEY_DSA;
#ifdef DEBUG_PK
		DSA_print_fp(stderr, k->dsa, 8);
#endif
		ret = SSH_ERR_SUCCESS;
#ifdef OPENSSL_HAS_ECC
	} else if (EVP_PKEY_id(pk) == EVP_PKEY_EC) {
		const EC_POINT *q = NULL;

		ret = SSH_ERR_SUCCESS;

		k->ecdsa = EVP_PKEY_get1_EC_KEY(pk);
		k->type = KEY_ECDSA;
		k->ecdsa_nid = key_ecdsa_key_to_nid(k->ecdsa);

		if (k->ecdsa_nid < 0) {
			error("%s: unsupported elliptic curve", __func__);
			ret = SSH_ERR_INVALID_FORMAT;
		}
		q = EC_KEY_get0_public_key(k->ecdsa);
		if ((ret == SSH_ERR_SUCCESS) &&
		    (q == NULL)
		) {
			error("%s: cannot get public ec key ", __func__);
			ret = SSH_ERR_LIBCRYPTO_ERROR;
		}
		if ((ret == SSH_ERR_SUCCESS) &&
		    (key_ec_validate_public(EC_KEY_get0_group(k->ecdsa), q) < 0)
		) {
			debug3("%s: cannot validate public ec key ", __func__);
			ret = SSH_ERR_KEY_INVALID_EC_VALUE;
		}
#ifdef DEBUG_PK
		key_dump_ec_point(EC_KEY_get0_group(k->ecdsa), q);
#endif
#endif /*def OPENSSL_HAS_ECC*/
	} else {
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
		error("%s: mismatch or "
		    "unknown EVP_PKEY type %d", __func__, EVP_PKEY_id(pk));
	}

	if (ret == SSH_ERR_SUCCESS) {
		if (pk != NULL)
			eng_try_load_cert(e, engkeyid, pk, k);

		debug3("ENGINE key type: %s", key_type(k));

		if (commentp != NULL)
			*commentp = xstrdup(engkeyid);
	}

	if (pk != NULL)
		EVP_PKEY_free(pk);

done:
	free(engkeyid);
	free(keyid);
	if (e != NULL)
		ENGINE_free(e);
	return(ret);
}


static ENGINE*
try_load_engine(const char *engine) {
	ENGINE *e = NULL;
	int self_registered = 0;

	if (engine == NULL) {
		fatal("%s: engine is NULL", __func__);
		return(NULL); /* ;-) */
	}

	/* Check if engine is not already loaded by openssl
	 * (as internal or from config file).
	 * If is not loaded we will call ENGINE_add to keep it
	 * loaded and registered for subsequent use.
	 */
	for (e = ENGINE_get_first(); e != NULL; e = ENGINE_get_next(e)) {
		if (strcmp(engine, ENGINE_get_id(e)) == 0) {
			/* with increase of structural reference */
			goto done;
		}
	}

	e = ENGINE_by_id(engine);
	if (e == NULL) {
		char ebuf[512];
		openssl_errormsg(ebuf, sizeof(ebuf));
		fatal("%s(%s): setup fail with last error '%.*s'"
		    , __func__, engine
		    , (int)sizeof(ebuf), ebuf);
		return(NULL); /* ;-) */
	}

{	/* OpenSSL 1.0.1g start to register engines internaly!
	 * So we try to find our engine in internal list and if not
	 * found we use ENGINE_add to register it for compatibility
	 * with previous OpenSSL versions.
	 * Loop on all entries to avoid increase of structural
	 * reference.
	 */
	ENGINE *g;
	for (g = ENGINE_get_first(); g != NULL; g = ENGINE_get_next(g)) {
		if (strcmp(engine, ENGINE_get_id(g)) == 0)
			self_registered = 1;
	}
}

	if (!self_registered && !ENGINE_add(e)) {
		char ebuf[512];
		openssl_errormsg(ebuf, sizeof(ebuf));
		fatal("%s(%s): registration fail with last error '%.*s'"
		    , __func__, engine
		    , (int)sizeof(ebuf), ebuf);
		return(NULL); /* ;-) */
	}

done:
	debug3("%s: engine '%s' loaded", __func__, ENGINE_get_name(e));
	return(e);
}


static ENGINE*
ssh_engine_setup(const char *engine) {
	int ctrl_ret;
	ENGINE *e = NULL;

	e = try_load_engine(engine); /* fatal on error */

	if (!ENGINE_init(e)) {
		char ebuf[512];
		openssl_errormsg(ebuf, sizeof(ebuf));
		fatal("%s(%s): ENGINE_init fail with last error '%.*s'"
		    , __func__, engine
		    , (int)sizeof(ebuf), ebuf);
		return(NULL); /* ;-) */
	}

	ctrl_ret = ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ssh_ui_method, 0, 1);
	if (!ctrl_ret) {
		char ebuf[512];
		openssl_errormsg(ebuf, sizeof(ebuf));
		debug3("%s(%s): unsupported engine command SET_USER_INTERFACE: %.*s"
		    , __func__, engine
		    , (int)sizeof(ebuf), ebuf);
	}

	if (!ENGINE_free(e)) {
		e = NULL;
	}

	return(e);
}


static void
ssh_engine_reset(const char *engine) {
	ENGINE *e = NULL;

	e = ENGINE_by_id(engine);
	if (e == NULL) return;

	/* decrease functional&structural reference from load - ENGINE_init */
	ENGINE_finish(e);

	/* decrease structural reference from above - ENGINE_by_id */
	ENGINE_free(e);
}


#define WHITESPACE " \t\r\n"
/* hold list with names of used engines to free at shutdown */
static Buffer	eng_list;

/* name of currect engine to process */
static char *eng_name = NULL;


int/*bool*/
process_engconfig_line(char *line, const char *filename, int linenum) {
	int ret = 1;
	size_t len;
	char *s, *keyword, *arg;
	ENGINE *e;
	int ctrl_ret;

	/* strip trailing whitespace */
	len = strlen(line);
	s = line + len - 1;
	for (; len > 0; s--, len--) {
		int ch = (unsigned char)*s;
		if (strchr(WHITESPACE, ch) == NULL)
			break;
		*s = '\0';
	}

	/* ignore leading whitespace */
	s = line;
	if (*s == '\0')
		return(1);
	keyword = strdelim(&s);
	if (keyword == NULL)
		return(1);
	if (*keyword == '\0')
		keyword = strdelim(&s);
	if (keyword == NULL)
		return(1);

	/* ignore comments */
	if (*keyword == '#')
		return(1);

	if (strcasecmp(keyword, "engine") == 0) {
		arg = strdelim(&s);
		if (!arg || *arg == '\0') {
			fatal("%.200s line %d: missing engine identifier"
			    , filename, linenum);
			goto done;
		}

		e = ssh_engine_setup(arg);
		if (e == NULL) {
			char ebuf[512];
			openssl_errormsg(ebuf, sizeof(ebuf));
			fatal("%.200s line %d: cannot load engine '%s':%.*s"
			    , filename, linenum, arg
			    , (int)sizeof(ebuf), ebuf);
		}
		if (eng_name != NULL)
			free(eng_name);
		eng_name = xstrdup(arg); /*fatal on error*/
		buffer_put_cstring(&eng_list, eng_name);
	}
	else {
		if (eng_name == NULL)
			fatal("%.200s line %d: engine is not specified"
			    , filename, linenum);

		e = ENGINE_by_id(eng_name);
		if (e == NULL)
			fatal("%.200s line %d: engine(%s) not found"
			    , filename, linenum, eng_name);

		arg = strdelim(&s);

		ctrl_ret = ENGINE_ctrl_cmd_string(e, keyword, arg, 0);
		if (!ctrl_ret) {
			char ebuf[512];
			openssl_errormsg(ebuf, sizeof(ebuf));
			fatal("%.200s line %d: engine command fail"
			    " with errormsg='%.*s'"
			    , filename, linenum
			    , (int)sizeof(ebuf), ebuf);
			ret = 0;
		}

		ENGINE_free(e);
	}

done:
	/* check that there is no garbage at end of line */
	if ((arg = strdelim(&s)) != NULL && *arg != '\0') {
		fatal("%.200s line %d: garbage at end of line - '%.200s'.",
		    filename, linenum, arg);
	}

	return(ret);
}
#endif /*def USE_OPENSSL_ENGINE*/


void
ssh_engines_startup() {
#ifdef USE_OPENSSL_ENGINE
	buffer_init(&eng_list);

	(void) setup_ssh_ui_method();
#endif
}


void
ssh_engines_shutdown() {
#ifdef USE_OPENSSL_ENGINE
	free(eng_name);
	eng_name = NULL;

	while (buffer_len(&eng_list) > 0) {
		u_int   k = 0;
		char    *s;

		s = buffer_get_cstring_ret(&eng_list, &k);
		ssh_engine_reset(s);
		free(s);
	};
	buffer_free(&eng_list);

	destroy_ssh_ui_method();
#endif
}
