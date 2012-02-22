/**
 * tagcrypt/tagcryptgen.c
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * Tagcrypt generative functions.
 *
 * @author Kristian Benoit
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <base64.h>
#include <kbuffer.h>

#include "tagcrypt.h"
#include "tagcryptpkey.h"
#include "tagcryptskey.h"
#include "tagcryptsignature.h"
#include "tagcryptlog.h"

static int tagcrypt_key_gen (gcry_sexp_t *key_pair, int size)
{
    gcry_sexp_t param;
    gcry_error_t err;

    err = gcry_sexp_build (&param, NULL, "(6:genkey(3:rsa(5:nbits%d)))", size);
    if (err) {
        GCRY_CRITICAL (gcry_strerror (err));
        goto ERR;
    }

    err = gcry_pk_genkey (key_pair, param);
    if (err) {
        GCRY_CRITICAL (gcry_strerror (err));
        goto ERR;
    }

    gcry_sexp_release(param);

    return 0;

ERR:
    if (param) gcry_sexp_release (param);
    return -1;
}


int tagcrypt_gen_public_secret(kbuffer *pkey, kbuffer *skey, uint64_t keyid, int size) {
    tagcrypt_pkey pkey_st = { .keyid = keyid };
    tagcrypt_skey skey_st = { .keyid = keyid };
    kbuffer *tmp = kbuffer_new(128);
    gcry_sexp_t key_pair;
    int err;

    err = tagcrypt_key_gen (&key_pair, size);
    if (err)
        return err;

    skey_st.key = gcry_sexp_find_token (key_pair, "private-key", 11);
    tagcrypt_skey_serialize (&skey_st, tmp);
    kbin2b64(tmp, skey);

    kbuffer_reset (tmp);

    pkey_st.key = gcry_sexp_find_token (key_pair, "public-key", 10);
    tagcrypt_pkey_serialize (&pkey_st, tmp);
    kbin2b64 (tmp, pkey);

    kbuffer_destroy (tmp);
    tagcrypt_skey_clean (&skey_st);
    tagcrypt_pkey_clean (&pkey_st);

    return 0;
}
