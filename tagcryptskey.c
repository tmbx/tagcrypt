/**
 * tagcrypt/tagcryptskey.c
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt secret key management function.
 *
 * @author Kristian Benoit
 */

#include <gcrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <kmem.h>
#include <kbuffer.h>

#include "tagcrypt.h"
#include "tagcryptskey.h"
#include "tagcryptversion.h"
#include "tagcryptlog.h"

#define TAGCRYPT_SKEY_MAJOR 1
#define TAGCRYPT_SKEY_MINOR 1

int tagcrypt_skey_serialize (tagcrypt_skey *self, kbuffer *buffer) {
    size_t size = gcry_sexp_sprint (self->key, GCRYSEXP_FMT_ADVANCED, NULL, 0);

    kbuffer_grow(buffer, 4 * sizeof(uint32_t) + sizeof(int64_t) + size);
    kbuffer_write32(buffer, TAGCRYPT_SKEY_MAGIC_NUM);
    kbuffer_write32(buffer, TAGCRYPT_SKEY_MAJOR);
    kbuffer_write32(buffer, TAGCRYPT_SKEY_MINOR);
    kbuffer_write64(buffer, (uint64_t) self->keyid);

    kbuffer_write32(buffer, (uint32_t) size);

    gcry_sexp_sprint (self->key,
                      GCRYSEXP_FMT_ADVANCED,
                      buffer->data + buffer->len,
                      size);

    buffer->len += size;

    return 0;
}

int tagcrypt_skey_init(tagcrypt_skey *self, kbuffer *serialized_skey) {
    gcry_error_t err;
    int retval = 0;
    uint32_t u32;
    uint32_t major;

    if (kbuffer_read32(serialized_skey, &u32))
        return -1;
    if (u32 != TAGCRYPT_SKEY_MAGIC_NUM)
        return -1;

    if (kbuffer_read32(serialized_skey, &major))
        return -1;
    if (kbuffer_read32(serialized_skey, &u32))
        return -1;
    if (kbuffer_read64(serialized_skey, &self->keyid))
        return -1;
    if (kbuffer_read32(serialized_skey, &u32))
        return -1;

    switch (major) {
        case 1:
            err = gcry_sexp_new (&self->key, serialized_skey->data + serialized_skey->pos, u32, 1);
            if (err) {
                printf (gcry_strerror (err));
                //FIXME: LOG
                retval = -1;
            }
            break;
        default:
            retval = -1;
    }
    return retval;
}

tagcrypt_skey *tagcrypt_skey_new (kbuffer *serialized_skey) {
    tagcrypt_skey *self = (tagcrypt_skey *)kmalloc(sizeof(tagcrypt_skey));

    if (tagcrypt_skey_init(self, serialized_skey)) {
        kfree(self);
        self = NULL;
    }
    return self;
}

void tagcrypt_skey_clean(tagcrypt_skey *self) {
    if (self) 
        gcry_sexp_release(self->key);
}

void tagcrypt_skey_destroy(tagcrypt_skey *self) {
    tagcrypt_skey_clean (self);
    kfree(self);
}

int tagcrypt_skey_do_decrypt (tagcrypt_skey *self, kbuffer *in, kbuffer *out) {
    size_t size;
    uint32_t len;
    uint8_t c;
    gcry_mpi_t mpi = NULL;
    gcry_sexp_t clear = NULL;
    gcry_sexp_t encrypted = NULL;
    gcry_error_t err;
    kbuffer *tmp_buf = kbuffer_new (64);

    if ((err = kbuffer_read32(in, &len))) {
        goto ERR;
    }

    if (len > in->len - in->pos) {
        TC_ERROR("invalid buffer received");
        goto ERR;
    }

    err = gcry_mpi_scan(&mpi, GCRYMPI_FMT_STD, in->data + in->pos, len, &size);

    if (err) {
        GCRY_ERROR(gcry_strerror (err));
        goto ERR;
    }

    in->pos += size;

    err = gcry_sexp_build (&encrypted, NULL, "(7:enc-val(5:flags)(3:rsa(1:a%m)))", mpi);

    if (err) {
        GCRY_ERROR (gcry_strerror (err));
        goto ERR;
    }

    gcry_mpi_release(mpi);

    err = gcry_pk_decrypt(&clear, encrypted, self->key);
    if (err) {
        GCRY_ERROR (gcry_strerror (err));
        goto ERR;
    }

    /******* TODO: RSA SPECIFIC ********/
        mpi = gcry_sexp_nth_mpi (clear, 1, GCRYMPI_FMT_USG);
        if (!mpi) {
            GCRY_ERROR ("Could not parse mpi");
            goto ERR;
        }

        len = (gcry_mpi_get_nbits (mpi) + 7) / 8;
        kbuffer_grow(tmp_buf, len);
        err = gcry_mpi_print (GCRYMPI_FMT_USG, (uint8_t *)(tmp_buf->data + tmp_buf->len), (size_t)len, &size, mpi);
        if (err) {
            GCRY_ERROR (gcry_strerror (err));
            goto ERR;
        }
        tmp_buf->len += size;
        
        if (kbuffer_read8(tmp_buf, &c))
            goto ERR;
        if (c != 0x02) {
            TC_ERROR ("Invalid decryption");
            goto ERR;
        }

        while (!kbuffer_eof(tmp_buf)) {
            if (kbuffer_read8(tmp_buf, &c))
                goto ERR;

            if (c == '\0')
                break;
        }

        kbuffer_write (out, tmp_buf->data + tmp_buf->pos, tmp_buf->len - tmp_buf->pos);

    /******* TODO: END RSA SPECIFIC *****/
    gcry_sexp_release (encrypted);
    gcry_sexp_release (clear);
    gcry_mpi_release (mpi);
    kbuffer_destroy (tmp_buf);
    return 0;
ERR:
    if (encrypted) gcry_sexp_release (encrypted);
    if (clear) gcry_sexp_release (clear);
    if (mpi) gcry_mpi_release (mpi);
    if (tmp_buf) kbuffer_destroy (tmp_buf);

    return -1;
}

static int tagcrypt_skey_parse(kbuffer *in, kbuffer *enc_symkey, kbuffer *enc_data) {
    uint32_t size;

    /* symmetric key */
    if (kbuffer_read32(in, &size))
        goto SIZE_ERR;

    kbuffer_grow(enc_symkey, size);

    kbuffer_read_buffer(in, enc_symkey, size);

    /* data */
    if (kbuffer_left (in) < (int)sizeof(uint32_t))
        goto SIZE_ERR;
    if (kbuffer_read32(in, &size))
        goto SIZE_ERR;

    kbuffer_grow(enc_data, size);

    if (kbuffer_read_buffer(in, enc_data, size))
        goto SIZE_ERR;

    return 0;

SIZE_ERR:
    TC_ERROR ("buffer to short to decrypt");
    return -1;
}

int tagcrypt_skey_decrypt (tagcrypt_skey *self, kbuffer *in, kbuffer *out) {
    kbuffer *enc_symkey = kbuffer_new (32);
    kbuffer *serialized_symkey = kbuffer_new (32);
    kbuffer *enc_data = kbuffer_new (32);
    tagcrypt_symkey *symkey = NULL;

    if (tagcrypt_skey_parse (in, enc_symkey, enc_data)) goto ERR;

    if (tagcrypt_skey_do_decrypt (self, enc_symkey, serialized_symkey)) goto ERR;
    symkey = tagcrypt_symkey_new_serialized (serialized_symkey);
    if (!symkey) goto ERR;

    tagcrypt_symkey_decrypt (symkey, enc_data, out);

    kbuffer_destroy (enc_symkey);
    kbuffer_destroy (serialized_symkey);
    kbuffer_destroy (enc_data);
    tagcrypt_symkey_destroy (symkey);
    
    return 0;
ERR:
    kbuffer_destroy (enc_symkey);
    kbuffer_destroy (serialized_symkey);
    kbuffer_destroy (enc_data);
    tagcrypt_symkey_destroy (symkey);
    
    return -1;
}

static int tagcrypt_pkey_sign_rsa(tagcrypt_skey *self, gcry_sexp_t sig, kbuffer *buffer) {
    unsigned char  *signature   = NULL;
    gcry_sexp_t     tmp_sexp    = NULL;
    gcry_mpi_t      mpi         = NULL;
    size_t          nbytes;
    self = self;

    tmp_sexp =  gcry_sexp_find_token (sig, "s", 1);

    mpi = gcry_sexp_nth_mpi (tmp_sexp, 1, GCRYMPI_FMT_USG);

    gcry_mpi_aprint(GCRYMPI_FMT_PGP, &signature, &nbytes, mpi);

    kbuffer_write32(buffer, (uint32_t)nbytes);

    kbuffer_write(buffer, signature, (uint32_t)nbytes);

    gcry_free (signature);
    gcry_mpi_release (mpi);
    gcry_sexp_release (tmp_sexp);
    return 0;
}

#define MAX_HASH_NAME_LEN 32

int tagcrypt_skey_sign(tagcrypt_skey *self, uint32_t hash_algo, kbuffer *data, kbuffer *signature) {
    gcry_error_t err = 0;
    gcry_sexp_t hash_sexp = NULL;
    gcry_sexp_t sig = NULL;
    size_t hash_len = gcry_md_get_algo_dlen(hash_algo);
    uint8_t *digest;
    char hash_name[MAX_HASH_NAME_LEN];
    const char *algo_name = NULL;
    
    algo_name = gcry_md_algo_name(hash_algo);
    strncpy(hash_name, algo_name, MAX_HASH_NAME_LEN);
    strntolower(hash_name, MAX_HASH_NAME_LEN);

    digest = kmalloc(hash_len);
    if (!digest) goto ERR;

    gcry_md_hash_buffer(hash_algo, digest, data->data + data->pos, data->len - data->pos);
    err = gcry_sexp_build(&hash_sexp,
                          NULL,
                          "(4:data(5:flags5:pkcs1)(4:hash%s%b))",
                          hash_name,
                          hash_len,
                          digest);
    if (err) goto ERR;
    //FIXME : Do something with the err.
    err = gcry_pk_sign (&sig, hash_sexp, self->key);
    if (err) goto ERR;
    //FIXME : Do something with the err.
    tagcrypt_pkey_sign_rsa (self, sig, signature);

ERR:
    kfree(digest);
    gcry_sexp_release (hash_sexp);
    gcry_sexp_release (sig);

    return err ? -1 : 0;
}
