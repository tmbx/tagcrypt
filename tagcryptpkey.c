/**
 * tagcrypt/include/tagcryptpkey.c
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt public key management functions.
 *
 * @author Kristian Benoit
 */

#include <gcrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <kmem.h>
#include <kbuffer.h>

#include "tagcrypt.h"
#include "tagcryptpkey.h"
#include "tagcryptskey.h"
#include "tagcryptversion.h"
#include "tagcryptlog.h"

enum PKEY_TYPE {
    PKEY_TYPE_PUB = (0 << 7),
    PKEY_TYPE_PRIV = (1 << 7)
};

enum PKEY_ALGO {
    PKEY_ALGO_RSA = 1,
    PKEY_ALGO_DSA = 2
};

int tagcrypt_pkey_wire_serialize(tagcrypt_pkey *self, kbuffer *buffer) {
    gcry_error_t err = 0;
    size_t n_size;
    size_t e_size;
    gcry_sexp_t n_sexp;
    gcry_sexp_t e_sexp;
    gcry_mpi_t n_mpi;
    gcry_mpi_t e_mpi;

    do {
        n_sexp = gcry_sexp_find_token (self->key, "n", 1);
        e_sexp = gcry_sexp_find_token (self->key, "e", 1);

        n_mpi = gcry_sexp_nth_mpi (n_sexp, 1, GCRYMPI_FMT_USG);
        e_mpi = gcry_sexp_nth_mpi (e_sexp, 1, GCRYMPI_FMT_USG);

        if (!e_sexp || !n_sexp || !e_mpi || !n_mpi) {
            err = -1;
            break;
        }
        err = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &n_size, n_mpi);
        if (err) {
            GCRY_ERROR (gcry_strerror (err));
            break;
        }
        err = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &e_size, e_mpi);
        if (err) {
            GCRY_ERROR (gcry_strerror (err));
            break;
        }

        kbuffer_grow(buffer, sizeof(uint8_t) + 2 * sizeof(uint32_t) + sizeof(uint64_t) + e_size + n_size);
        kbuffer_write8(buffer, PKEY_TYPE_PUB | PKEY_ALGO_RSA); //Hard coded as it's the only type we support for now.
        kbuffer_write64(buffer, self->keyid);
        kbuffer_write8(buffer, (uint8_t)self->type);
        kbuffer_write32(buffer, n_size);

        err = gcry_mpi_print(GCRYMPI_FMT_USG, (uint8_t *)(buffer->data + buffer->len), n_size, NULL, n_mpi);
        if (err) {
            GCRY_ERROR (gcry_strerror (err));
            break;
        }
        buffer->len += n_size;
        kbuffer_write32(buffer, e_size);
        err = gcry_mpi_print(GCRYMPI_FMT_USG, (uint8_t *)(buffer->data + buffer->len), e_size, NULL, e_mpi);
        if (err) {
            GCRY_ERROR (gcry_strerror (err));
            break;
        }
        buffer->len += e_size;
    } while (0);

    gcry_sexp_release(e_sexp);
    gcry_sexp_release(n_sexp);
    gcry_mpi_release(e_mpi);
    gcry_mpi_release(n_mpi);

    return err?-1:0;
}

int tagcrypt_pkey_wire_init (tagcrypt_pkey *self, kbuffer *buffer) {
    gcry_error_t err = 0;
    uint8_t key_type;
    uint32_t field_len;
    size_t n_size;
    size_t e_size;
    gcry_mpi_t n_mpi = NULL;
    gcry_mpi_t e_mpi = NULL;

    do {
        if (kbuffer_read8 (buffer, &key_type) || (key_type & (1 << 7)) != PKEY_TYPE_PUB) { err = -1; break;}
        if ((key_type & 0x7F) != PKEY_ALGO_RSA) {err = -1; break;}
            
        if (kbuffer_read64 (buffer, (uint64_t *)&self->keyid)) {err = -1; break;}

        if (kbuffer_read8 (buffer, &key_type)) {err = -1; break;}
        self->type = (enum key_type)key_type;

        // The rest is rsa specific. Move to another function if multiple algo are available.
        if (kbuffer_read32 (buffer, &field_len)) {err = -1; break;}
        n_size = field_len;
        err = gcry_mpi_scan (&n_mpi, GCRYMPI_FMT_USG, kbuffer_current_pos(buffer), n_size, NULL);
        if (err) {err = -1; break;}
        kbuffer_seek(buffer, n_size, SEEK_CUR);

        if (kbuffer_read32 (buffer, &field_len)) {err = -1; break;}
        e_size = field_len;
        err = gcry_mpi_scan (&e_mpi, GCRYMPI_FMT_USG, kbuffer_current_pos(buffer), e_size, NULL);
        if (err) {err = -1; break;}
        kbuffer_seek(buffer, e_size, SEEK_CUR);

        if (gcry_sexp_build (&self->key, NULL, "(10:public-key(3:rsa(1:n%m)(1:e%m)))", n_mpi, e_mpi)) {err = -1; break;}

    } while (0);

    gcry_mpi_release (n_mpi);
    gcry_mpi_release (e_mpi);

    return err ? -1 : 0;
}

int tagcrypt_pkey_serialize(tagcrypt_pkey *self, kbuffer *buffer) {
    size_t size = gcry_sexp_sprint(self->key, GCRYSEXP_FMT_CANON, NULL, 0);

    kbuffer_grow(buffer, 4 * sizeof(uint32_t) + sizeof(uint64_t) + size);
    kbuffer_write32(buffer, TAGCRYPT_PKEY_MAGIC_NUM);
    kbuffer_write32(buffer, TAGCRYPT_PKEY_MAJOR);
    kbuffer_write32(buffer, TAGCRYPT_PKEY_MINOR);
    kbuffer_write64(buffer, (uint64_t)self->keyid);
    kbuffer_write32(buffer, (uint32_t)size);

    gcry_sexp_sprint(self->key, GCRYSEXP_FMT_CANON, buffer->data + buffer->len, size);

    buffer->len += size;

    return 0;
}

/* Use KEY_TYPE_IDENTITY or KEY_TYPE_ENCRYPTION for the type. The others are for signing. */
int tagcrypt_pkey_init (tagcrypt_pkey *self, kbuffer *serialized_pkey, enum key_type type) {
    uint32_t u32;
    uint32_t major;

    if (kbuffer_read32(serialized_pkey, &u32))
        return -1;

    if (u32 != TAGCRYPT_PKEY_MAGIC_NUM)
        return -1;

    if (kbuffer_read32(serialized_pkey, &major))
        return -1;
    if (kbuffer_read32(serialized_pkey, &u32))
        return -1;
    if (kbuffer_read64(serialized_pkey, (uint64_t *)&self->keyid))
        return -1;
    if (kbuffer_read32(serialized_pkey, &u32))
        return -1;

    self->type = type;

    switch (major) {
        case 1:
            gcry_sexp_new (&self->key, serialized_pkey->data + serialized_pkey->pos, u32, 0);
            break;
        default:
            return -1;
    }
    return 0;
}

/* Use KEY_TYPE_IDENTITY or KEY_TYPE_ENCRYPTION for the type. The others are for signing. */
tagcrypt_pkey *tagcrypt_pkey_new (kbuffer *serialized_pkey, enum key_type type) {
    tagcrypt_pkey *self = (tagcrypt_pkey *)kmalloc(sizeof(tagcrypt_pkey));

    if (tagcrypt_pkey_init(self, serialized_pkey, type)) {
        kfree(self);
        self = NULL;
    }
    return self;
}

tagcrypt_pkey *tagcrypt_pkey_wire_new (kbuffer *serialized_pkey) {
    tagcrypt_pkey *self = (tagcrypt_pkey *)kmalloc(sizeof(tagcrypt_pkey));

    if (tagcrypt_pkey_wire_init(self, serialized_pkey)) {
        kfree(self);
        self = NULL;
    }
    return self;
}

void tagcrypt_pkey_clean (tagcrypt_pkey *self) {
    if (self) 
        gcry_sexp_release(self->key);
}

void tagcrypt_pkey_destroy (tagcrypt_pkey *self) {
    tagcrypt_pkey_clean(self);
    kfree(self);
}

// PKCS#1 padding. (Only for version 2.1 of the PKCS#1)
#if 0
#define PKCS1_HASH SHA1
static int mask_generation_function (uint8_t *seed, uint32_t seed_len, 
                                     uint8_t *ret_mask, uint32_t mask_len) {
    uint32_t counter;
    uint32_t C;
    uint32_t mask_size = 0;
    unsigned char *tmp_T;
    gcry_error_t err;
    gcry_md_hd_t hash = NULL;

    err = gcry_md_open(&hash, PKCS1_HASH, 0); 
    if (err) 
        goto ERR;

    while (counter = 0 ; counter < mask_len / gcry_md_get_algo_dlen(GCRY_MD_SHA1) - 1 ; counter++)     {
        gcry_md_write(hash, seed, seed_len);

        C = htonl(counter);
        gcry_md_write(hash, &C, 4);
        
        tmp_T = gcry_md_read(hash, 0);
        memcpy(ret_mask + mask_size, tmp_T, 
               MIN(gcry_md_get_algo_dlen(GCRY_MD_SHA1), mask_len - mask_size));

        ret_mask += MIN(gcry_md_get_algo_dlen(GCRY_MD_SHA1), mask_len - mask_size);
        mask_size += MIN(gcry_md_get_algo_dlen(GCRY_MD_SHA1), mask_len - mask_size);
        gcry_md_reset(hash);
    }

    return 0;

ERR:
    if (hash) 
        gcry_md_close(hash);

    return -1;
}
#endif

int tagcrypt_pkey_do_encrypt(tagcrypt_pkey *self, kbuffer *in, kbuffer *out) {
    size_t size;
    uint32_t len;
    gcry_sexp_t clear = NULL;
    gcry_sexp_t encrypted = NULL;
    gcry_sexp_t tmp = NULL;
    gcry_mpi_t mpi = NULL;
    gcry_error_t err;

    err = gcry_sexp_build(&clear, NULL, "(4:data(5:flags5:pkcs1)(5:value%b))", in->len, in->data);
    if (err) {
        GCRY_CRITICAL(gcry_strerror(err));
        goto ERR;
    }
    
    err = gcry_pk_encrypt(&encrypted, clear, self->key);
    if (err) {
        GCRY_ERROR(gcry_strerror(err));
        goto ERR;
    }
    
    /******* FIXME: RSA SPECIFIC ********/
        tmp = gcry_sexp_find_token(encrypted, "a", 1);
        if (!tmp) {
            GCRY_ERROR ("Could not find token");
            goto ERR;
        }

        mpi = gcry_sexp_nth_mpi(tmp, 1, GCRYMPI_FMT_USG);
        if (!mpi) {
            GCRY_ERROR("Could not parse mpi");
            goto ERR;
        }

        len = (gcry_mpi_get_nbits(mpi) + 7) / 8 + 100;

        kbuffer_grow(out, out->len + len);
        err = gcry_mpi_print(GCRYMPI_FMT_SSH, (uint8_t *)(out->data + out->len), 
                             (size_t)len, &size, mpi);
        if (err) {
            TC_CRITICAL("len = %i", len);
            TC_CRITICAL("size = %i", size);
            GCRY_CRITICAL (gcry_strerror (err));
            goto ERR;
        }
        out->len += size;

    /******* FIXME: END RSA SPECIFIC *****/

    gcry_sexp_release (tmp);
    gcry_sexp_release (encrypted);
    gcry_sexp_release (clear);
    gcry_mpi_release (mpi);
    return 0;

ERR:
    if (clear) gcry_sexp_release (clear);
    if (encrypted) gcry_sexp_release (encrypted);

    return -1;
}

int tagcrypt_pkey_encrypt (tagcrypt_pkey *self, kbuffer *in, kbuffer *out)
{
    int ret = -1;
    tagcrypt_symkey *symkey = tagcrypt_symkey_new ();
    kbuffer *enc_data = kbuffer_new(32);
    kbuffer *serialized_symkey = kbuffer_new(32);
    kbuffer *enc_symkey = kbuffer_new(32);

    if (tagcrypt_symkey_encrypt(symkey, in, enc_data)) 
        goto ERR;

    if (tagcrypt_symkey_serialize(symkey, serialized_symkey)) 
        goto ERR;

    if (tagcrypt_pkey_do_encrypt(self, serialized_symkey, enc_symkey)) 
        goto ERR;

    kbuffer_write32(out, enc_symkey->len);
    kbuffer_write(out, enc_symkey->data, enc_symkey->len);
    kbuffer_write32(out, enc_data->len);
    kbuffer_write(out, enc_data->data, enc_data->len);

    ret = 0;

ERR:
    kbuffer_destroy(enc_data);
    kbuffer_destroy(serialized_symkey);
    kbuffer_destroy(enc_symkey);
    tagcrypt_symkey_destroy(symkey);
    return ret;
}

//#define MAX_SIG_ALGO_NAME_LEN 32
#define MAX_HASH_ALGO_NAME_LEN 32

static int tagcrypt_pkey_verify_rsa(tagcrypt_pkey *self, kbuffer *buffer, gcry_sexp_t hash) {
    int err;
    uint32_t len;
    size_t nscanned;
    gcry_mpi_t sig_mpi;
    gcry_sexp_t sig_sexp;

    if (kbuffer_read32(buffer, &len))
        return -1;

    if (buffer->len - buffer->pos < len)
        return -1;

    gcry_mpi_scan(&sig_mpi, GCRYMPI_FMT_PGP, buffer->data + buffer->pos, (size_t)len, &nscanned);
    gcry_sexp_build(&sig_sexp, NULL, "(7:sig-val(3:rsa(1:s%m)))", sig_mpi);

    err = gcry_pk_verify(sig_sexp, hash, self->key);
    if (err) err = -1;

    gcry_sexp_release(sig_sexp);
    gcry_mpi_release(sig_mpi);

    return err;
}

int tagcrypt_pkey_verify(tagcrypt_pkey *self, uint32_t hash_algo, kbuffer *data, kbuffer *signature) {
    int result = -1;
    gcry_sexp_t hash_sexp;
    int digest_len = gcry_md_get_algo_dlen (hash_algo);
    char hashname[MAX_HASH_ALGO_NAME_LEN];

    uint8_t *digest = (uint8_t *)kmalloc(digest_len); 

    if (!digest) 
        goto ERR;

    strncpy(hashname, gcry_md_algo_name(hash_algo), MAX_HASH_ALGO_NAME_LEN);
    strntolower(hashname, MAX_HASH_ALGO_NAME_LEN);
    gcry_md_hash_buffer(hash_algo, digest, data->data + data->pos, data->len - data->pos);

    result = gcry_sexp_build(&hash_sexp, NULL, "(4:data(5:flags5:pkcs1)(4:hash%s%b))", 
                             hashname, digest_len, digest);
    if (result) 
        goto ERR;

    result = tagcrypt_pkey_verify_rsa(self, signature, hash_sexp);

ERR:
    kfree(digest);
    gcry_sexp_release(hash_sexp);
    return result;
}

