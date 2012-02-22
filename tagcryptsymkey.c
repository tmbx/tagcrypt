/**
 * tagcrypt/tagcryptsymkey.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt symmetric key management functions
 *
 * @author Kristian Benoit.
 */

#include <gcrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <kmem.h>
#include <kbuffer.h>

#include "tagcrypt.h"
#include "tagcryptlog.h"
#include "tagcryptsymkey.h"
#include "tagcryptsignature.h"

int tagcrypt_symkey_serialize(tagcrypt_symkey *self, kbuffer *buffer) {
    kbuffer_write8(buffer, (uint8_t)  self->cipher);
    kbuffer_write8(buffer, (uint8_t)  self->mode);
    kbuffer_write(buffer, (uint8_t *)self->key, self->key_len);
    kbuffer_write(buffer, (uint8_t *)self->iv, self->block_len);
    
    return 0;
}

void tagcrypt_symkey_clean(tagcrypt_symkey *self) {
    if (self) {
        kfree(self->iv);
        kfree(self->key);
        gcry_cipher_close (self->hd);
    }
}

int tagcrypt_symkey_init(tagcrypt_symkey *self, int cipher, int mode) {
    unsigned int flags = GCRY_CIPHER_SECURE;
    gcry_error_t err = 0;

    err = gcry_cipher_algo_info (cipher, GCRYCTL_TEST_ALGO, NULL, NULL);
    if (err) goto ERR;

    self->cipher = cipher;
    self->mode = mode;

    switch (mode) {
        case GCRY_CIPHER_MODE_ECB:
            TC_INFO ("You are asking for a key using the _WEAK_ ECB mode.\n");
            break;
        case GCRY_CIPHER_MODE_CBC:
            flags |= GCRY_CIPHER_CBC_CTS;
            break;
        case GCRY_CIPHER_MODE_CFB:
            break;
        default:
            TC_ERROR ("Unknown cipher mode %i\n", mode);
            goto ERR;
    }

    err = gcry_cipher_open(&self->hd, cipher, mode, flags);
    if (err) goto ERR;

    err = gcry_cipher_algo_info(cipher, GCRYCTL_GET_KEYLEN, NULL, &self->key_len);
    if (err) goto ERR;

    err = gcry_cipher_algo_info(cipher, GCRYCTL_GET_BLKLEN, NULL, &self->block_len);
    if (err) goto ERR;

    self->iv = (char *)kmalloc(self->block_len);
    self->key = (char *)kmalloc(self->key_len);

    return 0;

ERR:
    if (err) GCRY_ERROR (gcry_strerror (err));
    return -1;
}

int tagcrypt_symkey_init_serialized(tagcrypt_symkey *self, kbuffer *buffer) {
    int     err;
    uint8_t cipher;
    uint8_t mode;

    if (kbuffer_read8(buffer, &cipher) || kbuffer_read8(buffer, &mode)) 
        goto ERR;

    err = tagcrypt_symkey_init (self, cipher, mode);
    if (err) return err;

    if (kbuffer_read (buffer, (uint8_t *)self->key, self->key_len))
        goto ERR;

    if (kbuffer_read (buffer, (uint8_t *)self->iv, self->block_len))
        goto ERR;

    err = gcry_cipher_setkey (self->hd, self->key, self->key_len);
    if (err) goto ERR;

    return 0;
ERR:
    tagcrypt_symkey_clean (self);
    return -1;
}

int tagcrypt_symkey_init_new(tagcrypt_symkey *self, int cipher, int mode) {
    int err;
    err = tagcrypt_symkey_init (self, cipher, mode);
    if (err) return err;
    
    gcry_randomize (self->key, self->key_len, GCRY_VERY_STRONG_RANDOM);
    err = gcry_cipher_setkey (self->hd, self->key, self->key_len);
    if (err) goto ERR;

    gcry_randomize (self->iv, self->block_len, GCRY_VERY_STRONG_RANDOM);
    return 0;

ERR:
    if (err) GCRY_ERROR (gcry_strerror (err));
    return -1;
}

void tagcrypt_symkey_destroy (tagcrypt_symkey *self) {
    tagcrypt_symkey_clean(self);
    kfree(self);
}

tagcrypt_symkey *tagcrypt_symkey_new_serialized(kbuffer *buffer) {
    tagcrypt_symkey *self = (tagcrypt_symkey *)kmalloc(sizeof(tagcrypt_symkey));
    
    if (self && tagcrypt_symkey_init_serialized(self, buffer)) {
        kfree(self);
        self = NULL;
    }
    return self;
}

tagcrypt_symkey *tagcrypt_symkey_new_full(int cipher, int mode) {
    tagcrypt_symkey *self = (tagcrypt_symkey *)kmalloc(sizeof(tagcrypt_symkey));
    if (self && tagcrypt_symkey_init_new(self, cipher, mode)) {
        kfree(self);
        self = NULL;
    }
    return self;
}

static uint8_t *get_random_non_zero(size_t n) {
    uint8_t *data = (uint8_t *)gcry_random_bytes_secure(n, GCRY_STRONG_RANDOM);
    size_t i, z = 0;

    for (i = 0 ; i < n ; i++) {
        if (data[i] == '\0')
            data[i] = data[z++];
    }

    while (z) {
        uint8_t *more_data;
        size_t nb = z + z / 128 + 3;
        more_data = (uint8_t *) gcry_random_bytes_secure(nb, GCRY_STRONG_RANDOM); 
        for (i = 0 ; i < nb && z ; i++)
            if (more_data[i] != '\0')
                data[--z] = more_data[i];
        gcry_free(more_data);
    }
    return data;
}

#define TAGCRYPT_SYMKEY_ENCRYPT_MAGIC (0x23A6F9DDE35CF931ll)
int tagcrypt_symkey_encrypt(tagcrypt_symkey *self, kbuffer *in, kbuffer *out) {
    int err;
    kbuffer *padded_in = NULL;
    size_t block_len, missing_len;

    err = gcry_cipher_algo_info (self->cipher, GCRYCTL_GET_BLKLEN, NULL, &block_len); if (err) goto GCRY_ERR;
    missing_len = block_len - ((in->len + 9) % block_len);
    padded_in = kbuffer_new(in->len + 9 + missing_len);

    kbuffer_write64(padded_in, TAGCRYPT_SYMKEY_ENCRYPT_MAGIC);

    if (missing_len) {
        uint8_t *rdata = get_random_non_zero (missing_len);
        kbuffer_write (padded_in, rdata, missing_len);
        gcry_free (rdata);
    }

    kbuffer_write8 (padded_in, '\0');
    kbuffer_write_buffer (padded_in, in);

    err = gcry_cipher_reset(self->hd);
    if (err) goto GCRY_ERR;

    err = gcry_cipher_setiv(self->hd, self->iv, self->block_len);  
    if (err) goto GCRY_ERR;

    kbuffer_grow(out, out->len + padded_in->len);
    err = gcry_cipher_encrypt(self->hd, 
                              (char *)out->data + out->len, 
                              padded_in->len, 
                              padded_in->data, 
                              padded_in->len);
    if (err) goto GCRY_ERR;

    out->len += padded_in->len;

    kbuffer_destroy (padded_in);
    return 0;

GCRY_ERR:
    GCRY_CRITICAL (gcry_strerror(err));
    if (padded_in) kbuffer_destroy (padded_in);
    return -1;
}

int tagcrypt_symkey_decrypt (tagcrypt_symkey *self, kbuffer *in, kbuffer *out) {
    int err;
    char *err_str = NULL;
    kbuffer *tmp = kbuffer_new();
    uint64_t m;
    uint8_t c;
    uint8_t *buf_ptr;

    err = gcry_cipher_reset(self->hd);
    if (err) goto ERR;

    err = gcry_cipher_setiv(self->hd, self->iv, self->block_len);  
    if (err) goto ERR;

    buf_ptr = kbuffer_write_nbytes(tmp, in->len);
    err = gcry_cipher_decrypt(self->hd, 
                              (char *)buf_ptr, 
                              in->len, 
                              (char *)in->data, in->len);
    if (err) goto ERR;

    if (kbuffer_read64(tmp, &m))
        goto ERR;

    if (m != TAGCRYPT_SYMKEY_ENCRYPT_MAGIC) {
        err_str = "Decryption failed, wrong data obtained after decryption.";
        goto ERR;
    }

    while (1) {
        if (kbuffer_read8(tmp, &c))
            goto ERR;

        if (c == 0)
            break;
    }

    kbuffer_write(out, tmp->data + tmp->pos, tmp->len - tmp->pos);
    kbuffer_destroy(tmp);
    return 0;

ERR:
    kbuffer_destroy(tmp);

    if (err_str)    
        TC_ERROR (err_str);
    else
        GCRY_ERROR (gcry_strerror(err));

    return -1;
}
