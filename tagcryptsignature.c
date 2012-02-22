/**
 * tagcrypt/tagcryptsignature.c
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt signature management function.
 *
 * @author Kristian Benoit
 */

/*
 * FIXME: Per version 2.1 of the KSP, each subpackets now have its
 * length written in the subpackets byte array.  Each subpackets
 * should then check that the size that was written in the subpacket
 * stream is what it expects so that it doesn't go beyond his
 * borders.
 */

#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <kmem.h>
#include <base64.h>
#include <kbuffer.h>

#include "tagcryptsignature.h"
#include "tagcryptversion.h"
#include "tagcryptlog.h"

#define MAX_HASH_NAME_LEN 32

tagcrypt_signature *tagcrypt_sign_new_full(enum packet_type type,
                                           uint32_t major, uint32_t minor,
                                           uint32_t hash_algo,
                                           uint32_t sig_algo,
                                           tagcrypt_skey *key) {

    tagcrypt_signature *self = (tagcrypt_signature *)kmalloc(sizeof(tagcrypt_signature));
    if (self && tagcrypt_sign_init(self, type, major, minor, hash_algo, sig_algo, key)) {
        kfree(self);
        self = NULL;
    }

    return self;
}

//WARNING: The key is not copied.
int tagcrypt_sign_init(tagcrypt_signature *self, 
                       enum packet_type type,
                       uint32_t major, 
                       uint32_t minor,
                       uint32_t hash_algo, 
                       uint32_t sig_algo, 
                       tagcrypt_skey *key) {
    
    assert(gcry_md_test_algo(hash_algo) == 0);
    assert(gcry_pk_test_algo(sig_algo) == 0);

    TC_INFO("Creating a new signature (0x%X)", (unsigned int) self);
    TC_DEBUG("Using the hash algo %i(%s)", hash_algo, gcry_md_algo_name(hash_algo));
    TC_DEBUG("Using the sig algo %i(%s)", hash_algo, gcry_pk_algo_name(sig_algo));

    self->magic = TAGCRYPT_PACKET_MAGIC_NUM;
    self->major = major;
    self->minor = minor;
    if (key)
        self->keyid = key->keyid;
    else
        self->keyid = 0;
    self->hash_algo = hash_algo;
    self->sig_algo = sig_algo;
    self->type = type;
    self->subpackets_len = 0;
    memset(self->subpackets, 0, sizeof(tagcrypt_subpackets *) * TAG_SP_NB_TYPE);

    self->key = key;

    return 0;
}

void tagcrypt_sign_destroy(tagcrypt_signature *self) {
    tagcrypt_sign_clean(self);
    kfree(self);
}

void tagcrypt_sign_clean(tagcrypt_signature *self) {
    int i;
    struct tagcrypt_subpacket_ops *ops;

    for (i = 1 ; i < TAG_SP_NB_TYPE; i++) {
        tagcrypt_subpackets *carsubpackets;
        tagcrypt_subpackets *cdrsubpackets = self->subpackets[i];

        while (cdrsubpackets) {
            carsubpackets = cdrsubpackets;
            cdrsubpackets = cdrsubpackets->subpackets;
            
            ops = tagcrypt_subpacket_ops_array[carsubpackets->type];
            ops->destroy(self, carsubpackets->spkt);
            kfree(carsubpackets);                
        }
    }
}

int tagcrypt_sign_add_subpacket(tagcrypt_signature *self, 
                                enum subpacket_type type, 
                                void *params) {
    tagcrypt_subpackets *subpackets;
    struct tagcrypt_subpacket_ops *ops;
    size_t ps;

    /* Allocate allocate the subpacket structure. */
    subpackets = kmalloc(sizeof(tagcrypt_subpackets));
    subpackets->type = type;
    subpackets->spkt = tagcrypt_subpacket_ops_array[type]->create (self, params);

    do {
        if (!subpackets->spkt) break;

        /* Calculate the new len of the subpacket byte stream. */
        ops = tagcrypt_subpacket_ops_array[type];
        ps = ops->size(self, subpackets->spkt);

        /* FIXME: Version 1.1 support deprecated. */
        if (self->major == 1 && self->minor == 1) {
            if (ps > 0) 
                self->subpackets_len += sizeof(uint8_t) + ps;
        /* Other versions support the subpacket len and the type. */
        } else
            if (ps > 0) 
                self->subpackets_len += sizeof(uint8_t) + sizeof(uint16_t) + ps;
        
        subpackets->subpackets = self->subpackets[type];
        self->subpackets[type] = subpackets;

        return 0;

    } while (0);

    /* Errors go through here. */
    return -1;
}

static int tagcrypt_sign_serialize_subpackets(tagcrypt_signature *self, kbuffer *buffer) {
    int i, nb;
    uint16_t n;
    struct tagcrypt_subpacket_ops *ops;

    /* FIXME: Old KSP 1.1 support here. */
    if (self->major == 1 && self->minor == 1) 
        nb = 19;
    else
        nb = TAG_SP_NB_TYPE;

    for (i = 1 ; i < nb; i++) {
        tagcrypt_subpackets *carsubpackets;
        tagcrypt_subpackets *cdrsubpackets = self->subpackets[i];

        while (cdrsubpackets) {
            carsubpackets = cdrsubpackets;
            cdrsubpackets = cdrsubpackets->subpackets;            
            ops = tagcrypt_subpacket_ops_array[carsubpackets->type];

            if (ops->size(self, carsubpackets->spkt) > 0) {
                kbuffer_write8(buffer, carsubpackets->type);
                
                /* KSP 2.1 needs the size of the subpacket after the type. */
                if (self->major == 2 && self->minor == 1) {
                    n = ops->size(self, carsubpackets->spkt);
                    kbuffer_write16(buffer, n);
                }
                ops->serialize(self, carsubpackets->spkt, buffer);
            }
        }
    }

    return 0;
}

/*
static void tagcrypt_sign_serialize_rsa (tagcrypt_signature   *self,
                                  kbuffer      *buffer,
                                  gcry_sexp_t           sig)
{
    unsigned char  *signature   = NULL;
    gcry_sexp_t     tmp_sexp    = NULL;
    gcry_mpi_t      mpi         = NULL;
    size_t          nbytes;

    tmp_sexp =  gcry_sexp_find_token (sig, "s", 1);

    mpi = gcry_sexp_nth_mpi (tmp_sexp, 1, GCRYMPI_FMT_USG);

    gcry_mpi_aprint (GCRYMPI_FMT_PGP,
                     &signature,
                     &nbytes,
                     mpi);

    kbuffer_write32 (buffer, (uint32_t)nbytes);

    kbuffer_write (buffer, signature, (uint32_t)nbytes);

    gcry_free (signature);
    gcry_mpi_release (mpi);
    gcry_sexp_release (tmp_sexp);
}

static void tagcrypt_sign_serialize_sign(tagcrypt_signature *self, kbuffer *buffer) {
    gcry_error_t    err = 0;
    gcry_sexp_t     hash_sexp   = NULL;
    gcry_sexp_t     sig         = NULL;
    unsigned int    hash_len    = gcry_md_get_algo_dlen (self->hash_algo);
    uint8_t        *digest;
    char            hash_name[MAX_HASH_NAME_LEN];

    strncpy (hash_name, gcry_md_algo_name (self->hash_algo), MAX_HASH_NAME_LEN);
    strntolower (hash_name, MAX_HASH_NAME_LEN);
    

    digest = malloc (hash_len);
    gcry_md_hash_buffer (self->hash_algo, digest, buffer->data, buffer->len);
    err = gcry_sexp_build (&hash_sexp,
                           NULL,
                           "(4:data(5:flags5:pkcs1)(4:hash %s %b))",
                           hash_name,
                           hash_len,
                           digest);
    if (err) goto end;
    //FIXME : Do something with the err.
    err = gcry_pk_sign (&sig, hash_sexp, self->key->key);
    if (err) goto end;
    //FIXME : Do something with the err.
    switch (self->sig_algo) {
        case GCRY_AC_RSA:
            tagcrypt_sign_serialize_rsa (self, buffer, sig);
        case GCRY_AC_DSA:
        default:
            break;
    }

end:
    if (digest)     free (digest);
    if (hash_sexp)  gcry_sexp_release (hash_sexp);
    if (sig)        gcry_sexp_release (sig);
}
*/

static void tagcrypt_sign_serialize_sign(tagcrypt_signature *self, kbuffer *buffer) {
    if (self->key)
        tagcrypt_skey_sign (self->key, self->hash_algo, buffer, buffer);
    else
        kbuffer_write(buffer, (uint8_t *)"", 0);
}

int tagcrypt_sign_serialize(tagcrypt_signature *self, kbuffer *buffer) {
    assert(self && buffer);

    kbuffer_write32(buffer, self->magic);
    kbuffer_write32(buffer, self->major);
    kbuffer_write32(buffer, self->minor);
    if (self->key)
        kbuffer_write64(buffer, self->key->keyid);
    else
        kbuffer_write64(buffer, 0);
    kbuffer_write8(buffer, self->hash_algo);
    kbuffer_write8(buffer, self->sig_algo);
    kbuffer_write8(buffer, self->type);
    kbuffer_write32(buffer, self->subpackets_len);
    
    if (tagcrypt_sign_serialize_subpackets(self, buffer) < 0)
        return -1;

    /* Checks if the length of the subpackets is equals to the full len
       of the signature buffer minus the signature headers. */
    assert(self->subpackets_len == 
           buffer->len - 4 * sizeof(uint32_t) - sizeof(uint64_t) - 3 * sizeof(uint8_t));

    tagcrypt_sign_serialize_sign(self, buffer);

    return 0;
}

static int recognize_subpackets(tagcrypt_signature *sign, kbuffer *buffer, uint32_t *ret_len) {
    uint16_t tmp_len = 0;
    uint16_t size;
    void *subpacket;    
    uint8_t type;
    tagcrypt_subpackets *tmp_subpackets = NULL;
    struct tagcrypt_subpacket_ops *ops;
    int nb;

    /* FIXME: Old KSP 1.1 support here. */
    if (sign->major == 1 && sign->minor == 1) 
        nb = 19;
    else
        nb = TAG_SP_NB_TYPE;

    while (*ret_len > 0) {
        /* Read the type of the subpacket to instanciate. */
        if (kbuffer_read8(buffer, &type))
            goto err;
        
        (*ret_len)--;

        /* If the major version is not 1, also read the size of the
           subpacket that we want to instanciate. */
        if (sign->major > 1) {
            if (kbuffer_read16(buffer, &size))
                goto err;

            (*ret_len) -= sizeof(uint16_t);
        }

        /* Make sure the type is actually supported.  If it is, there
           will be some operations defined for it to be decoded.  If
           it is not supported, we need to skip to the next packet
           using the size of the packet. */
        if (type < nb) {
            ops = tagcrypt_subpacket_ops_array[type];
        
            if (!ops || ops->recognize(sign, buffer, &subpacket, &tmp_len)) 
                goto err;
            
            tmp_subpackets = sign->subpackets[type];
            sign->subpackets[type] = (tagcrypt_subpackets *)kmalloc(sizeof(tagcrypt_subpackets));
            sign->subpackets[type]->subpackets = tmp_subpackets;
            
            sign->subpackets[type]->type = type;
            sign->subpackets[type]->spkt = subpacket;
            
            *ret_len -= tmp_len;
        }
        /* If the major version is > 1, that means we have the size
           available to skip to the next packet.  If it's not
           available, well... we are screwed. */
        /* FIXME: Old 1.1 version supported here.  Kill that eventually. */
        else {
            if (sign->major > 1) {
                kbuffer_seek(buffer, size, SEEK_CUR);
                *ret_len -= size;
            } 
            else goto err;
        }
    }

    return 0;
err:
    return -1;
}

static int recognize_signature(tagcrypt_signature *sign, kbuffer *buffer, 
                               uint16_t *ret_len,
                               tagcrypt_pkey *pkey) {
    kbuffer data;
    if (pkey) {
        data.pos = 0;
        data.len = buffer->pos;
        data.data = buffer->data;
        *ret_len = 0;
        return tagcrypt_pkey_verify(pkey, sign->hash_algo, &data, buffer);
    } else
        return 0;
}

static int recognize_packet(tagcrypt_packet *packet, kbuffer *buffer, tagcrypt_pkey *pkey) {
    uint16_t ret_len;
    uint32_t tmp_len;
    uint32_t subpackets_pos;

    if (buffer->len < 5 * sizeof(uint32_t) + 2 * sizeof(uint64_t))
        goto ERR;

    /* MAGIC */
    if (kbuffer_read32(buffer, &packet->magic) || packet->magic != TAGCRYPT_PACKET_MAGIC_NUM)
        goto ERR;

    /* MAJOR */
    if (kbuffer_read32(buffer, &packet->major) ||
        packet->major < MIN_SIGN_VERSION || packet->major > MAX_SIGN_VERSION)
        goto ERR;

    /* MINOR */
    if (kbuffer_read32(buffer, &packet->minor))
        goto ERR;

    /* KEYID */
    if (kbuffer_read64(buffer, &packet->keyid))
        goto ERR;

    /* HASH_ALGO */
    if (kbuffer_read8(buffer, &packet->hash_algo))
        goto ERR;
    if (gcry_md_test_algo (packet->hash_algo))
        goto ERR;

    /* SIG_ALGO */
    if (kbuffer_read8(buffer, &packet->sig_algo))
        goto ERR;
    if (gcry_pk_test_algo (packet->sig_algo))
        goto ERR;

    /* Extensibility is good, but let's make sure the algorithms for
       the signature and hash is what we want them to be. */
    if (packet->sig_algo != GCRY_AC_RSA)
        goto ERR;
    if (packet->hash_algo != GCRY_MD_SHA1)
        goto ERR;

    /* PACKET_TYPE */
    if (kbuffer_read8(buffer, &packet->type))
        goto ERR;
    if (packet->type >= TAG_P_NB_TYPE)
        goto ERR;

    /* SUBPACKET_LEN */
    if (kbuffer_read32(buffer, &tmp_len))
        goto ERR;
    if (!tmp_len) return -1;

    subpackets_pos = buffer->pos;

    kbuffer_seek(buffer, tmp_len, SEEK_CUR);

    if (recognize_signature(packet, buffer, &ret_len, pkey))
        return -1;

    if (buffer->pos != buffer->pos)
        return -1;

    kbuffer_seek (buffer, subpackets_pos, SEEK_SET);

    memset(&packet->subpackets, 0, TAG_SP_NB_TYPE * sizeof(tagcrypt_subpackets *));
    if (recognize_subpackets(packet, buffer, &tmp_len)) 
        return -1;

    return 0;

ERR:
    return -1;
}

/* FIXME: This function is has been removed in KMO and should be
   removed in tagcrypt too.  It should be possible to access basic
   signature fields without converting it to a base64 string. */

#define KEYID_POS (3 * sizeof (uint32_t))

uint64_t tagcrypt_signature_get_keyid(const char *raw_sign, size_t raw_sign_s) {
    uint64_t keyid = 0;
    uint32_t u32;
    kbuffer *buffer = NULL;

    if (raw_sign_s < KEYID_POS + sizeof(uint64_t)) 
        goto err;

    if ((buffer = kbuffer_new()) == NULL)
        goto err;

    kbuffer_write(buffer, (uint8_t *)raw_sign, raw_sign_s);

    if (kbuffer_read32(buffer, &u32) || u32 != TAGCRYPT_PACKET_MAGIC_NUM)
        goto err;

    
    if (kbuffer_read32(buffer, &u32) || u32 < MIN_SIGN_VERSION || u32 > MAX_SIGN_VERSION) 
        goto err;

    kbuffer_seek(buffer, KEYID_POS, SEEK_SET);
    if (kbuffer_read64(buffer, &keyid))
        goto err;

err:
    if (buffer) 
        kbuffer_destroy(buffer);
    return keyid;
}

int tagcrypt_signature_init_serialized(tagcrypt_signature *self, kbuffer *buffer, tagcrypt_pkey *pkey) {
    return recognize_packet(self, buffer, pkey);
}

tagcrypt_signature *tagcrypt_signature_new_serialized(kbuffer *buffer, tagcrypt_pkey *pkey) {
    tagcrypt_signature *self;
    self = (tagcrypt_signature *)kmalloc(sizeof(tagcrypt_signature));

    if (tagcrypt_signature_init_serialized(self, buffer, pkey) < 0) {
        kfree(self);
        self = NULL;
    }
    return self;
}

void tagcrypt_signed_pkey_destroy (struct tagcrypt_signed_pkey *self) {
    if (self)
        tagcrypt_pkey_destroy(self->key);
    kfree(self);
}

// The pkey is the kryptiva signing pkey.
struct tagcrypt_signed_pkey *tagcrypt_sign_get_pkey (kbuffer *buffer, tagcrypt_pkey *pkey) {
    struct tagcrypt_signed_pkey *signed_pkey;
    struct tagcrypt_blob_params *blob;
    struct timeval *tv;
    kstr str;
    kbuffer buf_bin;
    tagcrypt_signature *sign;
    int err = 0;

    signed_pkey = kcalloc(sizeof(struct tagcrypt_signed_pkey));

    do {
        kstr_init_buf(&str, buffer->data, buffer->len);
        err = kbuffer_init_b64(&buf_bin, &str);
        kstr_clean(&str);

        if (err != 0) 
            break;
        
        sign = tagcrypt_signature_new_serialized (&buf_bin, pkey);
        if (sign == NULL)
            break;        

        signed_pkey->key = NULL;
        if (!sign) 
            break;
        
        signed_pkey->mid = sign->keyid;

        blob = (struct tagcrypt_blob_params *)sign->subpackets[TAG_SP_TYPE_BLOB]->spkt;
        if (blob == NULL)
            break;
        if (blob->type != 1)
            break;

        if (!sign->subpackets[TAG_SP_TYPE_DATE])
            break;

        tv = (struct timeval *)sign->subpackets[TAG_SP_TYPE_DATE]->spkt;
        signed_pkey->time.tv_sec = tv->tv_sec;
        signed_pkey->time.tv_usec = tv->tv_usec;

        signed_pkey->key = tagcrypt_pkey_wire_new (blob->blob);

        kbuffer_clean(&buf_bin);
        tagcrypt_sign_destroy(sign);
        return signed_pkey;

    } while (0);

    if (err == 0) 
        kbuffer_clean(&buf_bin);

    if (signed_pkey->key == NULL) 
        kfree(signed_pkey);

    return NULL;
}

int tagcrypt_sign_pkey (kbuffer *buffer, tagcrypt_skey *skey, tagcrypt_pkey *pkey) {
    int err = 0;
    tagcrypt_signature sign;
    kbuffer *serialized;
    struct tagcrypt_blob_params params;
    do {
        serialized = kbuffer_new (32);
        if (!serialized) {
            err = -1;
            break;
        }
        if (tagcrypt_sign_init (&sign, TAG_P_TYPE_SIGN, 2, 1, DEFAULT_HASH, GCRY_AC_RSA, skey)) {
            err = -1;
            break;
        }
        if (tagcrypt_pkey_wire_serialize (pkey, serialized)) {
            err = -1;
            break;
        }
        params.type = 1;
        params.blob = serialized;
        if (tagcrypt_sign_add_subpacket(&sign, TAG_SP_TYPE_BLOB, &params)) {
            err = -1;
            break;
        }
        if (tagcrypt_sign_add_subpacket(&sign, TAG_SP_TYPE_DATE, NULL)) {
            err = -1;
            break;
        }
        kbuffer_reset(serialized);
        if (tagcrypt_sign_serialize (&sign, serialized)) {
            err = -1;
            break;
        }
        kbin2b64(serialized, buffer);
    } while (0);
    
    tagcrypt_sign_clean(&sign);
    kbuffer_destroy (serialized);
    return err;
}
