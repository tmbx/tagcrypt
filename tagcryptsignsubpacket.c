/**
 * tagcrypt/tagcryptsignsubpacket.c
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt signature subpackets functions.
 *
 * @author Kristian Benoit
 */

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <assert.h>
#include <kmem.h>
#include <kbuffer.h>

#include "ktools.h"
#include "tagcryptlog.h"
#include "tagcryptsignature.h"
#include "tagcryptsymkey.h"
#include "tagcryptpkey.h"
#include "tagcryptotut.h"

/* =============== Stuff that only need to be hashed ================== */
static uint8_t *tagcrypt_sign_create_hash (tagcrypt_signature *self,
                                           struct tagcrypt_hash_params *params) {
    uint8_t *hash =  (uint8_t *) kmalloc(gcry_md_get_algo_dlen((int)self->hash_algo));
    if (!hash) {
        LIBC_CRITICAL;
        return NULL;
    }

    gcry_md_hash_buffer(self->hash_algo, 
                        (void *)hash,
                        (const void *)params->data,
                        (size_t)params->len);

    return hash;
}

static int tagcrypt_sign_recognize_hash(tagcrypt_signature *sign, 
                                        kbuffer *buffer, 
                                        void **subpacket_ret,
                                        uint16_t *ret_len) {
    uint8_t *hash;

    if (buffer->len < sizeof(uint32_t))
        return -1;
    
    /* Safe to cast, unlikely to be higher than 16k */
    *ret_len = (uint16_t)gcry_md_get_algo_dlen(sign->hash_algo);

    hash = (uint8_t *)kmalloc(*ret_len);
    kbuffer_read(buffer, hash, *ret_len);

    *subpacket_ret = (void *)hash;

    return 0;
}

static int tagcrypt_sign_serialize_hash(tagcrypt_signature *self, 
                                        uint8_t *hash, 
                                        kbuffer *buffer) {
    kbuffer_write(buffer, 
                  hash, 
                  (uint32_t)gcry_md_get_algo_dlen((int)self->hash_algo));
    return 0;
}

static uint16_t tagcrypt_sign_hash_size(tagcrypt_signature *self, 
                                        uint8_t *hash) {
    hash = hash;
    return (uint16_t)gcry_md_get_algo_dlen((int)self->hash_algo);
}

static void tagcrypt_sign_clean_simple_free(tagcrypt_signature *self,
                                            void *to_free) {
    self = self;
    kfree(to_free);
}

struct tagcrypt_subpacket_ops tagcrypt_hash_ops = {
    .type       = TAG_SP_TYPE_TO,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_hash,
    .recognize  =                           tagcrypt_sign_recognize_hash,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_hash,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_hash_size,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_simple_free
};

/* License subpacket. */
static struct tagcrypt_license_params *
tagcrypt_sign_create_license(tagcrypt_signature *self,
                             struct tagcrypt_license_params *params) {
    struct tagcrypt_license_params *lp;
    size_t ksn_s;

    self = self;
    ksn_s = strlen(params->license_kdn);
    lp = kmalloc(sizeof(struct tagcrypt_license_params));
    
    lp->license_lim = params->license_lim;
    lp->license_max = params->license_max;
    lp->license_kdn = kmalloc(ksn_s + 1);
    strcpy(lp->license_kdn, params->license_kdn);

    return lp;
}

static int tagcrypt_sign_recognize_license(__attribute__ ((unused)) tagcrypt_signature *self,
                                           kbuffer *buffer,
                                           void **subpacket_ret,
                                           uint16_t *ret_len) {
    struct tagcrypt_license_params *lp;
    size_t kdn_s;

    do {
        /* Allocate memory for the license structure. */
        lp = kmalloc(sizeof(struct tagcrypt_license_params));
        lp->license_kdn = NULL;
        
        /* Check if the buffer len is at least bigger than the numeric
           data at the start of the license subpackets. */
        if (buffer->len < sizeof(uint32_t) * 3)
            return -1;
        
        if (kbuffer_read32(buffer, &lp->license_lim)) break;
        if (kbuffer_read32(buffer, &lp->license_max)) break;
        if (kbuffer_read32(buffer, &kdn_s)) break;
        
        /* Check if the remaining data is big enough. */
        if (buffer->len < kdn_s)
            return -1;
        
        lp->license_kdn = kmalloc(kdn_s + 1);
        if (kbuffer_read(buffer, (uint8_t *)lp->license_kdn, kdn_s)) break;
        lp->license_kdn[kdn_s] = '\0';

        *subpacket_ret = (void *)lp;
        *ret_len = 3 * sizeof(uint32_t) + kdn_s;

        return 0;

    } while (0);

    if (lp->license_kdn != NULL)
        kfree(lp);
    kfree(lp);

    return -1;
}

static int tagcrypt_sign_serialize_license(__attribute__ ((unused)) tagcrypt_signature *self, 
                                           struct tagcrypt_license_params *params, 
                                           kbuffer *buffer) {
    size_t kdn_s;

    kdn_s = strlen(params->license_kdn);
    kbuffer_write32(buffer, params->license_lim);
    kbuffer_write32(buffer, params->license_max);
    kbuffer_write32(buffer, kdn_s);
    kbuffer_write(buffer, (uint8_t *)params->license_kdn, kdn_s);
    
    return 0;
}

static uint16_t tagcrypt_sign_license_size(__attribute__ ((unused)) tagcrypt_signature *self, 
                                           struct tagcrypt_license_params *lp) {
    return sizeof(uint32_t) * 3 + strlen(lp->license_kdn);
}

static void tagcrypt_sign_free_license(__attribute__ ((unused)) tagcrypt_signature *self,
                                       struct tagcrypt_license_params *lp) {
    if (lp->license_kdn != NULL)
        kfree(lp->license_kdn);

    kfree(lp);
}

struct tagcrypt_subpacket_ops tagcrypt_license_ops = {
    .type       = TAG_SP_TYPE_LICENSE,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_license,
    .recognize  =                           tagcrypt_sign_recognize_license,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_license,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_license_size,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_free_license
};

/* =============== Protocol ============== */

typedef struct tagcrypt_proto {
    uint32_t major;
    uint32_t minor;
} tagcrypt_proto;

static tagcrypt_proto *tagcrypt_sign_create_proto(tagcrypt_signature *self,
                                                  tagcrypt_proto_params *params) {
    tagcrypt_proto *proto = (tagcrypt_proto *)kmalloc(sizeof(tagcrypt_proto));
    self = self;

    memcpy(proto, params, sizeof(tagcrypt_proto));
    return proto;
}

static int tagcrypt_sign_serialize_proto(tagcrypt_signature *self, 
                                         tagcrypt_proto *proto, 
                                         kbuffer *buffer) {
    self = self;
    kbuffer_write32(buffer, proto->major);
    kbuffer_write32(buffer, proto->minor);
    return 0;
}

static int tagcrypt_sign_recognize_proto(tagcrypt_signature *sign, 
                                         kbuffer *buffer,
                                         void **subpacket_ret,
                                         uint16_t *ret_len) {
    tagcrypt_proto *proto;
    sign = sign;

    if (buffer->len < 2 * sizeof(uint32_t))
        return -1;

    proto = (tagcrypt_proto *)kmalloc(sizeof(tagcrypt_proto));

    do {
        if (kbuffer_read32(buffer, &proto->major) || kbuffer_read32(buffer, &proto->minor)) break;

        *subpacket_ret = (void *)proto;
        *ret_len = 2 * sizeof(uint32_t);

        return 0;

    } while (0);

    kfree(proto);
    return -1;
}

static uint16_t tagcrypt_sign_size_proto (tagcrypt_signature *self, tagcrypt_proto *proto) {
    self = self;
    proto = proto;
    return (uint16_t)sizeof(tagcrypt_proto);
}

struct tagcrypt_subpacket_ops tagcrypt_proto_ops = {
    .type       = TAG_SP_TYPE_PROTO,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_proto,
    .recognize  =                           tagcrypt_sign_recognize_proto,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_proto,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_proto,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_simple_free
};

/* ================ KSN ===================== */
static struct tagcrypt_ksn * tagcrypt_sign_create_ksn(tagcrypt_signature * self,
                                                      uint64_t * counter) {    
    struct timeval tv;
    struct tagcrypt_ksn * p = (struct tagcrypt_ksn *)kmalloc(sizeof(struct tagcrypt_ksn));

    /* Unlikely... */
    if (gettimeofday(&tv, NULL) < 0)
        return NULL;
    
    p->keyid = htonll(self->keyid);
    p->tv.tv_sec = htonl(tv.tv_sec);
    p->tv.tv_usec = htonl(tv.tv_usec);
    p->counter = htonll(*counter);

    return p;
}

static int tagcrypt_sign_recognize_ksn(tagcrypt_signature *self, kbuffer *buffer, 
                                       void **subpacket_ret, 
                                       uint16_t *ret_len) {
    struct tagcrypt_ksn * ksn;
    self = self;

    if (buffer->len < sizeof(in_addr_t))
        return -1;

    ksn = (struct tagcrypt_ksn *)kmalloc(sizeof(struct tagcrypt_ksn));

    if (ksn == NULL) 
        return -1;

    kbuffer_read(buffer, (uint8_t *)ksn, sizeof(struct tagcrypt_ksn));
    *subpacket_ret = (void *)ksn;
    *ret_len = sizeof(struct tagcrypt_ksn);
    return 0;
}

static int tagcrypt_sign_serialize_ksn(tagcrypt_signature *self, 
                                       struct tagcrypt_ksn *ksn, 
                                       kbuffer *buffer) {
    self = self;
    kbuffer_write(buffer, (uint8_t *)ksn, sizeof(struct tagcrypt_ksn));
    return 0;
}

static uint16_t tagcrypt_sign_size_ksn(tagcrypt_signature *self, 
                                       struct tagcrypt_ksn *ksn) {
    self = self;
    ksn = ksn;
    return sizeof(struct tagcrypt_ksn);
}

struct tagcrypt_subpacket_ops tagcrypt_ksn_ops = {
    .type       = TAG_SP_TYPE_KSN,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_ksn,
    .recognize  =                           tagcrypt_sign_recognize_ksn,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_ksn,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_ksn,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_simple_free
};

/* ============ attachments ================ */

static uint8_t * tagcrypt_sign_create_attachment(tagcrypt_signature * self, 
                                                 struct tagcrypt_attachment_params * ap) {
    int n = gcry_md_get_algo_dlen((int) self->hash_algo);
    uint8_t * hash = (uint8_t *)kmalloc(n * 2);
    uint8_t * pos = hash;

    /* Write the hashes. */
    gcry_md_hash_buffer(self->hash_algo, pos, (const void *)ap->filename, ap->filename_len);
    pos += n;
    gcry_md_hash_buffer(self->hash_algo, pos, (const void *)ap->payload, ap->payload_len);
    pos += n;
    
    return hash;
}

static int tagcrypt_sign_recognize_attachment(tagcrypt_signature * sign, 
                                              kbuffer * buffer,
                                              void ** subpacket_ret,
                                              uint16_t * ret_len) {
    uint8_t * hash;

    /* Read the size of the filename. */
    if (buffer->len < sizeof(uint32_t))
        return -1;

    *ret_len = (uint16_t)gcry_md_get_algo_dlen(sign->hash_algo) * 2;

    hash = (uint8_t *)kmalloc(*ret_len);
    kbuffer_read(buffer, hash, *ret_len);

    *subpacket_ret = (void *)hash;
    
    return 0;
}

static int tagcrypt_sign_serialize_attachment(tagcrypt_signature *self, 
                                              uint8_t *hash, 
                                              kbuffer *buffer) {
    kbuffer_write(buffer, hash, 
                  (uint32_t)gcry_md_get_algo_dlen((int)self->hash_algo) * 2);
    return 0;
}

static int tagcrypt_sign_size_attachment(tagcrypt_signature * self, 
                                         struct tagcrypt_attachment_params * ap) {
    ap = ap;
    return (uint32_t)gcry_md_get_algo_dlen((int)self->hash_algo) * 2;
}
 
struct tagcrypt_subpacket_ops tagcrypt_attachment_ops = {
    .type      = TAG_SP_TYPE_ATTACHMENT,
    .create    = (tagcrypt_create_fct)    tagcrypt_sign_create_attachment,
    .recognize =                          tagcrypt_sign_recognize_attachment,
    .serialize = (tagcrypt_serialize_fct) tagcrypt_sign_serialize_attachment,
    .size      = (tagcrypt_size_fct)      tagcrypt_sign_size_attachment,
    .destroy   = (tagcrypt_destroy_fct)   tagcrypt_sign_clean_simple_free
};

/* ========= Language code ============== */

static uint8_t *tagcrypt_sign_create_lang(tagcrypt_signature *self, uint32_t lang_code) {
    uint32_t *lang;
    self = self;

    lang = kmalloc(sizeof(uint32_t));
    *lang = lang_code;

    return (uint8_t *)lang;
}

static int tagcrypt_sign_recognize_lang(tagcrypt_signature *sign, kbuffer *buffer, 
                                        void **subpacket_ret,
                                        uint16_t *ret_len) {
    uint32_t *lang;
    sign = sign;

    lang = kmalloc(sizeof(uint32_t));
    kbuffer_read32(buffer, lang);

    *ret_len = sizeof(uint32_t);    
    *subpacket_ret = (void *)lang;

    return 0;
}

static int tagcrypt_sign_serialize_lang(tagcrypt_signature *self, uint32_t *lang, kbuffer *buffer) {
    /* no-op if the signature demanded doesn't support this type of
       packet. */
    if (self->major > 1)
        kbuffer_write32(buffer, *lang);
    
    return 0;
}

static uint32_t tagcrypt_sign_lang_size(tagcrypt_signature *self, uint8_t *hash) {
    /* 0 if the signature demanded doesn't suppor this type of
       packet. */
    hash = hash;
    if (self->major > 1)
        return sizeof(uint32_t);
    else
        return 0;
}

struct tagcrypt_subpacket_ops tagcrypt_lang_ops = {
    .type       = TAG_SP_TYPE_LANG,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_lang,
    .recognize  =                           tagcrypt_sign_recognize_lang,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_lang,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_lang_size,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_simple_free
};

/* ========= date ============== */

static struct timeval *tagcrypt_sign_create_date(tagcrypt_signature *self, void *none) {
    struct timeval *tv = kmalloc(sizeof(struct timeval));
    self = self;
    none = none;

    if (gettimeofday(tv, NULL) < 0) {
        TC_DEBUG (strerror(errno));
        return NULL;
    }

    return tv;
}

static int tagcrypt_sign_recognize_date(tagcrypt_signature *sign, kbuffer *buffer,
                                        void **subpacket_ret,
                                        uint16_t *ret_len) {
    struct timeval *tv = kmalloc(sizeof(struct timeval));
    uint32_t sec, usec;
    int err = 0;
    sign = sign;
    do {
        if (kbuffer_read32(buffer, &sec)) {
            TC_ERROR("Error reading buffer while parsing date\n");
            err = -1;
            break;
        }
        if (kbuffer_read32(buffer, &usec)) {
            TC_ERROR("Error reading buffer while parsing date\n");
            err = -1;
            break;
        }
        tv->tv_sec = sec;
        tv->tv_usec = usec;

        *ret_len = 2*sizeof(uint32_t);
        *subpacket_ret = (void *)tv;
    } while (0);

    if (err) {
        kfree (tv);
        return -1;
    }
    return 0;
}

static int tagcrypt_sign_serialize_date(tagcrypt_signature *self, struct timeval *tv, kbuffer *buffer) {
    if (self->major > 1) {
        kbuffer_write32(buffer, tv->tv_sec);
        kbuffer_write32(buffer, tv->tv_usec);
    }

    return 0;
}

static uint32_t tagcrypt_sign_date_size(tagcrypt_signature *self, struct timeval *tv) {
    tv = tv;
    if (self->major > 1)
        return 2 * sizeof(uint32_t);
    return 0;
}

struct tagcrypt_subpacket_ops tagcrypt_date_ops = {
    .type       = TAG_SP_TYPE_DATE,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_date,
    .recognize  =                           tagcrypt_sign_recognize_date,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_date,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_date_size,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_simple_free
};

/* ========= PoD target address ============= */

static 
struct tagcrypt_podto_params * tagcrypt_sign_create_podto(tagcrypt_signature * self, 
                                                          struct tagcrypt_podto_params * podto_params) {
    size_t s = podto_params->len + sizeof(struct tagcrypt_podto_params);    
    struct tagcrypt_podto_params *p = kmalloc(s);
    self = self;

    p->len = podto_params->len;
    p->data = (uint8_t *)((void *)p + sizeof(struct tagcrypt_podto_params));
    memcpy(p->data, podto_params->data, podto_params->len);
    
    return p;
}

static int tagcrypt_sign_recognize_podto(__attribute__ ((unused)) tagcrypt_signature *self, 
                                         kbuffer *buffer,
                                         void **subpacket_ret,
                                         uint16_t *ret_len) {
    struct tagcrypt_podto_params * p;
    size_t s, len;

    do {
        /* Read the length of the PoD target address. */
        if (kbuffer_read32(buffer, &len))
            break;

        /* Allocate enough space of the structure and the string. */
        s = sizeof(struct tagcrypt_podto_params) + len + 1;
        p = kmalloc(s);

        /* Read the string past the structure length. */
        if (kbuffer_read(buffer, (void *)p + sizeof(struct tagcrypt_podto_params), len))
            break;

        p->len = len;
        p->data = (uint8_t *)p + sizeof(struct tagcrypt_podto_params);        
        p->data[p->len] = 0;
        *subpacket_ret = (void *)p;
        *ret_len = len + sizeof(len);

        return 0;

    } while (0);

    kfree(p);

    return -1;
}

static int tagcrypt_sign_serialize_podto(tagcrypt_signature * self,
                                         struct tagcrypt_podto_params * podto_params,
                                         kbuffer * buffer) {
    self = self;
    kbuffer_write32(buffer, podto_params->len);
    kbuffer_write(buffer, podto_params->data, podto_params->len);

    return 0;    
}

static uint16_t tagcrypt_sign_size_podto(tagcrypt_signature * self,
                                         struct tagcrypt_podto_params * podto) {
    self = self;
    return sizeof(uint32_t) + podto->len;
}

struct tagcrypt_subpacket_ops tagcrypt_podto_ops = {
    .type       = TAG_SP_TYPE_PODTO,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_podto,
    .recognize  =                           tagcrypt_sign_recognize_podto,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_podto,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_podto,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_simple_free
};

/* ================ ip ===================== */

static in_addr_t *tagcrypt_sign_create_ipv4(tagcrypt_signature   *self,
                                            in_addr_t            *params) {
    self = self;
    in_addr_t *ipv4 = (in_addr_t *)kmalloc(sizeof(in_addr_t));

    memcpy(ipv4, params, sizeof (in_addr_t));
    return ipv4;
}

static struct in6_addr *tagcrypt_sign_create_ipv6 (tagcrypt_signature   *self,
                                                   struct in6_addr      *params)
{
    struct in6_addr *ipv6;
    self = self;

    ipv6 = (struct in6_addr *)kmalloc(sizeof(struct in6_addr));
    memcpy(ipv6, params, sizeof(struct in6_addr));
    return ipv6;
}

static int tagcrypt_sign_recognize_ipv4(tagcrypt_signature *sign, 
                                        kbuffer *buffer,
                                        void **subpacket_ret,
                                        uint16_t *ret_len) {
    in_addr_t *ipv4;
    sign = sign;

    if (buffer->len < sizeof(in_addr_t))
        return -1;

    ipv4 = (in_addr_t *)kmalloc(sizeof(in_addr_t));
    kbuffer_read32(buffer, ipv4);
    *subpacket_ret = (void*)ipv4;
    *ret_len = sizeof(in_addr_t);

    return 0;
}

static int tagcrypt_sign_recognize_ipv6(tagcrypt_signature *sign, 
                                        kbuffer *buffer,
                                        void **subpacket_ret,
                                        uint16_t *ret_len) {
    struct in6_addr *ipv6;
    sign = sign;

    if (buffer->len < sizeof (struct in6_addr))
        return -1;

    ipv6 = (struct in6_addr *)kmalloc(sizeof(struct in6_addr));
    kbuffer_read (buffer, (uint8_t *)ipv6, sizeof(struct in6_addr));
    *subpacket_ret = (void*)ipv6;
    *ret_len = sizeof(struct in6_addr);

    return 0;
}

static int tagcrypt_sign_serialize_ipv4(tagcrypt_signature *self, 
                                        in_addr_t *addr, 
                                        kbuffer *buffer) {
    self = self;
    kbuffer_write32(buffer, *addr);
    return 0;
}

static int tagcrypt_sign_serialize_ipv6(tagcrypt_signature *self, 
                                        struct in6_addr *addr, 
                                        kbuffer *buffer) {
    self = self;
    kbuffer_write(buffer, (uint8_t *)addr, sizeof(struct in6_addr));
    return 0;
}

static uint16_t tagcrypt_sign_size_ipv4(tagcrypt_signature *self, 
                                        in_addr_t *addr) {
    self = self;
    addr = addr;
    return sizeof(in_addr_t);
}

static uint16_t tagcrypt_sign_size_ipv6(tagcrypt_signature *self, 
                                        struct in6_addr *addr) {
    self = self;
    addr = addr;
    return sizeof(struct in6_addr);
}

struct tagcrypt_subpacket_ops tagcrypt_ipv4_ops = {
    .type       = TAG_SP_TYPE_IPV4,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_ipv4,
    .recognize  =                           tagcrypt_sign_recognize_ipv4,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_ipv4,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_ipv4,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_simple_free
};

struct tagcrypt_subpacket_ops tagcrypt_ipv6_ops = {
    .type       = TAG_SP_TYPE_IPV6,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_ipv6,
    .recognize  =                           tagcrypt_sign_recognize_ipv6,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_ipv6,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_ipv6,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_simple_free
};

/* =============== symkey ============== */

typedef struct tagcrypt_sp_symkey {
    uint64_t keyid;
    kbuffer *buffer;
} tagcrypt_sp_symkey;

static struct tagcrypt_sp_symkey *tagcrypt_sign_create_symkey(tagcrypt_signature *self,
                                                              struct tagcrypt_symkey_params *params) {
    kbuffer *buffer1;
    kbuffer *buffer2;

    tagcrypt_sp_symkey *ret = (tagcrypt_sp_symkey *)kmalloc(sizeof(tagcrypt_sp_symkey));

    assert ((((self->type & TAG_P_TYPE_POD) && params->pod_key) 
             || !((self->type & TAG_P_TYPE_POD) || params->pod_key))
            && (((self->type & TAG_P_TYPE_ENC) && params->encryption_key) 
                || !((self->type & TAG_P_TYPE_ENC) || params->encryption_key))
            && ((self->type & TAG_P_TYPE_POD) 
                || (self->type & TAG_P_TYPE_ENC)));

    assert (!params->pod_key || params->pod_key->type == KEY_TYPE_IDENTITY);
    assert (!params->encryption_key || params->encryption_key->type == KEY_TYPE_ENCRYPTION);

    buffer1 = kbuffer_new();
    buffer2 = kbuffer_new();
    
    kbuffer_write64(buffer1, self->keyid);
    kbuffer_write8(buffer1, self->type);
    tagcrypt_symkey_serialize(params->symkey, buffer2);
    kbuffer_serialize(buffer2, buffer1);
    kbuffer_reset(buffer2);

    if (self->type == TAG_P_TYPE_PODNENC) {
        tagcrypt_pkey_encrypt (params->pod_key, buffer1, buffer2);
        kbuffer_reset (buffer1);

        kbuffer_write64(buffer1, self->key->keyid);
        kbuffer_write8(buffer1, self->type);
        kbuffer_serialize(buffer2, buffer1);
        kbuffer_serialize(params->destination_list, buffer1);
        kbuffer_reset(buffer2);
    } else {
        kbuffer_serialize (params->destination_list, buffer1);
    }

    tagcrypt_pkey_encrypt (params->encryption_key, buffer1, buffer2);

    ret->keyid = params->encryption_key->keyid;

    kbuffer_destroy (buffer1);
    ret->buffer = buffer2;
    return ret;

err:
    if (buffer1) kbuffer_destroy(buffer1);
    if (buffer2) kbuffer_destroy(buffer2);
    return NULL;
}

/* #define CHECK_SIZE(buffer,size)\ */
/*     do { \ */
/*         if ((buffer)->len - (buffer)->pos < size) { \ */
/*             ERROR ("tagcrypt", "Unexpected end of buffer"); \ */
/*             goto ERR; \ */
/*         } \ */
/*     } while (0) */

static int tagcrypt_sign_recognize_symkey(tagcrypt_signature *sign,
                                          kbuffer *buffer,
                                          void **subpacket_ret,
                                          uint16_t *ret_len) {
    uint32_t len;
    uint8_t *buf_ptr;
    tagcrypt_sp_symkey *ret = (tagcrypt_sp_symkey *)kmalloc(sizeof(tagcrypt_sp_symkey));

    /* FIXME: I'm not sure I understand the why of that condition. There
       shouldn't be any symmetric key in non-encryption packets, or
       that symmetric should be ignored. */
    if (sign->type & TAG_P_TYPE_ENC) {
        if (kbuffer_read64(buffer, &ret->keyid))
            goto ERR;
    } else
        ret->keyid = -1;

    if (kbuffer_read32(buffer, &len))
        goto ERR;
    
    ret->buffer = kbuffer_new(len);
    buf_ptr = kbuffer_write_nbytes(ret->buffer, len);
    kbuffer_read(buffer, buf_ptr, len);

    *ret_len = sizeof(uint64_t) + sizeof(uint32_t) + len;
    *subpacket_ret = ret;

    return 0;

ERR:
    if (ret) {
        if (ret->buffer) 
            kbuffer_destroy(ret->buffer);

        kfree(ret);
    }

    return -1;
}

static int tagcrypt_sign_serialize_symkey(tagcrypt_signature *self, 
                                          tagcrypt_sp_symkey *sp_symkey,
                                          kbuffer *buffer) {
    self = self;
    if (sp_symkey != NULL)
        kbuffer_write64(buffer, sp_symkey->keyid);

    kbuffer_write32(buffer, sp_symkey->buffer->len);
    kbuffer_write(buffer, sp_symkey->buffer->data, sp_symkey->buffer->len);

    return 0;
}

static uint16_t tagcrypt_sign_size_symkey(tagcrypt_signature *self, 
                                          tagcrypt_sp_symkey *sp_symkey) {
    uint16_t size;
    self = self;
    size = sizeof(uint64_t) + sizeof(uint32_t) + sp_symkey->buffer->len;
    return size;
}

static void tagcrypt_sign_clean_symkey(tagcrypt_signature *self, 
                                       tagcrypt_sp_symkey *sp_symkey) {
    self = self;
    kbuffer_destroy (sp_symkey->buffer);
    kfree(sp_symkey);
}

struct tagcrypt_subpacket_ops tagcrypt_symkey_ops = {
    .type       = TAG_SP_TYPE_SYMKEY,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_symkey,
    .recognize  =                           tagcrypt_sign_recognize_symkey,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_symkey,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_symkey,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_symkey
};

/* ====================== SND_SYMKEY ===================== */

static kbuffer *tagcrypt_sign_create_snd_symkey(tagcrypt_signature *self,
                                                struct tagcrypt_snd_symkey_params *params)
{
    kbuffer *buffer1;
    kbuffer *buffer2;

    assert (params->snd_key->type == KEY_TYPE_IDENTITY);

    buffer1 = kbuffer_new(64);
    buffer2 = kbuffer_new(64);

    kbuffer_write64(buffer1, self->keyid);
    kbuffer_write8(buffer1, self->type);
    tagcrypt_symkey_serialize(params->symkey, buffer2);
    kbuffer_serialize(buffer2, buffer1);
    kbuffer_reset(buffer2);

    tagcrypt_pkey_encrypt(params->snd_key, buffer1, buffer2);

    kbuffer_destroy(buffer1);
    return buffer2;

err:
    if (buffer1 != NULL) 
        kbuffer_destroy (buffer1);
    if (buffer2 != NULL) 
        kbuffer_destroy (buffer2);
    return NULL;
}

static int tagcrypt_sign_recognize_snd_symkey(tagcrypt_signature *sign, 
                                              kbuffer *buffer,
                                              void **subpacket_ret,
                                              uint16_t *ret_len) {
    uint32_t len;
    kbuffer *ret;
    sign = sign;

    kbuffer_read32(buffer, &len);    
    ret = kbuffer_new(len);

    if (kbuffer_read_buffer(buffer, ret, len))
        goto ERR;

    *ret_len = sizeof (uint32_t) + len;
    *subpacket_ret = ret;

    return 0;

ERR:
    if (ret) 
        kbuffer_destroy(ret);

    return -1;
}

static int tagcrypt_sign_serialize_snd_symkey(tagcrypt_signature *self,
                                              kbuffer *snd_symkey, kbuffer *buffer) {
    self = self;
    kbuffer_write32 (buffer, snd_symkey->len);
    kbuffer_write (buffer, snd_symkey->data, snd_symkey->len);
    return 0;
}

/* ARGSUSED */
static uint16_t tagcrypt_sign_size_snd_symkey(tagcrypt_signature *self, 
                                              kbuffer *snd_symkey) {
    self = self;
    return sizeof (uint32_t) + snd_symkey->len;
}

static void tagcrypt_sign_clean_snd_symkey(tagcrypt_signature *self, 
                                           kbuffer *snd_symkey) {
    self = self;
    kbuffer_destroy (snd_symkey);
}

struct tagcrypt_subpacket_ops tagcrypt_snd_symkey_ops = {
    .type       = TAG_SP_TYPE_SND_SYMKEY,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_snd_symkey,
    .recognize  =                           tagcrypt_sign_recognize_snd_symkey,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_snd_symkey,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_snd_symkey,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_snd_symkey
};

/* =============== Mail client ============== */

static struct  tagcrypt_mua_params *tagcrypt_sign_create_mailer(tagcrypt_signature *self,
                                                                struct tagcrypt_mua_params *params) {
    struct tagcrypt_mua_params *id = 
        (struct tagcrypt_mua_params *)kmalloc(sizeof(struct tagcrypt_mua_params));
    self = self;

    memcpy(id, params, sizeof(struct tagcrypt_mua_params));
    return id;
}

static int tagcrypt_sign_recognize_mailer (tagcrypt_signature *sign, kbuffer *buffer,
                                           void **subpacket_ret,
                                           uint16_t *ret_len) {
    struct tagcrypt_mua_params *client;
    sign = sign;

    client = (struct tagcrypt_mua_params *)kmalloc(sizeof(struct tagcrypt_mua_params));

    do {
        if (kbuffer_read16(buffer, &client->product) ||
	    kbuffer_read16(buffer, &client->version) ||
	    kbuffer_read16(buffer, &client->release) ||
	    kbuffer_read16(buffer, &client->kpp_version)) break;

        *subpacket_ret = (void*)client;
        *ret_len = sizeof(struct tagcrypt_mua_params);

        return 0;

    } while (0);

    kfree(client);
    return -1;
}

static int tagcrypt_sign_serialize_mailer(tagcrypt_signature *self,
                                          struct tagcrypt_mua_params  *id,
                                          kbuffer *buffer) {
    self = self;
    kbuffer_write16(buffer, id->product);
    kbuffer_write16(buffer, id->version);
    kbuffer_write16(buffer, id->release);
    kbuffer_write16(buffer, id->kpp_version);
    return 0;
}

static uint16_t tagcrypt_sign_size_mailer(tagcrypt_signature *self, 
                                          struct tagcrypt_mua_params *id) {
    self = self;
    id = id;
    return sizeof(struct tagcrypt_mua_params);
}

struct tagcrypt_subpacket_ops tagcrypt_mail_client_ops = {
    .type       = TAG_SP_TYPE_MAIL_CLIENT,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_mailer,
    .recognize  =                           tagcrypt_sign_recognize_mailer,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_mailer,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_mailer,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_simple_free
};

/* =============== PASSWORD ====================== */

static kbuffer *tagcrypt_sign_create_passwd(tagcrypt_signature *self,
                                                    struct tagcrypt_passwd_params *params) {
    kbuffer *clear_passwd = kbuffer_new();
    kbuffer *enc_passwd = kbuffer_new ();
    kbuffer *hash = kbuffer_new();

    assert (params->pkey->type == KEY_TYPE_IDENTITY);

    if (!clear_passwd || !enc_passwd || !hash) 
        goto ERR;

    gcry_md_hash_buffer(self->hash_algo, 
                        kbuffer_write_nbytes(hash, gcry_md_get_algo_dlen(self->hash_algo)),
                        params->passwd->data, 
                        params->passwd->len);

    kbuffer_serialize(hash, clear_passwd);

    if (params->otut) {
        kbuffer_write8(clear_passwd, 1);
        tagcrypt_otut_serialize(params->otut, clear_passwd);
    } else 
        kbuffer_write8(clear_passwd, 0);

    tagcrypt_pkey_encrypt(params->pkey, clear_passwd, enc_passwd);
    kbuffer_destroy(clear_passwd);
    kbuffer_destroy(hash);

    return enc_passwd;
ERR:
    kbuffer_destroy(clear_passwd);
    kbuffer_destroy(enc_passwd);
    kbuffer_destroy(hash);
    return NULL;
}

static int tagcrypt_sign_recognize_passwd(tagcrypt_signature *sign, kbuffer *buffer,
                                           void **subpacket_ret,
                                           uint16_t *ret_len) {
    uint32_t len;
    sign = sign;

    kbuffer *enc_passwd = kbuffer_new(64);

    do {
        if (kbuffer_read32(buffer, &len))
            break;
        
        if (kbuffer_read_buffer(buffer, enc_passwd, len))
            break;
        
        *subpacket_ret = (void*)enc_passwd;
        *ret_len = sizeof(uint32_t) + len;

        return 0;

    } while (0);

    if (enc_passwd != NULL)
        kbuffer_destroy(enc_passwd);

    return -1;
}

static int tagcrypt_sign_serialize_passwd(tagcrypt_signature *self,
                                           kbuffer *passwd, kbuffer *buffer) {
    self = self;
    kbuffer_write32 (buffer, passwd->len);
    kbuffer_write_buffer (buffer, passwd);
    return 0;
}

static uint16_t tagcrypt_sign_size_passwd (tagcrypt_signature *self, kbuffer *passwd) {
    self = self;
    return sizeof(uint32_t) + passwd->len;
}

static void tagcrypt_sign_clean_passwd (tagcrypt_signature *self, kbuffer *passwd) {
    self = self;
    kbuffer_destroy (passwd);
}

struct tagcrypt_subpacket_ops tagcrypt_passwd_ops = {
    .type       = TAG_SP_TYPE_PASSWD,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_passwd,
    .recognize  =                           tagcrypt_sign_recognize_passwd,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_passwd,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_passwd,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_passwd
};


/* =============== blob ====================== */

/* WARNING !!! Becareful, the struct blob is not copied. */
static struct tagcrypt_blob_params *tagcrypt_sign_create_blob(tagcrypt_signature *self,
                                                              struct tagcrypt_blob_params *params) {
    struct tagcrypt_blob_params *blob = 
        (struct tagcrypt_blob_params *)kmalloc(sizeof(struct tagcrypt_blob_params));
    self = self;

    blob->blob = kbuffer_new (32);
    blob->type = params->type;

    kbuffer_write_buffer(blob->blob, params->blob);

    return blob;
}

static int tagcrypt_sign_recognize_blob(tagcrypt_signature *sign, kbuffer *buffer,
                                        void **subpacket_ret,
                                        uint16_t *ret_len) {
    struct tagcrypt_blob_params *blob = 
        (struct tagcrypt_blob_params *)kmalloc(sizeof(struct tagcrypt_blob_params));
    sign = sign,

    blob->blob = kbuffer_new(32);

    if (kbuffer_read32(buffer, &blob->type))
        goto ERR;

    if (kbuffer_read_serialized(buffer, blob->blob)) 
        goto ERR;

    *subpacket_ret = (void*)blob;
    *ret_len = 2 * sizeof(uint32_t) + blob->blob->len;

    return 0;

ERR:
    if (blob) 
        kbuffer_destroy(blob->blob);

    kfree(blob);
    return -1;
}

static int tagcrypt_sign_serialize_blob(tagcrypt_signature *self,
                                        struct tagcrypt_blob_params *blob,
                                        kbuffer *buffer) {
    self = self;
    kbuffer_write32(buffer, blob->type);
    kbuffer_serialize(blob->blob, buffer);

    return 0;
}

static uint16_t tagcrypt_sign_size_blob(tagcrypt_signature *self, 
                                        struct tagcrypt_blob_params *blob) {
    self = self;
    return 2 * sizeof (uint32_t) + blob->blob->len;
}

static void tagcrypt_sign_clean_blob(tagcrypt_signature *self, 
                                     struct tagcrypt_blob_params *blob) {
    self = self;
    if (blob) 
        kbuffer_destroy (blob->blob);

    kfree(blob);
}


struct tagcrypt_subpacket_ops tagcrypt_blob_ops = {
    .type       = TAG_SP_TYPE_PASSWD,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_blob,
    .recognize  =                           tagcrypt_sign_recognize_blob,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_blob,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_blob,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_blob
};

/*================================== KOS ADDR ====================== */

static struct tagcrypt_kpg_params *tagcrypt_sign_create_kpg_addr(tagcrypt_signature *self,
                                                                 struct tagcrypt_kpg_params *params) {
    struct tagcrypt_kpg_params *kpg = 
        (struct tagcrypt_kpg_params *)kmalloc(sizeof(struct tagcrypt_kpg_params));
    self = self;
    
    kpg->type = params->type;
    kpg->addr = kmalloc(sizeof(kstr));
    kstr_init_kstr(kpg->addr, params->addr);
    kpg->port = params->port;

    return kpg;
}

static int tagcrypt_sign_recognize_kpg_addr(tagcrypt_signature *sign, kbuffer *buffer,
                                            void **subpacket_ret,
                                            uint16_t *ret_len) {
    int initial_pos = buffer->pos;
    int err = -1;
    struct tagcrypt_kpg_params *kpg = 
        (struct tagcrypt_kpg_params *)kcalloc(sizeof(struct tagcrypt_kpg_params));
    sign = sign;

    /* TRY */
    do {

        if (kbuffer_read8(buffer, &kpg->type))
            break;

        if (kserializable_deserialize((kserializable **)&kpg->addr, buffer)) 
            break;

        if (kserializable_type((kserializable *)kpg->addr) != KSERIALIZABLE_TYPE_KSTR)
            break;

        if (kpg->type == KPG_ADDR_HOST) {
            if (kbuffer_read16(buffer, &kpg->port))
                break;
        }

        err = 0;
    } while (0);

    if (err) {
        kserializable_destroy((kserializable *)kpg->addr);
        kfree(kpg);
    } else
        *subpacket_ret = (void *)kpg;
        *ret_len = buffer->pos - initial_pos;

    return err;
}

static int tagcrypt_sign_serialize_kpg_addr(tagcrypt_signature *self,
                                        struct tagcrypt_kpg_params *kpg,
                                        kbuffer *buffer) {
    self = self;
    kbuffer_write8(buffer, kpg->type);
    kserializable_serialize((kserializable *)kpg->addr, buffer);
    if (kpg->type == KPG_ADDR_HOST) {
        kbuffer_write16(buffer, kpg->port);
    }

    return 0;
}

static void tagcrypt_sign_clean_kpg_addr(tagcrypt_signature *self,
                                     struct tagcrypt_kpg_params *kpg) {
    self = self;
    if (kpg) 
        kstr_destroy(kpg->addr);

    kfree(kpg);
}

static uint16_t tagcrypt_sign_size_kpg_addr(tagcrypt_signature *self,
                                            struct tagcrypt_kpg_params *kpg) {
    uint16_t len;
    self = self;
    kbuffer *buffer = kbuffer_new();
    tagcrypt_sign_serialize_kpg_addr(self, kpg, buffer);
    len = buffer->len;
    kbuffer_destroy(buffer);

    return len;
}

struct tagcrypt_subpacket_ops tagcrypt_kpg_ops = {
    .type       = TAG_SP_TYPE_KPG_ADDR,
    .create     = (tagcrypt_create_fct)     tagcrypt_sign_create_kpg_addr,
    .recognize  =                           tagcrypt_sign_recognize_kpg_addr,
    .serialize  = (tagcrypt_serialize_fct)  tagcrypt_sign_serialize_kpg_addr,
    .size       = (tagcrypt_size_fct)       tagcrypt_sign_size_kpg_addr,
    .destroy    = (tagcrypt_destroy_fct)    tagcrypt_sign_clean_kpg_addr
};

/*=================================================================*/

struct tagcrypt_subpacket_ops *tagcrypt_subpacket_ops_array[TAG_SP_NB_TYPE] = {
    NULL,
    &tagcrypt_proto_ops,       /* proto */
    &tagcrypt_hash_ops,        /* from_name  */
    &tagcrypt_hash_ops,        /* from_addr  */
    &tagcrypt_hash_ops,        /* to    */
    &tagcrypt_hash_ops,        /* cc    */
    &tagcrypt_hash_ops,        /* subject */
    &tagcrypt_hash_ops,        /* plain */
    &tagcrypt_hash_ops,        /* html  */
    &tagcrypt_ipv4_ops,        /* ipv4  */
    &tagcrypt_ipv6_ops,        /* ipv6  */
    &tagcrypt_attachment_ops,  /* attachment */
    &tagcrypt_symkey_ops,      /* symkey */
    &tagcrypt_snd_symkey_ops,  /* snd_symkey */
    &tagcrypt_passwd_ops,      /* passwd */
    &tagcrypt_mail_client_ops, /* mailerid */
    &tagcrypt_blob_ops,        /* blob */
    &tagcrypt_ksn_ops,         /* KSN */
    &tagcrypt_podto_ops,       /* PoD to */
    &tagcrypt_lang_ops,        /* Language code. */
    &tagcrypt_date_ops,        /* Date code. */
    &tagcrypt_license_ops,     /* License data */
    &tagcrypt_kpg_ops          /* kpg address */
};

#define MAX_DIGEST_LEN 64

/* operation on type */
int tagcrypt_signature_check (tagcrypt_signature   *self,
                              uint8_t               type,
                              uint8_t              *data,
                              uint32_t              len)
{
    assert (! (type <= TAG_SP_TYPE_INVALID || type >= TAG_SP_NB_TYPE || tagcrypt_subpacket_ops_array[type]->recognize != tagcrypt_sign_recognize_hash));
    int retval = -1;
    uint8_t digest[MAX_DIGEST_LEN];
    if (!self->subpackets[type])
        return -1;
    assert (MAX_DIGEST_LEN >= gcry_md_get_algo_dlen (self->hash_algo));
    gcry_md_hash_buffer (self->hash_algo, digest, data, len);
    if (memcmp (self->subpackets[type]->spkt,
                digest,
                gcry_md_get_algo_dlen (self->hash_algo))
        == 0)
        retval = 0;

    return retval;
}

int tagcrypt_signature_get_proto (tagcrypt_signature   *self,
                                  uint32_t             *major,
                                  uint32_t             *minor)
{
    if (!self->subpackets[TAG_SP_TYPE_PROTO])
        return -1;
    *major = ((uint32_t *)self->subpackets[TAG_SP_TYPE_PROTO]->spkt)[0];
    *minor = ((uint32_t *)self->subpackets[TAG_SP_TYPE_PROTO]->spkt)[1];
    return 0;
}

int tagcrypt_signature_get_ksn(tagcrypt_signature * self, char * ksn, size_t ksn_s) {
    assert(ksn_s >= sizeof(struct tagcrypt_ksn));

    if (!self->subpackets[TAG_SP_TYPE_KSN]) 
        return -1;

    memcpy(ksn, self->subpackets[TAG_SP_TYPE_KSN]->spkt, sizeof(struct tagcrypt_ksn));

    return 0;
}

/** Returns a pointer to a blob object. */
int tagcrypt_signature_get_blob(tagcrypt_signature * self, char ** blob, size_t * blob_s) {
    struct tagcrypt_blob_params *pb;

    if (!self->subpackets[TAG_SP_TYPE_BLOB])
        return -1;

    /* Read the blob size. */
    pb = self->subpackets[TAG_SP_TYPE_BLOB]->spkt;
    *blob_s = pb->blob->len;
    *blob = pb->blob->data;

    return 0;
}

int tagcrypt_signature_get_podto(tagcrypt_signature * self, char ** podto, size_t * podto_s) {
    struct tagcrypt_podto_params * p;
 
    assert(podto != NULL);
    assert(podto_s != NULL);

    if (!self->subpackets[TAG_SP_TYPE_PODTO]) {
	KERROR_SET(42, 0, "no PODTO subpacket");
        return -1;
    }
    
    p = (struct tagcrypt_podto_params *)self->subpackets[TAG_SP_TYPE_PODTO]->spkt;
    *podto = (char *)p->data;
    *podto_s = p->len;
    
    return 0;
}

int tagcrypt_signature_get_ip (tagcrypt_signature *self, struct sockaddr *addr) {
    int retval = -1;
    if (self->subpackets[TAG_SP_TYPE_IPV4]) {
        addr->sa_family = PF_INET;
        memcpy (&((struct sockaddr_in *)addr)->sin_addr.s_addr,
                self->subpackets[TAG_SP_TYPE_IPV4]->spkt,
                sizeof (in_addr_t));
        retval = 0 ;
    } else if (self->subpackets[TAG_SP_TYPE_IPV6]) {
        addr->sa_family = PF_INET6;
        memcpy (&((struct sockaddr_in6 *)addr)->sin6_addr,
                self->subpackets[TAG_SP_TYPE_IPV6]->spkt,
                sizeof (struct in6_addr));
        retval = 0 ;
    }

    return retval;
}

int tagcrypt_signature_get_mail_client (tagcrypt_signature  *self,
                                        struct tagcrypt_mua_params *mailer) {
    if (!self->subpackets[TAG_SP_TYPE_MAIL_CLIENT])
        return -1;

    memcpy(mailer, self->subpackets[TAG_SP_TYPE_MAIL_CLIENT]->spkt, 
           sizeof(struct tagcrypt_mua_params));
    return 0;
}

static int do_tagcrypt_sign_get_symkey(tagcrypt_signature *self,
                                       tagcrypt_skey *key,
                                       kbuffer *enc_symkey,
                                       kbuffer *clear_symkey,
                                       kbuffer *user_list) {
    kbuffer *dec_symkey = NULL;
    uint64_t k;
    uint8_t t;

    dec_symkey = kbuffer_new(64);

    if (tagcrypt_skey_decrypt(key, enc_symkey, dec_symkey)) goto ERR;

    if (kbuffer_read64(dec_symkey, &k))
        goto ERR;

    if (k != self->keyid) {
        TC_CRITICAL ("Symmetric key mid does not match mid of the packet.");
        goto ERR;
    }

    if (kbuffer_read8(dec_symkey, &t))
        goto ERR;
    if (t != self->type) {
        TC_CRITICAL ("Symmetric key does not match packet type.");
        goto ERR;
    }

    if (kbuffer_read_serialized(dec_symkey, clear_symkey)) goto ERR;
    
    /* user_list is NULL if there is no user list to read. */
    if (user_list && kbuffer_read_serialized(dec_symkey, user_list)) goto ERR;
    
    kbuffer_destroy(dec_symkey);

    return 0;

ERR:
    if (dec_symkey) 
        kbuffer_destroy(dec_symkey);
    return -1;
}

int tagcrypt_sign_get_symkey(tagcrypt_signature *self, tagcrypt_skey *key,
                             kbuffer *enc_symkey,
                             kbuffer *clear_symkey) {
    return do_tagcrypt_sign_get_symkey (self, key, enc_symkey, clear_symkey, NULL);
}

int tagcrypt_sign_get_snd_symkey (tagcrypt_signature *self,
                                  tagcrypt_skey *key,
                                  kbuffer *buffer) {
    kbuffer *enc_symkey = NULL;
    
    if (key->keyid != self->keyid)
        return -1;

    if (!self->subpackets[TAG_SP_TYPE_SND_SYMKEY]) {
        TC_ERROR ("Could not find the sender symkey in the packet");
        return -1;
    }

    enc_symkey = (kbuffer *)self->subpackets[TAG_SP_TYPE_SND_SYMKEY]->spkt;
    if (!enc_symkey) {
        TC_ERROR ("No buffer in the symkey ... tagcrypt is broken !");
        return -1;
    }

    if (do_tagcrypt_sign_get_symkey (self, key, enc_symkey, buffer, NULL))
        return -1;

    return 0;

}

static kbuffer *get_symkey_for_member(tagcrypt_signature *self, uint64_t keyid)
{
    tagcrypt_subpackets *subpackets = self->subpackets[TAG_SP_TYPE_SYMKEY];

    while (subpackets && ((tagcrypt_sp_symkey *)subpackets->spkt)->keyid != keyid)
        subpackets = subpackets->subpackets;
        
    if (!subpackets) return NULL;

    return ((tagcrypt_sp_symkey *)subpackets->spkt)->buffer;
}

/* FIXME: *lang == 1 (French) || *lang == 0 (English), add more
   language code and put them in common with tbxsosd. */
int tagcrypt_sign_get_lang(tagcrypt_signature *self, uint32_t *lang) {
    if (self->subpackets[TAG_SP_TYPE_LANG] == NULL)
        return 0;

    *lang = *(uint32_t *)self->subpackets[TAG_SP_TYPE_LANG]->spkt;
    return 0;
}

/** Return license data if present.
 *
 * This returns < if there is no license subpackets.  If there is a
 * license subpacket, license_lim, license_max and license_kdn are
 * set.  License_kdn is not copied.
 */
int tagcrypt_sign_get_license(tagcrypt_signature *self, 
                              uint32_t *license_lim,
                              uint32_t *license_max,
                              const char **license_kdn) {
    if (self->subpackets[TAG_SP_TYPE_LICENSE] != NULL) {
        void *spkt;
        struct tagcrypt_license_params *lp;

        spkt = self->subpackets[TAG_SP_TYPE_LICENSE]->spkt;
        lp = (struct tagcrypt_license_params *)spkt;
        
        *license_lim = lp->license_lim;
        *license_max = lp->license_max;
        *license_kdn = lp->license_kdn;

        return 0;
    }
    
    return -1;
}

int tagcrypt_sign_get_enc_symkey(tagcrypt_signature *self,
                                 tagcrypt_skey *key,
                                 kbuffer *buffer,
                                 kbuffer *user_list) {
    kbuffer *enc_symkey = NULL;

    enc_symkey = get_symkey_for_member(self, key->keyid);
    if (!enc_symkey)
        return -1;

    if (do_tagcrypt_sign_get_symkey (self, key, enc_symkey, buffer, user_list))
        return -1;

    return 0;
}

int tagcrypt_sign_check_passwd(tagcrypt_signature *self,
                               tagcrypt_skey *skey,
                               kbuffer *passwd,
                               struct tagcrypt_otut *otut) {
    tagcrypt_subpackets *spkts = NULL;
    kbuffer *dec_passwd = kbuffer_new (32);
    kbuffer *dec_data = kbuffer_new(32);

    uint8_t *hash = (uint8_t *)kmalloc(gcry_md_get_algo_dlen((int)self->hash_algo));

    gcry_md_hash_buffer(self->hash_algo,
                        (void *)hash,
                        (const void *)passwd->data,
                        (size_t)passwd->len);

    for (spkts = self->subpackets[TAG_SP_TYPE_PASSWD] ; spkts ; spkts = spkts->subpackets) {
        tagcrypt_skey_decrypt(skey, (kbuffer *)spkts->spkt, dec_data);
        kbuffer_seek((kbuffer *)spkts->spkt, 0, SEEK_SET);

        kbuffer_read_serialized(dec_data, dec_passwd);

        if (dec_passwd->len != gcry_md_get_algo_dlen((int)self->hash_algo))
            continue;

        if (memcmp(hash, dec_passwd->data, dec_passwd->len) == 0)
            break;

        kbuffer_reset(dec_data);
        kbuffer_reset(dec_passwd);
    }

    if (spkts && otut) {
        uint8_t has_otut;
            
        if (kbuffer_read8(dec_data, &has_otut))
            goto ERR;

        if (has_otut) 
            tagcrypt_otut_realize(dec_data, otut);
    }

    kbuffer_destroy(dec_data);
    kbuffer_destroy(dec_passwd);
    kfree(hash);
    return spkts ? 0 : -1;

ERR:
    kbuffer_destroy(dec_data);
    kbuffer_destroy(dec_passwd);
    kfree(hash);

    return -1;
}
