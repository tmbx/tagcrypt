/**
 * tagcrypt/include/tagcryptsignature.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt signature management functions.
 *
 * @author Kristian Benoit
 */

#ifndef __TAGCRYPTSIGNATURE_H__
#define __TAGCRYPTSIGNATURE_H__

#include <gcrypt.h>
#include <kbuffer.h>

#include "tagcryptskey.h"
#include "tagcryptsymkey.h"
#include "tagcryptpkey.h"

#define MIN_SIGN_VERSION 1
#define MAX_SIGN_VERSION 2

/* ===================== Type definition =========================== */

typedef struct tagcrypt_packet      tagcrypt_signature;
typedef struct tagcrypt_packet      tagcrypt_packet;
typedef struct tagcrypt_subpackets  tagcrypt_subpackets;

/** The different type of a KSP. */
enum packet_type {
    TAG_P_TYPE_SIGN = 0,
    TAG_P_TYPE_POD = 1,
    TAG_P_TYPE_ENC = 2,
    TAG_P_TYPE_PODNENC = 3,
    TAG_P_NB_TYPE = 4
};

/** The different type of the subpackets in a KSP. */
enum subpacket_type {
    TAG_SP_TYPE_INVALID = 0,
    TAG_SP_TYPE_PROTO = 1,
    TAG_SP_TYPE_FROM_NAME = 2,
    TAG_SP_TYPE_FROM_ADDR = 3,
    TAG_SP_TYPE_TO = 4,
    TAG_SP_TYPE_CC = 5,
    TAG_SP_TYPE_SUBJECT = 6,
    TAG_SP_TYPE_PLAIN = 7,
    TAG_SP_TYPE_HTML = 8,
    TAG_SP_TYPE_IPV4 = 9,
    TAG_SP_TYPE_IPV6 = 10,
    TAG_SP_TYPE_ATTACHMENT = 11,
    TAG_SP_TYPE_SYMKEY = 12,
    TAG_SP_TYPE_SND_SYMKEY = 13,
    TAG_SP_TYPE_PASSWD = 14,
    TAG_SP_TYPE_MAIL_CLIENT = 15,
    TAG_SP_TYPE_BLOB = 16,
    TAG_SP_TYPE_KSN = 17,
    TAG_SP_TYPE_PODTO = 18,
    TAG_SP_TYPE_LANG = 19,
    TAG_SP_TYPE_DATE = 20,
    TAG_SP_TYPE_LICENSE = 21,
    TAG_SP_TYPE_KPG_ADDR = 22,
    TAG_SP_NB_TYPE = 23
};

/* Type of the functions used on the subpackets */
typedef void    *(*tagcrypt_create_fct)   (tagcrypt_signature *self, 
                                           void *params);

typedef int      (*tagcrypt_recognize_fct)(tagcrypt_signature *self, 
                                           kbuffer *buffer, 
                                           void **spkt, 
                                           uint16_t *ret_len);

typedef int      (*tagcrypt_serialize_fct)(tagcrypt_signature *self, 
                                           void *spkt, 
                                           kbuffer *buffer);

typedef uint16_t (*tagcrypt_size_fct)     (tagcrypt_signature *self, 
                                           void *spkt);

typedef void     (*tagcrypt_destroy_fct)  (tagcrypt_signature *self, 
                                           void *spkt);

/** subpacket operation structure */
struct tagcrypt_subpacket_ops {
    uint8_t                 type;
    tagcrypt_create_fct     create;
    tagcrypt_recognize_fct  recognize;
    tagcrypt_serialize_fct  serialize;
    tagcrypt_size_fct       size;
    tagcrypt_destroy_fct    destroy;
};

/** Parameters for license subpacket. */
struct tagcrypt_license_params {
    uint32_t license_lim;
    uint32_t license_max;
    char *license_kdn;
};

/** parameter passed to add a hash subpacket (from, to, cc, subject, ...) */ 
struct tagcrypt_hash_params {
    uint8_t *data;
    uint32_t len;
};

/** PoD target address. */
struct tagcrypt_podto_params {
    uint8_t *data;
    uint32_t len;
};


struct tagcrypt_kpg_params {
    enum tagcrypt_kpg_type {
        KPG_ADDR_HOST,
        KPG_ADDR_DOMAIN
    } type;
    kstr *addr;
    uint16_t port;
};

/** parameter passed to add a proto subpacket. */ 
typedef uint32_t tagcrypt_proto_params[2];

/** parameter passed to add an ipv4 subpacket. */ 
typedef uint32_t tagcrypt_ipv4_params;

/** parameter passed to add a ipv6 subpacket. */ 
typedef uint32_t tagcrypt_ipv6_params[4];

/** parameter passed to add an ipv6 subpacket. */ 
struct tagcrypt_symkey_params {
    tagcrypt_symkey *symkey;
    tagcrypt_pkey   *encryption_key;
    tagcrypt_pkey   *pod_key;
    kbuffer *destination_list;
};

/* Parameter of attachments in the signature. */
struct tagcrypt_attachment_params {
    /* Filename of the attachment. */
    uint8_t *filename;

    /* Length of the filename. */
    size_t filename_len;

    /* Payload of the attachment. */
    uint8_t *payload;
    
    /* Length of payload. */
    size_t payload_len;
};

/* The serial number. */
struct tagcrypt_ksn {
    /** Key ID of the signature. */
    uint64_t keyid;

    /** Time at which the message was signed. */
    struct timeval tv;

    /** Application-provided counter. */
    uint64_t counter;
};

#define TAGCRYPT_KSN_SIZE sizeof(struct tagcrypt_ksn)

/** parameter passed to add a password */
struct tagcrypt_passwd_params {
    tagcrypt_pkey * pkey;
    kbuffer * passwd;
    struct tagcrypt_otut * otut;
};

/** parameter passed to add/retrieve a blob entry. (a blob is anything, useful for signing keys and token).*/
struct tagcrypt_blob_params {
    uint32_t type;
    kbuffer * blob;
};

/** parameter passed to add/retrieve a mua entry. */
struct tagcrypt_mua_params {
    uint16_t product;
    uint16_t version;
    uint16_t release;
    uint16_t kpp_version;
};

/** parameter passed to add a sender symkey subpacket.
 *
 * A SeNDer Symkey is a symmetric key encrypted with the sender signature public
 * key. It is used when encrypting for a non member, for PoD and for
 * PoD + Encryption to non members.
 */ 
struct tagcrypt_snd_symkey_params {
    tagcrypt_symkey * symkey;
    tagcrypt_pkey   * snd_key;
};

extern struct tagcrypt_subpacket_ops *tagcrypt_subpacket_ops_array[TAG_SP_NB_TYPE];

//FIXME: The subpackets should not be a linked list anymore. The list should be
//       implemented by the attachement subpacket as it's the only one using it.
//       ... the symkeys and the password must also be a list.
struct tagcrypt_subpackets {
    enum subpacket_type  type;
    uint16_t            *size;
    void                *spkt;
    tagcrypt_subpackets *subpackets;
};

/** The structure representing a Kriptiva Signature Packet (KSP). */
struct tagcrypt_packet {
    /** The magic number found in the packet, FIXME: this is useless in the structure. */
    uint32_t  magic; 
    /** The major number of the KSP format. */
    uint32_t major; 
    /** The major number of the KSP format. */
    uint32_t minor; 
    /** The member id of the member that signed this packet. */
    uint64_t keyid; 
    /** The algorithm id used to hash any hashed data in the KSP. */
    uint8_t  hash_algo;
    /** The public key algorithm used to sign the packet. 
     * FIXME: this is useless as the key know which algo is used. */ 
    uint8_t  sig_algo; 
    /** \see enum packet_type. */
    uint8_t  type; 
    /** The length of all the subpackets. */
    uint32_t subpackets_len; 
    /** Every subpacket structure. */
    tagcrypt_subpackets * subpackets[TAG_SP_NB_TYPE]; 
    /** The key used to sign/verify the packet. */
    tagcrypt_skey * key; 
};

/** Create a new signature.
 *
 * Create a new signature specifying the hash_algorithm and the asymmetric key encryption algorithm.
 * FIXME: There's no need to specify the asymmetric key algorithm.
 *
 * \param type the type of the KSP \see enum packet_type.
 * \param hash_algo the hash algorithm id used to hash any data that need to be hashed in the KSP.
 * \param sig_algo the asymmetric key encryption algorithm used. FIXME: No need of it.
 * \param key the secret key that will be used to sign the packet.
 * \return A newly allocated KSP to fill.
 */
tagcrypt_signature * tagcrypt_sign_new_full(enum packet_type type, 
                                            uint32_t major, 
                                            uint32_t minor,
                                            uint32_t hash_algo, 
                                            uint32_t sig_algo,
                                            tagcrypt_skey *key);

/** Unserialize a KSP.
 *
 * \param buffer the buffer containing the serialized KSP.
 * \param key the public key that will be used to verify the packet.
 * \return A newly allocated KSP to fill.
 */
tagcrypt_signature * tagcrypt_signature_new_serialized(kbuffer *buffer, tagcrypt_pkey *pkey);

/** Initialized a KSP.
 *
 * Use this for statically allocated KSP.
 *
 * \param self the KSP structure to initialize.
 * \param type the type of the KSP were creating.
 * \param hash_algo the hash algorithm id.
 * \param sig_algo the asymmetric key algorithm id.
 * \param key the secret key that will be used to sign the packet.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_sign_init(tagcrypt_signature *self, enum packet_type type, 
                       uint32_t major, uint32_t minor,
                       uint32_t hash_algo, uint32_t sig_algo, tagcrypt_skey *key);

/** Unserialize a KSP.
 *
 * Use this for statically allocated KSP.
 *
 * \param self the KSP structure to initialize.
 * \param buffer the buffer containing the serialized KSP.
 * \param pkey the public key that will be used to verify the packet.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_signature_init_serialized(tagcrypt_signature *self, kbuffer *buffer, tagcrypt_pkey *pkey);

/** Deallocate a KSP instanciated by tagcrypt_sign_new*
 *
 * \param self the KSP structure to deallocate.
 */
void tagcrypt_sign_destroy(tagcrypt_signature *self);

/** Release ressources used inside a KSP initialized by tagcrypt_sign_init*
 *
 * \param self the KSP structure that holds ressources to release.
 */
void tagcrypt_sign_clean(tagcrypt_signature *self);
#define DEFAULT_HASH GCRY_MD_SHA1
/** Create a new signature.
 *
 * Create a new signature with the default algo ids.
 * FIXME: There's no need to specify the asymmetric key algorithm.
 *
 * \param type the type of the KSP \see enum packet_type.
 * \param key the secret key that will be used to sign the packet.
 * \return A newly allocated KSP to fill.
 */
static inline tagcrypt_signature * tagcrypt_sign_new(enum packet_type type, 
                                                     uint32_t major, uint32_t minor, 
                                                     tagcrypt_skey *key) {
    return tagcrypt_sign_new_full ( type,
                                    major, minor,
                                    GCRY_MD_SHA1,
                                    GCRY_AC_RSA,
                                    key);
}

/** Add a subpacket to a KSP.
 *
 * \param self the KSP in which we want to add the subpacket.
 * \param type the subpacket type to add.
 * \param params the subpacket specific parameters used to create the it.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_sign_add_subpacket(tagcrypt_signature *self, enum subpacket_type type, void *params);

/** Serialize the KSP.
 *
 * \param self the KSP to serialize.
 * \param buffer the returned serialized KSP.
 */
int tagcrypt_sign_serialize(tagcrypt_signature *self, kbuffer *buffer);

/** Validate a subpacket (FROM, TO, CC, SUBJECT, TEXT, ...)
 *
 * \param self the KSP where containing the subpacket to check.
 * \return 0 if valid, -1 otherwise.
 */
int tagcrypt_signature_check(tagcrypt_signature *self, uint8_t type, uint8_t *data, uint32_t len);

/** Get the KMO/KPS Protocol version used to sign the packet.
 *
 * \param self the KSP containing the subpacket to get.
 * \param major the returned major number.
 * \param minor the returned minor number.
 * \return 0 if valid, -1 otherwise.
 */
int tagcrypt_signature_get_proto(tagcrypt_signature *self, uint32_t *major, uint32_t *minor);

/** Get the ip address of the sender.
 *
 * \param self the KSP containing the subpacket to get.
 * \param addr the returned address of the sender.
 * \return 0 on success, -1 otherwise.
 */
int tagcrypt_signature_get_ip(tagcrypt_signature *self, struct sockaddr *addr);

/** Get the mail_client id of the sender.
 *
 * \param self the KSP containing the subpacket to get.
 * \param mailer the returned mail_client id of the sender.
 * \return 0 on success, -1 otherwise.
 */
int tagcrypt_signature_get_mail_client(tagcrypt_signature *self, struct tagcrypt_mua_params *mailer);

/** Get the symmetric key encrypted with the SeNDers signature key.
 *
 * \param self the KSP containing the subpacket to get.
 * \param key the sender's secret key.
 * \param buffer the returned decrypted serialized symkey.
 * \return 0 on success, -1 otherwise.
 */
int tagcrypt_sign_get_snd_symkey(tagcrypt_signature *self, tagcrypt_skey *key, kbuffer *buffer);

/** Get a serialized symmetric key encrypted for pod and enc that has already been decrypted.
 *
 * \param self the KSP containing the subpacket to get.
 * \param key the sender's secret key.
 * \param buffer the returned decrypted serialized symkey.
 * \return 0 on success, -1 otherwise.
 */
int tagcrypt_sign_get_symkey(tagcrypt_signature *self, tagcrypt_skey *key,
                             kbuffer *enc_symkey,
                             kbuffer *clear_symkey);

/** Get a symmetric key encrypted for a specific recipient (member).
 *
 * \param self the KSP containing the subpacket to get.
 * \param key the sender's secret key.
 * \param buffer the returned decrypted serialized symkey.
 */
int tagcrypt_sign_get_enc_symkey(tagcrypt_signature *self, tagcrypt_skey *key,
                                 kbuffer *buffer,
                                 kbuffer *user_list);

/** Check the validity of a password.
 *
 * \param self the KSP containing the passwd subpackets to check against.
 * \param skey the senders secret key used to encrypt the passwords in the KSP.
 * \param passwd the password to check.
 * \param otut the returned otut when present with the matching password.
 *             The otut structure is initialized if an otut is present.
 *             If the otut is NULL, the otut is not returned.
 *             Clean it with tagcrypt_otut_clean.
 * \return 0 on passwd match, -1 otherwise.
 */
int tagcrypt_sign_check_passwd(tagcrypt_signature *self, tagcrypt_skey *skey,
                               kbuffer *passwd,
                               struct tagcrypt_otut *otut);

int tagcrypt_signature_get_ksn(tagcrypt_signature *self, char *ksn, size_t ksn_s);

int tagcrypt_signature_get_podto(tagcrypt_signature *self, char **podto, size_t *podto_s);

uint64_t tagcrypt_signature_get_keyid(const char *raw_sign, size_t raw_sign_s);

int tagcrypt_signature_get_blob(tagcrypt_signature *self, char **blob, size_t *blob_s);

int tagcrypt_sign_get_lang(tagcrypt_signature *self, uint32_t *lang);

/* For a signed pkey */
struct tagcrypt_signed_pkey {
    uint64_t mid;
    tagcrypt_pkey *key;
    struct timeval time;
};

void tagcrypt_signed_pkey_destroy (struct tagcrypt_signed_pkey *self);
int tagcrypt_sign_get_license(tagcrypt_signature *self, 
                              uint32_t *license_lim,
                              uint32_t *license_max,
                              const char **license_kdn);

struct tagcrypt_signed_pkey *tagcrypt_sign_get_pkey (kbuffer *buffer, tagcrypt_pkey *pkey);
int tagcrypt_sign_pkey (kbuffer *buffer, tagcrypt_skey *skey, tagcrypt_pkey *pkey);

#endif /* __TAGCRYPTSIGNATURE_H__ */
