/**
 * tagcrypt/include/tagcryptpkey.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt public key management functions.
 *
 * @author Kristian Benoit
 */

#ifndef __TAGCRYPTPKEY_H__
#define __TAGCRYPTPKEY_H__

#include <gcrypt.h>
#include <kbuffer.h>

/** The different uses of a key
 */
enum key_type {
    KEY_TYPE_MASTER = 0,
    KEY_TYPE_TIMESTAMP = 1,
    KEY_TYPE_IDENTITY = 2,
    KEY_TYPE_ENCRYPTION = 3,
};

/** An abstract public key.
 * The public key is used for encryption and verifications.
 */
typedef struct tagcrypt_pkey {
    uint64_t keyid;
    enum key_type type;
    gcry_sexp_t key;
} tagcrypt_pkey;

/** Serialize the public key.
 * Get a binary buffer containing a serialized version of a public key.
 * The buffer is binary not base64. This is the format for signing keys.
 *
 * \param pkey the public key to serialize.
 * \param buffer will contain the serialized pkey after success.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_pkey_wire_serialize(tagcrypt_pkey *pkey, kbuffer *buffer);

/** Serialize the public key.
 * Get a binary buffer containing a serialized version of a public key.
 * The buffer is binary not base64. This is the format in the DB.
 *
 * \param pkey the public key to serialize.
 * \param buffer will contain the serialized pkey after success.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_pkey_serialize(tagcrypt_pkey *pkey, kbuffer *buffer);

/** Initialize a public key.
 * Initialize a public key from a serialized public key (binary).
 * Use this function when initializing a static struct. Use pkey_new
 * to allocate the object for you.
 *
 * \param self the public key object to initialize.
 * \param serialized_pkey the buffer containing the serialized key.
 * \return 0 on success, -1 on error
 */
int tagcrypt_pkey_wire_init(tagcrypt_pkey *self, kbuffer *wired_pkey);

/** Initialize a public key.
 * Initialize a public key from a serialized public key (binary).
 * Use this function when initializing a static struct. Use pkey_new
 * to allocate the object for you.
 *
 * \param self the public key object to initialize.
 * \param serialized_pkey the buffer containing the serialized key.
 * \return 0 on success, -1 on error
 */
int tagcrypt_pkey_init(tagcrypt_pkey *self, kbuffer *serialized_pkey, enum key_type type);

/** Allocate and initialize a public key.
 * Create a public key from a wire serialized public key (binary).
 *
 * \param serialized_pkey the serialize key
 * \see tagcrypt_pkey_wire_serialize ()
 * \return a newly allocated public key object or NULL on error.
 */
tagcrypt_pkey *tagcrypt_pkey_wire_new(kbuffer *wired_pkey);

/** Allocate and initialize a public key.
 * Create a public key from a serialized public key (binary).
 *
 * \param serialized_pkey the serialize key
 * \see tagcrypt_pkey_serialize ()
 * \return a newly allocated public key object or NULL on error.
 */
tagcrypt_pkey *tagcrypt_pkey_new(kbuffer *serialized_pkey, enum key_type type);

/** Free ressource used by a public key.
 * Use this function when a statically allocated public key
 * (tagcrypt_pkey_init) will not be used anymore.
 *
 * \param self the public key to clean.
 */
void tagcrypt_pkey_clean(tagcrypt_pkey *self);

/** Delete the public key.
 * Use this function when a dynamically allocated public key
 * (tagcrypt_pkey_new) will not be used anymore.
 *
 * \param self the public key to destroy.
 */
void tagcrypt_pkey_destroy(tagcrypt_pkey *self);

/** Encrypt data.
 * Encrypt in into out using self.
 *
 * \param self the public use to encrypt in.
 * \param in the data to encrypt.
 * \param out will contain the encrypted data after a successful call.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_pkey_encrypt(tagcrypt_pkey *self, kbuffer *in, kbuffer *out);

/** Verify a signature.
 *
 * \param self the pkey used to validate the signature.
 * \param hashed_data the data to validate (hashed).
 * \param signature, the signature of the data (preceded by a 32 bits length).
 * \return 0 on success, -1 on error.
 */
int tagcrypt_pkey_verify(tagcrypt_pkey *self, uint32_t hash_algo,
                         kbuffer *hashed_data, kbuffer *signature);

#endif /* __TAGCRYPTPKEY_H__ */

