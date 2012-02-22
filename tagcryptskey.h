/**
 * tagcrypt/include/tagcryptskey.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt secret key management function.
 *
 * @author Kristian Benoit
 */

#ifndef __TAGCRYPTSKEY_H__
#define __TAGCRYPTSKEY_H__

#include <gcrypt.h>
#include <kbuffer.h>

/** An abstract secret key.
 * The secret key is used for decryption and signing.
 */
typedef struct tagcrypt_skey {
    uint64_t keyid;
    gcry_sexp_t key;
} tagcrypt_skey;

/** Serialize the secret key.
 * Get a binary buffer containing a serialized version of a secret key.
 * The buffer is binary not base64.
 *
 * \param pkey the public key to serialize.
 * \param buffer will contain the serialized pkey after success.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_skey_serialize(tagcrypt_skey *self, kbuffer *buffer);

/** Initialize a secret key.
 * Initialize a secret key from a serialized secret key (binary).
 * Use this function when initializing a static struct. Use skey_new
 * to allocate the object for you.
 *
 * \param self the secret key object to initialize.
 * \param serialized_skey the buffer containing the serialized key.
 * \return 0 on success, -1 on error
 */
int tagcrypt_skey_init(tagcrypt_skey *self, kbuffer *serialized_skey);

/** Allocate and initialize a secret key.
 * Create a secret key from a serialized secret key (binary).
 *
 * \param serialized_skey the serialize key
 * \see tagcrypt_skey_serialize ()
 * \return a newly allocated secret key object or NULL on error.
 */
tagcrypt_skey *tagcrypt_skey_new(kbuffer *serialized_skey);

/** Free ressource used by a public key.
 * Use this function when a statically allocated public key
 * (tagcrypt_pkey_init) will not be used anymore.
 *
 * \param self the public key to clean.
 */
void tagcrypt_skey_clean(tagcrypt_skey *self);

/** Delete the secret key.
 * Use this function when a dynamically allocated secret key
 * (tagcrypt_skey_new) will not be used anymore.
 *
 * \param self the secret key to destroy.
 */
void tagcrypt_skey_destroy(tagcrypt_skey     *self);

/** Decrypt data.
 * Decrypt in into out using self.
 *
 * \param self the secret key used to decrypt in (must match the public key used to encrypt).
 * \param in the data to decrypt.
 * \param out will contain the decrypted data after a successful call.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_skey_decrypt(tagcrypt_skey *self, kbuffer *in, kbuffer *out);

/** Sign data.
 *
 * \param self the secret key used to sign data.
 * \param hash_algo the algo id to use for hashing data.
 * \param data the data to sign.
 * \param signature the returned signature.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_skey_sign(tagcrypt_skey *self, uint32_t hash_algo, kbuffer *data, kbuffer *signature);

#endif /* __TAGCRYPTPKEY_H__ */

