/**
 * tagcrypt/include/tagcryptsymkey.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt symmetric key management functions
 *
 * @author Kristian Benoit.
 */

#ifndef __TAGCRYPT_SYMKEY_H__
#define __TAGCRYPT_SYMKEY_H__

#include <gcrypt.h>
#include <kbuffer.h>

/** A symmetric key.
 * A symmetric key is used for encrypting/decrypting data.
 */
typedef struct tagcrypt_symkey {
    int cipher;             /** the cipher identifier */
    int mode;               /** the cipher mode to use */
    size_t key_len;         /** the length in byte of the key */
    size_t block_len;       /** the length in byte of a block cipher */
    char *key;           /** the key */
    char *iv;            /** the initialization vector */
    gcry_cipher_hd_t hd;    /** a handle to the implementation of the cipher */
} tagcrypt_symkey;

/** Serialize a symmetric key.
 * Get a binary buffer containing a serialized version of a public key.
 * The buffer is binary not base64.
 *
 * \param pkey the public key to serialize.
 * \param buffer will contain the serialized pkey after success.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_symkey_serialize(tagcrypt_symkey *self, kbuffer *buffer);

/** Release ressources used by a symkey.
 * Use for statically allocated symkey.
 *
 * \param self the symmetric key to release.
 */
void tagcrypt_symkey_clean(tagcrypt_symkey *self);

/** Initialize a symmetric key object.
 *
 * \param self the symmetric key returned.
 * \param cipher the cipher identifier to use.
 * \param mode the cipher mode to use.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_symkey_init(tagcrypt_symkey *self, int cipher, int mode);

/** Initialize an existing symmetric key.
 * Initialize a symmetric key that was previously serialized with
 * tagcrypt_symkey_serialize.
 *
 * \param self the symmetric key to initialize.
 * \param buffer the serialized symmetric key.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_symkey_init_serialized(tagcrypt_symkey *self, kbuffer *buffer);

/** Initialize a symmetric key with new data.
 *
 * \param self the symmetric key returned.
 * \param cipher the cipher identifier to use.
 * \param mode the cipher mode to use.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_symkey_init_new(tagcrypt_symkey *self, int cipher, int mode);

/** Allocate and initialize a new symmetric key.
 *
 * \param cipher the cipher identifier to use.
 * \param mode the cipher mode to use.
 * \return the newly created symmetric key on success, NULL on error.
 */
tagcrypt_symkey *tagcrypt_symkey_new_full(int cipher, int mode);

/** Allocate and initialize a symmetric key from a serialized symmetric key.
 *
 * \param buffer the serialized symmetric key.
 * \return the newly created symmetric key on success, NULL on error.
 */
tagcrypt_symkey *tagcrypt_symkey_new_serialized(kbuffer *buffer);

/** Deallocate all ressources used by a symmetric key.
 * Deallocate all ressources used by a symmetric key created with
 * tagcrypt_symkey_new_serialized, tagcrtyp_symkey_new_full or
 * tagcrypt_symkey_new.
 * 
 * 
 *
 * \param self the symmetric key to destroy.
 */
void tagcrypt_symkey_destroy(tagcrypt_symkey *self);

/** Encrypt data with a symmetric key.
 *
 * \param self the symmetric key used to encrypt.
 * \param in the data to encrypt.
 * \param out the encrypted data returned.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_symkey_encrypt(tagcrypt_symkey *self, kbuffer *in, kbuffer *out);

/** Decrypt data with a symmetric key.
 *
 * \param self the symmetric key used to decrypt.
 * \param in the data to decrypt.
 * \param out the decrypted data returned.
 * \return 0 on success, -1 on error.
 */
int tagcrypt_symkey_decrypt(tagcrypt_symkey *self, kbuffer *in, kbuffer *out);

/** Allocate and initialize a new symmetric key.
 * Allocate and initialize a new symmetric key using the default cipher/mode.
 *
 * \return the newly created symmetric key on success, NULL on error.
 */
static inline
tagcrypt_symkey *tagcrypt_symkey_new() {
    return tagcrypt_symkey_new_full(GCRY_CIPHER_RIJNDAEL, GCRY_CIPHER_MODE_CBC);
}

#endif /*__TAGCRYPT_SYMKEY_H__*/
