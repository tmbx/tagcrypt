/**
 * tagcrypt/include/tagcryptgen.h
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt generative functions.
 *
 * @author Kristian Benoit
 */

#ifndef __TAGCRYPT_GEN_H__
#define __TAGCRYPT_GEN_H__

#include <sys/time.h>
#include <time.h>
#include <kbuffer.h>

#include "tagcryptskey.h"

/** Generate a key pair.
 *
 * \param pkey the public key encoded in base64.
 * \param skey the secret key encoded in base64.
 * \param keyid the memberid associated with this key.
 * \param size the size of the key.
 * \return 0 if there is no error -1 otherwise.
 */
int
tagcrypt_gen_public_secret(kbuffer *pkey, kbuffer *skey, uint64_t keyid, int size);

/** Generate a signature key pair.
 * A signature key pair has a size of 1024.
 *
 * \param pkey the public key encoded in base64.
 * \param skey the secret key encoded in base64.
 * \param keyid the memberid associated with this key.
 * \return 0 if there is no error -1 otherwise.
 */
static inline int tagcrypt_gen_sig_pair(kbuffer *pkey, kbuffer *skey, uint64_t keyid) {
    return tagcrypt_gen_public_secret (pkey, skey, keyid, 1024);
}

/** Generate an encryption key pair.
 * An encryption key pair has a size of 2048.
 *
 * \param pkey the public key encoded in base64.
 * \param skey the secret key encoded in base64.
 * \param keyid the memberid associated with this key.
 * \return 0 if there is no error -1 otherwise.
 */
static inline int tagcrypt_gen_enc_pair(kbuffer *pkey, kbuffer *skey, uint64_t keyid) {
    return tagcrypt_gen_public_secret (pkey, skey, keyid, 2048);
}

#endif /*__TAGCRYPT_GEN_H__*/

