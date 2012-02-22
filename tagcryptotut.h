/**
 * tagcrypt/tagcryptotut.c
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * Tagcrypt OTUT management function.
 *
 * @author François-Denis Gonthier
 */

#ifndef _TAGCRYPTOTUT_H
#define _TAGCRYPTOTUT_H

#include <tagcryptsignature.h>
#include <kbuffer.h>

/** parameter passed to add an OTUT subpacket. */ 
struct tagcrypt_otut {
    struct timeval tv;

    kbuffer *addr;
    kbuffer *data;
};

struct tagcrypt_ticket {
    /** Member ID of the client demanding the ticket. */
    uint64_t mid;

    /** Timestamp of the ticket. */
    struct timeval tv;

#define TAGCRYPT_MAX_OTUT_ADDR_SIZE 2048

    /** */
    kbuffer * otut_addr;

    /** Number of replies this ticket will be valid for. */
    uint32_t reply_count;
};

void tagcrypt_otut_clean(struct tagcrypt_otut *otut);

int tagcrypt_ticket_init(struct tagcrypt_ticket * ticket);

void tagcrypt_ticket_clean(struct tagcrypt_ticket * ticket);

int tagcrypt_otut_init(struct tagcrypt_otut *otut);

int tagcrypt_otut_serialize(struct tagcrypt_otut *otut, kbuffer *out);

int tagcrypt_otut_realize(kbuffer *otut_buf, struct tagcrypt_otut *otut);

int tagcrypt_gen_otut(struct tagcrypt_ticket *ticket, struct tagcrypt_otut *otut);

/** Good for one OTUT.
 *  
 * \param skey the secret key to sign the ticket data.
 * \param nbvalid the number of OTUT this ticket will allow.
 * \param out the signed ticket as output.
 * \return 0 on error, -1 otherwise.
 */
int tagcrypt_gen_ticket(tagcrypt_skey * skey, uint32_t nbvalid, kbuffer * otut_addr,
                        kbuffer * out);

int tagcrypt_get_ticket(tagcrypt_pkey *pkey, kbuffer *sign_buffer,
                        struct tagcrypt_ticket *ticket);

#endif // _TAGCRYPTOTUT_H
