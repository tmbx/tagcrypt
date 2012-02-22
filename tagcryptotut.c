/**
 * tagcrypt/tagcryptotut.c
 * Copyright (C) 2005-2012 Opersys inc., All rights reserved.
 *
 * Tagcrypt OTUT management function.
 *
 * @author François-Denis Gonthier
 */

#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <kbuffer.h>

#include "tagcryptskey.h"
#include "tagcryptotut.h"
#include "tagcryptsignature.h"

int tagcrypt_ticket_init(struct tagcrypt_ticket * ticket) {
    ticket->otut_addr = kbuffer_new(256);
    return 0;
}

void tagcrypt_ticket_clean(struct tagcrypt_ticket * ticket) {
    kbuffer_destroy(ticket->otut_addr);
}

/** clean an otut structure. */
void tagcrypt_otut_clean(struct tagcrypt_otut *otut) {
    kbuffer_destroy(otut->addr);
    kbuffer_destroy(otut->data);
}

/** initialize an otut structure. */
int tagcrypt_otut_init(struct tagcrypt_otut *otut) {
    otut->addr = kbuffer_new(1);
    otut->data = kbuffer_new(1);

    return 0;
}

/** KNP object identifiers. */
#define KNP_UINT32  1
#define KNP_UINT64  2
#define KNP_STR     3

/** Serialize the OTUT string. */
/* FIXME: COnvert this to use a tbuffer. */
int tagcrypt_otut_serialize(struct tagcrypt_otut *otut, kbuffer *out) {
    kbuffer_write8(out, KNP_STR);
    kbuffer_write32(out, otut->addr->len);
    kbuffer_write(out, otut->addr->data, otut->addr->len);
    kbuffer_write8(out, KNP_UINT32);
    kbuffer_write32(out, otut->tv.tv_sec);
    kbuffer_write8(out, KNP_UINT32);
    kbuffer_write32(out, otut->tv.tv_usec);
    kbuffer_write8(out, KNP_STR);
    kbuffer_write32(out, otut->data->len);
    kbuffer_write(out, otut->data->data, otut->data->len);
    
    return 0;
}

/** Read a serialized OTUT string. */
/* FIXME: Convert this to use a tbuffer. */
int tagcrypt_otut_realize(kbuffer *otut_buf, struct tagcrypt_otut *otut) {
    size_t n;
    uint8_t n8;

    if (kbuffer_read8(otut_buf, &n8)) return -1; // Reads KNP_STR

    if (kbuffer_read32(otut_buf, &n)) 
        return -1;

    if (kbuffer_read_buffer(otut_buf, otut->addr, n)) 
        return -1;

    if (kbuffer_read8(otut_buf, &n8)) return -1; // Reads KNP_UINT32

    if (kbuffer_read32(otut_buf, (uint32_t *)&otut->tv.tv_sec))
        return -1;

    if (kbuffer_read8(otut_buf, &n8)) return -1; // Reads KNP_UINT32

    if (kbuffer_read32(otut_buf, (uint32_t *)&otut->tv.tv_usec))
        return -1;

    if (kbuffer_read8(otut_buf, &n8)) return -1; // Reads KNP_STR

    if (kbuffer_read32(otut_buf, &n))
        return -1;

    if (kbuffer_read_buffer(otut_buf, otut->data, n))
        return -1;

    return 0;
}

/** Returns random data from /dev/urandom directly. 
 *
 * This function is meant to replace libgcrypt function for
 * low-security random.  We need to preserve our precious enthropy
 * pool.
 */
static int unsafe_rnd(char *buf, size_t s) {
    int fd;

    if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
        return -1;
    if ((size_t)read(fd, buf, s) < s)
        return -1;
    
    close(fd);

    return 0;
}

/** Generate an OTUT string.
 *
 * This function generates a valid OTUT string.  It can be called as
 * many time as needed to generate several OTUTs for the same ticket.
 * Don't forget to clean the OTUT when you are done with it.
 */
int tagcrypt_gen_otut(struct tagcrypt_ticket *ticket, struct tagcrypt_otut *otut) {    
    char rnd[32];

    if (gettimeofday(&otut->tv, NULL) < 0)
        return -1;
    otut->tv.tv_sec += (60 * 60 * 24 * 15);
    
    kbuffer_write(otut->addr, ticket->otut_addr->data, ticket->otut_addr->len);

    /* Write some random data. */
    if (unsafe_rnd(rnd, sizeof(rnd)) < 0)
        return -1;
    kbuffer_write(otut->data, (uint8_t *)rnd, sizeof(rnd));
    
    return 0;
}

/** Decode and validate an OTUT ticket. 
 *
 * This function validates the signature of a potential ticket and then
 * returns the data of the ticket in the ticket structure.  Don't
 * forget to clean the ticket object after calling this function.
 */
int tagcrypt_get_ticket(tagcrypt_pkey *pkey, 
                        kbuffer *sign_buffer, 
                        struct tagcrypt_ticket *ticket) {
    kbuffer *blob_buffer;
    tagcrypt_signature sign;
    struct tagcrypt_blob_params *bp;

    /* Create the signature object. */
    if (tagcrypt_signature_init_serialized(&sign, sign_buffer, pkey) < 0)
        return -1;
    
    do {
        /* Get the blob of the signature. */
        if (sign.subpackets[TAG_SP_TYPE_BLOB] != NULL) {
            
            bp = (struct tagcrypt_blob_params *)sign.subpackets[TAG_SP_TYPE_BLOB]->spkt;
            blob_buffer = bp->blob;

            /* Read the MID, timeval, and OTUT address size. */
            if (kbuffer_read64(blob_buffer, &ticket->mid) ||
		kbuffer_read(blob_buffer, (uint8_t *)&ticket->tv, sizeof(struct timeval)) ||
		kbuffer_read_serialized(blob_buffer, ticket->otut_addr) ||
		kbuffer_read32(blob_buffer, &ticket->reply_count)) {
                break;
	    }

            tagcrypt_sign_clean(&sign);
            return 0;

        } else
            break;

    } while (0);

    tagcrypt_sign_clean(&sign);
    return -1;
}

/** Generate a ticket good for one OTUT.
 *
 * This function generates a ticket suitable to obtain an OTUT
 * on the Online Ticket Server and put it in a signature object as a blob
 * subpacket.  The signature object should not contain any other
 * subpackets.  The ticket is returned in the buffer 'out'.
 */
int tagcrypt_gen_ticket(tagcrypt_skey *skey, uint32_t reply_count, 
                        kbuffer *otut_addr,
                        kbuffer *out) {
    int r = 0;
    struct tagcrypt_ticket ticket;
    kbuffer *ticket_buffer = NULL;
    tagcrypt_signature *ticket_sign;
    struct tagcrypt_blob_params bp;

    if (gettimeofday(&ticket.tv, NULL) < 0) 
        return -1;
    
    do {
        /* Create the signature which will hold the ticket. */
        if ((ticket_sign = tagcrypt_sign_new(TAG_P_TYPE_SIGN, 2, 1, skey)) == NULL) {
            r = -1;
            break;
        }

        ticket.mid = skey->keyid;
        ticket.reply_count = reply_count;        
        ticket.otut_addr = otut_addr;
        
        /* Create a buffer for the ticket data. */
        ticket_buffer = kbuffer_new(256);

        /* Write the ticket data in the buffer. */
        kbuffer_write64(ticket_buffer, ticket.mid);
        kbuffer_write(ticket_buffer, (uint8_t *)&ticket.tv, sizeof(struct timeval));
        kbuffer_serialize(otut_addr, ticket_buffer);
        kbuffer_write32(ticket_buffer, reply_count);

        bp.type = 0;
        bp.blob = ticket_buffer;

        /* Add the signature data as a BLOB. */
        if (tagcrypt_sign_add_subpacket(ticket_sign, TAG_SP_TYPE_BLOB, &bp) < 0) {
            r = -1;
            break;
        }

        /* Serialize the signed ticket. */
        tagcrypt_sign_serialize(ticket_sign, out);

    } while (0);

    if (ticket_sign != NULL)
        tagcrypt_sign_destroy(ticket_sign);
    if (ticket_buffer != NULL)
        kbuffer_destroy(ticket_buffer);

    return r;
}
