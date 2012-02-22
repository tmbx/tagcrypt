/**
 * tagcrypt/tagcrypt.c
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt initialization
 *
 * @author Kristian Benoit
 */

#include <gcrypt.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <kmem.h>
#include <kbuffer.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

/** GCRYPT out-of-core handler.
 *
 * Called by libgcrypt when his internal memory handler fails.
 */
static int tagcrypt_gcry_outofcore_handler(void *p, size_t s, uint32_t flag) {
    p = p;
    s = s;
    flag = flag;
    kmem_outofmem();
    return -1;
}

/** Tagcrypt initialization.
 *
 * This function can be called many times without harm.
 */
void tagcrypt_init() {
    gcry_set_outofcore_handler(tagcrypt_gcry_outofcore_handler, NULL);

    gcry_check_version (NULL);
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    gcry_control (GCRYCTL_INIT_SECMEM, 4096);
    gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM); 
}
