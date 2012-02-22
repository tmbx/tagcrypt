/**
 * tagcrypt/include/tagcryptlog.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt logging utilities.
 *
 * @author Kristian Benoit
 */

#ifndef __TAGCRYPTLOG_H__
#define __TAGCRYPTLOG_H__

/**
 * library names
 */
#define TC_PREFIX   "TAGCRYPT"
#define GCRY_PREFIX "LIBGCRYPT"

/** Macros to log tagcrypt errors.
 * \see logging.h in klib.
 */
#if 0
#define TC_DEBUG(...)               fprintf(stderr,  __VA_ARGS__)
#define TC_INFO(...)                fprintf(stderr,  __VA_ARGS__)
#define TC_WARNING(...)             fprintf(stderr, __VA_ARGS__)
#define TC_ERROR(...)               fprintf(stderr, __VA_ARGS__)
#define TC_CRITICAL(...)            fprintf(stderr, __VA_ARGS__)
#else
#define TC_DEBUG(...)   
#define TC_INFO(...)    
#define TC_WARNING(...) 
#define TC_ERROR(...)   
#define TC_CRITICAL(...)
#endif

/** Macros to log libgcrypt errors.
 * \see logging.h in klib.
 */
#define GCRY_DEBUG(...)             TC_DEBUG   (__VA_ARGS__)
#define GCRY_INFO(...)              TC_INFO    (__VA_ARGS__)
#define GCRY_WARNING(...)           TC_INFO    (__VA_ARGS__)
#define GCRY_ERROR(...)             TC_ERROR   (__VA_ARGS__)
#define GCRY_CRITICAL(...)          TC_CRITICAL(__VA_ARGS__)

#define MAX_STRERROR_SIZE 1024

#define LIBC_DEBUG()  {                                 \
        char buf[MAX_STRERROR_SIZE];                    \
        strerror_r(errno, buf, MAX_STRERROR_SIZE);      \
        TC_CRITICAL(buf);                               \
    }
#define LIBC_ERROR()  {                                 \
        char buf[MAX_STRERROR_SIZE];                    \
        strerror_r(errno, buf, MAX_STRERROR_SIZE);      \
        TC_CRITICAL(buf);                               \
    }
#define LIBC_INFO {                                     \
        char buf[MAX_STRERROR_SIZE];                    \
        strerror_r(errno, buf, MAX_STRERROR_SIZE);      \
        TC_CRITICAL(buf);                               \
    }
#define LIBC_WARN {                                     \
        char buf[MAX_STRERROR_SIZE];                    \
        strerror_r(errno, buf, MAX_STRERROR_SIZE);      \
        TC_CRITICAL(buf);                               \
    }
#define LIBC_CRITICAL {                                 \
        char buf[MAX_STRERROR_SIZE];                    \
        strerror_r(errno, buf, MAX_STRERROR_SIZE);      \
        TC_CRITICAL(buf);                               \
    }

#endif /* __TAGCRYPTLOG_H__ */
