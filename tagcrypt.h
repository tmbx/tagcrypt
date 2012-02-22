/**
 * tagcrypt/include/tagcrypt.h
 * Copyright (C) 2006-2012 Opersys inc., All rights reserved.
 *
 * tagcrypt main header file
 *
 * @author Kristian Benoit.
 * @author François-Denis Gonthier
 */

#ifndef __TAGCRYPT_H__
#define __TAGCRYPT_H__

#include <ctype.h>

#include "tagcryptgen.h"
#include "tagcryptlog.h"
#include "tagcryptpkey.h"
#include "tagcryptsignature.h"
#include "tagcryptskey.h"
#include "tagcryptsymkey.h"
#include "tagcryptotut.h"

/**
 * Call this function to initialize the library.
 */
void tagcrypt_init();

#endif //__TAGCRYPT_H__
