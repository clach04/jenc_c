/*
 * Minimal replacement for OpenSSH's openbsd-compat includes.h.
 *
 * openssh-portable sources (rijndael.c, sha2.c, bsd-sha2.h) do `#include "includes.h"`;
 * this shim satisfies that without dragging in the rest of OpenSSH.
 * Compile with this directory FIRST on the include search path.
 */
#ifndef JENC_C_SHIM_INCLUDES_H
#define JENC_C_SHIM_INCLUDES_H

#include "config.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* BSD-style types used by rijndael.h / bsd-sha2.h */
typedef unsigned char u_char;
typedef uint8_t  u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

/* sha2.c requires BYTE_ORDER to be LITTLE_ENDIAN or BIG_ENDIAN */
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN    4321
#endif
#ifndef BYTE_ORDER
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#endif

/* sha2.c calls explicit_bzero(); provided by jenc_crypto.c (volatile wipe).
 * Declared here so the openssh-portable file needs no explicit_bzero.c. */
void explicit_bzero(void *p, size_t n);

#endif /* JENC_C_SHIM_INCLUDES_H */
