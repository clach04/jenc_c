/*
 * Minimal config.h shim so that the openssh-portable OpenSSH openbsd-compat
 * sources (rijndael.c, sha2.c) compile standalone without running
 * the full OpenSSH configure script.
 */
#ifndef JENC_C_SHIM_CONFIG_H
#define JENC_C_SHIM_CONFIG_H

#define HAVE_STDINT_H 1
#define HAVE_STRING_H 1
#define HAVE_STDLIB_H 1

#endif /* JENC_C_SHIM_CONFIG_H */
