/*
 * Internal crypto primitives for libjenc.
 *
 * AES-256 block cipher and SHA-512 come from openssh-portable OpenSSH/OpenBSD code
 * (see src/openssh-portable/LICENCE). HMAC, PBKDF2, GCM and the RNG are
 * implemented in jenc_crypto.c.
 *
 * Not constant-time with respect to AES table lookups (openssh rijndael.c).
 * See TODO.md.
 */
#ifndef JENC_CRYPTO_H
#define JENC_CRYPTO_H

#include <stddef.h>

#include "jenc.h"

/* PBKDF2-HMAC-SHA512. out_len must be 1..64 (single block). iterations >= 1. */
jenc_status jenc_crypto_pbkdf2_sha512(const unsigned char *password,
                                      size_t password_len,
                                      const unsigned char *salt,
                                      size_t salt_len,
                                      unsigned int iterations,
                                      unsigned char *out, size_t out_len);

/*
 * AES-256-GCM, 128-bit tag, no AAD.
 * iv_len may be any value >= 1 (GHASH-derived J0 for iv_len != 12).
 *
 * jenc_crypto_gcm_ctr: CTR keystream XOR. in and out may alias.
 * jenc_crypto_gcm_tag: tag over ciphertext (ct, ct_len).
 *
 * Decrypt order: compute tag over input ciphertext, compare, then ctr.
 */
jenc_status jenc_crypto_gcm_ctr(const unsigned char key[JENC_KEY_LEN],
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *in, size_t len,
                                unsigned char *out);

jenc_status jenc_crypto_gcm_tag(const unsigned char key[JENC_KEY_LEN],
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *ct, size_t ct_len,
                                unsigned char tag[JENC_TAG_LEN]);

/* Constant-time comparison. Returns 1 if equal, 0 otherwise. */
int jenc_crypto_ct_equal(const unsigned char *a, const unsigned char *b,
                         size_t len);

/* Fill buf with OS random bytes. Fails hard if the OS source is unavailable. */
jenc_status jenc_crypto_random(unsigned char *buf, size_t len);

/* Zero memory in a way the optimiser may not remove. */
void jenc_crypto_wipe(void *p, size_t len);

#endif /* JENC_CRYPTO_H */
