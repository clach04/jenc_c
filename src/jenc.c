/*
 * libjenc - V001 jenc file format encrypt/decrypt.
 * See jenc.h for the format and jenc_crypto.c for primitives.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jenc.h"
#include "jenc_crypto.h"

const char *jenc_status_str(jenc_status status)
{
    switch (status) {
    case JENC_OK:           return "ok";
    case JENC_ERR_ARG:      return "invalid argument";
    case JENC_ERR_VERSION:  return "unsupported jenc version (only V001)";
    case JENC_ERR_FORMAT:   return "malformed jenc data (too short)";
    case JENC_ERR_AUTH:     return "MAC check failed: wrong password or corrupt data";
    case JENC_ERR_RANDOM:   return "OS random source unavailable";
    case JENC_ERR_NOMEM:    return "out of memory";
    case JENC_ERR_INTERNAL: return "internal error";
    }
    return "unknown status";
}

void jenc_free(void *p)
{
    free(p);
}

/* Derive the 256-bit AES key: PBKDF2-HMAC-SHA512(UTF-8 password, salt). */
static jenc_status derive_key(const char *password,
                              const unsigned char salt[JENC_SALT_LEN],
                              unsigned char key[JENC_KEY_LEN])
{
    if (!password) return JENC_ERR_ARG;
    return jenc_crypto_pbkdf2_sha512((const unsigned char *)password,
                                     strlen(password), salt, JENC_SALT_LEN,
                                     JENC_PBKDF2_ITER, key, JENC_KEY_LEN);
}

static jenc_status check_version(const unsigned char *in)
{
    if (memcmp(in, JENC_VERSION_STR, JENC_VERSION_LEN) != 0) {
        fprintf(stderr, "jenc: version tag %02x%02x%02x%02x is not %s\n",
                in[0], in[1], in[2], in[3], JENC_VERSION_STR);
        return JENC_ERR_VERSION;
    }
    return JENC_OK;
}

jenc_status jenc_encrypt_fixed(const char *password,
                               const unsigned char *plain, size_t plain_len,
                               const unsigned char *nonce,
                               const unsigned char *salt,
                               unsigned char **out, size_t *out_len)
{
    unsigned char key[JENC_KEY_LEN];
    unsigned char *buf;
    size_t total;
    jenc_status st;

    if (!password || !nonce || !salt || !out || !out_len) return JENC_ERR_ARG;
    if (!plain && plain_len != 0) return JENC_ERR_ARG;
    if (plain_len > ((size_t)-1) - JENC_MIN_FILE_LEN) return JENC_ERR_ARG;

    total = JENC_MIN_FILE_LEN + plain_len;
    buf = malloc(total);
    if (!buf) return JENC_ERR_NOMEM;

    memcpy(buf, JENC_VERSION_STR, JENC_VERSION_LEN);
    memcpy(buf + JENC_VERSION_LEN, nonce, JENC_NONCE_LEN);
    memcpy(buf + JENC_VERSION_LEN + JENC_NONCE_LEN, salt, JENC_SALT_LEN);

    st = derive_key(password, salt, key);
    if (st != JENC_OK) goto fail;

    st = jenc_crypto_gcm_ctr(key, nonce, JENC_NONCE_LEN, plain, plain_len,
                             buf + JENC_HEADER_LEN);
    if (st != JENC_OK) goto fail;

    st = jenc_crypto_gcm_tag(key, nonce, JENC_NONCE_LEN,
                             buf + JENC_HEADER_LEN, plain_len,
                             buf + JENC_HEADER_LEN + plain_len);
    if (st != JENC_OK) goto fail;

    jenc_crypto_wipe(key, sizeof(key));
    *out = buf;
    *out_len = total;
    return JENC_OK;

fail:
    jenc_crypto_wipe(key, sizeof(key));
    jenc_crypto_wipe(buf, total);
    free(buf);
    return st;
}

jenc_status jenc_encrypt(const char *password,
                         const unsigned char *plain, size_t plain_len,
                         unsigned char **out, size_t *out_len)
{
    unsigned char nonce[JENC_NONCE_LEN];
    unsigned char salt[JENC_SALT_LEN];
    jenc_status st;

    if (!password || !out || !out_len) return JENC_ERR_ARG;

    st = jenc_crypto_random(nonce, sizeof(nonce));
    if (st != JENC_OK) return st;
    st = jenc_crypto_random(salt, sizeof(salt));
    if (st != JENC_OK) return st;

    return jenc_encrypt_fixed(password, plain, plain_len, nonce, salt,
                              out, out_len);
}

/* Shared decrypt core. verify != 0 gates output on the GCM tag. */
static jenc_status decrypt_core(const char *password,
                                const unsigned char *in, size_t in_len,
                                int verify,
                                unsigned char **out, size_t *out_len)
{
    const unsigned char *nonce, *salt, *ct, *tag;
    size_t ct_len;
    unsigned char key[JENC_KEY_LEN];
    unsigned char calc_tag[JENC_TAG_LEN];
    unsigned char *buf;
    jenc_status st;

    if (!password || !in || !out || !out_len) return JENC_ERR_ARG;
    *out = NULL;
    *out_len = 0;

    if (in_len < JENC_MIN_FILE_LEN) {
        fprintf(stderr, "jenc: input %lu bytes, need at least %d\n",
                (unsigned long)in_len, JENC_MIN_FILE_LEN);
        return JENC_ERR_FORMAT;
    }
    st = check_version(in);
    if (st != JENC_OK) return st;

    nonce = in + JENC_VERSION_LEN;
    salt = nonce + JENC_NONCE_LEN;
    ct = in + JENC_HEADER_LEN;
    ct_len = in_len - JENC_HEADER_LEN - JENC_TAG_LEN;
    tag = in + JENC_HEADER_LEN + ct_len;

    st = derive_key(password, salt, key);
    if (st != JENC_OK) return st;

    if (verify) {
        st = jenc_crypto_gcm_tag(key, nonce, JENC_NONCE_LEN, ct, ct_len,
                                 calc_tag);
        if (st != JENC_OK) goto fail;
        if (!jenc_crypto_ct_equal(calc_tag, tag, JENC_TAG_LEN)) {
            st = JENC_ERR_AUTH;
            goto fail;
        }
    }

    buf = malloc(ct_len ? ct_len : 1);
    if (!buf) {
        st = JENC_ERR_NOMEM;
        goto fail;
    }
    st = jenc_crypto_gcm_ctr(key, nonce, JENC_NONCE_LEN, ct, ct_len, buf);
    if (st != JENC_OK) {
        jenc_crypto_wipe(buf, ct_len);
        free(buf);
        goto fail;
    }

    jenc_crypto_wipe(key, sizeof(key));
    *out = buf;
    *out_len = ct_len;
    return JENC_OK;

fail:
    jenc_crypto_wipe(key, sizeof(key));
    return st;
}

jenc_status jenc_decrypt(const char *password,
                         const unsigned char *in, size_t in_len,
                         unsigned char **out, size_t *out_len)
{
    return decrypt_core(password, in, in_len, 1, out, out_len);
}

#ifdef JENC_DEBUG_SKIP_MAC
jenc_status jenc_decrypt_skip_mac(const char *password,
                                  const unsigned char *in, size_t in_len,
                                  unsigned char **out, size_t *out_len)
{
    fprintf(stderr, "jenc: WARNING debug skip-MAC: output is UNAUTHENTICATED\n");
    return decrypt_core(password, in, in_len, 0, out, out_len);
}
#endif
