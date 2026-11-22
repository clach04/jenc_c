/*
 * libjenc - jenc V001 file format (Markor / jpencconverter compatible).
 *
 * Format (V001):
 *   4 bytes   "V001"
 *   32 bytes  GCM nonce (IV)
 *   64 bytes  PBKDF2 salt
 *   N bytes   AES-256-GCM ciphertext
 *   16 bytes  GCM authentication tag
 *
 * Key: PBKDF2-HMAC-SHA512, 10000 iterations, 32-byte key.
 * Password: UTF-8 bytes (caller supplies a NUL-terminated UTF-8 string).
 *
 * Reference: jenc-py (jenc/__init__.py), not in this tree.
 */
#ifndef JENC_H
#define JENC_H

#include <stddef.h>

#define JENC_VERSION_STR    "V001"
#define JENC_VERSION_LEN    4
#define JENC_NONCE_LEN      32
#define JENC_SALT_LEN      64
#define JENC_TAG_LEN       16
#define JENC_KEY_LEN       32
#define JENC_PBKDF2_ITER   10000
#define JENC_HEADER_LEN    (JENC_VERSION_LEN + JENC_NONCE_LEN + JENC_SALT_LEN)
#define JENC_MIN_FILE_LEN  (JENC_HEADER_LEN + JENC_TAG_LEN)

typedef enum {
    JENC_OK = 0,
    JENC_ERR_ARG,        /* invalid argument (NULL pointer, bad length) */
    JENC_ERR_VERSION,    /* version tag is not V001 (e.g. U001, V002) */
    JENC_ERR_FORMAT,     /* file too short to hold header + tag */
    JENC_ERR_AUTH,       /* GCM tag mismatch: wrong password or corrupt data */
    JENC_ERR_RANDOM,     /* OS random source failed */
    JENC_ERR_NOMEM,      /* allocation failed */
    JENC_ERR_INTERNAL    /* internal invariant violated */
} jenc_status;

/* Human-readable name for a status code. Never NULL. */
const char *jenc_status_str(jenc_status status);

/*
 * Encrypt plaintext into a newly allocated V001 buffer.
 * On success *out is set to a buffer of *outlen bytes; free with jenc_free().
 * Random nonce and salt are taken from the OS.
 */
jenc_status jenc_encrypt(const char *password,
                         const unsigned char *plain, size_t plain_len,
                         unsigned char **out, size_t *out_len);

/*
 * Decrypt a V001 buffer. Authentication is verified before any plaintext is
 * returned: on any failure *out is NULL and no plaintext is produced.
 * On success free the result with jenc_free().
 */
jenc_status jenc_decrypt(const char *password,
                         const unsigned char *in, size_t in_len,
                         unsigned char **out, size_t *out_len);

/*
 * Encrypt with caller-supplied nonce and salt. Deterministic; for known-answer
 * tests only. Nonce must be JENC_NONCE_LEN bytes, salt JENC_SALT_LEN bytes.
 */
jenc_status jenc_encrypt_fixed(const char *password,
                               const unsigned char *plain, size_t plain_len,
                               const unsigned char *nonce,
                               const unsigned char *salt,
                               unsigned char **out, size_t *out_len);

#ifdef JENC_DEBUG_SKIP_MAC
/*
 * DEBUG BUILD ONLY (-DJENC_DEBUG_SKIP_MAC). Decrypts without verifying the
 * tag. Output is UNAUTHENTICATED; never use on real data.
 */
jenc_status jenc_decrypt_skip_mac(const char *password,
                                  const unsigned char *in, size_t in_len,
                                  unsigned char **out, size_t *out_len);
#endif

void jenc_free(void *p);

#endif /* JENC_H */
