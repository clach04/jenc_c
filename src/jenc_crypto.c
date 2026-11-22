/*
 * Internal crypto for libjenc: HMAC-SHA512, PBKDF2, AES-256-GCM, RNG.
 *
 * Built on openssh-portable AES (openssh rijndael.c) and SHA-512 (openbsd sha2.c).
 * See jenc_crypto.h and TODO.md for the constant-time caveat.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "jenc_crypto.h"

#include "openssh-portable/rijndael.h"
#include "openbsd-compat/bsd-sha2.h"

#define AES_BLOCK 16
#define SHA512_BLK SHA512_BLOCK_LENGTH   /* 128 */
#define SHA512_DIG SHA512_DIGEST_LENGTH  /* 64 */

/* ---------- AES-256 ---------- */

typedef struct {
    unsigned int rk[4 * (AES_MAXROUNDS + 1)];
    int nr;
} aes_ctx;

static jenc_status aes_init(aes_ctx *ctx, const unsigned char key[JENC_KEY_LEN])
{
    ctx->nr = rijndaelKeySetupEnc(ctx->rk, key, 256);
    if (ctx->nr != 14) {
        fprintf(stderr, "jenc_crypto: AES key setup returned Nr=%d, expected 14\n",
                ctx->nr);
        return JENC_ERR_INTERNAL;
    }
    return JENC_OK;
}

static void aes_encrypt_block(const aes_ctx *ctx, const unsigned char in[AES_BLOCK],
                              unsigned char out[AES_BLOCK])
{
    rijndaelEncrypt(ctx->rk, ctx->nr, in, out);
}

/* ---------- SHA-512 / HMAC / PBKDF2 ---------- */

static void sha512(const unsigned char *data, size_t len,
                   unsigned char digest[SHA512_DIG])
{
    SHA2_CTX ctx;
    SHA512Init(&ctx);
    SHA512Update(&ctx, data, len);
    SHA512Final(digest, &ctx);
    jenc_crypto_wipe(&ctx, sizeof(ctx));
}

/* HMAC-SHA512 over two message parts (m1 || m2) to avoid a concat buffer. */
static void hmac_sha512(const unsigned char *key, size_t key_len,
                        const unsigned char *m1, size_t m1_len,
                        const unsigned char *m2, size_t m2_len,
                        unsigned char out[SHA512_DIG])
{
    unsigned char kblock[SHA512_BLK];
    unsigned char pad[SHA512_BLK];
    unsigned char inner[SHA512_DIG];
    SHA2_CTX ctx;
    size_t i;

    memset(kblock, 0, sizeof(kblock));
    if (key_len > SHA512_BLK) {
        sha512(key, key_len, kblock);  /* digest is 64 bytes, rest stays zero */
    } else {
        memcpy(kblock, key, key_len);
    }

    for (i = 0; i < SHA512_BLK; i++) pad[i] = kblock[i] ^ 0x36;
    SHA512Init(&ctx);
    SHA512Update(&ctx, pad, SHA512_BLK);
    SHA512Update(&ctx, m1, m1_len);
    SHA512Update(&ctx, m2, m2_len);
    SHA512Final(inner, &ctx);

    for (i = 0; i < SHA512_BLK; i++) pad[i] = kblock[i] ^ 0x5c;
    SHA512Init(&ctx);
    SHA512Update(&ctx, pad, SHA512_BLK);
    SHA512Update(&ctx, inner, SHA512_DIG);
    SHA512Final(out, &ctx);

    jenc_crypto_wipe(&ctx, sizeof(ctx));
    jenc_crypto_wipe(kblock, sizeof(kblock));
    jenc_crypto_wipe(pad, sizeof(pad));
    jenc_crypto_wipe(inner, sizeof(inner));
}

jenc_status jenc_crypto_pbkdf2_sha512(const unsigned char *password,
                                      size_t password_len,
                                      const unsigned char *salt,
                                      size_t salt_len,
                                      unsigned int iterations,
                                      unsigned char *out, size_t out_len)
{
    unsigned char u[SHA512_DIG];
    unsigned char t[SHA512_DIG];
    unsigned char ctr[4];
    unsigned int it;
    size_t i;

    if (!password || !salt || !out) return JENC_ERR_ARG;
    if (iterations < 1) return JENC_ERR_ARG;
    if (out_len < 1 || out_len > SHA512_DIG) {
        fprintf(stderr, "jenc_crypto: PBKDF2 out_len %lu outside 1..%d\n",
                (unsigned long)out_len, SHA512_DIG);
        return JENC_ERR_ARG;
    }

    /* Single block: INT(1). out_len <= hLen so only T_1 is needed. */
    ctr[0] = 0; ctr[1] = 0; ctr[2] = 0; ctr[3] = 1;
    hmac_sha512(password, password_len, salt, salt_len, ctr, sizeof(ctr), u);
    memcpy(t, u, SHA512_DIG);
    for (it = 1; it < iterations; it++) {
        hmac_sha512(password, password_len, u, SHA512_DIG, NULL, 0, u);
        for (i = 0; i < SHA512_DIG; i++) t[i] ^= u[i];
    }
    memcpy(out, t, out_len);

    jenc_crypto_wipe(u, sizeof(u));
    jenc_crypto_wipe(t, sizeof(t));
    return JENC_OK;
}

/* ---------- GHASH / GCM ---------- */

/* z = x * h in GF(2^128), NIST SP 800-38D algorithm 1. Branch-free. */
static void gf128_mul(unsigned char x[16], const unsigned char h[16])
{
    unsigned char z[16];
    unsigned char v[16];
    int i, j;

    memset(z, 0, sizeof(z));
    memcpy(v, h, 16);
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            unsigned char bit = (unsigned char)((x[i] >> j) & 1u);
            unsigned char mask = (unsigned char)(0u - bit);
            unsigned char lsb;
            int k;
            for (k = 0; k < 16; k++) z[k] ^= (unsigned char)(v[k] & mask);
            lsb = (unsigned char)(0u - (v[15] & 1u));
            for (k = 15; k > 0; k--) {
                v[k] = (unsigned char)((v[k] >> 1) | ((v[k - 1] & 1u) << 7));
            }
            v[0] = (unsigned char)(v[0] >> 1);
            v[0] ^= (unsigned char)(0xe1 & lsb);
        }
    }
    memcpy(x, z, 16);
}

/* Y = (Y ^ block) * H for each 16-byte block; partial final block zero-padded. */
static void ghash_absorb(unsigned char y[16], const unsigned char h[16],
                         const unsigned char *data, size_t len)
{
    size_t off = 0;
    int k;
    while (off < len) {
        unsigned char blk[16];
        size_t n = len - off < 16 ? len - off : 16;
        memset(blk, 0, sizeof(blk));
        memcpy(blk, data + off, n);
        for (k = 0; k < 16; k++) y[k] ^= blk[k];
        gf128_mul(y, h);
        off += n;
    }
}

static void put_u64_be(unsigned char *p, uint64_t v)
{
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (unsigned char)(v & 0xff);
        v >>= 8;
    }
}

/* Compute H = E_K(0^128) and J0 for the given IV. */
static jenc_status gcm_setup(const unsigned char key[JENC_KEY_LEN],
                             const unsigned char *iv, size_t iv_len,
                             aes_ctx *aes, unsigned char h[16],
                             unsigned char j0[16])
{
    unsigned char zero[16];
    jenc_status st;

    if (!iv || iv_len < 1) return JENC_ERR_ARG;
    st = aes_init(aes, key);
    if (st != JENC_OK) return st;

    memset(zero, 0, sizeof(zero));
    aes_encrypt_block(aes, zero, h);

    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        unsigned char lenblk[16];
        memset(j0, 0, 16);
        ghash_absorb(j0, h, iv, iv_len);
        memset(lenblk, 0, sizeof(lenblk));
        put_u64_be(lenblk + 8, (uint64_t)iv_len * 8u);
        for (size_t k = 0; k < 16; k++) j0[k] ^= lenblk[k];
        gf128_mul(j0, h);
    }
    return JENC_OK;
}

static void inc32(unsigned char ctr[16])
{
    int i;
    for (i = 15; i >= 12; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
}

jenc_status jenc_crypto_gcm_ctr(const unsigned char key[JENC_KEY_LEN],
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *in, size_t len,
                                unsigned char *out)
{
    aes_ctx aes;
    unsigned char h[16], j0[16], ctr[16], ks[16];
    jenc_status st;
    size_t off = 0;

    if (!key || !in || !out) return JENC_ERR_ARG;
    st = gcm_setup(key, iv, iv_len, &aes, h, j0);
    if (st != JENC_OK) return st;

    memcpy(ctr, j0, 16);
    while (off < len) {
        size_t n = len - off < 16 ? len - off : 16;
        size_t k;
        inc32(ctr);
        aes_encrypt_block(&aes, ctr, ks);
        for (k = 0; k < n; k++) out[off + k] = in[off + k] ^ ks[k];
        off += n;
    }

    jenc_crypto_wipe(&aes, sizeof(aes));
    jenc_crypto_wipe(h, sizeof(h));
    jenc_crypto_wipe(j0, sizeof(j0));
    jenc_crypto_wipe(ctr, sizeof(ctr));
    jenc_crypto_wipe(ks, sizeof(ks));
    return JENC_OK;
}

jenc_status jenc_crypto_gcm_tag(const unsigned char key[JENC_KEY_LEN],
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *ct, size_t ct_len,
                                unsigned char tag[JENC_TAG_LEN])
{
    aes_ctx aes;
    unsigned char h[16], j0[16], s[16], ej0[16], lenblk[16];
    jenc_status st;
    int k;

    if (!key || !ct || !tag) return JENC_ERR_ARG;
    st = gcm_setup(key, iv, iv_len, &aes, h, j0);
    if (st != JENC_OK) return st;

    /* S = GHASH(H, A = empty, C) with length block [0]64 || [len(C)]64 */
    memset(s, 0, sizeof(s));
    ghash_absorb(s, h, ct, ct_len);
    memset(lenblk, 0, sizeof(lenblk));
    put_u64_be(lenblk + 8, (uint64_t)ct_len * 8u);
    for (k = 0; k < 16; k++) s[k] ^= lenblk[k];
    gf128_mul(s, h);

    aes_encrypt_block(&aes, j0, ej0);
    for (k = 0; k < JENC_TAG_LEN; k++) tag[k] = s[k] ^ ej0[k];

    jenc_crypto_wipe(&aes, sizeof(aes));
    jenc_crypto_wipe(h, sizeof(h));
    jenc_crypto_wipe(j0, sizeof(j0));
    jenc_crypto_wipe(s, sizeof(s));
    jenc_crypto_wipe(ej0, sizeof(ej0));
    return JENC_OK;
}

/* ---------- utilities ---------- */

int jenc_crypto_ct_equal(const unsigned char *a, const unsigned char *b,
                         size_t len)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < len; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

jenc_status jenc_crypto_random(unsigned char *buf, size_t len)
{
    if (!buf) return JENC_ERR_ARG;
    if (len == 0) return JENC_OK;
#ifdef _WIN32
    if (len > 0xffffffffu) {
        fprintf(stderr, "jenc_crypto: random request %lu too large\n",
                (unsigned long)len);
        return JENC_ERR_ARG;
    }
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, buf, (ULONG)len,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        fprintf(stderr, "jenc_crypto: BCryptGenRandom failed\n");
        return JENC_ERR_RANDOM;
    }
#else
    {
        int fd = open("/dev/urandom", O_RDONLY);
        size_t off = 0;
        if (fd < 0) {
            fprintf(stderr, "jenc_crypto: cannot open /dev/urandom\n");
            return JENC_ERR_RANDOM;
        }
        while (off < len) {
            ssize_t n = read(fd, buf + off, len - off);
            if (n <= 0) {
                fprintf(stderr, "jenc_crypto: short read from /dev/urandom\n");
                close(fd);
                return JENC_ERR_RANDOM;
            }
            off += (size_t)n;
        }
        close(fd);
    }
#endif
    return JENC_OK;
}

void jenc_crypto_wipe(void *p, size_t len)
{
#ifdef _WIN32
    SecureZeroMemory(p, len);
#else
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) *vp++ = 0;
#endif
}

/* Required by openssh-portable openbsd-compat/sha2.c (declared in the shim). */
void explicit_bzero(void *p, size_t n)
{
    jenc_crypto_wipe(p, n);
}
