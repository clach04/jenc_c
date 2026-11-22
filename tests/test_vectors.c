/*
 * Test program for libjenc (V001).
 *
 * Vectors come from jenc-py tests/data (copied to tests/data):
 *   Test3.md.jenc                  password "geheim" -> Test3.md
 *   test.v001_winnewlines.md.jenc  password "geheim" -> test.v001.md
 *
 * Run from the jenc_c directory: `make test`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jenc.h"
#include "jenc_crypto.h"

#define VECTOR_PASSWORD "geheim"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do {                                   \
        checks++;                                               \
        if (!(cond)) {                                          \
            failures++;                                         \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);\
            fprintf(stderr, __VA_ARGS__);                       \
            fprintf(stderr, "\n");                              \
        }                                                       \
    } while (0)

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    size_t n, cap = 65536, off = 0;

    if (!f) {
        fprintf(stderr, "test: cannot open %s\n", path);
        exit(2);
    }
    buf = malloc(cap);
    if (!buf) {
        fprintf(stderr, "test: out of memory reading %s\n", path);
        exit(2);
    }
    while ((n = fread(buf + off, 1, cap - off, f)) > 0) {
        off += n;
        if (off == cap) {
            cap *= 2;
            buf = realloc(buf, cap);
            if (!buf) {
                fprintf(stderr, "test: out of memory growing buffer\n");
                exit(2);
            }
        }
    }
    fclose(f);
    *len = off;
    return buf;
}

/* Decrypt a vector file and compare to its plaintext file, byte-exact. */
static void check_decrypt_vector(const char *jenc_path, const char *plain_path)
{
    size_t in_len, plain_len, out_len;
    unsigned char *in, *plain, *out = NULL;
    jenc_status st;

    in = read_file(jenc_path, &in_len);
    plain = read_file(plain_path, &plain_len);
    st = jenc_decrypt(VECTOR_PASSWORD, in, in_len, &out, &out_len);
    CHECK(st == JENC_OK, "decrypt %s: %s", jenc_path, jenc_status_str(st));
    if (st == JENC_OK) {
        CHECK(out_len == plain_len, "decrypt %s: length %lu, expected %lu",
              jenc_path, (unsigned long)out_len, (unsigned long)plain_len);
        CHECK(out_len == plain_len && memcmp(out, plain, plain_len) == 0,
              "decrypt %s: content differs from %s", jenc_path, plain_path);
        jenc_free(out);
    }
    free(in);
    free(plain);
}

/*
 * Re-encrypt the plaintext with the nonce and salt taken from the vector.
 * Output must equal the vector byte-for-byte (encrypt KAT).
 */
static void check_encrypt_vector(const char *jenc_path, const char *plain_path)
{
    size_t in_len, plain_len, out_len;
    unsigned char *in, *plain, *out = NULL;
    jenc_status st;

    in = read_file(jenc_path, &in_len);
    plain = read_file(plain_path, &plain_len);
    if (in_len < JENC_HEADER_LEN + JENC_TAG_LEN) {
        CHECK(0, "vector %s too short", jenc_path);
        free(in);
        free(plain);
        return;
    }
    st = jenc_encrypt_fixed(VECTOR_PASSWORD, plain, plain_len,
                            in + JENC_VERSION_LEN,
                            in + JENC_VERSION_LEN + JENC_NONCE_LEN,
                            &out, &out_len);
    CHECK(st == JENC_OK, "encrypt_fixed %s: %s", jenc_path, jenc_status_str(st));
    if (st == JENC_OK) {
        CHECK(out_len == in_len, "encrypt %s: length %lu, expected %lu",
              jenc_path, (unsigned long)out_len, (unsigned long)in_len);
        CHECK(out_len == in_len && memcmp(out, in, in_len) == 0,
              "encrypt %s: bytes differ from vector", jenc_path);
        jenc_free(out);
    }
    free(in);
    free(plain);
}

static void check_wrong_password(const char *jenc_path)
{
    size_t in_len, out_len;
    unsigned char *in, *out = NULL;
    jenc_status st;

    in = read_file(jenc_path, &in_len);
    st = jenc_decrypt("wrong password", in, in_len, &out, &out_len);
    CHECK(st == JENC_ERR_AUTH, "wrong password: expected AUTH, got %s",
          jenc_status_str(st));
    CHECK(out == NULL && out_len == 0, "wrong password: output not cleared");
    free(in);
}

/* Flip one bit at byte offset pos; decrypt must fail with AUTH and no output. */
static void check_bit_flip(const unsigned char *good, size_t len, size_t pos,
                           const char *what)
{
    unsigned char *bad = malloc(len);
    unsigned char *out = NULL;
    size_t out_len = 0;
    jenc_status st;

    if (!bad) {
        fprintf(stderr, "test: out of memory\n");
        exit(2);
    }
    memcpy(bad, good, len);
    bad[pos] ^= 0x01;
    st = jenc_decrypt(VECTOR_PASSWORD, bad, len, &out, &out_len);
    CHECK(st == JENC_ERR_AUTH, "bit flip in %s (offset %lu): expected AUTH, got %s",
          what, (unsigned long)pos, jenc_status_str(st));
    CHECK(out == NULL, "bit flip in %s: plaintext returned", what);
    free(bad);
}

static void check_tamper(const char *jenc_path)
{
    size_t len;
    unsigned char *good = read_file(jenc_path, &len);
    size_t ct_len = len - JENC_HEADER_LEN - JENC_TAG_LEN;

    /* nonce: first, middle, last byte */
    check_bit_flip(good, len, JENC_VERSION_LEN, "nonce[0]");
    check_bit_flip(good, len, JENC_VERSION_LEN + JENC_NONCE_LEN / 2, "nonce[mid]");
    check_bit_flip(good, len, JENC_VERSION_LEN + JENC_NONCE_LEN - 1, "nonce[31]");
    /* salt */
    check_bit_flip(good, len, JENC_HEADER_LEN - JENC_SALT_LEN, "salt[0]");
    check_bit_flip(good, len, JENC_HEADER_LEN - 1, "salt[63]");
    /* ciphertext */
    if (ct_len > 0) {
        check_bit_flip(good, len, JENC_HEADER_LEN, "ct[0]");
        check_bit_flip(good, len, JENC_HEADER_LEN + ct_len - 1, "ct[last]");
    }
    /* tag */
    check_bit_flip(good, len, len - JENC_TAG_LEN, "tag[0]");
    check_bit_flip(good, len, len - 1, "tag[15]");
    free(good);
}

static void check_truncated(const char *jenc_path)
{
    size_t len;
    unsigned char *good = read_file(jenc_path, &len);
    unsigned char *out = NULL;
    size_t out_len = 0;
    jenc_status st;

    st = jenc_decrypt(VECTOR_PASSWORD, good, JENC_MIN_FILE_LEN - 1, &out, &out_len);
    CHECK(st == JENC_ERR_FORMAT, "truncated to %d: expected FORMAT, got %s",
          JENC_MIN_FILE_LEN - 1, jenc_status_str(st));

    st = jenc_decrypt(VECTOR_PASSWORD, good, len - 1, &out, &out_len);
    CHECK(st == JENC_ERR_AUTH, "truncated by 1 byte: expected AUTH, got %s",
          jenc_status_str(st));
    free(good);
}

static void check_bad_version(const char *jenc_path)
{
    size_t len;
    unsigned char *good = read_file(jenc_path, &len);
    unsigned char *out = NULL;
    size_t out_len = 0;
    jenc_status st;

    memcpy(good, "U001", 4);
    st = jenc_decrypt(VECTOR_PASSWORD, good, len, &out, &out_len);
    CHECK(st == JENC_ERR_VERSION, "U001 tag: expected VERSION, got %s",
          jenc_status_str(st));

    memcpy(good, "V002", 4);
    st = jenc_decrypt(VECTOR_PASSWORD, good, len, &out, &out_len);
    CHECK(st == JENC_ERR_VERSION, "V002 tag: expected VERSION, got %s",
          jenc_status_str(st));
    free(good);
}

static void check_round_trip(size_t plain_len)
{
    unsigned char *plain = malloc(plain_len ? plain_len : 1);
    unsigned char *enc = NULL, *dec = NULL;
    size_t enc_len = 0, dec_len = 0, i;
    jenc_status st;

    if (!plain) {
        fprintf(stderr, "test: out of memory\n");
        exit(2);
    }
    for (i = 0; i < plain_len; i++) plain[i] = (unsigned char)(i * 31 + 7);

    st = jenc_encrypt("roundtrip pw", plain, plain_len, &enc, &enc_len);
    CHECK(st == JENC_OK, "round trip %lu: encrypt %s",
          (unsigned long)plain_len, jenc_status_str(st));
    if (st == JENC_OK) {
        CHECK(enc_len == JENC_MIN_FILE_LEN + plain_len,
              "round trip %lu: encrypted length %lu",
              (unsigned long)plain_len, (unsigned long)enc_len);
        CHECK(memcmp(enc, JENC_VERSION_STR, JENC_VERSION_LEN) == 0,
              "round trip %lu: version tag missing", (unsigned long)plain_len);

        st = jenc_decrypt("roundtrip pw", enc, enc_len, &dec, &dec_len);
        CHECK(st == JENC_OK, "round trip %lu: decrypt %s",
              (unsigned long)plain_len, jenc_status_str(st));
        if (st == JENC_OK) {
            CHECK(dec_len == plain_len && (plain_len == 0 || memcmp(dec, plain, plain_len) == 0),
                  "round trip %lu: plaintext mismatch", (unsigned long)plain_len);
            jenc_free(dec);
        }
        jenc_free(enc);
    }
    free(plain);
}

/* Fail fast on the type contract: lengths and constants must match the spec. */
static void check_constants(void)
{
    CHECK(JENC_NONCE_LEN == 32, "nonce length %d, expected 32", JENC_NONCE_LEN);
    CHECK(JENC_SALT_LEN == 64, "salt length %d, expected 64", JENC_SALT_LEN);
    CHECK(JENC_TAG_LEN == 16, "tag length %d, expected 16", JENC_TAG_LEN);
    CHECK(JENC_KEY_LEN == 32, "key length %d, expected 32", JENC_KEY_LEN);
    CHECK(JENC_PBKDF2_ITER == 10000, "PBKDF2 iterations %d, expected 10000",
          JENC_PBKDF2_ITER);
    CHECK(JENC_HEADER_LEN == 100, "header length %d, expected 100", JENC_HEADER_LEN);
}

int main(void)
{
    static const size_t lens[] = {0, 1, 15, 16, 17, 31, 32, 33, 255, 4096};
    size_t i;

    check_constants();

    check_decrypt_vector("tests/data/Test3.md.jenc", "tests/data/Test3.md");
    check_decrypt_vector("tests/data/test.v001_winnewlines.md.jenc", "tests/data/test.v001.md");

    check_encrypt_vector("tests/data/Test3.md.jenc", "tests/data/Test3.md");
    check_encrypt_vector("tests/data/test.v001_winnewlines.md.jenc", "tests/data/test.v001.md");

    check_wrong_password("tests/data/Test3.md.jenc");
    check_wrong_password("tests/data/test.v001_winnewlines.md.jenc");

    check_tamper("tests/data/Test3.md.jenc");
    check_tamper("tests/data/test.v001_winnewlines.md.jenc");

    check_truncated("tests/data/Test3.md.jenc");
    check_bad_version("tests/data/Test3.md.jenc");

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        check_round_trip(lens[i]);
    }

    printf("jenc tests: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
