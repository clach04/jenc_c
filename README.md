# jenc_c

C99 implementation of the [**jenc V001**](https://github.com/clach04/jenc-py#jenc-file-format---v001) file format (the format used by
`jenc-py`). Provides a library and a command-line tool.

Only the V001 format is supported. U001 is not.

## Status

  * Decrypts both V001 reference vectors byte-for-byte.
  * Encrypts output that matches the reference vectors byte-for-byte.
  * Not yet reviewed for side-channel resistance (there are some home-grown; PBKDF2-HMAC-SHA512, GHASH/GCM, HMAC, RNG - which is less than ideal). See `TODO.md`.
      * **HMAC is hand-written, by choice.** openssh's `hmac.c` is not built: it needs `digest-libc.c`, which needs `sshbuf_ptr`/`sshbuf_len` (from `sshbuf.c`, which pulls in `misc.c`) and the MD5/SHA1 headers. Not worth the shim cost for ~40 lines.
      * `timingsafe_bcmp` is vendored from openbsd-compat (`timingsafe_bcmp.c`).
      * The volatile-loop wipe (`jenc_crypto_wipe`) is hand-written; vendored `explicit_bzero.c` needs `bzero`, which MinGW lacks.

## Format (V001)

| Field        | Size     | Notes                                   |
|--------------|----------|-----------------------------------------|
| Version      | 4 bytes  | ASCII `V001`                            |
| Nonce        | 32 bytes | Random per file                         |
| Salt         | 64 bytes | Random per file                         |
| Ciphertext   | n bytes  | AES-256-GCM                             |
| Tag          | 16 bytes | GCM authentication tag, at end of file  |

Key derivation: PBKDF2-HMAC-SHA512, 10000 iterations, 32-byte key.
The password is encoded as UTF-8.

## Build

Requirements: a C99 compiler (tested with GCC/MinGW) and openssh-portable.


```sh
cd src
# Obtain AES/rijndael and sha2
git clone https://github.com/clach04/openssh-portable.git
cd openssh-portable
mv includes.h includes.h_   # Windows: ren includes.h includes.h_
cd ../..
```

The rename is required. Vendored files in `src/openssh-portable/` do
`#include "includes.h"`, and quoted includes search the including file's own
directory before any `-I` path. A real `includes.h` there would shadow
`src/openssh_shim/includes.h` and break the build, so `-I` order cannot fix
it. `make` and `build.bat` stop with an error if `includes.h` is present or
`includes.h_` is missing.


```sh
make          # builds libjenc.a and the jenc tool
make test     # builds and runs tests/test_vectors.c
```

On Windows without make:

```bat
build.bat
```

Override the compiler with `make CC=<compiler>`.

## Command-line usage

```
jenc -e IN OUT [--password PASS] [-b]
jenc -d IN OUT [--password PASS]
```

  * `-e` encrypt, `-d` decrypt.
  * `-` for `IN` or `OUT` uses stdin or stdout.
  * Password sources, in order: `--password`, then the `JENC_PASSWORD` environment variable, then a no-echo prompt.
  * Encryption prompts for the password twice. `-b` skips the confirmation.
  * A failed decryption (wrong password or corrupt file) exits with status 1
    and writes no output file.

Avoid `--password` on shared machines: the value can be seen in the process
list.

### Debug build only

```sh
make JENC_DEBUG_SKIP_MAC=1
```

This build adds `--skip-mac` to decrypt without verifying the tag. It is for
debugging corrupt files only. Release builds reject the option.

## Library

```c
#include "jenc.h"
```

The buffer API takes the input and password and returns the output buffer.
File wrappers are also provided. Decryption verifies the GCM tag before any
plaintext is returned, so a bad password or tampered file yields no
plaintext.

See `src/jenc.h` for the exact signatures.

## Layout

```
src/jenc.{h,c}          library API and format handling
src/jenc_crypto.{h,c}   PBKDF2, GHASH/GCM, HMAC-SHA512, RNG
src/jenc_crypt.c        command-line tool
tests/test_vectors.c    test program
tests/data/             reference vectors from jenc-py
plan.md                 design notes
TODO.md                 open items, including jenc-py differences
```

## Tests

`make test` runs the vectors and checks:

  * Decryption of both V001 vectors, byte-exact.
  * Re-encryption matching the vectors.
  * Wrong password is rejected.
  * Single-bit flips and truncation are rejected.
  * Bad version is rejected.
  * Round trips.

## References

  * [jenc-py](https://github.com/clach04/jenc-py): format reference and test data.
  * https://github.com/clach04/chi_c - library and CLI structure
