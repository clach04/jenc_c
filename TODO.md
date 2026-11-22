# jenc_c TODO

Follow-ups. Tracked here per user request (not the codgent issue tracker).

- [ ] Crypto backend: swap table-based openssh rijndael for mbedTLS or
      OpenSSL, which are constant-time. Requires vendoring or a system lib.
- [ ] U001 support (PBKDF2-HMAC-SHA1, same layout). Out of scope now.
- [ ] Password-file option `-P FILE` (jenc-py: trailing blanks trimmed).
- [ ] Env var is JENC_PASSWORD (matches jenc-py); there is no `-E ENVVAR`.
- [ ] jenc-py `-j/--jenc-version` (only V001 exists here).
- [ ] jenc-py `--envvar` override option.
- [ ] Streaming API (current: whole file in memory).
- [ ] Larger test harness (cross-check against jenc-py output).
- [ ] Wipe: consider replacing hand-written `jenc_crypto_wipe` with vendored
      openbsd-compat `explicit_bzero.c`. Trade-off: it needs a `bzero` shim
      (MinGW lacks it), so the hand-written volatile loop stays for now.
- [ ] openssh-portable checkout: `includes.h` renamed to `includes.h_` (README
      build step) and `src/openssh_shim/includes.h` used instead. Not vendored
      here (gitignored), so edits to it are out of scope. Revisit if the shim
      or the rename causes build drift. Guarded: make/build.bat fail fast if
      includes.h is present or includes.h_ is missing.
- [ ] Remove the includes.h rename: copy the few vendored files actually built
      (rijndael.c, openbsd-compat/sha2.c, openbsd-compat/timingsafe_bcmp.c)
      into jenc_c with their licence notices, dropping the openssh checkout
      dependency. Trade-off: manual sync with upstream; needs a licence step.
- [ ] HMAC/PBKDF2 on Windows: use bcrypt.dll (already linked via -lbcrypt).
      BCryptCreateHash with BCRYPT_ALG_HANDLE_HMAC_FLAG gives HMAC-SHA512;
      BCryptDeriveKeyPBKDF2 gives PBKDF2. Would replace hmac_sha512 and most of
      PBKDF2 on Windows, with no vendoring. Not a big win: Linux still needs
      its own path (OpenSSL or mbedTLS, per the crypto backend item above), so
      the hand-written code stays for non-Windows builds unless that lands.
      Worth pursuing. Also revisit only if sshbuf/digest builds without stubs.
- [ ] Windows CRLF note: jenc-py checkout turns tests/data/*.md to CRLF
      (core.autocrlf). Vectors here are committed as-is; keep the
      test.v001.md copy at 41 bytes (CRLF) to match the vector.
