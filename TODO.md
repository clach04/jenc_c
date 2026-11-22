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
      or the rename causes build drift.
- [ ] HMAC: hand-written `hmac_sha512` kept (see README). Revisit only if
      sshbuf/digest can be built without a link-time stub.
- [ ] Windows CRLF note: jenc-py checkout turns tests/data/*.md to CRLF
      (core.autocrlf). Vectors here are committed as-is; keep the
      test.v001.md copy at 41 bytes (CRLF) to match the vector.
