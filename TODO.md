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
- [ ] Windows CRLF note: jenc-py checkout turns tests/data/*.md to CRLF
      (core.autocrlf). Vectors here are committed as-is; keep the
      test.v001.md copy at 41 bytes (CRLF) to match the vector.
