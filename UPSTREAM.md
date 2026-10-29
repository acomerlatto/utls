# Fork of refraction-networking/utls

This is the uTLS fork used by [Eidolon](https://github.com/acomerlatto/eidolon-tls).
The module path is `github.com/acomerlatto/utls`, so consumers need no `replace`.

- Upstream: `https://github.com/refraction-networking/utls`
- Base commit: `ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67` (2026-10-06)

## Rules

- Upstream changes come in by **merge**, never by a squashed "rebase upstream"
  commit, so `git log` and `git cherry` keep telling our patches apart.
- Each local patch is its own commit, with a test that fails before it and
  passes after it.
- Code changed by a patch is marked with `[eidolon]`.
- Links in comments and in `README.md`/`SECURITY.md` keep pointing to upstream:
  issues and history live there.

## Local patches

| ID | Commit | Change | Test |
|---|---|---|---|
| U1a | `816358f` | Use the private key of the classical key share the server selected, not always the first one (`EcdheByGroup`) | `u_eidolon_keyshare_test.go` |
| U1b | test only | Regression for the per-connection GREASE value in `signature_algorithms`, drawn from the seed (the substitution is upstream code). Ported from bogdanfinn/utls | `u_eidolon_grease_sigalg_test.go` |
| U2 | `618a0bb` | With GREASE ECH, accept the 8-byte `encrypted_client_hello` in a HelloRetryRequest (`decode_error` on any other length) instead of aborting; still rejected when no ECH was offered | `u_eidolon_grease_ech_hrr_test.go` |
| U3 | `9f9b133` | Server ALPS only on the codepoint the client sent and for a protocol offered in its ALPS extension | `u_eidolon_alps_test.go` |
| U4 | `ba6102e` | Compressed Certificate limited to `maxHandshakeCertificateMsg` before allocating (RFC 8879, Section 5) | `u_eidolon_compressed_cert_limit_test.go` |
| U5 | `99acdde` | Server CertificateVerify algorithm must be one offered in the ClientHello | `u_eidolon_certverify_sigalg_test.go` |
| U6 | `18ea062` | Reject server extensions not offered, GREASE, and those outside BoringSSL's set per message (ServerHello, HelloRetryRequest, EncryptedExtensions, CertificateEntry); validate ECH `retry_configs` | `u_eidolon_server_extensions_test.go` |
| U7 | `52c16a1` | Server-side ALPS: negotiated on the codepoint of the ClientHello when the client offers it for the negotiated protocol and `Config.ApplicationSettings` has settings for it; the client EncryptedExtensions are then required, and the session ticket waits for them | `u_eidolon_server_alps_test.go` |
| U8 | `94027cd` | An ECH rejection is authenticated for the public name of the ECHConfig, not for `Config.ServerName` or `InsecureServerNameToVerify` (RFC 9849, Section 6.1.7), as Go's crypto/tls and BoringSSL do | `u_eidolon_ech_rejection_test.go` |
| — | `742ee01` | Module path `github.com/refraction-networking/utls` → `github.com/acomerlatto/utls` | `go build ./...`, `go test ./...` |

## Syncing

```sh
git remote add upstream https://github.com/refraction-networking/utls.git  # once
git fetch upstream
git merge upstream/master
# conflicts on import paths: keep github.com/acomerlatto/utls
go test ./...
```

After a merge, update the base commit above.
