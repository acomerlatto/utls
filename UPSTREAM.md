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
| U1a | `ba0bec6` | Use the private key of the classical key share the server selected, not always the first one (`EcdheByGroup`) | `u_eidolon_keyshare_test.go` |
| — | "Rename module to github.com/acomerlatto/utls" | Module path `github.com/refraction-networking/utls` → `github.com/acomerlatto/utls` | `go build ./...`, `go test ./...` |

## Syncing

```sh
git remote add upstream https://github.com/refraction-networking/utls.git  # once
git fetch upstream
git merge upstream/master
# conflicts on import paths: keep github.com/acomerlatto/utls
go test ./...
```

After a merge, update the base commit above.
