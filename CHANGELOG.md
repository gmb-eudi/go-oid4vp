# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.0.7

Compatible: no signature changes, no message-text changes, nothing that passed before now
fails.

### Changed

- **Errors now wrap their cause as well as their sentinel — 18 sites** across `dcapi.go`,
  `engine.go`, `memstore.go`, `newsession.go`, `requestobject.go`, `response.go` and
  `session.go`. Each was built as `fmt.Errorf("%w: …: %v", ErrSentinel, err)`: the sentinel
  wrapped, the cause printed into the string and then unreachable. Both are now `%w`, so the
  cause is part of the chain:

  ```go
  var urlErr *url.Error
  if errors.As(err, &urlErr) { /* the configured base URL is the problem */ }
  ```

  `errors.Is(err, ErrConfig)` / `ErrSpec` still hold and every rendered message is
  byte-identical (`%v` and `%w` print an error the same way), so no existing caller needs to
  change.

### Fixed

- The P-256 test helper built a public key by assigning the deprecated `X`/`Y` coordinate
  fields; it now parses the uncompressed point, which also checks the point is on the curve.
  Test-only — no shipped behaviour changed.

### Dependencies

- `go-eudi-crypto` v0.0.5 → v0.0.6, `go-mdoc` v0.0.4 → v0.1.0,
  `go-eudi-trust` v0.0.6 → v0.1.0 (indirect).
  **Both `go-mdoc` v0.1.0 and `go-eudi-trust` v0.1.0 are breaking releases** — a device-key
  construction site and a `ResolveIssuerKey` signature respectively. If you reach either
  library directly as well, read its changelog before bumping.
- `github.com/fxamacker/cbor/v2` v2.9.2 → v2.9.3 (indirect),
  `golang.org/x/crypto` v0.54.0 → v0.55.0 (indirect),
  `github.com/lestrrat-go/dsig` v1.3.0 → v1.4.0 (indirect).

### Notes

- The `go` directive is now `1.26.6`, which is the minimum Go version a consumer needs. The
  previous `1.26` resolved to whatever patch the toolchain happened to have; the exact patch
  is pinned because earlier 1.26 releases carry standard-library security fixes this library's
  callers should not silently miss.
