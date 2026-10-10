# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.0.9

**Requires Go 1.27.2.** The `go` directive moves up from 1.27.0, so a consumer on an older
toolchain will not build this version. Go 1.27.2 is a security release, and under Go 1.27.0 this
library's code reaches four standard-library vulnerabilities, all in `net/http`: GO-2026-6603,
-6611, -6613 and -6617. No source, no signature and no message text changed.

### Changed

- **`go` directive 1.27.0 → 1.27.2**, the minimum Go version a consumer needs. Under 1.27.2
  `govulncheck` finds no vulnerability this library calls. Raise your own module's `go` directive
  to `1.27.2`; from there the go command downloads and uses that toolchain by itself.
- **The libraries it builds on, each at its own Go 1.27.2 release with no code change:**
  `go-dcql` → v0.0.3, `go-eudi-crypto` → v0.0.9, `go-eudi-rpcert` → v0.0.7, `go-mdoc` → v0.1.3,
  and `go-eudi-trust` → v0.1.3 through them.

### Notes

- **Indirect modules moved:** `fxamacker/cbor/v2` → v2.9.6, `goccy/go-json` → v0.11.2,
  `golang.org/x/crypto` → v0.58.0, `golang.org/x/sys` → v0.49.0.

- The gate is green on Go 1.27.2: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`,
  golangci-lint v2.14.0, `go test -race` with **0 races**, and all four fuzz targets for 30 seconds
  each with no failing input. `govulncheck` reports **no vulnerabilities found** at any level, the
  module-level `golang.org/x/crypto/openpgp` advisory (GO-2026-5932) included.

- Repository hygiene, with no effect on code that uses the library: CI's linter moved to
  golangci-lint v2.14.0 (the earlier release cannot read Go 1.27.2's compiled standard library).

## v0.0.8

**Requires Go 1.27.0.** The `go` directive moves up from 1.26.6, so a consumer on an older
toolchain will not build this version. Nothing else here behaves differently — no signature
changed, no message text changed, and nothing that passed before now fails.

### Changed

- **`go` directive 1.26.6 → 1.27.0.** This is the minimum Go version a consumer needs. The rest
  of this project's services already require 1.27.0; the libraries were the half still behind,
  and they are being brought up together.

### Notes

- **The first-party set moves as one:** `github.com/gmb-eudi/go-eudi-rpcert` → **v0.0.6**,
  `go-eudi-crypto` → **v0.0.8**, `go-eudi-trust` → **v0.1.2** and `go-mdoc` → **v0.1.2**.
  `go-dcql` is unchanged at v0.0.2 — it had no release to take. **None of those four changed
  source of its own**; each was itself a dependency-maintenance release, so nothing new reaches
  request building, the response and presentation-verification path, DCQL evaluation or the
  session store.

- **Transitive only:** `github.com/lestrrat-go/jwx/v3` → v3.3.0 (was v3.2.0),
  `golang.org/x/crypto` → v0.57.0 (was v0.55.0) and `golang.org/x/sys` → v0.48.0 (was v0.47.0).
  They arrive through `go-eudi-crypto`. The `x/crypto` move crosses v0.56.0, which fixed
  **GO-2026-6354** and **GO-2026-6355** upstream.

- The gate is green on the new set **and on the new directive**: `go mod verify`,
  `go mod tidy -diff`, build, vet, `gofmt`, and `go test -race` with **0 races**, run in a Go
  1.27.0 toolchain. `govulncheck` reports **0 vulnerabilities this library's code is affected
  by**. One advisory stands at module level — **GO-2026-5932**, the unmaintained
  `golang.org/x/crypto/openpgp` package. It has **no fixed version**, so no bump clears it, and
  nothing here imports it.

- Repository hygiene, with no effect on code that uses the library: CI now also runs on pushes
  to `develop`, the pinned GitHub Actions moved to their current commits, the `setup-go` pin
  rolled forward to v7.0.0, and `.gitattributes` now pins its own line endings.

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
