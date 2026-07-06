module github.com/gmb-eudi/go-oid4vp

go 1.26

require (
	github.com/gmb-eudi/go-dcql v0.0.0
	github.com/gmb-eudi/go-eudi-crypto v0.0.1
	github.com/gmb-eudi/go-eudi-rpcert v0.0.0
	github.com/gmb-eudi/go-mdoc v0.0.0
	github.com/lestrrat-go/jwx/v3 v3.1.1
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.3.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/veraison/go-cose v1.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

// go-dcql, go-eudi-rpcert and go-mdoc have no published tag yet: the bare
// v0.0.0 placeholder above is unresolvable from the proxy, and — unlike a
// plain go.work `use` entry — that becomes a problem for every OTHER module
// in the workspace too, because workspace mode computes one merged module
// graph across all `use`d go.mod files: as soon as go-oid4vp (requiring
// these placeholders) joins go.work's `use` list, any workspace command
// run from ANY other member module also needs to resolve v0.0.0, and
// fails with "unknown revision" even though the modules are `use`d
// locally (confirmed 2026-07-06, T-08.1; hit again for go-mdoc, T-08.7).
// `replace` pins them to the local checkout so no version ever needs
// remote resolution; go-eudi-crypto went through the same fix before it
// was tagged v0.0.1 (see go.work). Drop each line once its module is
// tagged and the require block above is updated to the real version.
replace (
	github.com/gmb-eudi/go-dcql => ../go-dcql
	github.com/gmb-eudi/go-eudi-rpcert => ../go-eudi-rpcert
	github.com/gmb-eudi/go-mdoc => ../go-mdoc
)
