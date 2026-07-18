package oid4vp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
	mdoc "github.com/gmb-eudi/go-mdoc"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// mdocGeneratedNonceFixture is an arbitrary apu value a wallet might still
// send (ISO 18013-7 Annex B; OID4VP Annex B.2). apu is no longer read by
// the engine at all — this
// fixture exists only to prove its PRESENCE has no
// effect; TestMdocWithoutAPUSucceeds proves the same for its ABSENCE.
const mdocGeneratedNonceFixture = "AXlNco6JqbX0ZgD5wat0Vw"

func mdocSession(t *testing.T, env *testEnv) (*oid4vp.Session, []oid4vp.Presentation) {
	t.Helper()
	ctx := context.Background()
	store := oid4vp.NewMemStore(env.clock.Now)
	spec := crossDeviceSpec(t)
	spec.Query = mdocQuery(t)
	s, _, err := env.engine.NewSession(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(sampleDeviceResponse)
	body := walletRespond(t, env, s, map[string]any{"pid_mdoc": []any{b64}}, mdocGeneratedNonceFixture)
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	consumed := consume(t, store, s.ID)
	prs, _, err := env.engine.ProcessResponse(ctx, consumed, oid4vp.RawResponse{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return consumed, prs
}

// sessionJWKThumbprint independently recomputes the RFC 7638 thumbprint of
// s's own ephemeral response-encryption key straight from
// Session.EphemeralKeyPKCS8 (the exported, persisted field) — NOT via any
// oid4vp-internal helper — so the assertions below prove
// Presentation.JWKThumbprint really is derived from the session's own key,
// independently of how ProcessResponse computes it.
func sessionJWKThumbprint(t *testing.T, s *oid4vp.Session) string {
	t.Helper()
	k, err := x509.ParsePKCS8PrivateKey(s.EphemeralKeyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("ephemeral key is %T, want *ecdsa.PrivateKey", k)
	}
	got, err := crypto.JWKThumbprint(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// mdoc without apu now succeeds: apu is no longer read by anything in the
// verification pipeline (dead since the jwk_thumbprint correction). The actual mdoc
// handover binding, Presentation.JWKThumbprint, is computed independently
// of any wallet-supplied apu value and must still be populated.
func TestMdocWithoutAPUSucceeds(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	store := oid4vp.NewMemStore(env.clock.Now)
	spec := crossDeviceSpec(t)
	spec.Query = mdocQuery(t)
	s, _, err := env.engine.NewSession(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(sampleDeviceResponse)
	body := walletRespond(t, env, s, map[string]any{"pid_mdoc": []any{b64}}, "") // no apu
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	consumed := consume(t, store, s.ID)
	prs, _, err := env.engine.ProcessResponse(ctx, consumed, oid4vp.RawResponse{Body: body})
	if err != nil {
		t.Fatalf("apu-absent mso_mdoc presentation must succeed (apu is no longer read): %v", err)
	}
	if len(prs) != 1 {
		t.Fatalf("presentations = %d, want 1", len(prs))
	}
	p := prs[0]
	if p.Format != dcql.FormatMdoc {
		t.Fatalf("Format = %q", p.Format)
	}
	if p.JWKThumbprint == "" {
		t.Error("JWKThumbprint must still be populated — the real handover binding is unaffected by apu's absence")
	}
	if p.Nonce != consumed.Nonce || p.ClientID != consumed.ClientID || p.ResponseURI != consumed.ResponseURI {
		t.Errorf("handover params = %+v, want session values", p)
	}
	if string(p.Payload) != string(sampleDeviceResponse) {
		t.Error("mdoc Payload must be the base64url-DECODED DeviceResponse bytes (Annex B.2)")
	}
}

// Corrected 2026-07-06: Presentation.JWKThumbprint is the RFC 7638
// thumbprint of the session's OWN ephemeral response-encryption key —
// recomputed independently here from the persisted Session.EphemeralKeyPKCS8
// — never anything wallet-supplied.
func TestPresentationJWKThumbprintIsSessionOwnKey(t *testing.T) {
	env := newTestEnv(t)
	s, prs := mdocSession(t, env)
	p := prs[0]
	if p.JWKThumbprint == "" {
		t.Fatal("JWKThumbprint must not be empty for an mso_mdoc presentation")
	}
	if want := sessionJWKThumbprint(t, s); p.JWKThumbprint != want {
		t.Errorf("JWKThumbprint = %q, want %q (derived from Session.EphemeralKeyPKCS8)", p.JWKThumbprint, want)
	}
}

// Two independent sessions mint two independent ephemeral keys, so
// they must produce two different thumbprints even though every
// wallet-supplied fixture (query, vp_token, apu) is identical across both —
// proof the value tracks the session's own key, not any wallet input.
func TestJWKThumbprintDiffersAcrossSessions(t *testing.T) {
	env := newTestEnv(t)
	_, prs1 := mdocSession(t, env)
	_, prs2 := mdocSession(t, env)
	if prs1[0].JWKThumbprint == "" || prs2[0].JWKThumbprint == "" {
		t.Fatal("JWKThumbprint must not be empty")
	}
	if prs1[0].JWKThumbprint == prs2[0].JWKThumbprint {
		t.Fatal("two different sessions must not share a JWKThumbprint")
	}
}

// SessionTranscript construction delegates EXACTLY to
// mdoc.OID4VPHandover with the Presentation's parameters — jwkThumbprint in
// the slot the stale brief called mdocGeneratedNonce (Annex B.2, corrected
// 2026-07-06). Byte-exactness of the CBOR vs the testwallet is
// asserted there.
func TestSessionTranscriptDelegatesToOID4VPHandover(t *testing.T) {
	env := newTestEnv(t)
	_, prs := mdocSession(t, env)
	p := prs[0]
	got, err := oid4vp.SessionTranscriptFor(p)
	if err != nil {
		t.Fatal(err)
	}
	want := mdoc.OID4VPHandover(p.ClientID, p.Nonce, p.JWKThumbprint, p.ResponseURI)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SessionTranscriptFor diverges from mdoc.OID4VPHandover:\n got %#v\nwant %#v", got, want)
	}
}

// Construction-level check that transcript binding is parameter-sensitive:
// swapping the nonce yields a different transcript. The downstream
// DeviceAuth failure on nonce swap is asserted against the testwallet.
func TestSessionTranscriptNonceSwapDiffers(t *testing.T) {
	env := newTestEnv(t)
	_, prs := mdocSession(t, env)
	p := prs[0]
	base, err := oid4vp.SessionTranscriptFor(p)
	if err != nil {
		t.Fatal(err)
	}
	swapped := p
	swapped.Nonce = "SWAPPED-NONCE"
	other, err := oid4vp.SessionTranscriptFor(swapped)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(base, other) {
		t.Fatal("transcript must change when the nonce changes")
	}
}

// Construction-level check that a swapped jwkThumbprint also changes the
// transcript (the security property this whole task exists for: the
// handover binds the RP's own key).
func TestSessionTranscriptThumbprintSwapDiffers(t *testing.T) {
	env := newTestEnv(t)
	_, prs := mdocSession(t, env)
	p := prs[0]
	base, err := oid4vp.SessionTranscriptFor(p)
	if err != nil {
		t.Fatal(err)
	}
	swapped := p
	swapped.JWKThumbprint = "SWAPPED-THUMBPRINT"
	other, err := oid4vp.SessionTranscriptFor(swapped)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(base, other) {
		t.Fatal("transcript must change when the jwkThumbprint changes")
	}
}

// Guards: only mso_mdoc presentations with complete parameters get a
// transcript; DCAPI presentations use the DCAPI handover (Origin is
// wired end-to-end; the delegation contract is pinned here already).
func TestSessionTranscriptParamGuards(t *testing.T) {
	env := newTestEnv(t)
	_, prs := mdocSession(t, env)
	good := prs[0]

	sdjwt := good
	sdjwt.Format = dcql.FormatSDJWT
	if _, err := oid4vp.SessionTranscriptFor(sdjwt); !errors.Is(err, oid4vp.ErrTranscriptParams) {
		t.Fatalf("sd-jwt: err = %v, want ErrTranscriptParams", err)
	}
	noThumb := good
	noThumb.JWKThumbprint = ""
	if _, err := oid4vp.SessionTranscriptFor(noThumb); !errors.Is(err, oid4vp.ErrTranscriptParams) {
		t.Fatalf("missing jwkThumbprint: err = %v, want ErrTranscriptParams", err)
	}
	noNonce := good
	noNonce.Nonce = ""
	if _, err := oid4vp.SessionTranscriptFor(noNonce); !errors.Is(err, oid4vp.ErrTranscriptParams) {
		t.Fatalf("missing nonce: err = %v, want ErrTranscriptParams", err)
	}
	noURI := good
	noURI.ResponseURI = ""
	if _, err := oid4vp.SessionTranscriptFor(noURI); !errors.Is(err, oid4vp.ErrTranscriptParams) {
		t.Fatalf("missing responseURI: err = %v, want ErrTranscriptParams", err)
	}
}

// DCAPI presentations (Origin set) delegate to OID4VPDCAPIHandover with no
// client_id/response_uri (OID4VP Annex A / Annex B.2.6.2 — corrected
// 2026-07-06: client_id dropped from this variant too). The full DCAPI response path and will build a
// Presentation exactly like this one; the delegation contract is pinned
// here using a directly-constructed value.
func TestSessionTranscriptDCAPIDelegation(t *testing.T) {
	p := oid4vp.Presentation{
		QueryCredID:   "pid_mdoc",
		Format:        dcql.FormatMdoc,
		Payload:       sampleDeviceResponse,
		Nonce:         "nonce",
		ClientID:      "x509_san_dns:verifier.example.com",
		Origin:        "https://client.example.com",
		JWKThumbprint: "fixture-thumbprint",
	}
	got, err := oid4vp.SessionTranscriptFor(p)
	if err != nil {
		t.Fatal(err)
	}
	want := mdoc.OID4VPDCAPIHandover(p.Origin, p.Nonce, p.JWKThumbprint)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DCAPI transcript diverges from mdoc.OID4VPDCAPIHandover:\n got %#v\nwant %#v", got, want)
	}
}

// DCAPI guard: missing jwkThumbprint fails closed same as the non-DCAPI path.
func TestSessionTranscriptDCAPIParamGuards(t *testing.T) {
	p := oid4vp.Presentation{
		Format: dcql.FormatMdoc,
		Nonce:  "nonce",
		Origin: "https://client.example.com",
	}
	if _, err := oid4vp.SessionTranscriptFor(p); !errors.Is(err, oid4vp.ErrTranscriptParams) {
		t.Fatalf("missing jwkThumbprint (dcapi): err = %v, want ErrTranscriptParams", err)
	}
}
