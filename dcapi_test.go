package oid4vp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	mdoc "github.com/gmb-eudi/go-mdoc"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

func dcapiSpec(t *testing.T) oid4vp.RequestSpec {
	s := crossDeviceSpec(t)
	s.Flow = oid4vp.DCAPI
	s.ResponseURI = ""
	s.ExpectedOrigins = []string{"https://client.example.com", "https://alt.example.com"}
	return s
}

func decodeDCAPIMember(t *testing.T, raw []byte) (protocol string, data map[string]any) {
	t.Helper()
	var member struct {
		Protocol string          `json:"protocol"`
		Data     json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &member); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(member.Data))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		t.Fatal(err)
	}
	return member.Protocol, data
}

// T-08.9 acceptance: golden request members for the SIGNED dc_api.jwt
// shape (OID4VP Annex A) — decode-and-assert (signature and ephemeral JWK
// are non-deterministic by design).
func TestDCAPISignedRequestMembers(t *testing.T) {
	env := newTestEnv(t)
	s, inv, err := env.engine.NewSession(context.Background(), dcapiSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.DCAPI) == 0 {
		t.Fatal("DCAPI invocation member must be populated for Flow=DCAPI")
	}
	if inv.SchemeURI != "" || inv.UniversalLink != "" || inv.QRPayload != "" {
		t.Error("DCAPI flow must not render request_uri invocation URLs")
	}
	protocol, data := decodeDCAPIMember(t, inv.DCAPI)
	if protocol != "openid4vp-v1-signed" {
		t.Fatalf("protocol = %q, want openid4vp-v1-signed (Annex A)", protocol)
	}
	reqJWT, ok := data["request"].(string)
	if !ok || reqJWT == "" {
		t.Fatal("signed data member must carry the request JWT")
	}
	payload, hdr, err := crypto.VerifyJWS([]byte(reqJWT), env.leafKey.Public())
	if err != nil {
		t.Fatalf("dc_api.jwt must verify against the WRPAC leaf: %v", err)
	}
	if hdr["typ"] != "oauth-authz-req+jwt" {
		t.Errorf("typ = %v", hdr["typ"])
	}
	if _, ok := hdr["x5c"].([]any); !ok {
		t.Error("x5c chain missing from dc_api.jwt header")
	}
	var claims map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		t.Fatal(err)
	}
	if claims["client_id"] != env.engine.ClientID() {
		t.Errorf("client_id = %v", claims["client_id"])
	}
	if claims["response_type"] != "vp_token" || claims["response_mode"] != "dc_api.jwt" {
		t.Errorf("response_type/mode = %v/%v (Annex A; HAIP: encrypted)", claims["response_type"], claims["response_mode"])
	}
	if claims["nonce"] != s.Nonce {
		t.Error("nonce must equal the session nonce")
	}
	wantOrigins := []any{"https://client.example.com", "https://alt.example.com"}
	if !reflect.DeepEqual(claims["expected_origins"], wantOrigins) {
		t.Errorf("expected_origins = %v, want %v (Annex A: REQUIRED for signed)", claims["expected_origins"], wantOrigins)
	}
	for _, absent := range []string{"response_uri", "state", "redirect_uri"} {
		if _, present := claims[absent]; present {
			t.Errorf("%s must be absent from DCAPI requests (Annex A)", absent)
		}
	}
	if _, ok := claims["dcql_query"].(map[string]any); !ok {
		t.Error("dcql_query missing")
	}
	if _, ok := claims["client_metadata"].(map[string]any); !ok {
		t.Error("client_metadata (ephemeral JWK) missing")
	}
	if _, ok := claims["verifier_registration"].(map[string]any); !ok {
		t.Error("verifier_registration missing — RPRC_19a applies to DCAPI too")
	}
}

// The unsigned dc_api variant: no signature, no client_id (the origin is
// the identity), still encrypted (response_mode dc_api.jwt — WP-08
// decision; HAIP encryption is mandatory).
func TestDCAPIUnsignedRequestMembers(t *testing.T) {
	env := newTestEnv(t)
	s, _, err := env.engine.NewSession(context.Background(), dcapiSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.engine.DCAPIUnsignedRequest(s)
	if err != nil {
		t.Fatal(err)
	}
	protocol, data := decodeDCAPIMember(t, raw)
	if protocol != "openid4vp-v1-unsigned" {
		t.Fatalf("protocol = %q, want openid4vp-v1-unsigned", protocol)
	}
	if data["response_mode"] != "dc_api.jwt" {
		t.Errorf("response_mode = %v — unsigned variant still encrypts (WP-08 decision)", data["response_mode"])
	}
	if data["nonce"] != s.Nonce {
		t.Error("nonce must equal the session nonce")
	}
	for _, absent := range []string{"client_id", "expected_origins", "aud", "iss", "response_uri", "state"} {
		if _, present := data[absent]; present {
			t.Errorf("%s must be absent from the unsigned dc_api request", absent)
		}
	}
	if _, ok := data["verifier_registration"].(map[string]any); !ok {
		t.Error("verifier_registration missing (RPRC_19a)")
	}
	if _, ok := data["client_metadata"].(map[string]any); !ok {
		t.Error("client_metadata missing")
	}
}

// walletRespondDCAPI: the browser-mediated wallet response — a JSON
// object {"response": <JWE>} (Annex A, dc_api.jwt).
func walletRespondDCAPI(t *testing.T, env *testEnv, s *oid4vp.Session, vpToken map[string]any) []byte {
	t.Helper()
	raw, err := env.engine.DCAPIRequest(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	_, data := decodeDCAPIMember(t, raw)
	payload, hdr, err := crypto.VerifyJWS([]byte(data["request"].(string)), env.leafKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	_ = hdr
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	pub := extractEncJWK(t, claims)
	// DCAPI: no state member; binding is nonce-based (WP-08 decision).
	b, err := json.Marshal(map[string]any{"vp_token": vpToken})
	if err != nil {
		t.Fatal(err)
	}
	jweCompact := encryptResponse(t, pub, b, "", claims["nonce"].(string))
	body, err := json.Marshal(map[string]string{"response": jweCompact})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// T-08.9: happy path + wrong-origin rejection.
func TestProcessDCAPIResponse(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	store := oid4vp.NewMemStore(env.clock.Now)
	spec := dcapiSpec(t)
	spec.Query = mdocQuery(t)
	s, _, err := env.engine.NewSession(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(sampleDeviceResponse)
	body := walletRespondDCAPI(t, env, s, map[string]any{"pid_mdoc": []any{b64}})
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	consumed := consume(t, store, s.ID)

	// T-08.9 acceptance: wrong-origin response rejected.
	if _, err := env.engine.ProcessDCAPIResponse(ctx, consumed, "https://evil.example.org", body); !errors.Is(err, oid4vp.ErrOriginNotExpected) {
		t.Fatalf("wrong origin: err = %v, want ErrOriginNotExpected", err)
	}

	prs, err := env.engine.ProcessDCAPIResponse(ctx, consumed, "https://client.example.com", body)
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 1 {
		t.Fatalf("presentations = %d, want 1", len(prs))
	}
	p := prs[0]
	if p.Origin != "https://client.example.com" {
		t.Errorf("Origin = %q — needed for OID4VPDCAPIHandover", p.Origin)
	}
	if p.ResponseURI != "" {
		t.Errorf("DCAPI presentation must not carry request_uri-flow params: %+v", p)
	}
	if p.Nonce != s.Nonce || p.ClientID != s.ClientID {
		t.Error("handover params must come from the session")
	}
	if string(p.Payload) != string(sampleDeviceResponse) {
		t.Error("payload must be the decoded DeviceResponse")
	}
}

func TestProcessDCAPIResponseGuards(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	store := oid4vp.NewMemStore(env.clock.Now)
	s, _, err := env.engine.NewSession(ctx, dcapiSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	body := walletRespondDCAPI(t, env, s, map[string]any{"pid": []any{sampleSDJWT}})
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}

	// not consumed
	loaded, err := store.Load(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.engine.ProcessDCAPIResponse(ctx, loaded, "https://client.example.com", body); !errors.Is(err, oid4vp.ErrSessionNotConsumed) {
		t.Fatalf("err = %v, want ErrSessionNotConsumed", err)
	}
	consumed := consume(t, store, s.ID)

	// wrong flow method on a DCAPI session (mirror of T-08.3's guard)
	if _, _, err := env.engine.ProcessResponse(ctx, consumed, oid4vp.RawResponse{Body: body}); !errors.Is(err, oid4vp.ErrFlowMismatch) {
		t.Fatalf("ProcessResponse on DCAPI session: err = %v, want ErrFlowMismatch", err)
	}
	// malformed body / missing response member
	if _, err := env.engine.ProcessDCAPIResponse(ctx, consumed, "https://client.example.com", []byte(`{"nope":1}`)); !errors.Is(err, oid4vp.ErrMalformedResponse) {
		t.Fatalf("missing response member: err = %v, want ErrMalformedResponse", err)
	}
	if _, err := env.engine.ProcessDCAPIResponse(ctx, consumed, "https://client.example.com", []byte(`not-json`)); !errors.Is(err, oid4vp.ErrMalformedResponse) {
		t.Fatalf("garbage body: err = %v, want ErrMalformedResponse", err)
	}
	// non-DCAPI session refused
	cd, _, err := env.engine.NewSession(ctx, crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	cd.Consumed = true
	if _, err := env.engine.ProcessDCAPIResponse(ctx, cd, "https://client.example.com", body); !errors.Is(err, oid4vp.ErrFlowMismatch) {
		t.Fatalf("cross-device session: err = %v, want ErrFlowMismatch", err)
	}
}

// T-08.9 carry-forward (T-08.7 correction 2026-07-06): a DCAPI mso_mdoc
// presentation must carry the RFC 7638 thumbprint of the session's OWN
// ephemeral response-encryption key — recomputed independently here from the
// persisted Session.EphemeralKeyPKCS8 (never anything wallet-supplied) — and
// SessionTranscriptFor must delegate to mdoc.OID4VPDCAPIHandover using it.
// This is the same computation/mechanism as ProcessResponse (T-08.7), applied
// to the DCAPI path.
func TestProcessDCAPIResponseThreadsSessionJWKThumbprint(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	store := oid4vp.NewMemStore(env.clock.Now)
	spec := dcapiSpec(t)
	spec.Query = mdocQuery(t)
	s, _, err := env.engine.NewSession(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(sampleDeviceResponse)
	body := walletRespondDCAPI(t, env, s, map[string]any{"pid_mdoc": []any{b64}})
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	consumed := consume(t, store, s.ID)
	prs, err := env.engine.ProcessDCAPIResponse(ctx, consumed, "https://client.example.com", body)
	if err != nil {
		t.Fatal(err)
	}
	p := prs[0]
	if p.JWKThumbprint == "" {
		t.Fatal("DCAPI mso_mdoc presentation must carry the session's own JWKThumbprint")
	}
	if want := sessionJWKThumbprint(t, consumed); p.JWKThumbprint != want {
		t.Errorf("JWKThumbprint = %q, want %q (session's own ephemeral key)", p.JWKThumbprint, want)
	}
	// SessionTranscriptFor now succeeds via the DCAPI handover, using the
	// Origin + JWKThumbprint this task populated.
	got, err := oid4vp.SessionTranscriptFor(p)
	if err != nil {
		t.Fatalf("SessionTranscriptFor(dcapi) = %v", err)
	}
	want := mdoc.OID4VPDCAPIHandover(p.Origin, p.Nonce, p.JWKThumbprint)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DCAPI transcript diverges from mdoc.OID4VPDCAPIHandover:\n got %#v\nwant %#v", got, want)
	}
}

// Hard rule 5: the DCAPI response body is untrusted input.
func FuzzProcessDCAPIResponse(f *testing.F) {
	env := newTestEnvF(f)
	ctx := context.Background()
	s, _, err := env.engine.NewSession(ctx, oid4vp.RequestSpec{
		Query:           testQueryF(f),
		Flow:            oid4vp.DCAPI,
		Registration:    testRegistration(),
		ExpectedOrigins: []string{"https://client.example.com"},
	})
	if err != nil {
		f.Fatal(err)
	}
	s.Consumed = true
	template := *s
	f.Add([]byte(`{"response":"a.b.c.d.e"}`))
	f.Add([]byte(`{"response":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Fuzz(func(_ *testing.T, data []byte) {
		clone := template
		_, _ = env.engine.ProcessDCAPIResponse(ctx, &clone, "https://client.example.com", data)
	})
}
