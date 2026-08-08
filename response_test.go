package oid4vp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	dcql "github.com/gmb-eudi/go-dcql"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// consume runs the service-side atomic consumption (Task 1 contract).
func consume(t *testing.T, store oid4vp.SessionStore, id string) *oid4vp.Session {
	t.Helper()
	s, err := store.ConsumeOnce(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Happy path with a wallet-produced response; every
// field asserted. End-to-end re-run with real credentials lives in
// internal/testwallet.
func TestProcessResponseHappyPathSameDevice(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	store := oid4vp.NewMemStore(env.clock.Now)
	s, _, err := env.engine.NewSession(ctx, sameDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	body := walletRespond(t, env, s, map[string]any{"pid": []any{sampleSDJWT}}, "")
	if err := store.Save(ctx, s); err != nil { // persist the served session
		t.Fatal(err)
	}

	got := consume(t, store, s.ID) // atomic one-time consume ([OID4VP §8.2])
	prs, code, err := env.engine.ProcessResponse(ctx, got, oid4vp.RawResponse{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 1 {
		t.Fatalf("presentations = %d, want 1", len(prs))
	}
	p := prs[0]
	if p.QueryCredID != "pid" {
		t.Errorf("QueryCredID = %q", p.QueryCredID)
	}
	if p.Format != dcql.FormatSDJWT {
		t.Errorf("Format = %q, want %q", p.Format, dcql.FormatSDJWT)
	}
	if !bytes.Equal(p.Payload, []byte(sampleSDJWT)) {
		t.Error("Payload must be the presentation string verbatim (dc+sd-jwt)")
	}
	if p.Nonce != got.Nonce || p.ClientID != got.ClientID || p.ResponseURI != got.ResponseURI {
		t.Errorf("binding params = %+v, want session values", p)
	}
	if p.Origin != "" {
		t.Errorf("sd-jwt cross/same-device presentation must not carry mdoc/DCAPI params: %+v", p)
	}

	// [OID4VP §8.2]: same-device mints a fresh single-use response_code.
	if code == "" {
		t.Fatal("same-device must mint a response_code (OID4VP §8.2)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(code))
	if err != nil || len(raw) < 16 {
		t.Fatalf("response_code %q must be ≥128-bit base64url", code)
	}
	if got.ResponseCode != string(code) || got.ResponseCodeUsed {
		t.Error("response_code must be stored unused on the session for §13.3 redemption")
	}
	// Service persists post-processing state; replay stays dead (Task 1).
	if err := store.Save(ctx, got); err != nil {
		t.Fatal(err)
	}
}

// Cross-device: no redirect, no response_code.
func TestProcessResponseCrossDeviceMintsNoCode(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	store := oid4vp.NewMemStore(env.clock.Now)
	s, _, err := env.engine.NewSession(ctx, crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	body := walletRespond(t, env, s, map[string]any{"pid": []any{sampleSDJWT}}, "")
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	got := consume(t, store, s.ID)
	prs, code, err := env.engine.ProcessResponse(ctx, got, oid4vp.RawResponse{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 1 || code != "" || got.ResponseCode != "" {
		t.Fatalf("cross-device: prs=%d code=%q stored=%q; want 1, empty, empty", len(prs), code, got.ResponseCode)
	}
}

// [OID4VP §8.1]: vp_token values are ARRAYS — multiple presentations per credential
// query id surface as multiple Presentations (dcql.Match enforces
// `multiple` later in the pipeline).
func TestProcessResponseArrayValues(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	store := oid4vp.NewMemStore(env.clock.Now)
	s, _, err := env.engine.NewSession(ctx, crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	body := walletRespond(t, env, s, map[string]any{"pid": []any{sampleSDJWT, sampleSDJWT}}, "")
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	got := consume(t, store, s.ID)
	prs, _, err := env.engine.ProcessResponse(ctx, got, oid4vp.RawResponse{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 2 {
		t.Fatalf("presentations = %d, want 2", len(prs))
	}
}

// The one-time-consumption precondition: sessions that skipped
// ConsumeOnce are rejected — the engine refuses to process a response on
// a merely-Loaded session ([OID4VP §8.2] one-time use).
func TestProcessResponseRequiresConsumedSession(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	s, _, err := env.engine.NewSession(ctx, crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	body := walletRespond(t, env, s, map[string]any{"pid": []any{sampleSDJWT}}, "")
	if _, _, err := env.engine.ProcessResponse(ctx, s, oid4vp.RawResponse{Body: body}); !errorsIs(err, oid4vp.ErrSessionNotConsumed) {
		t.Fatalf("err = %v, want ErrSessionNotConsumed", err)
	}
}
