package oid4vp_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// respEnv wires one consumed same-device session ready for a response.
type respEnv struct {
	env    *testEnv
	store  *oid4vp.MemStore
	s      *oid4vp.Session
	claims map[string]any
}

func newRespEnv(t *testing.T) *respEnv {
	t.Helper()
	ctx := context.Background()
	env := newTestEnv(t)
	store := oid4vp.NewMemStore(env.clock.Now)
	s, _, err := env.engine.NewSession(ctx, sameDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := buildRequestJWT(t, env, s)
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	consumed := consume(t, store, s.ID)
	return &respEnv{env: env, store: store, s: consumed, claims: claims}
}

func (r *respEnv) process(t *testing.T, body []byte) error {
	t.Helper()
	_, _, err := r.env.engine.ProcessResponse(context.Background(), r.s, oid4vp.RawResponse{Body: body})
	return err
}

// T-08.6 acceptance: every negative is a DISTINCT typed error.
// conventions.md mapping noted per case.
func TestProcessResponseNegatives(t *testing.T) {
	t.Run("wrong state", func(t *testing.T) { // err:presentation:nonce-mismatch
		r := newRespEnv(t)
		pub := extractEncJWK(t, r.claims)
		payload := responsePayloadJSON(t, "WRONG-STATE", map[string]any{"pid": []any{sampleSDJWT}})
		body := formBody(encryptResponse(t, pub, payload, "", r.claims["nonce"].(string)))
		if err := r.process(t, body); !errors.Is(err, oid4vp.ErrStateMismatch) {
			t.Fatalf("err = %v, want ErrStateMismatch", err)
		}
	})

	t.Run("replayed response dies at the store", func(t *testing.T) { // err:session:consumed
		r := newRespEnv(t)
		if _, err := r.store.ConsumeOnce(context.Background(), r.s.ID); !errors.Is(err, oid4vp.ErrSessionConsumed) {
			t.Fatalf("second ConsumeOnce: err = %v, want ErrSessionConsumed", err)
		}
	})

	t.Run("JWE to a stale key", func(t *testing.T) { // err:presentation:invalid-response
		r := newRespEnv(t)
		stale, err := crypto.GenerateEphemeralKey("P-256")
		if err != nil {
			t.Fatal(err)
		}
		payload := responsePayloadJSON(t, r.s.State, map[string]any{"pid": []any{sampleSDJWT}})
		body := formBody(encryptResponse(t, &stale.PublicKey, payload, "", r.s.Nonce))
		procErr := r.process(t, body)
		if !errors.Is(procErr, oid4vp.ErrDecrypt) || !errors.Is(procErr, crypto.ErrDecryptionFailed) {
			t.Fatalf("err = %v, want ErrDecrypt wrapping crypto.ErrDecryptionFailed", procErr)
		}
	})

	t.Run("vp_token key not in query", func(t *testing.T) { // err:presentation:invalid-response
		r := newRespEnv(t)
		pub := extractEncJWK(t, r.claims)
		payload := responsePayloadJSON(t, r.s.State, map[string]any{"ghost": []any{sampleSDJWT}})
		body := formBody(encryptResponse(t, pub, payload, "", r.s.Nonce))
		if err := r.process(t, body); !errors.Is(err, oid4vp.ErrUnknownCredentialID) {
			t.Fatalf("err = %v, want ErrUnknownCredentialID", err)
		}
	})

	t.Run("oversized body cap", func(t *testing.T) { // err:presentation:invalid-response
		r := newRespEnv(t)
		body := []byte("response=" + strings.Repeat("A", oid4vp.DefaultMaxResponseBody+1))
		if err := r.process(t, body); !errors.Is(err, oid4vp.ErrBodyTooLarge) {
			t.Fatalf("err = %v, want ErrBodyTooLarge", err)
		}
	})

	t.Run("malformed form encoding", func(t *testing.T) { // err:presentation:invalid-response
		r := newRespEnv(t)
		if err := r.process(t, []byte("%zz=%zz")); !errors.Is(err, oid4vp.ErrMalformedResponse) {
			t.Fatalf("err = %v, want ErrMalformedResponse", err)
		}
	})

	t.Run("missing response parameter", func(t *testing.T) {
		r := newRespEnv(t)
		if err := r.process(t, []byte("foo=bar")); !errors.Is(err, oid4vp.ErrMalformedResponse) {
			t.Fatalf("err = %v, want ErrMalformedResponse", err)
		}
	})

	t.Run("duplicate response parameter", func(t *testing.T) {
		r := newRespEnv(t)
		pub := extractEncJWK(t, r.claims)
		payload := responsePayloadJSON(t, r.s.State, map[string]any{"pid": []any{sampleSDJWT}})
		jwe := encryptResponse(t, pub, payload, "", r.s.Nonce)
		body := append(formBody(jwe), []byte("&"+string(formBody(jwe)))...)
		if err := r.process(t, body); !errors.Is(err, oid4vp.ErrMalformedResponse) {
			t.Fatalf("err = %v, want ErrMalformedResponse", err)
		}
	})

	t.Run("garbage JWE", func(t *testing.T) {
		r := newRespEnv(t)
		if err := r.process(t, []byte("response=not.a.jwe")); !errors.Is(err, oid4vp.ErrDecrypt) {
			t.Fatalf("err = %v, want ErrDecrypt", err)
		}
	})

	t.Run("apv mismatch", func(t *testing.T) { // err:presentation:nonce-mismatch
		r := newRespEnv(t)
		pub := extractEncJWK(t, r.claims)
		payload := responsePayloadJSON(t, r.s.State, map[string]any{"pid": []any{sampleSDJWT}})
		body := formBody(encryptResponse(t, pub, payload, "", "SOME-OTHER-NONCE"))
		if err := r.process(t, body); !errors.Is(err, oid4vp.ErrAPVMismatch) {
			t.Fatalf("err = %v, want ErrAPVMismatch", err)
		}
	})

	t.Run("vp_token value not an array", func(t *testing.T) {
		r := newRespEnv(t)
		pub := extractEncJWK(t, r.claims)
		payload := responsePayloadJSON(t, r.s.State, map[string]any{"pid": sampleSDJWT})
		body := formBody(encryptResponse(t, pub, payload, "", r.s.Nonce))
		if err := r.process(t, body); !errors.Is(err, oid4vp.ErrMalformedResponse) {
			t.Fatalf("err = %v, want ErrMalformedResponse", err)
		}
	})

	t.Run("vp_token empty array", func(t *testing.T) {
		r := newRespEnv(t)
		pub := extractEncJWK(t, r.claims)
		payload := responsePayloadJSON(t, r.s.State, map[string]any{"pid": []any{}})
		body := formBody(encryptResponse(t, pub, payload, "", r.s.Nonce))
		if err := r.process(t, body); !errors.Is(err, oid4vp.ErrMalformedResponse) {
			t.Fatalf("err = %v, want ErrMalformedResponse", err)
		}
	})

	t.Run("payload not JSON", func(t *testing.T) {
		r := newRespEnv(t)
		pub := extractEncJWK(t, r.claims)
		body := formBody(encryptResponse(t, pub, []byte("not-json"), "", r.s.Nonce))
		if err := r.process(t, body); !errors.Is(err, oid4vp.ErrMalformedResponse) {
			t.Fatalf("err = %v, want ErrMalformedResponse", err)
		}
	})

	t.Run("expired session", func(t *testing.T) { // err:session:not-found
		r := newRespEnv(t)
		pub := extractEncJWK(t, r.claims)
		payload := responsePayloadJSON(t, r.s.State, map[string]any{"pid": []any{sampleSDJWT}})
		body := formBody(encryptResponse(t, pub, payload, "", r.s.Nonce))
		r.env.clock.Advance(r.env.cfg.SessionTTL + time.Second)
		if err := r.process(t, body); !errors.Is(err, oid4vp.ErrSessionExpired) {
			t.Fatalf("err = %v, want ErrSessionExpired", err)
		}
	})

	t.Run("wallet error response surfaces as WalletError", func(t *testing.T) {
		r := newRespEnv(t)
		var we *oid4vp.WalletError
		err := r.process(t, []byte("error=access_denied&error_description=user+declined&state="+r.s.State))
		if !errors.As(err, &we) || we.Code != "access_denied" {
			t.Fatalf("err = %v, want *WalletError{access_denied}", err)
		}
	})

	t.Run("wallet error with foreign state is a state mismatch", func(t *testing.T) {
		r := newRespEnv(t)
		err := r.process(t, []byte("error=access_denied&state=WRONG"))
		if !errors.Is(err, oid4vp.ErrStateMismatch) {
			t.Fatalf("err = %v, want ErrStateMismatch", err)
		}
	})
}

// Errors must never leak payload contents (hard rule 3): process a
// response carrying a sentinel string and assert no error text contains it.
func TestProcessResponseErrorsCarryNoPayload(t *testing.T) {
	r := newRespEnv(t)
	pub := extractEncJWK(t, r.claims)
	const secret = "SECRET-ATTRIBUTE-VALUE"
	payload := responsePayloadJSON(t, "WRONG", map[string]any{"pid": []any{secret}})
	body := formBody(encryptResponse(t, pub, payload, "", r.s.Nonce))
	err := r.process(t, body)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error text leaks payload content: %v", err)
	}
}
