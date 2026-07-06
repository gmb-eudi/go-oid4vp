package oid4vp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

func txDataSpec(t *testing.T) ([][]byte, oid4vp.RequestSpec) {
	td := [][]byte{
		[]byte(`{"type":"qes_authorization","credential_ids":["pid"],"documentDigests":[{"hash":"abc","label":"contract"}]}`),
		[]byte(`{"type":"payment","credential_ids":["pid"],"amount":"42.00"}`),
	}
	spec := crossDeviceSpec(t)
	spec.TransactionData = td
	return td, spec
}

// expectedHashes recomputes what the wallet must echo: base64url( SHA-256(
// base64url(entry) ) ) — the OID4VP §5 transaction_data hashing.
func expectedHashes(td [][]byte) []string {
	out := make([]string, len(td))
	for i, e := range td {
		enc := base64.RawURLEncoding.EncodeToString(e)
		sum := sha256.Sum256([]byte(enc))
		out[i] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return out
}

// T-08.10: the request carries transaction_data (base64url entries) only
// when the phase-2 flag is on.
func TestRequestObjectTransactionData(t *testing.T) {
	td, spec := txDataSpec(t)
	env := newTestEnv(t, func(c *oid4vp.Config) { c.EnableTransactionData = true })
	_, claims, _ := newServedSession(t, env, spec)
	arr, ok := claims["transaction_data"].([]any)
	if !ok || len(arr) != 2 {
		t.Fatalf("transaction_data = %v, want 2 base64url entries", claims["transaction_data"])
	}
	for i, entry := range arr {
		got, err := base64.RawURLEncoding.DecodeString(entry.(string))
		if err != nil {
			t.Fatalf("entry %d not base64url: %v", i, err)
		}
		if !bytes.Equal(got, td[i]) {
			t.Errorf("entry %d decodes to %s, want the spec bytes", i, got)
		}
	}
}

// Off by default: even if a caller hand-builds a session with
// TransactionData, RequestObjectJWT must not emit it unless the engine
// enabled the flag (defense in depth).
func TestRequestObjectTransactionDataOmittedWhenDisabled(t *testing.T) {
	env := newTestEnv(t) // flag off
	s, _, err := env.engine.NewSession(context.Background(), crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	s.TransactionData = [][]byte{[]byte(`{"type":"qes"}`)} // sneak it in post-construction
	claims, _ := buildRequestJWT(t, env, s)
	if _, present := claims["transaction_data"]; present {
		t.Fatal("transaction_data must be omitted when the phase-2 flag is off")
	}
}

// TransactionDataHashes uses the ECCG policy for the digest — no hash
// literal in production code (hard rule 4).
func TestTransactionDataHashes(t *testing.T) {
	td, _ := txDataSpec(t)
	got, err := oid4vp.TransactionDataHashes(td, "ES256", crypto.ECCG())
	if err != nil {
		t.Fatal(err)
	}
	want := expectedHashes(td)
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("hash[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// unknown alg = reject (policy), never fall through.
	if _, err := oid4vp.TransactionDataHashes(td, "RS512", crypto.ECCG()); !errors.Is(err, crypto.ErrAlgorithmNotAllowed) {
		t.Fatalf("unknown alg: err = %v, want ErrAlgorithmNotAllowed", err)
	}
}

// T-08.10 acceptance: present/absent/mismatch matrix.
func TestValidateTransactionDataEcho(t *testing.T) {
	td, spec := txDataSpec(t)
	env := newTestEnv(t, func(c *oid4vp.Config) { c.EnableTransactionData = true })
	s, _, err := env.engine.NewSession(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	want := expectedHashes(td)

	t.Run("present and matching", func(t *testing.T) {
		if err := env.engine.ValidateTransactionDataEcho(s, want, "ES256"); err != nil {
			t.Fatalf("matching echo: %v", err)
		}
	})
	t.Run("order-insensitive set match", func(t *testing.T) {
		reordered := []string{want[1], want[0]}
		if err := env.engine.ValidateTransactionDataEcho(s, reordered, "ES256"); err != nil {
			t.Fatalf("reordered echo must still match (set semantics): %v", err)
		}
	})
	t.Run("missing echo", func(t *testing.T) {
		if err := env.engine.ValidateTransactionDataEcho(s, nil, "ES256"); !errors.Is(err, oid4vp.ErrTransactionDataMissing) {
			t.Fatalf("err = %v, want ErrTransactionDataMissing", err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		bad := []string{want[0], "AAAA"}
		if err := env.engine.ValidateTransactionDataEcho(s, bad, "ES256"); !errors.Is(err, oid4vp.ErrTransactionDataMismatch) {
			t.Fatalf("err = %v, want ErrTransactionDataMismatch", err)
		}
	})
	t.Run("count mismatch", func(t *testing.T) {
		if err := env.engine.ValidateTransactionDataEcho(s, want[:1], "ES256"); !errors.Is(err, oid4vp.ErrTransactionDataMismatch) {
			t.Fatalf("err = %v, want ErrTransactionDataMismatch", err)
		}
	})

	t.Run("none requested, none echoed", func(t *testing.T) {
		env2 := newTestEnv(t, func(c *oid4vp.Config) { c.EnableTransactionData = true })
		s2, _, err := env2.engine.NewSession(context.Background(), crossDeviceSpec(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := env2.engine.ValidateTransactionDataEcho(s2, nil, "ES256"); err != nil {
			t.Fatalf("no txn data both sides: %v", err)
		}
	})
	t.Run("none requested but echoed anyway", func(t *testing.T) {
		env2 := newTestEnv(t, func(c *oid4vp.Config) { c.EnableTransactionData = true })
		s2, _, err := env2.engine.NewSession(context.Background(), crossDeviceSpec(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := env2.engine.ValidateTransactionDataEcho(s2, []string{"AAAA"}, "ES256"); !errors.Is(err, oid4vp.ErrTransactionDataUnexpected) {
			t.Fatalf("err = %v, want ErrTransactionDataUnexpected", err)
		}
	})
	t.Run("feature disabled", func(t *testing.T) {
		envOff := newTestEnv(t)
		s3 := &oid4vp.Session{ID: "x", TransactionData: td, ExpiresAt: testEpoch.Add(time.Hour)}
		if err := envOff.engine.ValidateTransactionDataEcho(s3, want, "ES256"); !errors.Is(err, oid4vp.ErrTransactionDataDisabled) {
			t.Fatalf("err = %v, want ErrTransactionDataDisabled", err)
		}
	})
}

// transaction_data entries must be JSON objects (OID4VP §5) — reject
// non-object entries at NewSession.
func TestNewSessionRejectsBadTransactionData(t *testing.T) {
	env := newTestEnv(t, func(c *oid4vp.Config) { c.EnableTransactionData = true })
	spec := crossDeviceSpec(t)
	spec.TransactionData = [][]byte{[]byte(`"not-an-object"`)}
	if _, _, err := env.engine.NewSession(context.Background(), spec); !errors.Is(err, oid4vp.ErrTransactionDataInvalid) {
		t.Fatalf("err = %v, want ErrTransactionDataInvalid", err)
	}
}
