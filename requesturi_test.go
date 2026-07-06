package oid4vp_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// T-08.4 acceptance: second fetch fails.
func TestRequestURISingleUse(t *testing.T) {
	env := newTestEnv(t)
	s, _, err := env.engine.NewSession(context.Background(), crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.engine.RequestObjectJWT(context.Background(), s); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if !s.RequestObjectServed {
		t.Fatal("session must be marked served after the first fetch")
	}
	if _, err := env.engine.RequestObjectJWT(context.Background(), s); !errors.Is(err, oid4vp.ErrRequestURIConsumed) {
		t.Fatalf("second fetch: err = %v, want ErrRequestURIConsumed", err)
	}
}

// The served marker survives the store roundtrip — how verifier-core will
// actually enforce single-use across requests.
func TestRequestURISingleUseAcrossStore(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	store := oid4vp.NewMemStore(env.clock.Now)
	s, _, err := env.engine.NewSession(ctx, crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.engine.RequestObjectJWT(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	again, err := store.Load(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.engine.RequestObjectJWT(ctx, again); !errors.Is(err, oid4vp.ErrRequestURIConsumed) {
		t.Fatalf("refetch after store roundtrip: err = %v, want ErrRequestURIConsumed", err)
	}
}

// T-08.4 acceptance: expired session fails (engine-side check — fail
// closed even if the store returned a stale record).
func TestRequestURIExpiredSession(t *testing.T) {
	env := newTestEnv(t)
	s, _, err := env.engine.NewSession(context.Background(), crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(env.cfg.SessionTTL + time.Second)
	if _, err := env.engine.RequestObjectJWT(context.Background(), s); !errors.Is(err, oid4vp.ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
}

// T-08.4: wallet metadata absorption hook. request_uri_method is pinned
// to get in v1 (asserted on the invocation golden), so this is the seam
// for the future post method: it must accept a JSON object and reject
// everything else, capped.
func TestAbsorbWalletMetadata(t *testing.T) {
	env := newTestEnv(t)
	s, _, err := env.engine.NewSession(context.Background(), crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}}}`)
	if err := env.engine.AbsorbWalletMetadata(s, meta); err != nil {
		t.Fatalf("valid metadata: %v", err)
	}
	if !bytes.Equal(s.WalletMetadata, meta) {
		t.Error("metadata must be stored verbatim on the session")
	}
	for name, bad := range map[string][]byte{
		"array":    []byte(`[]`),
		"string":   []byte(`"x"`),
		"null":     []byte(`null`),
		"garbage":  []byte(`{"a":`),
		"trailing": []byte(`{} extra`),
		"empty":    nil,
		"oversize": bytes.Repeat([]byte("a"), 64<<10+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := env.engine.AbsorbWalletMetadata(s, bad); !errors.Is(err, oid4vp.ErrWalletMetadataInvalid) {
				t.Fatalf("err = %v, want ErrWalletMetadataInvalid", err)
			}
		})
	}
}

func FuzzAbsorbWalletMetadata(f *testing.F) {
	f.Add([]byte(`{"vp_formats_supported":{}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	env := newTestEnvF(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		s := &oid4vp.Session{ID: "fuzz", ExpiresAt: testEpoch.Add(time.Hour)}
		_ = env.engine.AbsorbWalletMetadata(s, data) // must not panic
	})
}
