package oid4vp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
	"github.com/gmb-eudi/go-oid4vp/storetest"
)

// The in-memory reference store passes the exported contract that
// the Valkey-backed store will also run.
func TestMemStoreContract(t *testing.T) {
	storetest.Run(t, func(_ *testing.T) oid4vp.SessionStore {
		return oid4vp.NewMemStore(nil)
	})
}

// MemStore honours an injected clock for expiry (the contract suite can
// only use real time; this pins the injectable-clock behavior).
func TestMemStoreExpiryUsesInjectedClock(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	st := oid4vp.NewMemStore(func() time.Time { return now })
	reg, err := rpcert.NewRegistrationRef("Example Verifier", "verifier.example.com", "https://registry.example.com/api", "intended-use-s")
	if err != nil {
		t.Fatal(err)
	}
	s := &oid4vp.Session{ID: "s", Registration: reg, ExpiresAt: now.Add(time.Minute)}
	if err := st.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(ctx, "s"); err != nil {
		t.Fatalf("Load before expiry: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := st.Load(ctx, "s"); !errors.Is(err, oid4vp.ErrSessionNotFound) {
		t.Fatalf("Load after expiry: err = %v, want ErrSessionNotFound", err)
	}
}
