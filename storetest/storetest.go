// Package storetest exports the SessionStore contract suite (WP-08
// T-08.1). Any SessionStore implementation — the in-memory reference, the
// WP-09 Valkey store — must pass Run unchanged.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// Run exercises the SessionStore contract documented on
// oid4vp.SessionStore. factory must return a fresh, empty store per call.
func Run(t *testing.T, factory func(t *testing.T) oid4vp.SessionStore) {
	t.Helper()
	ctx := context.Background()

	newSession := func(id string, ttl time.Duration) *oid4vp.Session {
		now := time.Now().UTC().Truncate(time.Second)
		reg, err := rpcert.NewRegistrationRef("Example Verifier", "verifier.example.com", "https://registry.example.com/api", "intended-use-"+id)
		if err != nil {
			t.Fatalf("NewRegistrationRef: %v", err)
		}
		return &oid4vp.Session{
			ID:           id,
			Flow:         oid4vp.CrossDevice,
			ClientID:     "x509_san_dns:verifier.example.com",
			Nonce:        "nonce-" + id,
			State:        "state-" + id,
			ResponseURI:  "https://verifier.example.com/response/" + id,
			Registration: reg,
			CreatedAt:    now,
			ExpiresAt:    now.Add(ttl),
		}
	}
	asJSON := func(t *testing.T, s *oid4vp.Session) string {
		t.Helper()
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t.Run("SaveLoadRoundtrip", func(t *testing.T) {
		st := factory(t)
		want := newSession("s1", time.Hour)
		if err := st.Save(ctx, want); err != nil {
			t.Fatalf("Save: %v", err)
		}
		got, err := st.Load(ctx, "s1")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if asJSON(t, got) != asJSON(t, want) {
			t.Errorf("roundtrip mismatch:\n got %s\nwant %s", asJSON(t, got), asJSON(t, want))
		}
	})

	t.Run("LoadReturnsACopy", func(t *testing.T) {
		st := factory(t)
		if err := st.Save(ctx, newSession("s1", time.Hour)); err != nil {
			t.Fatal(err)
		}
		first, err := st.Load(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		first.Nonce = "TAMPERED"
		second, err := st.Load(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		if second.Nonce != "nonce-s1" {
			t.Error("mutating a loaded session leaked into the store")
		}
	})

	t.Run("LoadUnknownIsNotFound", func(t *testing.T) {
		st := factory(t)
		if _, err := st.Load(ctx, "ghost"); !errors.Is(err, oid4vp.ErrSessionNotFound) {
			t.Fatalf("err = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("SaveRequiresID", func(t *testing.T) {
		st := factory(t)
		if err := st.Save(ctx, &oid4vp.Session{}); !errors.Is(err, oid4vp.ErrSessionInvalid) {
			t.Fatalf("empty id: err = %v, want ErrSessionInvalid", err)
		}
		if err := st.Save(ctx, nil); !errors.Is(err, oid4vp.ErrSessionInvalid) {
			t.Fatalf("nil session: err = %v, want ErrSessionInvalid", err)
		}
	})

	t.Run("ExpiredSessionIsNotFound", func(t *testing.T) {
		st := factory(t)
		if err := st.Save(ctx, newSession("old", -time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Load(ctx, "old"); !errors.Is(err, oid4vp.ErrSessionNotFound) {
			t.Fatalf("Load expired: err = %v, want ErrSessionNotFound", err)
		}
		if err := st.Save(ctx, newSession("old2", -time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ConsumeOnce(ctx, "old2"); !errors.Is(err, oid4vp.ErrSessionNotFound) {
			t.Fatalf("ConsumeOnce expired: err = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("ConsumeOnceConsumes", func(t *testing.T) {
		st := factory(t)
		if err := st.Save(ctx, newSession("c1", time.Hour)); err != nil {
			t.Fatal(err)
		}
		got, err := st.ConsumeOnce(ctx, "c1")
		if err != nil {
			t.Fatalf("first ConsumeOnce: %v", err)
		}
		if !got.Consumed {
			t.Error("ConsumeOnce must return the session with Consumed=true")
		}
		if _, err := st.ConsumeOnce(ctx, "c1"); !errors.Is(err, oid4vp.ErrSessionConsumed) {
			t.Fatalf("second ConsumeOnce: err = %v, want ErrSessionConsumed", err)
		}
		loaded, err := st.Load(ctx, "c1")
		if err != nil {
			t.Fatalf("Load after consume: %v", err)
		}
		if !loaded.Consumed {
			t.Error("Load after consume must show Consumed=true")
		}
	})

	t.Run("ConsumeOnceUnknownIsNotFound", func(t *testing.T) {
		st := factory(t)
		if _, err := st.ConsumeOnce(ctx, "ghost"); !errors.Is(err, oid4vp.ErrSessionNotFound) {
			t.Fatalf("err = %v, want ErrSessionNotFound", err)
		}
	})

	// WP-08 decision: the consumed marker is sticky across Save — the
	// service persists post-processing state (response_code) after
	// ConsumeOnce, and a replayed wallet POST must still fail (§12.1).
	t.Run("ConsumedMarkerSurvivesSave", func(t *testing.T) {
		st := factory(t)
		if err := st.Save(ctx, newSession("c2", time.Hour)); err != nil {
			t.Fatal(err)
		}
		s, err := st.ConsumeOnce(ctx, "c2")
		if err != nil {
			t.Fatal(err)
		}
		s.ResponseCode = "minted-after-consume"
		if err := st.Save(ctx, s); err != nil {
			t.Fatalf("Save after consume: %v", err)
		}
		if _, err := st.ConsumeOnce(ctx, "c2"); !errors.Is(err, oid4vp.ErrSessionConsumed) {
			t.Fatalf("replay after Save: err = %v, want ErrSessionConsumed", err)
		}
		loaded, err := st.Load(ctx, "c2")
		if err != nil {
			t.Fatal(err)
		}
		if loaded.ResponseCode != "minted-after-consume" {
			t.Error("Save after consume must persist new fields")
		}
	})

	// T-08.1 acceptance: ConsumeOnce is race-proof. This test detects
	// logical double-consume even without -race (no cgo on the dev box);
	// CI runs it under -race for the memory-model guarantee.
	t.Run("ConcurrentConsumeExactlyOnce", func(t *testing.T) {
		st := factory(t)
		if err := st.Save(ctx, newSession("race", time.Hour)); err != nil {
			t.Fatal(err)
		}
		const goroutines = 64
		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			wins      int
			conflicts int
		)
		start := make(chan struct{})
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := st.ConsumeOnce(ctx, "race")
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					wins++
				case errors.Is(err, oid4vp.ErrSessionConsumed):
					conflicts++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins != 1 || conflicts != goroutines-1 {
			t.Fatalf("wins = %d, conflicts = %d; want exactly 1 and %d", wins, conflicts, goroutines-1)
		}
	})
}
