package oid4vp_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// processedSameDevice returns a same-device session that has been served,
// consumed and processed — i.e. holding a freshly minted response_code.
func processedSameDevice(t *testing.T, env *testEnv) (*oid4vp.Session, oid4vp.ResponseCode) {
	t.Helper()
	ctx := context.Background()
	store := oid4vp.NewMemStore(env.clock.Now)
	s, _, err := env.engine.NewSession(ctx, sameDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	body := walletRespond(t, env, s, map[string]any{"pid": []any{sampleSDJWT}}, "")
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	consumed := consume(t, store, s.ID)
	_, code, err := env.engine.ProcessResponse(ctx, consumed, oid4vp.RawResponse{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return consumed, code
}

// [OID4VP §8.2/§8.3]: the response endpoint's redirect carries the response_code
// back to the client return URL.
func TestRedirectURICarriesResponseCode(t *testing.T) {
	env := newTestEnv(t)
	s, code := processedSameDevice(t, env)
	redirect, err := env.engine.RedirectURI(s)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(redirect, s.ReturnURI) {
		t.Errorf("redirect %q must target the session return_uri %q", redirect, s.ReturnURI)
	}
	if got := u.Query().Get("response_code"); got != string(code) {
		t.Errorf("response_code param = %q, want %q", got, code)
	}
}

// return_uri that already has a query gets & separation, not a second ?.
func TestRedirectURIPreservesExistingQuery(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	store := oid4vp.NewMemStore(env.clock.Now)
	spec := sameDeviceSpec(t)
	spec.ReturnURI = "https://client.example.com/callback?txn=7"
	s, _, err := env.engine.NewSession(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	body := walletRespond(t, env, s, map[string]any{"pid": []any{sampleSDJWT}}, "")
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	consumed := consume(t, store, s.ID)
	if _, _, err := env.engine.ProcessResponse(ctx, consumed, oid4vp.RawResponse{Body: body}); err != nil {
		t.Fatal(err)
	}
	redirect, err := env.engine.RedirectURI(consumed)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("txn") != "7" || u.Query().Get("response_code") == "" {
		t.Fatalf("redirect %q must keep txn and add response_code", redirect)
	}
}

func TestRedirectURIGuards(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	// cross-device: no redirect at all
	store := oid4vp.NewMemStore(env.clock.Now)
	cd, _, err := env.engine.NewSession(ctx, crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.engine.RedirectURI(cd); !errors.Is(err, oid4vp.ErrFlowMismatch) {
		t.Fatalf("cross-device: err = %v, want ErrFlowMismatch", err)
	}
	_ = store
	// same-device before processing: nothing minted yet
	sd, _, err := env.engine.NewSession(ctx, sameDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.engine.RedirectURI(sd); !errors.Is(err, oid4vp.ErrNoResponseCode) {
		t.Fatalf("unprocessed: err = %v, want ErrNoResponseCode", err)
	}
}

// [OID4VP §8.2]: response_code is single-use.
func TestResponseCodeSingleUse(t *testing.T) {
	env := newTestEnv(t)
	s, code := processedSameDevice(t, env)
	if err := env.engine.ConsumeResponseCode(s, code); err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if !s.ResponseCodeUsed {
		t.Fatal("session must record redemption (caller persists it)")
	}
	if err := env.engine.ConsumeResponseCode(s, code); !errors.Is(err, oid4vp.ErrResponseCodeConsumed) {
		t.Fatalf("second redemption: err = %v, want ErrResponseCodeConsumed", err)
	}
}

// Session-fixation attack ([OID4VP §12.1]): the attacker
// starts their OWN session on the victim's browser, then tries to redeem
// with the victim's session id (or their own code against the victim's
// session). Both cross-bindings must fail.
func TestResponseCodeFixationAttack(t *testing.T) {
	env := newTestEnv(t)
	victim, victimCode := processedSameDevice(t, env)
	attacker, attackerCode := processedSameDevice(t, env)

	// Attacker knows their own code but presents it against the victim's
	// session (guessed/fixated session id).
	if err := env.engine.ConsumeResponseCode(victim, attackerCode); !errors.Is(err, oid4vp.ErrResponseCodeMismatch) {
		t.Fatalf("attacker code on victim session: err = %v, want ErrResponseCodeMismatch", err)
	}
	// And the victim's code cannot be redeemed against the attacker's
	// session either.
	if err := env.engine.ConsumeResponseCode(attacker, victimCode); !errors.Is(err, oid4vp.ErrResponseCodeMismatch) {
		t.Fatalf("victim code on attacker session: err = %v, want ErrResponseCodeMismatch", err)
	}
	// Neither failed attempt burned the legitimate binding.
	if err := env.engine.ConsumeResponseCode(victim, victimCode); err != nil {
		t.Fatalf("legitimate redemption after attack attempts: %v", err)
	}
}

func TestConsumeResponseCodeWithoutMint(t *testing.T) {
	env := newTestEnv(t)
	s, _, err := env.engine.NewSession(context.Background(), sameDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.engine.ConsumeResponseCode(s, "anything"); !errors.Is(err, oid4vp.ErrNoResponseCode) {
		t.Fatalf("err = %v, want ErrNoResponseCode", err)
	}
}
