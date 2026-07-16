package oid4vp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// Invocation URL golden files — custom scheme AND
// https universal link AND QR payload string.
func TestNewSessionInvocationGoldens(t *testing.T) {
	env := newTestEnv(t) // deterministic seqReader → reproducible tokens
	s, inv, err := env.engine.NewSession(context.Background(), crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "AAECAwQFBgcICQoLDA0ODw" {
		t.Fatalf("deterministic session id = %q", s.ID)
	}
	golden := func(name string) string {
		t.Helper()
		//nolint:gosec // G304: name is always a compile-time constant fixture filename from this test file, never external input.
		raw, err := os.ReadFile(filepath.Join("testdata", "invocation", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(raw))
	}
	if got, want := inv.SchemeURI, golden("cross-device-scheme.golden"); got != want {
		t.Errorf("SchemeURI:\n got %s\nwant %s", got, want)
	}
	if got, want := inv.UniversalLink, golden("cross-device-universal-link.golden"); got != want {
		t.Errorf("UniversalLink:\n got %s\nwant %s", got, want)
	}
	// The QR payload is the custom-scheme URI.
	if inv.QRPayload != inv.SchemeURI {
		t.Errorf("QRPayload = %q, want the scheme URI", inv.QRPayload)
	}
	if !strings.Contains(inv.SchemeURI, "request_uri_method=get") {
		t.Error("invocation must pin request_uri_method=get (OID4VP §5)")
	}
}

// Confirmed HIGH-severity fix: the consumer must be able to control the
// exact request_uri shape its own routing needs ([OID4VP §5] does not
// prescribe a URL shape — it only requires client_id + request_uri +
// request_uri_method by reference). When RequestURIFunc is set, invocation()
// must call it with the minted session id and embed exactly what it
// returns — not the RequestURIBase+"/"+id default.
func TestNewSessionRequestURIFuncControlsRequestURI(t *testing.T) {
	var gotID string
	env := newTestEnv(t, func(c *oid4vp.Config) {
		c.RequestURIBase = "" // must not be required/consulted when RequestURIFunc is set
		c.RequestURIFunc = func(sessionID string) string {
			gotID = sessionID
			return "https://verifier.example.com/wallet/" + sessionID + "/request.jwt"
		}
	})
	s, inv, err := env.engine.NewSession(context.Background(), crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if gotID != s.ID {
		t.Fatalf("RequestURIFunc called with session id %q, want %q", gotID, s.ID)
	}
	_, query, ok := strings.Cut(inv.SchemeURI, "?")
	if !ok {
		t.Fatalf("SchemeURI has no query: %q", inv.SchemeURI)
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://verifier.example.com/wallet/" + s.ID + "/request.jwt"
	if got := q.Get("request_uri"); got != want {
		t.Errorf("request_uri = %q, want %q (RequestURIFunc result, not RequestURIBase+id)", got, want)
	}
	if !strings.Contains(inv.SchemeURI, "request_uri_method=get") {
		t.Error("request_uri_method=get must be preserved regardless of RequestURIFunc (OID4VP §5)")
	}
}

// nonce/state ≥128-bit from the injected rand source; uniqueness.
func TestNewSessionTokenEntropyAndUniqueness(t *testing.T) {
	env := newTestEnv(t, func(c *oid4vp.Config) { c.Rand = nil }) // real crypto/rand
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		s, _, err := env.engine.NewSession(context.Background(), crossDeviceSpec(t))
		if err != nil {
			t.Fatal(err)
		}
		for _, tok := range []string{s.ID, s.Nonce, s.State} {
			raw, err := base64.RawURLEncoding.DecodeString(tok)
			if err != nil {
				t.Fatalf("token %q is not base64url: %v", tok, err)
			}
			if len(raw) < 16 {
				t.Fatalf("token %q decodes to %d bytes, want ≥ 16 (128 bit)", tok, len(raw))
			}
			if seen[tok] {
				t.Fatalf("token %q repeated", tok)
			}
			seen[tok] = true
		}
		if s.Nonce == s.State || s.Nonce == s.ID || s.State == s.ID {
			t.Fatal("id/nonce/state must be pairwise distinct")
		}
	}
}

func TestNewSessionTTLAndTimes(t *testing.T) {
	env := newTestEnv(t)
	s, _, err := env.engine.NewSession(context.Background(), crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if !s.CreatedAt.Equal(testEpoch) {
		t.Errorf("CreatedAt = %v, want %v", s.CreatedAt, testEpoch)
	}
	if want := testEpoch.Add(env.cfg.SessionTTL); !s.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", s.ExpiresAt, want)
	}
}

// Per-session ephemeral response-encryption key: stored
// PKCS#8, EC on the configured curve, fresh per session.
func TestNewSessionEphemeralKeyPerSession(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	s1, _, err := env.engine.NewSession(ctx, crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	s2, _, err := env.engine.NewSession(ctx, crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	k1, err := x509.ParsePKCS8PrivateKey(s1.EphemeralKeyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := k1.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("ephemeral key is %T, want *ecdsa.PrivateKey", k1)
	}
	if ec.Curve.Params().Name != "P-256" {
		t.Errorf("curve = %s, want P-256", ec.Curve.Params().Name)
	}
	if string(s1.EphemeralKeyPKCS8) == string(s2.EphemeralKeyPKCS8) {
		t.Fatal("sessions must not share ephemeral keys")
	}
}

// Enforced at session creation: a request without a
// RegistrationRef is impossible to build — plus the rest of the spec
// validation matrix. Fail closed.
func TestNewSessionSpecValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *oid4vp.RequestSpec)
		want   error
	}{
		{"missing registration", func(_ *testing.T, s *oid4vp.RequestSpec) { s.Registration = rpcert.RegistrationRef{} }, oid4vp.ErrNoRegistration},
		{"empty query", func(_ *testing.T, s *oid4vp.RequestSpec) { s.Query.Credentials = nil }, oid4vp.ErrSpec},
		{"unknown flow", func(_ *testing.T, s *oid4vp.RequestSpec) { s.Flow = "carrier-pigeon" }, oid4vp.ErrSpec},
		{"http response_uri", func(_ *testing.T, s *oid4vp.RequestSpec) { s.ResponseURI = "http://verifier.example.com/response" }, oid4vp.ErrSpec},
		// The response_uri FQDN must equal the
		// x509_san_dns client identifier ([OID4VP §5] FQDN rule applied to
		// the response endpoint; fail closed).
		{"response_uri host mismatch", func(_ *testing.T, s *oid4vp.RequestSpec) { s.ResponseURI = "https://evil.example.org/response" }, oid4vp.ErrSpec},
		{"missing response_uri", func(_ *testing.T, s *oid4vp.RequestSpec) { s.ResponseURI = "" }, oid4vp.ErrSpec},
		{"cross-device with return_uri", func(_ *testing.T, s *oid4vp.RequestSpec) { s.ReturnURI = "https://client.example.com/cb" }, oid4vp.ErrSpec},
		{"cross-device with expected_origins", func(_ *testing.T, s *oid4vp.RequestSpec) { s.ExpectedOrigins = []string{"https://client.example.com"} }, oid4vp.ErrSpec},
		{"transaction_data behind phase-2 flag", func(_ *testing.T, s *oid4vp.RequestSpec) { s.TransactionData = [][]byte{[]byte(`{"type":"qes"}`)} }, oid4vp.ErrTransactionDataDisabled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			spec := crossDeviceSpec(t)
			tt.mutate(t, &spec)
			if _, _, err := env.engine.NewSession(context.Background(), spec); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("same-device requires https return_uri", func(t *testing.T) {
		env := newTestEnv(t)
		spec := sameDeviceSpec(t)
		spec.ReturnURI = ""
		if _, _, err := env.engine.NewSession(context.Background(), spec); !errors.Is(err, oid4vp.ErrSpec) {
			t.Fatalf("missing return_uri: err = %v, want ErrSpec", err)
		}
		spec.ReturnURI = "javascript:alert(1)"
		if _, _, err := env.engine.NewSession(context.Background(), spec); !errors.Is(err, oid4vp.ErrSpec) {
			t.Fatalf("non-https return_uri: err = %v, want ErrSpec", err)
		}
	})

	t.Run("dcapi flow shape", func(t *testing.T) {
		env := newTestEnv(t)
		spec := crossDeviceSpec(t)
		spec.Flow = oid4vp.DCAPI
		spec.ExpectedOrigins = []string{"https://client.example.com"}
		// DCAPI responses come back through the browser, not response_uri.
		if _, _, err := env.engine.NewSession(context.Background(), spec); !errors.Is(err, oid4vp.ErrSpec) {
			t.Fatalf("dcapi with response_uri: err = %v, want ErrSpec", err)
		}
		spec.ResponseURI = ""
		spec.ExpectedOrigins = nil
		if _, _, err := env.engine.NewSession(context.Background(), spec); !errors.Is(err, oid4vp.ErrSpec) {
			t.Fatalf("dcapi without expected_origins: err = %v, want ErrSpec", err)
		}
		spec.ExpectedOrigins = []string{"https://client.example.com/path"}
		if _, _, err := env.engine.NewSession(context.Background(), spec); !errors.Is(err, oid4vp.ErrSpec) {
			t.Fatalf("origin with path: err = %v, want ErrSpec", err)
		}
		spec.ExpectedOrigins = []string{"https://client.example.com"}
		s, _, err := env.engine.NewSession(context.Background(), spec)
		if err != nil {
			t.Fatalf("valid dcapi spec: %v", err)
		}
		if s.Flow != oid4vp.DCAPI {
			t.Fatalf("flow = %q", s.Flow)
		}
	})
}
