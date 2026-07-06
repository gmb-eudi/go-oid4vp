package oid4vp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"errors"
	"testing"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// T-08.2/T-08.3: engine construction is fail-closed — every config value
// is validated up front; algorithms/curves against the ECCG policy.
func TestNewConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*oid4vp.Config)
		want   error
	}{
		{"nil keys", func(c *oid4vp.Config) { c.Keys = nil }, oid4vp.ErrConfig},
		{"empty signing key id", func(c *oid4vp.Config) { c.SigningKeyID = "" }, oid4vp.ErrConfig},
		{"empty chain", func(c *oid4vp.Config) { c.WRPACChain = nil }, oid4vp.ErrConfig},
		{"empty dns name", func(c *oid4vp.Config) { c.ClientDNSName = "" }, oid4vp.ErrConfig},
		// WP-08 decision: x509_san_dns only in v1; other prefixes are an
		// extension point the constructor rejects.
		{"verifier_attestation prefix rejected", func(c *oid4vp.Config) { c.ClientIDPrefix = "verifier_attestation" }, oid4vp.ErrUnsupportedClientIDPrefix},
		{"dns not in leaf SAN", func(c *oid4vp.Config) { c.ClientDNSName = "other.example.org" }, oid4vp.ErrSANMismatch},
		{"unknown curve", func(c *oid4vp.Config) { c.ResponseEncryption.Curve = "P-192" }, oid4vp.ErrConfig},
		{"unknown jwe alg", func(c *oid4vp.Config) { c.ResponseEncryption.Alg = "RSA-OAEP" }, oid4vp.ErrConfig},
		{"unknown jwe enc", func(c *oid4vp.Config) { c.ResponseEncryption.EncValues = []string{"A128CBC-HS256"} }, oid4vp.ErrConfig},
		{"empty enc values", func(c *oid4vp.Config) { c.ResponseEncryption.EncValues = nil }, oid4vp.ErrConfig},
		{"unknown sd-jwt alg", func(c *oid4vp.Config) { c.VPFormats.SDJWTAlgValues = []string{"RS256"} }, oid4vp.ErrConfig},
		{"unknown kb-jwt alg", func(c *oid4vp.Config) { c.VPFormats.KBJWTAlgValues = []string{"none"} }, oid4vp.ErrConfig},
		{"unknown cose alg", func(c *oid4vp.Config) { c.VPFormats.MdocIssuerAuthAlgValues = []int64{-257} }, oid4vp.ErrConfig},
		{"empty vp format list", func(c *oid4vp.Config) { c.VPFormats.KBJWTAlgValues = nil }, oid4vp.ErrConfig},
		{"http request_uri base", func(c *oid4vp.Config) { c.RequestURIBase = "http://verifier.example.com/request" }, oid4vp.ErrConfig},
		{"request_uri base with query", func(c *oid4vp.Config) { c.RequestURIBase = "https://verifier.example.com/request?x=1" }, oid4vp.ErrConfig},
		{"universal link with query", func(c *oid4vp.Config) { c.UniversalLinkBase = "https://wallet.example.org/authorize?x=1" }, oid4vp.ErrConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _, _, _ := baseConfig(t)
			tt.mutate(&cfg)
			if _, err := oid4vp.New(context.Background(), cfg); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// The signing key must be the WRPAC leaf key — otherwise wallets reject
// the JAR signature against x5c (CIR 2024/2982 Art. 3; RFC 9101).
func TestNewRejectsSigningKeyLeafMismatch(t *testing.T) {
	cfg, _, _, _ := baseConfig(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Keys = crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"wrpac": other})
	if _, err := oid4vp.New(context.Background(), cfg); !errors.Is(err, oid4vp.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestClientIDDerivedFromSAN(t *testing.T) {
	env := newTestEnv(t)
	if got, want := env.engine.ClientID(), "x509_san_dns:verifier.example.com"; got != want {
		t.Fatalf("ClientID() = %q, want %q", got, want)
	}
}

func TestNewDefaults(t *testing.T) {
	cfg, _, _, _ := baseConfig(t)
	cfg.Policy = nil // defaults to crypto.ECCG()
	cfg.Clock = nil  // defaults to time.Now
	cfg.Rand = nil   // defaults to crypto/rand.Reader
	cfg.SessionTTL = 0
	cfg.MaxResponseBody = 0
	if _, err := oid4vp.New(context.Background(), cfg); err != nil {
		t.Fatalf("defaults must be valid: %v", err)
	}
}
