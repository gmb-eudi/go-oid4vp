package oid4vp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// errorsIs is a tiny alias so response_test.go reads cleanly.
func errorsIs(err, target error) bool { return errors.Is(err, target) }

var testEpoch = time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)

// seqReader is a deterministic io.Reader (0x00, 0x01, ...) so session
// id/nonce/state and the invocation golden files are reproducible.
type seqReader struct{ n byte }

func (r *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.n
		r.n++
	}
	return len(p), nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testChain builds a synthetic WRPAC-shaped chain (leaf with SAN dNSName,
// signed by a one-off CA) — test PKI only, generated in-process (ADR-0007:
// no real material). Profile/policy-OID checks are go-eudi-rpcert's job.
func testChain(t testing.TB, dns string) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test AccessCA"},
		NotBefore:             testEpoch.Add(-time.Hour),
		NotAfter:              testEpoch.Add(24 * 365 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(crand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dns},
		DNSNames:     []string{dns},
		NotBefore:    testEpoch.Add(-time.Hour),
		NotAfter:     testEpoch.Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(crand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{leaf, ca}, leafKey
}

type testEnv struct {
	engine  *oid4vp.Engine
	chain   []*x509.Certificate
	leafKey *ecdsa.PrivateKey
	clock   *fakeClock
	cfg     oid4vp.Config
}

// baseConfig returns a valid Config. Algorithm literals below are TEST
// FIXTURES; production code carries none (hard rule 4) — every value is
// validated against crypto.Policy inside New.
func baseConfig(t testing.TB) (oid4vp.Config, []*x509.Certificate, *ecdsa.PrivateKey, *fakeClock) {
	t.Helper()
	chain, leafKey := testChain(t, "verifier.example.com")
	clock := newFakeClock(testEpoch)
	cfg := oid4vp.Config{
		Keys:              crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"wrpac": leafKey}),
		SigningKeyID:      "wrpac",
		WRPACChain:        chain,
		ClientDNSName:     "verifier.example.com",
		Clock:             clock.Now,
		Rand:              &seqReader{},
		RequestURIBase:    "https://verifier.example.com/request",
		UniversalLinkBase: "https://wallet.example.org/authorize",
		SessionTTL:        5 * time.Minute,
		ResponseEncryption: oid4vp.ResponseEncryption{
			Curve: "P-256", Alg: "ECDH-ES", EncValues: []string{"A128GCM", "A256GCM"},
		},
		VPFormats: oid4vp.VPFormats{
			SDJWTAlgValues:          []string{"ES256"},
			KBJWTAlgValues:          []string{"ES256"},
			MdocIssuerAuthAlgValues: []int64{-7},
			MdocDeviceAuthAlgValues: []int64{-7},
		},
	}
	return cfg, chain, leafKey, clock
}

func newTestEnv(t *testing.T, mutate ...func(*oid4vp.Config)) *testEnv {
	t.Helper()
	cfg, chain, leafKey, clock := baseConfig(t)
	for _, m := range mutate {
		m(&cfg)
	}
	eng, err := oid4vp.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{engine: eng, chain: chain, leafKey: leafKey, clock: clock, cfg: cfg}
}

// newTestEnvF mirrors newTestEnv for fuzz targets (*testing.F satisfies
// testing.TB, so it shares baseConfig with the *testing.T callers).
func newTestEnvF(f *testing.F) *testEnv {
	f.Helper()
	cfg, chain, leafKey, clock := baseConfig(f)
	eng, err := oid4vp.New(context.Background(), cfg)
	if err != nil {
		f.Fatal(err)
	}
	return &testEnv{engine: eng, chain: chain, leafKey: leafKey, clock: clock, cfg: cfg}
}

func testQuery(t *testing.T) dcql.Query { return testQueryF(t) }

// testQueryF is the testing.TB variant of testQuery, shared with fuzz
// targets (*testing.F satisfies testing.TB).
func testQueryF(tb testing.TB) dcql.Query {
	tb.Helper()
	q, err := dcql.Parse([]byte(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}`))
	if err != nil {
		tb.Fatal(err)
	}
	return *q
}

// mdocQuery is the mso_mdoc counterpart to testQuery; used by the mdoc-flow
// tests (T-08.7 transcript_test.go).
func mdocQuery(t *testing.T) dcql.Query {
	t.Helper()
	q, err := dcql.Parse([]byte(`{"credentials":[{"id":"pid_mdoc","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["eu.europa.ec.eudi.pid.1","family_name"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return *q
}

func testRegistration() rpcert.RegistrationRef {
	return rpcert.RegistrationRef{
		ClientName:    "Example Client Ltd",
		ClientID:      "EX-CLIENT-0001",
		RegistryURI:   "https://registrar.example.eu",
		IntendedUseID: "intended-use-42",
	}
}

func crossDeviceSpec(t *testing.T) oid4vp.RequestSpec {
	return oid4vp.RequestSpec{
		Query:        testQuery(t),
		Flow:         oid4vp.CrossDevice,
		ResponseURI:  "https://verifier.example.com/response",
		Registration: testRegistration(),
	}
}

func sameDeviceSpec(t *testing.T) oid4vp.RequestSpec {
	s := crossDeviceSpec(t)
	s.Flow = oid4vp.SameDevice
	s.ReturnURI = "https://client.example.com/callback"
	return s
}
