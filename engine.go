package oid4vp

import (
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// ClientIDPrefixX509SANDNS is the only client_id prefix supported in v1
// (OID4VP §5 client identifier prefixes; WP-08 decision —
// verifier_attestation is an extension point, rejected by New until
// implemented).
const ClientIDPrefixX509SANDNS = "x509_san_dns"

const (
	// DefaultSessionTTL bounds request_uri fetch + wallet interaction.
	DefaultSessionTTL = 5 * time.Minute
	// DefaultMaxResponseBody caps wallet-posted bodies (T-08.6 oversized
	// body defense).
	DefaultMaxResponseBody = 1 << 20
	// tokenBytes: 128-bit session id / nonce / state / response_code
	// (OID4VP §5 nonce entropy; §12.1 session fixation).
	tokenBytes = 16
)

// ResponseEncryption configures the per-session ephemeral response
// encryption advertised in client_metadata (OID4VP §8.2 direct_post.jwt;
// HAIP §5: encryption mandatory). Values are supplied by the service's
// configuration and validated against crypto.Policy — this library
// hardcodes no algorithm strings (hard rule 4).
type ResponseEncryption struct {
	Curve     string   // ephemeral key curve, e.g. the HAIP baseline P-256
	Alg       string   // JWE key agreement advertised on the ephemeral JWK
	EncValues []string // encrypted_response_enc_values_supported (§8.2)
}

// VPFormats configures client_metadata vp_formats_supported (OID4VP §5;
// Annex B.2/B.3). Same rule: values from config, validated by policy.
type VPFormats struct {
	SDJWTAlgValues          []string // dc+sd-jwt sd-jwt_alg_values
	KBJWTAlgValues          []string // dc+sd-jwt kb-jwt_alg_values
	MdocIssuerAuthAlgValues []int64  // mso_mdoc issuerauth_alg_values (COSE labels)
	MdocDeviceAuthAlgValues []int64  // mso_mdoc deviceauth_alg_values (COSE labels)
}

// Config assembles an Engine. Everything is explicit and validated in New;
// zero values that have safe defaults are documented per field.
type Config struct {
	Keys           crypto.KeyProvider // operator signing key (WRPAC key)
	SigningKeyID   string
	WRPACChain     []*x509.Certificate // leaf first; goes into x5c (CIR 2024/2982 Art. 3)
	ClientDNSName  string              // must match a SAN dNSName of the leaf
	ClientIDPrefix string              // "" = x509_san_dns; anything else is rejected in v1

	Policy crypto.Policy    // nil = crypto.ECCG()
	Clock  func() time.Time // nil = time.Now
	Rand   io.Reader        // nil = crypto/rand.Reader

	RequestURIBase    string // e.g. https://verifier.example.com/request — session id is appended
	UniversalLinkBase string // wallet universal-link endpoint, e.g. https://wallet.example.org/authorize

	SessionTTL      time.Duration // 0 = DefaultSessionTTL
	MaxResponseBody int           // 0 = DefaultMaxResponseBody

	ResponseEncryption ResponseEncryption
	VPFormats          VPFormats

	EnableTransactionData bool // phase-2 flag (T-08.10)
}

// Engine is the OpenID4VP verifier protocol engine (WP-08 README). It is
// stateless between calls: all per-verification state lives in Session.
type Engine struct {
	cfg      Config
	policy   crypto.Policy
	clientID string
	clock    func() time.Time
	rand     io.Reader
}

// New validates cfg and derives the client identifier from the WRPAC leaf.
// Fail closed: any unknown algorithm/curve, prefix, or malformed base URL
// is a construction error (hard rule 7).
func New(ctx context.Context, cfg Config) (*Engine, error) {
	if cfg.Keys == nil {
		return nil, fmt.Errorf("%w: Keys required", ErrConfig)
	}
	if cfg.SigningKeyID == "" {
		return nil, fmt.Errorf("%w: SigningKeyID required", ErrConfig)
	}
	if len(cfg.WRPACChain) == 0 || cfg.WRPACChain[0] == nil {
		return nil, fmt.Errorf("%w: WRPACChain required, leaf first", ErrConfig)
	}
	if cfg.ClientDNSName == "" {
		return nil, fmt.Errorf("%w: ClientDNSName required", ErrConfig)
	}
	// WP-08 decision: client_id prefix v1 = x509_san_dns only.
	if cfg.ClientIDPrefix != "" && cfg.ClientIDPrefix != ClientIDPrefixX509SANDNS {
		return nil, fmt.Errorf("%w: %q (v1 supports %s only)", ErrUnsupportedClientIDPrefix, cfg.ClientIDPrefix, ClientIDPrefixX509SANDNS)
	}
	// OID4VP §5 x509_san_dns: the DNS name MUST match a SAN dNSName entry
	// in the leaf certificate. Mismatch = build error (T-08.3 acceptance).
	leaf := cfg.WRPACChain[0]
	if !slices.Contains(leaf.DNSNames, cfg.ClientDNSName) {
		return nil, fmt.Errorf("%w: %q not in %v", ErrSANMismatch, cfg.ClientDNSName, leaf.DNSNames)
	}
	// The JAR must verify against the x5c leaf (RFC 9101): the signing key
	// must BE the leaf key.
	pub, err := cfg.Keys.Public(ctx, cfg.SigningKeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: signing key: %v", ErrConfig, err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: signing key is %T, EC required", ErrConfig, pub)
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecPub.Equal(leafPub) {
		return nil, fmt.Errorf("%w: signing key does not match the WRPAC leaf public key", ErrConfig)
	}

	policy := cfg.Policy
	if policy == nil {
		policy = crypto.ECCG()
	}
	// Hard rule 4: every configured algorithm value must be allowed by the
	// central policy; unknown = reject, never fall through.
	if !policy.AllowedCurve(cfg.ResponseEncryption.Curve) {
		return nil, fmt.Errorf("%w: response encryption curve %q not allowed by policy", ErrConfig, cfg.ResponseEncryption.Curve)
	}
	if len(cfg.ResponseEncryption.EncValues) == 0 {
		return nil, fmt.Errorf("%w: at least one response enc value required (HAIP §5: encryption mandatory)", ErrConfig)
	}
	for _, enc := range cfg.ResponseEncryption.EncValues {
		if !policy.AllowedJWEAlg(cfg.ResponseEncryption.Alg, enc) {
			return nil, fmt.Errorf("%w: JWE alg=%q enc=%q not allowed by policy", ErrConfig, cfg.ResponseEncryption.Alg, enc)
		}
	}
	if len(cfg.VPFormats.SDJWTAlgValues) == 0 || len(cfg.VPFormats.KBJWTAlgValues) == 0 ||
		len(cfg.VPFormats.MdocIssuerAuthAlgValues) == 0 || len(cfg.VPFormats.MdocDeviceAuthAlgValues) == 0 {
		return nil, fmt.Errorf("%w: all four vp_formats_supported alg lists required", ErrConfig)
	}
	for _, alg := range append(append([]string{}, cfg.VPFormats.SDJWTAlgValues...), cfg.VPFormats.KBJWTAlgValues...) {
		if !policy.AllowedJWSAlg(alg) {
			return nil, fmt.Errorf("%w: JWS alg %q not allowed by policy", ErrConfig, alg)
		}
	}
	for _, alg := range append(append([]int64{}, cfg.VPFormats.MdocIssuerAuthAlgValues...), cfg.VPFormats.MdocDeviceAuthAlgValues...) {
		if !policy.AllowedCOSEAlg(alg) {
			return nil, fmt.Errorf("%w: COSE alg %d not allowed by policy", ErrConfig, alg)
		}
	}

	if err := validBaseURL(cfg.RequestURIBase); err != nil {
		return nil, fmt.Errorf("%w: RequestURIBase: %v", ErrConfig, err)
	}
	if err := validBaseURL(cfg.UniversalLinkBase); err != nil {
		return nil, fmt.Errorf("%w: UniversalLinkBase: %v", ErrConfig, err)
	}

	e := &Engine{
		cfg:      cfg,
		policy:   policy,
		clientID: ClientIDPrefixX509SANDNS + ":" + cfg.ClientDNSName,
		clock:    cfg.Clock,
		rand:     cfg.Rand,
	}
	e.cfg.RequestURIBase = strings.TrimSuffix(cfg.RequestURIBase, "/")
	if e.clock == nil {
		e.clock = time.Now
	}
	if e.rand == nil {
		e.rand = crand.Reader
	}
	if e.cfg.SessionTTL <= 0 {
		e.cfg.SessionTTL = DefaultSessionTTL
	}
	if e.cfg.MaxResponseBody <= 0 {
		e.cfg.MaxResponseBody = DefaultMaxResponseBody
	}
	// Mirror the resolved values back onto cfg so e.cfg.Clock/Rand/Policy
	// never lag the dedicated e.clock/e.rand/e.policy fields (kept in sync
	// the same way SessionTTL/MaxResponseBody are defaulted in place above).
	e.cfg.Clock = e.clock
	e.cfg.Rand = e.rand
	e.cfg.Policy = policy
	return e, nil
}

// ClientID returns the full prefixed client identifier,
// e.g. "x509_san_dns:verifier.example.com" (OID4VP §5).
func (e *Engine) ClientID() string { return e.clientID }

func validBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("must be an absolute https URL")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must not carry query or fragment")
	}
	return nil
}

// randToken returns base64url(n crypto-random bytes) from the injected
// source (OID4VP §5 nonce; §12.1: ≥128 bit, unguessable).
func randToken(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("oid4vp: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
