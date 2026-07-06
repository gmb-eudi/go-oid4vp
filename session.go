package oid4vp

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
)

// Flow selects the presentation flow of a session (WP-08 README).
type Flow string

// Flow values (WP-08 README naming).
const (
	SameDevice  Flow = "same-device"  // OID4VP §8.2/§8.3: redirect_uri + response_code return
	CrossDevice Flow = "cross-device" // QR / polling; response endpoint returns no redirect
	DCAPI       Flow = "dcapi"        // OID4VP Annex A: browser Digital Credentials API
)

// Session is the per-verification protocol state. It is a plain
// JSON-serializable record so SessionStore implementations (Valkey in
// WP-09) can persist it verbatim. Fields are exported for storage, not for
// mutation: services treat a Session as opaque between Engine calls.
//
// The response-encryption key is per-session ephemeral (WP-08 decision;
// HAIP-aligned): it lives only inside the session record and dies with it.
type Session struct {
	ID       string `json:"id"`
	Flow     Flow   `json:"flow"`
	ClientID string `json:"client_id"` // full prefixed form, e.g. "x509_san_dns:verifier.example.com"

	Nonce string `json:"nonce"` // OID4VP §5: ≥128-bit, crypto/rand, base64url
	State string `json:"state"` // response binding (§8.2)

	ResponseURI string `json:"response_uri"`         // §8.2 direct_post.jwt endpoint
	ReturnURI   string `json:"return_uri,omitempty"` // same-device §8.3 redirect target (see README corrections)

	Query           dcql.Query             `json:"query"`                      // OID4VP §6
	Registration    rpcert.RegistrationRef `json:"registration"`               // ARF RPRC_19a — always present
	WRPRC           []byte                 `json:"wrprc,omitempty"`            // optional registration certificate (ADR-0003)
	TransactionData [][]byte               `json:"transaction_data,omitempty"` // phase 2 (T-08.10)
	ExpectedOrigins []string               `json:"expected_origins,omitempty"` // DCAPI (Annex A)

	EphemeralKeyPKCS8 []byte `json:"ephemeral_key_pkcs8"` // per-session response-encryption private key, PKCS#8 DER

	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`

	RequestObjectServed bool   `json:"request_object_served"`     // single-use request_uri (T-08.4)
	WalletMetadata      []byte `json:"wallet_metadata,omitempty"` // absorbed hook payload (T-08.4)
	Consumed            bool   `json:"consumed"`                  // sticky one-time marker (ConsumeOnce)
	ResponseCode        string `json:"response_code,omitempty"`   // minted §8.2 (T-08.5), redeemed §8.3 (T-08.8)
	ResponseCodeUsed    bool   `json:"response_code_used,omitempty"`
}

// ephemeralPrivateKey recovers the per-session response-decryption key.
// First caller is RequestObjectJWT (T-08.3, via clientMetadata) which needs
// the public half for the advertised JWK; response decryption reuses it in
// T-08.5/6/7 (ProcessResponse decrypting direct_post.jwt).
func (s *Session) ephemeralPrivateKey() (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(s.EphemeralKeyPKCS8)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %v", ErrSessionInvalid, err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: ephemeral key is %T, EC required", ErrSessionInvalid, k)
	}
	return ec, nil
}

// SessionStore persists sessions. The Valkey implementation lives in
// services (WP-09); it MUST pass storetest.Run unchanged.
//
// Contract (verified by storetest.Run):
//   - Save then Load returns an equal, independent copy (mutating a loaded
//     session does not affect the stored one).
//   - Load/ConsumeOnce of an unknown OR expired id returns
//     ErrSessionNotFound (expiry may be storage eviction, e.g. Valkey TTL;
//     the Engine additionally enforces ExpiresAt itself, fail closed).
//   - ConsumeOnce is atomic: for one id, exactly one caller ever receives
//     the session (returned with Consumed=true); every other and every
//     later call gets ErrSessionConsumed — even after subsequent Save
//     calls of the same session (the consumed marker is sticky; WP-08
//     decision). This is the §12.1 replay defense for the response
//     endpoint (OID4VP §8.2).
type SessionStore interface {
	Save(ctx context.Context, s *Session) error
	Load(ctx context.Context, id string) (*Session, error)
	ConsumeOnce(ctx context.Context, id string) (*Session, error) // atomic: response endpoint
}
