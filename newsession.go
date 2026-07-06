package oid4vp

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
)

// RequestSpec describes one verification request (WP-08 README target
// interface). ReturnURI is the same-device §8.3 redirect target — a README
// addition required by T-08.8, flagged in the plan's README corrections.
type RequestSpec struct {
	Query           dcql.Query
	Flow            Flow // SameDevice | CrossDevice | DCAPI
	ResponseURI     string
	ReturnURI       string                 // same-device only (§8.3)
	Registration    rpcert.RegistrationRef // always (ARF RPRC_19a)
	WRPRC           []byte                 // optional (ADR-0003)
	TransactionData [][]byte               // phase 2 (T-08.10)
	ExpectedOrigins []string               // DCAPI signed requests (Annex A)
}

// WalletInvocation carries the flow-specific way to put the request in
// front of a wallet: custom-scheme URI, https universal link and QR
// payload for request_uri flows, or the DCAPI request member (T-08.9).
type WalletInvocation struct {
	SchemeURI     string // openid4vp://?client_id=...&request_uri=...&request_uri_method=get
	UniversalLink string // UniversalLinkBase + same query
	QRPayload     string // string to encode into the cross-device QR
	DCAPI         []byte // Annex A request member JSON (populated for Flow == DCAPI, T-08.9)
}

// NewSession validates spec, generates the session secrets (id, nonce,
// state — ≥128-bit from the injected rand; OID4VP §5, §12.1) and the
// per-session ephemeral response-encryption key (WP-08 decision), and
// returns the wallet invocation. The caller persists the session
// (SessionStore.Save).
func (e *Engine) NewSession(ctx context.Context, spec RequestSpec) (*Session, WalletInvocation, error) {
	if err := e.validateSpec(spec); err != nil {
		return nil, WalletInvocation{}, err
	}
	id, err := randToken(e.rand, tokenBytes)
	if err != nil {
		return nil, WalletInvocation{}, err
	}
	nonce, err := randToken(e.rand, tokenBytes)
	if err != nil {
		return nil, WalletInvocation{}, err
	}
	state, err := randToken(e.rand, tokenBytes)
	if err != nil {
		return nil, WalletInvocation{}, err
	}
	// Per-session ephemeral response-encryption key; curve from config,
	// policy-checked at New (HAIP §5 response encryption).
	key, err := crypto.GenerateEphemeralKey(e.cfg.ResponseEncryption.Curve)
	if err != nil {
		return nil, WalletInvocation{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, WalletInvocation{}, fmt.Errorf("%w: ephemeral key: %v", ErrConfig, err)
	}
	now := e.clock()
	s := &Session{
		ID:                id,
		Flow:              spec.Flow,
		ClientID:          e.clientID,
		Nonce:             nonce,
		State:             state,
		ResponseURI:       spec.ResponseURI,
		ReturnURI:         spec.ReturnURI,
		Query:             spec.Query,
		Registration:      spec.Registration,
		WRPRC:             spec.WRPRC,
		TransactionData:   spec.TransactionData,
		ExpectedOrigins:   spec.ExpectedOrigins,
		EphemeralKeyPKCS8: der,
		CreatedAt:         now,
		ExpiresAt:         now.Add(e.cfg.SessionTTL),
	}
	inv, err := e.invocation(ctx, s)
	if err != nil {
		return nil, WalletInvocation{}, err
	}
	return s, inv, nil
}

// validateSpec is the fail-closed gate on RequestSpec (hard rule 7).
func (e *Engine) validateSpec(spec RequestSpec) error {
	// T-08.3 acceptance: a request without a RegistrationRef is impossible
	// to build (ARF RPRC_19a).
	if isZeroRegistration(spec.Registration) {
		return ErrNoRegistration
	}
	if len(spec.Query.Credentials) == 0 {
		return fmt.Errorf("%w: dcql query with at least one credential query required (OID4VP §6)", ErrSpec)
	}
	if err := spec.Query.Validate(); err != nil {
		return fmt.Errorf("%w: dcql query: %v", ErrSpec, err)
	}
	if len(spec.TransactionData) > 0 {
		if !e.cfg.EnableTransactionData {
			return ErrTransactionDataDisabled
		}
		if err := validateTransactionData(spec.TransactionData); err != nil {
			return err
		}
	}
	switch spec.Flow {
	case SameDevice, CrossDevice:
		if err := e.validResponseURI(spec.ResponseURI); err != nil {
			return err
		}
		if len(spec.ExpectedOrigins) > 0 {
			return fmt.Errorf("%w: expected_origins is DCAPI-only (OID4VP Annex A)", ErrSpec)
		}
		if spec.Flow == SameDevice {
			if err := validHTTPSURL(spec.ReturnURI); err != nil {
				return fmt.Errorf("%w: same-device return_uri: %v (OID4VP §8.3)", ErrSpec, err)
			}
		} else if spec.ReturnURI != "" {
			return fmt.Errorf("%w: return_uri is same-device-only (OID4VP §8.3)", ErrSpec)
		}
	case DCAPI:
		if spec.ResponseURI != "" || spec.ReturnURI != "" {
			return fmt.Errorf("%w: DCAPI responses return via the browser, not response_uri (OID4VP Annex A)", ErrSpec)
		}
		if len(spec.ExpectedOrigins) == 0 {
			return fmt.Errorf("%w: expected_origins required for DCAPI (OID4VP Annex A)", ErrSpec)
		}
		for _, o := range spec.ExpectedOrigins {
			if err := validOrigin(o); err != nil {
				return fmt.Errorf("%w: expected origin %q: %v", ErrSpec, o, err)
			}
		}
	default:
		return fmt.Errorf("%w: unknown flow %q", ErrSpec, spec.Flow)
	}
	return nil
}

// validResponseURI: https, and the FQDN must equal the x509_san_dns client
// identifier — WP-08 recorded interpretation applying the OID4VP §5 FQDN
// rule to the response endpoint (fail closed; wallets enforce the same).
func (e *Engine) validResponseURI(raw string) error {
	if err := validHTTPSURL(raw); err != nil {
		return fmt.Errorf("%w: response_uri: %v (OID4VP §8.2)", ErrSpec, err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: response_uri: %v", ErrSpec, err)
	}
	if u.Hostname() != e.cfg.ClientDNSName {
		return fmt.Errorf("%w: response_uri host %q must equal the client_id DNS name %q (OID4VP §5 x509_san_dns)", ErrSpec, u.Hostname(), e.cfg.ClientDNSName)
	}
	return nil
}

func validHTTPSURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("must be an absolute https URL")
	}
	return nil
}

// validOrigin: a web origin is scheme://host[:port] with nothing else
// (OID4VP Annex A expected_origins).
func validOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("must be an https origin without path/query/fragment")
	}
	return nil
}

func isZeroRegistration(r rpcert.RegistrationRef) bool {
	return r == (rpcert.RegistrationRef{})
}

// invocation renders the flow-specific wallet invocation. For request_uri
// flows the authorization request is passed by reference (RFC 9101 §5;
// OID4VP §5): client_id + request_uri + request_uri_method=get only.
func (e *Engine) invocation(ctx context.Context, s *Session) (WalletInvocation, error) {
	if s.Flow == DCAPI {
		// DCAPI has no request_uri invocation URL; the SIGNED dc_api.jwt
		// request member is embedded directly (T-08.9, OID4VP Annex A).
		member, err := e.DCAPIRequest(ctx, s)
		if err != nil {
			return WalletInvocation{}, err
		}
		return WalletInvocation{DCAPI: member}, nil
	}
	q := url.Values{}
	q.Set("client_id", e.clientID)
	q.Set("request_uri", e.cfg.RequestURIBase+"/"+s.ID)
	q.Set("request_uri_method", "get") // OID4VP §5; WP-08 v1 pins GET (T-08.4)
	enc := q.Encode()
	inv := WalletInvocation{
		SchemeURI:     "openid4vp://?" + enc,
		UniversalLink: e.cfg.UniversalLinkBase + "?" + enc,
	}
	// WP-08 decision: the QR payload is the custom-scheme URI; services
	// may choose the universal link instead — both are returned.
	inv.QRPayload = inv.SchemeURI
	return inv, nil
}
