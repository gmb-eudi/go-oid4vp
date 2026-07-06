package oid4vp

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// typOAuthAuthzReq is the JAR media type (RFC 9101; OID4VP §5 signed
// request).
const typOAuthAuthzReq = "oauth-authz-req+jwt"

// audWallet: the wallet's AS identifier is unknown when the request is
// built; the SIOPv2/OID4VP static audience is used (WP-08 decision,
// matches the EUDI reference implementations).
const audWallet = "https://self-issued.me/v2"

// memberRegistration is the RPRC_19a registration-data member
// (ARF EW-DM-44-019). PROVISIONAL NAME: the OpenID4VP extension is
// specified by ETSI TS 119 472-2 + a CIR in preparation (RPRC_20a), not
// yet published — the name is isolated here and recorded in WP-08
// Decisions; revisit on publication. The member VALUE shape is owned by
// rpcert.RegistrationRef.Claims() (WP-07 Decision 9), not re-derived here.
const memberRegistration = "verifier_registration"

// memberVerifierInfo carries verifier attestations — the WRPRC when the
// Member State issued one (OID4VP §5 verifier_info; ADR-0003).
const memberVerifierInfo = "verifier_info"

// RequestObjectJWT builds and signs the Request Object for GET request_uri
// (RFC 9101 JAR; OID4VP §5; HAIP §5). Single-use: the session is marked
// served and the caller MUST persist it (SessionStore.Save); a second call
// fails with ErrRequestURIConsumed (T-08.4).
func (e *Engine) RequestObjectJWT(ctx context.Context, s *Session) ([]byte, error) {
	if s == nil {
		return nil, ErrSessionInvalid
	}
	if s.Flow == DCAPI {
		return nil, fmt.Errorf("%w: DCAPI sessions use the DCAPI request builder", ErrFlowMismatch)
	}
	if !e.clock().Before(s.ExpiresAt) {
		return nil, ErrSessionExpired // T-08.4: expired session fails
	}
	if s.RequestObjectServed {
		return nil, ErrRequestURIConsumed // T-08.4: second fetch fails
	}
	claims, err := e.requestClaims(s)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: request claims: %v", ErrConfig, err)
	}
	protected := map[string]any{
		"typ": typOAuthAuthzReq, // RFC 9101
		"x5c": e.cfg.WRPACChain, // WRPAC chain, leaf first (CIR 2024/2982 Art. 3)
	}
	tok, err := crypto.SignJWS(ctx, e.cfg.Keys, e.cfg.SigningKeyID, protected, payload)
	if err != nil {
		return nil, err
	}
	s.RequestObjectServed = true
	return tok, nil
}

// requestClaims assembles the JAR claim set for request_uri flows.
// Every member below is asserted one-by-one by TestRequestObjectJWTEveryMember.
func (e *Engine) requestClaims(s *Session) (map[string]any, error) {
	// Defense in depth for hand-built sessions: RPRC_19a data is never
	// optional (T-08.3 acceptance). isZeroRegistration first so a wholly
	// empty ref yields ErrNoRegistration, not rpcert's field-level error.
	if isZeroRegistration(s.Registration) {
		return nil, ErrNoRegistration
	}
	// The RPRC_19a member value comes from rpcert.RegistrationRef.Claims()
	// (WP-07 Decision 9 / TS 119 475 §5.2.4: name, sub, registry_uri,
	// intended_use_id) — never re-derived here, so the request object and
	// the persisted session share one wire vocabulary.
	regClaim, err := s.Registration.Claims()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoRegistration, err)
	}
	cm, err := e.clientMetadata(s)
	if err != nil {
		return nil, err
	}
	now := e.clock()
	claims := map[string]any{
		// RFC 9101: iss = client_id, aud = wallet identifier, freshness.
		"iss": e.clientID,
		"aud": audWallet,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": s.ExpiresAt.Unix(),
		// OID4VP §5 authorization request.
		"client_id":       e.clientID,        // x509_san_dns:<dns> (§5)
		"response_type":   "vp_token",        // §5
		"response_mode":   "direct_post.jwt", // §8.2; HAIP §5: encryption mandatory
		"response_uri":    s.ResponseURI,     // §8.2 — redirect_uri MUST NOT appear
		"nonce":           s.Nonce,           // §5
		"state":           s.State,           // §8.2 binding
		"dcql_query":      s.Query,           // §6
		"client_metadata": cm,                // §5
		// ARF RPRC_19a: registration data in EVERY request.
		memberRegistration: regClaim,
	}
	if len(s.WRPRC) > 0 {
		// OID4VP §5 verifier_info; format "jwt" per ETSI TS 119 475 WRPRC.
		claims[memberVerifierInfo] = []any{map[string]any{
			"format": "jwt",
			"data":   string(s.WRPRC),
		}}
	}
	// transaction_data (T-08.10, phase-2 flag): defense in depth — even a
	// hand-built session must not surface entries unless the engine has the
	// flag on (validateSpec already gates NewSession, but a caller can
	// mutate Session.TransactionData directly after construction).
	if len(s.TransactionData) > 0 && e.cfg.EnableTransactionData {
		claims["transaction_data"] = transactionDataStrings(s.TransactionData) // OID4VP §5 (phase-2 flag)
	}
	return claims, nil
}

// clientMetadata builds the OID4VP §5 client_metadata: the per-session
// ephemeral response-encryption JWK (use=enc), the supported enc values
// (§8.2), and vp_formats_supported (Annex B.2/B.3). All algorithm values
// come from Config, policy-validated at New (hard rule 4).
func (e *Engine) clientMetadata(s *Session) (map[string]any, error) {
	priv, err := s.ephemeralPrivateKey()
	if err != nil {
		return nil, err
	}
	jwk, err := ephemeralJWK(&priv.PublicKey, e.cfg.ResponseEncryption.Alg, s.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"jwks": map[string]any{
			"keys": []any{jwk},
		},
		"encrypted_response_enc_values_supported": e.cfg.ResponseEncryption.EncValues,
		"vp_formats_supported": map[string]any{
			dcql.FormatSDJWT: map[string]any{
				"sd-jwt_alg_values": e.cfg.VPFormats.SDJWTAlgValues,
				"kb-jwt_alg_values": e.cfg.VPFormats.KBJWTAlgValues,
			},
			dcql.FormatMdoc: map[string]any{
				"issuerauth_alg_values": e.cfg.VPFormats.MdocIssuerAuthAlgValues,
				"deviceauth_alg_values": e.cfg.VPFormats.MdocDeviceAuthAlgValues,
			},
		},
	}, nil
}

// ephemeralJWK renders an EC public key as an encryption JWK
// (RFC 7518 §6.2; use=enc per OID4VP §8.2 response encryption). Coordinates
// are read via crypto/ecdh (uncompressed SEC1 point 0x04||X||Y) rather than
// the deprecated ecdsa.PublicKey.X/Y fields (Go 1.26 SA1019).
func ephemeralJWK(pub *ecdsa.PublicKey, alg, kid string) (map[string]any, error) {
	ep, err := pub.ECDH()
	if err != nil {
		// Only NIST P-curves reach here (policy-validated at New); a failure
		// is a configuration bug, not attacker-controlled (fail closed).
		return nil, fmt.Errorf("%w: ephemeral key: %v", ErrConfig, err)
	}
	point := ep.Bytes() // 0x04 || X || Y, each coordinate `size` bytes
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(point) != 1+2*size {
		return nil, fmt.Errorf("%w: unexpected ephemeral point length %d", ErrConfig, len(point))
	}
	return map[string]any{
		"kty": "EC",
		"crv": pub.Curve.Params().Name,
		"x":   base64.RawURLEncoding.EncodeToString(point[1 : 1+size]),
		"y":   base64.RawURLEncoding.EncodeToString(point[1+size:]),
		"use": "enc",
		"alg": alg,
		"kid": kid,
	}, nil
}
