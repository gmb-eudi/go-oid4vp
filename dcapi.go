package oid4vp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"slices"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// DCAPI protocol identifiers (OID4VP Annex A: W3C Digital Credentials API
// request member protocols).
const (
	dcapiProtocolSigned   = "openid4vp-v1-signed"
	dcapiProtocolUnsigned = "openid4vp-v1-unsigned"
)

// DCAPIRequest renders the SIGNED dc_api.jwt request member for
// navigator.credentials.get (OID4VP Annex A): a JAR-typed JWT with the
// WRPAC x5c, expected_origins (REQUIRED for signed requests), and no
// response_uri/state — the browser returns the response and the origin is
// validated instead.
func (e *Engine) DCAPIRequest(ctx context.Context, s *Session) ([]byte, error) {
	if s == nil {
		return nil, ErrSessionInvalid
	}
	if s.Flow != DCAPI {
		return nil, fmt.Errorf("%w: DCAPIRequest requires Flow=DCAPI", ErrFlowMismatch)
	}
	if !e.clock().Before(s.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	claims, err := e.dcapiClaims(s, true)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: dcapi claims: %v", ErrConfig, err)
	}
	tok, err := crypto.SignJWS(ctx, e.cfg.Keys, e.cfg.SigningKeyID, map[string]any{
		"typ": typOAuthAuthzReq, // RFC 9101
		"x5c": e.cfg.WRPACChain, // WRPAC chain, leaf first (CIR 2024/2982 Art. 3)
	}, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"protocol": dcapiProtocolSigned,
		"data":     map[string]any{"request": string(tok)},
	})
}

// DCAPIUnsignedRequest renders the UNSIGNED dc_api variant (Annex A): the
// request parameters as a plain JSON object — no client_id (the calling
// origin is the identity). WP-08 decision: the unsigned variant still uses
// response_mode dc_api.jwt because HAIP makes response encryption
// mandatory.
func (e *Engine) DCAPIUnsignedRequest(s *Session) ([]byte, error) {
	if s == nil {
		return nil, ErrSessionInvalid
	}
	if s.Flow != DCAPI {
		return nil, fmt.Errorf("%w: DCAPIUnsignedRequest requires Flow=DCAPI", ErrFlowMismatch)
	}
	claims, err := e.dcapiClaims(s, false)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"protocol": dcapiProtocolUnsigned,
		"data":     claims,
	})
}

// dcapiClaims assembles the Annex A request parameters. ARF RPRC_19a applies
// to every presentation request, DCAPI included; its VALUE comes from
// rpcert.RegistrationRef.Claims() (WP-07 Decision 9 / TS 119 475 §5.2.4) —
// never re-derived here — exactly as requestClaims does for request_uri
// flows, so both paths share one wire vocabulary.
func (e *Engine) dcapiClaims(s *Session, signed bool) (map[string]any, error) {
	// Defense in depth for hand-built sessions: ARF RPRC_19a data is never
	// optional. isZeroRegistration first so a wholly empty ref yields
	// ErrNoRegistration, not rpcert's field-level error (mirrors requestClaims).
	if isZeroRegistration(s.Registration) {
		return nil, ErrNoRegistration
	}
	regClaim, err := s.Registration.Claims()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoRegistration, err)
	}
	cm, err := e.clientMetadata(s)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{
		"response_type":    "vp_token",   // Annex A
		"response_mode":    "dc_api.jwt", // Annex A; HAIP §5 encryption mandatory
		"nonce":            s.Nonce,      // §5
		"dcql_query":       s.Query,      // §6
		"client_metadata":  cm,           // §5
		memberRegistration: regClaim,     // ARF RPRC_19a: registration data in EVERY request
	}
	if len(s.WRPRC) > 0 {
		// OID4VP §5 verifier_info; format "jwt" per ETSI TS 119 475 WRPRC.
		claims[memberVerifierInfo] = []any{map[string]any{"format": "jwt", "data": string(s.WRPRC)}}
	}
	// transaction_data (T-08.10, phase-2 flag): defense in depth — even a
	// hand-built session must not surface entries unless the engine has the
	// flag on (mirrors requestClaims; WP-08 Decisions transaction_data scope
	// note).
	if len(s.TransactionData) > 0 && e.cfg.EnableTransactionData {
		claims["transaction_data"] = transactionDataStrings(s.TransactionData) // OID4VP §5 (phase-2 flag)
	}
	if signed {
		now := e.clock()
		claims["client_id"] = e.clientID               // §5 x509_san_dns:<dns>
		claims["expected_origins"] = s.ExpectedOrigins // Annex A: REQUIRED for signed
		claims["iss"] = e.clientID                     // RFC 9101
		claims["aud"] = audWallet                      // static wallet audience (WP-08 decision)
		claims["iat"] = now.Unix()
		claims["nbf"] = now.Unix()
		claims["exp"] = s.ExpiresAt.Unix()
	}
	return claims, nil
}

// ProcessDCAPIResponse handles the browser-returned dc_api.jwt response
// (OID4VP Annex A): validate the calling origin against expected_origins,
// then decrypt and parse like direct_post.jwt — but with no state member
// (the browser context provides correlation; binding is nonce-based plus
// origin validation, WP-08 decision) and the DCAPI handover. Fail closed:
// an origin absent from expected_origins is rejected with
// ErrOriginNotExpected before any decryption — the DCAPI analog of the
// §8.2 state binding.
// Precondition: s obtained via SessionStore.ConsumeOnce.
func (e *Engine) ProcessDCAPIResponse(ctx context.Context, s *Session, origin string, data []byte) ([]Presentation, error) {
	if s == nil {
		return nil, ErrSessionInvalid
	}
	if s.Flow != DCAPI {
		return nil, fmt.Errorf("%w: ProcessDCAPIResponse requires Flow=DCAPI", ErrFlowMismatch)
	}
	if !s.Consumed {
		return nil, ErrSessionNotConsumed
	}
	if !e.clock().Before(s.ExpiresAt) {
		return nil, ErrSessionExpired // fail closed even on a stale store read
	}
	// Annex A origin validation: exact match against the session-bound
	// expected_origins (set at NewSession). This is DCAPI's analog to the
	// §8.2 state binding — wrong/absent origin rejected before decryption.
	if !slices.Contains(s.ExpectedOrigins, origin) {
		return nil, ErrOriginNotExpected
	}
	if len(data) > e.cfg.MaxResponseBody {
		return nil, ErrBodyTooLarge // oversized body cap, before any parsing (T-08.6)
	}
	var body struct {
		Response string `json:"response"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&body); err != nil {
		return nil, fmt.Errorf("%w: DCAPI response body", ErrMalformedResponse)
	}
	if body.Response == "" {
		return nil, fmt.Errorf("%w: response member required (OID4VP Annex A)", ErrMalformedResponse)
	}

	// Decrypt with the per-session ephemeral key (WP-08 decision). A JWE
	// addressed to a stale/foreign key fails here.
	priv, err := s.ephemeralPrivateKey()
	if err != nil {
		return nil, err
	}
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{s.ID: priv})
	plain, hdr, err := crypto.DecryptJWE(ctx, kp, s.ID, []byte(body.Response))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	// apv still binds the session nonce if present (Annex B.2); apu is not
	// read (see checkAgreementInfo).
	if err := checkAgreementInfo(hdr, s); err != nil {
		return nil, err
	}

	// T-08.7 correction (2026-07-06), carried into DCAPI: the mdoc
	// SessionTranscript DCAPI handover binds the RP's OWN ephemeral
	// response-encryption key via its RFC 7638 thumbprint (the same key
	// advertised in client_metadata) — computed here, once, from priv, never
	// from wallet-supplied data. Threaded onto every mso_mdoc presentation by
	// presentationsFromVPToken exactly as ProcessResponse does for request_uri
	// flows (WP-08 README Decisions "T-08.7/T-08.9 correction").
	jwkThumbprint, err := crypto.JWKThumbprint(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key thumbprint: %v", ErrSessionInvalid, err)
	}

	payload, err := parseResponsePayload(plain)
	if err != nil {
		return nil, err
	}
	// DCAPI carries no state member; correlation is the origin (validated
	// above) plus the nonce-bound response encryption.
	prs, err := presentationsFromVPToken(s, payload.VPToken, jwkThumbprint)
	if err != nil {
		return nil, err
	}
	for i := range prs {
		prs[i].Origin = origin // DCAPI handover carries the origin instead of response_uri
	}
	return prs, nil
}
