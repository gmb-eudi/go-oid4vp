package oid4vp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// RawResponse is the wallet's POST body to the response endpoint
// (OID4VP §8.2 direct_post.jwt: application/x-www-form-urlencoded with
// response=<JWE>). The service passes it verbatim, size-unchecked — the
// engine owns the cap.
type RawResponse struct {
	Body []byte
}

// ResponseCode is the single-use §8.2 response_code minted for
// same-device sessions and redeemed via ConsumeResponseCode (§8.3/§12.1).
type ResponseCode string

// Presentation is one entry of the vp_token object (OID4VP §8.1), paired
// with the binding parameters downstream verification needs: nonce and
// client_id for KB-JWT (go-sdjwt), and the OID4VPHandover /
// OID4VPDCAPIHandover inputs for mdoc (go-mdoc, Annex B.2 / Annex A).
type Presentation struct {
	QueryCredID string // DCQL credential query id (vp_token key, §8.1)
	Format      string // dcql.FormatSDJWT | dcql.FormatMdoc (from the session's query)
	Payload     []byte // dc+sd-jwt: presentation string verbatim; mso_mdoc: base64url-decoded DeviceResponse

	Nonce, ClientID, ResponseURI string
	Origin                       string // DCAPI only (Annex A)

	// JWKThumbprint is the RFC 7638 thumbprint of the RP's OWN ephemeral
	// response-encryption public key (the same key advertised in
	// client_metadata, T-08.3) — computed by ProcessResponse from
	// Session.EphemeralKeyPKCS8 via crypto.JWKThumbprint, never from
	// anything wallet-supplied. The JWE apu header is not read at all (see
	// WP-08 README Decisions "T-08.7/T-08.9 correction"): JWKThumbprint is
	// the mdoc SessionTranscript handover's sole key-binding input, set
	// only for mso_mdoc presentations.
	JWKThumbprint string
}

// maxVPTokenKeyLen caps attacker-controlled key text quoted in errors
// (hard rule 3: identifiers only, bounded).
const maxVPTokenKeyLen = 64

// ProcessResponse handles the §8.2 direct_post.jwt response for
// request_uri flows: form parse → JWE decrypt with the per-session
// ephemeral key → apv handling (Annex B.2) → vp_token object parse
// (§8.1) → state binding → response_code mint (§8.2, same-device).
//
// Precondition: s was obtained from SessionStore.ConsumeOnce (atomic
// one-time consumption; replays die at the store). The caller persists s
// afterwards (Save) to store the minted response_code.
func (e *Engine) ProcessResponse(ctx context.Context, s *Session, r RawResponse) ([]Presentation, ResponseCode, error) {
	if s == nil {
		return nil, "", ErrSessionInvalid
	}
	if s.Flow == DCAPI {
		return nil, "", fmt.Errorf("%w: DCAPI sessions use ProcessDCAPIResponse", ErrFlowMismatch)
	}
	if !s.Consumed {
		return nil, "", ErrSessionNotConsumed
	}
	if !e.clock().Before(s.ExpiresAt) {
		return nil, "", ErrSessionExpired // fail closed even on a stale store read
	}
	if len(r.Body) > e.cfg.MaxResponseBody {
		return nil, "", ErrBodyTooLarge // T-08.6: oversized body cap, before any parsing
	}
	vals, err := url.ParseQuery(string(r.Body))
	if err != nil {
		return nil, "", fmt.Errorf("%w: form decoding", ErrMalformedResponse)
	}
	if vals.Get("error") != "" {
		// The wallet declined or failed (OID4VP error response) — T-08.11.
		return nil, "", walletErrorFrom(s, vals)
	}
	resp := vals["response"]
	if len(resp) != 1 || resp[0] == "" {
		return nil, "", fmt.Errorf("%w: exactly one response parameter required (OID4VP §8.2)", ErrMalformedResponse)
	}

	// Decrypt with the per-session ephemeral key (WP-08 decision). A JWE
	// addressed to a stale/foreign key fails here (T-08.6).
	priv, err := s.ephemeralPrivateKey()
	if err != nil {
		return nil, "", err
	}
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{s.ID: priv})
	plain, hdr, err := crypto.DecryptJWE(ctx, kp, s.ID, []byte(resp[0]))
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrDecrypt, err)
	}

	if err := checkAgreementInfo(hdr, s); err != nil {
		return nil, "", err
	}

	// T-08.7 (corrected 2026-07-06): the mdoc SessionTranscript handover
	// binds the RP's OWN ephemeral response-encryption key via its RFC 7638
	// thumbprint (same key as advertised in client_metadata, T-08.3). apu is
	// not read at all (WP-08 README Decisions "T-08.7/T-08.9 correction").
	// Computed here, once per response, from priv — never from
	// wallet-supplied data.
	jwkThumbprint, err := crypto.JWKThumbprint(&priv.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("%w: ephemeral key thumbprint: %v", ErrSessionInvalid, err)
	}

	payload, err := parseResponsePayload(plain)
	if err != nil {
		return nil, "", err
	}
	// §8.2 state binding — constant-time (conventions.md).
	if subtle.ConstantTimeCompare([]byte(payload.State), []byte(s.State)) != 1 {
		return nil, "", ErrStateMismatch
	}

	prs, err := presentationsFromVPToken(s, payload.VPToken, jwkThumbprint)
	if err != nil {
		return nil, "", err
	}

	var code ResponseCode
	if s.Flow == SameDevice {
		// §8.2: mint a fresh single-use response_code (≥128-bit, injected
		// rand; §12.1 session-fixation defense). Cross-device sessions get
		// none (WP-08 decision) — the browser polls instead.
		c, err := randToken(e.rand, tokenBytes)
		if err != nil {
			return nil, "", err
		}
		code = ResponseCode(c)
		s.ResponseCode = c
		s.ResponseCodeUsed = false
	}
	return prs, code, nil
}

// checkAgreementInfo validates apv against the session nonce (OID4VP Annex
// B.2 / ISO 18013-7 Annex B). WP-08 decision: apv absent is tolerated (KDF
// already bound the key); apv present-but-wrong is a hard failure. apu is
// not read: it fed only the now-removed Presentation.MdocGeneratedNonce,
// which nothing in the verification pipeline ever consulted — see WP-08
// README Decisions "T-08.7/T-08.9 correction" for the full rationale.
func checkAgreementInfo(hdr crypto.Header, s *Session) error {
	if v, ok := hdr["apv"]; ok {
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("%w: apv must be a base64url string", ErrMalformedResponse)
		}
		raw, err := base64.RawURLEncoding.DecodeString(str)
		if err != nil {
			return fmt.Errorf("%w: apv encoding", ErrMalformedResponse)
		}
		if subtle.ConstantTimeCompare(raw, []byte(s.Nonce)) != 1 {
			return ErrAPVMismatch
		}
	}
	return nil
}

// responsePayload is the decrypted direct_post.jwt JSON payload. Unknown
// members are tolerated (consumer side — unlike our strict authoring
// parsers); vp_token and state are what §8.1/§8.2 bind.
type responsePayload struct {
	VPToken map[string]json.RawMessage `json:"vp_token"`
	State   string                     `json:"state"`
}

func parseResponsePayload(plain []byte) (*responsePayload, error) {
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.UseNumber()
	var p responsePayload
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: response payload", ErrMalformedResponse)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after response payload", ErrMalformedResponse)
	}
	if len(p.VPToken) == 0 {
		return nil, fmt.Errorf("%w: non-empty vp_token object required (OID4VP §8.1)", ErrMalformedResponse)
	}
	return &p, nil
}

// presentationsFromVPToken maps the §8.1 vp_token JSON object (keys =
// DCQL credential query ids, values = ARRAYS of presentations) onto
// Presentations carrying the verification binding parameters. Fail
// closed: keys outside the session's query are rejected (T-08.6) — no
// over-disclosure enters the pipeline silently. jwkThumbprint is computed
// once per response by ProcessResponse and threaded onto every mso_mdoc
// presentation (T-08.7, see WP-08 README Decisions "T-08.7/T-08.9
// correction").
func presentationsFromVPToken(s *Session, vpToken map[string]json.RawMessage, jwkThumbprint string) ([]Presentation, error) {
	formats := make(map[string]string, len(s.Query.Credentials))
	for i := range s.Query.Credentials {
		formats[s.Query.Credentials[i].ID] = s.Query.Credentials[i].Format
	}
	ids := make([]string, 0, len(vpToken))
	for id := range vpToken {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic output order

	var out []Presentation
	for _, id := range ids {
		format, ok := formats[id]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownCredentialID, clip(id, maxVPTokenKeyLen))
		}
		var entries []string
		if err := json.Unmarshal(vpToken[id], &entries); err != nil || len(entries) == 0 {
			return nil, fmt.Errorf("%w: vp_token[%q] must be a non-empty array of strings (OID4VP §8.1)", ErrMalformedResponse, clip(id, maxVPTokenKeyLen))
		}
		for _, entry := range entries {
			if entry == "" {
				return nil, fmt.Errorf("%w: empty presentation in vp_token[%q]", ErrMalformedResponse, clip(id, maxVPTokenKeyLen))
			}
			p := Presentation{
				QueryCredID: id,
				Format:      format,
				Payload:     []byte(entry),
				Nonce:       s.Nonce,
				ClientID:    s.ClientID,
				ResponseURI: s.ResponseURI,
			}
			if format == dcql.FormatMdoc {
				// Annex B.2: DeviceResponse is base64url (no padding).
				raw, err := base64.RawURLEncoding.DecodeString(entry)
				if err != nil {
					return nil, fmt.Errorf("%w: vp_token[%q]: mso_mdoc presentations are base64url (OID4VP Annex B.2)", ErrMalformedResponse, clip(id, maxVPTokenKeyLen))
				}
				p.Payload = raw
				p.JWKThumbprint = jwkThumbprint
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// clip bounds attacker-controlled identifier text quoted in errors.
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// walletErrorFrom converts a wallet-sent OID4VP error response into a
// *WalletError (T-08.11 finishes the mapping/caps). If the wallet echoed
// a state, it must still match — otherwise the error cannot be attributed
// to this session.
func walletErrorFrom(s *Session, vals url.Values) error {
	if st := vals.Get("state"); st != "" && subtle.ConstantTimeCompare([]byte(st), []byte(s.State)) != 1 {
		return ErrStateMismatch
	}
	return &WalletError{
		Code:        clip(vals.Get("error"), maxWalletErrorLen),
		Description: clip(vals.Get("error_description"), maxWalletErrorLen),
	}
}

// maxWalletErrorLen caps wallet-supplied error text (untrusted).
const maxWalletErrorLen = 256
