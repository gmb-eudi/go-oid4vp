package oid4vp

import (
	dcql "github.com/gmb-eudi/go-dcql"
	mdoc "github.com/gmb-eudi/go-mdoc"
)

// SessionTranscriptFor builds the ISO 18013-5 SessionTranscript for one
// verified-to-be mso_mdoc Presentation by delegating to the go-mdoc
// constructors (OID4VP Annex B.2; ISO/IEC TS 18013-7 Annex B; Annex A for
// DCAPI):
//
//   - request_uri flows: OID4VPHandover(clientID, nonce, jwkThumbprint,
//     responseURI).
//   - DCAPI flows (Origin set): OID4VPDCAPIHandover(origin, nonce,
//     jwkThumbprint) — no client_id or response_uri in this variant.
//
// jwkThumbprint (Presentation.JWKThumbprint) is the RFC 7638 thumbprint of
// the RP's OWN ephemeral response-encryption public key — computed by
// ProcessResponse from Session.EphemeralKeyPKCS8, never from anything
// wallet-supplied. The JWE apu value is NOT an input to either constructor
// here and is not read anywhere in the pipeline (T-08.7 correction
// 2026-07-06: this task's original brief assumed apu/mdocGeneratedNonce
// filled this slot; the go-mdoc constructors' actual, EU-reference-verified
// shape takes jwkThumbprint instead — see WP-08 README Decisions
// "T-08.7/T-08.9 correction" for the full rationale).
//
// FLAG (carried from go-mdoc's OID4VPHandover/OID4VPDCAPIHandover doc
// comments and docs/mdoc-eu-gap-report.md): this handover shape is
// corroborated against a production EU reference verifier, not yet
// byte-for-byte confirmed against the OpenID4VP 1.0 Annex B.2 primary spec
// text (not vendored under references/ at the time of writing) — re-verify
// once that text is available.
//
// verifier-core passes the result to mdoc.Verifier.Verify as
// VerifyInput.SessionTranscript (WP-03). Fail closed: incomplete
// parameters are an error, never a zero transcript. Pure delegation — no
// CBOR/SessionTranscript construction of its own.
func SessionTranscriptFor(p Presentation) (mdoc.SessionTranscript, error) {
	var zero mdoc.SessionTranscript
	if p.Format != dcql.FormatMdoc {
		return zero, ErrTranscriptParams
	}
	if p.Nonce == "" || p.JWKThumbprint == "" {
		return zero, ErrTranscriptParams
	}
	if p.Origin != "" {
		// OID4VP Annex A / Annex B.2.6.2: DCAPI handover carries no
		// client_id or response_uri; origin is the RP identity signal
		// instead. T-08.9 wires the full DCAPI response path.
		return mdoc.OID4VPDCAPIHandover(p.Origin, p.Nonce, p.JWKThumbprint), nil
	}
	if p.ClientID == "" || p.ResponseURI == "" {
		return zero, ErrTranscriptParams
	}
	return mdoc.OID4VPHandover(p.ClientID, p.Nonce, p.JWKThumbprint, p.ResponseURI), nil
}
