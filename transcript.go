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
// the RP's OWN ephemeral response-encryption public key, as raw digest bytes —
// computed by ProcessResponse from Session.EphemeralKeyPKCS8, never from
// anything wallet-supplied. The JWE apu value is NOT an input to either
// constructor here and is not read anywhere in the pipeline.
//
// eudi-verifier-core passes the result to mdoc.Verifier.Verify as
// VerifyInput.SessionTranscript. Fail closed: incomplete
// parameters are an error, never a zero transcript. Pure delegation — no
// CBOR/SessionTranscript construction of its own.
func SessionTranscriptFor(p Presentation) (mdoc.SessionTranscript, error) {
	var zero mdoc.SessionTranscript
	if p.Format != dcql.FormatMdoc {
		return zero, ErrTranscriptParams
	}
	// Both response paths here are encrypted, so a missing thumbprint means the
	// presentation was not populated by ProcessResponse — refuse rather than
	// build the unencrypted-response (CBOR null) transcript, which would be a
	// different transcript silently accepted.
	if p.Nonce == "" || len(p.JWKThumbprint) == 0 {
		return zero, ErrTranscriptParams
	}
	if p.Origin != "" {
		// OID4VP Annex A / Annex B.2.6.2: DCAPI handover carries no
		// client_id or response_uri; origin is the RP identity signal
		// instead. The full DCAPI response path wires Origin end-to-end.
		return mdoc.OID4VPDCAPIHandover(p.Origin, p.Nonce, p.JWKThumbprint), nil
	}
	if p.ClientID == "" || p.ResponseURI == "" {
		return zero, ErrTranscriptParams
	}
	return mdoc.OID4VPHandover(p.ClientID, p.Nonce, p.JWKThumbprint, p.ResponseURI), nil
}
