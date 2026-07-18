package oid4vp

import "errors"

// Sentinel errors. Libraries return typed errors; services map them to
// err:domain:reason problem codes. The mapping each
// sentinel is expected to receive is noted inline. None of these messages
// ever carries attribute values, request bodies, or token contents —
// never leaked to the wallet.
var (
	// Session / store lifecycle.
	ErrSessionInvalid     = errors.New("oid4vp: invalid session")              // programming error; 500 at boundary
	ErrSessionNotFound    = errors.New("oid4vp: session not found or expired") // err:session:not-found
	ErrSessionExpired     = errors.New("oid4vp: session expired")              // err:session:not-found
	ErrSessionConsumed    = errors.New("oid4vp: session already consumed")     // err:session:consumed
	ErrSessionNotConsumed = errors.New("oid4vp: session must be obtained via SessionStore.ConsumeOnce")

	// Engine configuration / request spec.
	ErrConfig                    = errors.New("oid4vp: invalid engine config")
	ErrSANMismatch               = errors.New("oid4vp: client DNS name does not match a SAN dNSName in the WRPAC leaf") // [OID4VP §5] x509_san_dns
	ErrUnsupportedClientIDPrefix = errors.New("oid4vp: unsupported client_id prefix")                                   // x509_san_dns only in v1
	ErrSpec                      = errors.New("oid4vp: invalid request spec")
	ErrNoRegistration            = errors.New("oid4vp: registration reference required in every request (ARF RPRC_19a)")
	ErrFlowMismatch              = errors.New("oid4vp: operation not valid for this session flow")

	// request_uri lifecycle.
	ErrRequestURIConsumed    = errors.New("oid4vp: request object already served (single-use request_uri)") // [OID4VP §5] request_uri
	ErrWalletMetadataInvalid = errors.New("oid4vp: wallet metadata rejected")

	// Response processing. All map to
	// err:presentation:invalid-response unless noted.
	ErrBodyTooLarge        = errors.New("oid4vp: response body exceeds configured cap")
	ErrMalformedResponse   = errors.New("oid4vp: malformed response")
	ErrDecrypt             = errors.New("oid4vp: response decryption failed")               // stale/foreign key, bad JWE
	ErrStateMismatch       = errors.New("oid4vp: state does not match session")             // err:presentation:nonce-mismatch
	ErrAPVMismatch         = errors.New("oid4vp: JWE apv does not match the session nonce") // err:presentation:nonce-mismatch
	ErrUnknownCredentialID = errors.New("oid4vp: vp_token key does not identify a credential query")

	// Same-device return, [OID4VP §8.2/§8.3/§12.1].
	ErrNoResponseCode       = errors.New("oid4vp: no response_code minted for this session")
	ErrResponseCodeMismatch = errors.New("oid4vp: response_code is not bound to this session") // err:presentation:nonce-mismatch
	ErrResponseCodeConsumed = errors.New("oid4vp: response_code already used")                 // err:session:consumed

	// DCAPI, OID4VP Annex A.
	ErrOriginNotExpected = errors.New("oid4vp: response origin not in expected_origins")

	// transaction_data (phase-2 flag).
	ErrTransactionDataDisabled   = errors.New("oid4vp: transaction_data requested but the phase-2 flag is off")
	ErrTransactionDataInvalid    = errors.New("oid4vp: invalid transaction_data entry")
	ErrTransactionDataMissing    = errors.New("oid4vp: transaction_data_hashes missing from presentation")
	ErrTransactionDataUnexpected = errors.New("oid4vp: transaction_data_hashes present but none were requested")
	ErrTransactionDataMismatch   = errors.New("oid4vp: transaction_data_hashes do not match the request")

	// SessionTranscript delegation.
	ErrTranscriptParams = errors.New("oid4vp: presentation lacks the parameters for a SessionTranscript")
)

// WalletError is an OID4VP error response sent BY the wallet (e.g. the
// user declined: error=access_denied). It is not an engine failure; the
// service records the outcome and acknowledges the wallet. Code and
// Description are wallet-supplied, length-capped, and must be treated as
// untrusted text (never logged raw next to attribute data).
type WalletError struct {
	Code        string
	Description string
}

func (e *WalletError) Error() string { return "oid4vp: wallet returned error " + e.Code }
