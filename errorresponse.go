package oid4vp

import (
	"encoding/json"
	"errors"
)

// OID4VP / OAuth 2.0 error codes used at the wallet boundary (OID4VP
// Error Response; [RFC 6749 §4.1.2.1 / §5.2]).
const (
	errInvalidRequest        = "invalid_request"
	errInvalidClient         = "invalid_client"
	errAccessDenied          = "access_denied"
	errVPFormatsNotSupported = "vp_formats_not_supported"
	errInvalidRequestURI     = "invalid_request_uri"
	errInvalidRequestObject  = "invalid_request_object"
	errServer                = "server_error"
)

// ErrorResponse serializes an engine error for the WALLET boundary in the
// OpenID4VP Error Response format ({"error":..,"error_description":..}),
// NOT problem+json — the protocol wins on the wallet boundary.
// status is a plain int so this library imports no
// HTTP package. Services map the SAME sentinels to
// err:domain:reason problem codes for their own logging/metrics.
//
// Unknown or internal errors collapse to 500 server_error: fail closed,
// leak nothing.
func (e *Engine) ErrorResponse(err error) (int, []byte) {
	if err == nil {
		return serialize(500, errServer, "internal error")
	}
	// A wallet-sent OID4VP error we surfaced: echo its (bounded) code.
	var we *WalletError
	if errors.As(err, &we) {
		return serialize(400, normalizeWalletCode(we.Code), "wallet reported an error")
	}
	for _, m := range errorTable() {
		if errors.Is(err, m.sentinel) {
			return serialize(m.status, m.code, m.desc)
		}
	}
	return serialize(500, errServer, "internal error")
}

type sentinelMapping struct {
	sentinel error
	status   int
	code     string
	desc     string
}

// errorTable maps each engine sentinel to its wallet-boundary response.
// Order matters only for sentinels that could wrap each other; these do
// not, so the table is a flat lookup. // [OID4VP §8.2] error responses.
func errorTable() []sentinelMapping {
	return []sentinelMapping{
		// Session lifecycle.
		{ErrSessionNotFound, 404, errInvalidRequest, "unknown or expired session"},
		{ErrSessionExpired, 404, errInvalidRequest, "session expired"},
		{ErrSessionConsumed, 400, errInvalidRequest, "response already received"},
		{ErrRequestURIConsumed, 400, errInvalidRequestURI, "request already retrieved"},
		{ErrWalletMetadataInvalid, 400, errInvalidRequest, "wallet metadata rejected"},

		// Response processing (wallet-triggerable).
		{ErrBodyTooLarge, 400, errInvalidRequest, "response too large"},
		{ErrMalformedResponse, 400, errInvalidRequest, "malformed response"},
		{ErrDecrypt, 400, errInvalidRequest, "response could not be decrypted"},
		{ErrStateMismatch, 400, errInvalidRequest, "state binding failed"},
		{ErrAPVMismatch, 400, errInvalidRequest, "response nonce binding failed"},
		{ErrUnknownCredentialID, 400, errInvalidRequest, "unexpected credential in response"},

		// DCAPI.
		{ErrOriginNotExpected, 400, errInvalidClient, "origin not allowed"},

		// Same-device return.
		{ErrResponseCodeMismatch, 400, errInvalidRequest, "response code binding failed"},
		{ErrResponseCodeConsumed, 400, errInvalidRequest, "response code already used"},
		{ErrNoResponseCode, 400, errInvalidRequest, "no response code for session"},

		// transaction_data (wallet-triggerable at binding time).
		{ErrTransactionDataMismatch, 400, errInvalidRequest, "transaction data binding failed"},
		{ErrTransactionDataMissing, 400, errInvalidRequest, "transaction data not confirmed"},
		{ErrTransactionDataUnexpected, 400, errInvalidRequest, "unexpected transaction data"},

		// Flow misuse (a wallet hitting the wrong endpoint).
		{ErrFlowMismatch, 400, errInvalidRequest, "wrong endpoint for this session"},

		// Our-side build/config errors — never wallet-caused → 500,
		// leak nothing.
		{ErrNoRegistration, 500, errServer, "internal error"},
		{ErrConfig, 500, errServer, "internal error"},
		{ErrSpec, 500, errServer, "internal error"},
		{ErrSessionInvalid, 500, errServer, "internal error"},
		{ErrSessionNotConsumed, 500, errServer, "internal error"},
		{ErrTranscriptParams, 500, errServer, "internal error"},
		{ErrTransactionDataDisabled, 500, errServer, "internal error"},
		{ErrTransactionDataInvalid, 500, errServer, "internal error"},
		{ErrSANMismatch, 500, errServer, "internal error"},
		{ErrUnsupportedClientIDPrefix, 500, errServer, "internal error"},
	}
}

// normalizeWalletCode keeps only registered OID4VP/OAuth error codes; any
// other wallet-supplied value collapses to invalid_request (
// do not echo unbounded wallet text as a protocol code).
func normalizeWalletCode(code string) string {
	switch code {
	case errAccessDenied, errInvalidRequest, errInvalidClient,
		errVPFormatsNotSupported, errInvalidRequestURI, errInvalidRequestObject:
		return code
	default:
		return errInvalidRequest
	}
}

func serialize(status int, code, desc string) (int, []byte) {
	// json.Marshal of a fixed-shape map never fails.
	body, _ := json.Marshal(map[string]string{
		"error":             code,
		"error_description": desc,
	})
	return status, body
}
