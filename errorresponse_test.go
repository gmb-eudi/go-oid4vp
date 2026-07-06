package oid4vp_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// T-08.11: wallet-boundary errors serialize per the OID4VP error-response
// format (NOT problem+json). Each engine sentinel maps to a registered
// error code + HTTP status.
func TestErrorResponseMapping(t *testing.T) {
	env := newTestEnv(t)
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"nil is server_error", nil, 500, "server_error"},
		{"malformed response", oid4vp.ErrMalformedResponse, 400, "invalid_request"},
		{"body too large", oid4vp.ErrBodyTooLarge, 400, "invalid_request"},
		{"state mismatch", oid4vp.ErrStateMismatch, 400, "invalid_request"},
		{"apv mismatch", oid4vp.ErrAPVMismatch, 400, "invalid_request"},
		{"apu missing", oid4vp.ErrAPUMissing, 400, "invalid_request"},
		{"unknown credential id", oid4vp.ErrUnknownCredentialID, 400, "invalid_request"},
		{"decrypt failure", oid4vp.ErrDecrypt, 400, "invalid_request"},
		{"origin not expected", oid4vp.ErrOriginNotExpected, 400, "invalid_client"},
		{"session not found", oid4vp.ErrSessionNotFound, 404, "invalid_request"},
		{"session expired", oid4vp.ErrSessionExpired, 404, "invalid_request"},
		{"session consumed", oid4vp.ErrSessionConsumed, 400, "invalid_request"},
		{"request_uri consumed", oid4vp.ErrRequestURIConsumed, 400, "invalid_request_uri"},
		{"wallet metadata invalid", oid4vp.ErrWalletMetadataInvalid, 400, "invalid_request"},
		{"no registration", oid4vp.ErrNoRegistration, 500, "server_error"}, // our build error, not wallet-caused
		{"config error", oid4vp.ErrConfig, 500, "server_error"},
		{"tx data mismatch", oid4vp.ErrTransactionDataMismatch, 400, "invalid_request"},
		{"tx data missing", oid4vp.ErrTransactionDataMissing, 400, "invalid_request"},
		{"unmapped internal", fmt.Errorf("boom"), 500, "server_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := env.engine.ErrorResponse(tt.err)
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
			var resp map[string]any
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("body not JSON: %v (%s)", err, body)
			}
			if resp["error"] != tt.wantCode {
				t.Errorf("error = %v, want %v", resp["error"], tt.wantCode)
			}
			// OID4VP error response shape — never problem+json members.
			for _, forbidden := range []string{"type", "title", "status", "detail", "instance"} {
				if _, present := resp[forbidden]; present {
					t.Errorf("body carries problem+json member %q — must be OID4VP error shape", forbidden)
				}
			}
			if _, present := resp["error_description"]; !present {
				t.Error("error_description missing")
			}
		})
	}
}

// A *WalletError (the wallet already sent us an OID4VP error) maps by its
// code. access_denied is a user decision, invalid_request otherwise.
func TestErrorResponseWalletError(t *testing.T) {
	env := newTestEnv(t)
	for _, tt := range []struct {
		code       string
		wantStatus int
		wantCode   string
	}{
		{"access_denied", 400, "access_denied"},
		{"invalid_request", 400, "invalid_request"},
		{"vp_formats_not_supported", 400, "vp_formats_not_supported"},
		{"some_unregistered_code", 400, "invalid_request"}, // unknown wallet code → invalid_request
	} {
		t.Run(tt.code, func(t *testing.T) {
			status, body := env.engine.ErrorResponse(&oid4vp.WalletError{Code: tt.code, Description: "x"})
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
			var resp map[string]string
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatal(err)
			}
			if resp["error"] != tt.wantCode {
				t.Errorf("error = %q, want %q", resp["error"], tt.wantCode)
			}
		})
	}
}

// Hard rule 3: error_description is a static safe string, never the raw Go
// error text (which can carry identifiers).
func TestErrorResponseDescriptionIsStatic(t *testing.T) {
	env := newTestEnv(t)
	wrapped := fmt.Errorf("%w: vp_token[\"SECRET-CRED-ID\"] rejected", oid4vp.ErrUnknownCredentialID)
	_, body := env.engine.ErrorResponse(wrapped)
	if strings.Contains(string(body), "SECRET-CRED-ID") {
		t.Fatalf("error_description leaked wrapped detail: %s", body)
	}
	var resp map[string]string
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] != "invalid_request" {
		t.Errorf("wrapped sentinel must still map: error = %q", resp["error"])
	}
}

// Every exported sentinel must be handled by the table (no default-500
// surprises for known errors except the deliberately-internal ones).
func TestErrorResponseCoversResponseErrors(t *testing.T) {
	env := newTestEnv(t)
	// The wallet-boundary errors that a wallet can actually trigger must
	// NOT collapse to server_error.
	walletTriggerable := []error{
		oid4vp.ErrMalformedResponse, oid4vp.ErrBodyTooLarge, oid4vp.ErrStateMismatch,
		oid4vp.ErrAPVMismatch, oid4vp.ErrAPUMissing, oid4vp.ErrUnknownCredentialID,
		oid4vp.ErrDecrypt, oid4vp.ErrOriginNotExpected, oid4vp.ErrRequestURIConsumed,
		oid4vp.ErrSessionNotFound, oid4vp.ErrSessionExpired, oid4vp.ErrSessionConsumed,
		oid4vp.ErrWalletMetadataInvalid, oid4vp.ErrResponseCodeMismatch, oid4vp.ErrResponseCodeConsumed,
	}
	for _, e := range walletTriggerable {
		status, _ := env.engine.ErrorResponse(e)
		if status >= 500 {
			t.Errorf("%v mapped to %d — wallet-triggerable errors must be 4xx", e, status)
		}
	}
}
