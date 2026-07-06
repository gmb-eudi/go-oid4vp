package oid4vp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// transactionDataStrings renders the request transaction_data member:
// each entry base64url-encoded (OID4VP §5 transaction_data). Callers only
// reach this when the phase-2 flag is on and entries were validated at
// NewSession.
func transactionDataStrings(td [][]byte) []any {
	out := make([]any, len(td))
	for i, e := range td {
		out[i] = base64.RawURLEncoding.EncodeToString(e)
	}
	return out
}

// validateTransactionData enforces that each entry is a JSON object
// (OID4VP §5). Called from validateSpec when the flag is on.
func validateTransactionData(td [][]byte) error {
	for i, e := range td {
		var obj map[string]json.RawMessage
		dec := json.NewDecoder(bytes.NewReader(e))
		if err := dec.Decode(&obj); err != nil || obj == nil {
			return fmt.Errorf("%w: entry %d must be a JSON object", ErrTransactionDataInvalid, i)
		}
	}
	return nil
}

// TransactionDataHashes computes the expected transaction_data_hashes for
// a set of request entries: base64url( H( base64url(entry) ) ), where H is
// the digest bound to alg by the ECCG policy (OID4VP §5 transaction_data;
// HAIP baseline ES256 ⇒ SHA-256). No hash literal here — the algorithm
// comes from the policy (hard rule 4).
func TransactionDataHashes(td [][]byte, alg string, policy crypto.Policy) ([]string, error) {
	if policy == nil {
		policy = crypto.ECCG()
	}
	h, err := policy.HashForAlg(alg)
	if err != nil {
		return nil, err
	}
	if !h.Available() {
		return nil, fmt.Errorf("%w: hash for %q unavailable", crypto.ErrAlgorithmNotAllowed, alg)
	}
	out := make([]string, len(td))
	for i, e := range td {
		enc := base64.RawURLEncoding.EncodeToString(e)
		digest := h.New()
		digest.Write([]byte(enc))
		out[i] = base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
	}
	return out, nil
}

// ValidateTransactionDataEcho compares the transaction_data_hashes echoed
// by the wallet (in a KB-JWT for dc+sd-jwt, or the device-signed payload
// for mso_mdoc — extracted by go-sdjwt/go-mdoc, WP-09) against the hashes
// of the session's request entries (OID4VP §5). Set semantics: the wallet
// may reorder. present/absent/mismatch matrix (T-08.10):
//   - flag off but session carries entries → ErrTransactionDataDisabled
//   - entries requested, none echoed → ErrTransactionDataMissing
//   - none requested, some echoed → ErrTransactionDataUnexpected
//   - counts differ or any hash unmatched → ErrTransactionDataMismatch
func (e *Engine) ValidateTransactionDataEcho(s *Session, echoedHashes []string, hashAlgName string) error {
	if s == nil {
		return ErrSessionInvalid
	}
	if len(s.TransactionData) > 0 && !e.cfg.EnableTransactionData {
		return ErrTransactionDataDisabled
	}
	if len(s.TransactionData) == 0 {
		if len(echoedHashes) > 0 {
			return ErrTransactionDataUnexpected
		}
		return nil
	}
	if len(echoedHashes) == 0 {
		return ErrTransactionDataMissing
	}
	want, err := TransactionDataHashes(s.TransactionData, hashAlgName, e.policy)
	if err != nil {
		return err
	}
	if len(want) != len(echoedHashes) {
		return ErrTransactionDataMismatch
	}
	remaining := make(map[string]int, len(want))
	for _, w := range want {
		remaining[w]++
	}
	for _, got := range echoedHashes {
		if remaining[got] == 0 {
			return ErrTransactionDataMismatch
		}
		remaining[got]--
	}
	return nil
}
