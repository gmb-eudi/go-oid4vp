package oid4vp

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// maxWalletMetadataBytes caps the absorbed wallet metadata document.
const maxWalletMetadataBytes = 64 << 10

// AbsorbWalletMetadata is the wallet-metadata absorption hook
// ([OID4VP §5] request_uri_method). v1 pins request_uri_method=get, so no
// metadata arrives on the request_uri fetch yet; services call this when
// the future post method (or a DCAPI capability hint) delivers one. The
// document is validated as a JSON object, size-capped, and stored verbatim
// on the session for policy use — never parsed further here, never logged
// (treat as untrusted).
func (e *Engine) AbsorbWalletMetadata(s *Session, raw []byte) error {
	if s == nil {
		return ErrSessionInvalid
	}
	if len(raw) == 0 || len(raw) > maxWalletMetadataBytes {
		return fmt.Errorf("%w: metadata size out of bounds", ErrWalletMetadataInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var doc map[string]json.RawMessage
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("%w: not a JSON object", ErrWalletMetadataInvalid)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data", ErrWalletMetadataInvalid)
	}
	if doc == nil {
		return fmt.Errorf("%w: not a JSON object", ErrWalletMetadataInvalid)
	}
	cp := make([]byte, len(raw))
	copy(cp, raw)
	s.WalletMetadata = cp
	return nil
}
