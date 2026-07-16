package oid4vp

import (
	"crypto/subtle"
	"net/url"
	"strings"
)

// RedirectURI renders the [OID4VP §8.3] same-device return: the response endpoint
// answers the wallet's POST with 200 {"redirect_uri": <this value>}, and
// the wallet navigates the user's browser there. The response_code in the
// query fences the result fetch to the browser session that actually
// completed the presentation ([OID4VP §8.2, §12.1]).
func (e *Engine) RedirectURI(s *Session) (string, error) {
	if s == nil {
		return "", ErrSessionInvalid
	}
	if s.Flow != SameDevice {
		return "", ErrFlowMismatch
	}
	if s.ResponseCode == "" {
		return "", ErrNoResponseCode
	}
	sep := "?"
	if strings.Contains(s.ReturnURI, "?") {
		sep = "&"
	}
	return s.ReturnURI + sep + "response_code=" + url.QueryEscape(s.ResponseCode), nil
}

// ConsumeResponseCode redeems a response_code: constant-time comparison
// against the code minted FOR THIS SESSION, single-use. This is the [OID4VP §12.1]
// session-fixation defense — an attacker who fixated their own session id
// on a victim cannot fetch the victim's result: their code is bound to
// their session. The caller persists s (SessionStore.Save) so the
// used-marker sticks.
func (e *Engine) ConsumeResponseCode(s *Session, code ResponseCode) error {
	if s == nil {
		return ErrSessionInvalid
	}
	if s.ResponseCode == "" {
		return ErrNoResponseCode
	}
	if s.ResponseCodeUsed {
		return ErrResponseCodeConsumed
	}
	if subtle.ConstantTimeCompare([]byte(s.ResponseCode), []byte(code)) != 1 {
		return ErrResponseCodeMismatch
	}
	s.ResponseCodeUsed = true
	return nil
}
