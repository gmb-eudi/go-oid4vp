package oid4vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// sampleSDJWT is a structural stand-in for a dc+sd-jwt presentation
// (issuer-jwt~disclosure~kb-jwt). Cryptographic verification of the
// content is go-sdjwt's job; the pipeline wiring lives in the verifier.
const sampleSDJWT = "eyJhbGciOiJFUzI1NiJ9.eyJmYWtlIjoidmMifQ.c2ln~WyJzYWx0IiwiZmFtaWx5X25hbWUiLCJEZW50Il0~a2JqdXQ"

// sampleDeviceResponse is CBOR-ish stand-in bytes for an mso_mdoc
// DeviceResponse; go-mdoc owns real parsing. vp_token carries it
// base64url-encoded (OID4VP Annex B.2). Used by the mso_mdoc flow tests
// (see transcript_test.go).
var sampleDeviceResponse = []byte{0xA2, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x63, 0x31, 0x2E, 0x30}

// extractEncJWK pulls the per-session ephemeral encryption key out of the
// decoded request-object claims — exactly what a wallet does.
func extractEncJWK(t *testing.T, claims map[string]any) *ecdsa.PublicKey {
	t.Helper()
	keys := claims["client_metadata"].(map[string]any)["jwks"].(map[string]any)["keys"].([]any)
	jwk := keys[0].(map[string]any)
	if jwk["crv"] != "P-256" || jwk["use"] != "enc" {
		t.Fatalf("unexpected enc JWK: %v", jwk)
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk["y"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if len(x) != 32 || len(y) != 32 {
		t.Fatalf("unexpected P-256 coordinate sizes: %d/%d", len(x), len(y))
	}

	// 0x04 || X || Y — parsed rather than assigned to the deprecated X/Y fields,
	// which also checks the point is on the curve.
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}

	return pub
}

// encryptResponse builds the wallet-side JWE (ECDH-ES + A128GCM — a
// policy-allowed pair; [OID4VP §8.2] direct_post.jwt). apv carries the
// request nonce and is validated by the engine; apu is a header some
// wallets may still send but the engine no longer reads it at all — it is
// set here only
// so tests can prove its presence/absence makes no difference (OID4VP
// Annex B.2 / ISO 18013-7 Annex B). Empty strings omit the header.
func encryptResponse(t *testing.T, pub *ecdsa.PublicKey, payload []byte, apu, apv string) string {
	t.Helper()
	hdrs := jwe.NewHeaders()
	if apu != "" {
		if err := hdrs.Set("apu", []byte(apu)); err != nil {
			t.Fatal(err)
		}
	}
	if apv != "" {
		if err := hdrs.Set("apv", []byte(apv)); err != nil {
			t.Fatal(err)
		}
	}
	// apu/apv MUST ride in the per-recipient (key-agreement) headers so
	// jwx's ECDH-ES ConcatKDF consumes them on encrypt; for compact
	// serialization jwx merges them into the protected header, so the
	// verifier reads the same values and derives the same key. Placing them
	// in WithProtectedHeaders instead leaves them out of the encrypt-side
	// KDF while the decrypt side still uses them → AEAD auth failure. This
	// mirrors go-eudi-crypto's EncryptJWE (the canonical wallet-side path).
	tok, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.ECDH_ES(), pub, jwe.WithPerRecipientHeaders(hdrs)),
		jwe.WithContentEncryption(jwa.A128GCM()))
	if err != nil {
		t.Fatal(err)
	}
	return string(tok)
}

// responsePayloadJSON is the decrypted direct_post.jwt payload:
// vp_token object + state ([OID4VP §8.1/§8.2]).
func responsePayloadJSON(t *testing.T, state string, vpToken map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"vp_token": vpToken, "state": state})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// formBody renders the wallet POST body (application/x-www-form-urlencoded).
func formBody(jweCompact string) []byte {
	return []byte(url.Values{"response": {jweCompact}}.Encode())
}

// walletRespond drives the full wallet side for a session: fetch+verify
// the request object, extract nonce/state/JWK, encrypt vpToken. Returns
// the POST body. mdocGeneratedNonce != "" sets apu — a value the engine no
// longer reads (kept only so tests can construct fixtures with apu present
// or absent; see encryptResponse's doc comment).
func walletRespond(t *testing.T, env *testEnv, s *oid4vp.Session, vpToken map[string]any, mdocGeneratedNonce string) []byte {
	t.Helper()
	claims, _ := buildRequestJWT(t, env, s)
	pub := extractEncJWK(t, claims)
	payload := responsePayloadJSON(t, claims["state"].(string), vpToken)
	return formBody(encryptResponse(t, pub, payload, mdocGeneratedNonce, claims["nonce"].(string)))
}
