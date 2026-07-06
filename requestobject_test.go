package oid4vp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	dcql "github.com/gmb-eudi/go-dcql"
	crypto "github.com/gmb-eudi/go-eudi-crypto"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// buildRequestJWT signs, verifies against the WRPAC leaf key and decodes —
// this is what a wallet does with the fetched request object.
func buildRequestJWT(t *testing.T, env *testEnv, s *oid4vp.Session) (map[string]any, crypto.Header) {
	t.Helper()
	tok, err := env.engine.RequestObjectJWT(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	payload, hdr, err := crypto.VerifyJWS(tok, env.leafKey.Public())
	if err != nil {
		t.Fatalf("request object must verify against the WRPAC leaf key: %v", err)
	}
	var claims map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		t.Fatal(err)
	}
	return claims, hdr
}

func newServedSession(t *testing.T, env *testEnv, spec oid4vp.RequestSpec) (*oid4vp.Session, map[string]any, crypto.Header) {
	t.Helper()
	s, _, err := env.engine.NewSession(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	claims, hdr := buildRequestJWT(t, env, s)
	return s, claims, hdr
}

// T-08.3 acceptance: golden JWT decode asserts EVERY member. (Byte-golden
// is impossible by design: ECDSA signatures are randomized and the
// per-session ephemeral JWK is generated from crypto/rand — the decoded
// member set is the golden.)
func TestRequestObjectJWTEveryMember(t *testing.T) {
	env := newTestEnv(t)
	s, claims, hdr := newServedSession(t, env, crossDeviceSpec(t))

	// Protected header (RFC 9101; OID4VP §5 x509_san_dns).
	if hdr["typ"] != "oauth-authz-req+jwt" {
		t.Errorf("typ = %v, want oauth-authz-req+jwt", hdr["typ"])
	}
	if hdr["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256 (derived from the P-256 WRPAC key)", hdr["alg"])
	}
	x5c, ok := hdr["x5c"].([]any)
	if !ok || len(x5c) != len(env.chain) {
		t.Fatalf("x5c = %v, want %d certs", hdr["x5c"], len(env.chain))
	}
	for i, c := range env.chain {
		if x5c[i].(string) != base64.StdEncoding.EncodeToString(c.Raw) {
			t.Errorf("x5c[%d] does not match WRPAC chain cert", i)
		}
	}

	// RFC 9101 claims.
	if claims["iss"] != env.engine.ClientID() {
		t.Errorf("iss = %v, want client_id (RFC 9101)", claims["iss"])
	}
	if claims["aud"] != "https://self-issued.me/v2" {
		t.Errorf("aud = %v (WP-08 decision)", claims["aud"])
	}
	iat, _ := claims["iat"].(json.Number).Int64()
	nbf, _ := claims["nbf"].(json.Number).Int64()
	exp, _ := claims["exp"].(json.Number).Int64()
	if iat != testEpoch.Unix() || nbf != testEpoch.Unix() {
		t.Errorf("iat/nbf = %d/%d, want %d", iat, nbf, testEpoch.Unix())
	}
	if exp != s.ExpiresAt.Unix() {
		t.Errorf("exp = %d, want session expiry %d", exp, s.ExpiresAt.Unix())
	}

	// OID4VP §5 / §8.2 members.
	if claims["client_id"] != "x509_san_dns:verifier.example.com" {
		t.Errorf("client_id = %v", claims["client_id"])
	}
	if claims["response_type"] != "vp_token" {
		t.Errorf("response_type = %v", claims["response_type"])
	}
	if claims["response_mode"] != "direct_post.jwt" {
		t.Errorf("response_mode = %v (HAIP: encrypted responses)", claims["response_mode"])
	}
	if claims["response_uri"] != s.ResponseURI {
		t.Errorf("response_uri = %v, want %v", claims["response_uri"], s.ResponseURI)
	}
	if _, present := claims["redirect_uri"]; present {
		t.Error("redirect_uri MUST NOT be present when response_uri is used (OID4VP §8.2)")
	}
	if claims["nonce"] != s.Nonce || claims["state"] != s.State {
		t.Error("nonce/state must equal the session values")
	}

	// dcql_query roundtrips through the strict parser to the same model.
	rawQuery, err := json.Marshal(claims["dcql_query"])
	if err != nil {
		t.Fatal(err)
	}
	gotQuery, err := dcql.Parse(rawQuery)
	if err != nil {
		t.Fatalf("dcql_query must re-parse strictly: %v", err)
	}
	wantQuery := testQuery(t)
	if !reflect.DeepEqual(*gotQuery, wantQuery) {
		t.Errorf("dcql_query mismatch:\n got %#v\nwant %#v", *gotQuery, wantQuery)
	}

	// client_metadata: ephemeral JWK + enc values + vp_formats_supported.
	cm, ok := claims["client_metadata"].(map[string]any)
	if !ok {
		t.Fatal("client_metadata missing")
	}
	keys := cm["jwks"].(map[string]any)["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("jwks.keys = %v, want exactly the per-session ephemeral key", keys)
	}
	jwk := keys[0].(map[string]any)
	for k, want := range map[string]string{"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "kid": s.ID} {
		if jwk[k] != want {
			t.Errorf("jwk[%s] = %v, want %v", k, jwk[k], want)
		}
	}
	for _, coord := range []string{"x", "y"} {
		raw, err := base64.RawURLEncoding.DecodeString(jwk[coord].(string))
		if err != nil || len(raw) != 32 {
			t.Errorf("jwk.%s: %d bytes, err %v; want 32-byte P-256 coordinate", coord, len(raw), err)
		}
	}
	if !reflect.DeepEqual(cm["encrypted_response_enc_values_supported"], []any{"A128GCM", "A256GCM"}) {
		t.Errorf("encrypted_response_enc_values_supported = %v", cm["encrypted_response_enc_values_supported"])
	}
	vf, ok := cm["vp_formats_supported"].(map[string]any)
	if !ok {
		t.Fatal("vp_formats_supported missing (OID4VP §5 client_metadata)")
	}
	sd := vf["dc+sd-jwt"].(map[string]any)
	if !reflect.DeepEqual(sd["sd-jwt_alg_values"], []any{"ES256"}) || !reflect.DeepEqual(sd["kb-jwt_alg_values"], []any{"ES256"}) {
		t.Errorf("dc+sd-jwt alg values = %v", sd)
	}
	md := vf["mso_mdoc"].(map[string]any)
	wantCose := []any{json.Number("-7")}
	if !reflect.DeepEqual(md["issuerauth_alg_values"], wantCose) || !reflect.DeepEqual(md["deviceauth_alg_values"], wantCose) {
		t.Errorf("mso_mdoc alg values = %v", md)
	}

	// RPRC_19a registration member — ALWAYS present. Field vocabulary is
	// rpcert.RegistrationRef.Claims() (WP-07 Decision 9 / TS 119 475
	// §5.2.4: name, sub, registry_uri, intended_use_id).
	reg, ok := claims["verifier_registration"].(map[string]any)
	if !ok {
		t.Fatal("verifier_registration missing (ARF RPRC_19a)")
	}
	want := testRegistration()
	for k, v := range map[string]string{
		"name":            want.ClientName,
		"sub":             want.ClientID,
		"registry_uri":    want.RegistryURI,
		"intended_use_id": want.IntendedUseID,
	} {
		if reg[k] != v {
			t.Errorf("verifier_registration[%s] = %v, want %v", k, reg[k], v)
		}
	}

	// No WRPRC supplied → no verifier_info member.
	if _, present := claims["verifier_info"]; present {
		t.Error("verifier_info must be absent without a WRPRC")
	}
	// transaction_data only under the phase-2 flag (T-08.10).
	if _, present := claims["transaction_data"]; present {
		t.Error("transaction_data must be absent when not requested")
	}
}

// Optional WRPRC rides in verifier_info (OID4VP §5; WP-08 decision).
func TestRequestObjectAttachesWRPRC(t *testing.T) {
	env := newTestEnv(t)
	spec := crossDeviceSpec(t)
	spec.WRPRC = []byte("eyJhbGciOiJFUzI1NiJ9.wrprc-payload.sig") // structural stand-in; real WRPRC validation is go-eudi-rpcert's job (WP-07)
	_, claims, _ := newServedSession(t, env, spec)
	vi, ok := claims["verifier_info"].([]any)
	if !ok || len(vi) != 1 {
		t.Fatalf("verifier_info = %v, want one attestation", claims["verifier_info"])
	}
	att := vi[0].(map[string]any)
	if att["format"] != "jwt" || att["data"] != string(spec.WRPRC) {
		t.Errorf("verifier_info[0] = %v", att)
	}
}

// T-08.3 acceptance: request without RegistrationRef is impossible —
// belt (NewSession, tested in Task 2) AND suspenders (a hand-built session
// cannot sneak past RequestObjectJWT either).
func TestRequestObjectImpossibleWithoutRegistration(t *testing.T) {
	env := newTestEnv(t)
	s, _, err := env.engine.NewSession(context.Background(), crossDeviceSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	s.Registration = rpcert.RegistrationRef{}
	if _, err := env.engine.RequestObjectJWT(context.Background(), s); !errors.Is(err, oid4vp.ErrNoRegistration) {
		t.Fatalf("err = %v, want ErrNoRegistration", err)
	}
}

// T-08.3 acceptance: SAN/client_id mismatch is a BUILD error (engine
// construction), not a runtime surprise.
func TestSANMismatchIsBuildError(t *testing.T) {
	cfg, _, _, _ := baseConfig(t)
	cfg.ClientDNSName = "not-in-san.example.org"
	if _, err := oid4vp.New(context.Background(), cfg); !errors.Is(err, oid4vp.ErrSANMismatch) {
		t.Fatalf("err = %v, want ErrSANMismatch", err)
	}
}

// Per-session ephemeral keys: two sessions advertise different JWKs
// (WP-08 decision — no static decryption keys).
func TestRequestObjectEphemeralJWKPerSession(t *testing.T) {
	env := newTestEnv(t)
	_, claims1, _ := newServedSession(t, env, crossDeviceSpec(t))
	_, claims2, _ := newServedSession(t, env, crossDeviceSpec(t))
	jwkX := func(claims map[string]any) string {
		return claims["client_metadata"].(map[string]any)["jwks"].(map[string]any)["keys"].([]any)[0].(map[string]any)["x"].(string)
	}
	if jwkX(claims1) == jwkX(claims2) {
		t.Fatal("sessions must not share the response-encryption JWK")
	}
}

// DCAPI sessions are served by the DCAPI builder (T-08.9), never by the
// request_uri path.
func TestRequestObjectRejectsDCAPIFlow(t *testing.T) {
	env := newTestEnv(t)
	spec := crossDeviceSpec(t)
	spec.Flow = oid4vp.DCAPI
	spec.ResponseURI = ""
	spec.ExpectedOrigins = []string{"https://client.example.com"}
	s, _, err := env.engine.NewSession(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.engine.RequestObjectJWT(context.Background(), s); !errors.Is(err, oid4vp.ErrFlowMismatch) {
		t.Fatalf("err = %v, want ErrFlowMismatch", err)
	}
}
