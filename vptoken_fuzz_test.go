package oid4vp

import (
	"encoding/json"
	"testing"
	"time"

	dcql "github.com/gmb-eudi/go-dcql"
)

// FuzzVPToken fuzzes the decrypted-payload parsers (§8.1 vp_token JSON) —
// the layer below the JWE (hard rule 5).
func FuzzVPToken(f *testing.F) {
	f.Add([]byte(`{"vp_token":{"pid":["abc"]},"state":"s"}`))
	f.Add([]byte(`{"vp_token":{"pid":"not-array"},"state":"s"}`))
	f.Add([]byte(`{"vp_token":{}}`))
	f.Add([]byte(`{"vp_token":{"mdl":["!!!not-b64!!!"]},"state":"s"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	q, err := dcql.Parse([]byte(`{"credentials":[
		{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}},
		{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}`))
	if err != nil {
		f.Fatal(err)
	}
	s := &Session{
		ID: "fuzz", Flow: CrossDevice, ClientID: "x509_san_dns:v.example",
		Nonce: "n", State: "s", ResponseURI: "https://v.example/r",
		Query: *q, ExpiresAt: time.Now().Add(time.Hour), Consumed: true,
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		p, err := parseResponsePayload(data)
		if err != nil {
			return
		}
		_, _ = presentationsFromVPToken(s, p.VPToken, "mgn", "thumb")
		// exercise the raw map path too
		var m map[string]json.RawMessage
		if json.Unmarshal(data, &m) == nil {
			_, _ = presentationsFromVPToken(s, m, "", "")
		}
	})
}
