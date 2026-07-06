package oid4vp_test

import (
	"context"
	"testing"

	oid4vp "github.com/gmb-eudi/go-oid4vp"
)

// FuzzProcessResponse fuzzes the full untrusted path: form parse → JWE →
// payload JSON → vp_token (hard rule 5). Must never panic; every failure
// is a typed error.
func FuzzProcessResponse(f *testing.F) {
	env := newTestEnvF(f)
	ctx := context.Background()
	s, _, err := env.engine.NewSession(ctx, oid4vp.RequestSpec{
		Query:        testQueryF(f),
		Flow:         oid4vp.CrossDevice,
		ResponseURI:  "https://verifier.example.com/response",
		Registration: testRegistration(),
	})
	if err != nil {
		f.Fatal(err)
	}
	s.Consumed = true // simulate ConsumeOnce
	template := *s

	f.Add([]byte("response=abc.def.ghi.jkl.mno"))
	f.Add([]byte("response="))
	f.Add([]byte("error=access_denied&error_description=nope"))
	f.Add([]byte("%zz"))
	f.Add([]byte(""))
	f.Add([]byte("response=" + "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSJ9....")) // header-only JWE shape
	f.Fuzz(func(_ *testing.T, body []byte) {
		clone := template // fresh copy: ProcessResponse mutates ResponseCode
		_, _, _ = env.engine.ProcessResponse(ctx, &clone, oid4vp.RawResponse{Body: body})
	})
}
