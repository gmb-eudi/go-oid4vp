# go-oid4vp

OpenID for Verifiable Presentations 1.0 — the verifier (Relying Party)
protocol engine in Go: signed Request Objects (JAR/RFC 9101) with WRPAC
x5c, request_uri lifecycle, encrypted direct_post.jwt response processing
with per-session ephemeral keys, Digital Credentials API (DCAPI) request
and response shapes, same-device response_code return, transaction_data,
and OID4VP error-response mapping.

- Storage-free: bring your own SessionStore (in-memory reference included;
  contract test suite exported in package storetest).
- HTTP-free: services own transport; this library builds and consumes
  protocol payloads.
- All cryptography via github.com/gmb-eudi/go-eudi-crypto (ECCG-pinned
  policy; algorithms are configured and policy-validated, never chosen by
  tokens).
- client_id prefix v1: x509_san_dns only; verifier_attestation is an
  extension point (constructor rejects it until implemented).
- Response encryption keys are per-session ephemeral; static operator
  decryption keys are not supported.

Implemented specs: OpenID4VP 1.0 (final) §5/§6/§8/§13.3/§14.2, Annex A, Annex B;
RFC 9101; HAIP 1.0 (final); ARF 2.9 RPRC_19a; CIR 2024/2982 Art. 3.

Status: pre-v1. API frozen no earlier than OIDF conformance pass.
