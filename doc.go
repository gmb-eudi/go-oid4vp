// Package oid4vp implements the verifier (Relying Party) side of OpenID
// for Verifiable Presentations 1.0: signed Request Objects (RFC 9101 JAR)
// carrying the operator WRPAC, request_uri lifecycle, encrypted
// direct_post.jwt response processing with per-session ephemeral keys,
// Digital Credentials API shapes (Annex A), same-device response_code
// return ([OID4VP §8.2/§8.3]), and OID4VP error responses.
//
// The package is storage-free (SessionStore interface; in-memory reference
// implementation; contract suite in storetest) and HTTP-free (services own
// transport). All cryptography is delegated to
// github.com/gmb-eudi/go-eudi-crypto; algorithms come from configuration
// validated against the ECCG policy, never from tokens.
//
// Error mapping guidance for services (the err:domain:reason taxonomy) is on
// each sentinel in errors.go; wallet-boundary serialization is
// (*Engine).ErrorResponse — OID4VP error shapes, not problem+json.
package oid4vp
