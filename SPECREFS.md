# Pinned specification versions

| Spec | Version pinned | Sections used |
|---|---|---|
| OpenID4VP | 1.0 (final) | §5 (authorization request, client_id prefixes, verifier_info, request_uri_method, transaction_data), §6 (DCQL), §8.1 (vp_token), §8.2 (direct_post.jwt, response_code), §8.3 (redirect_uri return), §12.1 (session fixation), Annex A (DCAPI), Annex B.2 (mso_mdoc handover, RFC 7638 `jwk_thumbprint` of the RP's own ephemeral response-encryption key — corrected 2026-07-06, was `mdocGeneratedNonce`; plus JWE apu/apv), Annex B.3 (SD-JWT VC) |
| OpenID4VC HAIP | 1.0 (final) | §5 request/response requirements; response encryption mandatory; ES256/P-256 baseline |
| RFC 9101 (JAR) | RFC | signed Request Object, typ oauth-authz-req+jwt, aud/exp/iat/nbf |
| ISO/IEC TS 18013-7 | 2024 | Annex B via OID4VP Annex B.2 (SessionTranscript, JWE apu/apv) |
| ARF | 2.9 | RPRC_19a / EW-DM-44-019 (registration data in every request) |
| CIR 2024/2982 | OJ L | Art. 3 (WRPAC presented in request) |
| ETSI TS 119 472-2 | NOT YET PUBLISHED | RPRC_19a/RPRC_20a extension member — provisional member name `verifier_registration`, revisit on publication (see WP-08 Decisions) |
