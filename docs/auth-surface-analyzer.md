# Auth Surface Analyzer

Auth Surface Analyzer is a passive, local-only organizer for authorized auth and
session review. It accepts HAR, raw HTTP request/response, JWT text, JSON, YAML,
Endpoint Mapper and Frontend Exposure inventories, Evidence Locker workspaces,
and folders containing supported files.

## Workflow and commands

Use `bbs auth-surface scan-har <file>`, `scan-file <file>`, `scan-folder <dir>`,
or `scan-inventory <file>`. Focus views are available through `jwt`, `cookies`,
`headers`, `cors`, and `cache`. Generate redacted output with `report --format
markdown|json` and manual questions with `checklist --format markdown|json`.

## Review guidance

- **JWT:** inspect decoded header/claim metadata, lifetime, issuer, audience,
  broad scopes, privileged roles, tenant/org keys, PII claim presence, and token
  location. Decoding does not authenticate a token or prove a weakness.
- **Cookies:** validate the purpose and context of Secure, HttpOnly, SameSite,
  Domain, Path, expiry, and `__Host-`/`__Secure-` prefix observations.
- **Headers:** assess CSP and other hardening headers against application needs;
  a missing header is not automatically a vulnerability.
- **CORS:** validate browser, origin, credential, `Vary`, method, and exposed
  header context manually. Observed headers alone do not establish impact.
- **Cache:** determine whether authenticated or PII-bearing responses can
  actually enter browser or shared caches and cross a security boundary.
- **Auth endpoints:** use generated questions for login, logout, reset, MFA/OTP,
  OAuth/OIDC/SAML callbacks, refresh, invite, magic-link, CSRF, and tenant flows.

## Safety, redaction, and limitations

The module makes no live requests and performs no replay, fuzzing, payload
creation, exploitation, signature validation, key brute forcing, algorithm
confusion testing, `none` bypass testing, JWKS access, cloud calls, secret
validation, or telemetry. It does not generate CORS exploit pages because
exploitability depends on browser and credential context and must be validated
carefully within authorization and program rules.

Exports contain token fingerprints and claim summaries, never raw JWTs or cookie
values. Authorization material, secrets, session IDs, and PII are redacted.
Heuristics can miss dynamically generated behavior and produce false positives.
Manually confirm semantics, impact, scope, cache topology, browser behavior,
server-side authorization, token rotation, revocation, and flow binding before
reporting any issue.
