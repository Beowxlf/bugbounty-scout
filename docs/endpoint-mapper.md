# Passive Endpoint Mapper

Endpoint Mapper reads local HAR, JavaScript, HTML, JSON, and text files and
builds a redacted attack-surface inventory. It performs no network requests.
Conservative patterns recognize absolute and relative URLs, `fetch`, Axios,
WebSocket, EventSource, and simple GraphQL references.

## Workflow and commands

```bash
bbs endpoints from-har capture.har
bbs endpoints from-file app.js
bbs endpoints from-folder frontend/
bbs endpoints report capture.har --format markdown
bbs endpoints report frontend/ --format json
bbs endpoints checklist capture.har --format markdown
```

Reports summarize hosts, normalized endpoints, parameter names, auth
indicators, object-ID candidates, and conservative risk tags. Tags such as
`admin`, `billing`, `file-upload`, `state-changing`, and `idor-candidate` are
manual-review leads, not findings.

Object names such as `userId`, `tenantId`, and `invoiceId`, plus normalized
`{id}`, `{uuid}`, and `{slug}` segments, can guide authorized manual IDOR/BOLA
checks with separate test accounts. Checklists ask about ownership, role, and
tenant enforcement and never generate exploit payloads.

## Redaction, boundaries, and limitations

Reports retain parameter and header names, not observed secret values.
Endpoint Mapper does not fetch URLs, replay requests, scan hosts, validate
credentials, call cloud providers, fuzz, bypass controls, or exploit targets.

Phase 2B uses regex/string parsing rather than an AST. Dynamic routes,
minified code, aliases, and encoded content may be missed; generic strings may
be false positives; and methods can be `UNKNOWN`. Validate every lead manually
within the applicable authorization and program rules.
