# Frontend Exposure Analyzer

The Phase 2C Frontend Exposure Analyzer passively reads local JavaScript, HTML,
JSON, text, source-map files, and folders. It identifies redacted secret/config
observations, runtime configuration, source-map content, routes, API client
hints, browser storage references, and DOM or `postMessage` manual-review leads.
It never fetches a URL or validates a credential.

## Supported inputs and workflow

Supported suffixes are `.js`, `.html`, `.htm`, `.json`, `.txt`, and `.map`.
Export or save an authorized application's frontend resources, then run:

```bash
bbs frontend scan-file app.js
bbs frontend scan-folder frontend/
bbs frontend secrets app.js
bbs frontend sourcemaps app.js
bbs frontend storage app.js
bbs frontend dom-leads app.js
bbs frontend postmessage app.js
bbs frontend report frontend/ --format markdown
bbs frontend report frontend/ --format json
```

## Interpreting results

Secret/config classifications distinguish public identifiers from potentially
sensitive values, likely secrets, recognizable secret formats, and values that
need manual validation. Public Firebase, Stripe, OAuth, Sentry, and analytics
identifiers are not automatically vulnerabilities. Values are not checked
against provider APIs and evidence is redacted by default.

Source-map observations are informational unless the local map reveals more
sensitive material. Embedded source paths, comments, and routes can guide an
authorized manual review, but exposure alone is not rated critical.

Storage findings identify `localStorage`, `sessionStorage`, IndexedDB, cookies,
and Cache API usage. DOM leads use only source/sink proximity, and message leads
look for origin checks, wildcard target origins, and obvious data validation.
These are review prompts, not confirmed XSS or cross-origin vulnerabilities.

## Boundaries, limitations, and manual validation

The analyzer performs no crawling, active scanning, fuzzing, payload generation,
authentication bypass, WAF evasion, cloud calls, telemetry, or secret validation.
Regex and proximity checks can miss computed behavior or produce false positives.
Review code context, program rules, intended identifier visibility, server-side
authorization, and actual data flow manually. Use only owned, lab, or explicitly
authorized assets, and review every report before sharing it.
