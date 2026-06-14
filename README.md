# BugBountyScout

BugBountyScout is a local-first, modular CLI workbench for **authorized** web bug
bounty testing. It helps researchers stay in scope, review passive traffic,
redact sensitive material, preserve evidence, and produce report-ready findings.

> **Authorized use only.** Use BugBountyScout only on assets you own, lab
> environments, or targets for which you have explicit permission. You are
> responsible for following program scope, rate limits, and applicable law.

## What it is—and is not

BugBountyScout supports a disciplined workflow:

**Scope → Capture → Analyze → Map → Triage → Evidence → Report**

It is a passive-first workbench, not an exploit framework, mass scanner,
authentication bypass tool, WAF evasion tool, credential validator, or data
exfiltration utility. Phase 1 makes no network requests.

## Completed capabilities (Phase 1 through Phase 3A)

- Typer-based `bbs` CLI
- Local workspace creation and configuration
- ScopeGuard exact-domain, wildcard-domain, out-of-scope, and path checks
- Default redaction of tokens, JWTs, keys, cookies, session IDs, email
  addresses, and phone numbers
- Validated Pydantic finding, evidence, scope, and decision models
- Redacted Markdown finding export with quality warnings
- Friendly errors for missing, empty, malformed JSON/YAML, and invalid HAR inputs
- Passive HAR summaries and normalized endpoint inventory
- Redacted sensitive-material location detection across URLs, headers, cookies,
  query strings, and request/response bodies
- Cookie attribute, security-header, third-party leakage, and cache review
- Terminal tables plus redacted JSON and Markdown HAR reports
- Fake fixtures and unit tests
- Passive endpoint mapping from HAR, JavaScript, HTML, JSON, text, and folders
- Endpoint normalization, parameter names, auth indicators, object-ID candidates,
  and conservative risk tags
- Redacted Markdown/JSON inventories and manual testing question checklists
- Passive frontend exposure analysis for JavaScript, HTML, JSON, text, source maps, and folders
- Redacted secret/config classification, runtime config and sensitive-comment detection
- Source-map parsing with embedded source paths, routes, and API client hints
- Client storage, DOM source/sink proximity, and `postMessage` manual-review leads
- Manual IDOR/BOLA matrices for actors, objects, endpoint templates, expected
  and observed access, evidence references, conservative findings, and checklists
- Evidence Locker workspaces, redacted evidence exports, and report quality gates
- ParamForge passive vocabulary extraction from HAR, frontend files, source maps,
  endpoint/frontend inventories, authorization matrices, and evidence workspaces
- Names-only ParamForge reports and TXT/CSV/JSON wordlist exports with frequency
  scoring, risk scoring, thematic tags, filtering, and safe normalization
- GraphQL Risk Mapper for passive endpoint, operation, variable, fragment, local schema/introspection artifact, batching/error-detail, and authorization-lead review
- Redacted GraphQL Markdown/JSON reports and observation-driven manual testing checklists
- Project Correlator for combining saved artifacts into conservative triage leads
- `bbs doctor` for network-free local environment readiness checks
- `bbs demo` for generating a self-contained synthetic passive-workflow project
- End-to-end fixture tests, release checklists, and installed/PYTHONPATH smoke scripts

### GraphQL Risk Mapper examples

```bash
bbs graphql scan-har fixtures/graphql/fake_graphql.har
bbs graphql scan-file fixtures/graphql/fake_query.graphql
bbs graphql scan-folder fixtures/graphql/fake_folder
bbs graphql scan-inventory endpoint-inventory.json
bbs graphql endpoints capture.har
bbs graphql operations capture.har
bbs graphql variables capture.har
bbs graphql schema local-introspection.json
bbs graphql leads capture.har
bbs graphql report capture.har --format markdown
bbs graphql checklist capture.har --format json
```

GraphQL Risk Mapper reads only local captures and artifacts. It identifies observed endpoints, operations, variables, object-ID candidates, sensitive fields, fragments, mutations, local schema/introspection material, batching indicators, and verbose captured errors. It creates conservative manual-review leads rather than claiming vulnerabilities.

It deliberately does not fetch URLs, send queries, replay requests, run introspection, generate payloads, automate authorization bypass, or test depth, complexity, batching abuse, or denial of service. Reports redact credentials, cookies, JWTs, keys, PII, sessions, and authorization material while preserving operation, field, and variable names useful for authorized manual review. See [the GraphQL Risk Mapper guide](docs/graphql-risk-mapper.md).

### ParamForge examples

```bash
bbs paramforge scan-har fixtures/paramforge/fake_api.har
bbs paramforge scan-file fixtures/paramforge/fake_frontend.js
bbs paramforge scan-folder fixtures/paramforge/fake_folder
bbs paramforge scan-inventory fixtures/paramforge/fake_endpoint_inventory.json
bbs paramforge report vocabulary.json --format markdown
bbs paramforge export vocabulary.json --category params --format txt
bbs paramforge export-all vocabulary.json --output-dir wordlists
bbs paramforge stats vocabulary.json
```

ParamForge builds target-specific names for authorized manual endpoint review,
API documentation, authorization planning, and later manual configuration of
tools such as Burp Intruder or ffuf. ParamForge does not invoke those tools.
Exports exclude captured values and redact obvious secrets, cookies, JWTs,
authorization material, PII, and session identifiers by default.

This phase performs no live fetching, replay, fuzzing, payload generation,
scanning, bypass attempts, cloud calls, telemetry, or secret validation.
Heuristic extraction can produce false positives and does not prove that a
route, parameter, or vulnerability exists. Review every export and remain
within program scope. See [the ParamForge guide](docs/paramforge.md).

Phase 1.5 keeps Hatchling as the small standards-based packaging backend and
declares all runtime and development dependencies in `pyproject.toml`. CI and
the supported classifiers cover Python 3.11, 3.12, and 3.13.

## Installation

BugBountyScout requires Python 3.11 or newer.

```bash
git clone https://github.com/your-org/bugbounty-scout.git
cd bugbounty-scout
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
bbs --help
bbs doctor
```

Hatchling remains the standards-based build backend. The package targets Python
3.11, 3.12, and 3.13, includes the `bugbounty_scout` package from `src`, and
declares Typer, Pydantic, PyYAML, and Rich as runtime dependencies. Pytest and
Ruff are available through the `dev` extra.

### Installation troubleshooting and restricted networks

If editable installation fails, read the complete pip error first. Some managed
package indexes/proxies return `403 Forbidden` while resolving Hatchling. That
is an environment/index access problem and is not a reason by itself to change
the project's build backend.

For an offline or restricted-network test bench, pre-download the build/runtime
dependencies into an approved wheelhouse, then install with your organization's
documented `--no-index --find-links` process. When dependencies are already
available in the environment, run the source-tree fallback:

```bash
PYTHONPATH=src python -m bugbounty_scout.cli --help
PYTHONPATH=src python -m bugbounty_scout.cli doctor
bash scripts/smoke_py_path.sh
```

This fallback validates module execution but **does not** validate editable
installation or the generated `bbs` console script. After installation succeeds,
validate those separately:

```bash
python -m pip show bugbounty-scout
bbs --version
bbs --help
bbs doctor
```

Run the complete clean-environment test bench with
`bash scripts/test_bench_validation.sh` (or the PowerShell equivalent). See
[the release checklist](docs/release-checklist.md) for release gates.

## CLI examples

```bash
bbs --help
bbs init demo-workspace
cd demo-workspace
bbs scope init
# Edit scope.yml before checking targets.
bbs scope check https://api.example.test/v1/users
bbs redact capture.txt
bbs report export finding.yml
bbs har summary capture.har
bbs har summary capture.har --json
bbs har endpoints capture.har
bbs har secrets capture.har
bbs har cookies capture.har
bbs har headers capture.har
bbs har third-parties capture.har
bbs har report capture.har --format markdown
bbs har report capture.har --format json --output reports/capture.json
bbs endpoints from-har capture.har
bbs endpoints from-file app.js
bbs endpoints from-folder frontend/
bbs endpoints report capture.har --format markdown
bbs endpoints checklist capture.har --format markdown
bbs frontend scan-file app.js
bbs frontend scan-folder frontend/
bbs frontend secrets app.js
bbs frontend sourcemaps app.js
bbs frontend storage app.js
bbs frontend dom-leads app.js
bbs frontend postmessage app.js
bbs frontend report frontend/ --format markdown
bbs frontend report frontend/ --format json
bbs graphql scan-har capture.har
bbs graphql report capture.har --format markdown
bbs graphql checklist capture.har --format markdown
bbs authz init demo
bbs authz add-actor demo-authz-matrix.yml --name "User A" --role user
bbs authz add-object demo-authz-matrix.yml --type invoice --name "Invoice A" \
  --owner <generated-actor-id> --identifier invoiceId=inv_123
bbs authz import-endpoints demo-authz-matrix.yml endpoint-inventory.json
bbs authz expect demo-authz-matrix.yml --actor <actor-id> --object <object-id> \
  --endpoint <endpoint-id> --result deny --reason "Different owner"
bbs authz record demo-authz-matrix.yml --actor <actor-id> --object <object-id> \
  --endpoint <endpoint-id> --result allowed --evidence evidence/redacted.txt
bbs authz compare demo-authz-matrix.yml
bbs authz findings demo-authz-matrix.yml
bbs authz checklist demo-authz-matrix.yml --format markdown
bbs authz report demo-authz-matrix.yml --format json
```

Commands read `scope.yml` from the current workspace. Output paths can be
overridden with each command's options. Redacted and report files are written
locally; there is no telemetry or cloud dependency.

## Example workflow

1. Run `bbs init acme-review` and enter the new workspace.
2. Run `bbs scope init`, then copy only the program's documented rules into
   `scope.yml`.
3. Check a target with `bbs scope check <url>` before handling captured data.
4. Export browser traffic as HAR and inspect it with `bbs har summary`.
5. Inventory endpoints and review redacted observations with the other
   `bbs har` commands.
6. Redact evidence with `bbs redact`.
7. Record a validated finding based on `examples/finding.yml`.
8. Generate a submission draft with `bbs report export`.

## HAR redaction example

A captured header such as `Authorization: Bearer fake-value` is reported as a
`bearer_token` observation at `request header`; the value is represented as
`<redacted-bearer-token>`. Email addresses, phone numbers, JWTs, API keys,
session values, CSRF values, OAuth codes, refresh tokens, cookies, and
secret-looking key/value pairs follow the same typed-placeholder policy.

The source HAR remains sensitive and is not modified. Generated reports are
redacted by default, but researchers should still review them before sharing.

## Scope format

```yaml
program_name: Example Security Program
platform: Example Platform
in_scope:
  - example.test
  - "*.api.example.test"
out_of_scope:
  - admin.example.test
  - example.test/private/*
forbidden_tests:
  - denial of service
rate_limits:
  requests_per_second: 1
auth_notes: Use only supplied test accounts.
report_notes: Redact customer data.
```

Out-of-scope rules take precedence. A wildcard such as `*.example.test`
matches subdomains but not the apex `example.test`. Path rules use glob
matching and may be written as a full URL, host/path, or path-only pattern.

## Project structure

```text
src/bugbounty_scout/  Python package and command modules
tests/                Unit tests using fake data only
fixtures/             Synthetic HAR, requests, responses, scope, and findings
examples/             Safe example configuration and finding files
docs/                 Architecture, safety, and usage documentation
rules/                Default YAML detection/redaction rules
reports/              Generated local reports (contents ignored by Git)
.github/workflows/    Continuous integration
```

## Safety model

- Scope checks are local and make no requests.
- Passive analysis is preferred before any future active checks.
- Explicit exclusions override inclusions.
- Redaction is on by default for exports and stored derivatives.
- Full secrets are not intentionally persisted by the tool.
- Secret validation against provider APIs is not performed.
- Fixtures are synthetic and use reserved `.test` domains.
- No telemetry, cloud service, exploit automation, or bypass behavior.

Passive analysis means reading a HAR file that the authorized researcher
already captured and performing local parsing, classification, and redaction.
BugBountyScout does not replay HAR requests, contact captured hosts, validate
tokens, scan unrelated assets, bypass authentication or controls, or claim that
an informational observation is automatically a vulnerability.

Phase 2B also maps endpoints from local frontend files. It stores parameter
names rather than sensitive values, normalizes likely object identifiers, and
highlights leads for authorized manual API, IDOR/BOLA, role, and tenant-boundary
review. Regex extraction can miss dynamic routes or produce false positives;
risk tags are not confirmed vulnerabilities.

Phase 2C reads only supplied local frontend artifacts. It classifies public identifiers conservatively, redacts sensitive values, parses local source maps, and produces manual-review leads rather than vulnerability claims. It does not fetch source maps, validate secrets, generate XSS payloads, crawl sites, or perform active testing.

Phase 2D is a manual authorization testing workbench. It imports only
high-interest Endpoint Mapper records by default and documents expected versus
manually observed access. It never sends or replays requests, creates payloads,
fuzzes identifiers, validates secrets, or bypasses controls. Test only accounts
and synthetic data explicitly permitted by program rules, use the smallest
necessary test cases, and avoid destructive actions.

Matrix files and reports redact sensitive-looking strings by default. Do not put
passwords, cookies, tokens, sessions, raw private responses, or live credentials
in actor metadata or notes. Evidence is represented by a local path or future
Evidence Locker identifier; full Evidence Locker management is not included.

See [docs/safety.md](docs/safety.md),
[docs/har-analyzer.md](docs/har-analyzer.md),
[docs/endpoint-mapper.md](docs/endpoint-mapper.md),
[docs/frontend-exposure-analyzer.md](docs/frontend-exposure-analyzer.md),
[docs/idor-bola-matrix.md](docs/idor-bola-matrix.md),
[docs/graphql-risk-mapper.md](docs/graphql-risk-mapper.md), and
[SECURITY.md](SECURITY.md).

## Roadmap

### Completed

- Phase 1 foundation and shared safety/redaction/reporting architecture.
- Phase 2A–2I passive analyzers, manual authorization/evidence workflows, and
  Project Correlator.
- Phase 3A release hardening, doctor checks, synthetic demo packaging,
  end-to-end validation, command reference, and release test bench.

### In progress

- Documentation polish, compatibility review, and conservative false-positive
  reduction within existing passive modules.

### Planned

- Additional report/workflow ergonomics that preserve local-only,
  passive/manual-first operation.
- Future integrations only after separate design and safety review; none are
  included in Phase 3A.

### Not planned

- Exploit automation or mass scanning.
- WAF bypass or stealth/evasion tooling.
- JWT attacks or credential validation against provider APIs.
- CORS exploit pages.
- GraphQL denial-of-service testing.
- Authentication, anti-bot, rate-limit, or program-restriction bypass.
- Cloud calls, telemetry, credential theft PoCs, or automatic request replay.

## Development and testing

```bash
python -m pytest
ruff check .
ruff format --check .
```

Contributions should preserve the authorized-use, passive-first, local-first,
scope-aware, and redacted-by-default design. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Phase 2E: Evidence Locker and Report Quality Gate

Phase 2E adds local, report-ready evidence workspaces with SHA-256 file hashes,
ordered reproduction steps, expected-versus-actual behavior, actor/object context,
impact and severity rationale, redacted proof snippets, and Markdown/JSON exports.
The quality gate warns about missing proof, vague or speculative wording,
unsupported severity, missing impact/remediation/scope context, and possible
unredacted secrets or PII. Warnings inform manual review and never block export.

```bash
bbs evidence init "User A can access User B invoice"
bbs evidence add-request user-a-can-access-user-b-invoice-evidence.yml request.txt
bbs evidence add-response user-a-can-access-user-b-invoice-evidence.yml response.txt
bbs evidence add-step user-a-can-access-user-b-invoice-evidence.yml \
  --action "Request Invoice B as User A" --expected "Access is denied" \
  --actual "Invoice metadata is returned"
bbs evidence set-impact user-a-can-access-user-b-invoice-evidence.yml \
  --impact "A user can view another user's invoice metadata."
bbs evidence lint user-a-can-access-user-b-invoice-evidence.yml
bbs evidence export user-a-can-access-user-b-invoice-evidence.yml --format markdown
bbs report lint user-a-can-access-user-b-invoice-evidence.yml
bbs report export user-a-can-access-user-b-invoice-evidence.yml --format json
```

Evidence files are referenced locally and hashed; binary files are not embedded.
Text is redacted by default for authorization headers, bearer tokens, JWTs,
cookies, API/session/CSRF/OAuth/refresh secrets, emails, phone numbers, and
private-key-like blocks. Attach existing HAR, endpoint, frontend, or authz
reports with `evidence add-file` and the matching evidence type. This feature
never captures screenshots, sends/replays requests, validates credentials,
scans, fuzzes, generates payloads, or calls cloud services. Pattern linting can
produce false positives and cannot determine scope, exploitability, or severity.
See [docs/evidence-locker.md](docs/evidence-locker.md) and
[docs/report-quality-gate.md](docs/report-quality-gate.md).

## Phase 2G: Auth Surface Analyzer

`bbs auth-surface` passively reviews local HAR, raw HTTP, JWT text, JSON/YAML
inventories, evidence workspaces, and folders for JWT claim/lifetime signals,
session and CSRF cookie attributes, security headers, observed CORS and cache
behavior, and auth-related endpoints. It produces redacted structured reports
and context-specific manual checklists.

```bash
bbs auth-surface scan-har fixtures/auth_surface/fake_auth.har
bbs auth-surface scan-file fixtures/auth_surface/fake_jwt.txt
bbs auth-surface scan-folder fixtures/auth_surface/fake_folder
bbs auth-surface scan-inventory fixtures/auth_surface/fake_endpoint_inventory.json
bbs auth-surface jwt fixtures/auth_surface/fake_jwt.txt
bbs auth-surface cookies fixtures/auth_surface/fake_auth.har
bbs auth-surface headers fixtures/auth_surface/fake_headers_response.txt
bbs auth-surface cors fixtures/auth_surface/fake_cors.har
bbs auth-surface cache fixtures/auth_surface/fake_cache.har
bbs auth-surface report fixtures/auth_surface/fake_auth.har --format markdown
bbs auth-surface checklist fixtures/auth_surface/fake_auth.har --format json
```

JWT decoding is local and does not verify signatures. The analyzer never brute
forces keys, tests algorithm confusion or signature bypasses, contacts JWKS or
provider APIs, replays traffic, fetches URLs, fuzzes inputs, or generates exploit
payloads. Cookie, header, CORS, and cache findings are conservative review leads,
not vulnerability claims. Tokens, cookie values, authorization headers, API
keys, PII, and session identifiers are redacted by default. See
[the Auth Surface Analyzer guide](docs/auth-surface-analyzer.md).

## Phase 2I: Project Correlator

The passive, local-only Project Correlator combines saved outputs from the HAR
Analyzer, Endpoint Mapper, Frontend Exposure Analyzer, ParamForge, Auth Surface
Analyzer, GraphQL Risk Mapper, IDOR/BOLA Matrix, Evidence Locker, and legacy
findings. It normalizes endpoint paths, extracts conservative risk signals, and
produces project-level assets, triage leads, reportability assessments, and a
manual validation checklist.

```bash
bbs correlate scan fixtures/correlate/fake_project_folder
bbs correlate build correlation-project.yml
bbs correlate assets correlation-project.yml
bbs correlate signals correlation-project.yml
bbs correlate leads correlation-project.yml
bbs correlate report correlation-project.yml --format markdown
bbs correlate export-leads correlation-project.yml --format json
bbs correlate checklist correlation-project.yml --format markdown
```

Priority is a transparent 0–100 aggregation of source severity, supporting
signals, evidence, sensitive/state-changing context, and authorization-boundary
indicators. Reportability is separate: a high-priority lead can still require
manual validation or more evidence. Treat missing headers, public identifiers,
and source maps without demonstrated sensitive content as weak signals; do not
over-report them.

All processing is local. Evidence text is redacted by default, and linked
Evidence Locker hashes and quality state are preferred over raw evidence. The
correlator sends no requests, performs no replay, scanning, fuzzing,
introspection, payload generation, secret validation, or exploitation. Its
output is a prioritization aid rather than proof of a vulnerability. See
[Project Correlator](docs/project-correlator.md) for the workflow, scoring model,
and limitations.
