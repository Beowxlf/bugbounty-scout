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

## Phase 1.5, Phase 2A, and Phase 2B features

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
```

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

See [docs/safety.md](docs/safety.md),
[docs/har-analyzer.md](docs/har-analyzer.md),
[docs/endpoint-mapper.md](docs/endpoint-mapper.md), and [SECURITY.md](SECURITY.md).

## Planned modules

HAR Analyzer and Passive Endpoint Mapper are implemented through Phase 2B.
Possible next passive-first
modules, subject to the same authorization and redaction boundaries, include:

- Live JS Secret Scanner
- Source Map Hunter
- ParamForge
- JWT Risk Inspector
- Header/Cookie Auditor
- CORS Auditor
- GraphQL Risk Mapper
- Client Storage Auditor
- Debug Leak Analyzer
- Source Sink Mapper
- PostMessage Analyzer
- IDOR/BOLA Matrix
- Evidence Locker
- ReportForge

No active scanning, Burp integration, desktop UI, MCP integration, secret
validation, or cloud service is included.

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
