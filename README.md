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

## Phase 1 features

- Typer-based `bbs` CLI
- Local workspace creation and configuration
- ScopeGuard exact-domain, wildcard-domain, out-of-scope, and path checks
- Default redaction of tokens, JWTs, keys, cookies, session IDs, email
  addresses, and phone numbers
- Validated Pydantic finding, evidence, scope, and decision models
- Redacted Markdown finding export with quality warnings
- Passive HAR metadata summaries in terminal-table or JSON form
- Fake fixtures and unit tests

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
5. Redact evidence with `bbs redact`.
6. Record a validated finding based on `examples/finding.yml`.
7. Generate a submission draft with `bbs report export`.

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

See [docs/safety.md](docs/safety.md) and [SECURITY.md](SECURITY.md).

## Planned modules

These are roadmap items only and are **not implemented** in Phase 1:

- HAR Analyzer
- Live JS Secret Scanner
- Source Map Hunter
- SPA Endpoint Mapper
- Passive API Mapper
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
