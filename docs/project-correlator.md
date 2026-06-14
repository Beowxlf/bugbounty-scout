# Project Correlator

## Purpose

Project Correlator passively combines local BugBountyScout outputs into a
project-level risk map. It answers where multiple weak signals overlap and what
manual evidence is still needed. It does not establish that a vulnerability
exists.

## Supported artifacts

It accepts JSON, YAML, and Markdown reports representing HAR analysis, endpoint
inventories, frontend inventories, ParamForge inventories, auth-surface
inventories, GraphQL inventories, IDOR/BOLA matrices, Evidence Locker
workspaces, and findings. Unknown or malformed artifacts are retained with a
parse status and error rather than crashing the project build.

## Workflow

```bash
bbs correlate scan ./saved-outputs --output correlation-project.yml
bbs correlate add-artifact correlation-project.yml extra.json --type endpoint_inventory
bbs correlate build correlation-project.yml
bbs correlate report correlation-project.yml --format markdown
bbs correlate export-leads correlation-project.yml --format json
bbs correlate checklist correlation-project.yml --format markdown
```

`scan` recursively discovers supported local files and hashes each with SHA-256.
`add-artifact` links a file without modifying it. `build` reparses artifacts and
rebuilds assets, signals, and leads.

## Correlation and signals

HTTP assets are correlated by host, normalized path, and method. Numeric and
likely resource identifiers are normalized using Endpoint Mapper conventions.
GraphQL endpoint IDs connect operations to `/graphql`; authorization endpoint
templates and Evidence Locker affected assets connect manual observations to
the same normalized asset. Static assets are not broadly merged.

Signals preserve their source artifact and module. Endpoint risk tags,
frontend/source-map observations, JWT/cookie/CORS/cache metadata, GraphQL
operation metadata, authorization mismatches, HAR findings, and evidence quality
state are translated into conservative `RiskSignal` records. Raw evidence is not
copied; only redacted evidence is exported.

## Leads, scoring, and reportability

The score is capped at 100 and combines the strongest source severity, up to 20
points for corroborating signals, authorization mismatch, state-changing or
sensitive context, cross-organization/tenant context, and complete evidence.
Evidence gaps reduce the score. Priorities are: informational 0–14, low 15–39,
medium 40–69, high 70–89, and critical 90–100. Critical is possible only when
strong evidence and several high-impact indicators overlap.

Reportability is independent of priority. `report_ready` requires a complete,
ready Evidence Locker workspace with impact, affected asset, reproduction
notes, proof, and severity rationale and no quality warnings.
`needs_more_evidence` and `needs_manual_validation` are the normal outcomes for
passive leads. Isolated missing headers, public identifiers without impact, and
source maps without sensitive content are treated as likely noise.

## Manual checklist

The checklist groups high-priority leads, IDOR/BOLA, GraphQL authorization,
frontend exposure, auth/session, CORS/cache/header review, evidence gaps, and
likely noise. Steps are intentionally high level: confirm scope, compare
expected and observed behavior manually, minimize data access, and preserve
redacted evidence. It includes no payloads or exploit instructions.

## Safety and limitations

The correlator is local-only and manual-first. It performs no live requests,
replay, active scanning, fuzzing, payload generation, GraphQL introspection,
credential testing, cloud calls, telemetry, or exploit automation. Correlation
can produce false positives when paths are generic or source formats are
incomplete. Review every lead against program scope and demonstrate concrete
security impact before reporting it.
