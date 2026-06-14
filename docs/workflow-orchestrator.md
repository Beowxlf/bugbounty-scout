# Workflow Orchestrator

The Phase 3B Workflow Orchestrator turns BugBountyScout's existing passive
modules into one coherent, local project runner. It discovers files already on
disk, records their hashes and classifications, runs compatible analyzers in a
safe order, and writes an auditable `workflow.yml` manifest.

It is not an active scanner. It does not fetch URLs, replay requests, generate
payloads, fuzz inputs, validate secrets, introspect live GraphQL services, or
automatically test a target.

## Workspace layout

`bbs workflow init NAME` creates:

```text
NAME/
  inputs/{har,frontend,graphql,requests,responses,inventories,evidence,authz,other}/
  outputs/{har,endpoints,frontend,auth_surface,graphql,paramforge,authz,evidence,correlate}/
  reports/
  logs/
  evidence/
  scope.yml
  workflow.yml
  README.md
  .bugbounty-scout-workflow
```

The hidden marker prevents cleanup from deleting arbitrary directories.

## Example workflow

```bash
bbs workflow init demo-target
# Copy authorized local artifacts into demo-target/inputs/
bbs workflow detect demo-target
bbs workflow run demo-target
bbs workflow status demo-target
bbs workflow summary demo-target --format markdown
bbs workflow report demo-target --format markdown
bbs workflow manifest demo-target --format yaml
```

## Input detection

Detection recursively hashes files with SHA-256 and classifies HAR, JavaScript,
HTML, source maps, GraphQL documents, raw requests/responses, known module
inventories, evidence workspaces, authz matrices, and correlation projects.
Unknown files remain in the manifest as `unknown`; they do not crash a run.

## Pipeline execution

The runner calls existing local APIs in this order:

1. HAR Analyzer
2. Endpoint Mapper
3. Frontend Exposure Analyzer
4. Auth Surface Analyzer
5. GraphQL Risk Mapper
6. ParamForge
7. Project Correlator
8. Summary/report generation

IDOR/BOLA matrices and Evidence Locker workspaces remain user-driven. Existing
ones can be correlated, but the runner does not invent actors, access
expectations, proof, or impact.

Each step is recorded as completed, skipped, or failed. Missing compatible
inputs produce a clear skip reason. An isolated parser failure is recorded and
later safe steps continue.

## Reports and cleanup

Deterministic module artifacts are stored under `outputs/`; concise project
summaries are stored under `reports/`. Project reports reference large module
artifacts instead of inlining them.

`bbs workflow clean NAME --outputs-only` resets generated outputs while
preserving inputs, scope, and the safely reset manifest. Full cleanup only works
for a directory carrying the workflow marker.

## Limitations and manual validation

Passive artifacts can be stale, incomplete, malformed, or lack authorization
context. Correlator leads are review queues, not confirmed vulnerabilities.
Before reporting, manually confirm scope, reproduce only within program rules,
collect minimal redacted evidence, assess impact conservatively, and review all
exports for sensitive information.
