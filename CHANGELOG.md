# Changelog

## Phase 3C - ReportForge / Submission Packager

- Added local submission drafts sourced from Evidence Locker, correlator leads,
  workflow outputs, and finding files.
- Added redacted platform-profile exports, quality linting, checklists,
  attachment manifests, previews, and local package creation.
- Preserved the manual-submission boundary: no network calls, credentials,
  platform APIs, request replay, or exploit automation.

## Phase 3B — Workflow Orchestrator

- Added a marked, local-only project workspace and `bbs workflow` command group.
- Added recursive input detection, hashing, classification, and module routing.
- Added safe passive pipeline execution, deterministic outputs, manifests, status,
  summaries, project reports, skip/failure tracking, and guarded cleanup.
- Integrated synthetic demo projects with the workflow runner.

## Phase 3A — Release hardening
- Added environment doctor and synthetic demo project commands.
- Added end-to-end fixture validation, release/smoke scripts, command reference,
  example workflow, release checklist, and stronger CI checks.
- Hardened install troubleshooting, roadmap, and release documentation.

## Phase 2I — Project Correlator
- Correlated saved module artifacts into conservative risk signals and triage leads.

## Phase 2H — GraphQL Risk Mapper
- Added passive GraphQL endpoint, operation, variable, schema-artifact, and review-lead mapping.

## Phase 2G — Auth Surface Analyzer
- Added local JWT, cookie, header, CORS, cache, and auth-endpoint observations.

## Phase 2F — ParamForge
- Added passive names-only vocabulary extraction and safe exports.

## Phase 2E — Evidence Locker
- Added evidence workspaces, redacted exports, and report quality checks.

## Phase 2D — IDOR/BOLA Matrix
- Added manual expected-versus-observed authorization modeling.

## Phase 2C — Frontend Exposure Analyzer
- Added local frontend, source-map, storage, DOM, and postMessage review leads.

## Phase 2B — Passive Endpoint Mapper
- Added normalized endpoint inventories and manual review checklists.

## Phase 2A / Phase 1.5 — HAR Analyzer
- Added passive HAR summaries, redacted observations, and reports.

## Phase 1 — Foundation
- Added the Typer CLI, workspaces, ScopeGuard, shared models, redaction, reporting,
  synthetic fixtures, tests, and safety documentation.
