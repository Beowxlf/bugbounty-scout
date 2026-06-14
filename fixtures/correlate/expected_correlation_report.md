# Project Correlation Report

## Summary

Artifacts: 9; assets: 7; signals: 16; leads: 7.

## Artifacts analyzed

- `auth_surface_inventory` — `fixtures/correlate/fake_project_folder/fake_auth_surface_inventory.json` — parsed
- `authz_matrix` — `fixtures/correlate/fake_project_folder/fake_authz_matrix.yml` — parsed
- `endpoint_inventory` — `fixtures/correlate/fake_project_folder/fake_endpoint_inventory.json` — parsed
- `evidence_workspace` — `fixtures/correlate/fake_project_folder/fake_evidence_workspace.yml` — parsed
- `finding` — `fixtures/correlate/fake_project_folder/fake_finding.yml` — parsed
- `frontend_inventory` — `fixtures/correlate/fake_project_folder/fake_frontend_inventory.json` — parsed
- `graphql_inventory` — `fixtures/correlate/fake_project_folder/fake_graphql_inventory.json` — parsed
- `har_report` — `fixtures/correlate/fake_project_folder/fake_har_report.json` — parsed
- `paramforge_inventory` — `fixtures/correlate/fake_project_folder/fake_paramforge_inventory.json` — parsed

## Correlated assets

- `PATCH app.example.test/api/users/{id}` — score 92
- `POST app.example.test/graphql` — score 38
- `UNKNOWN app.example.test/api/users/{id}` — score 33
- `UNKNOWN app.example.test/admin/users` — score 8
- `UNKNOWN app.example.test/auth/session` — score 8
- `UNKNOWN public.example.test/` — score 2
- `UNKNOWN public.example.test/users/{id}` — score 2

## Risk signals

- **medium** — Auth surface: admin-role-claim
- **medium** — Auth surface: jwt-long-lifetime
- **low** — Auth surface: missing-httponly
- **info** — Auth surface: missing-header
- **medium** — Auth surface: risky-cache
- **high** — Authorization matrix observation
- **medium** — Endpoint tagged idor-candidate
- **medium** — Endpoint tagged state-changing
- **medium** — Endpoint tagged sensitive-data
- **info** — Cross-user profile update
- **info** — Public identifier observation
- **low** — Admin source map route
- **medium** — UpdateInvoice
- **medium** — UpdateInvoice
- **medium** — UpdateInvoice
- **medium** — Sensitive response cache review

## Top triage leads

- **critical** — Manual review: PATCH app.example.test/api/users/{id} (report_ready)
- **low** — Manual review: POST app.example.test/graphql (needs_manual_validation)
- **low** — Manual review: UNKNOWN app.example.test/api/users/{id} (needs_manual_validation)
- **informational** — Manual review: UNKNOWN public.example.test/ (likely_noise)
- **informational** — Manual review: UNKNOWN public.example.test/users/{id} (likely_noise)
- **informational** — Manual review: UNKNOWN app.example.test/auth/session (needs_more_evidence)
- **informational** — Manual review: UNKNOWN app.example.test/admin/users (likely_noise)

## Report-ready candidates

- **critical** — Manual review: PATCH app.example.test/api/users/{id} (report_ready)

## Leads needing more evidence

- **informational** — Manual review: UNKNOWN app.example.test/auth/session (needs_more_evidence)

## Likely noise / low-value items

- **informational** — Manual review: UNKNOWN public.example.test/ (likely_noise)
- **informational** — Manual review: UNKNOWN public.example.test/users/{id} (likely_noise)
- **informational** — Manual review: UNKNOWN app.example.test/admin/users (likely_noise)

## Manual validation checklist

## Highest-priority leads

- [ ] critical: Manual review: PATCH app.example.test/api/users/{id}
- [ ] low: Manual review: POST app.example.test/graphql
- [ ] low: Manual review: UNKNOWN app.example.test/api/users/{id}
- [ ] informational: Manual review: UNKNOWN public.example.test/
- [ ] informational: Manual review: UNKNOWN public.example.test/users/{id}
- [ ] informational: Manual review: UNKNOWN app.example.test/auth/session
- [ ] informational: Manual review: UNKNOWN app.example.test/admin/users

## IDOR/BOLA validation

- [ ] Manual review: PATCH app.example.test/api/users/{id}

## GraphQL authorization validation

- [ ] Manual review: POST app.example.test/graphql

## Frontend exposure validation

- _None._

## Auth/session validation

- [ ] Manual review: UNKNOWN app.example.test/auth/session

## CORS/cache/header validation

- _None._

## Evidence needed before reporting

- [ ] Manual review: UNKNOWN app.example.test/auth/session

## Likely noise to deprioritize

- [ ] Manual review: UNKNOWN public.example.test/
- [ ] Manual review: UNKNOWN public.example.test/users/{id}
- [ ] Manual review: UNKNOWN app.example.test/admin/users

## Suggested next manual actions

- [ ] Review only authorized assets.
- [ ] Collect minimal redacted evidence.
- [ ] Do not report weak signals without demonstrated security impact.

## Evidence gaps

Confirm affected assets, expected versus actual behavior, impact, redacted proof, reproduction notes, and severity rationale before submission.

## Redaction notice

Free-text evidence is redacted by default. Raw secrets, cookies, tokens, JWTs, authentication headers, and PII are not exported.

## Limitations

This is passive local correlation, not proof of vulnerability. It sends no requests, replays no traffic, generates no payloads, and performs no exploitation.

