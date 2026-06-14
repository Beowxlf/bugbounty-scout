# Project summary: bbs-fixture-workflow

> Authorized local-only passive analysis. No live requests or replay.

## Summary
- Inputs: 11
- Completed steps: 7
- Skipped steps: 0
- Failed steps: 0
- Outputs: 29
- High-priority leads: 0
- Report-ready candidates: 0
- Needs more evidence: 3

## Inputs
- `inputs/evidence/evidence-workspace.yml` — evidence_workspace (Project Correlator, Report Quality Gate)
- `inputs/frontend/fake.html` — html (Frontend Exposure Analyzer, Endpoint Mapper, ParamForge)
- `inputs/frontend/fake.js` — javascript (Frontend Exposure Analyzer, Endpoint Mapper, ParamForge, GraphQL Risk Mapper)
- `inputs/frontend/fake.js.map` — source_map (Frontend Exposure Analyzer, ParamForge)
- `inputs/graphql/fake.graphql` — graphql (GraphQL Risk Mapper, ParamForge)
- `inputs/har/fake.har` — har (HAR Analyzer, Endpoint Mapper, Auth Surface Analyzer, ParamForge)
- `inputs/har/fake_graphql.har` — har (HAR Analyzer, Endpoint Mapper, Auth Surface Analyzer, ParamForge, GraphQL Risk Mapper)
- `inputs/inventories/endpoint-inventory.json` — endpoint_inventory (Project Correlator, ParamForge, Authz import)
- `inputs/other/unknown.bin` — unknown (unclassified)
- `inputs/requests/request.txt` — raw_request (Auth Surface Analyzer, Evidence Locker)
- `inputs/responses/response.txt` — raw_response (Auth Surface Analyzer, Evidence Locker)

## Steps run
- HAR Analyzer: completed
- Endpoint Mapper: completed
- Frontend Exposure Analyzer: completed
- Auth Surface Analyzer: completed
- GraphQL Risk Mapper: completed
- ParamForge: completed
- Project Correlator: completed

## Skipped steps
- None

## Failed steps
- None

## Outputs
- `outputs/har/har-summary.json` (har_report)
- `outputs/har/har-report.md` (markdown_report)
- `outputs/endpoints/endpoint-inventory.json` (endpoint_inventory)
- `outputs/endpoints/endpoint-report.md` (markdown_report)
- `outputs/frontend/frontend-inventory.json` (frontend_inventory)
- `outputs/frontend/frontend-report.md` (markdown_report)
- `outputs/auth_surface/auth-surface-inventory.json` (auth_surface_inventory)
- `outputs/auth_surface/auth-surface-report.md` (markdown_report)
- `outputs/graphql/graphql-inventory.json` (graphql_inventory)
- `outputs/graphql/graphql-report.md` (markdown_report)
- `outputs/paramforge/paramforge-inventory.json` (paramforge_inventory)
- `outputs/paramforge/wordlists/params.txt` (checklist)
- `outputs/paramforge/wordlists/json_keys.txt` (checklist)
- `outputs/paramforge/wordlists/headers.txt` (checklist)
- `outputs/paramforge/wordlists/cookies.txt` (checklist)
- `outputs/paramforge/wordlists/routes.txt` (checklist)
- `outputs/paramforge/wordlists/endpoints.txt` (checklist)
- `outputs/paramforge/wordlists/object_ids.txt` (checklist)
- `outputs/paramforge/wordlists/graphql.txt` (checklist)
- `outputs/paramforge/wordlists/admin.txt` (checklist)
- `outputs/paramforge/wordlists/billing.txt` (checklist)
- `outputs/paramforge/wordlists/file.txt` (checklist)
- `outputs/paramforge/wordlists/auth.txt` (checklist)
- `outputs/paramforge/wordlists/debug.txt` (checklist)
- `outputs/paramforge/wordlists/all_terms.txt` (checklist)
- `outputs/correlate/correlation-project.yml` (correlation_project)
- `outputs/correlate/correlation-report.md` (correlation_report)
- `outputs/correlate/triage-leads.json` (triage_leads)
- `outputs/correlate/manual-checklist.md` (checklist)

## Highest-priority correlator leads
- None identified

## Report-ready candidates
- None identified

## Evidence gaps
- 3 lead(s) need more evidence.

## Next manual actions
- Confirm the affected asset is in scope.
- Compare expected and observed behavior using an authorized manual workflow.

## Redaction notice
Reports redact sensitive values by default. Review every artifact before sharing.

## Limitations
- Passive local-file analysis can produce false positives and incomplete context.
- BugBountyScout does not validate findings, send requests, replay traffic, or exploit targets.
