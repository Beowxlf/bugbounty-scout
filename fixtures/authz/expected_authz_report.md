# IDOR/BOLA Matrix — Synthetic authorization review

## Summary
- Actors: 7
- Objects: 4
- Endpoint templates: 6
- Mismatches: 5
- Candidate findings: 5

## Actors
- `actor-user-a` — User A (user); org=Org A; tenant=Tenant A
- `actor-user-b` — User B (user); org=Org A; tenant=Tenant A
- `actor-admin` — Admin (admin); org=Org A; tenant=Tenant A
- `actor-org-owner` — Org Owner (owner); org=Org A; tenant=Tenant A
- `actor-org-member` — Org Member (member); org=Org B; tenant=Tenant A
- `actor-tenant-a` — Tenant A user (user); org=Org A; tenant=Tenant A
- `actor-tenant-b` — Tenant B user (user); org=Org B; tenant=Tenant B

## Objects
- `object-invoice-a` — Invoice A (invoice); owner `actor-user-a`; sensitivity=high
- `object-file-a` — File A (file); owner `actor-user-a`; sensitivity=high
- `object-project-a` — Project A (project); owner `actor-user-a`; sensitivity=medium
- `object-org-settings` — Org A settings (organization); owner `actor-org-owner`; sensitivity=high

## Endpoint templates
- `endpoint-invoice` — `GET /api/invoices/{invoiceId}`; tags: idor-candidate, billing, sensitive-data
- `endpoint-file` — `GET /api/files/{fileId}`; tags: idor-candidate, file-download
- `endpoint-project` — `PATCH /api/projects/{projectId}`; tags: idor-candidate, state-changing
- `endpoint-org-settings` — `GET /api/orgs/{orgId}/settings`; tags: organization-management, sensitive-data
- `endpoint-admin` — `GET /api/admin/users`; tags: admin
- `endpoint-billing` — `GET /api/orgs/{orgId}/billing`; tags: billing, organization-management

## Expected access matrix
- `actor-user-b` → `object-invoice-a` via `endpoint-invoice`: **deny** (user) — Different owner
- `actor-org-member` → `object-org-settings` via `endpoint-org-settings`: **deny** (organization) — Different organization
- `actor-tenant-b` → `object-file-a` via `endpoint-file`: **deny** (tenant) — Different tenant
- `actor-user-b` → `object-project-a` via `endpoint-project`: **deny** (ownership) — Different owner cannot mutate
- `actor-admin` → `object-org-settings` via `endpoint-admin`: **allow** (role) — Admin should access scoped administration

## Observed access matrix
- `actor-user-b` → `object-invoice-a` via `endpoint-invoice`: **allowed**; status=200
- `actor-org-member` → `object-org-settings` via `endpoint-org-settings`: **allowed**; status=200
- `actor-tenant-b` → `object-file-a` via `endpoint-file`: **allowed**; status=200
- `actor-user-b` → `object-project-a` via `endpoint-project`: **allowed**; status=200
- `actor-admin` → `object-org-settings` via `endpoint-admin`: **denied**; status=403

## Mismatches
- Expected **deny**, observed **allowed** for `expect-cross-user`.
- Expected **deny**, observed **allowed** for `expect-cross-org`.
- Expected **deny**, observed **allowed** for `expect-cross-tenant`.
- Expected **deny**, observed **allowed** for `expect-mutation`.
- Expected **allow**, observed **denied** for `expect-admin-allow`.

## Candidate findings
- **HIGH — Authorization mismatch for Invoice A** (`idor`): Manual observations differ from the documented authorization expectation; validate scope, ownership, and returned or changed data.
- **HIGH — Authorization mismatch for Org A settings** (`cross_org_access`): Manual observations differ from the documented authorization expectation; validate scope, ownership, and returned or changed data.
- **HIGH — Authorization mismatch for File A** (`cross_tenant_access`): Manual observations differ from the documented authorization expectation; validate scope, ownership, and returned or changed data.
- **HIGH — Authorization mismatch for Project A** (`state_changing_authz_failure`): Manual observations differ from the documented authorization expectation; validate scope, ownership, and returned or changed data.
- **INFO — Authorization mismatch for Org A settings** (`needs_manual_review`): Manual observations differ from the documented authorization expectation; validate scope, ownership, and returned or changed data.

## Evidence references
- evidence/redacted-file.txt
- evidence/redacted-invoice.txt
- evidence/redacted-org-settings.txt
- evidence/redacted-project-change.txt

## Manual follow-up checklist
# IDOR/BOLA Manual Checklist

Authorized, owned-asset, or lab use only. This matrix stores manual notes and does not send, replay, fuzz, or generate HTTP requests.

- [ ] **organization**: Can a user from Org A access Org B objects?
- [ ] **organization**: Are organization identifiers enforced server-side?
- [ ] **organization**: Are exports scoped to the correct organization?
- [ ] **role**: Can a lower-privileged role directly reach a higher-privileged operation?
- [ ] **role**: Are role checks enforced server-side on every request?
- [ ] **tenant**: Can one tenant enumerate or access another tenant's resources?
- [ ] **tenant**: Are tenant identifiers enforced server-side?
- [ ] **tenant**: Can shared admin or support workflows cross tenant boundaries incorrectly?
- [ ] **user**: Can Actor A access an object owned by Actor B?
- [ ] **user**: Does the server enforce ownership rather than only hiding the object in the UI?
- [ ] **user**: Does a denied response still expose object metadata?
- [ ] **state-changing** (endpoint-project): Can a lower-privileged user change an object they do not own?
- [ ] **state-changing** (endpoint-project): Is role authorization enforced before the state change?
- [ ] **state-changing** (endpoint-project): Is object ownership checked before mutation?
- [ ] **admin** (endpoint-admin): Is this endpoint protected server-side rather than only hidden in the UI?
- [ ] **admin** (endpoint-admin): Can non-admin roles reach the endpoint directly?
- [ ] **admin** (endpoint-admin): Are admin role checks applied on every request?

## Redaction notice
Sensitive-looking values are redacted by default. Store only intentionally redacted local evidence references.

## Limitations
This is a manual testing workbench. It does not send requests, replay traffic, generate payloads, fuzz, scan, or prove exploitability.
