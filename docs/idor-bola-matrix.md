# IDOR/BOLA Matrix

## What it does

Phase 2D is a local, manual-first workbench for organizing authorized
object-level and role-level authorization testing. It relates actors, owned
objects, endpoint templates, expected access, manually observed results, and
redacted evidence references. It highlights mismatches and produces conservative
candidate findings and report-ready notes. Candidates are not proof of a
vulnerability.

## Supported workflow

1. Initialize a YAML matrix.
2. Add metadata-only actors; never add passwords, cookies, tokens, or sessions.
3. Add synthetic or program-authorized objects and owner metadata.
4. Add endpoint templates or import high-interest Phase 2B inventory.
5. Define expected access before testing.
6. Perform only permitted manual testing outside BugBountyScout.
7. Record the result and a redacted evidence reference.
8. Compare results, review candidates, and generate a report.

## Model actors and objects

Actors can represent User A, User B, Admin, Org Owner, Org Member, Guest, Free
User, Paid User, or Support Agent. Store only name, role, organization, tenant,
account type, and useful notes.

Objects can represent users, accounts, organizations, tenants, teams, invoices,
documents, projects, files, messages, payment methods, roles, permissions,
invites, exports, or reports. Each object has an owner and may have redacted
key/value identifiers.

```bash
bbs authz init demo
bbs authz add-actor demo-authz-matrix.yml \
  --name "Org Member" --role member --organization "Org A" --tenant "Tenant A"
bbs authz add-object demo-authz-matrix.yml \
  --type invoice --name "Invoice A" --owner actor-... \
  --organization "Org A" --identifier invoiceId=inv_123
```

## Endpoint templates and Endpoint Mapper import

Templates preserve method, normalized path, risk tags, object-ID candidates,
source endpoint ID, and source file. The importer selects authorization-relevant
tags such as `idor-candidate`, `state-changing`, `admin`, `billing`,
`file-download`, `export`, `invite`, organization, permission, role, and
sensitive-data management. Untagged static assets are excluded.

```bash
bbs authz add-endpoint demo-authz-matrix.yml \
  --method PATCH --path "/api/projects/{projectId}" --tag state-changing
bbs authz import-endpoints demo-authz-matrix.yml endpoint-inventory.json
```

Imported YAML entries remain editable.

## Define expected access

The tool does not infer business rules. Expected results are `allow`, `deny`, or
`unknown`. Boundaries are `user`, `organization`, `tenant`, `role`,
`subscription`, `ownership`, or `unknown`.

```bash
bbs authz expect demo-authz-matrix.yml \
  --actor actor-user-b --object object-invoice-a --endpoint endpoint-invoice \
  --result deny --reason "User B does not own User A's invoice" --boundary user
```

## Record observed results

After a test permitted by program rules, record `allowed`, `denied`, `error`,
`unknown`, or `not_tested`. Optional metadata includes status, response length,
content hash, visible field names, whether data changed, an error, notes, and a
local redacted evidence path.

```bash
bbs authz record demo-authz-matrix.yml \
  --actor actor-user-b --object object-invoice-a --endpoint endpoint-invoice \
  --result allowed --status-code 200 \
  --evidence evidence/redacted-invoice-response.txt
```

Do not attach raw sensitive responses. Phase 2D provides an
`evidence_reference` field for future Evidence Locker integration; it does not
implement a full locker.

## Interpret mismatches and findings

`expected deny` plus `observed allowed` is a possible authorization failure.
`expected allow` plus `observed denied` is informational and may indicate policy,
role configuration, or an incorrect expectation. `expected unknown` plus
`observed allowed` requires manual review.

Severity is conservative. Cross-tenant or cross-organization access to sensitive
data and unauthorized state changes are high-interest. User-to-user reads are
medium or high based on sensitivity. Metadata-only exposure should be reviewed
at low or medium severity. Evidence raises confidence, not impact. Validate the
actual boundary, returned data, ownership, business rule, and reproducibility
before reporting.

```bash
bbs authz compare demo-authz-matrix.yml
bbs authz findings demo-authz-matrix.yml
```

## Reports and checklists

```bash
bbs authz checklist demo-authz-matrix.yml --format markdown
bbs authz checklist demo-authz-matrix.yml --format json
bbs authz report demo-authz-matrix.yml --format markdown
bbs authz report demo-authz-matrix.yml --format json
```

Markdown includes summary, actors, objects, endpoint templates, expected and
observed matrices, mismatches, candidates, evidence references, manual
follow-up, redaction, and limitations. JSON includes the full structured matrix,
comparisons, findings, and checklist.

## Example report interpretation

A row saying “expected deny, observed allowed” with medium confidence means the
notes deserve focused validation. Confirm that actor and object belong to
different intended scopes, the response exposed meaningful data or performed a
change, evidence is redacted, and program rules permit the test. Do not submit
generated wording or severity without that validation.

## What it does not do

The matrix does not send or replay HTTP, generate payloads or bypass steps, fuzz
or enumerate identifiers, mass scan, bypass authentication or controls, validate
credentials against APIs, call cloud services, upload evidence, emit telemetry,
or prove exploitability.

## Limitations and false positives

Expected rules are user-authored and may be wrong. Status codes alone do not
prove access or denial. Caching, UI behavior, role inheritance, support
workflows, delegated access, subscriptions, and asynchronous changes affect
interpretation. Endpoint tags and ID candidates are heuristic.

## Manual validation guidance

Stay within written scope, use dedicated accounts and synthetic data, test the
smallest number of objects necessary, avoid destructive mutations, and retain
only redacted evidence. Confirm server-side ownership, role, organization, and
tenant enforcement rather than UI visibility. Stop if a test could affect a real
user, billing, availability, or data outside the explicitly permitted boundary.
