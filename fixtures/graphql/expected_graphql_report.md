# GraphQL Risk Mapper Report

## Summary

- Sources: 2
- Endpoints: 1
- Operations: 2
- Review leads: 5
- Mode: passive/local-only

## Sources analyzed

- fixtures/graphql/fake_folder/app.js
- fixtures/graphql/fake_folder/query.graphql

## GraphQL endpoints

- `UNKNOWN` `https://api.example.test/api/graphql` — unknown

## Operations inventory

- **subscription AccountChanged** — fields: account, accountChanged, accountId, email, owner; tags: manual-authorization-review, object-id-candidate, sensitive-field-selection
- **query GetUser** — fields: tenantId, user; tags: manual-authorization-review, object-id-candidate, sensitive-field-selection, tenant-boundary

## Variables and object-ID candidates

- `$accountId` (ID!) — object ID: yes
- `$tenantId` (ID!) — object ID: yes
- `$userId` (ID!) — object ID: yes

## Sensitive fields

- account
- accountChanged
- accountId
- email
- owner
- tenantId
- user

## Fragments

- **UserDetails** — email, fullName, organization, permissions, roles

## Schema/introspection artifacts

_None observed._

## Review leads

- **Low — Object ID variables in AccountChanged**: Observed object identifier variables: accountId.
- **Low — Sensitive fields selected by AccountChanged**: Selected fields need role and ownership review: account, accountChanged, accountId, email, owner.
- **Low — Object ID variables in GetUser**: Observed object identifier variables: tenantId, userId.
- **Low — Sensitive fields selected by GetUser**: Selected fields need role and ownership review: tenantId, user.
- **Low — Tenant Boundary: GetUser**: Observed operation names or fields indicate tenant boundary review.

## Manual testing checklist

# GraphQL Manual Testing Checklist

## Endpoint access review

- [ ] Are observed GraphQL endpoints protected consistently for authenticated and unauthenticated actors?

## Query authorization review

- [ ] Can Actor A query an object owned by Actor B using the observed object ID variable?

## Mutation authorization review

- [ ] Can a lower-privileged actor run each observed mutation directly?

## Object ID / BOLA review

- [ ] Are object ID variables authorized by ownership, not merely accepted as valid identifiers?

## Tenant/org boundary review

- [ ] Are tenantId/orgId variables enforced server-side or trusted from the request?

## Role/permission review

- [ ] Are admin-like operations protected server-side, not only hidden in the UI?

## Sensitive field exposure review

- [ ] Are sensitive fields filtered by role and object ownership?

## File/upload/export review

- [ ] Do file and export operations enforce ownership and least privilege?

## Billing/payment review

- [ ] Do billing and payment operations enforce account and organization boundaries?

## Introspection/schema artifact review

- [ ] Does the local schema artifact reveal sensitive operations that require manual authorization review?

## Batching/error detail review

- [ ] Are batch requests authorized per operation?
- [ ] Do GraphQL errors expose resolver names, stack traces, internal paths, or schema details?

> Manual, authorized review only. No requests or payloads are generated.


## Redaction notice

Captured values, credentials, cookies, tokens, PII, and authorization material are redacted by default. Reports retain operation, field, and variable names needed for manual review.

## Limitations

This passive mapper reads local artifacts only. It does not send or replay requests, run introspection, fuzz, generate payloads, bypass controls, validate vulnerabilities, or test GraphQL depth, complexity, batching abuse, or denial of service.
