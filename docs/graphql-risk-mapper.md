# GraphQL Risk Mapper

GraphQL Risk Mapper is BugBountyScout's Phase 2H passive, local-only review module. It organizes GraphQL endpoints, observed queries/mutations/subscriptions, variables, object identifiers, selected fields, fragments, local schema artifacts, captured errors, batching indicators, and conservative authorization-review leads.

## Supported inputs

The mapper reads HAR, JavaScript, HTML, JSON, text, `.graphql`, `.gql`, schema SDL, local introspection JSON, YAML/JSON evidence workspaces, existing Endpoint Mapper/Frontend/Auth Surface inventories, and folders containing these files. It never fetches a URL.

## Example workflow

```bash
bbs graphql scan-har capture.har > graphql-inventory.json
bbs graphql operations graphql-inventory.json
bbs graphql variables graphql-inventory.json
bbs graphql report graphql-inventory.json --format markdown
bbs graphql checklist graphql-inventory.json --format markdown
```

Other entry points include `scan-file`, `scan-folder`, `scan-inventory`, `endpoints`, `schema`, and `leads`. JSON report and checklist formats are also available.

## Reviewing the inventory

Operation records retain operation type/name, variable names and visible types, selected field names, fragment names, sensitive-field indicators, and object-ID candidates. Values are summarized or omitted rather than exposed. ID-like names and Relay/global-ID-looking values are leads, not proof of BOLA.

Review sensitive fields against role, ownership, tenant, and organization policy. Review every mutation—especially user, role, permission, tenant, billing, payment, file, invite, export, account, password, email, MFA, OTP, and admin operations—for server-side authorization. The generated checklist asks manual questions without producing requests or payloads.

## Schema, batching, and errors

Only already-local SDL and introspection-like JSON are parsed. Type names and root query/mutation/subscription fields can reveal areas requiring authorized manual review. Captured operation arrays are labeled as batching indicators, and captured GraphQL errors are checked for resolver, path, location, extension, exception, debug, and stack details.

## What it does not do

The mapper does not run introspection, contact targets, replay requests, generate GraphQL queries or exploit payloads, fuzz variables, automate authorization bypass, validate findings, test batching abuse, or perform depth/complexity/denial-of-service testing. Those boundaries reduce unintended traffic and keep the module suitable for evidence already captured under an authorized program.

## Redaction, limitations, and manual validation

Credentials, cookies, JWTs, API keys, PII, sessions, and authorization headers are redacted by default. Reports intentionally preserve operation, field, fragment, and variable names needed for review. Regex and structural heuristics can miss dynamically constructed operations and can produce false positives. A review lead is not a vulnerability; validate authorization and data exposure manually with permitted test accounts, minimal non-destructive cases, and the program's scope and rate limits.
