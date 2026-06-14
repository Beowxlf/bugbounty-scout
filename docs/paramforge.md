# ParamForge

ParamForge is BugBountyScout's Phase 2F passive vocabulary builder. It reads
local artifacts and inventories, extracts names and structural terms, scores
them, and produces redacted reports or names-only wordlists. It never fetches a
URL, replays a request, fuzzes a target, validates a secret, or generates an
exploit payload.

## Supported inputs

- HAR files
- JavaScript, HTML, JSON, text, and source-map files
- Folders containing supported files
- Endpoint Mapper and Frontend Exposure inventory JSON
- IDOR/BOLA authorization matrix YAML or JSON
- Evidence Locker workspace YAML or JSON

## Example workflow

```bash
PYTHONPATH=src python -m bugbounty_scout.cli paramforge scan-har capture.har > vocabulary.json
PYTHONPATH=src python -m bugbounty_scout.cli paramforge report vocabulary.json --format markdown
PYTHONPATH=src python -m bugbounty_scout.cli paramforge export vocabulary.json --category params --format txt
PYTHONPATH=src python -m bugbounty_scout.cli paramforge export-all vocabulary.json --output-dir wordlists
PYTHONPATH=src python -m bugbounty_scout.cli paramforge stats vocabulary.json
```

## Output categories

ParamForge distinguishes parameters, JSON and response keys, form fields,
headers, cookies, routes, endpoints, object names, GraphQL terms, JavaScript
identifiers, errors, and auth/admin/billing/file/organization/role/debug terms.
Export aliases include `all`, `params`, `query_params`, `body_params`,
`json_keys`, `headers`, `cookies`, `routes`, `endpoints`, `object_ids`,
`graphql`, `admin`, `billing`, `file`, `auth`, `debug`, `idor`, and `storage`.

TXT is suited to manually configured authorized tooling, CSV includes a header,
and JSON carries export metadata. `export-all` creates 14 names-only files.

## Scoring and tags

Frequency scores grow logarithmically with observed occurrences. Risk scores
increase for terms associated with authorization, administration, tenancy,
billing, files, redirects, sessions, accounts, and ownership. Neither score
proves a vulnerability.

Tags are heuristic themes such as `auth`, `admin`, `billing`, `file`, `upload`,
`export`, `debug`, `internal`, `idor`, `bola`, `graphql`, `storage`, `role`,
`permission`, `tenant`, `organization`, `user`, `account`, `session`,
`redirect`, `callback`, and `search`.

## Safety, redaction, limitations, and manual validation

Exports contain field names and terms, not captured values. Obvious bearer
tokens, JWTs, cookies, passwords, API keys, session identifiers, and redaction
placeholders are filtered. Evidence snippets are redacted by default.

Extraction is heuristic. Minified code, generic identifiers, generated source
maps, and prose can create false positives; dynamic names may be missed.
Manually validate terms against program scope and documentation. ParamForge
does not fuzz because this phase organizes passive evidence without creating
traffic, changing state, or exceeding authorization.
