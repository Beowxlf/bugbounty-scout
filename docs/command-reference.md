# Command reference

All commands are local-only unless explicitly documented otherwise; Phase 3A
adds no network behavior. Outputs are redacted by default. Use only synthetic
fixtures, owned assets, labs, or explicitly authorized bug bounty data.

| Command | Purpose and common commands | Input / output | Status and boundaries |
| --- | --- | --- | --- |
| `bbs --help` | Discover command groups; `bbs --version` shows the package version. | Terminal help. | Passive/local; no requests. |
| `bbs doctor` | Check Python, imports, paths, parsing, redaction, and invocation mode. Use `--format json` for automation. | Environment metadata/table or JSON. | Diagnostic only; no network or services. |
| `bbs init NAME` | Create a local workspace with safe directories/configuration. | Name → workspace folder. | Local setup only. |
| `bbs scope` | `init`; `check URL --scope-file scope.yml`. | YAML policy → allow/deny decision. | Offline policy evaluation; does not contact URL. |
| `bbs har` | `summary`, `endpoints`, `secrets`, `cookies`, `headers`, `third-parties`, `report`. | Local `.har` → table/JSON/Markdown. | Passive capture analysis; no replay. |
| `bbs endpoints` | `from-har`, `from-file`, `from-folder`, `report`, `checklist`. | HAR/frontend artifacts → API inventory. | Passive regex/parser leads; no scanning. |
| `bbs frontend` | `scan-file`, `scan-folder`, `secrets`, `sourcemaps`, `storage`, `dom-leads`, `postmessage`, `report`. | Local JS/HTML/JSON/map → inventory. | No fetching, payloads, or secret validation. |
| `bbs authz` | `init`, `add-actor`, `add-object`, `import-endpoints`, `expect`, `record`, `compare`, `findings`, `report`, `checklist`. | YAML matrix/manual observations → findings/checklist. | Manual modeling only; never sends tests. |
| `bbs evidence` | `init`, `add-request`, `add-response`, `add-file`, `add-note`, `add-step`, setters, `lint`, `export`. | Local evidence → redacted workspace/report. | Local organization; review before sharing. |
| `bbs report` | `lint`; `export FILE --format markdown/json`. | Finding/evidence YAML → report. | Quality warnings do not prove impact. |
| `bbs paramforge` | `scan-har`, `scan-file`, `scan-folder`, `scan-inventory`, `report`, `export`, `export-all`, `stats`. | Local artifacts → names-only vocabulary. | Does not fuzz or invoke other tools. |
| `bbs auth-surface` | `scan-har`, `scan-file`, `scan-folder`, `scan-inventory`, `jwt`, `cookies`, `headers`, `cors`, `cache`, `report`, `checklist`. | Captures/artifacts → observations. | Local decoding/review; no JWT attacks or CORS PoCs. |
| `bbs graphql` | `scan-har`, `scan-file`, `scan-folder`, `scan-inventory`, `endpoints`, `operations`, `variables`, `schema`, `leads`, `report`, `checklist`. | Local captures/schema → inventory. | No introspection requests, replay, or DoS testing. |
| `bbs correlate` | `init`, `add-artifact`, `scan`, `build`, `assets`, `signals`, `leads`, `report`, `export-leads`, `checklist`. | Saved local outputs → triage project. | Correlation is conservative and not proof. |
| `bbs demo` | `init NAME`, `status FOLDER`, `clean FOLDER`. | Name/folder → synthetic demo project/status/removal. | Fake `.test` data only; commands are not auto-run. |

Use `bbs GROUP --help` and `bbs GROUP COMMAND --help` for complete option names.
Report-producing commands generally accept `--format markdown` or
`--format json`; legacy table commands retain `--json` for compatibility.
Malformed, missing, or unsupported inputs return a nonzero exit code and a
concise error rather than a traceback.
