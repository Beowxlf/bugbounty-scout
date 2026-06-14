# Evidence Locker

Evidence Locker organizes authorized, local evidence into one YAML finding
workspace. Store redacted requests/responses, notes, screenshots, command output,
source files/maps, HAR excerpts, and exported endpoint, frontend, or authorization
matrix reports. Files remain in place and receive a SHA-256 integrity hash;
large or binary content is not copied into YAML.

Text evidence is read when practical and passed through the shared redaction
engine. Exports use only redacted evidence text. Review all output: pattern-based
redaction can miss novel formats or redact harmless strings, and raw source files
remain sensitive.

Reproduction steps should be ordered, minimal, and manual. Each step states the
action, expected result, actual result, and an optional evidence item ID. Expected
behavior should describe the intended authorization or product rule; actual
behavior should state only what was observed. Separate those facts from impact.

Use `evidence add-file --type authz_matrix` for an IDOR/BOLA report,
`endpoint_inventory` for Endpoint Mapper output, `frontend_inventory` for a
frontend report, and `har_entry` or `other` for a redacted HAR report. Export with
`bbs evidence export WORKSPACE --format markdown|json`.

Evidence Locker does not collect traffic, generate screenshots, replay requests,
validate secrets, contact providers, exploit, fuzz, scan, or bypass controls. It
cannot establish authorization, reproducibility, exploitability, or severity;
manual review and program compliance remain required.
