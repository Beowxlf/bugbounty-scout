# Phase 1 usage

Create a workspace with `bbs init NAME`, enter it, and run `bbs scope init`.
Replace every placeholder with the target program's published scope before
using `bbs scope check URL`.

Use `bbs har summary FILE` for a passive table or add `--json` for structured
output. Use `bbs redact FILE` to create `FILE.redacted`. Use
`bbs report export FINDING` to create a Markdown report from YAML or JSON.

These commands are local-only. A successful scope decision is a convenience,
not a replacement for reading and following the program policy.
