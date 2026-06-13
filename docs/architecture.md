# Architecture

Phase 1 separates validated models and pure local analysis from Typer command
adapters. `ScopeGuard` evaluates URL strings without networking. The redaction
engine transforms text before derived evidence or reports are written. The HAR
parser extracts capture metadata without active requests or secret scanning.

Workspaces contain captures, evidence, findings, and reports plus a small
`workspace.yml` safety manifest. YAML and JSON inputs are validated through
Pydantic before use.

Future modules should depend on these safety primitives rather than reimplement
scope or redaction behavior. Any future active capability must require an
affirmative ScopeDecision and conservative request controls.
