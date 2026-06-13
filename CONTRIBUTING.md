# Contributing

Thank you for helping improve BugBountyScout.

## Development

1. Create a focused branch.
2. Install with `python -m pip install -e ".[dev]"`.
3. Add tests that use synthetic data and reserved domains.
4. Run `python -m pytest`, `ruff check .`, and `ruff format --check .`.
5. Submit a clear pull request describing behavior and safety implications.

## Design requirements

Contributions must remain local-first, passive-first, scope-aware, and
redacted-by-default. Do not add exploit automation, mass scanning, bypass
features, provider credential validation, telemetry, or cloud dependencies.
Any future network behavior must be explicit, low-volume, and guarded by a
positive scope decision.

Do not commit real secrets, live traffic, personal data, or program-confidential
scope details. Documentation and tests must use `.test`, `.example`, or other
reserved identifiers.
