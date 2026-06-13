# Safety model

BugBountyScout is designed for authorized testing of owned assets, labs, and
targets explicitly listed by a bug bounty program.

Phase 1 performs no network requests. Scope exclusions override inclusions, and
unknown or malformed targets are denied. Redaction runs locally and replaces
common authentication material, secret-like values, and personal identifiers.
Report generation redacts free-text fields even when a caller forgets to supply
pre-redacted evidence.

The project will not implement mass scanning, exploit automation,
authentication or defensive-control bypasses, credential theft, data
exfiltration, or default validation of discovered secrets against real
providers. Future low-volume live checks must be opt-in and scope-aware.
