"""Redacted frontend exposure inventory reports."""

# ruff: noqa: E501

import json

from bugbounty_scout.models import FrontendInventory
from bugbounty_scout.redaction import redact_text


def render_json(inventory: FrontendInventory) -> str:
    return json.dumps(inventory.model_dump(mode="json"), indent=2)


def _items(values, template) -> str:
    return "\n".join(template(value) for value in values) or "- None observed."


def render_markdown(inventory: FrontendInventory) -> str:
    content = f"""# Frontend Exposure Analyzer Report

## Summary

- Files analyzed: {len(inventory.source_files)}
- Findings: {len(inventory.findings)}
- Secret/config observations: {len(inventory.secrets)}
- Source-map observations: {len(inventory.source_maps)}
- Manual review leads: {len(inventory.storage_references) + len(inventory.dom_review_leads) + len(inventory.postmessage_leads)}

## Files analyzed

{_items(inventory.source_files, lambda value: f"- `{value}`")}

## Frontend secret/config findings

{_items(inventory.secrets, lambda value: f"- **{value.title}** ({value.context.get('classification')}) — `{value.source_file}:{value.line}` — {value.redacted_evidence}")}

## Runtime config observations

{_items(inventory.runtime_configs, lambda value: f"- `{value.source_file}:{value.line}` — {value.redacted_evidence}")}

## Source map observations

{_items(inventory.source_maps, lambda value: f"- **{value.finding_type}** — `{value.source_map_file}` — {value.redacted_evidence}")}

## Routes and API client hints

{_items(inventory.routes, lambda value: f"- `{value.method} {value.url}` — {', '.join(value.risk_tags) or 'manual review'}")}

## Client storage review leads

{_items(inventory.storage_references, lambda value: f"- `{value.storage_type}` key `{value.key or 'unspecified'}` at `{value.source_file}:{value.line}` — {value.risk}")}

## DOM review leads

{_items(inventory.dom_review_leads, lambda value: f"- `{value.source_file}:{value.line}` — {value.source_pattern} → {value.sink_pattern}; {value.review_reason}")}

## postMessage review leads

{_items(inventory.postmessage_leads, lambda value: f"- `{value.source_file}:{value.line}` — origin check: {value.has_origin_check}; {value.review_reason}")}

## Manual follow-up checklist

- [ ] Confirm whether observed identifiers are intended to be public.
- [ ] Review sensitive configuration and source-map content in program scope.
- [ ] Trace storage, DOM, and message flows manually before assigning impact.
- [ ] Verify server-side authorization for discovered routes without automation.

## Redaction notice

Sensitive values are removed from findings and report evidence by default. Review
all output before sharing it.

## Limitations

Pattern and proximity analysis can produce false positives and miss dynamically
constructed values. This analyzer makes no network requests, validates no
credentials, generates no exploit payloads, and does not confirm vulnerabilities.
"""
    return redact_text(content)
