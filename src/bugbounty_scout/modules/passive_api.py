"""Passive API inventory reports and manual testing checklists."""

import json

from bugbounty_scout.models import ApiInventory, TestingChecklistItem
from bugbounty_scout.redaction import redact_text

QUESTIONS = {
    "idor-candidate": [
        "Can User A access this object when it belongs to User B?",
        "Is authorization enforced server-side for this object ID?",
        "Does the response expose object metadata across tenant boundaries?",
    ],
    "state-changing": [
        "Is CSRF protection required and present where applicable?",
        "Does the endpoint enforce role permissions before changing state?",
        "Are object ownership checks performed before update/delete actions?",
    ],
    "file-upload": [
        "Are file type, size, content, and storage-location controls enforced?",
        "Are uploaded files private by default?",
        "Can one user access another user's uploaded file?",
    ],
    "billing": [
        "Are billing objects scoped to the correct user, organization, or tenant?",
        "Are invoice/payment identifiers protected from cross-account access?",
    ],
    "admin": [
        "Is the endpoint hidden only in the UI, or actually protected server-side?",
        "Can non-admin roles reach the endpoint directly?",
    ],
}


def generate_checklist(inventory: ApiInventory) -> list[TestingChecklistItem]:
    items = []
    for endpoint in inventory.endpoints:
        for category in endpoint.risk_tags:
            for question in QUESTIONS.get(category, []):
                items.append(
                    TestingChecklistItem(
                        endpoint_id=endpoint.id,
                        category=category,
                        question=question,
                        reason=f"Endpoint is tagged {category}.",
                        priority="high"
                        if category in {"idor-candidate", "admin", "billing"}
                        else "medium",
                    )
                )
    return items


def render_inventory_json(inventory: ApiInventory) -> str:
    return json.dumps(inventory.model_dump(mode="json"), indent=2)


def render_inventory_markdown(inventory: ApiInventory) -> str:
    rows = [
        f"| `{e.method}` | `{e.host or 'relative'}` | `{e.path}` | "
        f"`{e.normalized_path}` | {', '.join(e.risk_tags) or '—'} |"
        for e in inventory.endpoints
    ]
    high = [
        f"- `{e.method} {e.normalized_path}` — {', '.join(e.risk_tags)}"
        for e in inventory.endpoints
        if e.risk_tags
    ]
    auth = [
        f"- `{e.method} {e.normalized_path}` — {', '.join(e.auth_indicators)}"
        for e in inventory.endpoints
    ]
    objects = [
        f"- `{e.method} {e.normalized_path}` — {', '.join(e.object_id_candidates)}"
        for e in inventory.endpoints
        if e.object_id_candidates
    ]
    risks = sorted(
        {tag for endpoint in inventory.endpoints for tag in endpoint.risk_tags}
    )
    params = [
        f"- `{e.method} {e.normalized_path}` — query: "
        f"{', '.join(e.query_params) or '—'}; body/JSON: "
        f"{', '.join(sorted(set(e.body_params + e.json_keys))) or '—'}"
        for e in inventory.endpoints
        if e.query_params or e.body_params or e.json_keys
    ]
    content = f"""# Passive Endpoint Inventory

## Summary

- Endpoints: {len(inventory.endpoints)}
- Hosts: {len(inventory.hosts)}
- Source files: {len(inventory.source_files)}

## Hosts observed

{
        chr(10).join(f"- `{host}`" for host in inventory.hosts)
        or "- Relative endpoints only."
    }

## Endpoint inventory

| Method | Host | Original path | Normalized path | Risk tags |
| --- | --- | --- | --- | --- |
{chr(10).join(rows) or "| — | — | — | — | — |"}

## High-interest endpoints

{chr(10).join(high) or "- None identified by conservative patterns."}

## Auth indicators

{chr(10).join(auth) or "- None observed."}

## Object ID candidates

{chr(10).join(objects) or "- None observed."}

## Risk tags

{", ".join(risks) or "None."}

## Parameters observed

{chr(10).join(params) or "- None observed."}

## Source files

{chr(10).join(f"- `{source}`" for source in inventory.source_files) or "- None."}

## Manual review notes

Tags are leads for authorized manual review, not confirmed vulnerabilities.

## Redaction notice

Reports retain parameter and header names, not observed secret values.
Evidence is redacted by default.

## Limitations

Regex extraction can miss dynamically constructed URLs and can produce false
positives. No live requests, replay, fuzzing, authentication bypass, or exploit
automation are performed.
"""
    return redact_text(content)


def render_checklist_json(items: list[TestingChecklistItem]) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items], indent=2)


def render_checklist_markdown(items: list[TestingChecklistItem]) -> str:
    lines = [
        "# Passive Endpoint Manual Testing Checklist",
        "",
        "Authorized manual review questions only; no exploit payloads are generated.",
        "",
    ]
    for item in items:
        lines.extend(
            [
                f"## {item.endpoint_id} — {item.category}",
                f"- [ ] {item.question}",
                f"- **Reason:** {item.reason}",
                f"- **Priority:** {item.priority}",
                "",
            ]
        )
    if not items:
        lines.append("_No tag-driven checklist items were generated._")
    return "\n".join(lines)
